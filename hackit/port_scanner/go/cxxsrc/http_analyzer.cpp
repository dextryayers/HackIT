#define _GNU_SOURCE
#include "http_analyzer.h"
#include "optimize.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <regex>
#include <memory>
#include <functional>
#include <cctype>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static std::mutex g_http_ssl_mutex;
static bool g_http_ssl_init = false;

static void http_ssl_init_once() {
    std::lock_guard<std::mutex> lock(g_http_ssl_mutex);
    if (!g_http_ssl_init) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        g_http_ssl_init = true;
    }
}

static std::string strip_string(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

HttpAnalyzer::HttpAnalyzer() {
    http_ssl_init_once();
    user_agent_ = "Mozilla/5.0 (compatible; PortStorm/2.0; +https://portstorm.dev)";
}

HttpAnalyzer::~HttpAnalyzer() {}

void HttpAnalyzer::set_user_agent(const std::string &ua) { user_agent_ = ua; }
void HttpAnalyzer::add_custom_header(const std::string &key, const std::string &value) {
    custom_headers_[key] = value;
}
void HttpAnalyzer::set_follow_redirects(bool follow) { follow_redirects_ = follow; }
void HttpAnalyzer::set_max_redirects(int n) { max_redirects_ = n; }
void HttpAnalyzer::set_path(const std::string &path) { path_ = path; }

std::string HttpAnalyzer::build_request(const std::string &host, int port) {
    std::string req = "GET " + path_ + " HTTP/1.1\r\n";
    req += "Host: " + host;
    if ((port != 80 && port != 443)) {
        req += ":" + std::to_string(port);
    }
    req += "\r\n";
    req += "User-Agent: " + user_agent_ + "\r\n";
    req += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    req += "Accept-Language: en-US,en;q=0.5\r\n";
    req += "Connection: close\r\n";

    for (const auto &kv : custom_headers_) {
        req += kv.first + ": " + kv.second + "\r\n";
    }

    req += "\r\n";
    return req;
}

std::string HttpAnalyzer::send_request(const std::string &host, int port, bool use_tls,
                                        const std::string &request, int timeout_ms)
{
    if (use_tls) {
        return tls_send_request(host, port, request, timeout_ms);
    }

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);

    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) return "";

    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, O_NONBLOCK);
        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        if (rc == 0) break;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) { close(fd); fd = -1; continue; }
        int so_err = 0;
        socklen_t err_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
        if (so_err != 0) { close(fd); fd = -1; continue; }
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return "";

    fcntl(fd, F_SETFL, 0);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    send(fd, request.data(), request.size(), 0);

    std::string response;
    char buf[8192];
    while (true) {
        int n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        response += buf;
        if (response.size() > 1024 * 256) break;
    }

    close(fd);
    return response;
}

std::string HttpAnalyzer::tls_send_request(const std::string &host, int port,
                                            const std::string &request, int timeout_ms)
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);

    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) return "";

    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        fcntl(fd, F_SETFL, O_NONBLOCK);
        rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        if (rc == 0) break;

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        rc = poll(&pfd, 1, timeout_ms);
        if (rc <= 0) { close(fd); fd = -1; continue; }
        int so_err = 0;
        socklen_t err_len = sizeof(so_err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
        if (so_err != 0) { close(fd); fd = -1; continue; }
        break;
    }
    freeaddrinfo(res);
    if (fd < 0) return "";

    fcntl(fd, F_SETFL, 0);

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(fd); return ""; }
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return ""; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());

    rc = SSL_connect(ssl);
    if (rc != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        ERR_clear_error();
        return "";
    }

    SSL_write(ssl, request.data(), request.size());

    std::string response;
    char buf[8192];
    while (true) {
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;
        response += buf;
        if (response.size() > 1024 * 256) break;
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return response;
}

std::pair<int, std::string> HttpAnalyzer::parse_status_line(const std::string &response) {
    std::pair<int, std::string> result{0, ""};
    size_t line_end = response.find("\r\n");
    if (line_end == std::string::npos) return result;

    std::string line = response.substr(0, line_end);
    std::regex status_regex("HTTP/\\d\\.\\d\\s+(\\d+)\\s*(.*)");
    std::smatch m;
    if (std::regex_search(line, m, status_regex)) {
        result.first = std::stoi(m[1].str());
        result.second = strip_string(m[2].str());
    }
    return result;
}

std::map<std::string, std::string> HttpAnalyzer::extract_headers(const std::string &response) {
    std::map<std::string, std::string> headers;
    size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) return headers;

    std::string header_section = response.substr(0, header_end);
    std::istringstream stream(header_section);
    std::string line;
    std::getline(stream, line);

    while (std::getline(stream, line)) {
        if (line.empty() || line == "\r") continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = strip_string(line.substr(0, colon));
        std::string val = strip_string(line.substr(colon + 1));
        if (!key.empty()) {
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            headers[key] = val;
        }
    }

    return headers;
}

std::string HttpAnalyzer::extract_title(const std::string &html_body) {
    std::regex title_regex("<title[^>]*>(.*?)</title>", std::regex::icase | std::regex::multiline);
    std::smatch m;
    if (std::regex_search(html_body, m, title_regex)) {
        std::string title = strip_string(m[1].str());
        size_t pos;
        while ((pos = title.find("  ")) != std::string::npos) {
            title.replace(pos, 2, " ");
        }
        return title;
    }
    return "";
}

void HttpAnalyzer::detect_technology(const std::string &headers, const std::string &body,
                                      std::vector<std::string> &tech_stack)
{
    std::string combined = headers + "\n" + body;
    std::string lower = combined;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    struct TechPattern {
        const char* pattern;
        const char* name;
    };

    static const TechPattern patterns[] = {
        {"nginx", "Nginx"},
        {"apache", "Apache HTTP Server"},
        {"iis", "IIS"},
        {"tomcat", "Apache Tomcat"},
        {"jetty", "Eclipse Jetty"},
        {"node.js", "Node.js"},
        {"nodejs", "Node.js"},
        {"express", "Express.js"},
        {"django", "Django"},
        {"flask", "Flask"},
        {"rails", "Ruby on Rails"},
        {"ruby on rails", "Ruby on Rails"},
        {"asp.net", "ASP.NET"},
        {"aspx", "ASP.NET"},
        {"php", "PHP"},
        {"caddy", "Caddy"},
        {"lighttpd", "Lighttpd"},
        {"gunicorn", "Gunicorn"},
        {"uwsgi", "uWSGI"},
        {"openresty", "OpenResty"},
        {"cloudflare", "Cloudflare"},
        {"akamai", "Akamai"},
        {"fastly", "Fastly"},
        {"wordpress", "WordPress"},
        {"wp-content", "WordPress"},
        {"drupal", "Drupal"},
        {"joomla", "Joomla"},
        {"magento", "Magento"},
        {"shopify", "Shopify"},
        {"nextcloud", "Nextcloud"},
        {"jquery", "jQuery"},
        {"react", "React"},
        {"angular", "Angular"},
        {"vue.js", "Vue.js"},
        {"vuejs", "Vue.js"},
        {"bootstrap", "Bootstrap"},
        {"tailwind", "Tailwind CSS"},
        {"webpack", "Webpack"},
        {"vite", "Vite"},
        {"next.js", "Next.js"},
        {"nuxt", "Nuxt.js"},
        {"gatsby", "Gatsby"},
        {"hugo", "Hugo"},
        {"recaptcha", "reCAPTCHA"},
        {"google analytics", "Google Analytics"},
        {"gtag", "Google Analytics"},
        {"facebook", "Facebook Pixel"},
        {"fbq", "Facebook Pixel"},
        {"hotjar", "Hotjar"},
        {"livechat", "LiveChat"},
        {"zendesk", "Zendesk"},
        {"intercom", "Intercom"},
        {"discourse", "Discourse"},
        {"sentry", "Sentry"},
        {"datadog", "Datadog"},
        {"newrelic", "New Relic"},
        {"s3", "Amazon S3"},
        {"aws", "Amazon Web Services"},
    };

    for (const auto &p : patterns) {
        if (lower.find(p.pattern) != std::string::npos) {
            if (std::find(tech_stack.begin(), tech_stack.end(), p.name) == tech_stack.end()) {
                tech_stack.emplace_back(p.name);
            }
        }
    }

    {
        std::regex server_re("Server:\\s*(\\S+)", std::regex::icase);
        std::smatch m;
        if (std::regex_search(headers, m, server_re)) {
            std::string srv = m[1].str();
            std::transform(srv.begin(), srv.end(), srv.begin(), ::tolower);
            if (srv.find("nginx") != std::string::npos && !std::count(tech_stack.begin(), tech_stack.end(), "Nginx")) {
                tech_stack.emplace_back("Nginx");
            } else if (srv.find("apache") != std::string::npos && !std::count(tech_stack.begin(), tech_stack.end(), "Apache HTTP Server")) {
                tech_stack.emplace_back("Apache HTTP Server");
            } else if (srv.find("iis") != std::string::npos && !std::count(tech_stack.begin(), tech_stack.end(), "IIS")) {
                tech_stack.emplace_back("IIS");
            } else if (srv.find("cloudflare") != std::string::npos && !std::count(tech_stack.begin(), tech_stack.end(), "Cloudflare")) {
                tech_stack.emplace_back("Cloudflare");
            }
        }
    }
}

HttpAnalysis HttpAnalyzer::analyze(const std::string &host, int port, bool use_tls, int timeout_ms) {
    HttpAnalysis analysis;
    std::string request = build_request(host, port);
    std::string response = send_request(host, port, use_tls, request, timeout_ms);
    std::string url = (use_tls ? "https://" : "http://") + host + ":" + std::to_string(port) + path_;

    if (response.empty()) {
        return analysis;
    }

    analysis.raw_response = response;

    auto status = parse_status_line(response);
    analysis.status_code = status.first;
    analysis.status_text = status.second;

    analysis.headers = extract_headers(response);

    auto sh = analysis.headers.find("server");
    if (sh != analysis.headers.end()) analysis.server = sh->second;

    auto ph = analysis.headers.find("x-powered-by");
    if (ph != analysis.headers.end()) analysis.powered_by = ph->second;

    auto ct = analysis.headers.find("content-type");
    if (ct != analysis.headers.end()) analysis.content_type = ct->second;

    auto cl = analysis.headers.find("content-length");
    if (cl != analysis.headers.end()) {
        try { analysis.content_length = std::stoi(cl->second); } catch (...) {}
    }

    auto loc = analysis.headers.find("location");
    if (loc != analysis.headers.end()) analysis.redirect_url = loc->second;

    size_t body_start = response.find("\r\n\r\n");
    std::string body;
    if (body_start != std::string::npos && body_start + 4 < response.size()) {
        body = response.substr(body_start + 4);
        analysis.body_preview = body.substr(0, 512);
    }

    analysis.title = extract_title(body);

    std::string headers_str;
    for (const auto &kv : analysis.headers) {
        headers_str += kv.first + ": " + kv.second + "\n";
    }

    detect_technology(headers_str, body, analysis.technology_stack);

    if (body.find("<form") != std::string::npos || body.find("<FORM") != std::string::npos) {
        analysis.has_form = true;
    }
    if (body.find("password") != std::string::npos || body.find("type=\"password\"") != std::string::npos ||
        body.find("login") != std::string::npos) {
        analysis.has_login = true;
    }
    if (body.find("type=\"file\"") != std::string::npos || body.find("enctype=\"multipart/form-data\"") != std::string::npos) {
        analysis.has_upload = true;
    }

    {
        std::string cookie_header;
        auto ckh = analysis.headers.find("set-cookie");
        if (ckh != analysis.headers.end()) {
            cookie_header = ckh->second;
            int count = 0;
            size_t pos = 0;
            while ((pos = cookie_header.find(";", pos)) != std::string::npos) {
                ++count;
                ++pos;
            }
            analysis.cookie_count = std::max(1, count + 1);
        }
    }

    return analysis;
}
