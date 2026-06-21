#define _GNU_SOURCE
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <cerrno>
#include <string_view>
#include <memory>
#include <unordered_map>


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct ServiceResult {
    int port;
    std::string status;
    std::string service;
    std::string banner;
    std::string version;
    std::string protocol;
    std::vector<std::string> cve;
    std::string cpe;
    int confidence;
    std::unordered_map<std::string, std::string> extra;
};

static std::mutex print_mutex;

static std::string strip(std::string_view s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return std::string(s.substr(a, b - a + 1));
}

static std::string url_decode(std::string_view s) {
    std::string r;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            char buf[3] = {s[i+1], s[i+2], 0};
            r += (char)strtol(buf, nullptr, 16);
            i += 2;
        } else if (s[i] == '+') {
            r += ' ';
        } else {
            r += s[i];
        }
    }
    return r;
}

static std::string json_escape(std::string_view s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    r += buf;
                } else {
                    r += c;
                }
        }
    }
    return r;
}

static void emit_result(const ServiceResult& sr) noexcept {
    std::lock_guard<std::mutex> lock(print_mutex);
    char buf[8192];
    int pos = snprintf(buf, sizeof(buf),
        "RESULT:{\"port\":%d,\"status\":\"%s\",\"service\":\"%s\",\"banner\":\"%s\","
        "\"version\":\"%s\",\"protocol\":\"%s\",\"cpe\":\"%s\",\"confidence\":%d",
        sr.port, json_escape(sr.status).c_str(), json_escape(sr.service).c_str(),
        json_escape(sr.banner).c_str(), json_escape(sr.version).c_str(),
        json_escape(sr.protocol).c_str(), json_escape(sr.cpe).c_str(), sr.confidence);

    for (const auto& kv : sr.extra) {
        int n = snprintf(buf + pos, sizeof(buf) - pos, ",\"%s\":\"%s\"",
            json_escape(kv.first).c_str(), json_escape(kv.second).c_str());
        if (n > 0) pos += n;
        if (pos >= (int)sizeof(buf) - 512) break;
    }

    pos += snprintf(buf + pos, sizeof(buf) - pos, ",\"cve\":[");
    bool first = true;
    for (const auto& c : sr.cve) {
        if (!first) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, ",");
        }
        first = false;
        pos += snprintf(buf + pos, sizeof(buf) - pos, "\"%s\"", json_escape(c).c_str());
        if (pos >= (int)sizeof(buf) - 64) break;
    }
    snprintf(buf + pos, sizeof(buf) - pos, "]}\n");
    printf("%s", buf);
    fflush(stdout);
}

static void emit_final(const std::vector<ServiceResult>& results) noexcept {
    printf("FINAL:{\"engine\":\"deep_analyzer\",\"service_count\":%zu,\"results\":[\n", results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& sr = results[i];
        printf("  {\"port\":%d,\"service\":\"%s\",\"version\":\"%s\",\"confidence\":%d}%s\n",
            sr.port, json_escape(sr.service).c_str(), json_escape(sr.version).c_str(),
            sr.confidence, (i + 1 < results.size()) ? "," : "");
    }
    printf("]}\n");
    fflush(stdout);
}

// ---------- protocol analysis ----------

static void analyze_http(std::string_view banner, ServiceResult& sr) noexcept {
    std::smatch m;

    // Server header
    if (std::regex_search(std::string(), m, std::regex("Server:\\s*([^\r\n]+)", std::regex::icase))) {
        std::string srv = strip(m[1].str());
        sr.extra["server"] = srv;
        // Try to extract version from server string
        std::smatch vm;
        if (std::regex_search(std::string(), vm, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?)"))) {
            sr.version = vm[1].str();
        }
    }

    // X-Powered-By
    if (std::regex_search(std::string(), m, std::regex("X-Powered-By:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["powered_by"] = strip(m[1].str());
    }

    // Set-Cookie
    if (std::regex_search(std::string(), m, std::regex("Set-Cookie:\\s*([^;\\r\\n]+)", std::regex::icase))) {
        sr.extra["cookie"] = strip(m[1].str());
    }

    // WWW-Authenticate
    if (std::regex_search(std::string(), m, std::regex("WWW-Authenticate:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["auth"] = strip(m[1].str());
    }

    // Content-Type
    if (std::regex_search(std::string(), m, std::regex("Content-Type:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["content_type"] = strip(m[1].str());
    }

    // Technology detection
    std::string banner_lower = std::string(banner);
    std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), ::tolower);

    std::vector<std::pair<std::string, std::string>> techs = {
        {"nginx", "Nginx"}, {"apache", "Apache"}, {"iis", "IIS"},
        {"tomcat", "Tomcat"}, {"jetty", "Jetty"}, {"nodejs", "Node.js"},
        {"express", "Express"}, {"django", "Django"}, {"flask", "Flask"},
        {"rails", "Ruby on Rails"}, {"asp\\.net", "ASP.NET"}, {"php", "PHP"},
        {"caddy", "Caddy"}, {"lighttpd", "Lighttpd"}, {"gunicorn", "Gunicorn"}
    };

    for (const auto& t : techs) {
        if (std::regex_search(std::string(), std::regex(t.first, std::regex::icase))) {
            auto it = sr.extra.find("technologies");
            if (it == sr.extra.end()) {
                sr.extra["technologies"] = t.second;
            } else {
                it->second += ", " + t.second;
            }
        }
    }

    // Status code
    if (std::regex_search(std::string(), m, std::regex("HTTP/\\d\\.\\d\\s+(\\d+)"))) {
        sr.extra["status_code"] = m[1].str();
    }

    // Location (redirect)
    if (std::regex_search(std::string(), m, std::regex("Location:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["redirect"] = strip(m[1].str());
    }

    // CPE generation
    auto sit = sr.extra.find("server");
    if (sit != sr.extra.end()) {
        std::string srv = sit->second;
        std::transform(srv.begin(), srv.end(), srv.begin(), ::tolower);
        if (srv.find("apache") != std::string::npos) {
            sr.cpe = "cpe:/a:apache:http_server";
            if (!sr.version.empty()) sr.cpe += ":" + sr.version;
        } else if (srv.find("nginx") != std::string::npos) {
            sr.cpe = "cpe:/a:nginx:nginx";
            if (!sr.version.empty()) sr.cpe += ":" + sr.version;
        } else if (srv.find("iis") != std::string::npos) {
            sr.cpe = "cpe:/a:microsoft:iis";
            if (!sr.version.empty()) sr.cpe += ":" + sr.version;
        }
    }
}

static void analyze_ssh(std::string_view banner, ServiceResult& sr) noexcept {
    std::smatch m;

    // SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
    if (std::regex_search(std::string(), m, std::regex("SSH-([0-9\\.]+)-([^\\s]+)"))) {
        sr.extra["ssh_version"] = strip(m[0].str());
        sr.version = strip(m[2].str());
    }

    if (std::regex_search(std::string(), m, std::regex("([Oo]pen[Ss][Ss][Hh]_?[0-9]+\\.[0-9]+[^\\s]*)"))) {
        sr.extra["software"] = strip(m[1].str());
    }

    // Key exchange algorithms often in banner or after
    if (std::regex_search(std::string(), m, std::regex("key\\s*exchange\\s*algorithms?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["kex_algorithms"] = strip(m[1].str());
    }

    // Extract version from software string
    if (!sr.extra["software"].empty()) {
        std::string sw = sr.extra["software"];
        std::smatch vm;
        if (std::regex_search(std::string(), vm, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?)"))) {
            sr.version = vm[1].str();
        }
    }

    // Auth methods
    if (std::regex_search(std::string(), m, std::regex("authentication\\s*methods?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["auth_methods"] = strip(m[1].str());
    }

    // Encryption algorithms
    if (std::regex_search(std::string(), m, std::regex("encryption\\s*algorithms?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["encryption"] = strip(m[1].str());
    }

    // MAC algorithms
    if (std::regex_search(std::string(), m, std::regex("mac\\s*algorithms?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["mac_algorithms"] = strip(m[1].str());
    }

    // Compression
    if (std::regex_search(std::string(), m, std::regex("compression\\s*algorithms?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["compression"] = strip(m[1].str());
    }

    // CPE
    std::string banner_lower = std::string(banner);
    std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), ::tolower);
    if (banner_lower.find("openssh") != std::string::npos) {
        sr.cpe = "cpe:/a:openbsd:openssh";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("libssh") != std::string::npos) {
        sr.cpe = "cpe:/a:libssh:libssh";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("dropbear") != std::string::npos) {
        sr.cpe = "cpe:/a:dropbear_ssh:dropbear_ssh";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    }
}

static void analyze_ftp(std::string_view banner, ServiceResult& sr) noexcept {
    std::smatch m;

    // FTP server banner: 220 ProFTPD 1.3.5 Server ready
    if (std::regex_search(std::string(), m, std::regex("220[\\s-]([^\r\n]+)", std::regex::icase))) {
        sr.extra["server_banner"] = strip(m[1].str());
    }

    // Extract software and version
    std::vector<std::pair<std::regex, std::string>> ftp_patterns = {
        {std::regex("ProFTPD\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase), "ProFTPD"},
        {std::regex("vsFTPd\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase), "vsFTPd"},
        {std::regex("FileZilla[^\\s]*\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase), "FileZilla"},
        {std::regex("Pure-FTPd\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase), "Pure-FTPd"},
        {std::regex("wu-ftp\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase), "Wu-FTP"},
        {std::regex("Microsoft\\s*FTP", std::regex::icase), "Microsoft FTP"},
        {std::regex("glFTPd", std::regex::icase), "glFTPd"},
        {std::regex("Serv-U", std::regex::icase), "Serv-U"}
    };

    for (const auto& p : ftp_patterns) {
        if (std::regex_search(banner, m, p.first)) {
            sr.extra["ftp_server"] = p.second;
            if (m.size() > 1 && m[1].matched) {
                sr.version = m[1].str();
            }
            break;
        }
    }

    // Features
    if (std::regex_search(std::string(), m, std::regex("Features?:\\s*([^\r\n]+)", std::regex::icase))) {
        sr.extra["features"] = strip(m[1].str());
    }

    // Check for AUTH TLS/SSL support
    if (std::regex_search(std::string(), std::regex("AUTH\\s+(TLS|SSL)", std::regex::icase))) {
        sr.extra["tls"] = "supported";
    }

    // Anonymous access
    if (std::regex_search(std::string(), std::regex("anonymous", std::regex::icase))) {
        sr.extra["anonymous"] = "yes";
    }

    // CPE
    std::string banner_lower = std::string(banner);
    std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), ::tolower);
    if (banner_lower.find("proftpd") != std::string::npos) {
        sr.cpe = "cpe:/a:proftpd:proftpd";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("vsftpd") != std::string::npos) {
        sr.cpe = "cpe:/a:vsftpd:vsftpd";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("pure-ftpd") != std::string::npos) {
        sr.cpe = "cpe:/a:pureftpd:pure-ftpd";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("filezilla") != std::string::npos) {
        sr.cpe = "cpe:/a:filezilla:filezilla_server";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    }
}

static void analyze_smtp(std::string_view banner, ServiceResult& sr) noexcept {
    std::smatch m;

    // SMTP banner: 220 mx.example.com ESMTP Postfix (Ubuntu)
    if (std::regex_search(std::string(), m, std::regex("220[\\s-]([^\r\n]+)", std::regex::icase))) {
        sr.extra["greeting"] = strip(m[1].str());
    }

    // Server identification
    std::vector<std::pair<std::regex, std::string>> smtp_patterns = {
        {std::regex("Postfix\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)?", std::regex::icase), "Postfix"},
        {std::regex("Exim\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)?", std::regex::icase), "Exim"},
        {std::regex("Sendmail\\s*([0-9]+\\.[0-9]+(\\.[0-9]+)?)?", std::regex::icase), "Sendmail"},
        {std::regex("Microsoft\\s*ESMTP|Exchange", std::regex::icase), "Exchange"},
        {std::regex("Qmail", std::regex::icase), "Qmail"},
        {std::regex("OpenSMTPD", std::regex::icase), "OpenSMTPD"},
        {std::regex("Courier", std::regex::icase), "Courier"},
        {std::regex("Cyrus\\s*SMTP", std::regex::icase), "Cyrus"}
    };

    for (const auto& p : smtp_patterns) {
        if (std::regex_search(banner, m, p.first)) {
            sr.extra["smtp_server"] = p.second;
            if (m.size() > 1 && m[1].matched) {
                sr.version = m[1].str();
            }
            break;
        }
    }

    // EHLO response - available commands
    if (std::regex_search(std::string(), std::regex("250[\\s-]AUTH\\s+", std::regex::icase))) {
        sr.extra["auth"] = "supported";
        // Extract auth methods
        if (std::regex_search(std::string(), m, std::regex("250[\\s-]AUTH\\s+([^\r\n]+)", std::regex::icase))) {
            sr.extra["auth_methods"] = strip(m[1].str());
        }
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]STARTTLS", std::regex::icase))) {
        sr.extra["starttls"] = "supported";
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]PIPELINING", std::regex::icase))) {
        sr.extra["pipelining"] = "supported";
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]SIZE\\s+\\d+", std::regex::icase))) {
        sr.extra["size_limit"] = "yes";
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]VRFY", std::regex::icase))) {
        sr.extra["vrfy"] = "enabled";
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]EXPN", std::regex::icase))) {
        sr.extra["expn"] = "enabled";
    }

    if (std::regex_search(std::string(), std::regex("250[\\s-]DSN", std::regex::icase))) {
        sr.extra["dsn"] = "supported";
    }

    // CPE
    std::string banner_lower = std::string(banner);
    std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), ::tolower);
    if (banner_lower.find("postfix") != std::string::npos) {
        sr.cpe = "cpe:/a:postfix:postfix";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("exim") != std::string::npos) {
        sr.cpe = "cpe:/a:exim:exim";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("sendmail") != std::string::npos) {
        sr.cpe = "cpe:/a:sendmail:sendmail";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    } else if (banner_lower.find("qmail") != std::string::npos) {
        sr.cpe = "cpe:/a:qmail:qmail";
        if (!sr.version.empty()) sr.cpe += ":" + sr.version;
    }
}

static void analyze_generic(std::string_view banner, ServiceResult& sr) noexcept {
    std::smatch m;

    // Try to extract any version-like pattern
    std::vector<std::regex> version_patterns = {
        std::regex("([0-9]+\\.[0-9]+\\.[0-9]+[a-zA-Z0-9._-]*)"),
        std::regex("([0-9]+\\.[0-9]+[a-zA-Z0-9._-]*)"),
        std::regex("v([0-9]+\\.[0-9]+(\\.[0-9]+)?)")
    };

    for (const auto& pat : version_patterns) {
        if (std::regex_search(banner, m, pat)) {
            sr.version = m[1].str();
            break;
        }
    }

    // Try to detect protocol/service from banner keywords
    std::vector<std::pair<std::string, std::string>> service_keywords = {
        {"redis", "Redis"}, {"mysql", "MySQL"}, {"postgresql", "PostgreSQL"},
        {"mongodb", "MongoDB"}, {"memcached", "Memcached"}, {"smtp", "SMTP"},
        {"pop3", "POP3"}, {"imap", "IMAP"}, {"ldap", "LDAP"}, {"rdp", "RDP"},
        {"vnc", "VNC"}, {"sip", "SIP"}, {"dns", "DNS"}, {"dhcp", "DHCP"},
        {"snmp", "SNMP"}, {"ntp", "NTP"}, {"telnet", "Telnet"},
        {"rlogin", "Rlogin"}, {"rsync", "Rsync"}
    };

    std::string banner_lower = std::string(banner);
    std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), ::tolower);

    for (const auto& sk : service_keywords) {
        if (banner_lower.find(sk.first) != std::string::npos) {
            sr.extra["detected_service"] = sk.second;
            break;
        }
    }
}

static int connect_and_grab_banner(std::string_view target, int port, int timeout_sec, std::string& out_banner) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    fd_set wfds, rfds;
    FD_ZERO(&wfds);
    FD_ZERO(&rfds);
    FD_SET(fd, &wfds);
    FD_SET(fd, &rfds);

    int sel = select(fd + 1, &rfds, &wfds, nullptr, &tv);
    if (sel <= 0) {
        close(fd);
        return -1;
    }

    // Try to read banner
    char buf[4096];
    int n;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    struct timeval read_tv;
    read_tv.tv_sec = 2;
    read_tv.tv_usec = 0;

    n = select(fd + 1, &read_fds, nullptr, nullptr, &read_tv);
    if (n > 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            out_banner = std::string(buf, n);
        }
    } else {
        // Maybe it's a service that waits for client input first (like HTTP)
        // Send a probe for common protocols
        const char* probes[] = {
            "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            "HELO localhost\r\n",
            "EHLO localhost\r\n",
            nullptr
        };

        for (int pi = 0; probes[pi]; ++pi) {
            write(fd, probes[pi], strlen(probes[pi]));
            usleep(200000);
            FD_ZERO(&read_fds);
            FD_SET(fd, &read_fds);
            read_tv.tv_sec = 2;
            read_tv.tv_usec = 0;
            n = select(fd + 1, &read_fds, nullptr, nullptr, &read_tv);
            if (n > 0) {
                n = read(fd, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = 0;
                    out_banner = std::string(buf, n);
                    break;
                }
            }
        }
    }

    close(fd);
    return out_banner.empty() ? -1 : 0;
}

static void analyze_banner(std::string_view banner, int port, ServiceResult& sr) noexcept {
    std::string banner_upper = std::string(banner);
    std::transform(banner_upper.begin(), banner_upper.end(), banner_upper.begin(), ::toupper);

    sr.service = "unknown";
    sr.cpe = "";
    sr.confidence = 50;

    if (banner_upper.find("HTTP/") != std::string::npos || banner_upper.find("HTTP") == 0) {
        sr.service = "HTTP";
        sr.protocol = "tcp";
        sr.confidence = 95;
        analyze_http(banner, sr);
    } else if (banner_upper.find("SSH-") != std::string::npos) {
        sr.service = "SSH";
        sr.protocol = "tcp";
        sr.confidence = 95;
        analyze_ssh(banner, sr);
    } else if (banner_upper.find("220") == 0 && (banner_upper.find("FTP") != std::string::npos ||
                banner_upper.find("PROFTPD") != std::string::npos ||
                banner_upper.find("VSFTPD") != std::string::npos)) {
        sr.service = "FTP";
        sr.protocol = "tcp";
        sr.confidence = 90;
        analyze_ftp(banner, sr);
    } else if (banner_upper.find("220") == 0 &&
               (banner_upper.find("SMTP") != std::string::npos ||
                banner_upper.find("ESMTP") != std::string::npos ||
                banner_upper.find("POSTFIX") != std::string::npos ||
                banner_upper.find("EXIM") != std::string::npos ||
                banner_upper.find("SENDMAIL") != std::string::npos ||
                banner_upper.find("MAIL") != std::string::npos)) {
        sr.service = "SMTP";
        sr.protocol = "tcp";
        sr.confidence = 90;
        analyze_smtp(banner, sr);
    } else if (banner_upper.find("220") == 0 && port == 25) {
        sr.service = "SMTP";
        sr.protocol = "tcp";
        sr.confidence = 85;
        analyze_smtp(banner, sr);
    } else if (banner_upper.find("220") == 0 && port == 110) {
        sr.service = "POP3";
        sr.protocol = "tcp";
        sr.confidence = 80;
    } else if (banner_upper.find("* OK") == 0 || banner_upper.find("* OK ") == 0) {
        sr.service = "IMAP";
        sr.protocol = "tcp";
        sr.confidence = 85;
        // Try to extract IMAP server version
        std::smatch m;
        if (std::regex_search(std::string(), m, std::regex("\\*\\s+OK\\s+\\[?([^\\]]+)"))) {
            sr.version = strip(m[1].str());
        }
    } else if (port == 443 || port == 8443 || banner_upper.find("SSL") != std::string::npos) {
        sr.service = "HTTPS";
        sr.protocol = "tcp";
        sr.confidence = 70;
    } else if (port == 3306 || banner_upper.find("MYSQL") != std::string::npos) {
        sr.service = "MySQL";
        sr.protocol = "tcp";
        sr.confidence = 85;
        if (std::regex_search(std::string(), std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
            std::smatch m;
            if (std::regex_search(std::string(), m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
                sr.version = m[1].str();
            }
        }
    } else if (port == 5432 || banner_upper.find("POSTGRESQL") != std::string::npos) {
        sr.service = "PostgreSQL";
        sr.protocol = "tcp";
        sr.confidence = 85;
    } else if (port == 6379 || banner_upper.find("REDIS") != std::string::npos) {
        sr.service = "Redis";
        sr.protocol = "tcp";
        sr.confidence = 85;
    } else if (port == 27017 || banner_upper.find("MONGODB") != std::string::npos) {
        sr.service = "MongoDB";
        sr.protocol = "tcp";
        sr.confidence = 80;
    } else if (port == 21) {
        sr.service = "FTP";
        sr.protocol = "tcp";
        sr.confidence = 60;
        analyze_ftp(banner, sr);
    } else if (port == 22) {
        sr.service = "SSH";
        sr.protocol = "tcp";
        sr.confidence = 60;
        analyze_ssh(banner, sr);
    } else if (port == 25 || port == 587 || port == 465) {
        sr.service = "SMTP";
        sr.protocol = "tcp";
        sr.confidence = 60;
        analyze_smtp(banner, sr);
    } else if (port == 80 || port == 8080 || port == 8000 || port == 3000 || port == 5000) {
        sr.service = "HTTP";
        sr.protocol = "tcp";
        sr.confidence = 60;
        analyze_http(banner, sr);
    } else {
        analyze_generic(banner, sr);
    }

    // Version override if we found one in generic analysis
    if (sr.version.empty()) {
        std::smatch m;
        if (std::regex_search(std::string(), m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+[a-zA-Z0-9._-]*)"))) {
            sr.version = m[1].str();
        } else if (std::regex_search(std::string(), m, std::regex("([0-9]+\\.[0-9]+[a-zA-Z0-9._-]*)"))) {
            sr.version = m[1].str();
        }
    }
}

struct Args {
    std::string target = "127.0.0.1";
    std::vector<int> ports;
    std::string banner;
    int timeout = 5;
    bool has_banner = false;
};

static Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) {
            args.target = argv[++i];
        } else if (arg == "--ports" && i + 1 < argc) {
            std::string ps = argv[++i];
            size_t pos = 0;
            while (pos < ps.size()) {
                size_t comma = ps.find(',', pos);
                std::string tok = ps.substr(pos, comma - pos);
                if (!tok.empty()) {
                    if (tok.find('-') != std::string::npos) {
                        size_t dash = tok.find('-');
                        int lo = std::stoi(tok.substr(0, dash));
                        int hi = std::stoi(tok.substr(dash + 1));
                        for (int p = lo; p <= hi; ++p) args.ports.emplace_back(p);
                    } else {
                        args.ports.emplace_back(std::stoi(tok));
                    }
                }
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        } else if (arg == "--banner" && i + 1 < argc) {
            args.banner = argv[++i];
            args.has_banner = true;
        } else if (arg == "--timeout" && i + 1 < argc) {
            args.timeout = std::atoi(argv[++i]);
            if (args.timeout < 1) args.timeout = 5;
        }
    }
    if (args.ports.empty()) args.ports.emplace_back(80);
    return args;
}

int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);
    std::vector<ServiceResult> results;

    if (args.has_banner && args.ports.size() == 1) {
        ServiceResult sr;
        sr.port = args.ports[0];
        sr.status = "open";
        sr.protocol = "tcp";
        sr.banner = args.banner;
        analyze_banner(args.banner, args.ports[0], sr);
        emit_result(sr);
        results.emplace_back(sr);
    } else {
        std::mutex results_mutex;
        std::vector<std::thread> threads;
threads.reserve(256);
for (int port : args.ports) {
            threads.emplace_back([&, port]() {
                std::string banner;
                int rc = connect_and_grab_banner(args.target, port, args.timeout, banner);

                ServiceResult sr;
                sr.port = port;
                sr.protocol = "tcp";

                if (rc < 0) {
                    sr.status = "closed";
                    sr.confidence = 95;
                    sr.service = "unknown";
                } else {
                    sr.status = "open";
                    sr.banner = banner;
                    analyze_banner(banner, port, sr);

                    if (sr.version.empty() && !banner.empty()) {
                        std::smatch m;
                        if (std::regex_search(std::string(), m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
                            sr.version = m[1].str();
                        }
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    emit_result(sr);
                    results.emplace_back(sr);
                }
            });
        }

        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }

    emit_final(results);
    return 0;
}
