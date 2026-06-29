#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <thread>
#include <mutex>
#include <cctype>
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


struct ParsedResponse {
    int port;
    std::string protocol;
    std::string raw;
    std::string status_line;
    int status_code;
    std::string status_message;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::string server;
    std::string version;
    std::string os_info;
    std::string banner;
    std::string service_type;
    std::vector<std::string> commands;
    std::vector<std::string> auth_methods;
    std::unordered_map<std::string, std::string> extensions;
    std::string error;
    int confidence;
    std::vector<std::string> warnings;
};

static std::mutex print_mutex;

static std::string json_escape(const std::string& s) {
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

static std::string strip(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return std::string(s.substr(a, b - a + 1));
}

static void emit_result(const ParsedResponse& pr) noexcept {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::string json;

    json += "RESULT:{\"port\":";
    json += std::to_string(pr.port);
    json += ",\"protocol\":\"";
    json += json_escape(pr.protocol);
    json += "\",\"service\":\"";
    json += json_escape(pr.service_type);
    json += "\",\"status_code\":";
    json += std::to_string(pr.status_code);
    json += ",\"status_line\":\"";
    json += json_escape(pr.status_line);
    json += "\",\"server\":\"";
    json += json_escape(pr.server);
    json += "\",\"version\":\"";
    json += json_escape(pr.version);
    json += "\",\"os_info\":\"";
    json += json_escape(pr.os_info);
    json += "\",\"banner\":\"";
    json += json_escape(pr.banner);
    json += "\",\"confidence\":";
    json += std::to_string(pr.confidence);
    json += ",\"error\":\"";
    json += json_escape(pr.error);
    json += "\"";

    json += ",\"headers\":{";
    bool hfirst = true;
    for (const auto& h : pr.headers) {
        if (!hfirst) json += ",";
        hfirst = false;
        json += "\"" + json_escape(h.first) + "\":\"" + json_escape(h.second) + "\"";
    }
    json += "}";

    if (!pr.commands.empty()) {
        json += ",\"commands\":[";
        for (size_t i = 0; i < pr.commands.size(); ++i) {
            if (i > 0) json += ",";
            json += "\"" + json_escape(pr.commands[i]) + "\"";
        }
        json += "]";
    }

    if (!pr.auth_methods.empty()) {
        json += ",\"auth_methods\":[";
        for (size_t i = 0; i < pr.auth_methods.size(); ++i) {
            if (i > 0) json += ",";
            json += "\"" + json_escape(pr.auth_methods[i]) + "\"";
        }
        json += "]";
    }

    if (!pr.extensions.empty()) {
        json += ",\"extensions\":{";
        bool efirst = true;
        for (const auto& e : pr.extensions) {
            if (!efirst) json += ",";
            efirst = false;
            json += "\"" + json_escape(e.first) + "\":\"" + json_escape(e.second) + "\"";
        }
        json += "}";
    }

    if (!pr.warnings.empty()) {
        json += ",\"warnings\":[";
        for (size_t i = 0; i < pr.warnings.size(); ++i) {
            if (i > 0) json += ",";
            json += "\"" + json_escape(pr.warnings[i]) + "\"";
        }
        json += "]";
    }

    json += "}";
    printf("%s\n", json.c_str());
    fflush(stdout);
}

static void emit_final(const std::vector<ParsedResponse>& results) noexcept {
    printf("FINAL:{\"engine\":\"response_parser\",\"response_count\":%zu,\"results\":[\n", results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& pr = results[i];
        printf("  {\"port\":%d,\"protocol\":\"%s\",\"service\":\"%s\",\"status_code\":%d,\"server\":\"%s\",\"version\":\"%s\",\"confidence\":%d}%s\n",
            pr.port, json_escape(pr.protocol).c_str(), json_escape(pr.service_type).c_str(),
            pr.status_code, json_escape(pr.server).c_str(), json_escape(pr.version).c_str(),
            pr.confidence, (i + 1 < results.size()) ? "," : "");
    }
    printf("]}\n");
    fflush(stdout);
}

// ---------- HTTP Parser ----------
static ParsedResponse parse_http(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "HTTP";
    pr.raw = raw;
    pr.service_type = "HTTP";
    pr.confidence = 95;

    std::smatch m;

    size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        header_end = raw.find("\n\n");
    }

    std::string header_section = raw;
    if (header_end != std::string::npos) {
        pr.body = raw.substr(header_end + (raw[header_end + 2] == '\r' ? 4 : 2));
        header_section = raw.substr(0, header_end);
    }

    std::istringstream hstream(header_section);
    std::string line;
    if (std::getline(hstream, line)) {
        pr.status_line = strip(line);
        if (std::regex_search(line, m, std::regex("HTTP/(\\d+\\.\\d+)\\s+(\\d+)\\s*(.*)"))) {
            pr.version = m[1].str();
            pr.status_code = std::stoi(m[2].str());
            pr.status_message = strip(m[3].str());
        }
    }

    while (std::getline(hstream, line)) {
        line = strip(line);
        if (line.empty()) continue;

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = strip(line.substr(0, colon));
            std::string val = strip(line.substr(colon + 1));
            pr.headers[key] = val;

            std::string kl = std::string(key);
            std::transform(kl.begin(), kl.end(), kl.begin(), ::tolower);

            if (kl == "server") {
                pr.server = val;
            } else if (kl == "x-powered-by") {
                std::smatch vm;
                if (std::regex_search(val, vm, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?"))) {
                    pr.version = vm[1].str();
                }
            } else if (kl == "set-cookie") {
                if (val.find("PHPSESSID") != std::string::npos) {
                    pr.extensions["technology"] = "PHP";
                } else if (val.find("JSESSIONID") != std::string::npos) {
                    pr.extensions["technology"] = "Java/J2EE";
                } else if (val.find("ASP.NET") != std::string::npos || val.find("ASPSESSION") != std::string::npos) {
                    pr.extensions["technology"] = "ASP.NET";
                }
            } else if (kl == "www-authenticate") {
                pr.auth_methods.emplace_back(val);
            }
        }
    }

    if (!pr.server.empty()) {
        std::string sl = pr.server;
        std::transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
        if (sl.find("ubuntu") != std::string::npos) pr.os_info = "Ubuntu Linux";
        else if (sl.find("debian") != std::string::npos) pr.os_info = "Debian Linux";
        else if (sl.find("centos") != std::string::npos) pr.os_info = "CentOS Linux";
        else if (sl.find("red hat") != std::string::npos || sl.find("redhat") != std::string::npos) pr.os_info = "Red Hat Linux";
        else if (sl.find("win") != std::string::npos || sl.find("microsoft") != std::string::npos) pr.os_info = "Windows";
        else if (sl.find("freebsd") != std::string::npos) pr.os_info = "FreeBSD";
        else if (sl.find("darwin") != std::string::npos || sl.find("apple") != std::string::npos) pr.os_info = "macOS";
    }

    if (pr.version.empty() && !pr.server.empty()) {
        std::smatch vm;
        if (std::regex_search(pr.server, vm, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?[a-zA-Z0-9]*)"))) {
            pr.version = vm[1].str();
        }
    }

    pr.banner = pr.status_line + " | Server: " + pr.server;
    return pr;
}

// ---------- SMTP Parser ----------
static ParsedResponse parse_smtp(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "SMTP";
    pr.raw = raw;
    pr.service_type = "SMTP";
    pr.confidence = 90;

    std::smatch m;
    std::string _raw(raw);
    std::istringstream stream(_raw);
    std::string line;

    while (std::getline(stream, line)) {
        line = strip(line);
        if (line.empty()) continue;

        if (std::regex_search(line, m, std::regex("^(\\d{3})([\\s-])(.*)"))) {
            int code = std::stoi(m[1].str());
            std::string rest = m[3].str();

            if (pr.status_code == 0) pr.status_code = code;
            pr.status_line = line;

            if (code == 220) {
                pr.banner = line;

                std::vector<std::pair<std::regex, std::string>> smtp_servers = {
                    {std::regex("Postfix", std::regex::icase), "Postfix"},
                    {std::regex("Exim", std::regex::icase), "Exim"},
                    {std::regex("Sendmail", std::regex::icase), "Sendmail"},
                    {std::regex("Qmail", std::regex::icase), "Qmail"},
                    {std::regex("Microsoft.*Exchange|Exchange", std::regex::icase), "Exchange"},
                    {std::regex("Courier", std::regex::icase), "Courier"},
                    {std::regex("Cyrus", std::regex::icase), "Cyrus"},
                    {std::regex("OpenSMTPD", std::regex::icase), "OpenSMTPD"}
                };

                for (const auto& sv : smtp_servers) {
                    if (std::regex_search(line, sv.first)) {
                        pr.server = sv.second;
                        break;
                    }
                }

                if (std::regex_search(line, m, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?[a-zA-Z0-9]*)"))) {
                    pr.version = m[1].str();
                }

                if (line.find("Ubuntu") != std::string::npos) pr.os_info = "Ubuntu Linux";
                else if (line.find("Debian") != std::string::npos) pr.os_info = "Debian Linux";
                else if (line.find("FreeBSD") != std::string::npos) pr.os_info = "FreeBSD";
            }

            if (code == 250) {
                size_t dash = line.find('-');
                size_t space = line.find(' ');
                std::string keyword;

                if (dash != std::string::npos) {
                    keyword = strip(line.substr(dash + 1));
                } else if (space != std::string::npos) {
                    keyword = strip(line.substr(space + 1));
                }

                if (!keyword.empty()) {
                    pr.commands.emplace_back(keyword);

                    if (keyword.find("AUTH") == 0) {
                        pr.extensions["auth"] = keyword;
                        std::string methods = keyword.substr(4);
                        std::istringstream ms(methods);
                        std::string method;
                        while (ms >> method) {
                            pr.auth_methods.emplace_back(method);
                        }
                    } else if (keyword.find("STARTTLS") == 0) {
                        pr.extensions["starttls"] = "yes";
                    } else if (keyword.find("SIZE") == 0) {
                        pr.extensions["size"] = keyword;
                    } else if (keyword.find("PIPELINING") == 0) {
                        pr.extensions["pipelining"] = "yes";
                    } else if (keyword.find("DSN") == 0) {
                        pr.extensions["dsn"] = "yes";
                    } else if (keyword.find("VRFY") == 0) {
                        pr.extensions["vrfy"] = "yes";
                    } else if (keyword.find("ETRN") == 0) {
                        pr.extensions["etrn"] = "yes";
                    } else if (keyword.find("ENHANCEDSTATUSCODES") == 0) {
                        pr.extensions["enhanced_status"] = "yes";
                    } else if (keyword.find("8BITMIME") == 0) {
                        pr.extensions["8bitmime"] = "yes";
                    } else if (keyword.find("CHUNKING") == 0) {
                        pr.extensions["chunking"] = "yes";
                    }
                }
            }

            if (code >= 500 && code < 600) {
                pr.warnings.emplace_back("SMTP error: " + line);
            }
        }
    }

    if (pr.server.empty() && !pr.banner.empty()) {
        std::string bl = pr.banner;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("postfix") != std::string::npos) pr.server = "Postfix";
        else if (bl.find("exim") != std::string::npos) pr.server = "Exim";
        else if (bl.find("sendmail") != std::string::npos) pr.server = "Sendmail";
        else if (bl.find("qmail") != std::string::npos) pr.server = "Qmail";
    }

    return pr;
}

// ---------- POP3 Parser ----------
static ParsedResponse parse_pop3(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "POP3";
    pr.raw = raw;
    pr.service_type = "POP3";
    pr.confidence = 85;

    std::smatch m;

    if (std::regex_search(raw, m, std::regex("\\+OK\\s*(.*)", std::regex::icase))) {
        pr.status_code = 200;
        pr.status_line = m[0].str();
        pr.banner = m[1].str();

        if (std::regex_search(pr.banner, m, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?"))) {
            pr.version = m[1].str();
        }

        std::string bl = pr.banner;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("dovecot") != std::string::npos) pr.server = "Dovecot";
        else if (bl.find("courier") != std::string::npos) pr.server = "Courier";
        else if (bl.find("cyrus") != std::string::npos) pr.server = "Cyrus";
        else if (bl.find("microsoft") != std::string::npos || bl.find("exchange") != std::string::npos) pr.server = "Exchange";
        else if (bl.find("qpopper") != std::string::npos) pr.server = "Qpopper";

        if (raw.find("CAPA") != std::string::npos) {
            std::string _raw(raw);
    std::istringstream stream(_raw);
            std::string line;
            bool in_capa = false;
            while (std::getline(stream, line)) {
                line = strip(line);
                if (line.find("CAPA") != std::string::npos) { in_capa = true; continue; }
                if (in_capa && line.find('.') == 0) break;
                if (in_capa && !line.empty() && line[0] != '-') {
                    pr.commands.emplace_back(line);
                    std::string ll = std::string(line);
                    std::transform(ll.begin(), ll.end(), ll.begin(), ::toupper);
                    if (ll == "STLS") pr.extensions["stls"] = "yes";
                    if (ll.find("SASL") != std::string::npos) {
                        pr.extensions["sasl"] = line;
                        std::string methods = line.substr(4);
                        std::istringstream ms(methods);
                        std::string method;
                        while (ms >> method) pr.auth_methods.emplace_back(method);
                    }
                }
            }
        }
    } else if (std::regex_search(raw, m, std::regex("-ERR\\s*(.*)", std::regex::icase))) {
        pr.status_code = 500;
        pr.error = m[1].str();
        pr.warnings.emplace_back("POP3 error: " + pr.error);
        pr.confidence = 60;
    }

    return pr;
}

// ---------- IMAP Parser ----------
static ParsedResponse parse_imap(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "IMAP";
    pr.raw = raw;
    pr.service_type = "IMAP";
    pr.confidence = 85;

    std::smatch m;

    if (std::regex_search(raw, m, std::regex("\\*\\s+OK\\s+(.*)", std::regex::icase))) {
        pr.status_code = 200;
        pr.status_line = m[0].str();
        pr.banner = m[1].str();

        if (std::regex_search(pr.banner, m, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?"))) {
            pr.version = m[1].str();
        }

        std::string bl = pr.banner;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("dovecot") != std::string::npos) pr.server = "Dovecot";
        else if (bl.find("courier") != std::string::npos) pr.server = "Courier";
        else if (bl.find("cyrus") != std::string::npos) pr.server = "Cyrus";

        if (raw.find("CAPABILITY") != std::string::npos) {
            std::string _raw(raw);
    std::istringstream stream(_raw);
            std::string line;
            bool in_cap = false;
            while (std::getline(stream, line)) {
                line = strip(line);
                if (line.find("CAPABILITY") != std::string::npos) { in_cap = true; continue; }
                if (in_cap && (line.find("*") == std::string::npos || line.find("OK") != std::string::npos)) break;
                if (in_cap && !line.empty()) {
                    std::istringstream ws(line);
                    std::string tok;
                    while (ws >> tok) {
                        if (tok != "*" && tok.find("OK") == std::string::npos) {
                            pr.commands.emplace_back(tok);
                        }
                    }
                }
            }
        }

        if (raw.find("LOGINDISABLED") != std::string::npos) {
            pr.warnings.emplace_back("LOGINDISABLED - plaintext auth disabled");
        }
        if (raw.find("STARTTLS") != std::string::npos) {
            pr.extensions["starttls"] = "yes";
        }
        if (raw.find("AUTH=PLAIN") != std::string::npos) pr.auth_methods.emplace_back("PLAIN");
        if (raw.find("AUTH=LOGIN") != std::string::npos) pr.auth_methods.emplace_back("LOGIN");
        if (raw.find("AUTH=CRAM-MD5") != std::string::npos) pr.auth_methods.emplace_back("CRAM-MD5");
        if (raw.find("AUTH=DIGEST-MD5") != std::string::npos) pr.auth_methods.emplace_back("DIGEST-MD5");
    } else if (std::regex_search(raw, m, std::regex("\\*\\s+(BYE|BAD|NO)\\s+(.*)", std::regex::icase))) {
        pr.status_code = 500;
        pr.error = m[2].str();
        pr.warnings.emplace_back("IMAP error: " + pr.error);
        pr.confidence = 60;
    }

    return pr;
}

// ---------- FTP Parser ----------
static ParsedResponse parse_ftp(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "FTP";
    pr.raw = raw;
    pr.service_type = "FTP";
    pr.confidence = 90;

    std::smatch m;

    std::string _raw(raw);
    std::istringstream stream(_raw);
    std::string line;
    while (std::getline(stream, line)) {
        line = strip(line);
        if (line.empty()) continue;

        if (std::regex_search(line, m, std::regex("^(\\d{3})([\\s-])(.*)"))) {
            int code = std::stoi(m[1].str());
            std::string rest = m[3].str();

            if (pr.status_code == 0) pr.status_code = code;
            pr.status_line = line;

            if (code == 220) {
                pr.banner = line;

                std::vector<std::pair<std::regex, std::string>> ftp_servers = {
                    {std::regex("ProFTPD", std::regex::icase), "ProFTPD"},
                    {std::regex("vsFTPd", std::regex::icase), "vsFTPd"},
                    {std::regex("Pure-FTPd", std::regex::icase), "Pure-FTPd"},
                    {std::regex("FileZilla", std::regex::icase), "FileZilla"},
                    {std::regex("Microsoft FTP", std::regex::icase), "Microsoft FTP"},
                    {std::regex("glFTPd", std::regex::icase), "glFTPd"},
                    {std::regex("Serv-U", std::regex::icase), "Serv-U"},
                    {std::regex("Wu-FTP", std::regex::icase), "Wu-FTP"}
                };

                for (const auto& sv : ftp_servers) {
                    if (std::regex_search(line, sv.first)) {
                        pr.server = sv.second;
                        break;
                    }
                }

                if (std::regex_search(line, m, std::regex("([0-9]+\\.[0-9]+(\\.[0-9]+)?"))) {
                    pr.version = m[1].str();
                }

                std::string ll = std::string(line);
                std::transform(ll.begin(), ll.end(), ll.begin(), ::tolower);
                if (ll.find("ubuntu") != std::string::npos) pr.os_info = "Ubuntu Linux";
                else if (ll.find("debian") != std::string::npos) pr.os_info = "Debian Linux";
                else if (ll.find("freebsd") != std::string::npos) pr.os_info = "FreeBSD";
            }

            if (code >= 500 && code < 600) {
                pr.warnings.emplace_back("FTP error: " + line);
            }
        }
    }

    if (pr.server.empty() && !pr.banner.empty()) {
        std::string bl = pr.banner;
        std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("proftpd") != std::string::npos) pr.server = "ProFTPD";
        else if (bl.find("vsftpd") != std::string::npos) pr.server = "vsFTPd";
        else if (bl.find("pure-ftpd") != std::string::npos) pr.server = "Pure-FTPd";
        else if (bl.find("filezilla") != std::string::npos) pr.server = "FileZilla";
    }

    return pr;
}

// ---------- SSH Parser ----------
static ParsedResponse parse_ssh(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "SSH";
    pr.raw = raw;
    pr.service_type = "SSH";
    pr.confidence = 95;

    std::smatch m;

    pr.banner = strip(raw);

    if (std::regex_search(raw, m, std::regex("SSH-([0-9\\.]+)-([^\\s]+)"))) {
        pr.status_line = m[0].str();
        pr.version = m[1].str();
        pr.server = strip(m[2].str());

        if (std::regex_search(raw, m, std::regex("([Oo]pen[Ss][Ss][Hh]_?([0-9]+\\.[0-9]+[^\\s]*))"))) {
            pr.server = "OpenSSH";
            if (m.size() > 2) pr.version = m[2].str();
        }
        if (raw.find("libssh") != std::string::npos) pr.server = "libssh";
        if (raw.find("Dropbear") != std::string::npos) pr.server = "Dropbear";
    }

    return pr;
}

// ---------- MySQL Parser ----------
static ParsedResponse parse_mysql(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "MySQL";
    pr.raw = raw;
    pr.service_type = "MySQL";
    pr.confidence = 85;

    // MySQL handshake: first byte is protocol version, followed by server version string
    if (raw.size() >= 5) {
        unsigned char proto_ver = (unsigned char)raw[0];
        pr.status_code = proto_ver;

        // Server version is null-terminated string starting at byte 1
        size_t end = raw.find('\0', 1);
        if (end != std::string::npos) {
            pr.server = raw.substr(1, end - 1);
            pr.banner = "MySQL Protocol " + std::to_string(proto_ver) + " - " + pr.server;
            pr.status_line = pr.banner;

            std::smatch m;
            if (std::regex_search(pr.server, m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
                pr.version = m[1].str();
            }
        }
    }

    return pr;
}

// ---------- PostgreSQL Parser ----------
static ParsedResponse parse_postgresql(const std::string& raw, int port) {
    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "PostgreSQL";
    pr.raw = raw;
    pr.service_type = "PostgreSQL";
    pr.confidence = 85;

    // PostgreSQL: 'R' (0x52) for authentication request, 'E' (0x45) for error
    if (raw.size() >= 8 && raw[0] == 'R') {
        pr.status_code = 200;
        pr.status_line = "PostgreSQL authentication request";

        // Try to extract version from error response
    } else if (raw.size() >= 8 && raw[0] == 'E') {
        pr.status_code = 500;
        pr.warnings.emplace_back("PostgreSQL error response");
    }

    // Look for version string
    std::smatch m;
    if (std::regex_search(raw, m, std::regex("PostgreSQL\\s+([0-9]+\\.[0-9]+(\\.[0-9]+)?)", std::regex::icase))) {
        pr.server = "PostgreSQL";
        pr.version = m[1].str();
        pr.banner = "PostgreSQL " + pr.version;
    }

    return pr;
}

// Main dispatch: detect protocol from raw data and/or port
static ParsedResponse parse_response(const std::string& raw, int port, const std::string& hint_protocol) {
    std::string upper = raw;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    // Protocol detection by content
    if (upper.find("HTTP/") != std::string::npos) {
        return parse_http(raw, port);
    }
    if (upper.find("SSH-") != std::string::npos) {
        return parse_ssh(raw, port);
    }
    if (upper.find("+OK") != std::string::npos) {
        return parse_pop3(raw, port);
    }
    if (upper.find("* OK") != std::string::npos || upper.find("*OK ") != std::string::npos) {
        return parse_imap(raw, port);
    }

    // Detect by port
    switch (port) {
        case 21: return parse_ftp(raw, port);
        case 22: return parse_ssh(raw, port);
        case 25: case 465: case 587: return parse_smtp(raw, port);
        case 80: case 8080: case 8000: case 3000: case 5000: case 443: case 8443:
            return parse_http(raw, port);
        case 110: return parse_pop3(raw, port);
        case 143: case 993: return parse_imap(raw, port);
        case 3306: return parse_mysql(raw, port);
        case 5432: return parse_postgresql(raw, port);
        default: break;
    }

    // Fallback: try each parser
    if (std::regex_search(raw, std::regex("^\\d{3}[\\s-]"))) {
        if (upper.find("ESMTP") != std::string::npos || upper.find("SMTP") != std::string::npos) {
            return parse_smtp(raw, port);
        }
        if (upper.find("FTP") != std::string::npos) {
            return parse_ftp(raw, port);
        }
    }

    if (!hint_protocol.empty()) {
        std::string hp = std::string(hint_protocol);
        std::transform(hp.begin(), hp.end(), hp.begin(), ::toupper);
        if (hp == "HTTP") return parse_http(raw, port);
        if (hp == "SMTP") return parse_smtp(raw, port);
        if (hp == "FTP") return parse_ftp(raw, port);
        if (hp == "SSH") return parse_ssh(raw, port);
        if (hp == "POP3") return parse_pop3(raw, port);
        if (hp == "IMAP") return parse_imap(raw, port);
        if (hp == "MYSQL") return parse_mysql(raw, port);
        if (hp == "POSTGRESQL") return parse_postgresql(raw, port);
    }

    ParsedResponse pr;
    pr.port = port;
    pr.protocol = "unknown";
    pr.raw = raw;
    pr.service_type = "unknown";
    pr.banner = raw;
    pr.confidence = 30;

    std::smatch m;
    if (std::regex_search(raw, m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
        pr.version = m[1].str();
    }

    return pr;
}

struct Args {
    std::string target = "127.0.0.1";
    int port = 80;
    std::string raw_data;
    std::string protocol_hint;
    int timeout = 5;
    bool has_raw = false;
};

static Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) args.target = argv[++i];
        else if (arg == "--port" && i + 1 < argc) args.port = std::atoi(argv[++i]);
        else if (arg == "--ports" && i + 1 < argc) {
            std::string ps = argv[++i];
            size_t comma = ps.find(',');
            args.port = std::stoi(ps.substr(0, comma));
        }
        else if (arg == "--raw" && i + 1 < argc) { args.raw_data = argv[++i]; args.has_raw = true; }
        else if (arg == "--banner" && i + 1 < argc) { args.raw_data = argv[++i]; args.has_raw = true; }
        else if (arg == "--protocol" && i + 1 < argc) args.protocol_hint = argv[++i];
        else if (arg == "--timeout" && i + 1 < argc) args.timeout = std::atoi(argv[++i]);
    }
    return args;
}

int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);
    std::vector<ParsedResponse> results;

    if (args.has_raw) {
        ParsedResponse pr = parse_response(args.raw_data, args.port, args.protocol_hint);
        emit_result(pr);
        results.emplace_back(pr);
    } else {
        // Read raw data from stdin (for piping)
        std::string input_data;
        std::string line;
        while (std::getline(std::cin, line)) {
            input_data += line + "\n";
        }
        if (!input_data.empty()) {
            ParsedResponse pr = parse_response(input_data, args.port, args.protocol_hint);
            emit_result(pr);
            results.emplace_back(pr);
        } else {
            ParsedResponse pr;
            pr.port = args.port;
            pr.protocol = "none";
            pr.service_type = "none";
            pr.error = "No input data provided";
            pr.confidence = 0;
            emit_result(pr);
            results.emplace_back(pr);
        }
    }

    emit_final(results);
    return 0;
}
