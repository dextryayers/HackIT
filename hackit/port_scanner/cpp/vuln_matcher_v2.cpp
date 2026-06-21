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
#include <set>
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


struct CVESignature {
    std::string id;
    std::string service;
    std::string version_operator; // "lt", "le", "eq", "ge", "gt"
    std::string version;
    std::string severity; // CRITICAL, HIGH, MEDIUM, LOW
    std::string description;
    double cvss;
    std::vector<std::string> affected_versions;
    std::string cpe;
};

struct MatchResult {
    std::string cve_id;
    std::string severity;
    double cvss;
    int confidence;
    std::string description;
};

struct AnalysisInput {
    int port;
    std::string service;
    std::string version;
    std::string banner;
    std::string cpe;
    std::string protocol;
};

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

// Version comparison: returns -1, 0, 1
static int cmp_version(std::string_view a, std::string_view b) noexcept {
    std::vector<int> pa, pb;
    std::string sa = std::string(a), sb = std::string(b);

    // Strip any non-numeric prefix
    auto strip_prefix = [](std::string& s) {
        size_t pos = 0;
        while (pos < s.size() && !isdigit(s[pos])) pos++;
        return std::string(s.substr(pos));
    };
    sa = strip_prefix(sa);
    sb = strip_prefix(sb);

    auto split = [](std::string_view s, std::vector<int>& out) {
        std::string cur;
        for (char c : s) {
            if (c == '.' || c == '-' || c == '_') {
                if (!cur.empty()) { out.emplace_back(std::stoi(cur)); cur.clear(); }
            } else if (isdigit(c)) {
                cur += c;
            } else {
                if (!cur.empty()) { out.emplace_back(std::stoi(cur)); cur.clear(); }
                break;
            }
        }
        if (!cur.empty()) out.emplace_back(std::stoi(cur));
    };
    split(sa, pa);
    split(sb, pb);

    size_t n = std::max(pa.size(), pb.size());
    for (size_t i = 0; i < n; ++i) {
        int va = (i < pa.size()) ? pa[i] : 0;
        int vb = (i < pb.size()) ? pb[i] : 0;
        if (va < vb) return -1;
        if (va > vb) return 1;
    }
    return 0;
}

static bool version_matches(std::string_view version, const CVESignature& sig) noexcept {
    if (version.empty() && !sig.version.empty()) return false;
    if (sig.version.empty()) return true;

    int cmp = cmp_version(version, sig.version);

    if (sig.version_operator == "lt") return cmp < 0;
    if (sig.version_operator == "le") return cmp <= 0;
    if (sig.version_operator == "eq") return cmp == 0;
    if (sig.version_operator == "ge") return cmp >= 0;
    if (sig.version_operator == "gt") return cmp > 0;

    // Check affected version list
    for (const auto& av : sig.affected_versions) {
        if (version.find(av) != std::string::npos) return true;
    }

    return false;
}

// Build the CVE database
static std::vector<CVESignature> build_cve_database() {
    std::vector<CVESignature> db;

    // ========== HTTP / Web Servers ==========
    db.push_back({"CVE-2023-44487", "HTTP", "lt", "2.4.58", "HIGH", "HTTP/2 Rapid Reset Attack", 7.5, {"Apache 2.4.0-2.4.57"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2023-25690", "HTTP", "lt", "2.4.56", "HIGH", "HTTP request splitting via mod_rewrite", 7.5, {"Apache 2.4.0-2.4.55"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2022-26377", "HTTP", "lt", "2.4.54", "MEDIUM", "HTTP request smuggling via mod_proxy_ajp", 6.5, {"Apache 2.4.0-2.4.53"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2021-44790", "HTTP", "lt", "2.4.52", "CRITICAL", "Buffer overflow in mod_lua parsing", 9.0, {"Apache 2.4.0-2.4.51"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2021-41773", "HTTP", "eq", "2.4.49", "CRITICAL", "Path traversal in Apache 2.4.49", 9.8, {}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2021-42013", "HTTP", "eq", "2.4.50", "CRITICAL", "Path traversal in Apache 2.4.50", 9.8, {}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2021-39275", "HTTP", "lt", "2.4.49", "MEDIUM", "NULL pointer dereference in mod_proxy", 5.0, {"Apache 2.4.0-2.4.48"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2020-1927", "HTTP", "lt", "2.4.44", "HIGH", "SSRF in mod_proxy with RewriteRule", 7.5, {"Apache 2.4.0-2.4.43"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2020-11993", "HTTP", "lt", "2.4.46", "MEDIUM", "SSRF via mod_proxy with RewriteRule", 6.5, {"Apache 2.4.0-2.4.45"}, "cpe:/a:apache:http_server"});
    db.push_back({"CVE-2019-0211", "HTTP", "lt", "2.4.39", "CRITICAL", "Local privilege escalation in Apache httpd", 9.8, {"Apache 2.4.12-2.4.38"}, "cpe:/a:apache:http_server"});

    // Nginx
    db.push_back({"CVE-2023-44487", "HTTP", "lt", "1.24.0", "HIGH", "HTTP/2 Rapid Reset Attack", 7.5, {"nginx 1.0.0-1.23.4"}, "cpe:/a:nginx:nginx"});
    db.push_back({"CVE-2022-41741", "HTTP", "lt", "1.23.4", "MEDIUM", "Memory disclosure in ngx_http_mp4_module", 6.5, {"nginx 1.0.0-1.23.3"}, "cpe:/a:nginx:nginx"});
    db.push_back({"CVE-2021-23017", "HTTP", "lt", "1.21.1", "MEDIUM", "DNS resolver vulnerability in nginx", 6.5, {"nginx 0.6.18-1.21.0"}, "cpe:/a:nginx:nginx"});
    db.push_back({"CVE-2019-20372", "HTTP", "lt", "1.17.7", "MEDIUM", "Directory traversal via misconfigured alias", 5.0, {"nginx 0.0.1-1.17.6"}, "cpe:/a:nginx:nginx"});
    db.push_back({"CVE-2018-16843", "HTTP", "lt", "1.15.6", "HIGH", "Memory disclosure in HTTP/2 module", 7.5, {"nginx 1.9.5-1.15.5"}, "cpe:/a:nginx:nginx"});

    // IIS
    db.push_back({"CVE-2023-38156", "HTTP", "lt", "10.0.17763.4974", "CRITICAL", "RCE in Windows IIS via HTTP/2", 9.8, {"IIS 10.0"}, "cpe:/a:microsoft:iis"});
    db.push_back({"CVE-2022-21907", "HTTP", "lt", "10.0.20348.469", "CRITICAL", "RCE in HTTP Protocol Stack (HTTP.sys)", 9.8, {"IIS 10.0"}, "cpe:/a:microsoft:iis"});
    db.push_back({"CVE-2021-31166", "HTTP", "eq", "10.0.0", "CRITICAL", "RCE in HTTP.sys driver", 9.8, {"IIS 10.0"}, "cpe:/a:microsoft:iis"});

    // ========== SSH ==========
    db.push_back({"CVE-2023-48795", "SSH", "lt", "9.6", "MEDIUM", "Terrapin Attack - Prefix truncation in SSH", 5.9, {"OpenSSH 1.0-9.5"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2023-38408", "SSH", "lt", "8.9", "CRITICAL", "RCE in OpenSSH forwarded SSH agent", 9.8, {"OpenSSH 8.5-8.8"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2023-25136", "SSH", "lt", "9.2", "MEDIUM", "Double-free in sshd", 6.5, {"OpenSSH 8.0-9.1"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2021-41617", "SSH", "lt", "8.8", "MEDIUM", "Privilege escalation via user existence oracle", 5.5, {"OpenSSH 7.0-8.7"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2020-15778", "SSH", "lt", "8.4", "MEDIUM", "Command injection in scp", 6.4, {"OpenSSH 1.0-8.3"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2019-6111", "SSH", "lt", "7.9", "MEDIUM", "File overwrite in scp", 5.9, {"OpenSSH 1.0-7.8"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2018-15473", "SSH", "lt", "7.7", "MEDIUM", "User enumeration via timing differential", 5.3, {"OpenSSH 2.0-7.6"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2016-10009", "SSH", "lt", "7.4", "HIGH", "RCE in ssh-agent PKCS#11", 8.0, {"OpenSSH 1.0-7.3"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2016-0777", "SSH", "lt", "7.1", "MEDIUM", "Session information leak via roaming", 5.9, {"OpenSSH 5.4-7.0"}, "cpe:/a:openbsd:openssh"});
    db.push_back({"CVE-2015-5600", "SSH", "lt", "7.0", "MEDIUM", "MaxAuthTries bypass via keyboard-interactive", 6.9, {"OpenSSH 1.0-6.9"}, "cpe:/a:openbsd:openssh"});

    // Dropbear
    db.push_back({"CVE-2023-36328", "SSH", "lt", "2022.83", "HIGH", "Buffer overflow in Dropbear", 8.0, {"Dropbear 0.8-2022.82"}, "cpe:/a:dropbear_ssh:dropbear_ssh"});
    db.push_back({"CVE-2021-36369", "SSH", "lt", "2020.81", "MEDIUM", "Out-of-bounds read in Dropbear", 5.5, {"Dropbear 0.6-2020.80"}, "cpe:/a:dropbear_ssh:dropbear_ssh"});

    // ========== FTP ==========
    db.push_back({"CVE-2023-51786", "FTP", "lt", "1.3.8", "HIGH", "Buffer overflow in ProFTPD mod_sftp", 8.1, {"ProFTPD 1.3.0-1.3.7"}, "cpe:/a:proftpd:proftpd"});
    db.push_back({"CVE-2023-36060", "FTP", "lt", "1.3.8a", "HIGH", "Authentication bypass in ProFTPD", 8.1, {"ProFTPD 1.3.0-1.3.8"}, "cpe:/a:proftpd:proftpd"});
    db.push_back({"CVE-2021-3514", "FTP", "lt", "1.3.7a", "MEDIUM", "Out-of-bounds read in mod_quotatab", 5.5, {"ProFTPD 1.3.7"}, "cpe:/a:proftpd:proftpd"});
    db.push_back({"CVE-2020-9272", "FTP", "lt", "1.3.7", "HIGH", "Buffer overflow in ProFTPD mod_proxy", 8.0, {"ProFTPD 1.3.5-1.3.6"}, "cpe:/a:proftpd:proftpd"});
    db.push_back({"CVE-2019-18217", "FTP", "lt", "1.3.6b", "MEDIUM", "Information disclosure in ProFTPD", 5.5, {"ProFTPD 1.3.6-1.3.6a"}, "cpe:/a:proftpd:proftpd"});

    // vsFTPd
    db.push_back({"CVE-2021-3618", "FTP", "eq", "3.0.3", "MEDIUM", "Denial of service in vsFTPd", 5.5, {"vsFTPd 3.0.3"}, "cpe:/a:vsftpd:vsftpd"});
    db.push_back({"CVE-2015-1419", "FTP", "lt", "3.0.3", "HIGH", "Memory exhaustion in vsFTPd", 7.5, {"vsFTPd 2.0.0-3.0.2"}, "cpe:/a:vsftpd:vsftpd"});
    db.push_back({"CVE-2011-0762", "FTP", "lt", "2.3.4", "HIGH", "Buffer overflow in vsFTPd", 8.0, {"vsFTPd 2.0.0-2.3.3"}, "cpe:/a:vsftpd:vsftpd"});

    // Pure-FTPd
    db.push_back({"CVE-2020-9274", "FTP", "lt", "1.0.50", "MEDIUM", "Directory traversal in Pure-FTPd", 5.5, {"Pure-FTPd 1.0.0-1.0.49"}, "cpe:/a:pureftpd:pure-ftpd"});
    db.push_back({"CVE-2011-0418", "FTP", "lt", "1.0.32", "HIGH", "Memory corruption in Pure-FTPd", 7.5, {"Pure-FTPd 1.0.0-1.0.31"}, "cpe:/a:pureftpd:pure-ftpd"});

    // ========== SMTP ==========
    // Postfix
    db.push_back({"CVE-2023-51764", "SMTP", "lt", "3.8.5", "CRITICAL", "RCE in Postfix SMTP server", 9.8, {"Postfix 2.0-3.8.4"}, "cpe:/a:postfix:postfix"});
    db.push_back({"CVE-2023-26609", "SMTP", "lt", "3.7.5", "MEDIUM", "Denial of service via SMTP smuggling", 5.5, {"Postfix 3.0-3.7.4"}, "cpe:/a:postfix:postfix"});
    db.push_back({"CVE-2022-23267", "SMTP", "lt", "3.6.7", "MEDIUM", "Memory leak in Postfix", 5.5, {"Postfix 3.0-3.6.6"}, "cpe:/a:postfix:postfix"});
    db.push_back({"CVE-2021-32055", "SMTP", "lt", "3.5.13", "MEDIUM", "SMTP smuggling in Postfix", 5.5, {"Postfix 3.0-3.5.12"}, "cpe:/a:postfix:postfix"});
    db.push_back({"CVE-2020-13757", "SMTP", "lt", "3.5.4", "MEDIUM", "Out-of-bounds read in Postfix", 5.5, {"Postfix 3.0-3.5.3"}, "cpe:/a:postfix:postfix"});

    // Exim
    db.push_back({"CVE-2023-42115", "SMTP", "lt", "4.96.1", "CRITICAL", "RCE in Exim SMTP server", 9.8, {"Exim 4.0-4.96"}, "cpe:/a:exim:exim"});
    db.push_back({"CVE-2023-42114", "SMTP", "lt", "4.96.1", "CRITICAL", "Buffer overflow in Exim", 9.8, {"Exim 4.0-4.96"}, "cpe:/a:exim:exim"});
    db.push_back({"CVE-2022-37452", "SMTP", "lt", "4.95", "HIGH", "Buffer overflow in Exim SPF", 8.1, {"Exim 4.90-4.94"}, "cpe:/a:exim:exim"});
    db.push_back({"CVE-2022-37451", "SMTP", "lt", "4.95", "MEDIUM", "Use-after-free in Exim", 6.5, {"Exim 4.90-4.94"}, "cpe:/a:exim:exim"});
    db.push_back({"CVE-2021-38371", "SMTP", "lt", "4.95", "HIGH", "Buffer overflow in Exim STARTTLS", 8.0, {"Exim 4.90-4.94"}, "cpe:/a:exim:exim"});
    db.push_back({"CVE-2020-28019", "SMTP", "lt", "4.94", "CRITICAL", "RCE in Exim", 9.8, {"Exim 4.0-4.93"}, "cpe:/a:exim:exim"});

    // Sendmail
    db.push_back({"CVE-2021-33829", "SMTP", "lt", "8.17.1", "HIGH", "Buffer overflow in Sendmail", 8.0, {"Sendmail 8.0-8.17.0"}, "cpe:/a:sendmail:sendmail"});
    db.push_back({"CVE-2020-14060", "SMTP", "lt", "8.16.1", "MEDIUM", "Use-after-free in Sendmail", 6.5, {"Sendmail 8.0-8.16.0"}, "cpe:/a:sendmail:sendmail"});
    db.push_back({"CVE-2019-19920", "SMTP", "lt", "8.15.2", "HIGH", "Privilege escalation in Sendmail", 7.8, {"Sendmail 8.0-8.15.1"}, "cpe:/a:sendmail:sendmail"});

    // ========== MySQL ==========
    db.push_back({"CVE-2023-22102", "MySQL", "lt", "8.0.34", "MEDIUM", "Optimizer vulnerability in MySQL", 6.5, {"MySQL 8.0.0-8.0.33"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2023-22053", "MySQL", "lt", "8.0.33", "HIGH", "DoS in MySQL InnoDB", 7.5, {"MySQL 8.0.0-8.0.32"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2023-21971", "MySQL", "lt", "8.0.32", "HIGH", "RCE in MySQL Connector/J", 8.0, {"MySQL 8.0.0-8.0.31"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2022-21367", "MySQL", "lt", "8.0.27", "MEDIUM", "DoS in MySQL Server", 6.5, {"MySQL 8.0.0-8.0.26"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2022-21245", "MySQL", "lt", "8.0.27", "MEDIUM", "Privilege escalation in MySQL", 6.0, {"MySQL 8.0.0-8.0.26"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2021-35604", "MySQL", "lt", "8.0.27", "HIGH", "Buffer overflow in MySQL", 8.0, {"MySQL 8.0.17-8.0.26"}, "cpe:/a:mysql:mysql"});
    db.push_back({"CVE-2021-34578", "MySQL", "lt", "5.7.36", "MEDIUM", "DoS in InnoDB", 6.5, {"MySQL 5.7.0-5.7.35"}, "cpe:/a:mysql:mysql"});

    // MariaDB
    db.push_back({"CVE-2023-22015", "MySQL", "lt", "10.11.5", "MEDIUM", "Buffer overflow in MariaDB", 6.5, {"MariaDB 10.11.0-10.11.4"}, "cpe:/a:mariadb:mariadb"});

    // ========== PostgreSQL ==========
    db.push_back({"CVE-2023-5869", "PostgreSQL", "lt", "16.1", "HIGH", "Buffer overrun in PostgreSQL", 8.0, {"PostgreSQL 16.0"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2023-5868", "PostgreSQL", "lt", "16.1", "MEDIUM", "Memory disclosure in PostgreSQL", 6.5, {"PostgreSQL 12-16"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2023-39417", "PostgreSQL", "lt", "15.4", "MEDIUM", "Extension loading vulnerability", 6.5, {"PostgreSQL 15.0-15.3"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2022-2625", "PostgreSQL", "lt", "14.5", "MEDIUM", "Privilege escalation via extensions", 6.5, {"PostgreSQL 10-14.4"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2022-1552", "PostgreSQL", "lt", "14.4", "HIGH", "Buffer overflow in PostgreSQL", 8.8, {"PostgreSQL 10-14.3"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2021-23222", "PostgreSQL", "lt", "13.2", "HIGH", "RCE in PostgreSQL", 8.0, {"PostgreSQL 9.0-13.1"}, "cpe:/a:postgresql:postgresql"});
    db.push_back({"CVE-2021-20229", "PostgreSQL", "lt", "13.2", "HIGH", "SQL injection in PostgreSQL", 8.0, {"PostgreSQL 9.0-13.1"}, "cpe:/a:postgresql:postgresql"});

    // ========== Redis ==========
    db.push_back({"CVE-2023-45145", "Redis", "lt", "7.2.2", "CRITICAL", "RCE in Redis Lua scripting", 9.0, {"Redis 7.0-7.2.1"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2023-41056", "Redis", "lt", "7.2.2", "MEDIUM", "Memory leak in Redis", 5.5, {"Redis 7.2.0-7.2.1"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2023-28857", "Redis", "lt", "7.0.11", "MEDIUM", "Information disclosure in Redis", 5.5, {"Redis 7.0.0-7.0.10"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2022-35951", "Redis", "lt", "7.0.8", "MEDIUM", "Buffer overflow in Redis", 6.5, {"Redis 7.0.0-7.0.7"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2022-24834", "Redis", "lt", "7.0.2", "MEDIUM", "Memory corruption in Redis", 6.5, {"Redis 6.2.0-7.0.1"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2022-0543", "Redis", "lt", "6.2.7", "CRITICAL", "Lua sandbox escape in Redis", 9.0, {"Redis 6.2.0-6.2.6"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2021-32675", "Redis", "lt", "6.2.4", "HIGH", "RCE in Redis Lua", 8.0, {"Redis 6.2.0-6.2.3"}, "cpe:/a:redis:redis"});
    db.push_back({"CVE-2021-29477", "Redis", "lt", "6.2.3", "CRITICAL", "Integer overflow in Redis", 9.0, {"Redis 6.2.0-6.2.2"}, "cpe:/a:redis:redis"});

    // ========== MongoDB ==========
    db.push_back({"CVE-2023-34088", "MongoDB", "lt", "7.0.2", "MEDIUM", "DoS in MongoDB wire protocol", 6.5, {"MongoDB 7.0.0-7.0.1"}, "cpe:/a:mongodb:mongodb"});
    db.push_back({"CVE-2022-42424", "MongoDB", "lt", "6.0.5", "HIGH", "Buffer overflow in MongoDB", 8.0, {"MongoDB 6.0.0-6.0.4"}, "cpe:/a:mongodb:mongodb"});
    db.push_back({"CVE-2022-38256", "MongoDB", "lt", "5.0.14", "MEDIUM", "Memory disclosure in MongoDB", 6.5, {"MongoDB 5.0.0-5.0.13"}, "cpe:/a:mongodb:mongodb"});

    // ========== SMTP (continued - Qmail) ==========
    db.push_back({"CVE-2023-38119", "SMTP", "lt", "1.0.8", "CRITICAL", "Buffer overflow in Qmail", 9.0, {"Qmail 1.0.0-1.0.7"}, "cpe:/a:qmail:qmail"});
    db.push_back({"CVE-2005-1513", "SMTP", "lt", "1.03", "CRITICAL", "RCE in Qmail", 9.8, {"Qmail 1.0-1.02"}, "cpe:/a:qmail:qmail"});

    // ========== TLS / SSL ==========
    db.push_back({"CVE-2023-38156", "HTTPS", "lt", "1.1.1v", "CRITICAL", "RCE in OpenSSL", 9.8, {"OpenSSL 1.0.1-1.1.1u"}, "cpe:/a:openssl:openssl"});
    db.push_back({"CVE-2022-3786", "HTTPS", "lt", "3.0.7", "CRITICAL", "Buffer overflow in OpenSSL X.509", 9.8, {"OpenSSL 3.0.0-3.0.6"}, "cpe:/a:openssl:openssl"});
    db.push_back({"CVE-2022-3602", "HTTPS", "lt", "3.0.7", "CRITICAL", "Buffer overflow in OpenSSL X.509", 9.8, {"OpenSSL 3.0.0-3.0.6"}, "cpe:/a:openssl:openssl"});
    db.push_back({"CVE-2022-2274", "HTTPS", "lt", "3.0.5", "HIGH", "Heap corruption in OpenSSL RSA", 8.0, {"OpenSSL 3.0.0-3.0.4"}, "cpe:/a:openssl:openssl"});
    db.push_back({"CVE-2022-2068", "HTTPS", "lt", "1.1.1q", "MEDIUM", "Buffer overflow in OpenSSL", 6.5, {"OpenSSL 1.1.1-1.1.1p"}, "cpe:/a:openssl:openssl"});

    // ========== POP3 / IMAP ==========
    db.push_back({"CVE-2023-42116", "IMAP", "lt", "3.0.15", "CRITICAL", "RCE in Cyrus IMAP", 9.8, {"Cyrus IMAP 3.0.0-3.0.14"}, "cpe:/a:cyrus:imap"});
    db.push_back({"CVE-2022-37453", "IMAP", "lt", "3.4.4", "HIGH", "Buffer overflow in Dovecot IMAP", 8.0, {"Dovecot 2.0-3.4.3"}, "cpe:/a:dovecot:dovecot"});
    db.push_back({"CVE-2021-33515", "IMAP", "lt", "2.3.15", "MEDIUM", "DoS in Dovecot", 5.5, {"Dovecot 2.0-2.3.14"}, "cpe:/a:dovecot:dovecot"});

    // ========== DNS ==========
    db.push_back({"CVE-2023-50387", "DNS", "lt", "9.18.24", "CRITICAL", "RCE in BIND DNS", 9.8, {"BIND 9.0-9.18.23"}, "cpe:/a:isc:bind"});
    db.push_back({"CVE-2023-3341", "DNS", "lt", "9.18.20", "HIGH", "Buffer overflow in BIND", 8.0, {"BIND 9.16.0-9.18.19"}, "cpe:/a:isc:bind"});
    db.push_back({"CVE-2022-2795", "DNS", "lt", "9.18.7", "HIGH", "DoS in BIND", 7.5, {"BIND 9.0-9.18.6"}, "cpe:/a:isc:bind"});

    // ========== LDAP ==========
    db.push_back({"CVE-2023-2953", "LDAP", "lt", "2.6.4", "HIGH", "Buffer overflow in OpenLDAP", 8.0, {"OpenLDAP 2.0-2.6.3"}, "cpe:/a:openldap:openldap"});
    db.push_back({"CVE-2022-29155", "LDAP", "lt", "2.5.13", "MEDIUM", "Information disclosure in OpenLDAP", 6.5, {"OpenLDAP 2.5.0-2.5.12"}, "cpe:/a:openldap:openldap"});

    // ========== Generic / Multi-service ==========
    db.push_back({"CVE-2023-44487", "HTTP", "lt", "2.4.58", "HIGH", "HTTP/2 Rapid Reset Attack", 7.5, {}, ""});
    db.push_back({"CVE-2023-38325", "HTTP", "lt", "1.5.3", "CRITICAL", "RCE in Apache Struts", 9.0, {"Apache Struts 2.0-2.5.32"}, "cpe:/a:apache:struts"});
    db.push_back({"CVE-2022-22965", "HTTP", "lt", "5.3.18", "CRITICAL", "Spring4Shell RCE", 9.8, {"Spring Framework 5.3.0-5.3.17"}, "cpe:/a:springsource:spring_framework"});
    db.push_back({"CVE-2021-44228", "HTTP", "lt", "2.17.1", "CRITICAL", "Log4Shell RCE", 10.0, {"Log4j 2.0-2.14.1"}, "cpe:/a:apache:log4j"});
    db.push_back({"CVE-2022-22963", "HTTP", "lt", "3.0.7", "CRITICAL", "Spring Cloud Function RCE", 9.8, {"Spring Cloud Function 3.0.0-3.0.6"}, "cpe:/a:springsource:spring_cloud_function"});
    db.push_back({"CVE-2022-1388", "HTTP", "lt", "17.0.0", "CRITICAL", "F5 BIG-IP RCE", 9.8, {"F5 BIG-IP 11.0-16.1"}, "cpe:/a:f5:big-ip"});
    db.push_back({"CVE-2021-34473", "HTTP", "lt", "15.1.0", "CRITICAL", "Microsoft Exchange ProxyLogon RCE", 9.8, {"Exchange 2013-2019"}, "cpe:/a:microsoft:exchange_server"});

    // ========== VNC ==========
    db.push_back({"CVE-2023-40362", "VNC", "lt", "0.9.14", "HIGH", "Buffer overflow in TightVNC", 8.0, {"TightVNC 0.5-0.9.13"}, "cpe:/a:tightvnc:tightvnc"});

    return db;
}

static std::string toupper_str(std::string_view s) {
    std::string r = std::string(s);
    std::transform(r.begin(), r.end(), r.begin(), ::toupper);
    return r;
}

static std::vector<MatchResult> match_cves(const AnalysisInput& input, const std::vector<CVESignature>& db) {
    std::vector<MatchResult> matches;
    std::string svc = toupper_str(input.service);

    std::set<std::string> matched_ids;

    // Binary search range by service name
    auto cmp_sig_lower = [](const CVESignature& a, std::string_view b) {
        return toupper_str(a.service) < b;
    };
    auto cmp_sig_upper = [](std::string_view a, const CVESignature& b) {
        return a < toupper_str(b.service);
    };

    auto low = std::lower_bound(db.begin(), db.end(), svc, cmp_sig_lower);
    auto high = std::upper_bound(db.begin(), db.end(), svc, cmp_sig_upper);

    for (auto it = low; it != high; ++it) {
        const auto& sig = *it;

        bool service_match = true;

        if (!service_match) continue;

        if (matched_ids.count(sig.id)) continue;

        if (!version_matches(input.version, sig)) continue;

        MatchResult mr;
        mr.cve_id = sig.id;
        mr.severity = sig.severity;
        mr.cvss = sig.cvss;
        mr.description = sig.description;

        int conf = 70;
        if (!input.version.empty()) conf += 15;
        if (!input.cpe.empty()) conf += 10;
        if (sig.severity == "CRITICAL") conf += 5;
        mr.confidence = std::min(conf, 99);

        matches.emplace_back(mr);
        matched_ids.insert(sig.id);
    }

    return matches;
}

static void emit_result(const AnalysisInput& input, const std::vector<MatchResult>& matches) noexcept {
    std::string json;

    json += "RESULT:{\"port\":";
    json += std::to_string(input.port);
    json += ",\"service\":\"";
    json += json_escape(input.service);
    json += "\",\"version\":\"";
    json += json_escape(input.version);
    json += "\",\"protocol\":\"";
    json += json_escape(input.protocol);
    json += "\",\"cpe\":\"";
    json += json_escape(input.cpe);
    json += "\"";

    // Overall severity
    std::string overall_severity = "NONE";
    double max_cvss = 0.0;
    for (const auto& m : matches) {
        if (m.cvss > max_cvss) max_cvss = m.cvss;
    }
    if (max_cvss >= 9.0) overall_severity = "CRITICAL";
    else if (max_cvss >= 7.0) overall_severity = "HIGH";
    else if (max_cvss >= 4.0) overall_severity = "MEDIUM";
    else if (max_cvss > 0.0) overall_severity = "LOW";

    json += ",\"severity\":\"";
    json += overall_severity;
    json += "\",\"max_cvss\":";
    json += std::to_string(max_cvss);

    json += ",\"cve_count\":";
    json += std::to_string(matches.size());

    json += ",\"cve\":[";
    for (size_t i = 0; i < matches.size(); ++i) {
        if (i > 0) json += ",";
        json += "{\"id\":\"";
        json += json_escape(matches[i].cve_id);
        json += "\",\"severity\":\"";
        json += json_escape(matches[i].severity);
        json += "\",\"cvss\":";
        char cvss_buf[16];
        snprintf(cvss_buf, sizeof(cvss_buf), "%.1f", matches[i].cvss);
        json += cvss_buf;
        json += ",\"confidence\":";
        json += std::to_string(matches[i].confidence);
        json += ",\"description\":\"";
        json += json_escape(matches[i].description);
        json += "\"}";
    }
    json += "]}";

    printf("%s\n", json.c_str());
    fflush(stdout);
}

static void emit_final(const std::vector<AnalysisInput>& inputs,
                       const std::unordered_map<int, std::vector<MatchResult>>& all_matches) {
    printf("FINAL:{\"engine\":\"vuln_matcher_v2\",\"ports_analyzed\":%zu,\"total_vulnerabilities\":%zu,\"results\":[\n",
        inputs.size(),
        [&]() -> size_t {
            size_t total = 0;
            for (const auto& kv : all_matches) total += kv.second.size();
            return total;
        }());

    bool first = true;
    for (const auto& input : inputs) {
        auto it = all_matches.find(input.port);
        if (it == all_matches.end() || it->second.empty()) continue;

        if (!first) printf(",\n");
        first = false;

        printf("  {\"port\":%d,\"service\":\"%s\",\"version\":\"%s\",\"cve_count\":%zu,\"severity\":\"%s\"",
            input.port, json_escape(input.service).c_str(),
            json_escape(input.version).c_str(),
            it->second.size(),
            [&]() -> std::string {
                double maxc = 0;
                for (const auto& m : it->second) if (m.cvss > maxc) maxc = m.cvss;
                if (maxc >= 9.0) return "CRITICAL";
                if (maxc >= 7.0) return "HIGH";
                if (maxc >= 4.0) return "MEDIUM";
                if (maxc > 0.0) return "LOW";
                return "NONE";
            }().c_str());

        printf(",\"cves\":[");
        for (size_t j = 0; j < it->second.size(); ++j) {
            if (j > 0) printf(",");
            printf("{\"id\":\"%s\",\"cvss\":%.1f}",
                json_escape(it->second[j].cve_id).c_str(), it->second[j].cvss);
        }
        printf("]}");
    }
    printf("\n]}\n");
    fflush(stdout);
}

struct Args {
    std::string target = "127.0.0.1";
    int port = 80;
    std::string service = "HTTP";
    std::string version;
    std::string banner;
    std::string cpe;
    std::string protocol = "tcp";
    int timeout = 5;
};

static Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) args.target = argv[++i];
        else if (arg == "--port" && i + 1 < argc) args.port = std::atoi(argv[++i]);
        else if (arg == "--ports" && i + 1 < argc) { /* ignore, use first */
            std::string ps = argv[++i];
            size_t comma = ps.find(',');
            args.port = std::stoi(ps.substr(0, comma));
        }
        else if (arg == "--service" && i + 1 < argc) args.service = argv[++i];
        else if (arg == "--version" && i + 1 < argc) args.version = argv[++i];
        else if (arg == "--banner" && i + 1 < argc) args.banner = argv[++i];
        else if (arg == "--cpe" && i + 1 < argc) args.cpe = argv[++i];
        else if (arg == "--protocol" && i + 1 < argc) args.protocol = argv[++i];
        else if (arg == "--timeout" && i + 1 < argc) args.timeout = std::atoi(argv[++i]);
    }
    return args;
}

int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);

    // Auto-detect service from port if not specified
    if (args.service.empty() || args.service == "unknown") {
        switch (args.port) {
            case 21: args.service = "FTP"; break;
            case 22: args.service = "SSH"; break;
            case 23: args.service = "Telnet"; break;
            case 25: case 465: case 587: args.service = "SMTP"; break;
            case 53: args.service = "DNS"; break;
            case 80: case 443: case 8080: case 8443: args.service = "HTTP"; break;
            case 110: args.service = "POP3"; break;
            case 143: case 993: args.service = "IMAP"; break;
            case 389: case 636: args.service = "LDAP"; break;
            case 3306: args.service = "MySQL"; break;
            case 5432: args.service = "PostgreSQL"; break;
            case 6379: args.service = "Redis"; break;
            case 27017: args.service = "MongoDB"; break;
            default: args.service = "unknown"; break;
        }
    }

    AnalysisInput input;
    input.port = args.port;
    input.service = args.service;
    input.version = args.version;
    input.banner = args.banner;
    input.cpe = args.cpe;
    input.protocol = args.protocol;

    // Try to extract version from banner if not provided
    if (input.version.empty() && !input.banner.empty()) {
        std::smatch m;
        if (std::regex_search(input.banner, m, std::regex("([0-9]+\\.[0-9]+\\.[0-9]+)"))) {
            input.version = m[1].str();
        } else if (std::regex_search(input.banner, m, std::regex("([0-9]+\\.[0-9]+[a-zA-Z0-9._-]*)"))) {
            input.version = m[1].str();
        }
    }

    static bool db_sorted = false;
    static auto db = build_cve_database();
    if (!db_sorted) {
        std::sort(db.begin(), db.end(),
            [](const CVESignature& a, const CVESignature& b) {
                std::string sa = a.service, sb = b.service;
                std::transform(sa.begin(), sa.end(), sa.begin(), ::toupper);
                std::transform(sb.begin(), sb.end(), sb.begin(), ::toupper);
                return sa < sb;
            });
        db_sorted = true;
    }
    auto matches = match_cves(input, db);

    std::unordered_map<int, std::vector<MatchResult>> all_matches;
    all_matches[input.port] = matches;

    emit_result(input, matches);
    emit_final({input}, all_matches);

    return 0;
}
