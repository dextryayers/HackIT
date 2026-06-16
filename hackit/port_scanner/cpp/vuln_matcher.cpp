/*
 * HackIT Vulnerability Pattern Matcher v2.0
 * Matches service product/version against CVE database
 * Compiler: g++ -std=c++17 -O3 -o vuln_matcher vuln_matcher.cpp -lssl -lcrypto -lpthread
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <cctype>
#include <cmath>
#include <cstdint>

using namespace std;
using namespace chrono;

struct CVEMatch {
    string cve_id;
    string name;
    double cvss_score;
    string severity;
    string description;
    string affected_product;
    string affected_version;
    string fixed_version;
};

struct VulnResult {
    int port;
    string service;
    string product;
    string version;
    vector<CVEMatch> matches;
    int total_cves;
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    double max_cvss;
    string risk_level;
};

static vector<CVEMatch> build_cve_db() {
    return {
        // OpenSSH
        {"CVE-2024-6387", "regreSSHion", 9.8, "CRITICAL", "RCE in OpenSSH signal handler", "OpenSSH", "0", "8.7"},
        {"CVE-2024-6387", "regreSSHion (glibc based)", 9.8, "CRITICAL", "RCE in OpenSSH signal handler (glibc)", "OpenSSH", "8.5p1", "8.7p1"},
        {"CVE-2023-38408", "SSH Agent RCE", 9.8, "CRITICAL", "SSH-agent remote code execution via PKCS11", "OpenSSH", "9.3p1", "9.3p2"},
        {"CVE-2023-28531", "SSH Agent RCE", 7.8, "HIGH", "SSH-agent RCE via smartcard provider", "OpenSSH", "9.3p1", "9.3p2"},
        {"CVE-2023-25136", "SSH Double-Free", 7.5, "HIGH", "OpenSSH double-free in sshd preauth", "OpenSSH", "9.1", "9.2"},
        {"CVE-2023-48795", "Terrapin SSH", 5.9, "MEDIUM", "SSH prefix truncation attack", "OpenSSH", "9.5", "9.6"},
        {"CVE-2018-15473", "SSH User Enum", 5.3, "MEDIUM", "Username enumeration via timing", "OpenSSH", "7.7", "7.8"},

        // vsftpd
        {"CVE-2011-2523", "vsftpd Backdoor", 10.0, "CRITICAL", "vsftpd 2.3.4 backdoor (smiley-face RCE)", "vsftpd", "2.3.4", "2.3.5"},

        // ProFTPD
        {"CVE-2010-4221", "ProFTPD RCE", 9.3, "CRITICAL", "ProFTPD sql_include buffer overflow", "ProFTPD", "1.3.3c", "1.3.3d"},
        {"CVE-2023-51766", "ProFTPD TLS Leak", 5.3, "MEDIUM", "ProFTPD mod_tls memory leak", "ProFTPD", "1.3.8", "1.3.8a"},
        {"CVE-2019-12815", "ProFTPD RCE", 9.8, "CRITICAL", "ProFTPD mod_copy copy_file RCE", "ProFTPD", "1.3.5", "1.3.6"},

        // Pure-FTPd
        {"CVE-2020-9365", "Pure-FTPd Overflow", 7.5, "HIGH", "Pure-FTPd heap-based buffer overflow in dirlist", "Pure-FTPd", "1.0.49", "1.0.50"},
        {"CVE-2019-20176", "Pure-FTPd DoS", 5.0, "MEDIUM", "Pure-FTPd symlink resolution DoS", "Pure-FTPd", "1.0.47", "1.0.48"},
        {"CVE-2014-3639", "Pure-FTPd Race", 6.1, "MEDIUM", "Pure-FTPd race condition in chroot", "Pure-FTPd", "1.0.42", "1.0.43"},
        {"CVE-2011-0418", "Pure-FTPd Log DoS", 5.0, "MEDIUM", "Pure-FTPd log file exhaustion DoS", "Pure-FTPd", "1.0.29", "1.0.30"},

        // Exim
        {"CVE-2023-42117", "Exim RCE", 9.8, "CRITICAL", "Exim remote code execution in SMTP", "Exim", "4.96", "4.97"},
        {"CVE-2023-42116", "Exim OOB Read", 7.5, "HIGH", "Exim out-of-bounds read in SMTP response", "Exim", "4.96", "4.97"},
        {"CVE-2022-3559", "Exim UAF", 9.8, "CRITICAL", "Exim use-after-free in SMTP accept", "Exim", "4.95", "4.96"},
        {"CVE-2020-28007", "Exim LPE", 7.0, "HIGH", "Exim privilege escalation via link attack", "Exim", "4.94", "4.95"},
        {"CVE-2020-28008", "Exim Mail Spool", 7.0, "HIGH", "Exim mail spool symlink attack", "Exim", "4.94", "4.95"},
        {"CVE-2019-10149", "Exim RCE", 9.8, "CRITICAL", "Exim RCE via experimental SPF support", "Exim", "4.92", "4.93"},
        {"CVE-2019-16928", "Exim RCE", 9.8, "CRITICAL", "Exim RCE via string_interpret_escape()", "Exim", "4.92", "4.93"},
        {"CVE-2018-6789", "Exim RCE", 9.8, "CRITICAL", "Exim base64 decode heap overflow", "Exim", "4.90", "4.91"},

        // Sendmail
        {"CVE-2023-40300", "Sendmail Overflow", 8.1, "HIGH", "Sendmail heap overflow", "Sendmail", "8.16", "8.17"},

        // Dovecot
        {"CVE-2022-30550", "Dovecot Memleak", 5.3, "MEDIUM", "Dovecot memory leak in IMAP STATUS", "Dovecot IMAP", "2.3.18", "2.3.19"},
        {"CVE-2022-30550", "Dovecot Memleak", 5.3, "MEDIUM", "Dovecot memory leak in POP3", "Dovecot POP3", "2.3.18", "2.3.19"},
        {"CVE-2021-29157", "Dovecot Crash", 5.0, "MEDIUM", "Dovecot crash via empty token", "Dovecot IMAP", "2.3.13", "2.3.14"},
        {"CVE-2021-29157", "Dovecot Crash", 5.0, "MEDIUM", "Dovecot crash via empty token", "Dovecot POP3", "2.3.13", "2.3.14"},
        {"CVE-2021-33515", "Dovecot DoS", 5.0, "MEDIUM", "Dovecot DoS via mail-log plugin", "Dovecot IMAP", "2.3.14", "2.3.15"},
        {"CVE-2020-24386", "Dovecot IMAP Crash", 5.0, "MEDIUM", "Dovecot IMAP crash via SETACL", "Dovecot IMAP", "2.3.10", "2.3.11"},
        {"CVE-2017-14461", "Dovecot Parse Crash", 5.0, "MEDIUM", "Dovecot POP3 crash on malformed date", "Dovecot POP3", "2.2.28", "2.2.29"},
        {"CVE-2017-2669", "Dovecot NOTIFY Crash", 5.0, "MEDIUM", "Dovecot IMAP crash on invalid NOTIFY", "Dovecot IMAP", "2.2.25", "2.2.26"},

        // LiteSpeed
        {"CVE-2022-44728", "LiteSpeed XSS", 6.1, "MEDIUM", "LiteSpeed Web Server XSS vulnerability", "LiteSpeed", "6.0.4", "6.0.5"},
        {"CVE-2022-44727", "LiteSpeed SSRF", 7.5, "HIGH", "LiteSpeed Web Server SSRF vulnerability", "LiteSpeed", "6.0.0", "6.0.5"},
        {"CVE-2022-22736", "LiteSpeed XSS", 6.1, "MEDIUM", "LiteSpeed Web Server XSS in HTTP response", "LiteSpeed", "5.4.7", "5.4.8"},
        {"CVE-2021-21907", "LiteSpeed RCE", 9.8, "CRITICAL", "LiteSpeed Web Server HTTP/2 RCE", "LiteSpeed", "6.0.0", "6.0.1"},

        // cPanel
        {"CVE-2023-4487", "cPanel PHPMailer RCE", 9.8, "CRITICAL", "cPanel PHPMailer dependency RCE", "cPanel", "11.108", "11.109"},
        {"CVE-2023-29489", "cPanel XSS", 6.1, "MEDIUM", "cPanel XSS in cpsrvd", "cPanel", "11.106", "11.107"},
        {"CVE-2022-48105", "cPanel PrivEsc", 7.8, "HIGH", "cPanel privilege escalation", "cPanel", "11.104", "11.105"},
        {"CVE-2022-45479", "cPanel Hash Disclosure", 7.5, "HIGH", "cPanel password hash disclosure", "cPanel", "11.102", "11.103"},
        {"CVE-2021-3197", "cPanel Auth Bypass", 9.8, "CRITICAL", "cPanel authentication bypass", "cPanel", "11.94", "11.95"},

        // Apache
        {"CVE-2021-42013", "Apache Path Traversal RCE", 9.8, "CRITICAL", "Path traversal and RCE in Apache 2.4.50", "Apache httpd", "2.4.50", "2.4.51"},
        {"CVE-2021-41773", "Apache Path Traversal", 9.8, "CRITICAL", "Path traversal in Apache 2.4.49", "Apache httpd", "2.4.49", "2.4.50"},
        {"CVE-2023-38196", "Apache SSRF", 7.5, "HIGH", "SSRF via mod_proxy", "Apache httpd", "2.4.49", "2.4.57"},
        {"CVE-2023-25690", "Apache Smuggling", 9.8, "CRITICAL", "HTTP request smuggling via mod_proxy", "Apache httpd", "2.4.55", "2.4.56"},
        {"CVE-2021-44790", "Apache mod_lua RCE", 9.8, "CRITICAL", "RCE in Apache mod_lua", "Apache httpd", "2.4.51", "2.4.52"},
        {"CVE-2020-1927", "Apache mod_rewrite SSRF", 7.5, "HIGH", "SSRF in Apache mod_rewrite", "Apache httpd", "2.4.41", "2.4.42"},

        // Nginx
        {"CVE-2024-24989", "Nginx DoS", 7.5, "HIGH", "Nginx HTTP/3 DoS via quic", "nginx", "1.25.3", "1.25.4"},
        {"CVE-2023-44487", "HTTP/2 Rapid Reset", 7.5, "HIGH", "HTTP/2 stream reset DDoS", "nginx", "1.25.0", "1.25.3"},
        {"CVE-2021-3618", "Nginx ALPACA", 5.9, "MEDIUM", "Nginx ALPACA TLS attack", "nginx", "1.21.0", "1.21.1"},

        // PHP
        {"CVE-2024-4577", "PHP CGI RCE", 9.8, "CRITICAL", "PHP CGI argument injection RCE", "PHP", "8.2.7", "8.2.8"},
        {"CVE-2023-36802", "PHP SPL RCE", 9.8, "CRITICAL", "PHP SPL multibyte string RCE", "PHP", "8.1.15", "8.1.16"},
        {"CVE-2019-11043", "PHP-FPM RCE", 9.8, "CRITICAL", "PHP-FPM nginx misconfiguration RCE", "PHP", "7.3.0", "7.3.11"},

        // Tomcat
        {"CVE-2020-1938", "Ghostcat", 9.8, "CRITICAL", "AJP file read/inclusion in Tomcat", "Apache Tomcat", "9.0.30", "9.0.31"},
        {"CVE-2020-9484", "Tomcat RCE", 9.8, "CRITICAL", "RCE via session persistence in Tomcat", "Apache Tomcat", "9.0.34", "9.0.35"},
        {"CVE-2020-13935", "Tomcat WebSocket DoS", 7.5, "HIGH", "DoS via WebSocket frame", "Apache Tomcat", "9.0.36", "9.0.38"},

        // MySQL/MariaDB
        {"CVE-2023-22102", "MySQL OOB", 7.5, "HIGH", "MySQL out-of-bounds write", "MySQL", "8.1.0", "8.1.1"},
        {"CVE-2023-22053", "MySQL Race", 5.5, "MEDIUM", "MySQL race condition", "MySQL", "8.0.33", "8.0.34"},
        {"CVE-2023-21971", "MySQL Connector RCE", 7.5, "HIGH", "MySQL Connector/J RCE", "MySQL", "8.0.32", "8.0.33"},

        // OpenSSL
        {"CVE-2023-5363", "OpenSSL FIPS Bug", 5.3, "MEDIUM", "OpenSSL FIPS module bug", "OpenSSL", "3.0.8", "3.0.10"},
        {"CVE-2023-4807", "OpenSSL POLY1305", 5.3, "MEDIUM", "OpenSSL POLY1305 MAC bug", "OpenSSL", "3.1.1", "3.1.4"},
        {"CVE-2023-3446", "OpenSSL DoS", 6.5, "MEDIUM", "OpenSSL DoS via DH keys", "OpenSSL", "3.1.2", "3.1.3"},
        {"CVE-2022-3786", "OpenSSL X.509 Overflow", 7.5, "HIGH", "OpenSSL X.509 email buffer overflow", "OpenSSL", "3.0.6", "3.0.7"},
        {"CVE-2022-3602", "OpenSSL X.509 Overflow", 7.5, "HIGH", "OpenSSL X.509 puny-code overflow", "OpenSSL", "3.0.6", "3.0.7"},
        {"CVE-2022-0778", "OpenSSL Inf Loop", 7.5, "HIGH", "OpenSSL infinite loop in BN_mod_sqrt", "OpenSSL", "3.0.1", "3.0.2"},
        {"CVE-2022-1292", "OpenSSL c_rehash RCE", 9.8, "CRITICAL", "OpenSSL RCE via c_rehash script", "OpenSSL", "3.0.0", "3.0.3"},

        // Redis
        {"CVE-2023-45156", "Redis RCE", 9.8, "CRITICAL", "Redis Lua sandbox escape RCE", "Redis", "7.2.0", "7.2.2"},
        {"CVE-2022-35951", "Redis Lua DoS", 5.3, "MEDIUM", "Redis Lua runtime DoS", "Redis", "7.0.0", "7.0.8"},
        {"CVE-2021-32675", "Redis Lua RCE", 7.0, "HIGH", "Redis Lua sandbox RCE", "Redis", "6.2.0", "6.2.4"},

        // Widespread CVEs
        {"CVE-2022-29464", "WSO2 RCE", 9.8, "CRITICAL", "WSO2 file upload RCE", "WSO2", "0", ""},
        {"CVE-2022-22965", "Spring4Shell", 9.8, "CRITICAL", "Spring Framework RCE", "Spring Framework", "5.3.17", "5.3.18"},
        {"CVE-2021-44228", "Log4Shell", 10.0, "CRITICAL", "Log4j JNDI injection RCE", "Log4j", "2.14.1", "2.15.0"},
        {"CVE-2021-45046", "Log4j Bypass", 9.0, "CRITICAL", "Log4j DoS/RCE bypass", "Log4j", "2.15.0", "2.16.0"},
        {"CVE-2021-45105", "Log4j DoS", 7.5, "HIGH", "Log4j infinite recursion DoS", "Log4j", "2.16.0", "2.17.0"},
        {"CVE-2023-46604", "ActiveMQ RCE", 10.0, "CRITICAL", "ActiveMQ RCE via serialization", "ActiveMQ", "5.18.2", "5.18.3"},
        {"CVE-2023-22527", "Confluence RCE", 10.0, "CRITICAL", "Confluence template injection RCE", "Confluence", "8.5.3", "8.5.4"},
        {"CVE-2023-32315", "Openfire RCE", 9.8, "CRITICAL", "Openfire admin console bypass", "Openfire", "4.7.4", "4.7.5"},
        {"CVE-2023-21839", "WebLogic RCE", 7.5, "HIGH", "WebLogic NRM RCE", "WebLogic", "14.1.1.0.0", "14.1.1.0.1"},
        {"CVE-2020-14882", "WebLogic Console RCE", 9.8, "CRITICAL", "WebLogic console RCE", "WebLogic", "12.2.1.4.0", "12.2.1.4.1"},

        // Samba
        {"CVE-2023-34968", "Samba RCE", 9.8, "CRITICAL", "Samba netlogon RCE via MITM", "Samba", "4.18.4", "4.18.5"},
        {"CVE-2023-3347", "Samba Info Leak", 7.5, "HIGH", "Samba info leak via SMB2/3", "Samba", "4.18.4", "4.18.5"},
        {"CVE-2020-1472", "Zerologon", 9.8, "CRITICAL", "Netlogon privilege escalation in Windows", "Windows Server", "0", ""},

        // Exchange
        {"CVE-2021-34473", "ProxyShell", 9.8, "CRITICAL", "Exchange RCE via multiple vulns", "Exchange", "15.1.2375.7", "15.1.2375.8"},
        {"CVE-2021-26855", "Exchange SSRF", 9.8, "CRITICAL", "Exchange SSRF leading to RCE", "Exchange", "15.1.2308.14", "15.1.2308.15"},

        // Kernel / System
        {"CVE-2023-4911", "Looney Tunables", 7.8, "HIGH", "GNU C library ld.so LPE", "glibc", "2.37.0", "2.37.2"},
        {"CVE-2021-4034", "PwnKit", 7.8, "HIGH", "polkit pkexec LPE", "polkit", "0.120", "0.121"},
        {"CVE-2022-0847", "Dirty Pipe", 7.8, "HIGH", "Linux kernel privilege escalation", "Linux Kernel", "5.8", "5.16.11"},

        // EOL flags
        {"EOL-APACHE-2.2", "Apache 2.2 EOL", 0, "HIGH", "Apache HTTP Server 2.2 is end-of-life", "Apache httpd", "2.2", "0"},
        {"EOL-PHP-5", "PHP 5.x EOL", 0, "CRITICAL", "PHP 5.x is end-of-life", "PHP", "5.0.0", "7.0.0"},
        {"EOL-PHP-7.0", "PHP 7.0 EOL", 0, "HIGH", "PHP 7.0 is end-of-life", "PHP", "7.0.0", "7.1.0"},
        {"EOL-PHP-7.1", "PHP 7.1 EOL", 0, "HIGH", "PHP 7.1 is end-of-life", "PHP", "7.1.0", "7.2.0"},
        {"EOL-PHP-7.2", "PHP 7.2 EOL", 0, "MEDIUM", "PHP 7.2 is end-of-life", "PHP", "7.2.0", "7.3.0"},
        {"EOL-PHP-7.3", "PHP 7.3 EOL", 0, "MEDIUM", "PHP 7.3 is end-of-life", "PHP", "7.3.0", "7.4.0"},
        {"EOL-PHP-7.4", "PHP 7.4 EOL", 0, "MEDIUM", "PHP 7.4 is end-of-life", "PHP", "7.4.0", "8.0.0"},
        {"EOL-VSFTPD-2.3.4", "vsftpd 2.3.4 Backdoor", 10.0, "CRITICAL", "vsftpd 2.3.4 contains a backdoor", "vsftpd", "2.3.4", "2.3.5"},
        {"EOL-OPENSSL-1.0.1", "OpenSSL Heartbleed", 9.8, "CRITICAL", "OpenSSL 1.0.1 vulnerable to Heartbleed", "OpenSSL", "1.0.1", "1.0.2"},
        {"EOL-OPENSSL-1.0.0", "OpenSSL 1.0.0 EOL", 0, "HIGH", "OpenSSL 1.0.0 is end-of-life", "OpenSSL", "1.0.0", "1.0.1"},
        {"EOL-TOMCAT-7", "Tomcat 7 EOL", 0, "HIGH", "Apache Tomcat 7 is end-of-life", "Apache Tomcat", "7.0.0", "8.0.0"},
        {"EOL-TOMCAT-8", "Tomcat 8 EOL", 0, "MEDIUM", "Apache Tomcat 8.0 is end-of-life", "Apache Tomcat", "8.0.0", "8.5.0"},

        // Postfix
        {"CVE-2023-51764", "Postfix Smuggling", 7.5, "HIGH", "Postfix SMTP smuggling", "Postfix", "3.8.0", "3.8.1"},
        {"CVE-2023-51764", "Postfix Smuggling", 7.5, "HIGH", "Postfix SMTP smuggling", "Postfix", "3.7.0", "3.7.4"},

        // PostgreSQL
        {"CVE-2024-0985", "PostgreSQL Vacuum", 6.5, "MEDIUM", "PostgreSQL vacuum locking DoS", "PostgreSQL", "16.0", "16.2"},
        {"CVE-2023-5869", "PostgreSQL Cursor", 7.5, "HIGH", "PostgreSQL aggregate final function exploit", "PostgreSQL", "16.0", "16.1"},

        // Redis additional
        {"INFO-NOAUTH", "Redis No Auth", 7.0, "HIGH", "Redis: No authentication by default", "Redis", "0", ""},
        {"INFO-NOAUTH", "MongoDB No Auth", 7.0, "HIGH", "MongoDB: No auth by default", "MongoDB", "0", ""},
        {"INFO-EXPOSED", "Docker Exposed", 10.0, "CRITICAL", "Docker daemon exposed without TLS", "Docker Engine", "0", ""},
    };
}

static vector<int> parse_ports(const string& spec) {
    vector<int> ports;
    if (spec.empty()) return ports;
    if (spec == "auto") {
        return {21,22,23,25,53,80,110,111,135,139,143,161,179,389,443,445,465,514,587,636,873,990,992,993,995,1080,1194,1433,1521,1723,2049,2375,2376,2379,3128,3306,3389,3690,4369,5432,5672,5900,5984,5985,6379,6443,8080,8443,8500,9090,9092,9200,10250,11211,15672,25565,27017,32400};
    }
    char buf[65536];
    strncpy(buf, spec.c_str(), sizeof(buf)-1);
    char* tok = strtok(buf, ",");
    while (tok) {
        char* dash = strchr(tok, '-');
        if (dash) {
            int s = atoi(tok), e = atoi(dash+1);
            for (int p = s; p <= e; p++) ports.push_back(p);
        } else ports.push_back(atoi(tok));
        tok = strtok(NULL, ",");
    }
    return ports;
}

static bool version_less_than(const string& v1, const string& v2) {
    if (v1.empty() || v2.empty()) return false;
    if (v1 == "0") return true;
    if (v2 == "0") return false;
    vector<int> p1, p2;
    string s1 = v1, s2 = v2;
    char* t1 = strtok(&s1[0], ".");
    while (t1) { p1.push_back(atoi(t1)); t1 = strtok(NULL, "."); }
    char* t2 = strtok(&s2[0], ".");
    while (t2) { p2.push_back(atoi(t2)); t2 = strtok(NULL, "."); }
    size_t n = max(p1.size(), p2.size());
    p1.resize(n, 0); p2.resize(n, 0);
    for (size_t i = 0; i < n; i++) {
        if (p1[i] != p2[i]) return p1[i] < p2[i];
    }
    return false;
}

static VulnResult scan_vulns(int port, const string& product, const string& version) {
    VulnResult r;
    r.port = port;
    r.product = product;
    r.version = version;
    r.max_cvss = 0;
    r.critical_count = r.high_count = r.medium_count = r.low_count = 0;
    string prod_lower = product;
    transform(prod_lower.begin(), prod_lower.end(), prod_lower.begin(), ::tolower);
    auto db = build_cve_db();
    for (auto& cve : db) {
        string affected_lower = cve.affected_product;
        transform(affected_lower.begin(), affected_lower.end(), affected_lower.begin(), ::tolower);
        if (prod_lower.find(affected_lower) == string::npos &&
            affected_lower.find(prod_lower) == string::npos) continue;
        if (!cve.fixed_version.empty() && !version.empty() && version != "0") {
            if (version_less_than(version, cve.fixed_version)) {
                r.matches.push_back(cve);
                r.total_cves++;
                if (cve.cvss_score >= 9.0) r.critical_count++;
                else if (cve.cvss_score >= 7.0) r.high_count++;
                else if (cve.cvss_score >= 4.0) r.medium_count++;
                else r.low_count++;
                if (cve.cvss_score > r.max_cvss) r.max_cvss = cve.cvss_score;
            }
        } else if (!cve.affected_version.empty() && cve.affected_version != "0") {
            if (version == cve.affected_version) {
                r.matches.push_back(cve);
                r.total_cves++;
                if (cve.cvss_score >= 9.0) r.critical_count++;
                else if (cve.cvss_score >= 7.0) r.high_count++;
                else if (cve.cvss_score >= 4.0) r.medium_count++;
                else r.low_count++;
                if (cve.cvss_score > r.max_cvss) r.max_cvss = cve.cvss_score;
            }
        } else {
            r.matches.push_back(cve);
            r.total_cves++;
            if (cve.cvss_score >= 9.0) r.critical_count++;
            else if (cve.cvss_score >= 7.0) r.high_count++;
            else if (cve.cvss_score >= 4.0) r.medium_count++;
            else r.low_count++;
            if (cve.cvss_score > r.max_cvss) r.max_cvss = cve.cvss_score;
        }
    }
    if (r.max_cvss >= 9.0) r.risk_level = "CRITICAL";
    else if (r.max_cvss >= 7.0) r.risk_level = "HIGH";
    else if (r.max_cvss >= 4.0) r.risk_level = "MEDIUM";
    else if (r.total_cves > 0) r.risk_level = "LOW";
    else r.risk_level = "INFO";
    return r;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <product> <version> [ports] [format:text|json]\n", argv[0]);
        fprintf(stderr, "Example: %s \"Apache httpd\" \"2.4.49\" 80,443 json\n", argv[0]);
        fprintf(stderr, "Uses stdin: echo '{\"product\":\"OpenSSH\",\"version\":\"8.5\",\"port\":22}' | %s\n", argv[0]);
        return 1;
    }
    string product = argv[1];
    string version = argv[2];
    int port = argc > 3 ? atoi(argv[3]) : 0;
    string format = argc > 4 ? argv[4] : "text";
    VulnResult r = scan_vulns(port, product, version);
    if (format == "json") {
        printf("{\"port\":%d,\"product\":\"%s\",\"version\":\"%s\",\"risk\":\"%s\",\"total_cves\":%d,\"critical\":%d,\"high\":%d,\"medium\":%d,\"low\":%d,\"max_cvss\":%.1f}\n",
            port, product.c_str(), version.c_str(), r.risk_level.c_str(),
            r.total_cves, r.critical_count, r.high_count, r.medium_count, r.low_count, r.max_cvss);
    } else {
        printf("VULN: port=%d product=%s version=%s risk=%s cves=%d crit=%d high=%d med=%d low=%d cvss=%.1f\n",
            port, product.c_str(), version.c_str(), r.risk_level.c_str(),
            r.total_cves, r.critical_count, r.high_count, r.medium_count, r.low_count, r.max_cvss);
    }
    return 0;
}
