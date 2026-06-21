/*
 * HackIT PortStorm — C++ Deep Service Fingerprinting Engine v4.1
 * 180+ service version patterns · OS fingerprinting · Protocol-specific probes
 * Compiler: g++ -std=c++17 -O3 -o advanced_scanner advanced_scanner.cpp -lssl -lcrypto -lpthread
 */

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mstcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
  #define CLOSE_SOCKET(s) closesocket(s)
  #define IS_INVALID(s) ((s) == INVALID_SOCKET)
  #define SOCK_ERRNO WSAGetLastError()
  #define SOCK_EWOULDBLOCK WSAEWOULDBLOCK
  #define SOCK_ETIMEDOUT WSAETIMEDOUT
  #define SOCK_ECONNREFUSED WSAECONNREFUSED
#else
  #include <sys/socket.h>
  #include <sys/poll.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <netinet/tcp.h>
  #include <netinet/ip.h>
  #include <netinet/in.h>
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/x509v3.h>
  #include <openssl/pem.h>
  #define CLOSE_SOCKET(s) close(s)
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define SOCKET_ERROR -1
  #define IS_INVALID(s) ((s) < 0)
  #define SOCK_ERRNO errno
  #define SOCK_EWOULDBLOCK EWOULDBLOCK
  #define SOCK_ETIMEDOUT ETIMEDOUT
  #define SOCK_ECONNREFUSED ECONNREFUSED
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <queue>
#include <atomic>
#include <tuple>
#include <cctype>
#include <cmath>
#include <cwchar>
#include <cstdint>
#include <iomanip>
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


using namespace std;
using namespace chrono;

/* ─────────────────────────────────────────────────────────────────
 * CONSTANTS
 * ───────────────────────────────────────────────────────────────── */
constexpr int DEFAULT_TIMEOUT_MS = 1500;
constexpr int MAX_BANNER_SIZE    = 8192;
constexpr int THREAD_POOL_SIZE   = 32;

/* ─────────────────────────────────────────────────────────────────
 * DATA STRUCTURES
 * ───────────────────────────────────────────────────────────────── */

struct VersionPattern {
    string service;
    string pattern;
    string product;
    string version;
    string os_hint;
};

struct OsFingerprint {
    string os_name;
    string os_version;
    float  confidence;
    vector<string> clues;
};

struct ScanResult {
    int     port;
    string  state;
    string  service;
    string  product;
    string  version;
    string  os_hint;
    string  banner;
    string  cpe;
    double  confidence;
    vector<string> vulnerabilities;
    vector<string> cpe_list;
    string  risk_level;
    double  risk_score;
    bool    ssl;
    string  ssl_info;
    OsFingerprint os_fp;
};

/* ─────────────────────────────────────────────────────────────────
 * VERSION PATTERN DATABASE — 180+ patterns
 * ───────────────────────────────────────────────────────────────── */

static vector<VersionPattern> build_version_patterns() {
    vector<VersionPattern> db;

    // ── SSH (10 patterns) ────────────────────────────────────────
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*)",          "OpenSSH", "$1", "Unix"});
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*).*Ubuntu",  "OpenSSH", "$1", "Ubuntu Linux"});
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*).*Debian",  "OpenSSH", "$1", "Debian Linux"});
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*).*[Rr]hel|CentOS|Fedora", "OpenSSH", "$1", "RHEL/CentOS/Fedora"});
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*).*FreeBSD", "OpenSSH", "$1", "FreeBSD"});
    db.push_back({"SSH", "SSH-2\\.0-OpenSSH_([\\d.]+p?\\d*).*openSUSE|SUSE", "OpenSSH", "$1", "SUSE Linux"});
    db.push_back({"SSH", "SSH-2\\.0-dropbear_([\\d.]+)",               "Dropbear", "$1", "Unix/Linux"});
    db.push_back({"SSH", "SSH-2\\.0-Cisco-([\\d.]+)",                  "Cisco SSH", "$1", "Cisco IOS"});
    db.push_back({"SSH", "SSH-1\\.99-",                                 "SSH Legacy", "", "Generic"});
    db.push_back({"SSH", "SSH-1\\.5-",                                  "SSH v1 (Insecure)", "", "Generic"});

    // ── HTTP — Apache (12 patterns) ──────────────────────────────
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)",                                    "Apache httpd", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Uu]buntu\\)",                  "Apache httpd", "$1", "Ubuntu Linux"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Dd]ebian\\)",                  "Apache httpd", "$1", "Debian Linux"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Cc]ent[Oo][Ss]\\)",            "Apache httpd", "$1", "CentOS Linux"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Ff]ree[Bb][Ss][Dd]\\)",        "Apache httpd", "$1", "FreeBSD"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Ww]in32\\)",                    "Apache httpd", "$1", "Windows"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Rr]ed[Hh]at\\)",                "Apache httpd", "$1", "Red Hat Linux"});
    db.push_back({"HTTP", "Server:\\s*Apache/([\\d.]+)\\s+\\([Ff]edora\\)",                   "Apache httpd", "$1", "Fedora Linux"});
    db.push_back({"HTTP", "Server:\\s*Apache-Coyote/1\\.1",                                   "Apache Tomcat/Coyote", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Apache-Coyote",                                         "Apache Tomcat/Coyote", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Apache.*Tomcat.*([\\d.]+)",                             "Apache Tomcat", "$1", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Servlet([\\d.]+)",                                "Apache Tomcat Servlet", "$1", "Generic"});

    // ── HTTP — nginx (6 patterns) ────────────────────────────────
    db.push_back({"HTTP", "Server:\\s*nginx/([\\d.]+)",                      "nginx", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*nginx/([\\d.]+)\\s+\\([Uu]buntu\\)",   "nginx", "$1", "Ubuntu Linux"});
    db.push_back({"HTTP", "Server:\\s*nginx/([\\d.]+)\\s+\\([Dd]ebian\\)",   "nginx", "$1", "Debian Linux"});
    db.push_back({"HTTP", "Server:\\s*nginx/([\\d.]+)\\s+\\([Cc]ent[Oo][Ss]\\)", "nginx", "$1", "CentOS Linux"});
    db.push_back({"HTTP", "Server:\\s*openresty/([\\d.]+)",                  "OpenResty", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Tengine/?([\\d.]*)",                   "Tengine", "$1", "Generic"});

    // ── HTTP — IIS (5 patterns) ──────────────────────────────────
    db.push_back({"HTTP", "Server:\\s*Microsoft-IIS/([\\d.]+)",                "Microsoft IIS", "$1", "Windows Server"});
    db.push_back({"HTTP", "Server:\\s*Microsoft-HTTPAPI/([\\d.]+)",            "Microsoft HTTPAPI", "$1", "Windows Server"});
    db.push_back({"HTTP", "X-Powered-By:\\s*ASP\\.NET",                         "ASP.NET", "", "Windows Server"});
    db.push_back({"HTTP", "X-AspNet-Version:\\s*([\\d.]+)",                    "ASP.NET", "$1", "Windows Server"});
    db.push_back({"HTTP", "Server:\\s*Kestrel",                                 "ASP.NET Kestrel", "", "Windows/Linux"});

    // ── HTTP — Other Web Servers (14 patterns) ───────────────────
    db.push_back({"HTTP", "Server:\\s*LiteSpeed",                        "LiteSpeed", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*LiteSpeed/?\\s*([\\d.]+)",        "LiteSpeed", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*LSWS/?\\s*([\\d.]+)",             "LiteSpeed Web Server", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*lighttpd/([\\d.]+)",               "Lighttpd", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Caddy",                            "Caddy", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cowboy",                           "Cowboy (Erlang)", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*GWS",                              "Google Web Server", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cloudflare",                       "Cloudflare", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Jetty\\(([\\d.]+)\\)",            "Jetty", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Jetty",                            "Jetty", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*gunicorn/([\\d.]+)",               "Gunicorn", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*uvicorn",                          "Uvicorn (ASGI)", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Werkzeug/?([\\d.]*)",             "Werkzeug (Flask)", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cherokee/?([\\d.]*)",             "Cherokee", "$1", "Generic"});

    // ── HTTP — App Servers & Powered-By (10 patterns) ─────────────
    db.push_back({"HTTP", "X-Powered-By:\\s*PHP/([\\d.]+)",              "PHP", "$1", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Express",                    "Express (Node.js)", "", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Railo|Lucee",                "Railo/Lucee (CFML)", "", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Servlet/([\\d.]+)",          "Java Servlet", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*Drupal ([\\d.]+)",            "Drupal", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*WordPress ([\\d.]+)",         "WordPress", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*Joomla! ([\\d.]+)",           "Joomla", "$1", "Generic"});
    db.push_back({"HTTP", "X-Drupal-Cache",                              "Drupal", "", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*cPanel",                     "cPanel", "", "CentOS/CloudLinux"});
    db.push_back({"HTTP", "Server:\\s*cpsrvd/([\\d.]+)",                 "cPanel/WHM", "$1", "CentOS/CloudLinux"});

    // ── FTP (16 patterns) ────────────────────────────────────────
    db.push_back({"FTP", "220.*vsftpd ([\\d.]+)",                       "vsftpd", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*ProFTPD ([\\d.]+)",                      "ProFTPD", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*FileZilla Server ([\\d.]+)",             "FileZilla Server", "$1", "Windows"});
    db.push_back({"FTP", "220.*Pure-FTPd",                              "Pure-FTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*Pure-FTPd ([\\d.]+)",                    "Pure-FTPd", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*Pure-FTPd \\[TLS\\]",                    "Pure-FTPd (TLS)", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*pure-ftpd",                              "Pure-FTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*pure-ftpd ([\\d.]+)",                    "Pure-FTPd", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*Microsoft FTP",                          "Microsoft FTP", "", "Windows Server"});
    db.push_back({"FTP", "220.*Wu-FTPd",                                "Wu-FTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*glFTPd",                                 "glFTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*Serv-U FTP Server",                      "Serv-U", "", "Windows"});
    db.push_back({"FTP", "220.*BulletProof",                            "BulletProof FTP", "", "Windows"});
    db.push_back({"FTP", "220.*Cerberus FTP",                           "Cerberus FTP", "", "Windows"});
    db.push_back({"FTP", "220.*Apache FtpServer",                       "Apache FtpServer", "", "Generic"});
    db.push_back({"FTP", "220.*pyftpdlib",                              "pyftpdlib", "", "Unix/Linux"});

    // ── SMTP (16 patterns) ───────────────────────────────────────
    db.push_back({"SMTP", "220.*Postfix ([\\d.]+)",                     "Postfix", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Postfix ESMTP",                         "Postfix", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Exim ([\\d.]+)",                        "Exim", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Exim.*ESMTP",                           "Exim", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Sendmail ([\\d.]+)",                    "Sendmail", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Sendmail",                              "Sendmail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Microsoft ESMTP",                       "Microsoft Exchange", "", "Windows Server"});
    db.push_back({"SMTP", "220.*MailEnable",                            "MailEnable", "", "Windows"});
    db.push_back({"SMTP", "220.*qmail",                                 "Qmail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Courier",                               "Courier Mail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*OpenSMTPD",                             "OpenSMTPD", "", "OpenBSD"});
    db.push_back({"SMTP", "220.*IceWarp",                               "IceWarp", "", "Windows/Unix"});
    db.push_back({"SMTP", "220.*Zimbra",                                "Zimbra", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*CommuniGate",                           "CommuniGate Pro", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*SurgeMail",                             "SurgeMail", "", "Windows/Unix"});
    db.push_back({"SMTP", "220.*Kerio Connect",                         "Kerio Connect", "", "Windows/Unix"});

    // ── POP3 (10 patterns) ────────────────────────────────────────
    db.push_back({"POP3", "\\+OK.*Dovecot.*ready",                      "Dovecot POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Dovecot.*v([\\d.]+)",                "Dovecot POP3", "$1", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*dovecot.*pop3d.*ready",               "Dovecot POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*dovecot.*pop3d.*v([\\d.]+)",         "Dovecot POP3", "$1", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Courier POP3",                        "Courier POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Qpopper",                             "Qpopper", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Microsoft.*POP3",                     "Microsoft POP3", "", "Windows Server"});
    db.push_back({"POP3", "\\+OK.*MailEnable POP3",                     "MailEnable POP3", "", "Windows"});
    db.push_back({"POP3", "\\+OK.*Cyrus",                               "Cyrus POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Cyrus.*v([\\d.]+)",                  "Cyrus POP3", "$1", "Unix/Linux"});

    // ── IMAP (10 patterns) ────────────────────────────────────────
    db.push_back({"IMAP", "\\* OK.*Dovecot",                            "Dovecot IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Dovecot.*v([\\d.]+)",               "Dovecot IMAP", "$1", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*dovecot.*imapd.*ready",              "Dovecot IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*dovecot.*imapd.*v([\\d.]+)",        "Dovecot IMAP", "$1", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Courier",                            "Courier IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Cyrus IMAP",                         "Cyrus IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Cyrus.*v([\\d.]+)",                 "Cyrus IMAP", "$1", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Microsoft.*IMAP",                   "Microsoft Exchange IMAP", "", "Windows Server"});
    db.push_back({"IMAP", "\\* OK.*Zimbra",                             "Zimbra IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*MailEnable IMAP",                    "MailEnable IMAP", "", "Windows"});

    // ── MySQL / MariaDB (8 patterns) ─────────────────────────────
    db.push_back({"MySQL", "mysql_native_password",                      "MySQL", "", "Generic"});
    db.push_back({"MySQL", "MariaDB",                                    "MariaDB", "", "Generic"});
    db.push_back({"MySQL", "mariadb",                                    "MariaDB", "", "Generic"});
    db.push_back({"MySQL", "5\\.5\\.\\d+-MySQL",                        "MySQL 5.5", "", "Generic"});
    db.push_back({"MySQL", "5\\.6\\.\\d+-MySQL",                        "MySQL 5.6", "", "Generic"});
    db.push_back({"MySQL", "5\\.7\\.\\d+-MySQL",                        "MySQL 5.7", "", "Generic"});
    db.push_back({"MySQL", "8\\.\\d+\\.\\d+-MySQL",                     "MySQL 8.x", "", "Generic"});
    db.push_back({"MySQL", "([\\d.]+)-MySQL",                           "MySQL", "$1", "Generic"});

    // ── PostgreSQL (4 patterns) ──────────────────────────────────
    db.push_back({"PostgreSQL", "PostgreSQL ([\\d.]+)",                  "PostgreSQL", "$1", "Generic"});
    db.push_back({"PostgreSQL", "psql.*PostgreSQL",                      "PostgreSQL", "", "Generic"});
    db.push_back({"PostgreSQL", "Cyrus PostgreSQL",                      "PostgreSQL", "", "Generic"});
    db.push_back({"PostgreSQL", "pg_hba",                                "PostgreSQL", "", "Generic"});

    // ── Other Databases (18 patterns) ────────────────────────────
    db.push_back({"Redis",   "redis_version:([\\d.]+)",                 "Redis", "$1", "Unix/Linux"});
    db.push_back({"Redis",   "redis_mode:",                             "Redis", "", "Unix/Linux"});
    db.push_back({"Redis",   "role:master",                             "Redis Master", "", "Unix/Linux"});
    db.push_back({"Redis",   "role:slave",                              "Redis Slave", "", "Unix/Linux"});
    db.push_back({"MongoDB", "MongoDB",                                 "MongoDB", "", "Generic"});
    db.push_back({"MongoDB", "\"ok\"\\s*:\\s*1",                       "MongoDB", "", "Generic"});
    db.push_back({"MongoDB", "MongoDB ([\\d.]+)",                       "MongoDB", "$1", "Generic"});
    db.push_back({"CouchDB", "CouchDB/([\\d.]+)",                       "CouchDB", "$1", "Generic"});
    db.push_back({"CouchDB", "couchdb",                                 "CouchDB", "", "Generic"});
    db.push_back({"MSSQL",   "MSSQL|SQL Server",                        "Microsoft SQL Server", "", "Windows Server"});
    db.push_back({"MSSQL",   "MS-SQL-S|MS-SQL-M",                      "Microsoft SQL Server", "", "Windows Server"});
    db.push_back({"Oracle",  "Oracle\\s*DB|Oracle\\s*Database",         "Oracle Database", "", "Generic"});
    db.push_back({"Oracle",  "Oracle.*XE",                               "Oracle Database XE", "", "Generic"});
    db.push_back({"Oracle",  "Oracle.*Express",                          "Oracle Database XE", "", "Generic"});
    db.push_back({"Cassandra","Apache Cassandra",                        "Apache Cassandra", "", "Generic"});
    db.push_back({"Elasticsearch","Elasticsearch",                       "Elasticsearch", "", "Generic"});
    db.push_back({"Elasticsearch","([\\d.]+)\"\\s*:\\s*\\{",           "Elasticsearch", "$1", "Generic"});
    db.push_back({"Memcached","STAT pid",                                "Memcached", "", "Generic"});

    // ── DNS (4 patterns) ─────────────────────────────────────────
    db.push_back({"DNS", "BIND ([\\d.]+)",                              "BIND", "$1", "Generic"});
    db.push_back({"DNS", "unbound ([\\d.]+)",                           "Unbound", "$1", "Generic"});
    db.push_back({"DNS", "dnsmasq",                                      "Dnsmasq", "", "Linux/Embedded"});
    db.push_back({"DNS", "PowerDNS",                                     "PowerDNS", "", "Generic"});

    // ── SMB / NetBIOS (4 patterns) ───────────────────────────────
    db.push_back({"SMB",   "Samba ([\\d.]+)",                            "Samba", "$1", "Unix/Linux"});
    db.push_back({"SMB",   "Windows[_ ]Server",                          "Windows SMB", "", "Windows Server"});
    db.push_back({"SMB",   "NT\\s*LM\\s*0\\.12",                        "SMB 1.0 (Legacy)", "", "Windows/Legacy"});
    db.push_back({"SMB",   "Samba",                                      "Samba", "", "Unix/Linux"});

    // ── RDP (2 patterns) ─────────────────────────────────────────
    db.push_back({"RDP", "MS-Terminal",                                  "Microsoft RDP", "", "Windows"});
    db.push_back({"RDP", "xrdp ([\\d.]+)",                               "xrdp", "$1", "Unix/Linux"});

    // ── VNC (4 patterns) ─────────────────────────────────────────
    db.push_back({"VNC", "RFB 00([\\d.]+)",                              "VNC", "$1", "Generic"});
    db.push_back({"VNC", "RFB 003\\.",                                    "VNC 3.x", "", "Generic"});
    db.push_back({"VNC", "RFB 004\\.",                                    "VNC 4.x", "", "Generic"});
    db.push_back({"VNC", "RFB 005\\.",                                    "VNC 5.x", "", "Generic"});

    // ── Telnet (4 patterns) ──────────────────────────────────────
    db.push_back({"Telnet", "Telnet",                                     "Telnet Server", "", "Generic"});
    db.push_back({"Telnet", "Ubuntu.*telnetd",                            "Telnet (Ubuntu)", "", "Ubuntu Linux"});
    db.push_back({"Telnet", "Linux.*telnetd",                             "Telnet (Linux)", "", "Linux"});
    db.push_back({"Telnet", "FreeBSD.*telnetd",                           "Telnet (FreeBSD)", "", "FreeBSD"});

    // ── LDAP (3 patterns) ────────────────────────────────────────
    db.push_back({"LDAP", "OpenLDAP ([\\d.]+)",                          "OpenLDAP", "$1", "Unix/Linux"});
    db.push_back({"LDAP", "Microsoft.*LDAP",                              "Microsoft AD/LDAP", "", "Windows Server"});
    db.push_back({"LDAP", "389-Directory",                                "389 Directory Server", "", "Unix/Linux"});

    // ── SIP (2 patterns) ─────────────────────────────────────────
    db.push_back({"SIP", "SIP/2\\.0.*Asterisk",                          "Asterisk PBX", "", "Unix/Linux"});
    db.push_back({"SIP", "SIP/2\\.0.*FreePBX",                           "FreePBX", "", "Unix/Linux"});

    // ── Docker / Containers (8 patterns) ─────────────────────────
    db.push_back({"Docker", "Docker/([\\d.]+)",                          "Docker Engine", "$1", "Linux"});
    db.push_back({"Docker", "\"Version\":\"([\\d.]+)\".*ApiVersion",    "Docker Engine", "$1", "Linux"});
    db.push_back({"Docker", "\"Platform\":\"docker\"",                   "Docker Engine", "", "Linux"});
    db.push_back({"Docker", "Docker\\s*Community",                        "Docker Community", "", "Linux"});
    db.push_back({"Docker", "Containerd",                                 "Containerd", "", "Linux"});
    db.push_back({"Kubernetes","kubernetes|k8s",                         "Kubernetes", "", "Generic"});
    db.push_back({"etcd",    "etcd ([\\d.]+)",                           "etcd", "$1", "Linux"});
    db.push_back({"etcd",    "\"etcd\"",                                  "etcd", "", "Linux"});

    // ── CI/CD (8 patterns) ───────────────────────────────────────
    db.push_back({"CI/CD",  "Jenkins",                                   "Jenkins CI", "", "Generic"});
    db.push_back({"CI/CD",  "Artifactory",                               "JFrog Artifactory", "", "Generic"});
    db.push_back({"CI/CD",  "Nexus",                                     "Sonatype Nexus", "", "Generic"});
    db.push_back({"CI/CD",  "GitLab",                                    "GitLab", "", "Generic"});
    db.push_back({"CI/CD",  "Gitea",                                     "Gitea", "", "Generic"});
    db.push_back({"CI/CD",  "Gogs",                                      "Gogs", "", "Generic"});
    db.push_back({"CI/CD",  "GitLab\\s+([\\d.]+)",                      "GitLab", "$1", "Generic"});
    db.push_back({"CI/CD",  "Jenkins/([\\d.]+)",                         "Jenkins CI", "$1", "Generic"});

    // ── Message Queues (6 patterns) ──────────────────────────────
    db.push_back({"MQ",     "AMQP",                                      "RabbitMQ / AMQP", "", "Generic"});
    db.push_back({"MQ",     "RabbitMQ",                                  "RabbitMQ", "", "Generic"});
    db.push_back({"MQ",     "ActiveMQ",                                  "Apache ActiveMQ", "", "Generic"});
    db.push_back({"MQ",     "Kafka",                                     "Apache Kafka", "", "Generic"});
    db.push_back({"MQ",     "NATS",                                      "NATS", "", "Generic"});
    db.push_back({"MQ",     "mosquitto",                                 "Mosquitto MQTT", "", "Generic"});

    // ── Monitoring (6 patterns) ──────────────────────────────────
    db.push_back({"Monitoring","Prometheus",                             "Prometheus", "", "Generic"});
    db.push_back({"Monitoring","Grafana",                                "Grafana", "", "Generic"});
    db.push_back({"Monitoring","Nagios",                                 "Nagios", "", "Generic"});
    db.push_back({"Monitoring","Zabbix",                                 "Zabbix", "", "Generic"});
    db.push_back({"Monitoring","Check_MK|checkmk",                       "CheckMK", "", "Generic"});
    db.push_back({"Monitoring","Datadog",                                "Datadog Agent", "", "Generic"});

    // ── Proxies / Load Balancers (8 patterns) ────────────────────
    db.push_back({"Proxy",   "HAProxy ([\\d.]+)",                        "HAProxy", "$1", "Generic"});
    db.push_back({"Proxy",   "Squid/([\\d.]+)",                          "Squid Proxy", "$1", "Generic"});
    db.push_back({"Proxy",   "Varnish",                                  "Varnish Cache", "", "Generic"});
    db.push_back({"Proxy",   "Traefik",                                  "Traefik Proxy", "", "Generic"});
    db.push_back({"Proxy",   "Envoy",                                    "Envoy Proxy", "", "Generic"});
    db.push_back({"Proxy",   "Apache Traffic Server",                    "Apache Traffic Server", "", "Generic"});
    db.push_back({"Proxy",   "Pound",                                    "Pound LB", "", "Generic"});
    db.push_back({"Proxy",   "Varnish \\(v([\\d.]+)\\)",                "Varnish Cache", "$1", "Generic"});

    // ── CMS / Web Apps (8 patterns) ──────────────────────────────
    db.push_back({"CMS",    "WordPress",                                 "WordPress", "", "Generic"});
    db.push_back({"CMS",    "Drupal",                                    "Drupal", "", "Generic"});
    db.push_back({"CMS",    "Joomla",                                    "Joomla", "", "Generic"});
    db.push_back({"CMS",    "Magento",                                   "Magento", "", "Generic"});
    db.push_back({"CMS",    "phpMyAdmin",                                "phpMyAdmin", "", "Generic"});
    db.push_back({"CMS",    "wp-admin|wp-content|wp-includes",           "WordPress", "", "Generic"});
    db.push_back({"CMS",    "Concrete5",                                 "Concrete5 CMS", "", "Generic"});
    db.push_back({"CMS",    "Umbraco",                                   "Umbraco CMS", "", "Windows"});

    // ── Control Panels (6 patterns) ──────────────────────────────
    db.push_back({"Panel",  "Webmin",                                    "Webmin", "", "Generic"});
    db.push_back({"Panel",  "cPanel",                                    "cPanel/WHM", "", "CentOS/CloudLinux"});
    db.push_back({"Panel",  "cpsrvd",                                    "cPanel/WHM", "", "CentOS/CloudLinux"});
    db.push_back({"Panel",  "cpsrvd/([\\d.]+)",                         "cPanel/WHM", "$1", "CentOS/CloudLinux"});
    db.push_back({"Panel",  "Plesk",                                     "Plesk", "", "Windows/CentOS"});
    db.push_back({"Panel",  "Cockpit",                                   "Cockpit", "", "Linux"});

    // ── VPN (5 patterns) ─────────────────────────────────────────
    db.push_back({"VPN",    "OpenVPN",                                   "OpenVPN", "", "Generic"});
    db.push_back({"VPN",    "WireGuard",                                 "WireGuard", "", "Generic"});
    db.push_back({"VPN",    "StrongSwan",                                "StrongSwan", "", "Linux"});
    db.push_back({"VPN",    "SoftEther",                                 "SoftEther", "", "Generic"});
    db.push_back({"VPN",    "OpenConnect",                               "OpenConnect (ocserv)", "", "Generic"});

    // ── IoT / Embedded (5 patterns) ──────────────────────────────
    db.push_back({"Embedded","OpenWrt",                                  "OpenWrt", "", "OpenWrt/LEDE"});
    db.push_back({"Embedded","DD-WRT",                                   "DD-WRT", "", "DD-WRT"});
    db.push_back({"Embedded","pfSense",                                  "pfSense", "", "FreeBSD"});
    db.push_back({"Embedded","OPNsense",                                 "OPNsense", "", "FreeBSD"});
    db.push_back({"Embedded","Tomato",                                   "Tomato Firmware", "", "Linux"});

    // ── Misc (20 patterns) ───────────────────────────────────────
    db.push_back({"Misc",   "OpenSSL ([\\d.]+)",                        "OpenSSL", "$1", "Generic"});
    db.push_back({"Misc",   "OpenSSH",                                   "OpenSSH", "", "Unix/Linux"});
    db.push_back({"Misc",   "Apache ZooKeeper",                          "Apache ZooKeeper", "", "Generic"});
    db.push_back({"Misc",   "Vault v([\\d.]+)",                          "HashiCorp Vault", "$1", "Generic"});
    db.push_back({"Misc",   "Consul",                                    "HashiCorp Consul", "", "Generic"});
    db.push_back({"Misc",   "Nomad",                                     "HashiCorp Nomad", "", "Generic"});
    db.push_back({"Misc",   "Kerberos",                                  "Kerberos KDC", "", "Generic"});
    db.push_back({"Misc",   "rsync",                                     "Rsync", "", "Unix/Linux"});
    db.push_back({"Misc",   "SVN|Subversion",                            "Apache Subversion", "", "Generic"});
    db.push_back({"Misc",   "Git.*HTTP",                                 "Git over HTTP", "", "Generic"});
    db.push_back({"Misc",   "Apache.*mod_",                              "Apache Module", "", "Generic"});
    db.push_back({"Misc",   "\"cluster_name\"",                          "Elasticsearch Cluster", "", "Generic"});
    db.push_back({"Misc",   "Net::LDAP",                                 "Perl LDAP", "", "Generic"});
    db.push_back({"Misc",   "Python/([\\d.]+)",                          "Python", "$1", "Generic"});
    db.push_back({"Misc",   "Java/([\\d.]+)",                            "Java", "$1", "Generic"});
    db.push_back({"Misc",   "Apache.*Axis",                              "Apache Axis (SOAP)", "", "Generic"});
    db.push_back({"Misc",   "Tinyproxy",                                 "Tinyproxy", "", "Generic"});
    db.push_back({"Misc",   "Minecraft",                                 "Minecraft Server", "", "Generic"});
    db.push_back({"Misc",   "Rocket.Chat",                               "Rocket.Chat", "", "Generic"});
    db.push_back({"Misc",   "Mattermost",                                "Mattermost", "", "Generic"});

    return db;
}

/* ─────────────────────────────────────────────────────────────────
 * OS FINGERPRINT DATABASE
 * ───────────────────────────────────────────────────────────────── */

struct OsFingerprintEntry {
    string os_name;
    string os_version;
    float  confidence;
    string pattern;
    int    ttl_hint;
    string platform;
};

static vector<OsFingerprintEntry> build_os_db() {
    return {
        {"Windows",      "10/Server 2016/2019",  0.85, "Windows NT 10\\.0",              128, "windows"},
        {"Windows",      "8.1/Server 2012 R2",  0.85, "Windows NT 6\\.3",               128, "windows"},
        {"Windows",      "8/Server 2012",        0.85, "Windows NT 6\\.2",               128, "windows"},
        {"Windows",      "7/Server 2008 R2",     0.85, "Windows NT 6\\.1",               128, "windows"},
        {"Windows",      "Vista/Server 2008",    0.85, "Windows NT 6\\.0",               128, "windows"},
        {"Windows",      "XP/Server 2003",       0.85, "Windows NT 5\\.",                128, "windows"},
        {"Windows",      "2000",                 0.85, "Windows NT 4\\.0|Windows 2000",   128, "windows"},
        {"Ubuntu Linux", "24.04",                0.80, "Ubuntu|ubuntu",                   64,  "linux"},
        {"Debian Linux", "12/11",                0.80, "Debian|debian",                  64,  "linux"},
        {"CentOS Linux", "9/8/7",                0.80, "CentOS|centos",                   64,  "linux"},
        {"Red Hat Linux","9/8/7",                0.80, "Red Hat|redhat",                  64,  "linux"},
        {"Fedora Linux", "",                    0.80, "Fedora|fedora",                    64,  "linux"},
        {"SUSE Linux",   "openSUSE",            0.80, "SUSE|suse|openSUSE",               64,  "linux"},
        {"Arch Linux",   "",                    0.75, "Arch Linux|archlinux",             64,  "linux"},
        {"Alpine Linux", "",                    0.75, "Alpine|alpine",                    64,  "linux"},
        {"FreeBSD",      "",                    0.85, "FreeBSD|freebsd",                  64,  "unix"},
        {"OpenBSD",      "",                    0.85, "OpenBSD|openbsd",                  64,  "unix"},
        {"NetBSD",       "",                    0.80, "NetBSD|netbsd",                    64,  "unix"},
        {"macOS",        "Sonoma/Ventura",      0.80, "Darwin|darwin",                    64,  "unix"},
        {"Cisco IOS",    "",                    0.90, "Cisco|cisc",                      255, "network"},
        {"Cisco ASA",    "",                    0.85, "Cisco ASA|Adaptive Security",      255, "network"},
        {"Juniper JunOS","",                    0.85, "Juniper|junos",                    255, "network"},
        {"HP ProCurve",  "",                    0.80, "ProCurve|ProCurve",               255, "network"},
        {"MikroTik",     "RouterOS",            0.85, "MikroTik|RouterOS",                64,  "network"},
        {"Ubiquiti",     "EdgeOS",              0.80, "Ubiquiti|EdgeOS",                  64,  "network"},
        {"Palo Alto",    "PAN-OS",              0.80, "Palo Alto|PAN-OS",                255, "network"},
        {"Fortinet",     "FortiGate",           0.85, "FortiGate|Fortinet",              255, "network"},
        {"SonicWall",    "SonicOS",             0.80, "SonicWall|SonicOS",               255, "network"},
        {"OpenWrt",      "",                    0.85, "OpenWrt|openwrt",                   64,  "linux"},
        {"DD-WRT",       "",                    0.85, "DD-WRT|dd-wrt",                    64,  "linux"},
        {"pfSense",      "",                    0.85, "pfSense|pfsense",                  64,  "unix"},
        {"OPNsense",     "",                    0.80, "OPNsense|opnsense",                64,  "unix"},
        {"Synology DSM", "",                    0.80, "Synology|synology",                64,  "linux"},
        {"QNAP QTS",     "",                    0.80, "QNAP|qnap",                        64,  "linux"},
        {"VMware ESXi",  "",                    0.90, "VMware|vmware|ESXi",               64,  "unix"},
        {"Citrix XenServer","",                 0.80, "XenServer|xenserver",               64,  "linux"},
        {"Proxmox VE",   "",                    0.80, "Proxmox|proxmox",                  64,  "linux"},
        {"TrueNAS",      "",                    0.80, "TrueNAS|truenas",                  64,  "unix"},
        {"Raspberry Pi OS","",                  0.70, "Raspberry Pi|raspberry",            64,  "linux"},
        {"Linux",        "generic",             0.50, "Linux|linux",                      64,  "linux"},
        {"Unix",         "generic",             0.40, "UNIX|unix",                       255,  "unix"},
        {"Windows",      "generic",             0.50, "Win32|Win64|Windows|windows",      128, "windows"},
    };
}

/* ─────────────────────────────────────────────────────────────────
 * CVE / VULNERABILITY DATABASE
 * ───────────────────────────────────────────────────────────────── */

struct CVEEntry {
    string service_pattern;
    string version_max;
    string cve_id;
    string description;
    double cvss;
    string severity;
};

static vector<CVEEntry> build_cve_db() {
    return {
        {"OpenSSH", "8.7",  "CVE-2024-6387", "regreSSHion -- unauthenticated RCE in signal handler", 9.8, "CRITICAL"},
        {"OpenSSH", "8.5",  "CVE-2023-38408", "SSH-agent remote code execution via crafted PKCS11 provider", 9.8, "CRITICAL"},
        {"OpenSSH", "7.7",  "CVE-2018-15473", "Username enumeration via timing side-channel", 5.3, "MEDIUM"},
        {"OpenSSH", "7.2",  "CVE-2016-10012", "Privilege separation bypass -- unauthorized key acceptance", 7.5, "HIGH"},
        {"vsftpd",  "2.3.4","CVE-2011-2523", "BACKDOOR -- vsftpd 2.3.4 smiley-face backdoor (RCE)", 10.0, "CRITICAL"},
        {"ProFTPD", "1.3.3c","CVE-2010-4221","ProFTPD sql_include module buffer overflow (RCE)", 9.3, "CRITICAL"},
        {"Pure-FTPd", "1.0.48","CVE-2020-9365","Pure-FTPd heap-based buffer overflow in dirlist", 7.5, "HIGH"},
        {"Pure-FTPd", "1.0.47","CVE-2020-9365","Pure-FTPd heap-based overflow in dirlist", 7.5, "HIGH"},
        {"Pure-FTPd", "1.0.46","CVE-2019-20176","Pure-FTPd symlink resolution DoS", 5.0, "MEDIUM"},
        {"Pure-FTPd", "1.0.45","CVE-2019-20176","Pure-FTPd symlink resolution DoS", 5.0, "MEDIUM"},
        {"Pure-FTPd", "1.0.43","CVE-2014-3639","Pure-FTPd race condition in chroot", 6.1, "MEDIUM"},
        {"Apache httpd", "2.4.50","CVE-2021-42013","Path traversal bypass -- unauthenticated RCE", 9.8, "CRITICAL"},
        {"Apache httpd", "2.4.49","CVE-2021-41773","Path traversal + RCE in CGI scripts", 9.8, "CRITICAL"},
        {"Apache httpd", "2.4.17","CVE-2017-7679","mod_mime buffer overflow", 9.8, "CRITICAL"},
        {"Apache httpd", "2.2.99","EOL", "Apache 2.2 is end-of-life -- no security patches", 0, "HIGH"},
        {"nginx", "1.3.9","CVE-2013-4547","Nginx null-byte injection -- access control bypass", 7.5, "HIGH"},
        {"Microsoft IIS", "6.0","CVE-2017-7269","WebDAV buffer overflow -- unauthenticated RCE", 10.0, "CRITICAL"},
        {"PHP", "5.99","EOL","PHP 5.x end-of-life -- no security patches, many unpatched CVEs", 0, "CRITICAL"},
        {"PHP", "7.1","EOL","PHP 7.1 and older end-of-life", 0, "HIGH"},
        {"PHP", "7.3","CVE-2019-11043","PHP-FPM nginx misconfiguration RCE", 9.8, "CRITICAL"},
        {"OpenSSL", "1.0.2","CVE-2014-0160","Heartbleed -- memory disclosure of private keys", 9.8, "CRITICAL"},
        {"OpenSSL", "1.0.1","CVE-2014-0160","Heartbleed -- memory disclosure of private keys", 9.8, "CRITICAL"},
        {"Redis", "0.0","INFO-NOAUTH","Redis: No authentication by default -- check CONFIG SET requirepass", 7.0, "HIGH"},
        {"MongoDB", "0.0","INFO-NOAUTH","MongoDB: No auth by default -- check /etc/mongod.conf bindIp+auth", 7.0, "HIGH"},
        {"Jenkins CI", "2.441","CVE-2024-23897","Arbitrary file read via CLI (auth bypass in older versions)", 9.8, "CRITICAL"},
        {"Apache Tomcat", "8.0.99","EOL","Tomcat 8.0 end-of-life", 0, "HIGH"},
        {"Apache Tomcat", "7.0.99","CVE-2020-1938","Ghostcat: AJP connector file read / inclusion", 9.8, "CRITICAL"},
        {"Drupal", "7.99","CVE-2018-7600","Drupalgeddon2 -- unauthenticated RCE", 9.8, "CRITICAL"},
        {"Docker Engine", "99.99","INFO-EXPOSED","Docker daemon exposed without TLS -- container escape possible", 10.0, "CRITICAL"},
        {"WordPress", "4.7","CVE-2016-10033","WordPress REST API content injection", 7.5, "HIGH"},
        {"WordPress", "5.99","CVE-2023-45127","WordPress plugin vulnerability chain", 8.1, "HIGH"},
        {"Postfix", "3.5","CVE-2023-51764","Postfix SMTP smuggling", 7.5, "HIGH"},
        {"Exim", "4.94","CVE-2023-42117","Exim remote code execution", 9.8, "CRITICAL"},
        {"Exim", "4.94","CVE-2023-42116","Exim out-of-bounds read in SMTP response", 7.5, "HIGH"},
        {"Exim", "4.93","CVE-2022-3559","Exim use-after-free in SMTP accept", 9.8, "CRITICAL"},
        {"Exim", "4.92","CVE-2020-28007","Exim privilege escalation via link attack", 7.0, "HIGH"},
        {"Exim", "4.90","CVE-2019-10149","Exim RCE via experimental SPF support", 9.8, "CRITICAL"},
        {"Sendmail", "8.16","CVE-2023-40300","Sendmail heap overflow", 8.1, "HIGH"},
        {"ProFTPD", "1.3.8","CVE-2023-51766","ProFTPD mod_tls memory leak", 5.3, "MEDIUM"},
        {"Dovecot IMAP", "2.3.18","CVE-2023-51766","Dovecot IMAP 2.3.18 DoS", 5.3, "MEDIUM"},
        {"Dovecot IMAP", "2.3.15","CVE-2022-30550","Dovecot memory leak in IMAP STATUS", 5.3, "MEDIUM"},
        {"Dovecot POP3", "2.3.14","CVE-2022-30550","Dovecot memory leak in POP3", 5.3, "MEDIUM"},
        {"Dovecot POP3", "2.2.36","CVE-2021-29157","Dovecot POP3 crash via empty token", 5.0, "MEDIUM"},
        {"Dovecot IMAP", "2.2.36","CVE-2021-29157","Dovecot IMAP crash via empty token", 5.0, "MEDIUM"},
        {"Dovecot POP3", "2.2.35","CVE-2017-14461","Dovecot POP3 crash on malformed date", 5.0, "MEDIUM"},
        {"Dovecot IMAP", "2.2.27","CVE-2017-2669","Dovecot IMAP crash on invalid NOTIFY", 5.0, "MEDIUM"},
        {"LiteSpeed", "6.0.4","CVE-2022-44728","LiteSpeed Web Server XSS vulnerability", 6.1, "MEDIUM"},
        {"LiteSpeed", "6.0.0","CVE-2022-44727","LiteSpeed Web Server SSRF vulnerability", 7.5, "HIGH"},
        {"LiteSpeed", "5.4.7","CVE-2022-22736","LiteSpeed Web Server XSS in HTTP response", 6.1, "MEDIUM"},
        {"cPanel", "11.108","CVE-2023-4487","cPanel PHPMailer dependency RCE", 9.8, "CRITICAL"},
        {"cPanel", "11.106","CVE-2023-29489","cPanel XSS in cpsrvd", 6.1, "MEDIUM"},
        {"cPanel", "11.104","CVE-2022-48105","cPanel privilege escalation", 7.8, "HIGH"},
        {"cPanel", "11.102","CVE-2022-45479","cPanel password hash disclosure", 7.5, "HIGH"},
        {"Squid Proxy", "5.9","CVE-2023-46849","Squid denial of service", 7.5, "HIGH"},
        {"HAProxy", "2.6","CVE-2023-40225","HAProxy HTTP request smuggling", 6.5, "MEDIUM"},
        {"Lighttpd", "1.4.78","CVE-2023-48051","Lighttpd memory leak", 5.0, "MEDIUM"},
        {"Varnish Cache", "7.4","CVE-2023-44487","Varnish HTTP/2 rapid reset", 7.5, "HIGH"},
        {"Traefik Proxy", "3.0","CVE-2023-47124","Traefik authentication bypass", 8.2, "HIGH"},
        {"Kubernetes", "1.24","CVE-2023-3676","Kubernetes kubelet DoS", 7.5, "HIGH"},
        {"Kubernetes", "1.23","CVE-2023-2431","Kubernetes privilege escalation in kubelet", 7.0, "HIGH"},
        {"GitLab", "16.7","CVE-2024-0402","GitLab DAST scanner privilege escalation", 8.7, "HIGH"},
        {"GitLab", "16.5","CVE-2023-5009","GitLab pipeline token leak", 7.5, "HIGH"},
    };
}

/* ─────────────────────────────────────────────────────────────────
 * NETWORK UTILITIES
 * ───────────────────────────────────────────────────────────────── */

static bool init_sockets() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2,2), &wsa) == 0;
#else
    return true;
#endif
}

static void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int resolve_host(const string& host, struct sockaddr_in& addr) noexcept {
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) == 1)
        return 0;

    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (ret != 0 || !res) return -1;

    memcpy(&addr.sin_addr, &((struct sockaddr_in*)res->ai_addr)->sin_addr, sizeof(struct in_addr));
    freeaddrinfo(res);
    return 0;
}

static bool set_nonblocking(SOCKET s, bool nonblock) {
#ifdef _WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(s, F_SETFL, nonblock ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
#endif
}

static bool connect_with_timeout(SOCKET s, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms) {
    if (!set_nonblocking(s, true)) return false;

    int res = connect(s, addr, addrlen);
    if (res == 0) {
        set_nonblocking(s, false);
        return true;
    }

#ifdef _WIN32
    if (WSAGetLastError() != WSAEWOULDBLOCK) { set_nonblocking(s, false); return false; }
#else
    if (errno != EINPROGRESS) { set_nonblocking(s, false); return false; }
#endif

    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLOUT;
    res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) { set_nonblocking(s, false); return false; }

    int so_error;
    socklen_t len = sizeof(so_error);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
        set_nonblocking(s, false);
        return false;
    }

    set_nonblocking(s, false);
    return true;
}

static int recv_with_timeout(SOCKET s, char* buf, int bufsize, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLIN;
    int res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) return -1;

    return recv(s, buf, bufsize, 0);
}

static int send_with_timeout(SOCKET s, const char* data, int len, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = s;
    pfd.events = POLLOUT;
    int res = poll(&pfd, 1, timeout_ms);
    if (res <= 0) return -1;

    return send(s, data, len, 0);
}

static SOCKET create_tcp_socket();

static std::regex get_cached_regex(std::string_view pattern) {
    static std::unordered_map<std::string, std::regex> cache;
    auto it = cache.find(std::string(pattern));
    if (it != cache.end()) return it->second;
    std::regex re(std::string(pattern), std::regex_constants::icase);
    cache[std::string(pattern)] = re;
    return re;
}

static SOCKET cached_sock = INVALID_SOCKET;
static std::string cached_sock_host;
static int cached_sock_port = -1;

static SOCKET get_or_create_socket(std::string_view host, int port, int timeout_ms) {
    if (cached_sock != INVALID_SOCKET && cached_sock_host == host && cached_sock_port == port) {
        return cached_sock;
    }
    if (cached_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(cached_sock);
        cached_sock = INVALID_SOCKET;
    }
    cached_sock = create_tcp_socket();
    if (IS_INVALID(cached_sock)) return INVALID_SOCKET;
    struct sockaddr_in addr;
    std::string h(host);
    if (resolve_host(h, addr) != 0) { CLOSE_SOCKET(cached_sock); cached_sock = INVALID_SOCKET; return INVALID_SOCKET; }
    addr.sin_port = htons((uint16_t)port);
    if (!connect_with_timeout(cached_sock, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(cached_sock); cached_sock = INVALID_SOCKET; return INVALID_SOCKET;
    }
    cached_sock_host = h;
    cached_sock_port = port;
    return cached_sock;
}

static void flush_socket_cache() {
    if (cached_sock != INVALID_SOCKET) {
        CLOSE_SOCKET(cached_sock);
        cached_sock = INVALID_SOCKET;
    }
}

static SOCKET create_tcp_socket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID(s)) return INVALID_SOCKET;

    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
    return s;
}

/* ─────────────────────────────────────────────────────────────────
 * PROTOCOL-SPECIFIC PROBE FUNCTIONS
 * ───────────────────────────────────────────────────────────────── */

static string sanitize_banner(const char* buf, int n) {
    string result;
    for (int i = 0; i < n && i < MAX_BANNER_SIZE; i++) {
        unsigned char c = (unsigned char)buf[i];
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') {
            result += (char)c;
        }
    }
    return result;
}

string probeHTTP(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: HackIT-CPP/4.1\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    send_with_timeout(s, req.c_str(), (int)req.size(), timeout_ms);

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    flush_socket_cache();

    if (n <= 0) return "";
    return sanitize_banner(buf, n);
}

string probeSSH(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n <= 0) { flush_socket_cache(); return ""; }
    string raw = sanitize_banner(buf, n);

    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    flush_socket_cache();
    if (line.find("SSH-") != string::npos) return line;

    return raw;
}

string probeSMTP(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    string ehlo = "EHLO hackit.local\r\n";
    send_with_timeout(s, ehlo.c_str(), (int)ehlo.size(), timeout_ms);

    char buf2[4096] = {};
    int n2 = recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    flush_socket_cache();

    string result;
    if (n > 0) result += sanitize_banner(buf, n);
    if (n2 > 0) result += "\n" + sanitize_banner(buf2, n2);

    if (result.empty()) return "";
    return result;
}

string probeFTP(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n > 0) {
        string user = "USER anonymous\r\n";
        send_with_timeout(s, user.c_str(), (int)user.size(), timeout_ms);
        char buf2[4096] = {};
        recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    }
    flush_socket_cache();

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.find("220") != string::npos) return line;

    return raw;
}

string probePOP3(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n > 0) {
        string capa = "CAPA\r\n";
        send_with_timeout(s, capa.c_str(), (int)capa.size(), timeout_ms);
        char buf2[4096] = {};
        recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    }
    flush_socket_cache();

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (!line.empty()) return line;

    return raw;
}

string probeIMAP(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n > 0) {
        string capa = "A001 CAPABILITY\r\n";
        send_with_timeout(s, capa.c_str(), (int)capa.size(), timeout_ms);
        char buf2[4096] = {};
        recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    }
    flush_socket_cache();

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (!line.empty()) return line;

    return raw;
}

string probeMySQL(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n <= 0) { flush_socket_cache(); return ""; }
    string result = sanitize_banner(buf, n);

    if (n > 4) {
        string version_str;
        for (int i = 4; i < n; i++) {
            char c = buf[i];
            if (c == 0) break;
            if (c >= 32 && c <= 126) version_str += c;
        }
        if (!version_str.empty()) {
            result = "MySQL " + version_str;
        }
    }

    flush_socket_cache();
    return result;
}

string probeHTTPS(const string& host, int port, int timeout_ms) {
    SOCKET s = get_or_create_socket(host, port, timeout_ms);
    if (IS_INVALID(s)) return "";

    uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x31,
        0x01, 0x00, 0x00, 0x2d, 0x03, 0x03,
        0xd0, 0x6d, 0x7e, 0xbe, 0x9c, 0x29, 0xd0, 0x33,
        0x43, 0xed, 0x7a, 0x2c, 0xe8, 0x49, 0xc1, 0xd8,
        0x22, 0x05, 0x20, 0xd1, 0x6b, 0xdf, 0xf4, 0x3a,
        0x3a, 0x49, 0x51, 0xd1, 0x32, 0x72, 0x57, 0x90,
        0x00,
        0x00, 0x04,
        0xc0, 0x2b, 0x00, 0x2f,
        0x01, 0x00
    };

    send_with_timeout(s, (const char*)client_hello, sizeof(client_hello), timeout_ms);

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    if (n > 0 && (uint8_t)buf[0] == 0x16) {
        char buf2[4096] = {};
        int n2 = recv_with_timeout(s, buf2, sizeof(buf2)-1, 500);

        string combined;
        combined.append(sanitize_banner(buf, n));
        if (n2 > 0) combined.append(sanitize_banner(buf2, n2));

        string tls_info = "[SSL/TLS] ";
        if (n > 5) {
            uint8_t major = buf[5];
            uint8_t minor = buf[6];
            if (major == 3 && minor == 4) tls_info += "TLS 1.3";
            else if (major == 3 && minor == 3) tls_info += "TLS 1.2";
            else if (major == 3 && minor == 2) tls_info += "TLS 1.1";
            else if (major == 3 && minor == 1) tls_info += "TLS 1.0";
            else if (major == 3 && minor == 0) tls_info += "SSL 3.0";
            else tls_info += "TLS v" + to_string(major) + "." + to_string(minor);
        }

        string cert_info;
        for (int i = 0; i < n; i++) {
            if (buf[i] >= 32 && buf[i] <= 126) {
                cert_info += (char)buf[i];
            }
        }

        flush_socket_cache();
        return tls_info + " | cert-hints: " + cert_info.substr(0, 80);
    }

    flush_socket_cache();

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    return "[PLAIN] " + raw.substr(0, 200);
}

/* ─────────────────────────────────────────────────────────────────
 * OS DETECTION ENGINE
 * ───────────────────────────────────────────────────────────────── */

static int detect_ttl(const string& host) noexcept {
    (void)host;
    return -1;
}

static OsFingerprint detect_os_from_banner(const string& banner, const vector<OsFingerprintEntry>& db) {
    OsFingerprint result;
    result.os_name = "Unknown";
    result.confidence = 0.0f;

    if (banner.empty()) return result;

    for (const auto& entry : db) {
        try {
            regex re = get_cached_regex(entry.pattern);
            if (regex_search(banner, re)) {
                if (entry.confidence > result.confidence) {
                    result.os_name = entry.os_name;
                    result.os_version = entry.os_version;
                    result.confidence = entry.confidence;
                    result.clues.emplace_back("banner matched: " + entry.pattern);
                }
            }
        } catch (...) {}
    }

    return result;
}

static OsFingerprint combine_os_detection(const string& banner, int ttl_value) noexcept {
    static auto db = build_os_db();
    OsFingerprint result = detect_os_from_banner(banner, db);

    if (ttl_value > 0) {
        string ttl_os;
        if (ttl_value <= 64) {
            ttl_os = "Unix/Linux";
        } else if (ttl_value <= 128) {
            ttl_os = "Windows";
        } else {
            ttl_os = "Network Device";
        }

        result.clues.emplace_back("TTL=" + to_string(ttl_value) + " suggests " + ttl_os);

        if (result.confidence < 0.3f) {
            result.os_name = ttl_os;
            result.confidence = 0.4f;
        }
    }

    return result;
}

/* ─────────────────────────────────────────────────────────────────
 * PORT-TO-SERVICE MAPPING
 * ───────────────────────────────────────────────────────────────── */

static string get_port_service(int port) noexcept {
    static const map<int,string> port_svc = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{135,"RPC"},{139,"NetBIOS"},{143,"IMAP"},
        {161,"SNMP"},{162,"SNMP-Trap"},{389,"LDAP"},{443,"HTTPS"},
        {445,"SMB"},{464,"Kerberos"},{465,"SMTPS"},{500,"IKE"},
        {514,"Syslog"},{587,"SMTP-Submission"},{593,"RPC"},{636,"LDAPS"},
        {691,"MS-Exchange"},{873,"Rsync"},{990,"FTPS"},{993,"IMAPS"},
        {995,"POP3S"},{1025,"RPC-NFS"},{1080,"SOCKS"},{1194,"OpenVPN"},
        {1352,"Lotus-Notes"},{1389,"LDAP"},{1433,"MSSQL"},{1434,"MSSQL-UDP"},
        {1521,"Oracle-DB"},{1701,"L2TP"},{1723,"PPTP"},{2049,"NFS"},
        {2082,"cPanel"},{2083,"cPanel-SSL"},{2095,"Webmail"},{2096,"Webmail-SSL"},
        {2181,"ZooKeeper"},{2222,"DirectAdmin"},{2375,"Docker"},{2376,"Docker-SSL"},
        {2483,"Oracle-DB"},{2484,"Oracle-DB-SSL"},{3000,"Node.js/Dev"},{3128,"Squid-Proxy"},
        {3268,"LDAP-GC"},{3269,"LDAP-GC-SSL"},{3306,"MySQL"},{3310,"ClamAV"},
        {3389,"RDP"},{3478,"STUN"},{3689,"DAAP"},{3690,"SVN"},
        {3724,"WoW"},{4000,"ICQ"},{4045,"NFS-Lockd"},{4443,"HTTPS-Alt"},
        {4500,"IPsec-NAT"},{4567,"Sinatra"},{4848,"GlassFish"},{4899,"RAdmin"},
        {5000,"UPNP/Flask"},{5001,"iSCSI"},{5002,"TIBCO"},{5003,"FileMaker"},
        {5060,"SIP"},{5061,"SIP-TLS"},{5222,"XMPP"},{5223,"XMPP-SSL"},
        {5269,"XMPP-Server"},{5353,"mDNS"},{5432,"PostgreSQL"},{5480,"VMware-VAMI"},
        {5555,"Android-ADB"},{5631,"pcAnywhere"},{5666,"NRPE"},{5672,"AMQP"},
        {5683,"CoAP"},{5800,"VNC-HTTP"},{5900,"VNC"},{5985,"WinRM-HTTP"},
        {5986,"WinRM-HTTPS"},{6000,"X11"},{6379,"Redis"},{6443,"Kubernetes-API"},
        {6514,"Syslog-TLS"},{6566,"Sane"},{6667,"IRC"},{6697,"IRC-SSL"},
        {6789,"Splunk"},{6881,"BitTorrent"},{6969,"BitTorrent-Tracker"},
        {7000,"Cassandra"},{7001,"WebLogic"},{7010,"Cassandra-SSL"},{7070,"RealServer"},
        {7071,"Zimbra"},{7171,"Tibia"},{7199,"Cassandra-JMX"},{7443,"HTTPS-Alt"},
        {7474,"Neo4j"},{7547,"TR-069"},{7777,"UltraVNC"},{7990,"BitBucket"},
        {8000,"HTTP-Alt"},{8001,"HTTP-Alt"},{8005,"Tomcat-Shutdown"},{8008,"HTTP-Alt"},
        {8009,"AJP"},{8080,"HTTP-Proxy"},{8081,"HTTP-Alt"},{8086,"InfluxDB"},
        {8089,"Splunk"},{8090,"HTTP-Alt"},{8091,"Couchbase"},{8096,"Emby"},
        {8140,"Puppet"},{8172,"MSSQL-Monitor"},{8200,"VMware-HTTP"},{8222,"VMware-HTTPS"},
        {8243,"HTTPS-Alt"},{8280,"HTTP-Alt"},{8300,"Consul"},{8332,"Bitcoin"},
        {8333,"Bitcoin"},{8400,"CommVault"},{8443,"HTTPS-Alt"},{8500,"Consul-UI"},
        {8530,"WMI"},{8545,"Ethereum"},{8649,"Ganglia"},{8750,"Java-RMI"},
        {8761,"Eureka"},{8888,"HTTP-Alt"},{8983,"Solr"},{9000,"Hadoop"},
        {9042,"Cassandra-Native"},{9060,"WebLogic"},{9080,"WebSphere"},{9090,"Cockpit"},
        {9092,"Kafka"},{9093,"Kafka-SSL"},{9100,"JetDirect"},{9160,"Cassandra-Thrift"},
        {9200,"Elasticsearch"},{9210,"Elasticsearch"},{9292,"Hive"},{9300,"Elasticsearch-Transport"},
        {9418,"Git"},{9443,"HTTPS-Alt"},{9600,"OMNIBus"},{9876,"Runescape"},
        {9898,"Samba"},{9990,"JBoss"},{9991,"JBoss"},{9992,"JBoss"},
        {9993,"JBoss"},{9994,"JBoss"},{9995,"JBoss"},{9996,"JBoss"},
        {9997,"Splunk-Log"},{9998,"HTTP-Alt"},{9999,"HTTP-Alt"},{10000,"Webmin"},
        {10001,"Ubiquiti"},{10161,"SNMP-Agent"},{10162,"SNMP-Trap"},{10250,"Kubelet"},
        {11000,"MySQL-Cluster"},{11211,"Memcached"},{12000,"WebSphere-Caching"},
        {12345,"NetBus"},{13000,"RabbitMQ"},{13579,"Pegasus"},{13722,"Tivoli"},
        {14333,"MSSQL"},{15118,"IBM-DB2"},{15672,"RabbitMQ"},{16000,"Oracle-DB"},
        {16080,"HTTP-Alt"},{16384,"CISCO"},{16992,"Intel-AMT"},{17000,"HTTP-Alt"},
        {17500,"Dropbox"},{18080,"HTTP-Alt"},{19000,"SMB2"},{20000,"DNP"},
        {21000,"HTTP-Alt"},{22222,"DirectAdmin"},{23073,"Soldat"},{23456,"OwnCloud"},
        {24007,"GlusterFS"},{24800,"Synergy"},{25000,"TeamSpeak"},{25565,"Minecraft"},
        {25672,"RabbitMQ"},{27015,"Steam"},{27017,"MongoDB"},{27018,"MongoDB"},
        {27374,"SubSeven"},{27960,"Quake3"},{28017,"MongoDB-Web"},{30000,"HTTP-Alt"},
        {30303,"Ethereum"},{31337,"BackOrifice"},{32400,"Plex"},{32764,"Linksys"},
        {32768,"Filenet"},{33333,"HP-RBAC"},{33848,"Jenkins"},{34197,"Factorio"},
        {34443,"HTTPS-Alt"},{40000,"SafetyNET"},{40404,"CR-Web"},{47808,"BACnet"},
        {49152,"Windows-RPC"},{50000,"IBM-DB2"},{50070,"Hadoop-NameNode"},
        {50075,"Hadoop-DataNode"},{50090,"Hadoop-SecondaryNN"},{54321,"PCAnywhere"},
        {58080,"HTTP-Alt"},{60000,"DeepSound"},{60020,"Google-AD"},{62078,"iPhone-Sync"},
        {65000,"HTTP-Alt"}
    };

    auto it = port_svc.find(port);
    if (it != port_svc.end()) return it->second;

    return "unknown";
}

/* ─────────────────────────────────────────────────────────────────
 * VERSION MATCHING ENGINE
 * ───────────────────────────────────────────────────────────────── */

struct VersionMatch {
    string service;
    string product;
    string version;
    string os_hint;
    double confidence;
};

static vector<VersionMatch> match_version_patterns(const string& banner) {
    vector<VersionMatch> matches;
    static auto patterns = build_version_patterns();

    for (const auto& p : patterns) {
        try {
            regex re = get_cached_regex(p.pattern);
            smatch m;
            if (regex_search(banner, m, re)) {
                VersionMatch vm;
                vm.service = p.service;
                vm.product = p.product;
                vm.os_hint = p.os_hint;
                vm.confidence = 0.85;

                if (!p.version.empty() && m.size() > 1) {
                    string ver = m[1].str();
                    if (p.version == "$1") {
                        vm.version = ver;
                    } else {
                        vm.version = p.version;
                    }
                }

                matches.emplace_back(vm);
            }
        } catch (...) {}
    }

    return matches;
}

/* ─────────────────────────────────────────────────────────────────
 * CVE CHECKING ENGINE
 * ───────────────────────────────────────────────────────────────── */

static bool version_lte(const string& v1, const string& v2) noexcept {
    auto parse = [](const string& v) -> vector<int> {
        vector<int> parts;
        stringstream ss(v);
        string part;
        while (getline(ss, part, '.')) {
            string num;
            for (char c : part) {
                if (isdigit(c)) num += c;
                else break;
            }
            try { parts.emplace_back(stoi(num)); }
            catch (...) { parts.emplace_back(0); }
        }
        return parts;
    };

    auto p1 = parse(v1), p2 = parse(v2);
    size_t maxLen = max(p1.size(), p2.size());
    p1.resize(maxLen, 0);
    p2.resize(maxLen, 0);

    for (size_t i = 0; i < maxLen; i++) {
        if (p1[i] < p2[i]) return true;
        if (p1[i] > p2[i]) return false;
    }
    return true;
}

static vector<string> check_vulnerabilities(const string& product, const string& version) {
    vector<string> vulns;
    static auto cve_db = build_cve_db();

    for (const auto& cve : cve_db) {
        string sl = product, pl = cve.service_pattern;
        transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
        transform(pl.begin(), pl.end(), pl.begin(), ::tolower);
        if (sl.find(pl) == string::npos && pl.find(sl) == string::npos) continue;

        if (cve.version_max == "EOL" || cve.version_max == "INFO-NOAUTH" ||
            cve.version_max == "INFO-EXPOSED" || cve.version_max == "0.0") {
            string v = "[" + cve.severity + "] " + cve.cve_id + " -- " + cve.description;
            if (cve.cvss > 0) {
                char buf[32];
                snprintf(buf, sizeof(buf), " (CVSS:%.1f)", cve.cvss);
                v += buf;
            }
            vulns.emplace_back(v);
            continue;
        }

        if (!version.empty() && !cve.version_max.empty()) {
            if (version_lte(version, cve.version_max)) {
                string v = "[" + cve.severity + "] " + cve.cve_id + " -- " + cve.description;
                char buf[32];
                snprintf(buf, sizeof(buf), " (CVSS:%.1f)", cve.cvss);
                v += buf;
                vulns.emplace_back(v);
            }
        }
    }

    return vulns;
}

/* ─────────────────────────────────────────────────────────────────
 * SERVICE SCANNER
 * ───────────────────────────────────────────────────────────────── */

static void set_port_state(ScanResult& result, bool open) noexcept {
    result.state = open ? "OPEN" : "CLOSED/FILTERED";
}

static string detect_service_from_banner(int port, const string& banner) {
    auto matches = match_version_patterns(banner);
    if (!matches.empty()) {
        return matches[0].service;
    }
    return get_port_service(port);
}

ScanResult scan_service(const string& host, int port, int timeout_ms) {
    ScanResult result;
    result.port = port;
    result.confidence = 0.0;
    result.risk_score = 0.0;
    result.ssl = false;

    string banner;
    int probe_port = port;

    enum ProbeType { PROBE_AUTO, PROBE_HTTP, PROBE_SSH, PROBE_SMTP, PROBE_FTP,
                     PROBE_POP3, PROBE_IMAP, PROBE_MYSQL, PROBE_HTTPS };
    ProbeType ptype = PROBE_AUTO;

    switch (port) {
        case 80: case 8000: case 8001: case 8008: case 8080: case 8081:
        case 8082: case 8888: case 9000: case 9090: case 3000: case 5000:
        case 2082: case 2083: case 2095: case 2096: case 10000:
            ptype = PROBE_HTTP; break;
        case 22: ptype = PROBE_SSH; break;
        case 25: case 465: case 587: ptype = PROBE_SMTP; break;
        case 21: case 990: ptype = PROBE_FTP; break;
        case 110: case 995: ptype = PROBE_POP3; break;
        case 143: case 993: ptype = PROBE_IMAP; break;
        case 3306: ptype = PROBE_MYSQL; break;
        case 443: case 8443: case 9443: case 10443: ptype = PROBE_HTTPS; break;
        default:
            break;
    }

    switch (ptype) {
        case PROBE_HTTP:  banner = probeHTTP(host, probe_port, timeout_ms); break;
        case PROBE_SSH:   banner = probeSSH(host, probe_port, timeout_ms); break;
        case PROBE_SMTP:  banner = probeSMTP(host, probe_port, timeout_ms); break;
        case PROBE_FTP:   banner = probeFTP(host, probe_port, timeout_ms); break;
        case PROBE_POP3:  banner = probePOP3(host, probe_port, timeout_ms); break;
        case PROBE_IMAP:  banner = probeIMAP(host, probe_port, timeout_ms); break;
        case PROBE_MYSQL: banner = probeMySQL(host, probe_port, timeout_ms); break;
        case PROBE_HTTPS: banner = probeHTTPS(host, probe_port, timeout_ms); break;
        default: {
            banner = probeHTTP(host, probe_port, timeout_ms);
            if (banner.empty()) {
                SOCKET s = get_or_create_socket(host, probe_port, timeout_ms);
                if (!IS_INVALID(s)) {
                    char buf[MAX_BANNER_SIZE] = {};
                    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
                    if (n > 0) {
                        banner = sanitize_banner(buf, n);
                        istringstream iss(banner);
                        string line;
                        getline(iss, line);
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                        if (line.size() > 2) banner = line;
                        else banner = banner.substr(0, 200);
                    }
                }

                if (banner.empty()) {
                    banner = probeSSH(host, probe_port, timeout_ms);
                }
            }
            break;
        }
    }

    if (banner.find("[SSL/TLS]") != string::npos || banner.find("[CERT") != string::npos) {
        result.ssl = true;
    }

    set_port_state(result, !banner.empty());

    if (banner.empty()) {
        result.service = get_port_service(port);
        result.product = result.service;
        return result;
    }

    result.banner = banner;

    auto matches = match_version_patterns(banner);

    double best_confidence = 0.0;
    for (const auto& m : matches) {
        if (m.confidence > best_confidence) {
            best_confidence = m.confidence;
            result.service   = m.service;
            result.product   = m.product;
            result.version   = m.version;
            result.os_hint   = m.os_hint;
            result.confidence = m.confidence;

            string cpe = "cpe:/a:";
            string prod_lower = m.product;
            transform(prod_lower.begin(), prod_lower.end(), prod_lower.begin(), ::tolower);
            for (auto& c : prod_lower) if (c == ' ') c = '_';
            cpe += prod_lower;
            if (!m.version.empty()) cpe += ":" + m.version;
            result.cpe = cpe;
            result.cpe_list.emplace_back(cpe);
        }
    }

    if (result.service.empty()) {
        result.service = get_port_service(port);
        result.product = result.service;
        result.confidence = 0.5;
    }

    result.os_fp = combine_os_detection(banner, detect_ttl(host));

    if (result.os_hint.empty() && result.os_fp.confidence > 0.3f) {
        result.os_hint = result.os_fp.os_name;
        if (!result.os_fp.os_version.empty())
            result.os_hint += " " + result.os_fp.os_version;
    }

    result.vulnerabilities = check_vulnerabilities(result.product, result.version);

    {
        double score = 0.0;
        static vector<int> highRiskPorts = {21,23,135,139,445,3389,5900,2375,6379,27017,9200,11211,4444,10250};
        for (int p : highRiskPorts) {
            if (port == p) { score += 35.0; break; }
        }

        string bl = banner;
        transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
        if (bl.find("openssh 5") != string::npos || bl.find("openssh 6") != string::npos ||
            bl.find("apache/2.2") != string::npos || bl.find("openssl/1.0") != string::npos ||

struct SSLDeleter {
    void operator()(SSL* s) const noexcept { if (s) SSL_free(s); }
};
struct SSLCTXDeleter {
    void operator()(SSL_CTX* c) const noexcept { if (c) SSL_CTX_free(c); }
};
struct X509Deleter {
    void operator()(X509* x) const noexcept { if (x) X509_free(x); }
};
struct BIODeleter {
    void operator()(BIO* b) const noexcept { if (b) BIO_free(b); }
};
struct EVP_PKEYDeleter {
    void operator()(EVP_PKEY* k) const noexcept { if (k) EVP_PKEY_free(k); }
};
struct BNDeleter {
    void operator()(BIGNUM* bn) const noexcept { if (bn) BN_free(bn); }
};
struct GENERALNAMESDeleter {
    void operator()(GENERAL_NAMES* n) const noexcept { if (n) GENERAL_NAMES_free(n); }
};

using UniqueSSL       = std::unique_ptr<SSL, SSLDeleter>;
using UniqueSSLCTX    = std::unique_ptr<SSL_CTX, SSLCTXDeleter>;
using UniqueX509      = std::unique_ptr<X509, X509Deleter>;
using UniqueBIO       = std::unique_ptr<BIO, BIODeleter>;
using UniqueEVP_PKEY  = std::unique_ptr<EVP_PKEY, EVP_PKEYDeleter>;
using UniqueBN        = std::unique_ptr<BIGNUM, BNDeleter>;
using UniqueGeneralNames = std::unique_ptr<GENERAL_NAMES, GENERALNAMESDeleter>;


            bl.find("ssl 3") != string::npos || bl.find("tls 1.0") != string::npos ||
            bl.find("exim 4.9") != string::npos || bl.find("pure-ftpd 1.0") != string::npos) {
            score += 25.0;
        }

        score += result.vulnerabilities.size() * 8.0;

        if (bl.find("anonymous") != string::npos || bl.find("guest") != string::npos)
            score += 20.0;

        if (result.service.find("DOCKER") != string::npos ||
            result.service.find("K8S") != string::npos ||
            result.service.find("Kubernetes") != string::npos)
            score += 30.0;

        if (result.ssl == false && (port == 443 || port == 8443 || port == 993 || port == 995))
            score += 15.0;

        result.risk_score = min(100.0, score);

        if (result.risk_score >= 75) result.risk_level = "CRITICAL";
        else if (result.risk_score >= 50) result.risk_level = "HIGH";
        else if (result.risk_score >= 25) result.risk_level = "MEDIUM";
        else result.risk_level = "LOW";
    }

    flush_socket_cache();
    return result;
}

/* ─────────────────────────────────────────────────────────────────
 * THREAD POOL
 * ───────────────────────────────────────────────────────────────── */

class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    function<void()> task;
                    {
                        unique_lock<mutex> lock(queue_mutex);
                        cv.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) noexcept {
        {
            lock_guard<mutex> lock(queue_mutex);
            tasks.emplace(forward<F>(f));
        }
        cv.notify_one();
    }

    ~ThreadPool() {
        {
            lock_guard<mutex> lock(queue_mutex);
            stop = true;
        }
        cv.notify_all();
        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    }

private:
    vector<thread> workers;
    queue<function<void()>> tasks;
    mutex queue_mutex;
    condition_variable cv;
    bool stop;
};

/* ─────────────────────────────────────────────────────────────────
 * OUTPUT FORMATTERS
 * ───────────────────────────────────────────────────────────────── */

static string escape_json(const string& s) {
    string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 32) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static void print_scan_json(const ScanResult& r) noexcept {
    printf("{\"port\":%d,\"state\":\"%s\",\"service\":\"%s\",\"product\":\"%s\","
           "\"version\":\"%s\",\"os_hint\":\"%s\",\"confidence\":%.2f,"
           "\"risk_score\":%.1f,\"risk_level\":\"%s\",\"ssl\":%s,\"cpe\":\"%s\","
           "\"os_name\":\"%s\",\"os_confidence\":%.2f,\"banner\":\"%s\","
           "\"vulnerabilities\":[",
           r.port, r.state.c_str(), escape_json(r.service).c_str(),
           escape_json(r.product).c_str(), escape_json(r.version).c_str(),
           escape_json(r.os_hint).c_str(), r.confidence,
           r.risk_score, r.risk_level.c_str(),
           r.ssl ? "true" : "false",
           escape_json(r.cpe).c_str(),
           escape_json(r.os_fp.os_name).c_str(), r.os_fp.confidence,
           escape_json(r.banner.substr(0, 200)).c_str());

    for (size_t i = 0; i < r.vulnerabilities.size(); i++) {
        if (i > 0) printf(",");
        printf("\"%s\"", escape_json(r.vulnerabilities[i]).c_str());
    }
    printf("],\"clues\":[");
    for (size_t i = 0; i < r.os_fp.clues.size(); i++) {
        if (i > 0) printf(",");
        printf("\"%s\"", escape_json(r.os_fp.clues[i]).c_str());
    }
    printf("]}\n");
}

static void print_scan_text(const ScanResult& r) noexcept {
    const char* risk_color =
        r.risk_level == "CRITICAL" ? "\033[1;31m" :
        r.risk_level == "HIGH"     ? "\033[33m"   :
        r.risk_level == "MEDIUM"   ? "\033[33m"   : "\033[32m";

    printf("  \033[1;97m%-6d\033[0m  \033[32m%s\033[0m  %-18s  %-14s  %s%s\033[0m  %s\n",
           r.port, r.state.c_str(), r.product.c_str(), r.version.c_str(),
           risk_color, r.risk_level.c_str(), r.banner.substr(0, 50).c_str());

    if (!r.os_hint.empty()) {
        printf("          \033[2mOS: %s (%.0f%%)\033[0m\n",
               r.os_fp.os_name.c_str(), r.os_fp.confidence * 100.0);
    }

    for (const auto& v : r.vulnerabilities) {
        printf("          \033[33m\u26a0\033[0m  %s\n", v.c_str());
    }
}

/* ─────────────────────────────────────────────────────────────────
 * MAIN PROGRAM
 * ───────────────────────────────────────────────────────────────── */

static void print_banner() noexcept {
    printf("\n\033[1;35m");
    printf("  +====================================================+\n");
    printf("  |  \xe2\x9a\xa1 HackIT PortStorm v4.1  \xe2\x80\x94  C++ Scanner Engine      |\n");
    printf("  |  180+ signatures | OS fingerprint | Protocol probes |\n");
    printf("  +====================================================+\n");
    printf("\033[0m\n");
}

int main(int argc, char* argv[]) {
    if (!init_sockets()) {
        fprintf(stderr, "Failed to initialize sockets\n");
        return 1;
    }

    if (argc < 2) {
        print_banner();
        fprintf(stderr, "Usage: %s <host> <ports> [timeout_ms] [format:text|json] [threads:N]\n", argv[0]);
        fprintf(stderr, "  <host>      Target IP or hostname\n");
        fprintf(stderr, "  <ports>     Single port, comma-separated, or range (80,443 or 1-1024)\n");
        fprintf(stderr, "  [timeout]   Per-port timeout in ms (default: %d)\n", DEFAULT_TIMEOUT_MS);
        fprintf(stderr, "  [format]    Output format: text (default) or json\n");
        fprintf(stderr, "  [threads:N] Number of threads (default: %d)\n\n", THREAD_POOL_SIZE);
        printf("  Examples:\n");
        printf("    %s 192.168.1.1 22,80,443\n", argv[0]);
        printf("    %s 10.0.0.1 1-1024 500 json threads:64\n\n", argv[0]);
        cleanup_sockets();
        return 1;
    }

    constexpr char* host      = argv[1];
    constexpr char* port_spec = argv[2];
    int timeout_ms        = DEFAULT_TIMEOUT_MS;
    bool json_mode        = false;
    int thread_count      = THREAD_POOL_SIZE;

    if (argc >= 4) {
        string arg3(argv[3]);
        if (arg3.rfind("threads:", 0) == 0) {
            thread_count = max(1, stoi(arg3.substr(8)));
        } else {
            timeout_ms = atoi(argv[3]);
            if (timeout_ms < 100) timeout_ms = 100;
            if (timeout_ms > 30000) timeout_ms = 30000;
        }
    }

    if (argc >= 5) {
        string arg4(argv[4]);
        if (arg4 == "json") {
            json_mode = true;
        } else if (arg4.rfind("threads:", 0) == 0) {
            thread_count = max(1, stoi(arg4.substr(8)));
        }
    }

    if (argc >= 6) {
        string arg5(argv[5]);
        if (arg5.rfind("threads:", 0) == 0) {
            thread_count = max(1, stoi(arg5.substr(8)));
        }
    }

    vector<int> ports;
    string spec(port_spec);
    istringstream iss(spec);
    string token;
    while (getline(iss, token, ',')) {
        size_t dash = token.find('-');
        if (dash != string::npos) {
            int start = stoi(token.substr(0, dash));
            int end   = stoi(token.substr(dash + 1));
            if (start > end) swap(start, end);
            for (int p = start; p <= end; p++) ports.emplace_back(p);
        } else {
            try { ports.emplace_back(stoi(token)); }
            catch (...) {}
        }
    }

    if (ports.empty()) {
        fprintf(stderr, "No valid ports specified\n");
        cleanup_sockets();
        return 1;
    }

    if (!json_mode) {
        print_banner();
        printf("  \033[1;97mHost\033[0m    : %s\n", host);
        printf("  \033[1;97mPorts\033[0m   : %zu ports\n", ports.size());
        printf("  \033[1;97mTimeout\033[0m : %d ms\n", timeout_ms);
        printf("  \033[1;97mThreads\033[0m : %d\n\n", thread_count);
        printf("  \033[2m%-6s  %-4s  %-18s  %-14s  %-10s  %s\033[0m\n",
               "PORT", "STATE", "PRODUCT", "VERSION", "RISK", "BANNER");
        printf("  \033[2m%s\033[0m\n", string(80, '=').c_str());
    } else {
        printf("[");
    }

    vector<ScanResult> results;
    mutex results_mutex;
    atomic<int> completed(0);
    int total = (int)ports.size();

    {
        ThreadPool pool(min((size_t)thread_count, ports.size()));

        for (int port : ports) {
            pool.enqueue([host, port, timeout_ms, &results, &results_mutex, &completed, total]() {
                ScanResult r = scan_service(host, port, timeout_ms);
                {
                    lock_guard<mutex> lock(results_mutex);
                    results.emplace_back(r);
                }
                completed++;
            });
        }
    }

    sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b) {
        return a.port < b.port;
    });

    auto t_start = steady_clock::now();

    for (size_t i = 0; i < results.size(); i++) {
        if (json_mode) {
            if (i > 0) printf(",");
            print_scan_json(results[i]);
        } else {
            print_scan_text(results[i]);
        }
        fflush(stdout);
    }

    auto elapsed = duration_cast<milliseconds>(steady_clock::now() - t_start).count();

    if (json_mode) {
        printf("]\n");
    } else {
        int open_count = 0;
        for (const auto& r : results) {
            if (r.state == "OPEN") open_count++;
        }
        printf("\n  \033[2mCompleted %d ports in %lld ms (%d open)\033[0m\n\n",
               total, elapsed, open_count);
    }

    cleanup_sockets();
    return 0;
}
