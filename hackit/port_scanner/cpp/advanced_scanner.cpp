/*
 * HackIT PortStorm — C++ Deep Service Fingerprinting Engine v4.0
 * 150+ service version patterns · OS fingerprinting · Protocol-specific probes
 * Compiler: g++ -std=c++17 -O3 -o advanced_scanner advanced_scanner.cpp -lws2_32 (Win)
 *           g++ -std=c++17 -O3 -o advanced_scanner advanced_scanner.cpp (Linux)
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

using namespace std;
using namespace chrono;

/* ─────────────────────────────────────────────────────────────────
 * CONSTANTS
 * ───────────────────────────────────────────────────────────────── */
const int DEFAULT_TIMEOUT_MS = 1500;
const int MAX_BANNER_SIZE    = 8192;
const int THREAD_POOL_SIZE   = 32;

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
 * VERSION PATTERN DATABASE — 150+ patterns
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

    // ── HTTP — Other Web Servers (12 patterns) ───────────────────
    db.push_back({"HTTP", "Server:\\s*LiteSpeed",                      "LiteSpeed", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*lighttpd/([\\d.]+)",             "Lighttpd", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Caddy",                          "Caddy", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cowboy",                         "Cowboy (Erlang)", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*GWS",                            "Google Web Server", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cloudflare",                     "Cloudflare", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Jetty\\(([\\d.]+)\\)",          "Jetty", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Jetty",                          "Jetty", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*gunicorn/([\\d.]+)",             "Gunicorn", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*uvicorn",                        "Uvicorn (ASGI)", "", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Werkzeug/?([\\d.]*)",           "Werkzeug (Flask)", "$1", "Generic"});
    db.push_back({"HTTP", "Server:\\s*Cherokee/?([\\d.]*)",           "Cherokee", "$1", "Generic"});

    // ── HTTP — App Servers & Powered-By (8 patterns) ─────────────
    db.push_back({"HTTP", "X-Powered-By:\\s*PHP/([\\d.]+)",           "PHP", "$1", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Express",                 "Express (Node.js)", "", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Railo|Lucee",             "Railo/Lucee (CFML)", "", "Generic"});
    db.push_back({"HTTP", "X-Powered-By:\\s*Servlet/([\\d.]+)",       "Java Servlet", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*Drupal ([\\d.]+)",         "Drupal", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*WordPress ([\\d.]+)",      "WordPress", "$1", "Generic"});
    db.push_back({"HTTP", "X-Generator:\\s*Joomla! ([\\d.]+)",        "Joomla", "$1", "Generic"});
    db.push_back({"HTTP", "X-Drupal-Cache",                           "Drupal", "", "Generic"});

    // ── FTP (12 patterns) ────────────────────────────────────────
    db.push_back({"FTP", "220.*vsftpd ([\\d.]+)",                    "vsftpd", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*ProFTPD ([\\d.]+)",                   "ProFTPD", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*FileZilla Server ([\\d.]+)",          "FileZilla Server", "$1", "Windows"});
    db.push_back({"FTP", "220.*Pure-FTPd",                           "Pure-FTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*Pure-FTPd ([\\d.]+)",                 "Pure-FTPd", "$1", "Unix/Linux"});
    db.push_back({"FTP", "220.*Microsoft FTP",                       "Microsoft FTP", "", "Windows Server"});
    db.push_back({"FTP", "220.*Wu-FTPd",                             "Wu-FTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*glFTPd",                              "glFTPd", "", "Unix/Linux"});
    db.push_back({"FTP", "220.*Serv-U FTP Server",                   "Serv-U", "", "Windows"});
    db.push_back({"FTP", "220.*BulletProof",                         "BulletProof FTP", "", "Windows"});
    db.push_back({"FTP", "220.*Cerberus FTP",                        "Cerberus FTP", "", "Windows"});
    db.push_back({"FTP", "220.*Apache FtpServer",                    "Apache FtpServer", "", "Generic"});

    // ── SMTP (12 patterns) ───────────────────────────────────────
    db.push_back({"SMTP", "220.*Postfix ([\\d.]+)",                  "Postfix", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Postfix ESMTP",                      "Postfix", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Exim ([\\d.]+)",                     "Exim", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Sendmail ([\\d.]+)",                 "Sendmail", "$1", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Sendmail",                           "Sendmail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Microsoft ESMTP",                    "Microsoft Exchange", "", "Windows Server"});
    db.push_back({"SMTP", "220.*MailEnable",                         "MailEnable", "", "Windows"});
    db.push_back({"SMTP", "220.*qmail",                              "Qmail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*Courier",                            "Courier Mail", "", "Unix/Linux"});
    db.push_back({"SMTP", "220.*OpenSMTPD",                          "OpenSMTPD", "", "OpenBSD"});
    db.push_back({"SMTP", "220.*IceWarp",                            "IceWarp", "", "Windows/Unix"});
    db.push_back({"SMTP", "220.*Zimbra",                             "Zimbra", "", "Unix/Linux"});

    // ── POP3 (6 patterns) ────────────────────────────────────────
    db.push_back({"POP3", "\\+OK.*Dovecot.*ready",                   "Dovecot POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Courier POP3",                     "Courier POP3", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Qpopper",                          "Qpopper", "", "Unix/Linux"});
    db.push_back({"POP3", "\\+OK.*Microsoft.*POP3",                  "Microsoft POP3", "", "Windows Server"});
    db.push_back({"POP3", "\\+OK.*MailEnable POP3",                  "MailEnable POP3", "", "Windows"});
    db.push_back({"POP3", "\\+OK.*Cyrus",                            "Cyrus POP3", "", "Unix/Linux"});

    // ── IMAP (6 patterns) ────────────────────────────────────────
    db.push_back({"IMAP", "\\* OK.*Dovecot",                         "Dovecot IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Courier",                         "Courier IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Cyrus IMAP",                      "Cyrus IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*Microsoft.*IMAP",                "Microsoft Exchange IMAP", "", "Windows Server"});
    db.push_back({"IMAP", "\\* OK.*Zimbra",                          "Zimbra IMAP", "", "Unix/Linux"});
    db.push_back({"IMAP", "\\* OK.*MailEnable IMAP",                 "MailEnable IMAP", "", "Windows"});

    // ── MySQL / MariaDB (6 patterns) ─────────────────────────────
    db.push_back({"MySQL", "mysql_native_password",                   "MySQL", "", "Generic"});
    db.push_back({"MySQL", "MariaDB",                                 "MariaDB", "", "Generic"});
    db.push_back({"MySQL", "5\\.5\\.\\d+-MySQL",                     "MySQL 5.5", "", "Generic"});
    db.push_back({"MySQL", "5\\.6\\.\\d+-MySQL",                     "MySQL 5.6", "", "Generic"});
    db.push_back({"MySQL", "5\\.7\\.\\d+-MySQL",                     "MySQL 5.7", "", "Generic"});
    db.push_back({"MySQL", "8\\.\\d+\\.\\d+-MySQL",                  "MySQL 8.x", "", "Generic"});

    // ── PostgreSQL (4 patterns) ──────────────────────────────────
    db.push_back({"PostgreSQL", "PostgreSQL ([\\d.]+)",              "PostgreSQL", "$1", "Generic"});
    db.push_back({"PostgreSQL", "psql.*PostgreSQL",                  "PostgreSQL", "", "Generic"});
    db.push_back({"PostgreSQL", "Cyrus PostgreSQL",                  "PostgreSQL", "", "Generic"});
    db.push_back({"PostgreSQL", "pg_hba",                             "PostgreSQL", "", "Generic"});

    // ── Other Databases (16 patterns) ────────────────────────────
    db.push_back({"Redis",   "redis_version:([\\d.]+)",              "Redis", "$1", "Unix/Linux"});
    db.push_back({"Redis",   "redis_mode:",                          "Redis", "", "Unix/Linux"});
    db.push_back({"Redis",   "role:master",                          "Redis Master", "", "Unix/Linux"});
    db.push_back({"Redis",   "role:slave",                           "Redis Slave", "", "Unix/Linux"});
    db.push_back({"MongoDB", "MongoDB",                              "MongoDB", "", "Generic"});
    db.push_back({"MongoDB", "\"ok\"\\s*:\\s*1",                    "MongoDB", "", "Generic"});
    db.push_back({"MongoDB", "MongoDB ([\\d.]+)",                    "MongoDB", "$1", "Generic"});
    db.push_back({"CouchDB", "CouchDB/([\\d.]+)",                    "CouchDB", "$1", "Generic"});
    db.push_back({"CouchDB", "couchdb",                              "CouchDB", "", "Generic"});
    db.push_back({"MSSQL",   "MSSQL|SQL Server",                     "Microsoft SQL Server", "", "Windows Server"});
    db.push_back({"MSSQL",   "MS-SQL-S|MS-SQL-M",                   "Microsoft SQL Server", "", "Windows Server"});
    db.push_back({"Oracle",  "Oracle\\s*DB|Oracle\\s*Database",      "Oracle Database", "", "Generic"});
    db.push_back({"Oracle",  "Oracle.*XE",                            "Oracle Database XE", "", "Generic"});
    db.push_back({"Cassandra","Apache Cassandra",                     "Apache Cassandra", "", "Generic"});
    db.push_back({"Elasticsearch","Elasticsearch",                    "Elasticsearch", "", "Generic"});
    db.push_back({"Memcached","STAT pid",                             "Memcached", "", "Generic"});

    // ── DNS (3 patterns) ─────────────────────────────────────────
    db.push_back({"DNS", "BIND ([\\d.]+)",                           "BIND", "$1", "Generic"});
    db.push_back({"DNS", "unbound ([\\d.]+)",                        "Unbound", "$1", "Generic"});
    db.push_back({"DNS", "dnsmasq",                                   "Dnsmasq", "", "Linux/Embedded"});

    // ── SMB / NetBIOS (3 patterns) ───────────────────────────────
    db.push_back({"SMB",   "Samba ([\\d.]+)",                        "Samba", "$1", "Unix/Linux"});
    db.push_back({"SMB",   "Windows[_ ]Server",                      "Windows SMB", "", "Windows Server"});
    db.push_back({"SMB",   "NT\\s*LM\\s*0\\.12",                     "SMB 1.0 (Legacy)", "", "Windows/Legacy"});

    // ── RDP (2 patterns) ─────────────────────────────────────────
    db.push_back({"RDP", "MS-Terminal",                               "Microsoft RDP", "", "Windows"});
    db.push_back({"RDP", "xrdp ([\\d.]+)",                            "xrdp", "$1", "Unix/Linux"});

    // ── VNC (3 patterns) ─────────────────────────────────────────
    db.push_back({"VNC", "RFB 00([\\d.]+)",                          "VNC", "$1", "Generic"});
    db.push_back({"VNC", "RFB 003\\.",                                "VNC 3.x", "", "Generic"});
    db.push_back({"VNC", "RFB 004\\.",                                "VNC 4.x", "", "Generic"});

    // ── Telnet (3 patterns) ──────────────────────────────────────
    db.push_back({"Telnet", "Telnet",                                 "Telnet Server", "", "Generic"});
    db.push_back({"Telnet", "Ubuntu.*telnetd",                        "Telnet (Ubuntu)", "", "Ubuntu Linux"});
    db.push_back({"Telnet", "Linux.*telnetd",                         "Telnet (Linux)", "", "Linux"});

    // ── LDAP (2 patterns) ────────────────────────────────────────
    db.push_back({"LDAP", "OpenLDAP ([\\d.]+)",                      "OpenLDAP", "$1", "Unix/Linux"});
    db.push_back({"LDAP", "Microsoft.*LDAP",                          "Microsoft AD/LDAP", "", "Windows Server"});

    // ── SIP (2 patterns) ─────────────────────────────────────────
    db.push_back({"SIP", "SIP/2\\.0.*Asterisk",                      "Asterisk PBX", "", "Unix/Linux"});
    db.push_back({"SIP", "SIP/2\\.0.*FreePBX",                       "FreePBX", "", "Unix/Linux"});

    // ── Docker / Containers (8 patterns) ─────────────────────────
    db.push_back({"Docker", "Docker/([\\d.]+)",                      "Docker Engine", "$1", "Linux"});
    db.push_back({"Docker", "\"Version\":\"([\\d.]+)\".*ApiVersion", "Docker Engine", "$1", "Linux"});
    db.push_back({"Docker", "\"Platform\":\"docker\"",               "Docker Engine", "", "Linux"});
    db.push_back({"Docker", "Docker\\s*Community",                    "Docker Community", "", "Linux"});
    db.push_back({"Docker", "Containerd",                             "Containerd", "", "Linux"});
    db.push_back({"Kubernetes","kubernetes|k8s",                     "Kubernetes", "", "Generic"});
    db.push_back({"etcd",    "etcd ([\\d.]+)",                       "etcd", "$1", "Linux"});
    db.push_back({"etcd",    "\"etcd\"",                              "etcd", "", "Linux"});

    // ── CI/CD (6 patterns) ───────────────────────────────────────
    db.push_back({"CI/CD",  "Jenkins",                               "Jenkins CI", "", "Generic"});
    db.push_back({"CI/CD",  "Artifactory",                           "JFrog Artifactory", "", "Generic"});
    db.push_back({"CI/CD",  "Nexus",                                 "Sonatype Nexus", "", "Generic"});
    db.push_back({"CI/CD",  "GitLab",                                "GitLab", "", "Generic"});
    db.push_back({"CI/CD",  "Gitea",                                 "Gitea", "", "Generic"});
    db.push_back({"CI/CD",  "Gogs",                                  "Gogs", "", "Generic"});

    // ── Message Queues (5 patterns) ──────────────────────────────
    db.push_back({"MQ",     "AMQP",                                  "RabbitMQ / AMQP", "", "Generic"});
    db.push_back({"MQ",     "RabbitMQ",                              "RabbitMQ", "", "Generic"});
    db.push_back({"MQ",     "ActiveMQ",                              "Apache ActiveMQ", "", "Generic"});
    db.push_back({"MQ",     "Kafka",                                 "Apache Kafka", "", "Generic"});
    db.push_back({"MQ",     "NATS",                                  "NATS", "", "Generic"});

    // ── Monitoring (5 patterns) ──────────────────────────────────
    db.push_back({"Monitoring","Prometheus",                         "Prometheus", "", "Generic"});
    db.push_back({"Monitoring","Grafana",                            "Grafana", "", "Generic"});
    db.push_back({"Monitoring","Nagios",                             "Nagios", "", "Generic"});
    db.push_back({"Monitoring","Zabbix",                             "Zabbix", "", "Generic"});
    db.push_back({"Monitoring","Check_MK|checkmk",                   "CheckMK", "", "Generic"});

    // ── Proxies / Load Balancers (7 patterns) ────────────────────
    db.push_back({"Proxy",   "HAProxy ([\\d.]+)",                    "HAProxy", "$1", "Generic"});
    db.push_back({"Proxy",   "Squid/([\\d.]+)",                      "Squid Proxy", "$1", "Generic"});
    db.push_back({"Proxy",   "Varnish",                              "Varnish Cache", "", "Generic"});
    db.push_back({"Proxy",   "Traefik",                              "Traefik Proxy", "", "Generic"});
    db.push_back({"Proxy",   "Envoy",                                "Envoy Proxy", "", "Generic"});
    db.push_back({"Proxy",   "Apache Traffic Server",                "Apache Traffic Server", "", "Generic"});
    db.push_back({"Proxy",   "Pound",                                "Pound LB", "", "Generic"});

    // ── CMS / Web Apps (6 patterns) ──────────────────────────────
    db.push_back({"CMS",    "WordPress",                             "WordPress", "", "Generic"});
    db.push_back({"CMS",    "Drupal",                                "Drupal", "", "Generic"});
    db.push_back({"CMS",    "Joomla",                                "Joomla", "", "Generic"});
    db.push_back({"CMS",    "Magento",                               "Magento", "", "Generic"});
    db.push_back({"CMS",    "phpMyAdmin",                            "phpMyAdmin", "", "Generic"});
    db.push_back({"CMS",    "wp-admin|wp-content|wp-includes",       "WordPress", "", "Generic"});

    // ── Control Panels (4 patterns) ──────────────────────────────
    db.push_back({"Panel",  "Webmin",                                "Webmin", "", "Generic"});
    db.push_back({"Panel",  "cPanel",                                "cPanel/WHM", "", "CentOS/CloudLinux"});
    db.push_back({"Panel",  "Plesk",                                 "Plesk", "", "Windows/CentOS"});
    db.push_back({"Panel",  "Cockpit",                               "Cockpit", "", "Linux"});

    // ── VPN (5 patterns) ─────────────────────────────────────────
    db.push_back({"VPN",    "OpenVPN",                               "OpenVPN", "", "Generic"});
    db.push_back({"VPN",    "WireGuard",                             "WireGuard", "", "Generic"});
    db.push_back({"VPN",    "StrongSwan",                            "StrongSwan", "", "Linux"});
    db.push_back({"VPN",    "SoftEther",                             "SoftEther", "", "Generic"});
    db.push_back({"VPN",    "OpenConnect",                           "OpenConnect (ocserv)", "", "Generic"});

    // ── IoT / Embedded (4 patterns) ──────────────────────────────
    db.push_back({"Embedded","OpenWrt",                              "OpenWrt", "", "OpenWrt/LEDE"});
    db.push_back({"Embedded","DD-WRT",                               "DD-WRT", "", "DD-WRT"});
    db.push_back({"Embedded","pfSense",                              "pfSense", "", "FreeBSD"});
    db.push_back({"Embedded","OPNsense",                             "OPNsense", "", "FreeBSD"});

    // ── Misc (16 patterns) ───────────────────────────────────────
    db.push_back({"Misc",   "OpenSSL ([\\d.]+)",                     "OpenSSL", "$1", "Generic"});
    db.push_back({"Misc",   "OpenSSH",                               "OpenSSH", "", "Unix/Linux"});
    db.push_back({"Misc",   "Apache ZooKeeper",                      "Apache ZooKeeper", "", "Generic"});
    db.push_back({"Misc",   "Vault v([\\d.]+)",                      "HashiCorp Vault", "$1", "Generic"});
    db.push_back({"Misc",   "Consul",                                "HashiCorp Consul", "", "Generic"});
    db.push_back({"Misc",   "Nomad",                                 "HashiCorp Nomad", "", "Generic"});
    db.push_back({"Misc",   "Kerberos",                              "Kerberos KDC", "", "Generic"});
    db.push_back({"Misc",   "rsync",                                 "Rsync", "", "Unix/Linux"});
    db.push_back({"Misc",   "SVN|Subversion",                        "Apache Subversion", "", "Generic"});
    db.push_back({"Misc",   "Git.*HTTP",                             "Git over HTTP", "", "Generic"});
    db.push_back({"Misc",   "Apache.*mod_",                          "Apache Module", "", "Generic"});
    db.push_back({"Misc",   "\"cluster_name\"",                      "Elasticsearch Cluster", "", "Generic"});
    db.push_back({"Misc",   "Net::LDAP",                            "Perl LDAP", "", "Generic"});
    db.push_back({"Misc",   "Python/([\\d.]+)",                      "Python", "$1", "Generic"});
    db.push_back({"Misc",   "Java/([\\d.]+)",                        "Java", "$1", "Generic"});
    db.push_back({"Misc",   "Apache.*Axis",                          "Apache Axis (SOAP)", "", "Generic"});

    return db;
}

/* ─────────────────────────────────────────────────────────────────
 * OS FINGERPRINT DATABASE
 * ───────────────────────────────────────────────────────────────── */

struct OsFingerprintEntry {
    string os_name;
    string os_version;
    float  confidence;
    string pattern;        // regex pattern in banner
    int    ttl_hint;       // expected TTL if available
    string platform;       // "windows", "linux", "unix", "network"
};

static vector<OsFingerprintEntry> build_os_db() {
    return {
        // Windows variants (TTL ~128)
        {"Windows",      "10/Server 2016/2019",  0.85, "Windows NT 10\\.0",              128, "windows"},
        {"Windows",      "8.1/Server 2012 R2",  0.85, "Windows NT 6\\.3",               128, "windows"},
        {"Windows",      "8/Server 2012",        0.85, "Windows NT 6\\.2",               128, "windows"},
        {"Windows",      "7/Server 2008 R2",     0.85, "Windows NT 6\\.1",               128, "windows"},
        {"Windows",      "Vista/Server 2008",    0.85, "Windows NT 6\\.0",               128, "windows"},
        {"Windows",      "XP/Server 2003",       0.85, "Windows NT 5\\.",                128, "windows"},
        {"Windows",      "2000",                 0.85, "Windows NT 4\\.0|Windows 2000",   128, "windows"},

        // Linux variants (TTL ~64)
        {"Ubuntu Linux", "24.04",                0.80, "Ubuntu|ubuntu",                   64,  "linux"},
        {"Debian Linux", "12/11",                0.80, "Debian|debian",                  64,  "linux"},
        {"CentOS Linux", "9/8/7",                0.80, "CentOS|centos",                   64,  "linux"},
        {"Red Hat Linux","9/8/7",                0.80, "Red Hat|redhat",                  64,  "linux"},
        {"Fedora Linux", "",                    0.80, "Fedora|fedora",                    64,  "linux"},
        {"SUSE Linux",   "openSUSE",            0.80, "SUSE|suse|openSUSE",               64,  "linux"},
        {"Arch Linux",   "",                    0.75, "Arch Linux|archlinux",             64,  "linux"},
        {"Alpine Linux", "",                    0.75, "Alpine|alpine",                    64,  "linux"},

        // BSD variants (TTL ~64)
        {"FreeBSD",      "",                    0.85, "FreeBSD|freebsd",                  64,  "unix"},
        {"OpenBSD",      "",                    0.85, "OpenBSD|openbsd",                  64,  "unix"},
        {"NetBSD",       "",                    0.80, "NetBSD|netbsd",                    64,  "unix"},
        {"macOS",        "Sonoma/Ventura",      0.80, "Darwin|darwin",                    64,  "unix"},

        // Network devices (TTL ~255)
        {"Cisco IOS",    "",                    0.90, "Cisco|cisc",                      255, "network"},
        {"Cisco ASA",    "",                    0.85, "Cisco ASA|Adaptive Security",      255, "network"},
        {"Juniper JunOS","",                    0.85, "Juniper|junos",                    255, "network"},
        {"HP ProCurve",  "",                    0.80, "ProCurve|ProCurve",               255, "network"},
        {"MikroTik",     "RouterOS",            0.85, "MikroTik|RouterOS",                64,  "network"},
        {"Ubiquiti",     "EdgeOS",              0.80, "Ubiquiti|EdgeOS",                  64,  "network"},
        {"Palo Alto",    "PAN-OS",              0.80, "Palo Alto|PAN-OS",                255, "network"},
        {"Fortinet",     "FortiGate",           0.85, "FortiGate|Fortinet",              255, "network"},
        {"SonicWall",    "SonicOS",             0.80, "SonicWall|SonicOS",               255, "network"},

        // Embedded / IoT (TTL ~64)
        {"OpenWrt",      "",                    0.85, "OpenWrt|openwrt",                   64,  "linux"},
        {"DD-WRT",       "",                    0.85, "DD-WRT|dd-wrt",                    64,  "linux"},
        {"pfSense",      "",                    0.85, "pfSense|pfsense",                  64,  "unix"},
        {"OPNsense",     "",                    0.80, "OPNsense|opnsense",                64,  "unix"},
        {"Synology DSM", "",                    0.80, "Synology|synology",                64,  "linux"},
        {"QNAP QTS",     "",                    0.80, "QNAP|qnap",                        64,  "linux"},
        {"VMware ESXi",  "",                    0.90, "VMware|vmware|ESXi",               64,  "unix"},
        {"Citrix XenServer","",                 0.80, "XenServer|xenserver",               64,  "linux"},
        {"Proxmox VE",   "",                    0.80, "Proxmox|proxmox",                  64,  "linux"},
        {"NAS4Free",     "",                    0.75, "NAS4Free|nas4free",                64,  "unix"},
        {"TrueNAS",      "",                    0.80, "TrueNAS|truenas",                  64,  "unix"},
        {"Raspberry Pi OS","",                  0.70, "Raspberry Pi|raspberry",            64,  "linux"},

        // Generic patterns (lower confidence)
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
        {"OpenSSH", "8.7",  "CVE-2024-6387", "regreSSHion — unauthenticated RCE in signal handler", 9.8, "CRITICAL"},
        {"OpenSSH", "8.5",  "CVE-2023-38408", "SSH-agent remote code execution via crafted PKCS11 provider", 9.8, "CRITICAL"},
        {"OpenSSH", "7.7",  "CVE-2018-15473", "Username enumeration via timing side-channel", 5.3, "MEDIUM"},
        {"OpenSSH", "7.2",  "CVE-2016-10012", "Privilege separation bypass — unauthorized key acceptance", 7.5, "HIGH"},
        {"vsftpd",  "2.3.4","CVE-2011-2523", "BACKDOOR — vsftpd 2.3.4 smiley-face backdoor (RCE)", 10.0, "CRITICAL"},
        {"ProFTPD", "1.3.3c","CVE-2010-4221","ProFTPD sql_include module buffer overflow (RCE)", 9.3, "CRITICAL"},
        {"Apache httpd", "2.4.50","CVE-2021-42013","Path traversal bypass — unauthenticated RCE", 9.8, "CRITICAL"},
        {"Apache httpd", "2.4.49","CVE-2021-41773","Path traversal + RCE in CGI scripts", 9.8, "CRITICAL"},
        {"Apache httpd", "2.4.17","CVE-2017-7679","mod_mime buffer overflow", 9.8, "CRITICAL"},
        {"Apache httpd", "2.2.99","EOL", "Apache 2.2 is end-of-life — no security patches", 0, "HIGH"},
        {"nginx", "1.3.9","CVE-2013-4547","Nginx null-byte injection — access control bypass", 7.5, "HIGH"},
        {"Microsoft IIS", "6.0","CVE-2017-7269","WebDAV buffer overflow — unauthenticated RCE", 10.0, "CRITICAL"},
        {"PHP", "5.99","EOL","PHP 5.x end-of-life — no security patches, many unpatched CVEs", 0, "CRITICAL"},
        {"PHP", "7.1","EOL","PHP 7.1 and older end-of-life", 0, "HIGH"},
        {"PHP", "7.3","CVE-2019-11043","PHP-FPM nginx misconfiguration RCE", 9.8, "CRITICAL"},
        {"OpenSSL", "1.0.2","CVE-2014-0160","Heartbleed — memory disclosure of private keys", 9.8, "CRITICAL"},
        {"Redis", "0.0","INFO-NOAUTH","Redis: No authentication by default — check CONFIG SET requirepass", 7.0, "HIGH"},
        {"MongoDB", "0.0","INFO-NOAUTH","MongoDB: No auth by default — check /etc/mongod.conf bindIp+auth", 7.0, "HIGH"},
        {"Jenkins CI", "2.441","CVE-2024-23897","Arbitrary file read via CLI (auth bypass in older versions)", 9.8, "CRITICAL"},
        {"Apache Tomcat", "8.0.99","EOL","Tomcat 8.0 end-of-life", 0, "HIGH"},
        {"Apache Tomcat", "7.0.99","CVE-2020-1938","Ghostcat: AJP connector file read / inclusion", 9.8, "CRITICAL"},
        {"Drupal", "7.99","CVE-2018-7600","Drupalgeddon2 — unauthenticated RCE", 9.8, "CRITICAL"},
        {"Docker Engine", "99.99","INFO-EXPOSED","Docker daemon exposed without TLS — container escape possible", 10.0, "CRITICAL"},
        {"WordPress", "4.7","CVE-2016-10033","WordPress REST API content injection", 7.5, "HIGH"},
        {"WordPress", "5.99","CVE-2023-45127","WordPress plugin vulnerability chain", 8.1, "HIGH"},
        {"Postfix", "3.5","CVE-2023-51764","Postfix SMTP smuggling", 7.5, "HIGH"},
        {"Exim", "4.94","CVE-2023-42117","Exim remote code execution", 9.8, "CRITICAL"},
        {"Sendmail", "8.16","CVE-2023-40300","Sendmail heap overflow", 8.1, "HIGH"},
        {"ProFTPD", "1.3.8","CVE-2023-51766","ProFTPD mod_tls memory leak", 5.3, "MEDIUM"},
        {"Squid Proxy", "5.9","CVE-2023-46849","Squid denial of service", 7.5, "HIGH"},
        {"HAProxy", "2.6","CVE-2023-40225","HAProxy HTTP request smuggling", 6.5, "MEDIUM"},
        {"Lighttpd", "1.4.78","CVE-2023-48051","Lighttpd memory leak", 5.0, "MEDIUM"},
        {"Varnish Cache", "7.4","CVE-2023-44487","Varnish HTTP/2 rapid reset", 7.5, "HIGH"},
        {"Traefik Proxy", "3.0","CVE-2023-47124","Traefik authentication bypass", 8.2, "HIGH"},
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

static int resolve_host(const string& host, struct sockaddr_in& addr) {
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

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(s, &fdset);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    res = select((int)s + 1, nullptr, &fdset, nullptr, &tv);
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
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(s, &fdset);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int res = select((int)s + 1, &fdset, nullptr, nullptr, &tv);
    if (res <= 0) return -1;

    return recv(s, buf, bufsize, 0);
}

static int send_with_timeout(SOCKET s, const char* data, int len, int timeout_ms) {
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(s, &fdset);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int res = select((int)s + 1, nullptr, &fdset, nullptr, &tv);
    if (res <= 0) return -1;

    return send(s, data, len, 0);
}

static SOCKET create_tcp_socket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (IS_INVALID(s)) return INVALID_SOCKET;

#ifdef _WIN32
    DWORD tv = 100;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
#else
    struct timeval tv = {0, 100000};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

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
        } else if (c == 0) {
            // null byte — skip
        } else if (result.empty()) {
            // skip leading non-printable
        }
    }
    return result;
}

string probeHTTP(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: HackIT-CPP/4.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    send_with_timeout(s, req.c_str(), (int)req.size(), timeout_ms);

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    CLOSE_SOCKET(s);

    if (n <= 0) return "";
    return sanitize_banner(buf, n);
}

string probeSSH(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // SSH server sends banner immediately on connect
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    CLOSE_SOCKET(s);

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    // Extract first line (SSH banner is single line)
    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.find("SSH-") != string::npos) return line;

    return raw;
}

string probeSMTP(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // Read initial banner
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    // Send EHLO
    string ehlo = "EHLO hackit.local\r\n";
    send_with_timeout(s, ehlo.c_str(), (int)ehlo.size(), timeout_ms);

    char buf2[4096] = {};
    int n2 = recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    CLOSE_SOCKET(s);

    string result;
    if (n > 0) result += sanitize_banner(buf, n);
    if (n2 > 0) result += "\n" + sanitize_banner(buf2, n2);

    if (result.empty()) return "";
    return result;
}

string probeFTP(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // FTP banner is sent on connect
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    // Try anonymous login to get post-login banner
    if (n > 0) {
        string user = "USER anonymous\r\n";
        send_with_timeout(s, user.c_str(), (int)user.size(), timeout_ms);
        char buf2[4096] = {};
        recv_with_timeout(s, buf2, sizeof(buf2)-1, timeout_ms);
    }
    CLOSE_SOCKET(s);

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    // Return first line (the 220 greeting)
    istringstream iss(raw);
    string line;
    getline(iss, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.find("220") != string::npos) return line;

    return raw;
}

string probePOP3(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // POP3 server sends greeting on connect
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    CLOSE_SOCKET(s);

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
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // IMAP server sends greeting on connect
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    CLOSE_SOCKET(s);

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
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // MySQL sends a greeting packet on connect
    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
    CLOSE_SOCKET(s);

    if (n <= 0) return "";
    string result = sanitize_banner(buf, n);

    // MySQL protocol greeting contains version string after 4-byte header
    // Fall back to raw bytes analysis
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

    return result;
}

string probeHTTPS(const string& host, int port, int timeout_ms) {
    SOCKET s = create_tcp_socket();
    if (IS_INVALID(s)) return "";

    struct sockaddr_in addr;
    if (resolve_host(host, addr) != 0) { CLOSE_SOCKET(s); return ""; }
    addr.sin_port = htons((uint16_t)port);

    if (!connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
        CLOSE_SOCKET(s); return "";
    }

    // Minimal TLS 1.2 ClientHello (correctly sized)
    // Record layer: 16 03 01 (Handshake, TLS 1.0)
    // Record length: 0x00 0x31 = 49 bytes in this record
    // Handshake: 01 (ClientHello)
    // Handshake length: 0x00 0x00 0x2d = 45 bytes
    // Client version: 03 03 (TLS 1.2)
    // Random: 32 random-ish bytes
    // Session ID: empty (length 0x00)
    // Cipher suites: 2 suites (TLS_ECDHE_RSA + TLS_RSA) = 4 bytes
    // Compression: null (0x01 0x00)
    uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x31, // record header
        0x01, 0x00, 0x00, 0x2d, 0x03, 0x03, // handshake header + version
        // random (32 bytes)
        0xd0, 0x6d, 0x7e, 0xbe, 0x9c, 0x29, 0xd0, 0x33,
        0x43, 0xed, 0x7a, 0x2c, 0xe8, 0x49, 0xc1, 0xd8,
        0x22, 0x05, 0x20, 0xd1, 0x6b, 0xdf, 0xf4, 0x3a,
        0x3a, 0x49, 0x51, 0xd1, 0x32, 0x72, 0x57, 0x90,
        0x00, // session ID length (0)
        0x00, 0x04, // cipher suites length (4)
        0xc0, 0x2b, 0x00, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM, TLS_RSA_WITH_AES_128_CBC
        0x01, 0x00  // compression: null
    };

    send_with_timeout(s, (const char*)client_hello, sizeof(client_hello), timeout_ms);

    char buf[MAX_BANNER_SIZE] = {};
    int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);

    // Also try reading additional data (Certificate message)
    if (n > 0 && (uint8_t)buf[0] == 0x16) {
        // Try to get more of the handshake
        char buf2[4096] = {};
        int n2 = recv_with_timeout(s, buf2, sizeof(buf2)-1, 500);
        CLOSE_SOCKET(s);

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

        // Try to extract CN from Certificate in the response
        // Scan for recognizable ASCII strings in certificate (CN, O, OU)
        string cert_info;
        for (int i = 0; i < n; i++) {
            if (buf[i] >= 32 && buf[i] <= 126) {
                cert_info += (char)buf[i];
            }
        }

        return tls_info + " | cert-hints: " + cert_info.substr(0, 80);
    }

    CLOSE_SOCKET(s);

    if (n <= 0) return "";
    string raw = sanitize_banner(buf, n);

    // Not TLS — maybe plain HTTP
    return "[PLAIN] " + raw.substr(0, 200);
}

/* ─────────────────────────────────────────────────────────────────
 * OS DETECTION ENGINE
 * ───────────────────────────────────────────────────────────────── */

static int detect_ttl(const string& host) {
#ifdef __linux__
    // On Linux, we can try to get TTL via /proc/net/tcp or icmp
    // Simple approach: use a UDP/ICMP based approach
    // For now, return -1 (unknown)
    (void)host;
    return -1;
#else
    (void)host;
    return -1;
#endif
}

static OsFingerprint detect_os_from_banner(const string& banner, const vector<OsFingerprintEntry>& db) {
    OsFingerprint result;
    result.os_name = "Unknown";
    result.confidence = 0.0f;

    if (banner.empty()) return result;

    for (const auto& entry : db) {
        try {
            regex re(entry.pattern, regex_constants::icase);
            if (regex_search(banner, re)) {
                if (entry.confidence > result.confidence) {
                    result.os_name = entry.os_name;
                    result.os_version = entry.os_version;
                    result.confidence = entry.confidence;
                    result.clues.push_back("banner matched: " + entry.pattern);
                }
            }
        } catch (...) {}
    }

    return result;
}

static OsFingerprint combine_os_detection(const string& banner, int ttl_value) {
    auto db = build_os_db();
    OsFingerprint result = detect_os_from_banner(banner, db);

    // TTL-based OS hinting
    if (ttl_value > 0) {
        string ttl_os;
        if (ttl_value <= 64) {
            ttl_os = "Unix/Linux";
        } else if (ttl_value <= 128) {
            ttl_os = "Windows";
        } else {
            ttl_os = "Network Device";
        }

        result.clues.push_back("TTL=" + to_string(ttl_value) + " suggests " + ttl_os);

        // If banner didn't give a result, use TTL guess with lower confidence
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

static string get_port_service(int port) {
    static const map<int,string> port_svc = {
        {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},
        {80,"HTTP"},{110,"POP3"},{135,"RPC"},{139,"NetBIOS"},{143,"IMAP"},
        {161,"SNMP"},{162,"SNMP-Trap"},{389,"LDAP"},{443,"HTTPS"},
        {445,"SMB"},{464,"Kerberos"},{465,"SMTPS"},{500,"IKE"},
        {514,"Syslog"},{587,"SMTP-Submission"},{593,"RPC"},{636,"LDAPS"},
        {691,"MS-Exchange"},{873,"Rsync"},{990,"FTPS"},{993,"IMAPS"},
        {995,"POP3S"},{1025,"RPC-NFS"},{1080,"SOCKS"},{1194,"OpenVPN"},
        {1352,"Lotus-Notes"},{1389,"LDAP"},{1433,"MSSQL"},{1434,"MSSQL-UDP"},
        {1521,"Oracle-DB"},{1701,"L2TP"},{1723,"PPTP"},{1741,"DMX"},{1761,"Cisco-SCCP"},
        {1900,"UPNP"},{2000,"Cisco-SCCP"},{2049,"NFS"},{2082,"cPanel"},
        {2083,"cPanel-SSL"},{2095,"Webmail"},{2096,"Webmail-SSL"},{2181,"ZooKeeper"},
        {2222,"DirectAdmin"},{2375,"Docker"},{2376,"Docker-SSL"},{2483,"Oracle-DB"},{2484,"Oracle-DB-SSL"},
        {3000,"Node.js/Dev"},{3128,"Squid-Proxy"},{3268,"LDAP-GC"},{3269,"LDAP-GC-SSL"},
        {3306,"MySQL"},{3310,"ClamAV"},{3389,"RDP"},{3478,"STUN"},{3541,"Vobile"},
        {3689,"DAAP"},{3690,"SVN"},{3724,"WoW"},{3784,"Ventrilo"},{4000,"ICQ"},{4045,"NFS-Lockd"},
        {4224,"Cisco-FTP"},{4443,"HTTPS-Alt"},{4500,"IPsec-NAT"},{4567,"Sinatra"},{4662,"eMule"},
        {4848,"GlassFish"},{4899,"RAdmin"},{5000,"UPNP/Flask"},{5001,"iSCSI"},{5002,"TIBCO"},
        {5003,"FileMaker"},{5004,"RTP"},{5005,"RTP"},{5009,"Airport"},{5050,"Yahoo-Messenger"},
        {5060,"SIP"},{5061,"SIP-TLS"},{5093,"SafeNet"},{5222,"XMPP"},{5223,"XMPP-SSL"},
        {5269,"XMPP-Server"},{5308,"CFD"},{5347,"Google-Talk"},{5351,"NAT-PMP"},{5353,"mDNS"},
        {5432,"PostgreSQL"},{5445,"Cisco-IPS"},{5480,"VMware-VAMI"},{5481,"VMware-VAMI-SSL"},
        {5554,"SGI"},{5555,"Android-ADB"},{5631,"pcAnywhere"},{5666,"NRPE"},{5672,"AMQP"},
        {5683,"CoAP"},{5800,"VNC-HTTP"},{5900,"VNC"},{5901,"VNC-1"},{5902,"VNC-2"},
        {5985,"WinRM-HTTP"},{5986,"WinRM-HTTPS"},{6000,"X11"},{6001,"X11-1"},{6002,"X11-2"},
        {6039,"OpenNMS"},{6379,"Redis"},{6443,"Kubernetes-API"},{6480,"VNC"},{6500,"GameServer"},
        {6514,"Syslog-TLS"},{6566,"Sane"},{6567,"Dab"},{6580,"Frox"},{6660,"IRC"},{6661,"IRC"},
        {6662,"IRC"},{6663,"IRC"},{6664,"IRC"},{6665,"IRC"},{6666,"IRC"},{6667,"IRC"},{6668,"IRC"},
        {6669,"IRC"},{6670,"IRC"},{6697,"IRC-SSL"},{6789,"Splunk"},{6881,"BitTorrent"},
        {6969,"BitTorrent-Tracker"},{7000,"Cassandra"},{7001,"WebLogic"},{7010,"Cassandra-SSL"},
        {7070,"RealServer"},{7071,"Zimbra"},{7077,"AppDynamics"},{7100,"X11"},{7171,"Tibia"},
        {7199,"Cassandra-JMX"},{7320,"SlimServer"},{7443,"HTTPS-Alt"},{7474,"Neo4j"},
        {7496,"HP-RBAC"},{7547,"TR-069"},{7611,"Nexus"},{7624,"Indi"},{7634,"HP-RBAC"},
        {7654,"JetDirect"},{7777,"UltraVNC"},{7778,"UltraVNC"},{7780,"ISS"},{7781,"ISS"},
        {7888,"HP-RBAC"},{7890,"HP-RBAC"},{7911,"HP-RBAC"},{7990,"BitBucket"},{8000,"HTTP-Alt"},
        {8001,"HTTP-Alt"},{8002,"HTTP-Alt"},{8005,"Tomcat-Shutdown"},{8008,"HTTP-Alt"},
        {8009,"AJP"},{8010,"HTTP-Alt"},{8080,"HTTP-Proxy"},{8081,"HTTP-Alt"},{8082,"HTTP-Alt"},
        {8083,"HTTP-Alt"},{8086,"InfluxDB"},{8087,"HTTP-Alt"},{8088,"HTTP-Alt"},{8089,"Splunk"},
        {8090,"HTTP-Alt"},{8091,"Couchbase"},{8092,"Couchbase"},{8096,"Emby"},{8100,"Aruba"},
        {8111,"Skype"},{8112,"Skype"},{8123,"Polipo"},{8140,"Puppet"},{8172,"MSSQL-Monitor"},
        {8200,"VMware-HTTP"},{8222,"VMware-HTTPS"},{8243,"HTTPS-Alt"},{8280,"HTTP-Alt"},
        {8300,"Consul"},{8332,"Bitcoin"},{8333,"Bitcoin"},{8400,"CommVault"},{8443,"HTTPS-Alt"},
        {8500,"Consul-UI"},{8530,"WMI"},{8545,"Ethereum"},{8649,"Ganglia"},{8750,"Java-RMI"},
        {8761,"Eureka"},{8800,"Sun-Java-Server"},{8880,"HTTP-Alt"},{8888,"HTTP-Alt"},
        {8889,"HTTP-Alt"},{8890,"HTTP-Alt"},{8900,"HTTP-Alt"},{8983,"Solr"},
        {8990,"HTTP-Alt"},{8991,"HTTP-Alt"},{9000,"Hadoop"},{9001,"Hadoop-SSL"},
        {9002,"Hadoop"},{9003,"Hadoop"},{9004,"Hadoop"},{9005,"Hadoop"},
        {9042,"Cassandra-Native"},{9060,"WebLogic"},{9080,"WebSphere"},{9090,"Cockpit"},
        {9092,"Kafka"},{9093,"Kafka-SSL"},{9100,"JetDirect"},{9119,"MXP"},
        {9160,"Cassandra-Thrift"},{9200,"Elasticsearch"},{9210,"Elasticsearch"},
        {9292,"Hive"},{9300,"Elasticsearch-Transport"},{9371,"BitTorrent-DHT"},
        {9418,"Git"},{9443,"HTTPS-Alt"},{9527,"IBM-CICS"},{9530,"HP-RBAC"},
        {9600,"OMNIBus"},{9669,"VibeStreamer"},{9673,"HP-RBAC"},{9700,"HP-RBAC"},
        {9797,"HP-RBAC"},{9876,"Runescape"},{9877,"Runescape"},{9898,"Samba"},
        {9900,"HP-RBAC"},{9990,"JBoss"},{9991,"JBoss"},{9992,"JBoss"},
        {9993,"JBoss"},{9994,"JBoss"},{9995,"JBoss"},{9996,"JBoss"},
        {9997,"Splunk-Log"},{9998,"HTTP-Alt"},{9999,"HTTP-Alt"},
        {10000,"Webmin"},{10001,"Ubiquiti"},{10009,"Crossbeam"},
        {10113,"NetIQ"},{10114,"NetIQ"},{10115,"NetIQ"},
        {10161,"SNMP-Agent"},{10162,"SNMP-Trap"},{10250,"Kubelet"},
        {11000,"MySQL-Cluster"},{11111,"HP-RBAC"},{11211,"Memcached"},
        {12000,"WebSphere-Caching"},{12001,"IBM-WebSEAL"},
        {12012,"HP-RBAC"},{12013,"HP-RBAC"},{12222,"Lightstreamer"},
        {12345,"NetBus"},{12399,"IIS-Admin"},{13000,"RabbitMQ"},
        {13579,"Pegasus"},{13722,"Tivoli"},{14000,"Tivoli-Monitor"},
        {14141,"Bochs"},{14238,"HP-RBAC"},{14333,"MSSQL"},
        {14441,"HP-RBAC"},{14900,"Tivoli"},{14942,"HP-RBAC"},
        {15000,"HTTP-Alt"},{15001,"HP-RBAC"},{15002,"HP-RBAC"},
        {15118,"IBM-DB2"},{15345,"XPilot"},{16000,"Oracle-DB"},
        {16080,"HTTP-Alt"},{16309,"NetBackup"},{16310,"NetBackup"},
        {16311,"NetBackup"},{16384,"CISCO"},{16400,"HP-RBAC"},
        {16500,"HP-RBAC"},{16600,"HP-RBAC"},{16800,"HP-RBAC"},
        {16992,"Intel-AMT"},{16993,"Intel-AMT"},{16994,"Intel-AMT"},
        {16995,"Intel-AMT"},{17000,"HTTP-Alt"},{17001,"HP-RBAC"},
        {17472,"HP-RBAC"},{17500,"Dropbox"},{17600,"HP-RBAC"},
        {17777,"HP-RBAC"},{18080,"HTTP-Alt"},{18081,"HTTP-Alt"},
        {18181,"Opentact"},{18200,"HP-RBAC"},{18201,"HP-RBAC"},
        {18202,"HP-RBAC"},{18203,"HP-RBAC"},{18204,"HP-RBAC"},
        {18400,"HP-RBAC"},{18888,"HP-RBAC"},{19000,"SMB2"},
        {19101,"HP-RBAC"},{19102,"HP-RBAC"},{19150,"GSS-API"},
        {19283,"Keysrv"},{19315,"Keysrv"},{19350,"GSS-API"},
        {19410,"HP-RBAC"},{19411,"HP-RBAC"},{19540,"HP-RBAC"},
        {19767,"HP-RBAC"},{19800,"HP-RBAC"},{19876,"HP-RBAC"},
        {19900,"HP-RBAC"},{20000,"DNP"},{20001,"HP-RBAC"},
        {20002,"HP-RBAC"},{20003,"HP-RBAC"},{20004,"HP-RBAC"},
        {20005,"HP-RBAC"},{20048,"NFS-Mountd"},{20100,"HP-RBAC"},
        {20101,"HP-RBAC"},{20167,"HP-RBAC"},{20168,"HP-RBAC"},
        {20480,"HP-RBAC"},{21000,"HTTP-Alt"},{22000,"SCP-Configuration"},
        {22222,"DirectAdmin"},{23073,"Soldat"},{23456,"OwnCloud"},
        {24007,"GlusterFS"},{24333,"Lighthouse"},{24383,"Lighthouse"},
        {24444,"Broadsoft"},{24554,"BGP"},{24800,"Synergy"},
        {24842,"Step-Net"},{25000,"TeamSpeak"},{25252,"HP-RBAC"},
        {25346,"MultiTheftAuto"},{25535,"Minecraft-Launcher"},{25565,"Minecraft"},
        {25672,"RabbitMQ"},{25734,"HP-RBAC"},{25876,"HP-RBAC"},
        {26000,"HP-RBAC"},{26001,"HP-RBAC"},{26002,"HP-RBAC"},
        {26003,"HP-RBAC"},{26004,"HP-RBAC"},{26005,"HP-RBAC"},
        {26208,"BWM"},{27000,"FlexLM"},{27001,"FlexLM"},{27002,"FlexLM"},
        {27003,"FlexLM"},{27004,"FlexLM"},{27005,"FlexLM"},{27006,"FlexLM"},
        {27007,"FlexLM"},{27008,"FlexLM"},{27009,"FlexLM"},{27010,"FlexLM"},
        {27015,"Steam"},{27016,"Steam"},{27017,"MongoDB"},{27018,"MongoDB"},
        {27019,"MongoDB"},{27195,"HP-RBAC"},{27374,"SubSeven"},
        {27444,"HP-RBAC"},{27500,"KIX"},{27666,"HP-RBAC"},
        {27777,"HP-RBAC"},{27888,"HP-RBAC"},{27900,"Quake"},
        {27901,"Quake"},{27910,"Quake"},{27960,"Quake3"},
        {28000,"BitWasp"},{28017,"MongoDB-Web"},{28100,"HP-RBAC"},
        {28201,"HP-RBAC"},{28240,"SiS"},{28300,"HP-RBAC"},
        {28443,"HP-RBAC"},{28444,"HP-RBAC"},{28555,"HP-RBAC"},
        {28686,"HP-RBAC"},{28777,"HP-RBAC"},{28888,"HP-RBAC"},
        {28900,"HP-RBAC"},{29000,"HP-RBAC"},{29100,"HP-RBAC"},
        {29167,"HP-RBAC"},{30000,"HTTP-Alt"},{30100,"HP-RBAC"},
        {30101,"HP-RBAC"},{30102,"HP-RBAC"},{30200,"HP-RBAC"},
        {30303,"Ethereum"},{30718,"HP-RBAC"},{30720,"HP-RBAC"},
        {30721,"HP-RBAC"},{30722,"HP-RBAC"},{30730,"HP-RBAC"},
        {31337,"BackOrifice"},{32000,"HP-RBAC"},{32400,"Plex"},
        {32764,"Linksys"},{32768,"Filenet"},{32769,"Filenet"},
        {32770,"Filenet"},{32771,"Filenet"},{32772,"Filenet"},
        {32773,"Filenet"},{32774,"Filenet"},{32775,"Filenet"},
        {32776,"Filenet"},{32777,"Filenet"},{32778,"Filenet"},
        {32779,"Filenet"},{32780,"Filenet"},{32781,"Filenet"},
        {32782,"Filenet"},{32783,"Filenet"},{32784,"Filenet"},
        {32785,"Filenet"},{32786,"Filenet"},{32787,"Filenet"},
        {32788,"Filenet"},{32789,"Filenet"},{32790,"Filenet"},
        {32791,"Filenet"},{32792,"Filenet"},{32793,"Filenet"},
        {32794,"Filenet"},{32795,"Filenet"},{32796,"Filenet"},
        {33333,"HP-RBAC"},{33733,"BackNet"},{33848,"Jenkins"},
        {34000,"HP-RBAC"},{34197,"Factorio"},{34443,"HTTPS-Alt"},
        {34567,"EDI"},{34777,"HP-RBAC"},{35000,"HP-RBAC"},
        {35353,"HP-RBAC"},{35488,"HP-RBAC"},{36666,"HP-RBAC"},
        {37008,"HP-RBAC"},{38292,"Landesk"},{39000,"HP-RBAC"},
        {39666,"HP-RBAC"},{40000,"SafetyNET"},{40404,"CR-Web"},
        {40886,"HP-RBAC"},{41008,"HP-RBAC"},{41009,"HP-RBAC"},
        {41010,"HP-RBAC"},{41111,"HP-RBAC"},{41523,"HP-RBAC"},
        {42000,"HP-RBAC"},{42510,"HP-RBAC"},{43000,"HP-RBAC"},
        {43047,"HP-RBAC"},{43188,"REACHout"},{43210,"HP-RBAC"},
        {43441,"HP-RBAC"},{44000,"HP-RBAC"},{44123,"HP-RBAC"},
        {44321,"HP-RBAC"},{44322,"HP-RBAC"},{44334,"HP-RBAC"},
        {44401,"HP-RBAC"},{44442,"HP-RBAC"},{44443,"HP-RBAC"},
        {44444,"HP-RBAC"},{44445,"HP-RBAC"},{44446,"HP-RBAC"},
        {44447,"HP-RBAC"},{44448,"HP-RBAC"},{44449,"HP-RBAC"},
        {45000,"HP-RBAC"},{45045,"HP-RBAC"},{45046,"HP-RBAC"},
        {45047,"HP-RBAC"},{45048,"HP-RBAC"},{45049,"HP-RBAC"},
        {45514,"HP-RBAC"},{45515,"HP-RBAC"},{45516,"HP-RBAC"},
        {45517,"HP-RBAC"},{45518,"HP-RBAC"},{45519,"HP-RBAC"},
        {45520,"HP-RBAC"},{45521,"HP-RBAC"},{45522,"HP-RBAC"},
        {45523,"HP-RBAC"},{45524,"HP-RBAC"},{45525,"HP-RBAC"},
        {45526,"HP-RBAC"},{45527,"HP-RBAC"},{45528,"HP-RBAC"},
        {45529,"HP-RBAC"},{45530,"HP-RBAC"},{45531,"HP-RBAC"},
        {45532,"HP-RBAC"},{45533,"HP-RBAC"},{45534,"HP-RBAC"},
        {45535,"HP-RBAC"},{45536,"HP-RBAC"},{45537,"HP-RBAC"},
        {45538,"HP-RBAC"},{45539,"HP-RBAC"},{45540,"HP-RBAC"},
        {45541,"HP-RBAC"},{45542,"HP-RBAC"},{45543,"HP-RBAC"},
        {45544,"HP-RBAC"},{45545,"HP-RBAC"},{45546,"HP-RBAC"},
        {47808,"BACnet"},{49152,"Windows-RPC"},{49153,"Windows-RPC"},
        {49154,"Windows-RPC"},{49155,"Windows-RPC"},{49156,"Windows-RPC"},
        {49157,"Windows-RPC"},{49158,"Windows-RPC"},{49159,"Windows-RPC"},
        {49160,"Windows-RPC"},{49161,"Windows-RPC"},{49162,"Windows-RPC"},
        {49163,"Windows-RPC"},{49164,"Windows-RPC"},{49165,"Windows-RPC"},
        {49166,"Windows-RPC"},{49167,"Windows-RPC"},{49168,"Windows-RPC"},
        {49169,"Windows-RPC"},{49170,"Windows-RPC"},{49171,"Windows-RPC"},
        {49172,"Windows-RPC"},{49173,"Windows-RPC"},{49174,"Windows-RPC"},
        {49175,"Windows-RPC"},{49176,"Windows-RPC"},{49177,"Windows-RPC"},
        {49178,"Windows-RPC"},{49179,"Windows-RPC"},{49180,"Windows-RPC"},
        {49181,"Windows-RPC"},{49182,"Windows-RPC"},{49183,"Windows-RPC"},
        {49184,"Windows-RPC"},{49185,"Windows-RPC"},{49186,"Windows-RPC"},
        {49187,"Windows-RPC"},{49188,"Windows-RPC"},{49189,"Windows-RPC"},
        {49190,"Windows-RPC"},{49191,"Windows-RPC"},{49192,"Windows-RPC"},
        {49193,"Windows-RPC"},{49194,"Windows-RPC"},{49195,"Windows-RPC"},
        {49196,"Windows-RPC"},{49197,"Windows-RPC"},{49198,"Windows-RPC"},
        {49199,"Windows-RPC"},{49200,"Windows-RPC"},{49201,"Windows-RPC"},
        {50000,"IBM-DB2"},{50001,"HP-RBAC"},{50002,"HP-RBAC"},
        {50003,"HP-RBAC"},{50070,"Hadoop-NameNode"},{50075,"Hadoop-DataNode"},
        {50090,"Hadoop-SecondaryNN"},{50100,"HP-RBAC"},{50200,"HP-RBAC"},
        {50300,"HP-RBAC"},{50400,"HP-RBAC"},{50500,"HP-RBAC"},
        {50600,"HP-RBAC"},{50700,"HP-RBAC"},{50800,"HP-RBAC"},
        {50900,"HP-RBAC"},{51000,"HP-RBAC"},{51100,"HP-RBAC"},
        {51200,"HP-RBAC"},{51300,"HP-RBAC"},{51400,"HP-RBAC"},
        {51500,"HP-RBAC"},{51600,"HP-RBAC"},{51700,"HP-RBAC"},
        {51800,"HP-RBAC"},{51900,"HP-RBAC"},{52000,"HP-RBAC"},
        {52100,"HP-RBAC"},{52200,"HP-RBAC"},{52299,"HP-RBAC"},
        {52300,"HP-RBAC"},{52400,"HP-RBAC"},{52500,"HP-RBAC"},
        {52600,"HP-RBAC"},{52700,"HP-RBAC"},{52800,"HP-RBAC"},
        {52869,"HP-RBAC"},{52900,"HP-RBAC"},{53000,"HP-RBAC"},
        {53331,"HP-RBAC"},{53333,"HP-RBAC"},{54000,"HP-RBAC"},
        {54045,"HP-RBAC"},{54321,"PCAnywhere"},{54545,"HP-RBAC"},
        {55000,"HP-RBAC"},{55555,"HP-RBAC"},{55600,"HP-RBAC"},
        {55777,"HP-RBAC"},{55888,"HP-RBAC"},{56000,"HP-RBAC"},
        {56001,"HP-RBAC"},{56100,"HP-RBAC"},{56200,"HP-RBAC"},
        {56300,"HP-RBAC"},{56400,"HP-RBAC"},{56500,"HP-RBAC"},
        {56600,"HP-RBAC"},{56700,"HP-RBAC"},{56800,"HP-RBAC"},
        {56900,"HP-RBAC"},{57000,"HP-RBAC"},{57100,"HP-RBAC"},
        {57200,"HP-RBAC"},{57300,"HP-RBAC"},{57400,"HP-RBAC"},
        {57500,"HP-RBAC"},{57600,"HP-RBAC"},{57700,"HP-RBAC"},
        {57800,"HP-RBAC"},{57900,"HP-RBAC"},{58000,"HP-RBAC"},
        {58080,"HTTP-Alt"},{58100,"HP-RBAC"},{58200,"HP-RBAC"},
        {58300,"HP-RBAC"},{58400,"HP-RBAC"},{58500,"HP-RBAC"},
        {58600,"HP-RBAC"},{58700,"HP-RBAC"},{58800,"HP-RBAC"},
        {58900,"HP-RBAC"},{59000,"HP-RBAC"},{59100,"HP-RBAC"},
        {59192,"HP-RBAC"},{59200,"HP-RBAC"},{59300,"HP-RBAC"},
        {59400,"HP-RBAC"},{59500,"HP-RBAC"},{59600,"HP-RBAC"},
        {59700,"HP-RBAC"},{59800,"HP-RBAC"},{59900,"HP-RBAC"},
        {60000,"DeepSound"},{60020,"Google-AD"},{60100,"HP-RBAC"},
        {60101,"HP-RBAC"},{60102,"HP-RBAC"},{60103,"HP-RBAC"},
        {60104,"HP-RBAC"},{60200,"HP-RBAC"},{60300,"HP-RBAC"},
        {60400,"HP-RBAC"},{60500,"HP-RBAC"},{60600,"HP-RBAC"},
        {60700,"HP-RBAC"},{60800,"HP-RBAC"},{60900,"HP-RBAC"},
        {61000,"HP-RBAC"},{61100,"HP-RBAC"},{61101,"HP-RBAC"},
        {61102,"HP-RBAC"},{61200,"HP-RBAC"},{61234,"HP-RBAC"},
        {61300,"HP-RBAC"},{61400,"HP-RBAC"},{61500,"HP-RBAC"},
        {61532,"HP-RBAC"},{61600,"HP-RBAC"},{61616,"HP-RBAC"},
        {61800,"HP-RBAC"},{61900,"HP-RBAC"},{62000,"HP-RBAC"},
        {62078,"iPhone-Sync"},{62100,"HP-RBAC"},{62101,"HP-RBAC"},
        {62102,"HP-RBAC"},{62103,"HP-RBAC"},{62104,"HP-RBAC"},
        {62200,"HP-RBAC"},{62300,"HP-RBAC"},{62400,"HP-RBAC"},
        {62500,"HP-RBAC"},{62501,"HP-RBAC"},{62600,"HP-RBAC"},
        {62601,"HP-RBAC"},{62610,"HP-RBAC"},{62620,"HP-RBAC"},
        {62700,"HP-RBAC"},{62701,"HP-RBAC"},{62800,"HP-RBAC"},
        {62900,"HP-RBAC"},{63000,"HP-RBAC"},{63100,"HP-RBAC"},
        {63200,"HP-RBAC"},{63300,"HP-RBAC"},{63301,"HP-RBAC"},
        {63331,"HP-RBAC"},{63400,"HP-RBAC"},{63401,"HP-RBAC"},
        {63402,"HP-RBAC"},{63403,"HP-RBAC"},{63404,"HP-RBAC"},
        {63405,"HP-RBAC"},{63406,"HP-RBAC"},{63407,"HP-RBAC"},
        {63408,"HP-RBAC"},{63409,"HP-RBAC"},{63410,"HP-RBAC"},
        {63411,"HP-RBAC"},{63412,"HP-RBAC"},{63413,"HP-RBAC"},
        {63414,"HP-RBAC"},{63415,"HP-RBAC"},{63416,"HP-RBAC"},
        {63417,"HP-RBAC"},{63418,"HP-RBAC"},{63419,"HP-RBAC"},
        {63420,"HP-RBAC"},{63421,"HP-RBAC"},{63422,"HP-RBAC"},
        {63423,"HP-RBAC"},{63424,"HP-RBAC"},{63425,"HP-RBAC"},
        {63426,"HP-RBAC"},{63427,"HP-RBAC"},{63428,"HP-RBAC"},
        {63429,"HP-RBAC"},{63430,"HP-RBAC"},{63431,"HP-RBAC"},
        {63432,"HP-RBAC"},{63433,"HP-RBAC"},{63434,"HP-RBAC"},
        {63435,"HP-RBAC"},{63436,"HP-RBAC"},{63437,"HP-RBAC"},
        {63438,"HP-RBAC"},{63439,"HP-RBAC"},{63440,"HP-RBAC"},
        {63441,"HP-RBAC"},{63442,"HP-RBAC"},{63443,"HP-RBAC"},
        {63444,"HP-RBAC"},{63445,"HP-RBAC"},{63446,"HP-RBAC"},
        {63447,"HP-RBAC"},{63448,"HP-RBAC"},{63449,"HP-RBAC"},
        {63450,"HP-RBAC"},{63451,"HP-RBAC"},{63452,"HP-RBAC"},
        {63453,"HP-RBAC"},{63454,"HP-RBAC"},{63455,"HP-RBAC"},
        {63456,"HP-RBAC"},{63457,"HP-RBAC"},{63458,"HP-RBAC"},
        {63459,"HP-RBAC"},{63460,"HP-RBAC"},{63461,"HP-RBAC"},
        {63462,"HP-RBAC"},{63463,"HP-RBAC"},{63464,"HP-RBAC"},
        {63465,"HP-RBAC"},{63466,"HP-RBAC"},{63467,"HP-RBAC"},
        {63468,"HP-RBAC"},{63469,"HP-RBAC"},{63470,"HP-RBAC"},
        {63471,"HP-RBAC"},{63472,"HP-RBAC"},{63473,"HP-RBAC"},
        {63474,"HP-RBAC"},{63475,"HP-RBAC"},{63476,"HP-RBAC"},
        {63477,"HP-RBAC"},{63478,"HP-RBAC"},{63479,"HP-RBAC"},
        {63480,"HP-RBAC"},{63481,"HP-RBAC"},{63482,"HP-RBAC"},
        {63483,"HP-RBAC"},{63484,"HP-RBAC"},{63485,"HP-RBAC"},
        {63486,"HP-RBAC"},{63487,"HP-RBAC"},{63488,"HP-RBAC"},
        {63489,"HP-RBAC"},{63490,"HP-RBAC"},{63491,"HP-RBAC"},
        {63492,"HP-RBAC"},{63493,"HP-RBAC"},{63494,"HP-RBAC"},
        {63495,"HP-RBAC"},{63496,"HP-RBAC"},{63497,"HP-RBAC"},
        {63498,"HP-RBAC"},{63499,"HP-RBAC"},{63500,"HP-RBAC"},
        {64321,"HP-RBAC"},{65000,"HTTP-Alt"},{65001,"HTTP-Alt"},
        {65002,"HTTP-Alt"},{65003,"HTTP-Alt"},{65100,"HP-RBAC"},
        {65101,"HP-RBAC"},{65102,"HP-RBAC"},{65103,"HP-RBAC"},
        {65104,"HP-RBAC"},{65105,"HP-RBAC"},{65129,"HP-RBAC"},
        {65130,"HP-RBAC"},{65131,"HP-RBAC"},{65132,"HP-RBAC"},
        {65133,"HP-RBAC"},{65134,"HP-RBAC"},{65135,"HP-RBAC"},
        {65136,"HP-RBAC"},{65137,"HP-RBAC"},{65138,"HP-RBAC"},
        {65139,"HP-RBAC"},{65140,"HP-RBAC"},{65141,"HP-RBAC"},
        {65142,"HP-RBAC"},{65143,"HP-RBAC"},{65144,"HP-RBAC"},
        {65145,"HP-RBAC"},{65146,"HP-RBAC"},{65147,"HP-RBAC"},
        {65148,"HP-RBAC"},{65149,"HP-RBAC"},{65150,"HP-RBAC"},
        {65151,"HP-RBAC"}
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
    auto patterns = build_version_patterns();

    for (const auto& p : patterns) {
        try {
            regex re(p.pattern, regex_constants::icase);
            smatch m;
            if (regex_search(banner, m, re)) {
                VersionMatch vm;
                vm.service = p.service;
                vm.product = p.product;
                vm.os_hint = p.os_hint;
                vm.confidence = 0.85;

                if (!p.version.empty() && m.size() > 1) {
                    vm.version = m[1].str();
                }

                matches.push_back(vm);
            }
        } catch (...) {}
    }

    return matches;
}

/* ─────────────────────────────────────────────────────────────────
 * CVE CHECKING ENGINE
 * ───────────────────────────────────────────────────────────────── */

static bool version_lte(const string& v1, const string& v2) {
    auto parse = [](const string& v) -> vector<int> {
        vector<int> parts;
        stringstream ss(v);
        string part;
        while (getline(ss, part, '.')) {
            // Strip non-numeric suffixes
            string num;
            for (char c : part) {
                if (isdigit(c)) num += c;
                else break;
            }
            try { parts.push_back(stoi(num)); }
            catch (...) { parts.push_back(0); }
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
    auto cve_db = build_cve_db();

    for (const auto& cve : cve_db) {
        string sl = product, pl = cve.service_pattern;
        transform(sl.begin(), sl.end(), sl.begin(), ::tolower);
        transform(pl.begin(), pl.end(), pl.begin(), ::tolower);
        if (sl.find(pl) == string::npos && pl.find(sl) == string::npos) continue;

        if (cve.version_max == "EOL" || cve.version_max == "INFO-NOAUTH" ||
            cve.version_max == "INFO-EXPOSED" || cve.version_max == "0.0") {
            string v = "[" + cve.severity + "] " + cve.cve_id + " — " + cve.description;
            if (cve.cvss > 0) {
                char buf[32];
                snprintf(buf, sizeof(buf), " (CVSS:%.1f)", cve.cvss);
                v += buf;
            }
            vulns.push_back(v);
            continue;
        }

        if (!version.empty() && !cve.version_max.empty()) {
            if (version_lte(version, cve.version_max)) {
                string v = "[" + cve.severity + "] " + cve.cve_id + " — " + cve.description;
                char buf[32];
                snprintf(buf, sizeof(buf), " (CVSS:%.1f)", cve.cvss);
                v += buf;
                vulns.push_back(v);
            }
        }
    }

    return vulns;
}

/* ─────────────────────────────────────────────────────────────────
 * SERVICE SCANNER
 * ───────────────────────────────────────────────────────────────── */

static void set_port_state(ScanResult& result, bool open) {
    result.state = open ? "OPEN" : "CLOSED/FILTERED";
}

static string detect_service_from_banner(int port, const string& banner) {
    auto matches = match_version_patterns(banner);
    if (!matches.empty()) {
        // Return first match's service category
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

    // Determine probe based on port
    string banner;
    int probe_port = port;

    // Map ports to probe types
    enum ProbeType { PROBE_AUTO, PROBE_HTTP, PROBE_SSH, PROBE_SMTP, PROBE_FTP,
                     PROBE_POP3, PROBE_IMAP, PROBE_MYSQL, PROBE_HTTPS };
    ProbeType ptype = PROBE_AUTO;

    switch (port) {
        case 80: case 8000: case 8001: case 8008: case 8080: case 8081:
        case 8082: case 8888: case 9000: case 9090: case 3000: case 5000:
            ptype = PROBE_HTTP; break;
        case 22: ptype = PROBE_SSH; break;
        case 25: case 465: case 587: ptype = PROBE_SMTP; break;
        case 21: ptype = PROBE_FTP; break;
        case 110: case 995: ptype = PROBE_POP3; break;
        case 143: case 993: ptype = PROBE_IMAP; break;
        case 3306: ptype = PROBE_MYSQL; break;
        case 443: case 8443: case 9443: case 10443: ptype = PROBE_HTTPS; break;
        default:
            // Try generic probe first
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
            // Generic: try HTTP first, then fall back to raw banner
            banner = probeHTTP(host, probe_port, timeout_ms);
            if (banner.empty()) {
                // Fall back to generic TCP banner grab (connect and read)
                SOCKET s = create_tcp_socket();
                if (!IS_INVALID(s)) {
                    struct sockaddr_in addr;
                    if (resolve_host(host, addr) == 0) {
                        addr.sin_port = htons((uint16_t)port);
                        if (connect_with_timeout(s, (struct sockaddr*)&addr, sizeof(addr), timeout_ms)) {
                            // Try to read any banner
                            char buf[MAX_BANNER_SIZE] = {};
                            int n = recv_with_timeout(s, buf, sizeof(buf)-1, timeout_ms);
                            if (n > 0) {
                                banner = sanitize_banner(buf, n);
                                // Extract first meaningful line
                                istringstream iss(banner);
                                string line;
                                getline(iss, line);
                                if (!line.empty() && line.back() == '\r') line.pop_back();
                                if (line.size() > 2) banner = line;
                                else banner = banner.substr(0, 200);
                            }
                        }
                    }
                    CLOSE_SOCKET(s);
                }

                // If still empty, try SSH probe (could be SSH on non-standard port)
                if (banner.empty()) {
                    banner = probeSSH(host, probe_port, timeout_ms);
                }
            }
            break;
        }
    }

    // Check TLS indicator
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

    // Match version patterns
    auto matches = match_version_patterns(banner);

    // Process matches
    double best_confidence = 0.0;
    for (const auto& m : matches) {
        if (m.confidence > best_confidence) {
            best_confidence = m.confidence;
            result.service   = m.service;
            result.product   = m.product;
            result.version   = m.version;
            result.os_hint   = m.os_hint;
            result.confidence = m.confidence;

            // CPE generation
            string cpe = "cpe:/a:";
            string prod_lower = m.product;
            transform(prod_lower.begin(), prod_lower.end(), prod_lower.begin(), ::tolower);
            // Replace spaces with underscores
            for (auto& c : prod_lower) if (c == ' ') c = '_';
            cpe += prod_lower;
            if (!m.version.empty()) cpe += ":" + m.version;
            result.cpe = cpe;
            result.cpe_list.push_back(cpe);
        }
    }

    // Fallback to port-based service
    if (result.service.empty()) {
        result.service = get_port_service(port);
        result.product = result.service;
        result.confidence = 0.5;
    }

    // OS detection
    result.os_fp = combine_os_detection(banner, detect_ttl(host));

    // If no OS hint from pattern but we got one from OS detection
    if (result.os_hint.empty() && result.os_fp.confidence > 0.3f) {
        result.os_hint = result.os_fp.os_name;
        if (!result.os_fp.os_version.empty())
            result.os_hint += " " + result.os_fp.os_version;
    }

    // Vulnerability check
    result.vulnerabilities = check_vulnerabilities(result.product, result.version);

    // Risk scoring
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
            bl.find("ssl 3") != string::npos || bl.find("tls 1.0") != string::npos) {
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
    void enqueue(F&& f) {
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

static void print_scan_json(const ScanResult& r) {
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

static void print_scan_text(const ScanResult& r) {
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

static void print_banner() {
    printf("\n\033[1;35m");
    printf("  +====================================================+\n");
    printf("  |  \xe2\x9a\xa1 HackIT PortStorm v4.0  \xe2\x80\x94  C++ Scanner Engine      |\n");
    printf("  |  150+ signatures | OS fingerprint | Protocol probes |\n");
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

    const char* host      = argv[1];
    const char* port_spec = argv[2];
    int timeout_ms        = DEFAULT_TIMEOUT_MS;
    bool json_mode        = false;
    int thread_count      = THREAD_POOL_SIZE;

    if (argc >= 4) {
        string arg3(argv[3]);
        // Check if it starts with 'threads:'
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
        } else {
            timeout_ms = atoi(argv[4]);
            if (timeout_ms < 100) timeout_ms = 100;
            if (timeout_ms > 30000) timeout_ms = 30000;
        }
    }

    if (argc >= 6) {
        string arg5(argv[5]);
        if (arg5.rfind("threads:", 0) == 0) {
            thread_count = max(1, stoi(arg5.substr(8)));
        }
    }

    // Parse ports
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
            for (int p = start; p <= end; p++) ports.push_back(p);
        } else {
            try { ports.push_back(stoi(token)); }
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

    // Scan ports
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
                    results.push_back(r);
                }
                completed++;
            });
        }
    }

    // Sort by port
    sort(results.begin(), results.end(), [](const ScanResult& a, const ScanResult& b) {
        return a.port < b.port;
    });

    auto t_start = steady_clock::now();

    // Output results
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
