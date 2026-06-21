/*
 * HackIT C++ Expert Service & Version Discovery Engine v2.0
 * Cross-platform banner grabbing and protocol analysis with regex version extraction
 * Compiler: g++ -std=c++17 -O3 -o service_scanner service_scanner.cpp -lssl -lcrypto -lpthread
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
#include <algorithm>
#include <chrono>
#include <sstream>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <functional>
#include <queue>
#include <condition_variable>
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


#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #define CLOSE_SOCKET(s) closesocket(s)
  #define IS_INVALID(s) ((s) == INVALID_SOCKET)
  #define SOCKET_ERROR_RETURN SOCKET_ERROR
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <sys/poll.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <netinet/tcp.h>
  #include <netinet/in.h>
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/x509v3.h>
  #define CLOSE_SOCKET(s) close(s)
  #define SOCKET int
  #define INVALID_SOCKET -1
  #define IS_INVALID(s) ((s) < 0)
#endif

using namespace std;
using namespace chrono;

class ServiceScanner {
public:
    static string analyze_banner(int port, const string& banner) {
        if (banner.empty()) return "unknown";

        // HTTP/HTTPS
        if (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 9443 || port == 2083) {
            regex http_regex("Server: ([^\\r\\n]+)");
            smatch match;
            if (regex_search(banner, match, http_regex)) return match[1];
            regex powered_regex("X-Powered-By: ([^\\r\\n]+)");
            if (regex_search(banner, match, powered_regex)) return match[1];
        }

        // SSH
        if (port == 22) {
            regex ssh_regex("SSH-([^-]+)-([^\\s\\r\\n]+)");
            smatch match;
            if (regex_search(banner, match, ssh_regex)) return "SSH " + match[1].str() + " (" + match[2].str() + ")";
        }

        // FTP
        if (port == 21 || port == 990) {
            regex ftp_regex("220[-\\s]([^\\r\\n]+)");
            smatch match;
            if (regex_search(banner, match, ftp_regex)) return match[1];
            if (banner.find("vsFTPd") != string::npos) return "vsFTPd";
            if (banner.find("ProFTPD") != string::npos) return "ProFTPD";
            if (banner.find("Pure-FTPd") != string::npos) {
                regex pure_regex("Pure-FTPd ([\\d.]+)");
                if (regex_search(banner, match, pure_regex)) return "Pure-FTPd " + match[1].str();
                return "Pure-FTPd";
            }
            if (banner.find("pure-ftpd") != string::npos) {
                regex pure_regex("pure-ftpd ([\\d.]+)");
                if (regex_search(banner, match, pure_regex)) return "Pure-FTPd " + match[1].str();
                return "Pure-FTPd";
            }
        }

        // MySQL / MariaDB
        if (port == 3306) {
            if (banner.length() > 5) {
                string ver = banner.substr(5, 15);
                if (ver.find("MariaDB") != string::npos) return "MariaDB " + ver;
                return "MySQL " + ver;
            }
        }

        // SMB
        if (port == 445) {
            return "Microsoft-DS (SMB)";
        }

        // RDP
        if (port == 3389) {
            return "RDP (Remote Desktop)";
        }

        // Telnet
        if (port == 23) {
            if (banner.find("\xff\xfd") != string::npos) return "Telnet (Negotiation)";
            return "Telnet";
        }

        // VNC
        if (port == 5900 || port == 5901) {
            if (banner.find("RFB") != string::npos) return "VNC (" + banner.substr(0, 12) + ")";
            return "VNC";
        }

        // PostgreSQL
        if (port == 5432) {
            regex pg_regex("PostgreSQL ([\\d.]+)");
            smatch match;
            if (regex_search(banner, match, pg_regex)) return "PostgreSQL " + match[1].str();
            return "PostgreSQL";
        }

        // MSSQL
        if (port == 1433) {
            return "MSSQL Server";
        }

        // Oracle DB
        if (port == 1521) {
            return "Oracle DB";
        }

        // SNMP
        if (port == 161) {
            return "SNMP Service";
        }

        // Redis
        if (port == 6379) {
            if (banner.find("redis_version") != string::npos) {
                regex redis_regex("redis_version:([0-9.]+)");
                smatch match;
                if (regex_search(banner, match, redis_regex)) return "Redis " + match[1].str();
            }
            return "Redis";
        }

        // MongoDB
        if (port == 27017) {
            return "MongoDB";
        }

        // SMTP
        if (port == 25 || port == 587 || port == 465) {
            if (banner.find("Postfix") != string::npos) {
                regex pf_regex("Postfix ([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, pf_regex)) return "Postfix " + match[1].str();
                return "Postfix SMTP";
            }
            if (banner.find("Exim") != string::npos) {
                regex exim_regex("Exim ([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, exim_regex)) return "Exim " + match[1].str();
                return "Exim SMTP";
            }
            if (banner.find("Sendmail") != string::npos) {
                regex sendmail_regex("Sendmail ([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, sendmail_regex)) return "Sendmail " + match[1].str();
                return "Sendmail";
            }
            if (banner.find("Microsoft ESMTP") != string::npos) return "Microsoft Exchange";
            if (banner.find("OpenSMTPD") != string::npos) return "OpenSMTPD";
            return "SMTP";
        }

        // POP3
        if (port == 110 || port == 995) {
            if (banner.find("Dovecot") != string::npos) {
                regex dovecot_regex("Dovecot.*v([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, dovecot_regex)) return "Dovecot POP3 " + match[1].str();
                if (banner.find("pop3d") != string::npos) return "Dovecot POP3 (pop3d)";
                return "Dovecot POP3";
            }
            if (banner.find("Courier") != string::npos) return "Courier POP3";
            if (banner.find("Cyrus") != string::npos) {
                regex cyrus_regex("Cyrus.*v([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, cyrus_regex)) return "Cyrus POP3 " + match[1].str();
                return "Cyrus POP3";
            }
            return "POP3";
        }

        // IMAP
        if (port == 143 || port == 993) {
            if (banner.find("Dovecot") != string::npos) {
                regex dovecot_regex("Dovecot.*v([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, dovecot_regex)) return "Dovecot IMAP " + match[1].str();
                if (banner.find("imapd") != string::npos) return "Dovecot IMAP (imapd)";
                return "Dovecot IMAP";
            }
            if (banner.find("Courier") != string::npos) return "Courier IMAP";
            if (banner.find("Cyrus") != string::npos) return "Cyrus IMAP";
            if (banner.find("Zimbra") != string::npos) return "Zimbra IMAP";
            return "IMAP";
        }

        // DNS
        if (port == 53) {
            if (banner.find("BIND") != string::npos) {
                regex bind_regex("BIND ([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, bind_regex)) return "BIND " + match[1].str();
                return "BIND DNS";
            }
            return "DNS";
        }

        // LDAP
        if (port == 389 || port == 636 || port == 3268 || port == 3269) {
            if (banner.find("OpenLDAP") != string::npos) {
                regex ldap_regex("OpenLDAP ([\\d.]+)");
                smatch match;
                if (regex_search(banner, match, ldap_regex)) return "OpenLDAP " + match[1].str();
                return "OpenLDAP";
            }
            return "LDAP";
        }

        return std::string(banner.substr(0, 50));
    }

    static string grab_deep_banner(const char* host, int port, int timeout_ms) {
#ifdef _WIN32
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (IS_INVALID(s)) return "";

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            CLOSE_SOCKET(s);
            return "";
        }

#ifdef _WIN32
        DWORD tv = timeout_ms;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int flag = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));
#endif

        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            CLOSE_SOCKET(s);
            return "";
        }

        // Protocol-specific probes
        if (port == 80 || port == 8080 || port == 8000 || port == 8888) {
            string probe = "GET / HTTP/1.0\r\nHost: " + string(host) + "\r\nUser-Agent: HackIT-Scanner/2.0\r\nAccept: */*\r\n\r\n";
            send(s, probe.c_str(), probe.length(), 0);
        } else if (port == 443 || port == 8443 || port == 9443 || port == 2083 || port == 2096) {
            // Minimal TLS ClientHello
            unsigned char tls_probe[] = {
                0x16, 0x03, 0x01, 0x00, 0x31,
                0x01, 0x00, 0x00, 0x2d, 0x03, 0x03,
                0xd0, 0x6d, 0x7e, 0xbe, 0x9c, 0x29, 0xd0, 0x33,
                0x43, 0xed, 0x7a, 0x2c, 0xe8, 0x49, 0xc1, 0xd8,
                0x22, 0x05, 0x20, 0xd1, 0x6b, 0xdf, 0xf4, 0x3a,
                0x3a, 0x49, 0x51, 0xd1, 0x32, 0x72, 0x57, 0x90,
                0x00, 0x00, 0x04, 0xc0, 0x2b, 0x00, 0x2f, 0x01, 0x00
            };
            send(s, (const char*)tls_probe, sizeof(tls_probe), 0);
        } else if (port == 3306) {
            // MySQL — just read greeting
        } else if (port == 445) {
            unsigned char smb_probe[] = {
                0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x02,
                0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
            };
            send(s, (const char*)smb_probe, sizeof(smb_probe), 0);
        } else if (port == 3389) {
            unsigned char rdp_probe[] = {
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
                0x00, 0x00, 0x00
            };
            send(s, (const char*)rdp_probe, sizeof(rdp_probe), 0);
        } else if (port == 23) {
            unsigned char telnet_probe[] = { 0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03 };
            send(s, (const char*)telnet_probe, sizeof(telnet_probe), 0);
        } else if (port == 5900 || port == 5901) {
            string vnc_probe = "RFB 003.008\n";
            send(s, vnc_probe.c_str(), vnc_probe.length(), 0);
        } else if (port == 5432) {
            unsigned char pg_probe[] = { 0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f };
            send(s, (const char*)pg_probe, sizeof(pg_probe), 0);
        } else if (port == 6379) {
            string redis_probe = "INFO\r\n";
            send(s, redis_probe.c_str(), redis_probe.length(), 0);
        } else if (port == 27017) {
            unsigned char mongo_probe[] = {
                0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69,
                0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00, 0x00, 0x00, 0x10, 0x69,
                0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
            };
            send(s, (const char*)mongo_probe, sizeof(mongo_probe), 0);
        } else if (port == 25 || port == 587 || port == 465) {
            string smtp_probe = "EHLO hackit.local\r\n";
            send(s, smtp_probe.c_str(), smtp_probe.length(), 0);
        } else if (port == 110 || port == 995) {
            string pop3_probe = "CAPA\r\n";
            send(s, pop3_probe.c_str(), pop3_probe.length(), 0);
        } else if (port == 143 || port == 993) {
            string imap_probe = "A001 CAPABILITY\r\n";
            send(s, imap_probe.c_str(), imap_probe.length(), 0);
        } else if (port == 21 || port == 990) {
            string ftp_probe = "SYST\r\n";
            send(s, ftp_probe.c_str(), ftp_probe.length(), 0);
        }

        char buffer[4096] = {0};
        int bytes = recv(s, buffer, sizeof(buffer) - 1, 0);

        // Try to read more data for TLS (certificate)
        if (bytes > 0 && port == 443 || port == 8443 || port == 2083 || port == 993 || port == 995 || port == 465) {
            char buf2[4096] = {0};
            int n2 = recv(s, buf2, sizeof(buf2) - 1, 0);
            CLOSE_SOCKET(s);
            string combined(buffer, bytes);
            if (n2 > 0) combined += string(buf2, n2);
            return combined;
        }

        CLOSE_SOCKET(s);

        if (bytes > 0) return string(buffer, bytes);
        return "";
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port> [timeout]\n", argv[0]);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    const char* host = argv[1];
    int port = stoi(argv[2]);
    int timeout = (argc > 3) ? stoi(argv[3]) : 1500;

    string banner = ServiceScanner::grab_deep_banner(host, port, timeout);
    string version = ServiceScanner::analyze_banner(port, banner);

    // Clean banner for JSON output
    string clean_banner;
    for (char c : banner) {
        if (c == '\n' || c == '\r') clean_banner += ' ';
        else if (c == '"') clean_banner += '\'';
        else if (c >= 32 && c <= 126) clean_banner += c;
    }

    printf("{\"port\": %d, \"banner\": \"%s\", \"version\": \"%s\"}\n",
           port, clean_banner.c_str(), version.c_str());

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
