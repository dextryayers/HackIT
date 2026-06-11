#include "banner_grabber.h"
#include "tcp_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#endif

static int connect_and_send(const char* host, int port, int timeout_ms,
                            const char* send_data, int send_len,
                            char* response, int response_size) {
    if (!host || !response || response_size <= 0) return -1;

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return -1;
#else
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);

    struct hostent* he = gethostbyname(host);
    if (he) {
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        addr.sin_addr.s_addr = inet_addr(host);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd);
#endif
            return -1;
        }
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc != 0) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(fd);
            return -1;
        }
#else
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
#endif
        fd_set wset;
        struct timeval tv;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select((int)(fd + 1), NULL, &wset, NULL, &tv);
        if (rc <= 0) {
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd);
#endif
            return -1;
        }
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd);
#endif
            return -1;
        }
    }

#ifdef _WIN32
    mode = 0;
    ioctlsocket(fd, FIONBIO, &mode);
#else
    fcntl(fd, F_SETFL, flags);
#endif

    if (send_data && send_len > 0) {
        send(fd, send_data, send_len, 0);
    }

    int total = 0;
    while (total < response_size - 1) {
        fd_set rset;
        struct timeval tv;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        rc = select((int)(fd + 1), &rset, NULL, NULL, &tv);
        if (rc <= 0) break;
        int n = recv(fd, response + total, response_size - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    response[total] = '\0';

#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return total;
}

int hackit_grab_banner_tcp(const char* host, int port, int timeout_ms,
                           char* banner, int banner_size) {
    if (!host || !banner || banner_size <= 0) return -1;

    const char* probe = NULL;
    char probe_buf[128];
    int probe_len = 0;

    switch (port) {
        case 80:
        case 8080:
        case 8000:
        case 8888:
        case 8008:
            probe = hackit_get_http_probe();
            probe_len = (int)strlen(probe);
            {
                char http_req[512];
                snprintf(http_req, sizeof(http_req), probe, host);
                return connect_and_send(host, port, timeout_ms, http_req, (int)strlen(http_req), banner, banner_size);
            }
        case 443:
        case 993:
        case 995:
        case 8443:
            return connect_and_send(host, port, timeout_ms, NULL, 0, banner, banner_size);
        case 21:
        case 22:
        case 23:
        case 25:
        case 110:
        case 143:
            return connect_and_send(host, port, timeout_ms, NULL, 0, banner, banner_size);
        case 6379:
            probe = hackit_get_redis_probe();
            probe_len = (int)strlen(probe);
            return connect_and_send(host, port, timeout_ms, probe, probe_len, banner, banner_size);
        case 3306:
            return connect_and_send(host, port, timeout_ms, NULL, 0, banner, banner_size);
        case 5432:
            return connect_and_send(host, port, timeout_ms, NULL, 0, banner, banner_size);
        case 27017:
            return connect_and_send(host, port, timeout_ms, NULL, 0, banner, banner_size);
        default:
            snprintf(probe_buf, sizeof(probe_buf), hackit_get_http_probe(), host);
            return connect_and_send(host, port, timeout_ms, probe_buf, (int)strlen(probe_buf), banner, banner_size);
    }
}

int hackit_probe_service(const char* host, int port, int timeout_ms,
                         const char* probe_data, int probe_len,
                         char* response, int response_size) {
    return connect_and_send(host, port, timeout_ms, probe_data, probe_len, response, response_size);
}

static void extract_version_str(const char* src, const char* prefix, char* version, int version_size) {
    if (!src || !prefix || !version || version_size <= 0) return;
    const char* p = strstr(src, prefix);
    if (!p) return;
    p += strlen(prefix);
    int i = 0;
    while (*p && i < version_size - 1 && (isdigit((unsigned char)*p) || *p == '.' || *p == '-' || *p == '_' || *p == 'p' || *p == 'P')) {
        if (*p == '_') version[i++] = '.';
        else version[i++] = *p;
        p++;
    }
    version[i] = '\0';
}

void hackit_detect_version_from_banner(const char* service, const char* banner,
                                       char* product, int product_size,
                                       char* version, int version_size,
                                       char* os_hint, int os_hint_size) {
    if (!banner || !product || product_size <= 0) return;
    if (version && version_size > 0) version[0] = '\0';
    if (os_hint && os_hint_size > 0) os_hint[0] = '\0';

    product[0] = '\0';
    if (service) {
        strncpy(product, service, product_size - 1);
        product[product_size - 1] = '\0';
    }

    if (strstr(banner, "OpenSSH")) {
        snprintf(product, product_size, "OpenSSH");
        if (version && version_size > 0) extract_version_str(banner, "OpenSSH_", version, version_size);
        if (strstr(banner, "Ubuntu") && os_hint && os_hint_size > 0) strncpy(os_hint, "Ubuntu", os_hint_size - 1);
        else if (strstr(banner, "Debian") && os_hint && os_hint_size > 0) strncpy(os_hint, "Debian", os_hint_size - 1);
        else if (strstr(banner, "FreeBSD") && os_hint && os_hint_size > 0) strncpy(os_hint, "FreeBSD", os_hint_size - 1);
        return;
    }

    if (strstr(banner, "nginx/")) {
        snprintf(product, product_size, "nginx");
        if (version && version_size > 0) extract_version_str(banner, "nginx/", version, version_size);
        return;
    }

    if (strstr(banner, "Apache")) {
        snprintf(product, product_size, "Apache httpd");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "Apache");
            if (v) {
                v += 6;
                while (*v && !isdigit((unsigned char)*v)) v++;
                if (*v) {
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        if (strstr(banner, "Ubuntu") && os_hint && os_hint_size > 0) strncpy(os_hint, "Ubuntu", os_hint_size - 1);
        else if (strstr(banner, "Debian") && os_hint && os_hint_size > 0) strncpy(os_hint, "Debian", os_hint_size - 1);
        else if (strstr(banner, "CentOS") && os_hint && os_hint_size > 0) strncpy(os_hint, "CentOS", os_hint_size - 1);
        else if (strstr(banner, "Red Hat") && os_hint && os_hint_size > 0) strncpy(os_hint, "Red Hat", os_hint_size - 1);
        else if (strstr(banner, "Win") && os_hint && os_hint_size > 0) strncpy(os_hint, "Windows", os_hint_size - 1);
        return;
    }

    if (strstr(banner, "IIS")) {
        snprintf(product, product_size, "Microsoft IIS");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "IIS");
            if (v) {
                v += 3;
                while (*v && !isdigit((unsigned char)*v)) v++;
                if (*v) {
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        if (os_hint && os_hint_size > 0) strncpy(os_hint, "Windows", os_hint_size - 1);
        return;
    }

    if (strstr(banner, "vsFTPd")) {
        snprintf(product, product_size, "vsFTPd");
        if (version && version_size > 0) extract_version_str(banner, "vsFTPd ", version, version_size);
        if (os_hint && os_hint_size > 0) {
            if (strstr(banner, "Ubuntu")) strncpy(os_hint, "Ubuntu", os_hint_size - 1);
            else if (strstr(banner, "Debian")) strncpy(os_hint, "Debian", os_hint_size - 1);
            else if (strstr(banner, "CentOS")) strncpy(os_hint, "CentOS", os_hint_size - 1);
            else if (strstr(banner, "Fedora")) strncpy(os_hint, "Fedora", os_hint_size - 1);
        }
        return;
    }

    if (strstr(banner, "ProFTPD")) {
        snprintf(product, product_size, "ProFTPD");
        if (version && version_size > 0) extract_version_str(banner, "ProFTPD ", version, version_size);
        return;
    }

    if (strstr(banner, "MySQL") || strstr(banner, "mysql")) {
        if (strstr(banner, "MariaDB")) {
            snprintf(product, product_size, "MariaDB");
        } else {
            snprintf(product, product_size, "MySQL");
        }
        if (version && version_size > 0) {
            const char* v = strstr(banner, "MySQL");
            if (!v) v = strstr(banner, "mysql");
            if (v) {
                while (*v && !isdigit((unsigned char)*v)) v++;
                if (*v) {
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.' || v[i] == '-')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        return;
    }

    if (strstr(banner, "Postfix")) {
        snprintf(product, product_size, "Postfix");
        if (version && version_size > 0) extract_version_str(banner, "Postfix ", version, version_size);
        return;
    }

    if (strstr(banner, "Redis") || strstr(banner, "redis")) {
        snprintf(product, product_size, "Redis");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "redis_version:");
            if (!v) v = strstr(banner, "Redis ");
            if (!v) v = strstr(banner, "redis ");
            if (v) {
                v = strchr(v, ' ');
                if (v) {
                    v++;
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        return;
    }

    if (strstr(banner, "MongoDB") || strstr(banner, "mongodb")) {
        snprintf(product, product_size, "MongoDB");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "MongoDB ");
            if (!v) v = strstr(banner, "mongodb ");
            if (v) {
                v = strchr(v, ' ');
                if (v) {
                    v++;
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        return;
    }

    if (strstr(banner, "Pure-FTPd")) {
        snprintf(product, product_size, "Pure-FTPd");
        if (version && version_size > 0) extract_version_str(banner, "Pure-FTPd ", version, version_size);
        return;
    }

    if (strstr(banner, "FileZilla")) {
        snprintf(product, product_size, "FileZilla Server");
        if (version && version_size > 0) extract_version_str(banner, "FileZilla Server ", version, version_size);
        return;
    }

    if (strstr(banner, "lighttpd")) {
        snprintf(product, product_size, "lighttpd");
        if (version && version_size > 0) extract_version_str(banner, "lighttpd/", version, version_size);
        return;
    }

    if (strstr(banner, "Tomcat")) {
        snprintf(product, product_size, "Apache Tomcat");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "Tomcat");
            v = strchr(v, '/');
            if (v) {
                v++;
                int i = 0;
                while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                    version[i] = v[i];
                    i++;
                }
                version[i] = '\0';
            }
        }
        return;
    }

    if (strstr(banner, "PostgreSQL") || strstr(banner, "postgres")) {
        snprintf(product, product_size, "PostgreSQL");
        if (version && version_size > 0) {
            const char* v = strstr(banner, "PostgreSQL ");
            if (!v) v = strstr(banner, "postgres ");
            if (v) {
                v = strchr(v, ' ');
                if (v) {
                    v++;
                    int i = 0;
                    while (v[i] && i < version_size - 1 && (isdigit((unsigned char)v[i]) || v[i] == '.')) {
                        version[i] = v[i];
                        i++;
                    }
                    version[i] = '\0';
                }
            }
        }
        return;
    }

    if (strstr(banner, "OpenSSL")) {
        snprintf(product, product_size, "OpenSSL");
        if (version && version_size > 0) extract_version_str(banner, "OpenSSL ", version, version_size);
        return;
    }

    if (strstr(banner, "OpenSSH") || strstr(banner, "ssh")) {
        if (strstr(banner, "Dropbear")) {
            snprintf(product, product_size, "Dropbear SSH");
            if (version && version_size > 0) extract_version_str(banner, "Dropbear ", version, version_size);
        }
        return;
    }

    if (strstr(banner, "Dropbear")) {
        snprintf(product, product_size, "Dropbear");
        if (version && version_size > 0) extract_version_str(banner, "Dropbear ", version, version_size);
        return;
    }

    if (strstr(banner, "Courier-IMAP")) {
        snprintf(product, product_size, "Courier-IMAP");
        if (version && version_size > 0) extract_version_str(banner, "Courier-IMAP ", version, version_size);
        return;
    }

    if (strstr(banner, "Dovecot")) {
        snprintf(product, product_size, "Dovecot");
        if (version && version_size > 0) extract_version_str(banner, "Dovecot ", version, version_size);
        return;
    }

    if (strstr(banner, "Exim")) {
        snprintf(product, product_size, "Exim");
        if (version && version_size > 0) extract_version_str(banner, "Exim ", version, version_size);
        return;
    }

    if (strstr(banner, "Sendmail")) {
        snprintf(product, product_size, "Sendmail");
        if (version && version_size > 0) extract_version_str(banner, "Sendmail ", version, version_size);
        return;
    }

    if (strstr(banner, "Microsoft ESMTP")) {
        snprintf(product, product_size, "Microsoft Exchange");
        if (os_hint && os_hint_size > 0) strncpy(os_hint, "Windows", os_hint_size - 1);
        return;
    }

    if (strstr(banner, "qmail")) {
        snprintf(product, product_size, "qmail");
        return;
    }

    if (strstr(banner, "NetBSD") && os_hint && os_hint_size > 0) {
        strncpy(os_hint, "NetBSD", os_hint_size - 1);
    }

    if (strstr(banner, "OpenBSD") && os_hint && os_hint_size > 0) {
        strncpy(os_hint, "OpenBSD", os_hint_size - 1);
    }

    if (strstr(banner, "ESXi") && os_hint && os_hint_size > 0) {
        strncpy(os_hint, "VMware ESXi", os_hint_size - 1);
    }

    if (product[0] == '\0') {
        const char* known_products[] = {
            "SSH-", "HTTP/", "SMTP", "FTP", "POP3", "IMAP", "Banner:",
            "220 ", " greeting", "Welcome", "ready", "Escape"
        };
        for (int i = 0; i < (int)(sizeof(known_products) / sizeof(known_products[0])); i++) {
            if (strstr(banner, known_products[i])) {
                snprintf(product, product_size, "Unknown (%s)", known_products[i]);
                break;
            }
        }
    }
}

const char* hackit_get_http_probe(void) {
    static const char probe[] = "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 HackIT\r\n\r\n";
    return probe;
}

const char* hackit_get_redis_probe(void) {
    static const char probe[] = "*1\r\n$4\r\nPING\r\n";
    return probe;
}
