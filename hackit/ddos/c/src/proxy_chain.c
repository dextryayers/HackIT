#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAX_PROXIES 1024
#define MAX_PROXY_LINE 128
#define PROXY_BUF_SIZE 4096

struct proxy_entry {
    char host[64];
    int port;
    int fd;
    int in_use;
};

static struct proxy_entry g_proxies[MAX_PROXIES];
static int g_proxy_count = 0;
static int g_proxy_current = 0;
static char g_proxy_err[256] = {0};

static int socks5_handshake(int fd, const char *target_host, int target_port)
{
    unsigned char buf[PROXY_BUF_SIZE];

    buf[0] = 0x05;
    buf[1] = 0x01;
    buf[2] = 0x00;

    if (write(fd, buf, 3) != 3) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks5 write auth: %s", strerror(errno));
        return -1;
    }

    int n = (int)read(fd, buf, 2);
    if (n != 2 || buf[0] != 0x05 || buf[1] != 0x00) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks5 auth response failed");
        return -1;
    }

    int off = 0;
    buf[off++] = 0x05;
    buf[off++] = 0x01;
    buf[off++] = 0x00;
    buf[off++] = 0x03;

    size_t hostlen = strlen(target_host);
    if (hostlen > 255) hostlen = 255;
    buf[off++] = (unsigned char)hostlen;
    memcpy(buf + off, target_host, hostlen);
    off += (int)hostlen;
    buf[off++] = (unsigned char)(target_port >> 8);
    buf[off++] = (unsigned char)(target_port & 0xFF);

    if (write(fd, buf, (size_t)off) != off) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks5 write connect: %s", strerror(errno));
        return -1;
    }

    n = (int)read(fd, buf, 10);
    if (n < 10 || buf[0] != 0x05 || buf[1] != 0x00) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks5 connect failed (code %d)", n > 1 ? buf[1] : -1);
        return -1;
    }

    return 0;
}

static int socks4_connect(int fd, const char *target_host, int target_port)
{
    unsigned char buf[PROXY_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    buf[0] = 0x04;
    buf[1] = 0x01;
    buf[2] = (unsigned char)(target_port >> 8);
    buf[3] = (unsigned char)(target_port & 0xFF);

    struct in_addr addr;
    if (inet_aton(target_host, &addr) == 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks4 requires IP, not hostname");
        return -1;
    }
    memcpy(buf + 4, &addr.s_addr, 4);

    strcpy((char *)buf + 8, "");
    int req_len = 8 + 1;

    if (write(fd, buf, (size_t)req_len) != req_len) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks4 write: %s", strerror(errno));
        return -1;
    }

    int n = (int)read(fd, buf, 8);
    if (n < 8 || buf[1] != 0x5A) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socks4 connect rejected (code %d)", n > 1 ? buf[1] : -1);
        return -1;
    }

    return 0;
}

EXPORT int proxy_chain_init(const char *proxy_list_file)
{
    if (!proxy_list_file) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "proxy list file required");
        return -1;
    }

    FILE *f = fopen(proxy_list_file, "r");
    if (!f) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "cannot open %s: %s", proxy_list_file, strerror(errno));
        return -1;
    }

    g_proxy_count = 0;
    memset(g_proxies, 0, sizeof(g_proxies));

    char line[MAX_PROXY_LINE];
    while (fgets(line, sizeof(line), f) && g_proxy_count < MAX_PROXIES) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';
        if (line[0] == '\0' || line[0] == '#') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *host = line;
        int port = atoi(colon + 1);
        if (port <= 0 || port > 65535) continue;

        strncpy(g_proxies[g_proxy_count].host, host, sizeof(g_proxies[g_proxy_count].host) - 1);
        g_proxies[g_proxy_count].port = port;
        g_proxies[g_proxy_count].fd = -1;
        g_proxies[g_proxy_count].in_use = 0;
        g_proxy_count++;
    }

    fclose(f);
    g_proxy_current = 0;
    return g_proxy_count;
}

EXPORT int proxy_connect(int proxy_idx, const char *target_host, int target_port)
{
    if (proxy_idx < 0 || proxy_idx >= g_proxy_count) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "invalid proxy index");
        return -1;
    }
    if (!target_host || target_port <= 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "invalid target");
        return -1;
    }

    struct proxy_entry *p = &g_proxies[proxy_idx];
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }

    p->fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (p->fd < 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(p->host);
    if (sin.sin_addr.s_addr == INADDR_NONE) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(p->host, NULL, &hints, &res) != 0) {
            close(p->fd); p->fd = -1;
            snprintf(g_proxy_err, sizeof(g_proxy_err), "cannot resolve %s", p->host);
            return -1;
        }
        sin.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    sin.sin_port = htons((uint16_t)p->port);

    struct timeval tv;
    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(p->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(p->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(p->fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "connect to proxy %s:%d: %s", p->host, p->port, strerror(errno));
        close(p->fd); p->fd = -1;
        return -1;
    }

    if (socks5_handshake(p->fd, target_host, target_port) < 0) {
        if (socks4_connect(p->fd, target_host, target_port) < 0) {
            close(p->fd); p->fd = -1;
            return -1;
        }
    }

    p->in_use = 1;
    return p->fd;
}

EXPORT int proxy_send(int proxy_fd, const unsigned char *data, int len)
{
    if (proxy_fd < 0 || !data || len <= 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "invalid arguments");
        return -1;
    }
    int total = 0;
    while (total < len) {
        int n = (int)write(proxy_fd, data + total, (size_t)(len - total));
        if (n <= 0) {
            snprintf(g_proxy_err, sizeof(g_proxy_err), "proxy_send: %s", strerror(errno));
            return total > 0 ? total : -1;
        }
        total += n;
    }
    return total;
}

EXPORT int proxy_recv(int proxy_fd, unsigned char *buf, int max_len)
{
    if (proxy_fd < 0 || !buf || max_len <= 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "invalid arguments");
        return -1;
    }
    int n = (int)read(proxy_fd, buf, (size_t)max_len);
    if (n < 0) {
        snprintf(g_proxy_err, sizeof(g_proxy_err), "proxy_recv: %s", strerror(errno));
        return -1;
    }
    return n;
}

EXPORT int proxy_next(void)
{
    if (g_proxy_count <= 0) return -1;
    g_proxy_current = (g_proxy_current + 1) % g_proxy_count;
    return g_proxy_current;
}

EXPORT int proxy_count(void)
{
    return g_proxy_count;
}

EXPORT void proxy_cleanup(void)
{
    for (int i = 0; i < g_proxy_count; i++) {
        if (g_proxies[i].fd >= 0) {
            close(g_proxies[i].fd);
            g_proxies[i].fd = -1;
        }
        g_proxies[i].in_use = 0;
    }
    g_proxy_count = 0;
    g_proxy_current = 0;
}
