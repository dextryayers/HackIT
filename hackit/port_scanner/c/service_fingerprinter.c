#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>

#include "optimize.h"

#define MAX_RESULTS     4096
#define MAX_BANNER      8192
#define MAX_PROBES      32
#define MAX_WORKERS     64
#define MAX_SIGNATURES  256
#define CONFIDENCE_HIGH 0.95
#define CONFIDENCE_MED  0.80
#define CONFIDENCE_LOW  0.60

typedef struct {
    const char* service;
    const char* product;
    const char* version_pattern;
    const char* banner_substring;
    double      confidence;
    int         port;
} ServiceSignature;

static const ServiceSignature SIG_DB[] = {
    {"ssh", "OpenSSH", "OpenSSH_[0-9.]+", "SSH-", 0.95, 22},
    {"ssh", "Dropbear", "dropbear_[0-9.]+", "dropbear", 0.95, 22},
    {"ssh", "libssh", "libssh", "libssh", 0.85, 22},
    {"http", "Apache", "Apache/[0-9.]+", "Apache", 0.95, 80},
    {"http", "Apache", "Apache/[0-9.]+", "Apache", 0.95, 8080},
    {"http", "nginx", "nginx/[0-9.]+", "nginx", 0.95, 80},
    {"http", "nginx", "nginx/[0-9.]+", "nginx", 0.95, 8080},
    {"http", "IIS", "Microsoft-IIS/[0-9.]+", "Microsoft-IIS", 0.95, 80},
    {"http", "IIS", "Microsoft-IIS/[0-9.]+", "Microsoft-IIS", 0.95, 443},
    {"http", "lighttpd", "lighttpd/[0-9.]+", "lighttpd", 0.95, 80},
    {"http", "Caddy", "Caddy", "Caddy", 0.90, 443},
    {"http", "Node.js", "Node.js", "Node.js", 0.85, 3000},
    {"http", "Tomcat", "Apache.*Tomcat", "Tomcat", 0.90, 8080},
    {"http", "Jetty", "Jetty", "Jetty", 0.85, 8080},
    {"http", "Gunicorn", "gunicorn", "gunicorn", 0.85, 8000},
    {"http", "Express", "Express", "Express", 0.80, 3000},
    {"ftp", "vsFTPd", "vsFTPd [0-9.]+", "vsFTPd", 0.95, 21},
    {"ftp", "ProFTPD", "ProFTPD [0-9.]+", "ProFTPD", 0.95, 21},
    {"ftp", "Pure-FTPd", "Pure-FTPd", "Pure-FTPd", 0.95, 21},
    {"ftp", "FileZilla", "FileZilla", "FileZilla", 0.90, 21},
    {"ftp", "OpenBSD FTP", "OpenBSD", "OpenBSD FTP", 0.85, 21},
    {"smtp", "Postfix", "Postfix", "220.*ESMTP Postfix", 0.95, 25},
    {"smtp", "Exim", "Exim [0-9.]+", "Exim", 0.95, 25},
    {"smtp", "Sendmail", "Sendmail [0-9.]+", "Sendmail", 0.95, 25},
    {"smtp", "Courier", "Courier", "Courier", 0.90, 25},
    {"smtp", "Qmail", "qmail", "qmail", 0.90, 25},
    {"smtp", "Microsoft ESMTP", "Microsoft.*ESMTP", "Microsoft ESMTP", 0.90, 25},
    {"pop3", "Dovecot", "Dovecot", "Dovecot", 0.95, 110},
    {"pop3", "Courier", "Courier", "Courier POP", 0.90, 110},
    {"pop3", "Qpopper", "Qpopper", "Qpopper", 0.85, 110},
    {"pop3", "UW IMAP", "UW.*IMAP", "UW IMAP", 0.85, 110},
    {"imap", "Dovecot", "Dovecot", "* OK.*Dovecot", 0.95, 143},
    {"imap", "Courier", "Courier", "* OK.*Courier", 0.90, 143},
    {"imap", "Cyrus", "Cyrus", "* OK.*Cyrus", 0.90, 143},
    {"imap", "UW IMAP", "UW.*IMAP", "* OK.*IMAP", 0.85, 143},
    {"imap", "Exchange", "Exchange", "Microsoft Exchange", 0.85, 143},
    {"mysql", "MySQL", "mysql", "mysql", 0.90, 3306},
    {"mysql", "MySQL", "MariaDB", "MariaDB", 0.85, 3306},
    {"mysql", "Percona", "Percona", "Percona", 0.85, 3306},
    {"postgresql", "PostgreSQL", "PostgreSQL", "PostgreSQL", 0.95, 5432},
    {"postgresql", "PostgreSQL", "PostgreSQL", "N;", 0.85, 5432},
    {"redis", "Redis", "redis", "+OK", 0.90, 6379},
    {"redis", "Redis", "redis", "-NOAUTH", 0.90, 6379},
    {"redis", "Redis", "redis", "-ERR", 0.85, 6379},
    {"mongodb", "MongoDB", "MongoDB", "MongoDB", 0.90, 27017},
    {"mongodb", "MongoDB", "MongoDB", "db", 0.85, 27017},
    {"ssl", "OpenSSL", "OpenSSL", "OpenSSL", 0.85, 443},
    {"ssl", "GnuTLS", "GnuTLS", "GnuTLS", 0.85, 443},
    {"telnet", "Linux Telnet", "Linux", "Linux", 0.80, 23},
    {"telnet", "BSD Telnet", "BSD", "BSD", 0.80, 23},
    {"telnet", "Solaris Telnet", "Solaris", "Solaris", 0.80, 23},
    {"http", "nginx", "nginx/[0-9.]+", "nginx", 0.95, 443},
    {"http", "Apache", "Apache/[0-9.]+", "Apache", 0.95, 443},
    {"ssh", "OpenSSH", "OpenSSH_[0-9.]+", "SSH-", 0.95, 2222},
    {"smtp", "Postfix", "Postfix", "220.*ESMTP Postfix", 0.95, 587},
    {"smtp", "Exim", "Exim [0-9.]+", "Exim", 0.95, 587},
    {"imap", "Dovecot", "Dovecot", "* OK.*Dovecot", 0.95, 993},
    {"imap", "Courier", "Courier", "* OK.*Courier", 0.90, 993},
    {"pop3", "Dovecot", "Dovecot", "+OK.*Dovecot", 0.95, 995},
    {"pop3", "Courier", "Courier", "+OK.*Courier", 0.90, 995},
    {"http", "Apache", "Apache/[0-9.]+", "Apache", 0.95, 8000},
    {"http", "nginx", "nginx/[0-9.]+", "nginx", 0.95, 8000},
    {"http", "Apache", "Apache/[0-9.]+", "Apache", 0.95, 8443},
    {"http", "nginx", "nginx/[0-9.]+", "nginx", 0.95, 8443},
    {"smtp", "Qmail", "qmail", "qmail", 0.90, 465},
    {NULL, NULL, NULL, NULL, 0.0, 0}
};

typedef struct {
    int         port;
    char        service[64];
    char        product[128];
    char        version[64];
    char        banner[MAX_BANNER];
    double      confidence;
    bool        fingerprinted;
} FingerprintResult;

typedef struct {
    uint32_t    target_ip;
    int*        ports;
    int         port_count;
    int         timeout_ms;
    int         thread_count;
    atomic_int  next_idx;
    atomic_int  result_count;
    FingerprintResult results[MAX_RESULTS];
    long long   start_time;
} FingerprintContext;

static const char* get_probe(int port, int* plen) {
    static const struct { int p; const char* probe; int len; } probes[] = {
        {80, "GET / HTTP/1.0\r\nHost: hackit.local\r\nUser-Agent: HackIT-FP/1.0\r\nAccept: */*\r\n\r\n", 0},
        {443, "GET / HTTP/1.0\r\nHost: hackit.local\r\n\r\n", 0},
        {8080, "GET / HTTP/1.0\r\nHost: hackit.local\r\n\r\n", 0},
        {8000, "GET / HTTP/1.0\r\nHost: hackit.local\r\n\r\n", 0},
        {8443, "GET / HTTP/1.0\r\nHost: hackit.local\r\n\r\n", 0},
        {3000, "GET / HTTP/1.0\r\nHost: hackit.local\r\n\r\n", 0},
        {21, "SYST\r\n", 0},
        {25, "EHLO hackit.local\r\n", 0},
        {587, "EHLO hackit.local\r\n", 0},
        {110, "CAPA\r\n", 0},
        {995, "CAPA\r\n", 0},
        {143, "a001 CAPABILITY\r\n", 0},
        {993, "a001 CAPABILITY\r\n", 0},
        {6379, "INFO server\r\n", 0},
        {27017, "", 0},
        {11211, "stats\r\n", 0},
        {22, "", 0},
        {23, "", 0},
        {3306, "", 0},
        {5432, "", 0},
        {0, NULL, 0}
    };
    for (int i = 0; probes[i].probe; i++) {
        if (probes[i].p == port) {
            *plen = probes[i].len ? probes[i].len : (int)strlen(probes[i].probe);
            return probes[i].probe;
        }
    }
    *plen = 0;
    return NULL;
}

HOT static int grab_banner(uint32_t ip, int port, int timeout_ms, char* banner, int banner_size) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (unlikely(sock < 0)) return -1;

    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(sock); return -1; }

    struct epoll_event ev;
    int epfd = epoll_create1(0);
    if (unlikely(epfd < 0)) { close(sock); return -1; }
    ev.data.fd = sock;
    ev.events = EPOLLOUT | EPOLLERR;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);

    struct epoll_event events[1];
    rc = epoll_wait(epfd, events, 1, timeout_ms);
    close(epfd);
    if (rc <= 0) { close(sock); return -1; }

    int so_err = 0;
    socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) { close(sock); return -1; }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);

    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int one = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

    char tmp[MAX_BANNER];
    int total = 0;
    memset(tmp, 0, sizeof(tmp));

    for (int attempt = 0; attempt < 3 && total < MAX_BANNER - 1; attempt++) {
        int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
        if (n > 0) {
            total += n;
        } else {
            if (total == 0 && attempt == 0) {
                int plen = 0;
                const char* probe = get_probe(port, &plen);
                if (probe && plen > 0) {
                    write(sock, probe, plen);
                    usleep(100000);
                    n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
                    if (n > 0) total += n;
                }
            }
            usleep(50000);
        }
    }

    close(sock);

    if (total > 0) {
        tmp[total] = 0;
        int out = 0;
        for (int i = 0; i < total && out < banner_size - 1; i++) {
            char c = tmp[i];
            if (c == '\r') continue;
            if (c == '\n') {
                if (out > 0 && banner[out - 1] != ' ') banner[out++] = ' ';
                continue;
            }
            if (c >= 32 && c < 127) banner[out++] = c;
        }
        banner[out] = 0;
        return out;
    }
    return 0;
}

HOT static int match_signatures(const char* banner, int port, char* service, int svc_sz, char* product, int prod_sz, char* version, int ver_sz, double* confidence) {
    if (!banner || !banner[0]) return 0;

    int best_match = -1;
    double best_conf = 0.0;

    for (int i = 0; SIG_DB[i].service != NULL; i++) {
        if (SIG_DB[i].port != port && SIG_DB[i].port != 0) continue;

        if (strstr(banner, SIG_DB[i].banner_substring) != NULL) {
            if (SIG_DB[i].confidence > best_conf) {
                best_match = i;
                best_conf = SIG_DB[i].confidence;
            }
        }
    }

    if (best_match >= 0) {
        strncpy(service, SIG_DB[best_match].service, svc_sz - 1);
        strncpy(product, SIG_DB[best_match].product, prod_sz - 1);

        const char* vp = SIG_DB[best_match].version_pattern;
        if (vp && vp[0]) {
            const char* start = strstr(banner, vp);
            if (!start) {
                const char* slash = strchr(SIG_DB[best_match].banner_substring, '/');
                if (slash) {
                    const char* vs = strstr(banner, slash);
                    if (vs) {
                        vs++;
                        int vi = 0;
                        while (vs[vi] && vs[vi] > ' ' && vi < ver_sz - 1)
                            version[vi++] = vs[vi];
                        version[vi] = 0;
                    }
                }
            }
            if (!version[0]) {
                const char* vstart = strstr(banner, SIG_DB[best_match].banner_substring);
                if (vstart) {
                    vstart += strlen(SIG_DB[best_match].banner_substring);
                    while (*vstart == ' ' || *vstart == '/') vstart++;
                    int vi = 0;
                    while (vstart[vi] && vstart[vi] > ' ' && vstart[vi] != ',' && vi < ver_sz - 1)
                        version[vi++] = vstart[vi];
                    version[vi] = 0;
                }
            }
        }
        *confidence = best_conf;
        return 1;
    }

    return 0;
}

HOT static void* fingerprint_worker(void* arg) {
    FingerprintContext* ctx = (FingerprintContext*)arg;

    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;

        int port = ctx->ports[idx];
        char banner[MAX_BANNER] = {0};
        int blen = grab_banner(ctx->target_ip, port, ctx->timeout_ms, banner, sizeof(banner));
        if (blen < 0) continue;

        int ri = atomic_fetch_add(&ctx->result_count, 1);
        if (ri >= MAX_RESULTS) break;

        FingerprintResult* r = &ctx->results[ri];
        memset(r, 0, sizeof(FingerprintResult));
        r->port = port;
        strncpy(r->banner, banner, sizeof(r->banner) - 1);

        int matched = match_signatures(banner, port, r->service, sizeof(r->service),
            r->product, sizeof(r->product), r->version, sizeof(r->version), &r->confidence);

        if (matched) r->fingerprinted = true;
        if (r->confidence == 0.0) r->confidence = CONFIDENCE_LOW;
    }
    return NULL;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <target> <port1,port2,...> [timeout_ms] [threads]\n", prog);
    fprintf(stderr, "  target      - IP or hostname\n");
    fprintf(stderr, "  ports       - comma separated list or range (e.g. 22,80,443 or 1-1000)\n");
    fprintf(stderr, "  timeout_ms  - per-port timeout (default: 3000)\n");
    fprintf(stderr, "  threads     - worker threads (default: 4)\n");
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int parse_ports(const char* spec, int** ports_out) {
    static int ports[65536];
    int count = 0;
    if (!spec) return 0;
    if (strcmp(spec, "all") == 0) {
        for (int p = 1; p <= 65535 && count < 65536; p++) ports[count++] = p;
        *ports_out = ports;
        return count;
    }
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char* t = strtok(buf, ",");
    while (t && count < 65536) {
        char* d = strchr(t, '-');
        if (d) {
            int s = atoi(t), e = atoi(d + 1);
            if (s < 1) s = 1;
            if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < 65536; p++) ports[count++] = p;
        } else {
            int p = atoi(t);
            if (p >= 1 && p <= 65535) ports[count++] = p;
        }
        t = strtok(NULL, ",");
    }
    *ports_out = ports;
    return count;
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    uint32_t target = resolve_ip(argv[1]);
    if (unlikely(target == 0)) {
        fprintf(stderr, "Failed to resolve: %s\n", argv[1]);
        return 1;
    }

    int* ports = NULL;
    int port_count = parse_ports(argv[2], &ports);
    if (port_count <= 0) {
        fprintf(stderr, "No valid ports\n");
        return 1;
    }

    int timeout_ms = argc > 3 ? atoi(argv[3]) : 3000;
    int threads = argc > 4 ? atoi(argv[4]) : 4;
    if (threads < 1) threads = 1;
    if (threads > MAX_WORKERS) threads = MAX_WORKERS;

    FingerprintContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_ip = target;
    ctx.ports = ports;
    ctx.port_count = port_count;
    ctx.timeout_ms = timeout_ms;
    ctx.thread_count = threads;
    ctx.start_time = now_ms();

    struct in_addr ia;
    ia.s_addr = target;
    fprintf(stderr, "SERVICE_FP target=%s ports=%d timeout=%dms threads=%d\n",
        inet_ntoa(ia), port_count, timeout_ms, threads);

    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < threads; i++)
        pthread_create(&workers[i], NULL, fingerprint_worker, &ctx);
    for (int i = 0; i < threads; i++)
        pthread_join(workers[i], NULL);

    long long elapsed = now_ms() - ctx.start_time;
    int fingerprinted = 0;

    for (int i = 0; i < ctx.result_count; i++) {
        FingerprintResult* r = &ctx.results[i];
        if (r->fingerprinted || r->banner[0]) {
            printf("{\"port\":%d,\"service\":\"%s\",\"product\":\"%s\",\"version\":\"%s\",\"confidence\":%.2f,\"banner\":\"%s\"}\n",
                r->port, r->service[0] ? r->service : "unknown",
                r->product[0] ? r->product : "",
                r->version[0] ? r->version : "",
                r->confidence,
                r->banner);
            if (r->fingerprinted) fingerprinted++;
        }
    }

    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"ports_scanned\":%d,\"fingerprinted\":%d,\"total_results\":%d,\"elapsed_ms\":%lld}\n",
        inet_ntoa(ia), port_count, fingerprinted, ctx.result_count, elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
