/*
 * banner_grabber.c - Deep banner extraction with TLS/SSL and 80+ protocol probes
 * Compile: gcc -O3 -o ../bin/banner_grabber banner_grabber.c -lpthread -lssl -lcrypto
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "optimize.h"

#define MAX_PORTS    65536
#define MAX_WORKERS  64
#define BANNER_SIZE  32768

typedef struct {
    int port;
    const char* probe;
    int plen;
    const char* service;
    bool use_tls;
} GrabDef;

static const GrabDef GRABS[] = {
    {80,   "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Banner/1.0\r\nAccept: */*\r\n\r\n", 77, "HTTP", false},
    {8080, "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Banner/1.0\r\nAccept: */*\r\n\r\n", 77, "HTTP", false},
    {8000, "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Banner/1.0\r\nAccept: */*\r\n\r\n", 77, "HTTP", false},
    {8888, "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Banner/1.0\r\nAccept: */*\r\n\r\n", 77, "HTTP", false},
    {8008, "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-Banner/1.0\r\nAccept: */*\r\n\r\n", 77, "HTTP", false},
    {3000, "GET / HTTP/1.0\r\nHost: hackit\r\n\r\n", 33, "HTTP-Alt", false},
    {5000, "GET / HTTP/1.0\r\nHost: hackit\r\n\r\n", 33, "HTTP-Alt", false},
    {443,  "", 0, "HTTPS", true},
    {8443, "", 0, "HTTPS-Alt", true},
    {22,   "", 0, "SSH", false},
    {21,   "SYST\r\n", 6, "FTP", false},
    {25,   "EHLO hackit\r\n", 14, "SMTP", false},
    {587,  "EHLO hackit\r\n", 14, "SMTP-Submit", false},
    {465,  "EHLO hackit\r\n", 14, "SMTPS", true},
    {110,  "CAPA\r\n", 6, "POP3", false},
    {995,  "CAPA\r\n", 6, "POP3S", true},
    {143,  "A001 CAPABILITY\r\n", 18, "IMAP", false},
    {993,  "A001 CAPABILITY\r\n", 18, "IMAPS", true},
    {3306, "", 0, "MySQL", false},
    {5432, "\x00\x00\x00\x08\x04\xd2\x16\x2f", 8, "PostgreSQL", false},
    {6379, "PING\r\n", 6, "Redis", false},
    {11211,"stats\r\n", 7, "Memcached", false},
    {27017,"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", 59, "MongoDB", false},
    {27018,"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00", 59, "MongoDB", false},
    {5900, "", 0, "VNC", false},
    {5901, "", 0, "VNC-1", false},
    {3389, "", 0, "RDP", false},
    {389,  "", 0, "LDAP", false},
    {636,  "", 0, "LDAPS", true},
    {445,  "", 0, "SMB", false},
    {139,  "", 0, "NetBIOS", false},
    {135,  "", 0, "MSRPC", false},
    {1433, "", 0, "MSSQL", false},
    {1521, "", 0, "Oracle", false},
    {119,  "CAPABILITIES\r\n", 14, "NNTP", false},
    {563,  "CAPABILITIES\r\n", 14, "NNTPS", true},
    {873,  "", 0, "Rsync", false},
    {2082, "HEAD / HTTP/1.0\r\n\r\n", 20, "cPanel", false},
    {2083, "HEAD / HTTP/1.0\r\n\r\n", 20, "cPanel-SSL", true},
    {2086, "HEAD / HTTP/1.0\r\n\r\n", 20, "WHM", false},
    {2087, "HEAD / HTTP/1.0\r\n\r\n", 20, "WHM-SSL", true},
    {2096, "HEAD / HTTP/1.0\r\n\r\n", 20, "Webmail", false},
    {9090, "", 0, "WebSM", false},
    {9200, "", 0, "Elasticsearch", false},
    {9300, "", 0, "Elasticsearch-Transport", false},
    {5672, "", 0, "AMQP", false},
    {1883, "", 0, "MQTT", false},
    {8883, "", 0, "MQTT-TLS", true},
    {1935, "", 0, "RTMP", false},
    {554,  "", 0, "RTSP", false},
    {179,  "", 0, "BGP", false},
    {194,  "", 0, "IRC", false},
    {6667, "", 0, "IRC", false},
    {6697, "", 0, "IRC-SSL", true},
    {5060, "", 0, "SIP", false},
    {5061, "", 0, "SIP-TLS", true},
    {1194, "", 0, "OpenVPN", false},
    {1723, "", 0, "PPTP", false},
    {1701, "", 0, "L2TP", false},
    {2049, "", 0, "NFS", false},
    {111,  "", 0, "RPCBind", false},
    {631,  "", 0, "IPP", false},
    {9100, "", 0, "JetDirect", false},
    {6000, "", 0, "X11", false},
    {5984, "", 0, "CouchDB", false},
    {5985, "", 0, "WinRM-HTTP", false},
    {5986, "", 0, "WinRM-HTTPS", true},
    {2375, "", 0, "Docker", false},
    {2376, "", 0, "Docker-TLS", true},
    {6443, "", 0, "K8s-API", true},
    {10250,"", 0, "Kubelet", true},
    {8161, "", 0, "ActiveMQ", false},
    {3307, "", 0, "MySQL-Alt", false},
    {3323, "", 0, "MySQL-Alt", false},
    {5433, "", 0, "PostgreSQL-Alt", false},
    {6380, "PING\r\n", 6, "Redis-TLS", true},
    {11222,"stats\r\n", 7, "Memcached-Alt", false},
    {12345,"", 0, "NetBus", false},
    {31337,"", 0, "BackOrifice", false},
    {27374,"", 0, "SubSeven", false},
    {0, NULL, 0, NULL, false}
};

typedef struct {
    char      target[256];
    uint32_t  target_ip;
    int       ports[MAX_PORTS];
    int       port_count;
    int       timeout_ms;
    int       workers;
    atomic_int next_idx;
    long long start_time;
} GrabContext;

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static HOT uint32_t resolve_ip(const char* RESTRICT host) {
    struct in_addr addr;
    if (likely(inet_pton(AF_INET, host, &addr) == 1)) return addr.s_addr;
    struct hostent* he = gethostbyname(host);
    if (unlikely(!he || !he->h_addr_list[0])) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static FLATTEN void sanitize_banner(const char* RESTRICT raw, int raw_len, char* RESTRICT out, int out_sz) {
    int o = 0;
    int i;
    for (i = 0; i < raw_len && o < out_sz - 1; ++i) {
        char c = raw[i];
        if (c == '\r') continue;
        if (c == '\n') { if (o > 0 && out[o - 1] != ' ') out[o++] = ' '; continue; }
        if (c >= 32 && c < 127) out[o++] = c;
    }
    out[o] = 0;
}

static HOT int do_tls_handshake(int sock, int timeout_ms, char* RESTRICT banner, int bs, char* RESTRICT cert_cn, int ccn_sz) {
    int ret, err, blen, n;
    long long deadline;
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;
    const char* tls_ver;
    const char* cipher;
    X509* cert;
    struct timeval tv;
    struct pollfd pf;

    ctx = SSL_CTX_new(TLS_client_method());
    if (unlikely(!ctx)) return 0;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    ssl = SSL_new(ctx);
    if (unlikely(!ssl)) { SSL_CTX_free(ctx); return 0; }
    SSL_set_fd(ssl, sock);
    SSL_set_connect_state(ssl);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    bio = SSL_get_rbio(ssl);
    if (bio) BIO_set_nbio(bio, 0);
    deadline = now_ms() + timeout_ms;
    while ((ret = SSL_connect(ssl)) <= 0) {
        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (unlikely(now_ms() > deadline)) break;
            pf.fd = sock;
            pf.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            poll(&pf, 1, 10);
            continue;
        }
        break;
    }
    if (unlikely(ret <= 0)) { SSL_free(ssl); SSL_CTX_free(ctx); return 0; }
    tls_ver = SSL_get_version(ssl);
    if (tls_ver && banner) {
        blen = (int)strlen(banner);
        snprintf(banner + blen, bs - blen, " TLS=%s", tls_ver);
    }
    cipher = SSL_get_cipher(ssl);
    if (cipher && banner) {
        blen = (int)strlen(banner);
        snprintf(banner + blen, bs - blen, " Cipher=%s", cipher);
    }
    cert = SSL_get_peer_certificate(ssl);
    if (likely(cert)) {
        char subject[256];
        char issuer[256];
        int pos;
        X509_NAME* name;
        ASN1_STRING* data;
        const char* cn;
        memset(subject, 0, sizeof(subject));
        memset(issuer, 0, sizeof(issuer));
        X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
        X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
        if (cert_cn) {
            name = X509_get_subject_name(cert);
            pos = -1;
            for (;;) {
                pos = X509_NAME_get_index_by_NID(name, NID_commonName, pos);
                if (pos < 0) break;
                data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, pos));
                if (data) {
                    cn = (const char*)ASN1_STRING_get0_data(data);
                    if (cn) { strncpy(cert_cn, cn, ccn_sz - 1); break; }
                }
            }
        }
        if (banner) {
            blen = (int)strlen(banner);
            snprintf(banner + blen, bs - blen, " Subject=%s Issuer=%s", subject, issuer);
        }
        X509_free(cert);
    }
    if (banner) {
        blen = (int)strlen(banner);
        SSL_read(ssl, banner + blen, bs - blen - 1);
        while ((n = SSL_read(ssl, banner + (int)strlen(banner), bs - (int)strlen(banner) - 1)) > 0);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
}

#define CONN_CACHE_SIZE 32
typedef struct { uint32_t ip; int port; int fd; long long last_used; } ConnCacheEntry;
static ConnCacheEntry conn_cache[CONN_CACHE_SIZE] = {{0}};

static int cache_get(uint32_t ip, int port) {
    int i;
    for (i = 0; i < CONN_CACHE_SIZE; ++i)
        if (likely(conn_cache[i].fd >= 0) && conn_cache[i].ip == ip && conn_cache[i].port == port)
            { conn_cache[i].last_used = now_ms(); return conn_cache[i].fd; }
    return -1;
}

static void cache_put(uint32_t ip, int port, int fd) {
    int i;
    int oldest;
    for (i = 0; i < CONN_CACHE_SIZE; ++i) {
        if (unlikely(conn_cache[i].fd < 0)) {
            conn_cache[i].ip = ip; conn_cache[i].port = port; conn_cache[i].fd = fd; conn_cache[i].last_used = now_ms();
            return;
        }
    }
    oldest = 0;
    for (i = 1; i < CONN_CACHE_SIZE; i++)
        if (conn_cache[i].last_used < conn_cache[oldest].last_used) oldest = i;
    close(conn_cache[oldest].fd);
    conn_cache[oldest].ip = ip; conn_cache[oldest].port = port; conn_cache[oldest].fd = fd; conn_cache[oldest].last_used = now_ms();
}

static HOT int grab_banner(uint32_t ip, int port, int timeout_ms, char* RESTRICT banner, int bs, bool use_tls, char* RESTRICT cert_cn, int ccn_sz) {
    struct sockaddr_in addr;
    int cached, sock, one, epfd, so_err, flags, i, n, total, plen;
    struct epoll_event ev, events[1];
    socklen_t el;
    struct timeval tv;
    struct pollfd pfd;
    const char* probe;
    char tmp[16384];
    int rc;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    cached = cache_get(ip, port);
    sock = cached;
    if (unlikely(sock < 0)) {
        sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (unlikely(sock < 0)) return 2;
        one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
        epfd = epoll_create1(0);
        if (unlikely(epfd < 0)) { close(sock); return 2; }
        ev.data.fd = sock;
        ev.events = EPOLLOUT | EPOLLERR;
        epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        rc = epoll_wait(epfd, events, 1, timeout_ms);
        close(epfd);
        if (unlikely(rc <= 0)) { close(sock); return rc == 0 ? 2 : 0; }
        so_err = 0;
        el = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
        if (unlikely(so_err != 0)) { close(sock); return so_err == ECONNREFUSED ? 0 : 2; }
        flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    if (use_tls) {
        do_tls_handshake(sock, timeout_ms, banner, bs, cert_cn, ccn_sz);
        if (cached < 0) close(sock);
        return 1;
    }
    total = 0;
    memset(tmp, 0, sizeof(tmp));
    pfd.fd = sock;
    pfd.events = POLLIN;
    n = (int)read(sock, tmp + total, sizeof(tmp) - 1 - total);
    if (likely(n > 0)) total += n;
    probe = NULL;
    plen = 0;
    for (i = 0; GRABS[i].service; ++i) {
        if (likely(GRABS[i].port == port)) { probe = GRABS[i].probe; plen = GRABS[i].plen; break; }
    }
    if (likely(probe && plen > 0)) {
        write(sock, probe, plen);
        pfd.fd = sock; pfd.events = POLLIN;
        poll(&pfd, 1, 250);
        for (i = 0; i < 4; ++i) {
            n = (int)read(sock, tmp + total, sizeof(tmp) - 1 - total);
            if (n > 0) total += n;
            else break;
        }
    }
    if (cached < 0 && !use_tls) cache_put(ip, port, sock);
    else if (cached < 0) close(sock);
    if (total > 0) sanitize_banner(tmp, total, banner, bs);
    return 1;
}

static int fast_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9')
        n = n * 10 + (*s++ - '0');
    return n;
}

static HOT int parse_ports(const char* RESTRICT spec, int* RESTRICT ports, int max) {
    int count = 0;
    int i, p, s, e;
    char *t, *d;
    if (unlikely(!spec)) return 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    if (buf[0] == 't' && buf[1] == 'o' && buf[2] == 'p') {
        int top[] = {7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49154,0};
        for (i = 0; top[i] && count < max; ++i) ports[count++] = top[i];
        return count;
    }
    if (buf[0] == 'a' && buf[1] == 'l' && buf[2] == 'l' && buf[3] == '\0') { for (p = 1; p <= 65535 && count < max; p++) ports[count++] = p; return count; }
    t = strtok(buf, ",");
    while (likely(t && count < max)) {
        d = strchr(t, '-');
        if (likely(d)) {
            s = fast_atoi(t); e = fast_atoi(d + 1);
            if (s < 1) s = 1;
            if (e > 65535) e = 65535;
            for (p = s; p <= e && count < max; p++) ports[count++] = p;
        } else {
            p = fast_atoi(t);
            if (p >= 1 && p <= 65535) ports[count++] = p;
        }
        t = strtok(NULL, ",");
    }
    return count;
}

static CONST_FN FLATTEN const char* get_service(int port) {
    int i;
    for (i = 0; GRABS[i].service; ++i)
        if (GRABS[i].port == port) return GRABS[i].service;
    return "unknown";
}

static HOT void* grab_worker(void* arg) {
    GrabContext* RESTRICT ctx = (GrabContext*)arg;
    int idx, port, i, state, vi;
    long long t0, rtt;
    bool use_tls;
    const char* v;
    const char* svc;
    char banner[BANNER_SIZE];
    char cert_cn[256];
    char version[128];
    char outbuf[4096];
    int olen;

    for (;;) {
        idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (unlikely(idx >= ctx->port_count)) break;
        port = ctx->ports[idx];
        use_tls = false;
        for (i = 0; GRABS[i].service; ++i) {
            if (GRABS[i].port == port) { use_tls = GRABS[i].use_tls; break; }
        }
        memset(banner, 0, BANNER_SIZE);
        memset(cert_cn, 0, 256);
        memset(version, 0, 128);
        t0 = now_ms();
        state = grab_banner(ctx->target_ip, port, ctx->timeout_ms, banner, BANNER_SIZE, use_tls, cert_cn, sizeof(cert_cn));
        rtt = now_ms() - t0;
        svc = get_service(port);
        v = strstr(banner, "Apache/");
        if (v) { v += 7; vi = 0; while (v[vi] && v[vi] != ' ' && vi < 127) { version[vi] = v[vi]; vi++; } }
        else {
            v = strstr(banner, "nginx/");
            if (v) { v += 6; vi = 0; while (v[vi] && v[vi] != ' ' && vi < 127) { version[vi] = v[vi]; vi++; } }
            else {
                v = strstr(banner, "OpenSSH_");
                if (v) { v += 8; vi = 0; while (v[vi] && v[vi] != ' ' && vi < 127) { version[vi] = v[vi]; vi++; } }
            }
        }
        olen = snprintf(outbuf, sizeof(outbuf),
            "RESULT:{\"port\":%d,\"status\":\"%s\",\"service\":\"%s\",\"banner\":\"%s\",\"version\":\"%s\",\"protocol\":\"tcp\",\"cert_cn\":\"%s\",\"response_time_ms\":%lld}\n",
            port, state == 1 ? "open" : (state == 0 ? "closed" : "filtered"),
            svc, banner, version, cert_cn, rtt);
        fwrite(outbuf, 1, olen < 0 ? 0 : (size_t)olen, stdout);
    }
    return NULL;
}

HOT int main(int argc, char** argv) {
    int i, nt;
    long long elapsed;
    char* target;
    char* ports_str;
    int timeout_ms;
    int workers;
    GrabContext ctx;
    pthread_t threads[MAX_WORKERS];

    signal(SIGPIPE, SIG_IGN);
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    target = NULL;
    ports_str = NULL;
    timeout_ms = 5000;
    workers = 8;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] == 't' && argv[i][3] == 'a' && i + 1 < argc) target = argv[++i];
        else if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] == 'p' && i + 1 < argc) ports_str = argv[++i];
        else if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] == 't' && argv[i][3] == 'i' && i + 1 < argc) timeout_ms = fast_atoi(argv[++i]);
        else if (argv[i][0] == '-' && argv[i][1] == '-' && argv[i][2] == 'w' && i + 1 < argc) workers = fast_atoi(argv[++i]);
        else if (!target) target = argv[i];
        else if (!ports_str) ports_str = argv[i];
        else if (timeout_ms == 5000) timeout_ms = fast_atoi(argv[i]);
        else if (workers == 8) workers = fast_atoi(argv[i]);
    }
    if (unlikely(!target || !ports_str)) {
        fprintf(stderr, "Usage: %s --target <host> --ports <ports> [--timeout ms] [--workers n]\n", argv[0]);
        fprintf(stderr, "  %s 192.168.1.1 22,80,443,8080\n", argv[0]);
        return 1;
    }
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.target, target, sizeof(ctx.target) - 1);
    ctx.target_ip = resolve_ip(target);
    if (unlikely(ctx.target_ip == 0)) { fprintf(stderr, "Failed to resolve target\n"); return 1; }
    ctx.port_count = parse_ports(ports_str, ctx.ports, MAX_PORTS);
    if (unlikely(ctx.port_count <= 0)) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.timeout_ms = timeout_ms;
    ctx.workers = workers;
    ctx.start_time = now_ms();
    fprintf(stderr, "BANNER_GRABBER target=%s ports=%d timeout=%dms workers=%d\n",
        target, ctx.port_count, timeout_ms, workers);
    nt = workers;
    if (nt > MAX_WORKERS) nt = MAX_WORKERS;
    if (nt > ctx.port_count) nt = ctx.port_count;
    if (nt < 1) nt = 1;
    for (i = 0; i < nt; ++i) pthread_create(&threads[i], NULL, grab_worker, &ctx);
    for (i = 0; i < nt; ++i) pthread_join(threads[i], NULL);
    elapsed = now_ms() - ctx.start_time;
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"elapsed_ms\":%lld}\n",
        target, ctx.port_count, elapsed);
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

// vim: ts=4 sw=4 et tw=80
