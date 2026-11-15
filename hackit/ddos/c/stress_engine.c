/*
 * stress_engine — measurement counterpart to flood_engine. Where flood pushes
 * packets without looking, this one completes every exchange and reports
 * latency, so you can see the knee before the target falls over.
 *
 * Modes: tcp (handshake rate) http (full request/response) icmp (echo RTT/loss)
 *
 * --waf regenerates request identity per request. --tls speaks TLS. Every
 * connect uses a non-blocking deadline so a dead target cannot stall a worker
 * for the kernel's SYN retry window.
 *
 * stdout: progress JSON lines, then one result JSON line. Exit 3 on EPERM.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <pthread.h>
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

#define HARD_MAX_DURATION_S 1200
#define HARD_MAX_THREADS    128
#define HARD_MAX_RPS        20000
#define SAMPLES_PER_THREAD  4096
#define RECV_BUF            4096
#define CONNECT_TIMEOUT_MS  3000
#define IO_TIMEOUT_MS       3000

typedef enum { MODE_TCP, MODE_HTTP, MODE_ICMP } engine_mode_t;

typedef struct {
    engine_mode_t mode;
    char host[256];
    char port[8];
    char path[512];
    char method[16];
    char body[1024];
    int body_len;
    int duration_s, threads, rps, thread_id;
    int tls, waf;
    uint64_t ok, errors;
    double lat_us[SAMPLES_PER_THREAD];
    uint64_t lat_count, lat_filled;
    uint16_t icmp_seq;
    int icmp_fd;
    waf_t wafp;
} worker_arg_t;

static atomic_int g_stop, g_perm;
static atomic_uint_fast64_t g_ok, g_err;
static double g_start_s;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static double g_samples[SAMPLES_PER_THREAD * HARD_MAX_THREADS];
static size_t g_sample_n;
static struct sockaddr_storage g_target;
static socklen_t g_target_len;
static int g_family = AF_INET;
static SSL_CTX *g_ssl;
static char g_sni[256];

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void on_sigint(int s) { (void)s; atomic_store(&g_stop, 1); }

static void sample_add(worker_arg_t *w, double us) {
    w->lat_count++;
    if (w->lat_filled < SAMPLES_PER_THREAD) { w->lat_us[w->lat_filled++] = us; return; }
    uint64_t j = (uint64_t)rand() % w->lat_count;
    if (j < SAMPLES_PER_THREAD) w->lat_us[j] = us;
}

static void sample_flush(worker_arg_t *w) {
    pthread_mutex_lock(&g_lock);
    for (uint64_t i = 0; i < w->lat_filled && g_sample_n < sizeof(g_samples) / sizeof(g_samples[0]); i++)
        g_samples[g_sample_n++] = w->lat_us[i];
    pthread_mutex_unlock(&g_lock);
}

/* ---------- icmp ---------- */
#define ICMP_ECHO 8
#define ICMP_REPLY 0

struct icmp_hdr { uint8_t type, code; uint16_t csum, id, seq; } __attribute__((packed));

static uint16_t icmp_csum(const void *d, size_t n) {
    const uint16_t *w = d;
    uint32_t s = 0;
    while (n > 1) { s += *w++; n -= 2; }
    if (n) s += *(const uint8_t *)w;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

static int icmp_ping(int fd, uint16_t id, uint16_t seq, uint64_t *rtt) {
    unsigned char pay[16];
    for (int i = 0; i < 16; i++) pay[i] = (unsigned char)(i * 7 + 3);
    unsigned char buf[sizeof(struct icmp_hdr) + sizeof(pay)];
    struct icmp_hdr h = { ICMP_ECHO, 0, 0, htons(id), htons(seq) };
    memcpy(buf, &h, sizeof(h));
    memcpy(buf + sizeof(h), pay, sizeof(pay));
    ((struct icmp_hdr *)buf)->csum = icmp_csum(buf, sizeof(buf));

    uint64_t t0 = now_ns();
    if (sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&g_target, g_target_len) < 0) return -1;

    uint8_t rb[2048];
    for (;;) {
        fd_set s; FD_ZERO(&s); FD_SET(fd, &s);
        struct timeval tv = { 1, 0 };
        if (select(fd + 1, &s, NULL, NULL, &tv) <= 0) return -1;
        ssize_t n = recv(fd, rb, sizeof(rb), 0);
        if (n <= 0) return -1;
        size_t off = 0;
        if ((rb[0] >> 4) == 4 && n >= 20) off = (size_t)(rb[0] & 0x0f) * 4;
        if ((size_t)n - off < sizeof(struct icmp_hdr)) continue;
        struct icmp_hdr rep;
        memcpy(&rep, rb + off, sizeof(rep));
        if (rep.type != ICMP_REPLY) continue;
        if (ntohs(rep.id) != id || ntohs(rep.seq) != seq) continue;
        *rtt = (now_ns() - t0) / 1000;
        return 0;
    }
}

/* ---------- tcp/http ---------- */

static int wait_fd(int fd, int wr, int ms) {
    fd_set s; FD_ZERO(&s); FD_SET(fd, &s);
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    return select(fd + 1, wr ? NULL : &s, wr ? &s : NULL, NULL, &tv);
}

static int connect_timeout(int ms) {
    int fd = socket(g_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&g_target, g_target_len);
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        if (wait_fd(fd, 1, ms) <= 0) { close(fd); return -1; }
        int e = 0; socklen_t el = sizeof(e);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) != 0 || e) { close(fd); return -1; }
    }
    fcntl(fd, F_SETFL, fl);
    struct timeval tv = { IO_TIMEOUT_MS / 1000, (IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}

static SSL *tls_start(int fd, int ms) {
    SSL *ssl = SSL_new(g_ssl);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (g_sni[0]) SSL_set_tlsext_host_name(ssl, g_sni);
    SSL_set_connect_state(ssl);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    for (;;) {
        int r = SSL_connect(ssl);
        if (r == 1) { fcntl(fd, F_SETFL, fl); return ssl; }
        int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_WANT_READ) { if (wait_fd(fd, 0, ms) <= 0) break; }
        else if (e == SSL_ERROR_WANT_WRITE) { if (wait_fd(fd, 1, ms) <= 0) break; }
        else break;
    }
    fcntl(fd, F_SETFL, fl);
    SSL_free(ssl);
    return NULL;
}

static int http_exchange(worker_arg_t *w, int fd, SSL *ssl) {
    char req[3072];
    char path[768];
    if (w->waf) waf_build_path(&w->wafp, w->path, path, sizeof(path));
    else snprintf(path, sizeof(path), "%s", w->path);

    char hdrs[2048];
    size_t hn;
    if (w->waf) hn = waf_build_headers(&w->wafp, w->host, 0, hdrs, sizeof(hdrs));
    else hn = (size_t)snprintf(hdrs, sizeof(hdrs),
        "Host: %s\r\nUser-Agent: hackit-stresslab/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        w->host);

    size_t n = (size_t)snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\n", w->method, path);
    if (n >= sizeof(req)) return -1;
    if (w->body_len) {
        n += (size_t)snprintf(req + n, sizeof(req) - n,
             "Content-Length: %d\r\nContent-Type: text/plain\r\n", w->body_len);
    }
    if (n + hn >= sizeof(req)) return -1;
    memcpy(req + n, hdrs, hn);
    n += hn;
    if (w->body_len) {
        size_t room = sizeof(req) - n;
        size_t cp = (size_t)w->body_len < room ? (size_t)w->body_len : room;
        memcpy(req + n, w->body, cp);
        n += cp;
    }

    if (ssl) { if (SSL_write(ssl, req, (int)n) <= 0) return -1; }
    else if (send(fd, req, n, MSG_NOSIGNAL) != (ssize_t)n) return -1;

    char rb[RECV_BUF];
    int got = ssl ? SSL_read(ssl, rb, (int)sizeof(rb) - 1)
                  : (int)recv(fd, rb, sizeof(rb) - 1, 0);
    if (got <= 0) return -1;
    rb[got] = '\0';
    if (!strncmp(rb, "HTTP/", 5)) {
        int st = atoi(rb + 9);
        return st >= 500 ? -1 : st;
    }
    return 0;
}

static const char *mode_name(engine_mode_t m) {
    switch (m) { case MODE_TCP: return "tcp"; case MODE_HTTP: return "http"; default: return "icmp"; }
}

static void *worker(void *arg) {
    worker_arg_t *w = arg;
    uint64_t interval = 1000000000ull * (uint64_t)w->threads / (uint64_t)w->rps;
    if (!interval) interval = 1000000;

    if (w->mode == MODE_ICMP) {
        w->icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (w->icmp_fd < 0) {
            if (errno == EPERM || errno == EACCES) { atomic_store(&g_perm, 1); atomic_store(&g_stop, 1); }
            return NULL;
        }
    }

    double deadline = now_s() + (double)w->duration_s;
    while (!atomic_load(&g_stop) && now_s() < deadline) {
        uint64_t t0 = now_ns();

        if (w->mode == MODE_ICMP) {
            uint16_t id = (uint16_t)(((getpid() & 0xff) << 8) | (w->thread_id & 0xff));
            uint16_t seq = ++w->icmp_seq;
            uint64_t rtt = 0;
            if (icmp_ping(w->icmp_fd, id, seq, &rtt) == 0) {
                atomic_fetch_add(&g_ok, 1);
                sample_add(w, (double)rtt);
            } else {
                atomic_fetch_add(&g_err, 1);
            }
        } else {
            int fd = connect_timeout(CONNECT_TIMEOUT_MS);
            if (fd < 0) {
                atomic_fetch_add(&g_err, 1);
            } else {
                SSL *ssl = NULL;
                if (w->tls) {
                    ssl = tls_start(fd, CONNECT_TIMEOUT_MS);
                    if (!ssl) { close(fd); atomic_fetch_add(&g_err, 1); fd = -1; }
                }
                if (fd >= 0) {
                    if (w->mode == MODE_TCP) atomic_fetch_add(&g_ok, 1);
                    else if (http_exchange(w, fd, ssl) >= 0) atomic_fetch_add(&g_ok, 1);
                    else atomic_fetch_add(&g_err, 1);
                    if (ssl) SSL_free(ssl);
                    close(fd);
                }
            }
            sample_add(w, (double)(now_ns() - t0) / 1000.0);
        }

        uint64_t spent = now_ns() - t0;
        if (spent < interval) {
            struct timespec ts = { (time_t)((interval - spent) / 1000000000ull),
                                   (long)((interval - spent) % 1000000000ull) };
            nanosleep(&ts, NULL);
        }
    }

    if (w->icmp_fd > 0) close(w->icmp_fd);
    sample_flush(w);
    return NULL;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static double pct(const double *s, size_t n, double p) {
    if (!n) return 0.0;
    double idx = p / 100.0 * (double)(n - 1);
    size_t lo = (size_t)idx, hi = lo + 1;
    if (hi >= n) return s[lo];
    return s[lo] * (1.0 - (idx - (double)lo)) + s[hi] * (idx - (double)lo);
}
static void json_esc(const char *in, char *out, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c >= 0x20) out[j++] = (char)c;
    }
    out[j] = '\0';
}

static void *monitor(void *arg) {
    int ms = *(int *)arg;
    while (!atomic_load(&g_stop)) {
        struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (atomic_load(&g_stop)) break;
        double el = now_s() - g_start_s;
        if (el <= 0) continue;
        uint64_t ok = atomic_load(&g_ok), er = atomic_load(&g_err), t = ok + er;
        printf("{\"type\":\"progress\",\"elapsed_s\":%.3f,\"requests\":%llu,\"ok\":%llu,"
               "\"errors\":%llu,\"achieved_rps\":%.2f}\n",
               el, (unsigned long long)t, (unsigned long long)ok, (unsigned long long)er,
               (double)t / el);
        fflush(stdout);
    }
    return NULL;
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s <tcp|http|https|icmp> <host> [port] [opts]\n"
      "  --duration N --threads N --rps N --path P --method M --body B --tls --waf\n"
      "  duration 1-%d, threads 1-%d, rps 1-%d\n",
      p, HARD_MAX_DURATION_S, HARD_MAX_THREADS, HARD_MAX_RPS);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 2; }

    engine_mode_t mode;
    if (!strcmp(argv[1], "tcp")) mode = MODE_TCP;
    else if (!strcmp(argv[1], "http") || !strcmp(argv[1], "https")) mode = MODE_HTTP;
    else if (!strcmp(argv[1], "icmp")) mode = MODE_ICMP;
    else { usage(argv[0]); return 2; }
    int want_tls = !strcmp(argv[1], "https");
    if (mode != MODE_ICMP && argc < 4) { usage(argv[0]); return 2; }

    worker_arg_t proto; memset(&proto, 0, sizeof(proto));
    proto.mode = mode;
    snprintf(proto.host, sizeof(proto.host), "%s", argv[2]);
    snprintf(proto.port, sizeof(proto.port), "%s", mode == MODE_ICMP ? "0" : argv[3]);
    snprintf(proto.path, sizeof(proto.path), "/");
    snprintf(proto.method, sizeof(proto.method), "GET");
    proto.duration_s = 10; proto.threads = 4; proto.rps = 50; proto.tls = want_tls;

    int i0 = (mode == MODE_ICMP) ? 3 : 4;
    for (int i = i0; i < argc; i++) {
        if (!strcmp(argv[i], "--duration") && i + 1 < argc) proto.duration_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) proto.threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rps") && i + 1 < argc) proto.rps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) snprintf(proto.path, sizeof(proto.path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--method") && i + 1 < argc) snprintf(proto.method, sizeof(proto.method), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--body") && i + 1 < argc) {
            const char *b = argv[++i];
            proto.body_len = (int)strlen(b);
            if (proto.body_len > (int)sizeof(proto.body)) proto.body_len = (int)sizeof(proto.body);
            memcpy(proto.body, b, (size_t)proto.body_len);
        } else if (!strcmp(argv[i], "--tls")) proto.tls = 1;
        else if (!strcmp(argv[i], "--waf")) proto.waf = 1;
        else { usage(argv[0]); return 2; }
    }

    if (!strcmp(proto.port, "443")) proto.tls = 1;
    if (proto.duration_s < 1) proto.duration_s = 1;
    if (proto.duration_s > HARD_MAX_DURATION_S) proto.duration_s = HARD_MAX_DURATION_S;
    if (proto.threads < 1) proto.threads = 1;
    if (proto.threads > HARD_MAX_THREADS) proto.threads = HARD_MAX_THREADS;
    if (proto.rps < 1) proto.rps = 1;
    if (proto.rps > HARD_MAX_RPS) proto.rps = HARD_MAX_RPS;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    g_start_s = now_s();

    {
        struct addrinfo h = {0}, *r = NULL;
        h.ai_family = AF_UNSPEC;
        if (mode == MODE_ICMP) { h.ai_family = AF_INET; h.ai_socktype = SOCK_RAW; h.ai_protocol = IPPROTO_ICMP; }
        else h.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(proto.host, mode == MODE_ICMP ? NULL : proto.port, &h, &r) != 0) {
            fprintf(stderr, "stress_engine: cannot resolve %s\n", proto.host); return 2;
        }
        memcpy(&g_target, r->ai_addr, r->ai_addrlen);
        g_target_len = (socklen_t)r->ai_addrlen;
        g_family = r->ai_family;
        freeaddrinfo(r);
    }

    if (proto.tls) {
        snprintf(g_sni, sizeof(g_sni), "%s", proto.host);
        OPENSSL_init_ssl(0, NULL);
        g_ssl = SSL_CTX_new(TLS_client_method());
        if (!g_ssl) { fprintf(stderr, "stress_engine: TLS context failed\n"); return 1; }
        SSL_CTX_set_min_proto_version(g_ssl, TLS1_2_VERSION);
        SSL_CTX_set_verify(g_ssl, SSL_VERIFY_NONE, NULL);
    }

    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);

    worker_arg_t *args = calloc(HARD_MAX_THREADS, sizeof(worker_arg_t));
    pthread_t *tids = calloc(HARD_MAX_THREADS, sizeof(pthread_t));
    if (!args || !tids) { fprintf(stderr, "stress_engine: out of memory\n"); return 1; }

    for (int i = 0; i < proto.threads; i++) {
        args[i] = proto;
        args[i].thread_id = i;
        waf_init(&args[i].wafp, proto.waf, (uint64_t)now_ns() + (uint64_t)i * 7919);
        if (pthread_create(&tids[i], NULL, worker, &args[i]) != 0) {
            atomic_store(&g_stop, 1);
            fprintf(stderr, "stress_engine: pthread_create failed\n"); return 1;
        }
    }
    pthread_t mon; bool mst = false;
    int pms = 500;
    if (pthread_create(&mon, NULL, monitor, &pms) == 0) mst = true;
    for (int i = 0; i < proto.threads; i++) pthread_join(tids[i], NULL);
    atomic_store(&g_stop, 1);
    if (mst) pthread_join(mon, NULL);

    if (atomic_load(&g_perm)) {
        fprintf(stderr, "stress_engine: ICMP needs root or CAP_NET_RAW\n");
        return 3;
    }

    double el = now_s() - g_start_s;
    if (el <= 0) el = 1e-6;

    uint64_t ok = atomic_load(&g_ok), er = atomic_load(&g_err), total = ok + er;
    qsort(g_samples, g_sample_n, sizeof(double), cmp_d);

    char eh[512], target[560];
    json_esc(proto.host, eh, sizeof(eh));
    if (mode == MODE_ICMP) snprintf(target, sizeof(target), "%s", eh);
    else snprintf(target, sizeof(target), "%s:%s", eh, proto.port);

    printf("{\"type\":\"result\",\"engine\":\"c\",\"mode\":\"%s\",\"target\":\"%s\",\"method\":%s,"
           "\"duration_s\":%.3f,\"requests\":%llu,\"ok\":%llu,\"errors\":%llu,"
           "\"achieved_rps\":%.2f,\"error_rate\":%.4f,\"tls\":%s,\"waf\":%s,"
           "\"latency_ms\":{\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f}}\n",
           mode_name(mode), target,
           mode == MODE_HTTP ? "\"REQ\"" : (mode == MODE_ICMP ? "\"ICMP ECHO\"" : "null"),
           el, (unsigned long long)total, (unsigned long long)ok, (unsigned long long)er,
           (double)total / el, total ? (double)er / (double)total : 0.0,
           proto.tls ? "true" : "false", proto.waf ? "true" : "false",
           pct(g_samples, g_sample_n, 50) / 1000.0, pct(g_samples, g_sample_n, 90) / 1000.0,
           pct(g_samples, g_sample_n, 99) / 1000.0,
           g_sample_n ? g_samples[g_sample_n - 1] / 1000.0 : 0.0);

    free(args); free(tids);
    if (g_ssl) SSL_CTX_free(g_ssl);
    return 0;
}