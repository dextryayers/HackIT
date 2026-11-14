/*
 * stress_engine — scoped TCP/HTTP load generator for authorized resilience
 * testing. C11, pthreads, POSIX sockets. Measurement tool, not an attack kit:
 * no packet spoofing, no amplification, no evasion. The calling framework
 * (hackit stress) enforces scope, approval and caps before this binary runs.
 *
 * Modes:
 *   tcp  — connect + close handshake rate/latency
 *   http — connect, plain HTTP/1.1 GET, read status line, close (HTTP only)
 *
 * Output: one JSON object on stdout.
 * Build: see Makefile (cc -O2 -std=c11 -Wall -Wextra -pthread)
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

#define HARD_MAX_DURATION_S 600
#define HARD_MAX_THREADS    64
#define HARD_MAX_RPS        10000
#define SAMPLES_PER_THREAD  4096
#define RECV_BUF            4096
#define CONNECT_TIMEOUT_MS  3000
#define IO_TIMEOUT_MS       3000

typedef enum { MODE_TCP, MODE_HTTP, MODE_ICMP } engine_mode_t;

typedef struct {
    engine_mode_t mode;
    char     host[256];
    char     port[8];
    char     path[512];
    int      duration_s;
    int      threads;
    int      rps;          /* global cap; divided evenly across threads */
    int      thread_id;
    uint64_t ok, errors;
    double   lat_us[SAMPLES_PER_THREAD];
    uint64_t lat_count;    /* reservoir sampling counter */
    uint64_t lat_filled;   /* samples actually stored */
    uint16_t icmp_seq;     /* ICMP echo sequence */
} worker_arg_t;

static atomic_int g_stop;
static atomic_int g_perm;
static atomic_uint_fast64_t g_ok, g_err;
static double g_start_s;
static pthread_mutex_t g_sample_lock = PTHREAD_MUTEX_INITIALIZER;
static double g_samples[SAMPLES_PER_THREAD * HARD_MAX_THREADS];
static size_t g_sample_n;

static double now_mono_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint64_t now_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void sample_add(worker_arg_t *w, double us) {
    /* Reservoir sampling, per worker, bounded memory. */
    w->lat_count++;
    if (w->lat_filled < SAMPLES_PER_THREAD) {
        w->lat_us[w->lat_filled++] = us;
        return;
    }
    uint64_t j = (uint64_t)rand() % w->lat_count;
    if (j < SAMPLES_PER_THREAD) w->lat_us[j] = us;
}

static void sample_flush(worker_arg_t *w) {
    pthread_mutex_lock(&g_sample_lock);
    for (uint64_t i = 0; i < w->lat_filled && g_sample_n < sizeof(g_samples)/sizeof(g_samples[0]); i++) {
        g_samples[g_sample_n++] = w->lat_us[i];
    }
    pthread_mutex_unlock(&g_sample_lock);
}

static int fcntl_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return flags;
}


/* ---------- ICMP echo (raw socket, ala ping) ---------- */
#define ICMP_ECHO_TYPE     8
#define ICMP_ECHOREPLY_TYPE 0

struct icmp_echo_hdr {
    uint8_t  type, code;
    uint16_t checksum;
    uint16_t id, seq;
} __attribute__((packed));

static uint16_t icmp_checksum(const void *data, size_t len) {
    const uint16_t *words = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *words++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)words;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* One ICMP echo request -> reply. Needs root or CAP_NET_RAW. */
static int icmp_ping(const char *host, uint16_t id, uint16_t seq, uint64_t *rtt_us, int *perm_error) {
    *perm_error = 0;
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        if (errno == EPERM || errno == EACCES) *perm_error = 1;
        freeaddrinfo(res);
        return -1;
    }

    unsigned char payload[16];
    for (int i = 0; i < 16; i++) payload[i] = (unsigned char)(i * 7 + 3);
    unsigned char buf[sizeof(struct icmp_echo_hdr) + sizeof(payload)];
    struct icmp_echo_hdr hdr = { .type = ICMP_ECHO_TYPE, .code = 0,
                                 .checksum = 0, .id = htons(id), .seq = htons(seq) };
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), payload, sizeof(payload));
    struct icmp_echo_hdr *p = (struct icmp_echo_hdr *)buf;
    p->checksum = icmp_checksum(buf, sizeof(buf));

    uint64_t t0 = now_mono_ns();
    ssize_t sent = sendto(fd, buf, sizeof(buf), 0, res->ai_addr, res->ai_addrlen);
    if (sent < 0) { close(fd); freeaddrinfo(res); return -1; }

    int ok = -1;
    uint8_t rbuf[2048];
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = { 1, 0 };
        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc <= 0) break;
        ssize_t n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) break;
        size_t off = 0;
        if ((rbuf[0] >> 4) == 4 && n >= 20) off = (size_t)(rbuf[0] & 0x0F) * 4;
        if ((size_t)n - off < sizeof(struct icmp_echo_hdr)) continue;
        struct icmp_echo_hdr rep;
        memcpy(&rep, rbuf + off, sizeof(rep));
        if (rep.type != ICMP_ECHOREPLY_TYPE) continue;
        if (ntohs(rep.id) != id) continue;
        if (ntohs(rep.seq) != seq) continue;
        *rtt_us = (now_mono_ns() - t0) / 1000;
        ok = 0;
        break;
    }
    close(fd);
    freeaddrinfo(res);
    return ok;
}

static const char *mode_name(engine_mode_t m) {
    switch (m) { case MODE_TCP: return "tcp"; case MODE_HTTP: return "http"; default: return "icmp"; }
}

/* Non-blocking connect with explicit timeout. Returns fd or -1. */
static int connect_timeout(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        int flags = fcntl_nonblock(fd);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) { /* instant success */ }
        else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            rc = select(fd + 1, NULL, &wfds, NULL, &tv);
            if (rc > 0) {
                int soerr = 0; socklen_t slen = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) {
                    /* connected */
                } else { close(fd); fd = -1; continue; }
            } else { close(fd); fd = -1; continue; }
        } else { close(fd); fd = -1; continue; }

        /* Back to blocking mode for the HTTP exchange. */
        fcntl(fd, F_SETFL, flags);
        struct timeval ioto = { IO_TIMEOUT_MS / 1000, (IO_TIMEOUT_MS % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &ioto, sizeof(ioto));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &ioto, sizeof(ioto));
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static int http_get_status(int fd, const char *host, const char *path) {
    char req[1024];
    int n = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hackit-stresslab/1.0\r\nConnection: close\r\n\r\n",
        path, host);
    if (n < 0 || (size_t)n >= sizeof(req)) return -1;
    if (send(fd, req, (size_t)n, MSG_NOSIGNAL) != n) return -1;

    char buf[RECV_BUF];
    ssize_t got = recv(fd, buf, sizeof(buf) - 1, 0);
    if (got <= 0) return -1;
    buf[got] = '\0';

    int status = -1;
    if (sscanf(buf, "HTTP/1.%*s %d", &status) != 1) {
        /* Tolerate bare "HTTP/1.1 200" as well as minor-version variants. */
        char *sp = strchr(buf, ' ');
        if (sp) status = atoi(sp + 1);
    }
    return status;
}

static void *worker(void *argp) {
    worker_arg_t *w = argp;
    /* Per-worker rate: global cap split evenly. */
    uint64_t interval_ns = (uint64_t)1000000000ull * (uint64_t)w->threads / (uint64_t)w->rps;
    if (interval_ns == 0) interval_ns = 1000000; /* 1 ms floor */

    double deadline = now_mono_s() + (double)w->duration_s;
    while (!atomic_load(&g_stop) && now_mono_s() < deadline) {
        uint64_t t0 = now_mono_ns();

        if (w->mode == MODE_ICMP) {
            uint16_t id = (uint16_t)((getpid() & 0xFF) << 8 | (w->thread_id & 0xFF));
            uint16_t seq = (uint16_t)++w->icmp_seq;
            uint64_t rtt = 0;
            int perm_error = 0;
            if (icmp_ping(w->host, id, seq, &rtt, &perm_error) == 0) {
                atomic_fetch_add(&g_ok, 1);
                sample_add(w, (double)rtt);
                uint64_t spent = now_mono_ns() - t0;
                if (spent < interval_ns) {
                    struct timespec ts = { (time_t)((interval_ns - spent) / 1000000000ull),
                                           (long)((interval_ns - spent) % 1000000000ull) };
                    nanosleep(&ts, NULL);
                }
                continue;
            }
            atomic_fetch_add(&g_err, 1);
            if (perm_error) { atomic_store(&g_perm, 1); atomic_store(&g_stop, 1); }
        } else {
            int fd = connect_timeout(w->host, w->port, CONNECT_TIMEOUT_MS);
            if (fd < 0) {
                atomic_fetch_add(&g_err, 1);
            } else {
                if (w->mode == MODE_TCP) {
                    atomic_fetch_add(&g_ok, 1);
                } else {
                    int status = http_get_status(fd, w->host, w->path);
                    if (status > 0 && status < 500) atomic_fetch_add(&g_ok, 1);
                    else atomic_fetch_add(&g_err, 1);
                }
                close(fd);
            }
        }

        double us = (double)(now_mono_ns() - t0) / 1000.0;
        if (w->mode != MODE_ICMP) {
            sample_add(w, us);
        }

        uint64_t spent = now_mono_ns() - t0;
        if (spent < interval_ns) {
            struct timespec ts = { (time_t)((interval_ns - spent) / 1000000000ull),
                                   (long)((interval_ns - spent) % 1000000000ull) };
            nanosleep(&ts, NULL);
        }
    }

    sample_flush(w);
    return NULL;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static double percentile(const double *sorted, size_t n, double p) {
    if (n == 0) return 0.0;
    double idx = p / 100.0 * (double)(n - 1);
    size_t lo = (size_t)idx;
    size_t hi = lo + 1;
    if (hi >= n) return sorted[lo];
    double frac = idx - (double)lo;
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

static void json_escape(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c >= 0x20) out[j++] = (char)c;
        /* control bytes dropped — targets/paths with control chars are invalid anyway */
    }
    out[j] = '\0';
}

static void *monitor(void *arg) {
    int progress_ms = *(int *)arg;
    while (!atomic_load(&g_stop)) {
        struct timespec ts = { progress_ms / 1000, (long)(progress_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (atomic_load(&g_stop)) break;
        double elapsed = now_mono_s() - g_start_s;
        if (elapsed <= 0.0) continue;
        uint64_t ok = atomic_load(&g_ok), err = atomic_load(&g_err), total = ok + err;
        printf("{\"type\":\"progress\",\"elapsed_s\":%.3f,\"requests\":%llu,\"ok\":%llu,\"errors\":%llu,\"achieved_rps\":%.2f}\n",
               elapsed, (unsigned long long)total, (unsigned long long)ok,
               (unsigned long long)err, (double)total / elapsed);
        fflush(stdout);
    }
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <tcp|http> <host> <port> [options]\n"
        "       %s icmp <host> [options]\n"
        "  --duration SEC   test duration (1-%d, default 10)\n"
        "  --threads N      worker threads (1-%d, default 4)\n"
        "  --rps N          global rate cap (1-%d, default 50)\n"
        "  --path PATH      HTTP path (default /)\n"
        "  --progress-ms N  progress line interval, 0 = silent (default 500)\n",
        prog, prog, HARD_MAX_DURATION_S, HARD_MAX_THREADS, HARD_MAX_RPS);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 2; }

    engine_mode_t mode;
    if (strcmp(argv[1], "tcp") == 0) mode = MODE_TCP;
    else if (strcmp(argv[1], "http") == 0) mode = MODE_HTTP;
    else if (strcmp(argv[1], "icmp") == 0) mode = MODE_ICMP;
    else { usage(argv[0]); return 2; }

    if (mode != MODE_ICMP && argc < 4) { usage(argv[0]); return 2; }

    worker_arg_t proto = {0};
    proto.mode = mode;
    snprintf(proto.host, sizeof(proto.host), "%s", argv[2]);
    snprintf(proto.port, sizeof(proto.port), "%s", mode == MODE_ICMP ? "0" : argv[3]);
    snprintf(proto.path, sizeof(proto.path), "/");
    proto.duration_s = 10;
    proto.threads = 4;
    proto.rps = 50;
    int progress_ms = 500;

    for (int i = (mode == MODE_ICMP ? 3 : 4); i < argc; i++) {
        if (!strcmp(argv[i], "--duration") && i + 1 < argc) proto.duration_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) proto.threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rps") && i + 1 < argc) proto.rps = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) snprintf(proto.path, sizeof(proto.path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--progress-ms") && i + 1 < argc) progress_ms = atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }
    if (proto.duration_s < 1) proto.duration_s = 1;
    if (proto.duration_s > HARD_MAX_DURATION_S) proto.duration_s = HARD_MAX_DURATION_S;
    if (proto.threads < 1) proto.threads = 1;
    if (proto.threads > HARD_MAX_THREADS) proto.threads = HARD_MAX_THREADS;
    if (proto.rps < 1) proto.rps = 1;
    if (proto.rps > HARD_MAX_RPS) proto.rps = HARD_MAX_RPS;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    g_start_s = now_mono_s();

    pthread_t tids[HARD_MAX_THREADS];
    worker_arg_t args[HARD_MAX_THREADS];
    double start = now_mono_s();

    for (int i = 0; i < proto.threads; i++) {
        args[i] = proto;
        args[i].thread_id = i;
        args[i].ok = args[i].errors = 0;
        args[i].lat_count = args[i].lat_filled = 0;
        if (pthread_create(&tids[i], NULL, worker, &args[i]) != 0) {
            atomic_store(&g_stop, 1);
            fprintf(stderr, "stress_engine: pthread_create failed\n");
            return 1;
        }
    }
    pthread_t mon;
    bool mon_started = false;
    if (progress_ms > 0) {
        if (pthread_create(&mon, NULL, monitor, &progress_ms) == 0) mon_started = true;
    }
    for (int i = 0; i < proto.threads; i++) pthread_join(tids[i], NULL);
    atomic_store(&g_stop, 1);
    if (mon_started) pthread_join(mon, NULL);
    if (atomic_load(&g_perm)) {
        fprintf(stderr, "stress_engine: ICMP mode needs root or CAP_NET_RAW (raw socket) — run with sudo or use tcp/udp/dns instead\n");
        return 3;
    }

    double elapsed = now_mono_s() - start;
    if (elapsed <= 0.0) elapsed = 1e-6;

    uint64_t ok = atomic_load(&g_ok), err = atomic_load(&g_err), total = ok + err;

    qsort(g_samples, g_sample_n, sizeof(double), cmp_double);

    char esc_host[512];
    json_escape(proto.host, esc_host, sizeof(esc_host));
    char esc_target[560];
    if (mode == MODE_ICMP) snprintf(esc_target, sizeof(esc_target), "%s", esc_host);
    else snprintf(esc_target, sizeof(esc_target), "%s:%s", esc_host, proto.port);

    double err_rate = total ? (double)err / (double)total : 0.0;
    printf("{\"type\":\"result\",\"engine\":\"c\",\"mode\":\"%s\",\"target\":\"%s\",\"method\":%s,"
           "\"duration_s\":%.3f,\"requests\":%llu,\"ok\":%llu,\"errors\":%llu,"
           "\"achieved_rps\":%.2f,\"error_rate\":%.4f,"
           "\"latency_ms\":{\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f}}\n",
           mode_name(mode),
           esc_target,
           mode == MODE_HTTP ? "\"GET\"" : (mode == MODE_ICMP ? "\"ICMP ECHO\"" : "null"),
           elapsed,
           (unsigned long long)total, (unsigned long long)ok, (unsigned long long)err,
           (double)total / elapsed, err_rate,
           percentile(g_samples, g_sample_n, 50) / 1000.0,
           percentile(g_samples, g_sample_n, 90) / 1000.0,
           percentile(g_samples, g_sample_n, 99) / 1000.0,
           g_sample_n ? g_samples[g_sample_n - 1] / 1000.0 : 0.0);

    return 0;
}
