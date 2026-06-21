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
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "optimize.h"

#define MAX_BATCH     256
#define MAX_PORTS     65536
#define IP_HDR_LEN    sizeof(struct iphdr)
#define TCP_HDR_LEN   sizeof(struct tcphdr)
#define PKT_LEN       (IP_HDR_LEN + TCP_HDR_LEN)
#define MAX_WORKERS   32
#define SRC_PORT_BASE 20000

typedef struct PACKED {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} PseudoHeader;

typedef struct {
    int         port;
    bool        open;
    bool        closed;
    int         ttl;
    uint16_t    window;
} PortResult;

typedef struct {
    char        pkt[PKT_LEN];
    struct sockaddr_in addr;
} SendEntry;

typedef struct {
    uint32_t    target_ip;
    int         start_port;
    int         end_port;
    int         timeout_ms;
    int         thread_count;
    int         rate_limit;
    atomic_int  next_port;
    atomic_int  result_count;
    atomic_int  open_count;
    PortResult  results[MAX_PORTS];
    uint32_t    src_ip;
    int         src_port_start;
    bool        running;
    long long   start_time;
    atomic_llong packets_sent;
    atomic_llong packets_recv;
} ScanContext;

static const char* get_service(int port) {
    static const struct { int p; const char* n; } svc[] = {
        {7,"echo"},{21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},
        {80,"http"},{110,"pop3"},{111,"rpcbind"},{143,"imap"},{443,"https"},
        {445,"smb"},{465,"smtps"},{514,"syslog"},{543,"klogin"},{544,"kshell"},
        {587,"submission"},{631,"ipp"},{993,"imaps"},{995,"pop3s"},
        {1433,"mssql"},{1521,"oracle"},{2049,"nfs"},{3306,"mysql"},
        {3389,"rdp"},{5432,"postgresql"},{5900,"vnc"},{6379,"redis"},
        {8080,"http-alt"},{8443,"https-alt"},{11211,"memcached"},
        {27017,"mongod"},{0,NULL}
    };
    for (int i = 0; svc[i].p; i++)
        if (svc[i].p == port) return svc[i].n;
    return "unknown";
}

static ALWAYS_INLINE uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += buf[i];
    if (len & 1) sum += (uint16_t)((uint8_t*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static ALWAYS_INLINE uint16_t calc_tcp_checksum(struct tcphdr* tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    pseudo.saddr = saddr;
    pseudo.daddr = daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);
    char buf[sizeof(PseudoHeader) + tcp_len];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(buf));
}

static ALWAYS_INLINE void build_syn_packet(char* pkt, uint32_t src, uint32_t dst, int sp, int dp) {
    struct iphdr* ip = (struct iphdr*)pkt;
    struct tcphdr* tcp = (struct tcphdr*)(pkt + IP_HDR_LEN);
    memset(pkt, 0, PKT_LEN);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(PKT_LEN);
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src;
    ip->daddr = dst;
    ip->check = 0;
    tcp->source = htons((uint16_t)sp);
    tcp->dest = htons((uint16_t)dp);
    tcp->seq = htonl((uint32_t)(rand() | ((uint32_t)rand() << 16)));
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = calc_tcp_checksum(tcp, TCP_HDR_LEN, src, dst);
}

static int create_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (unlikely(sock < 0)) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (likely(sock >= 0)) {
            int one = 1;
            setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        }
    }
    if (likely(sock >= 0)) {
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        struct timeval tv = { 2, 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return sock;
}

HOT static int batch_send_syns(int rs, uint32_t src, uint32_t dst, int* ports, int count, int src_port_base) {
    static SendEntry entries[MAX_BATCH];
    static struct mmsghdr msgs[MAX_BATCH];
    int batch = count > MAX_BATCH ? MAX_BATCH : count;

    for (int i = 0; i < batch; i++) {
        int sp = src_port_base + (rand() % 10000);
        build_syn_packet(entries[i].pkt, src, dst, sp, ports[i]);
        memset(&entries[i].addr, 0, sizeof(struct sockaddr_in));
        entries[i].addr.sin_family = AF_INET;
        entries[i].addr.sin_addr.s_addr = dst;
        msgs[i].msg_hdr.msg_name = &entries[i].addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_iov = (struct iovec[]){{entries[i].pkt, PKT_LEN}};
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    int sent = sendmmsg(rs, msgs, batch, MSG_DONTWAIT);
    return sent;
}

static ALWAYS_INLINE long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

HOT static int batch_recv_responses(int rs, PortResult* results, int max_results, uint32_t target_ip, int* ports, int port_count, long long deadline) {
    char buf[65536];
    int found = 0;
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);

    while (found < max_results && now_ms() < deadline) {
        int n = recvfrom(rs, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &fl);
        if (unlikely(n <= 0)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            continue;
        }
        if (n < (int)PKT_LEN) continue;
        struct iphdr* ip = (struct iphdr*)buf;
        if (ip->protocol != IPPROTO_TCP || ip->saddr != target_ip) continue;
        int iphl = ip->ihl * 4;
        struct tcphdr* tcp = (struct tcphdr*)(buf + iphl);
        int sport = ntohs(tcp->source);
        if (!tcp->syn || !tcp->ack) continue;
        for (int i = 0; i < port_count; i++) {
            if (ports[i] == sport) {
                results[found].port = sport;
                results[found].open = true;
                results[found].closed = false;
                results[found].ttl = ip->ttl;
                results[found].window = ntohs(tcp->window);
                found++;
                break;
            }
        }
    }
    return found;
}

HOT static void* flood_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int rs = create_raw_socket();
    if (unlikely(rs < 0)) {
        fprintf(stderr, "Failed to create raw socket (need root?)\n");
        return NULL;
    }
    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));
    int local_src = SRC_PORT_BASE + (rand() % 10000);

    while (1) {
        int start = atomic_fetch_add(&ctx->next_port, MAX_BATCH);
        if (start >= ctx->end_port) break;

        int remaining = ctx->end_port - start;
        int batch_size = remaining > MAX_BATCH ? MAX_BATCH : remaining;

        int ports[MAX_BATCH];
        for (int i = 0; i < batch_size; i++) ports[i] = start + i;

        int sent = batch_send_syns(rs, ctx->src_ip, ctx->target_ip, ports, batch_size, local_src);
        if (sent > 0) atomic_fetch_add(&ctx->packets_sent, sent);

        if (ctx->rate_limit > 0) {
            int sleep_us = (batch_size * 1000000) / ctx->rate_limit;
            if (sleep_us > 0) usleep(sleep_us);
        }
    }

    long long deadline = now_ms() + ctx->timeout_ms;
    while (1) {
        PortResult tmp[MAX_BATCH];
        int ports_batch[MAX_BATCH];
        int total_ports = ctx->end_port - ctx->start_port;
        for (int i = 0; i < total_ports; i++) ports_batch[i] = ctx->start_port + i;

        int n = batch_recv_responses(rs, tmp, MAX_BATCH, ctx->target_ip, ports_batch, total_ports, deadline);
        if (n == 0) break;
        atomic_fetch_add(&ctx->packets_recv, n);
        for (int i = 0; i < n; i++) {
            int idx = atomic_fetch_add(&ctx->result_count, 1);
            if (idx < MAX_PORTS) {
                ctx->results[idx] = tmp[i];
                atomic_fetch_add(&ctx->open_count, 1);
            }
        }
        if (now_ms() >= deadline) break;
    }
    close(rs);
    return NULL;
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <target> <port_range> [timeout_ms] [threads] [rate_limit]\n", prog);
    fprintf(stderr, "  target      - IP or hostname\n");
    fprintf(stderr, "  port_range  - e.g. 80,443 or 1-1024 or all\n");
    fprintf(stderr, "  timeout_ms  - response wait time (default: 2000)\n");
    fprintf(stderr, "  threads     - worker threads (default: 4)\n");
    fprintf(stderr, "  rate_limit  - packets/sec (default: 0 = unlimited)\n");
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) return addr.s_addr;
    struct hostent* he = gethostbyname(hostname);
    if (!he || !he->h_addr_list[0]) return 0;
    memcpy(&addr.s_addr, he->h_addr_list[0], 4);
    return addr.s_addr;
}

static uint32_t get_source_ip(uint32_t dst) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return htonl(0x01010101);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = dst;
    sa.sin_port = htons(80);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(s); return htonl(0x01010101); }
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr*)&local, &len);
    close(s);
    return local.sin_addr.s_addr;
}

static int parse_port_range(const char* spec, int** ports_out) {
    static int ports[MAX_PORTS];
    int count = 0;
    if (!spec) return 0;
    if (strcmp(spec, "all") == 0) {
        for (int p = 1; p <= 65535 && count < MAX_PORTS; p++) ports[count++] = p;
        *ports_out = ports;
        return count;
    }
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char* t = strtok(buf, ",");
    while (t && count < MAX_PORTS) {
        char* d = strchr(t, '-');
        if (d) {
            int s = atoi(t), e = atoi(d + 1);
            if (s < 1) s = 1;
            if (e > 65535) e = 65535;
            if (s > e) { int tmp = s; s = e; e = tmp; }
            for (int p = s; p <= e && count < MAX_PORTS; p++) ports[count++] = p;
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
    if (geteuid() != 0) {
        fprintf(stderr, "Error: SYN flood requires root privileges\n");
        return 1;
    }

    uint32_t target = resolve_ip(argv[1]);
    if (unlikely(target == 0)) {
        fprintf(stderr, "Failed to resolve: %s\n", argv[1]);
        return 1;
    }

    int* ports = NULL;
    int port_count = parse_port_range(argv[2], &ports);
    if (port_count <= 0) {
        fprintf(stderr, "No valid ports specified\n");
        return 1;
    }

    int timeout_ms = argc > 3 ? atoi(argv[3]) : 2000;
    int threads = argc > 4 ? atoi(argv[4]) : 4;
    int rate_limit = argc > 5 ? atoi(argv[5]) : 0;
    if (threads < 1) threads = 1;
    if (threads > MAX_WORKERS) threads = MAX_WORKERS;

    int min_port = ports[0], max_port = ports[port_count - 1];
    for (int i = 1; i < port_count; i++) {
        if (ports[i] < min_port) min_port = ports[i];
        if (ports[i] > max_port) max_port = ports[i];
    }

    ScanContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_ip = target;
    ctx.start_port = min_port;
    ctx.end_port = max_port + 1;
    ctx.timeout_ms = timeout_ms;
    ctx.thread_count = threads;
    ctx.rate_limit = rate_limit;
    ctx.src_ip = get_source_ip(target);
    ctx.start_time = now_ms();

    struct in_addr ia;
    ia.s_addr = target;
    fprintf(stderr, "SYN_FLOOD target=%s ports=%d-%d timeout=%dms threads=%d rate=%d\n",
        inet_ntoa(ia), min_port, max_port, timeout_ms, threads, rate_limit);

    pthread_t workers[MAX_WORKERS];
    for (int i = 0; i < threads; i++)
        pthread_create(&workers[i], NULL, flood_worker, &ctx);
    for (int i = 0; i < threads; i++)
        pthread_join(workers[i], NULL);

    long long elapsed = now_ms() - ctx.start_time;
    int unique_open[MAX_PORTS];
    int unique_count = 0;
    for (int i = 0; i < ctx.result_count; i++) {
        bool dup = false;
        for (int j = 0; j < unique_count; j++) {
            if (unique_open[j] == ctx.results[i].port) { dup = true; break; }
        }
        if (!dup) unique_open[unique_count++] = ctx.results[i].port;
    }

    for (int i = 0; i < unique_count; i++) {
        printf("{\"port\":%d,\"state\":\"open\",\"service\":\"%s\"}\n",
            unique_open[i], get_service(unique_open[i]));
    }

    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"ports_scanned\":%d,\"open\":%d,\"packets_sent\":%lld,\"packets_recv\":%lld,\"elapsed_ms\":%lld}\n",
        inet_ntoa(ia), port_count, unique_count,
        (long long)atomic_load(&ctx.packets_sent),
        (long long)atomic_load(&ctx.packets_recv), elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
