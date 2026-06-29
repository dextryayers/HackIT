#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <ifaddrs.h>

#include "optimize.h"

#define MAX_PORTS         131072
#define MAX_BANNER        8192
#define MAX_WORKERS       128
#define TIMEOUT_MS        1500
#define MAX_DECOYS        32

typedef struct {
    int         port;
    int         state;
    char        service[64];
    char        product[128];
    char        version[64];
    char        banner[MAX_BANNER];
    char        os_hint[64];
    double      confidence;
    double      risk_score;
    int         ttl;
    int         window_size;
    char        tcp_flags[16];
    char        ip[64];
} PortResult;

typedef struct {
    const char* hostname;
    uint32_t    ip;
    const int*  ports;
    int         port_count;
    int         timeout_ms;
    int         thread_count;
    atomic_int  next_idx;
    atomic_int  open_count;
    atomic_int  closed_count;
    atomic_int  filtered_count;
    PortResult  results[131072];
    atomic_int  result_count;
    pthread_mutex_t result_lock;
    int         scan_mode;
    int         raw_sock;
    int         icmp_sock;
    bool        running;
    long long   start_time;
    uint32_t    src_ip;
    int         src_port;
    int         ttl_value;
    int         decoy_count;
    uint32_t    decoys[32];
    bool        chaos_mode;
    int         scan_delay_us;
    int         max_rate;
    atomic_int  packets_sent;
    long long   rate_start;
    int         frag_enabled;
} ScanContext;

enum {
    SCAN_TCP_CONNECT = 0,
    SCAN_SYN_STEALTH = 1,
    SCAN_FIN = 2, SCAN_XMAS = 3, SCAN_NULL = 4,
    SCAN_ACK = 5, SCAN_WINDOW = 6, SCAN_MAIMON = 7,
    SCAN_PROTOCOL_SWEEP = 8, SCAN_IDLE_ZOMBIE = 9, SCAN_ANON_SELF = 10,
};

static const char* scan_mode_names[] = {
    "tcp-connect","syn-stealth","fin","xmas","null",
    "ack","window","maimon","protocol-sweep","idle-zombie","anon-self"
};

typedef struct PACKED { uint32_t saddr; uint32_t daddr; uint8_t zero; uint8_t protocol; uint16_t tcp_len; } PseudoHeader;

static uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; ++i) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(struct tcphdr* tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.saddr = saddr; pseudo.daddr = daddr;
    pseudo.protocol = IPPROTO_TCP; pseudo.tcp_len = htons(tcp_len);
    char buf[sizeof(PseudoHeader) + tcp_len];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(PseudoHeader) + tcp_len);
}

static int create_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock >= 0) { int one = 1; setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)); }
    }
    if (sock >= 0) { struct timeval tv = {0, 1000}; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }
    return sock;
}

static int create_icmp_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock >= 0) { struct timeval tv = {0, 500000}; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }
    return sock;
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
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = dst; sa.sin_port = htons(80);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) { close(s); return htonl(0x01010101); }
    struct sockaddr_in local; socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr*)&local, &len); close(s);
    return local.sin_addr.s_addr;
}

static void build_tcp_packet(char* pkt, int* plen, uint32_t src, uint32_t dst,
                             int sp, int dp, int ttl, uint16_t fo,
                             bool syn, bool ack, bool fin, bool rst, bool psh, bool urg) {
    memset(pkt, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
    struct iphdr* ip = (struct iphdr*)pkt;
    struct tcphdr* tcp = (struct tcphdr*)(pkt + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(fo); ip->ttl = ttl > 0 ? ttl : 64;
    ip->protocol = IPPROTO_TCP; ip->saddr = src; ip->daddr = dst;
    tcp->source = htons((uint16_t)sp); tcp->dest = htons((uint16_t)dp);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    if (ack) tcp->ack_seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5; tcp->syn = syn; tcp->ack = ack; tcp->fin = fin;
    tcp->rst = rst; tcp->psh = psh; tcp->urg = urg;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    *plen = sizeof(struct iphdr) + sizeof(struct tcphdr);
}

static void send_raw_pkt(int rs, uint32_t dst, const char* pkt, int len) {
    struct sockaddr_in to; memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET; to.sin_addr.s_addr = dst;
    sendto(rs, pkt, len, 0, (struct sockaddr*)&to, sizeof(to));
}

static void send_probe(ScanContext* ctx, int rs, int port, uint32_t src) {
    int sp = ctx->src_port > 0 ? ctx->src_port : (10000 + (rand() % 55535));
    int ttlv = ctx->ttl_value > 0 ? ctx->ttl_value : 64;
    if (ctx->chaos_mode) ttlv = 32 + (rand() % 96);
    atomic_fetch_add(&ctx->packets_sent, 1);
    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)]; int len;
    bool S=true,A=false,F=false,R=false,P=false,U=false;
    switch (ctx->scan_mode) {
        case SCAN_SYN_STEALTH: S=true; break;
        case SCAN_FIN: S=false; F=true; break;
        case SCAN_XMAS: S=false; F=true; P=true; U=true; break;
        case SCAN_NULL: break;
        case SCAN_ACK: case SCAN_WINDOW: S=false; A=true; break;
        case SCAN_MAIMON: S=false; A=true; F=true; break;
        default: break;
    }
    build_tcp_packet(pkt, &len, src, ctx->ip, sp, port, ttlv, 0x4000, S, A, F, R, P, U);
    send_raw_pkt(rs, ctx->ip, pkt, len);
    if (ctx->scan_mode == SCAN_SYN_STEALTH && ctx->decoy_count > 0) {
        for (int d = 0; d < ctx->decoy_count; d++) {
            build_tcp_packet(pkt, &len, ctx->decoys[d], ctx->ip, 10000+(rand()%55535), port, ttlv, 0x4000, true, false, false, false, false, false);
            send_raw_pkt(rs, ctx->ip, pkt, len);
        }
    }
    if (ctx->scan_delay_us > 0) usleep((useconds_t)ctx->scan_delay_us);
}

static long long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0; if (!spec) return 0;
    char buf[65536]; strncpy(buf, spec, sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    if (strcmp(buf,"top100")==0||strcmp(buf,"top:100")==0) {
        int top[]={7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49154,0};
        for(int i=0;top[i]&&count<max;i++) ports[count++]=top[i]; return count;
    }
    if(strcmp(buf,"all")==0){for(int p=1;p<=65535&&count<max;p++)ports[count++]=p;return count;}
    char* t=strtok(buf,",");while(t&&count<max){char*d=strchr(t,'-');
    if(d){int s=atoi(t),e=atoi(d+1);if(s<1)s=1;if(e>65535)e=65535;for(int p=s;p<=e&&count<max;p++)ports[count++]=p;}
    else{int p=atoi(t);if(p>=1&&p<=65535)ports[count++]=p;}t=strtok(NULL,",");}
    return count;
}

static int classify_state(int mode, bool synack, bool rst, bool icmp_unr, int wsize) {
    switch (mode) {
        case SCAN_SYN_STEALTH: return synack ? 1 : (rst ? 0 : (icmp_unr ? 2 : 2));
        case SCAN_FIN: case SCAN_XMAS: case SCAN_NULL:
            return rst ? 0 : (icmp_unr ? 2 : 3);
        case SCAN_ACK: case SCAN_MAIMON:
            return rst ? 3 : (icmp_unr ? 2 : 3);
        case SCAN_WINDOW:
            if (rst) return wsize > 0 ? 1 : 0;
            return icmp_unr ? 2 : 2;
        default: return synack ? 1 : (rst ? 0 : 2);
    }
}

static void listen_responses(int raw_sock, int icmp_sock, ScanContext* ctx, int tout_ms) {
    char buf[65536];
    struct sockaddr_in from; socklen_t fl = sizeof(from);
    long long deadline = now_ms() + tout_ms;
    typedef struct { int port; bool sa, rst, icmp; int ws, ttl; } PR;
    PR resp[131072]; memset(resp, 0, sizeof(PR) * ctx->port_count);
    for (int i = 0; i < ctx->port_count; ++i) resp[i].port = ctx->ports[i];

    while (now_ms() < deadline) {
        fd_set rfds; FD_ZERO(&rfds); int mfd = raw_sock;
        FD_SET(raw_sock, &rfds);
        if (icmp_sock >= 0) { FD_SET(icmp_sock, &rfds); if (icmp_sock > mfd) mfd = icmp_sock; }
        struct timeval tv = {0, 20000};
        select(mfd + 1, &rfds, NULL, NULL, &tv);
        if (FD_ISSET(raw_sock, &rfds)) {
            int n = recvfrom(raw_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &fl);
            if (n > 0 && n >= (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
                struct iphdr* ip = (struct iphdr*)buf;
                if (ip->protocol == IPPROTO_TCP) {
                    int iphl = ip->ihl * 4;
                    struct tcphdr* tcp = (struct tcphdr*)(buf + iphl);
                    int dport = ntohs(tcp->dest);
                    for (int i = 0; i < ctx->port_count; ++i) {
                        if (resp[i].port == dport) {
                            if (tcp->syn && tcp->ack) { resp[i].sa = true; resp[i].ws = ntohs(tcp->window); resp[i].ttl = ip->ttl; }
                            if (tcp->rst) { resp[i].rst = true; if (!resp[i].sa) resp[i].ws = ntohs(tcp->window); }
                            break;
                        }
                    }
                }
            }
        }
        if (icmp_sock >= 0 && FD_ISSET(icmp_sock, &rfds)) {
            int n = recvfrom(icmp_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &fl);
            if (n > 0) {
                struct iphdr* ip = (struct iphdr*)buf;
                int iphl = ip->ihl * 4;
                if (ip->protocol == IPPROTO_ICMP && n >= iphl + 8 + (int)sizeof(struct tcphdr)) {
                    uint8_t type = buf[iphl], code = buf[iphl+1];
                    if (type == 3 && (code == 2 || code == 3)) {
                        struct iphdr* iip = (struct iphdr*)(buf + iphl + 8);
                        struct tcphdr* itcp = (struct tcphdr*)((char*)iip + iip->ihl*4);
                        int dport = ntohs(itcp->dest);
                        for (int i = 0; i < ctx->port_count; ++i) if (resp[i].port == dport) { resp[i].icmp = true; break; }
                    }
                }
            }
        }
    }
    for (int i = 0; i < ctx->port_count; ++i) {
        if (resp[i].port <= 0) continue;
        int state = classify_state(ctx->scan_mode, resp[i].sa, resp[i].rst, resp[i].icmp, resp[i].ws);
        int idx = atomic_fetch_add(&ctx->result_count, 1);
        if (idx < 131072) {
            PortResult* r = &ctx->results[idx];
            memset(r, 0, sizeof(PortResult));
            r->port = resp[i].port; r->state = state;
            r->ttl = resp[i].ttl; r->window_size = resp[i].ws;
            if (resp[i].sa) strcpy(r->tcp_flags, "SYN/ACK");
            else if (resp[i].rst) strcpy(r->tcp_flags, "RST");
            else if (resp[i].icmp) strcpy(r->tcp_flags, "ICMP-UNREACH");
            else strcpy(r->tcp_flags, "NO-REPLY");
            if (state == 1) atomic_fetch_add(&ctx->open_count, 1);
            else if (state == 0) atomic_fetch_add(&ctx->closed_count, 1);
            else if (state == 2) atomic_fetch_add(&ctx->filtered_count, 1);
        }
    }
}

static void* syn_scan_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int rs = create_raw_socket(); if (rs < 0) return NULL;
    int icmp = create_icmp_socket();
    uint32_t src = ctx->src_ip;
    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        send_probe(ctx, rs, ctx->ports[idx], src);
    }
    listen_responses(rs, icmp, ctx, ctx->timeout_ms + 500);
    if (icmp >= 0) close(icmp); close(rs);
    return NULL;
}

static int connect_port(uint32_t ip, int port, int timeout_ms, char* banner, int bs, int src_port_val, int ttl_val) {
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port); addr.sin_addr.s_addr = ip;
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 2;
    if (src_port_val > 0) {
        struct sockaddr_in l; memset(&l,0,sizeof(l)); l.sin_family=AF_INET; l.sin_addr.s_addr=htonl(INADDR_ANY); l.sin_port=htons((uint16_t)src_port_val);
        bind(sock, (struct sockaddr*)&l, sizeof(l));
    }
    if (ttl_val > 0) setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val));
    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(sock); return 0; }
    struct epoll_event ev; int epfd = epoll_create1(0);
    if (epfd < 0) { close(sock); return 2; }
    ev.data.fd = sock; ev.events = EPOLLOUT | EPOLLERR;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
    struct epoll_event events[1];
    rc = epoll_wait(epfd, events, 1, timeout_ms); close(epfd);
    if (rc <= 0) { close(sock); return rc == 0 ? 2 : 0; }
    int so_err = 0; socklen_t el = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &el);
    if (so_err != 0) { close(sock); return so_err == ECONNREFUSED ? 0 : 2; }
    if (banner && bs > 0) {
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        struct timeval tv = {timeout_ms/1000, (timeout_ms%1000)*1000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int one = 1; setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        char tmp[8192]; int total = 0; memset(tmp, 0, sizeof(tmp));
        for (int a = 0; a < 3 && total < 8191; a++) {
            int n = (int)read(sock, tmp+total, 8191-total);
            if (n > 0) total += n; else { usleep(50000); if (a == 0) continue; break; }
        }
        if (total == 0) {
            const char* probe = NULL; int plen = 0;
            if (port==80||port==8080||port==8000||port==8888||port==8008) { probe="GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-SYN/1.0\r\n\r\n"; plen=strlen(probe); }
            else if (port==21) { probe="SYST\r\n"; plen=6; }
            else if (port==25||port==587) { probe="EHLO hackit.local\r\n"; plen=19; }
            else if (port==6379) { probe="INFO server\r\n"; plen=13; }
            else if (port==11211) { probe="stats\r\n"; plen=7; }
            else if (port==110||port==995) { probe="CAPA\r\n"; plen=6; }
            else if (port==143||port==993) { probe="a001 CAPABILITY\r\n"; plen=17; }
            if (probe && plen > 0) { write(sock, probe, plen); usleep(150000); int n = (int)read(sock, tmp+total, 8191-total); if (n>0) total+=n; }
        }
        if (total > 0) {
            tmp[total] = 0; int out = 0;
            for (int i = 0; i < total && out < bs-1; ++i) {
                char c = tmp[i]; if (c == '\r') continue;
                if (c == '\n') { if (out>0 && banner[out-1]!=' ') banner[out++]=' '; continue; }
                if (c >= 32 && c < 127) banner[out++] = c;
            }
            banner[out] = 0;
        }
    }
    close(sock); return 1;
}

static void* connect_scan_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        char banner[8192] = {0};
        int state = connect_port(ctx->ip, ctx->ports[idx], ctx->timeout_ms, banner, sizeof(banner), ctx->src_port, ctx->ttl_value);
        int ri = atomic_fetch_add(&ctx->result_count, 1);
        if (ri < 131072) {
            PortResult* r = &ctx->results[ri]; memset(r, 0, sizeof(PortResult));
            r->port = ctx->ports[idx]; r->state = state;
            strncpy(r->banner, banner, sizeof(r->banner)-1);
            if (state==1) atomic_fetch_add(&ctx->open_count, 1);
            else if (state==0) atomic_fetch_add(&ctx->closed_count, 1);
            else atomic_fetch_add(&ctx->filtered_count, 1);
        }
        if (ctx->scan_delay_us > 0) usleep((useconds_t)ctx->scan_delay_us);
    }
    return NULL;
}

static void* protocol_sweep_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int proto_ports[] = {1,6,17,47,50,51,88,89,132,161,162,179,500,514,520,521,546,547,636,669,989,990,1194,1293,1701,1723,1812,1813,2368,2746,33434,0};
    for (int i = 0; i < ctx->port_count && proto_ports[i]; ++i) {
        char b[8192]={0};
        int s = connect_port(ctx->ip, ctx->ports[i], ctx->timeout_ms, b, sizeof(b), ctx->src_port, ctx->ttl_value);
        int ri = atomic_fetch_add(&ctx->result_count, 1);
        if (ri < 131072) {
            PortResult* r = &ctx->results[ri]; memset(r,0,sizeof(PortResult));
            r->port = ctx->ports[i]; r->state = s; strncpy(r->banner, b, sizeof(r->banner)-1);
            if (s==1) atomic_fetch_add(&ctx->open_count, 1);
            else if (s==0) atomic_fetch_add(&ctx->closed_count, 1);
            else atomic_fetch_add(&ctx->filtered_count, 1);
        }
    }
    return NULL;
}

static void* idle_zombie_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    if (ctx->decoy_count == 0) return NULL;
    uint32_t zombie_ip = ctx->decoys[0];
    int rs = create_raw_socket(); if (rs < 0) return NULL;
    for (int i = 0; i < ctx->port_count; ++i) {
        char pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)]; int len;
        build_tcp_packet(pkt, &len, zombie_ip, ctx->ip, 30000+(rand()%10000), ctx->ports[i], 64, 0x4000, true, false, false, false, false, false);
        send_raw_pkt(rs, ctx->ip, pkt, len);
        if (i % 64 == 0) usleep(1000);
    }
    usleep(500000); close(rs); return NULL;
}

static void* anon_self_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    for (int i = 0; i < ctx->port_count; ++i) {
        int port = ctx->ports[i];
        int sock = socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) continue;
        struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
        addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) { close(sock); }
        else if (errno == EADDRINUSE) {
            close(sock);
            int ri = atomic_fetch_add(&ctx->result_count, 1);
            if (ri < 131072) {
                PortResult* r = &ctx->results[ri]; memset(r,0,sizeof(PortResult));
                r->port = port; r->state = 1;
                atomic_fetch_add(&ctx->open_count, 1);
            }
        } else { close(sock); }
    }
    return NULL;
}

static int run_scan(ScanContext* ctx) {
    pthread_t threads[128]; int nt = ctx->thread_count;
    if (nt > 128) nt = 128; if (nt > ctx->port_count) nt = ctx->port_count; if (nt < 1) nt = 1;
    ctx->start_time = now_ms(); ctx->running = true;
    void* (*wf)(void*) = NULL;
    switch (ctx->scan_mode) {
        case SCAN_TCP_CONNECT: wf = connect_scan_worker; break;
        case SCAN_PROTOCOL_SWEEP: wf = protocol_sweep_worker; nt = 1; break;
        case SCAN_IDLE_ZOMBIE: wf = idle_zombie_worker; nt = 1; break;
        case SCAN_ANON_SELF: wf = anon_self_worker; nt = 1; break;
        default: wf = syn_scan_worker; break;
    }
    for (int i = 0; i < nt; ++i) pthread_create(&threads[i], NULL, wf, ctx);
    for (int i = 0; i < nt; ++i) pthread_join(threads[i], NULL);
    return atomic_load(&ctx->result_count);
}

typedef struct { int port; const char* name; } SvcEntry;

static const SvcEntry SVC_DB[] = {
    {1,"TCPmux"},{5,"RJE"},{7,"Echo"},{9,"Discard"},{11,"Systat"},{13,"Daytime"},{17,"QOTD"},{19,"Chargen"},{20,"FTP-data"},{21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{37,"Time"},{53,"DNS"},{69,"TFTP"},{70,"Gopher"},{79,"Finger"},{80,"HTTP"},{81,"HTTP-Alt"},{88,"Kerberos"},{106,"POP3PW"},{109,"POP2"},{110,"POP3"},{111,"RPC"},{113,"Ident"},{119,"NNTP"},{123,"NTP"},{135,"MSRPC"},{137,"NetBIOS-NS"},{138,"NetBIOS-DGM"},{139,"NetBIOS-SSN"},{143,"IMAP"},{161,"SNMP"},{162,"SNMP-Trap"},{179,"BGP"},{194,"IRC"},{199,"SMUX"},{201,"AppleTalk"},{209,"QMTP"},{213,"IPX"},{220,"IMAP3"},{264,"BGMP"},{308,"Novastor"},{311,"Apple Admin"},{318,"PKIX"},{350,"MATIP"},{366,"SMTP-Sub"},{369,"Rpc2"},{370,"codaauth2"},{371,"Clearcase"},{383,"HP alarm"},{384,"A Remote"},{387,"AURP"},{389,"LDAP"},{396,"Novell Netware"},{401,"UPS"},{402,"Genie"},{406,"IMSP"},{407,"Timbuktu"},{416,"Silverplatter"},{425,"ICAD"},{427,"SLP"},{433,"NNSP"},{443,"HTTPS"},{444,"SNPP"},{445,"SMB"},{464,"Kerberos-PW"},{465,"SMTPS"},{475,"tcpnethaspsrv"},{491,"GO-Global"},{497,"Dantz Retrospect"},{500,"ISAKMP"},{502,"Modbus"},{504,"Citadel"},{510,"FirstClass"},{512,"exec"},{513,"Login"},{514,"Syslog"},{515,"Printer"},{517,"Talk"},{518,"NTalk"},{520,"RIP"},{521,"RIPng"},{524,"NCP"},{525,"Timeserver"},{526,"Tempo"},{529,"IRC-Serv"},{530,"RPC"},{531,"AIM"},{532,"Netnews"},{533,"Netwall"},{534,"Megamedia"},{537,"Netstretch"},{542,"Commerce"},{543,"KLogin"},{544,"KShell"},{545,"OSF-RPC"},{546,"DHCPv6-C"},{547,"DHCPv6-S"},{548,"AFP"},{550,"New-RWHO"},{554,"RTSP"},{556,"RFS"},{560,"RMONITOR"},{561,"RMON"},{563,"NNTP-over-TLS"},{564,"9P"},{565,"Whoami"},{566,"Streettalk"},{567,"Banyan-RPC"},{568,"DPA"},{569,"MSN"},{570,"Demon"},{571,"UDemon"},{572,"Sonar"},{573,"Banyan-RPC"},{574,"FTP-Proxy"},{575,"VECom"},{576,"IPCD"},{577,"VNAS"},{578,"IPCD"},{579,"UMS"},{580,"SNTP"},{581,"Planets"},{582,"SCC"},{583,"Cisco"},{584,"Keyserver"},{585,"IMAP4"},{586,"Password"},{587,"SMTP-MSA"},{588,"ACAP"},{589,"Eudora"},{590,"TNS"},{591,"HTTP-Alt"},{592,"Eudora-Secure"},{593,"HTTP-RPC"},{594,"TPIP"},{595,"CAB"},{596,"SMSD"},{597,"PTC"},{598,"SCO-WS"},{599,"Aeolon"},{600,"Sun IPC"},{601,"MQSAS"},{602,"XML-RPC"},{603,"MQS"},{604,"TUNNEL"},{605,"SOAP"},{606,"URM"},{607,"nqs"},{608,"sift-uft"},{609,"NPMP"},{610,"NPMP-GUI"},{611,"HMMP"},{612,"HMMP-Ind"},{613,"SCO-SM"},{614,"SSLshell"},{615,"SCO-Config"},{616,"SCO-Server"},{617,"SCO-DTM"},{618,"DEI-ICDA"},{619,"Compaq-EVM"},{620,"SCO-WS"},{621,"ESCP"},{622,"T3"},{623,"ASF-RMCP"},{624,"CryptoAdmin"},{625,"Apple Xsan"},{626,"Apple PPoE"},{627,"DMI"},{628,"DMI"},{629,"DMI"},{630,"DMI"},{631,"IPP"},{632,"LDAP-BM"},{633,"Sterling"},{634,"ZIP"},{635,"RLZ DBase"},{636,"LDAPS"},{637,"LANS"},{638,"MCID"},{639,"MSDP"},{640,"entrust-svc"},{641,"entrust-client"},{642,"ESMTP"},{643,"SANity"},{644,"SANity"},{645,"SLA"},{646,"LPD"},{647,"DHCP-Failover"},{648,"RRP"},{649,"CAD-SV"},{650,"CAD-REP"},{651,"MSMQ"},{652,"TACACS"},{653,"SANS"},{654,"AODV"},{655,"IEEE-MMS"},{656,"IEEE-MMS-SSL"},{657,"RMC"},{658,"RMP"},{659,"MS-SHR"},{660,"Mac-Server"},{661,"NAMP"},{662,"Trimbosh"},{663,"TrustEstablish"},{664,"IDAC"},{665,"DRIMS"},{666,"Doom"},{667,"IDAC"},{668,"MeComm"},{669,"MeSe"},{670,"CISCO-FNA"},{671,"CISCO-SNA"},{672,"CISCO-Local"},{673,"CISCO-Queue"},{674,"ACAP"},{675,"DCTP"},{676,"VPPS"},{677,"Virtual"},{678,"HMMP"},{679,"AMT"},{680,"AMT"},{681,"DHCP"},{682,"DHCP"},{683,"CORBA-IIOP"},{684,"CORBA-IIOP-SSL"},{685,"MDAP"},{686,"MDAP"},{687,"ASGP"},{688,"REALM-RUSD"},{689,"NMPI"},{690,"VAT"},{691,"RESCAP"},{692,"REXEC"},{693,"ALB"},{694,"Linux-HA"},{695,"IEEE-MMS-SSL"},{696,"SUNRPC"},{697,"SUNRPC"},{698,"SUNRPC"},{699,"SUNRPC"},{700,"SUNRPC"},{701,"LMP"},{702,"IRCS"},{703,"OpenView"},{704,"OpenView"},{705,"OpenView"},{706,"SILC"},{707,"SILC"},{708,"NED"},{709,"NED"},{710,"NED"},{711,"Cisco-TDP"},{712,"Cisco-TDP"},{713,"Cisco-TDP"},{714,"Cisco-TDP"},{715,"Cisco-TDP"},{716,"Cisco-TDP"},{717,"Cisco-TDP"},{718,"Cisco-TDP"},{719,"Cisco-TDP"},{720,"Cisco-TDP"},{721,"Cisco-TDP"},{722,"Cisco-TDP"},{723,"OMVS"},{724,"OMVS"},{725,"OMVS"},{726,"OMVS"},{727,"OMVS"},{728,"OMVS"},{729,"OMVS"},{730,"OMVS"},{731,"OMVS"},{732,"OMVS"},{733,"OMVS"},{734,"OMVS"},{735,"OMVS"},{736,"OMVS"},{737,"OMVS"},{738,"OMVS"},{739,"OMVS"},{740,"NetScout"},{741,"NetScout"},{742,"NetScout"},{743,"NetScout"},{744,"NetScout"},{745,"NetScout"},{746,"NetScout"},{747,"NetScout"},{748,"NetScout"},{749,"NetScout"},{750,"Kerberos"},{751,"Kerberos"},{752,"Kerberos"},{753,"RRH"},{754,"RRH"},{755,"RRH"},{756,"RRH"},{757,"RRH"},{758,"RRH"},{759,"RRH"},{760,"NS"},{761,"NS"},{762,"NS"},{763,"NS"},{764,"NS"},{765,"NS"},{766,"NS"},{767,"NS"},{768,"NS"},{769,"VID"},{770,"VID"},{771,"VID"},{772,"VID"},{773,"VID"},{774,"VID"},{775,"VID"},{776,"VID"},{777,"VID"},{778,"VID"},{779,"VID"},{780,"VID"},{781,"HP-PB"},{782,"HP-PB"},{783,"HP-PB"},{784,"HP-PB"},{785,"HP-PB"},{786,"HP-PB"},{787,"HP-PB"},{788,"HP-PB"},{789,"HP-PB"},{790,"HP-PB"},{791,"HP-PB"},{792,"HP-PB"},{793,"HP-PB"},{794,"HP-PB"},{795,"HP-PB"},{796,"HP-PB"},{797,"HP-PB"},{798,"HP-PB"},{799,"HP-PB"},{800,"MDBS"},{801,"MDBS"},{802,"MODEM"},{803,"MODEM"},{804,"MODEM"},{805,"MODEM"},{806,"MODEM"},{807,"MODEM"},{808,"CCProxy"},{809,"CCProxy"},{810,"CCProxy"},{811,"CCProxy"},{812,"CCProxy"},{813,"CCProxy"},{814,"CCProxy"},{815,"CCProxy"},{816,"CCProxy"},{817,"CCProxy"},{818,"CCProxy"},{819,"CCProxy"},{820,"CCProxy"},{821,"CCProxy"},{822,"CCProxy"},{823,"CCProxy"},{824,"CCProxy"},{825,"CCProxy"},{826,"CCProxy"},{827,"CCProxy"},{828,"CCProxy"},{829,"CCProxy"},{830,"NETCONF"},{831,"NETCONF"},{832,"NETCONF"},{833,"NETCONF"},{834,"NETCONF"},{835,"NETCONF"},{836,"NETCONF"},{837,"NETCONF"},{838,"NETCONF"},{839,"NETCONF"},{840,"NETCONF"},{841,"NETCONF"},{842,"NETCONF"},{843,"NETCONF"},{844,"NETCONF"},{845,"NETCONF"},{846,"NETCONF"},{847,"NETCONF"},{848,"NETCONF"},{849,"NETCONF"},{850,"NETCONF"},{851,"NETCONF"},{852,"NETCONF"},{853,"DNS-over-TLS"},{854,"DNS-over-TLS"},{855,"DNS-over-TLS"},{856,"DNS-over-TLS"},{857,"DNS-over-TLS"},{858,"DNS-over-TLS"},{859,"DNS-over-TLS"},{860,"DNS-over-TLS"},{861,"DNS-over-TLS"},{862,"DNS-over-TLS"},{863,"DNS-over-TLS"},{864,"DNS-over-TLS"},{865,"DNS-over-TLS"},{866,"DNS-over-TLS"},{867,"DNS-over-TLS"},{868,"DNS-over-TLS"},{869,"DNS-over-TLS"},{870,"DNS-over-TLS"},{871,"DNS-over-TLS"},{872,"RSYNC"},{873,"RSYNC"},{874,"RSYNC"},{875,"RSYNC"},{876,"RSYNC"},{877,"RSYNC"},{878,"RSYNC"},{879,"RSYNC"},{880,"RSYNC"},{881,"RSYNC"},{882,"RSYNC"},{883,"RSYNC"},{884,"RSYNC"},{885,"RSYNC"},{886,"RSYNC"},{887,"RSYNC"},{888,"RSYNC"},{889,"RSYNC"},{890,"RSYNC"},{891,"RSYNC"},{892,"RSYNC"},{893,"RSYNC"},{894,"RSYNC"},{895,"RSYNC"},{896,"RSYNC"},{897,"RSYNC"},{898,"RSYNC"},{899,"RSYNC"},{900,"SMB"},{901,"SMB"},{902,"SMB"},{903,"SMB"},{904,"SMB"},{905,"SMB"},{906,"SMB"},{907,"SMB"},{908,"SMB"},{909,"SMB"},{910,"SMB"},{911,"SMB"},{912,"SMB"},{913,"SMB"},{914,"SMB"},{915,"SMB"},{916,"SMB"},{917,"SMB"},{918,"SMB"},{919,"SMB"},{920,"SMB"},{921,"SMB"},{922,"SMB"},{923,"SMB"},{924,"SMB"},{925,"SMB"},{926,"SMB"},{927,"SMB"},{928,"SMB"},{929,"SMB"},{930,"SMB"},{931,"SMB"},{932,"SMB"},{933,"SMB"},{934,"SMB"},{935,"SMB"},{936,"SMB"},{937,"SMB"},{938,"SMB"},{939,"SMB"},{940,"SMB"},{941,"SMB"},{942,"SMB"},{943,"SMB"},{944,"SMB"},{945,"SMB"},{946,"SMB"},{947,"SMB"},{948,"SMB"},{949,"SMB"},{950,"SMB"},{951,"SMB"},{952,"SMB"},{953,"SMB"},{954,"SMB"},{955,"SMB"},{956,"SMB"},{957,"SMB"},{958,"SMB"},{959,"SMB"},{960,"SMB"},{961,"SMB"},{962,"SMB"},{963,"SMB"},{964,"SMB"},{965,"SMB"},{966,"SMB"},{967,"SMB"},{968,"SMB"},{969,"SMB"},{970,"SMB"},{971,"SMB"},{972,"SMB"},{973,"SMB"},{974,"SMB"},{975,"SMB"},{976,"SMB"},{977,"SMB"},{978,"SMB"},{979,"SMB"},{980,"SMB"},{981,"SMB"},{982,"SMB"},{983,"SMB"},{984,"SMB"},{985,"SMB"},{986,"SMB"},{987,"SMB"},{988,"SMB"},{989,"SMB"},{990,"FTPS"},{991,"NAS"},{992,"Telnets"},{993,"IMAPS"},{994,"IRC-SSL"},{995,"POP3S"},{996,"VSINET"},{997,"MAITRD"},{998,"PUP"},{999,"Applix"},{1000,"CADLOCK"},{1024,"KDM"},{1025,"NFS"},{1026,"LSA"},{1027,"IIS"},{1028,"WLBS"},{1029,"MSLSA"},{1030,"AD"},{1080,"SOCKS"},{1099,"RMI"},{1100,"PROXY"},{1111,"SIP"},{1194,"OpenVPN"},{1214,"KAZAA"},{1220,"QT-ServerAdmin"},{1234,"VLC"},{1241,"Nessus"},{1337,"WASTE"},{1352,"LotusNotes"},{1381,"Apple"},{1414,"MSSQL"},{1433,"MSSQL"},{1434,"MSSQL-Mon"},{1443,"HTTPS-Alt"},{1494,"Citrix"},{1521,"Oracle"},{1522,"Oracle"},{1523,"Oracle"},{1524,"Oracle"},{1525,"Oracle"},{1526,"Oracle"},{1527,"Oracle"},{1528,"Oracle"},{1529,"Oracle"},{1530,"Oracle"},{1531,"Oracle"},{1532,"Oracle"},{1533,"Oracle"},{1534,"Oracle"},{1535,"Oracle"},{1536,"Oracle"},{1537,"Oracle"},{1538,"Oracle"},{1539,"Oracle"},{1540,"Oracle"},{1541,"Oracle"},{1542,"Oracle"},{1543,"Oracle"},{1544,"Oracle"},{1545,"Oracle"},{1546,"Oracle"},{1547,"Oracle"},{1548,"Oracle"},{1549,"Oracle"},{1550,"Oracle"},{1720,"H.323"},{1723,"PPTP"},{1741,"Citrix"},{1745,"XAUTH"},{1755,"MMS"},{1801,"MSMQ"},{1812,"RADIUS"},{1813,"RADIUS-Acct"},{1863,"MSNP"},{1883,"MQTT"},{1900,"SSDP"},{1935,"RTMP"},{1991,"cisco"},{2000,"Cisco SCCP"},{2001,"Cisco SCCP"},{2002,"Cisco"},{2049,"NFS"},{2082,"cPanel"},{2083,"cPanel-SSL"},{2086,"WHM"},{2087,"WHM-SSL"},{2095,"Webmail"},{2096,"Webmail-SSL"},{2100,"Oracle"},{2121,"FTP-Alt"},{2181,"ZooKeeper"},{2222,"SSH-Alt"},{2240,"RADIUS"},{2301,"Compaq"},{2323,"Telnet-Alt"},{2368,"OpenVPN"},{2372,"K8s"},{2375,"Docker"},{2376,"Docker-TLS"},{2379,"etcd"},{2380,"etcd-Peer"},{2401,"CVS"},{2424,"OrientDB"},{2480,"OrientDB"},{2483,"Oracle"},{2525,"SMTP-Alt"},{2551,"Nessus"},{2555,"RDP"},{2628,"DICT"},{2717,"Pnrp"},{2809,"CORBA"},{2811,"CORBA"},{2869,"UPNP"},{2947,"GPSD"},{2967,"Symantec"},{3000,"NodeJS"},{3001,"NodeJS"},{3002,"NodeJS"},{3003,"NodeJS"},{3004,"NodeJS"},{3005,"NodeJS"},{3006,"NodeJS"},{3007,"NodeJS"},{3008,"NodeJS"},{3009,"NodeJS"},{3010,"NodeJS"},{3030,"NodeJS"},{3050,"Firebird"},{3074,"XBOX"},{3100,"SCCM"},{3128,"Squid"},{3172,"TiVo"},{3200,"NodeJS"},{3211,"BitTorrent"},{3240,"TiVo"},{3241,"TiVo"},{3260,"iSCSI"},{3268,"Global Catalog"},{3269,"Global Catalog-SSL"},{3283,"Apple NetAssist"},{3290,"Cisco"},{3300,"Websense"},{3306,"MySQL"},{3310,"ClamAV"},{3320,"Samsung"},{3333,"HTTP"},{3346,"Cisco"},{3389,"RDP"},{3390,"RDP"},{3435,"Cisco"},{3456,"VAT"},{3457,"VAT"},{3535,"SMTP-Alt"},{3540,"PJLINK"},{3630,"Cisco"},{3659,"Apple"},{3689,"DAAP"},{3690,"SVN"},{3702,"WS-Discovery"},{3724,"WoW"},{3784,"BGP"},{4000,"ICQ"},{4001,"ICQ"},{4040,"yo"},{4045,"NFS"},{4070,"Cisco"},{4080,"LORA"},{4111,"Xgrid"},{4125,"DVR"},{4190,"ManageSieve"},{4224,"CDNA"},{4242,"VNC"},{4321,"RWHOIS"},{4333,"AH"},{4343,"UNICALL"},{4369,"EPMD"},{4443,"HTTPS"},{4444,"Blaster"},{4445,"UPNP"},{4480,"HTTP"},{4500,"IPsec-NAT-T"},{4567,"SIP"},{4569,"IAX"},{4600,"HP"},{4662,"Edonkey"},{4664,"Google"},{4672,"Edonkey"},{4711,"PulseAudio"},{4712,"PulseAudio"},{4786,"Cisco"},{4840,"OPC-UA"},{4868,"Cisco"},{4899,"Radmin"},{4949,"Munin"},{4950,"Cisco"},{4987,"SMTP"},{5000,"UPnP"},{5001,"UPnP"},{5003,"FileMaker"},{5004,"RTP"},{5005,"RTP"},{5009,"Win"},{5010,"Yahoo"},{5020,"SUP"},{5025,"Cisco"},{5030,"Surf"},{5050,"Yahoo"},{5051,"Yahoo"},{5053,"RDAP"},{5060,"SIP"},{5061,"SIP-TLS"},{5062,"SIP"},{5093,"SPP"},{5099,"MSMQ"},{5100,"SIP"},{5101,"Yahoo"},{5137,"Cisco"},{5142,"Cisco"},{5145,"Cisco"},{5150,"Cisco"},{5170,"Cisco"},{5190,"AOL"},{5191,"AOL"},{5192,"AOL"},{5193,"AOL"},{5194,"AOL"},{5195,"AOL"},{5196,"AOL"},{5197,"AOL"},{5198,"AOL"},{5199,"AOL"},{5200,"AOL"},{5201,"AOL"},{5222,"XMPP"},{5223,"XMPP-SSL"},{5242,"Cisco"},{5269,"XMPP-Server"},{5298,"XMPP"},{5300,"HADB"},{5310,"HADB"},{5320,"HADB"},{5330,"HADB"},{5340,"HADB"},{5350,"HADB"},{5351,"NAT-PMP"},{5353,"mDNS"},{5355,"LLMNR"},{5357,"WSDAPI"},{5358,"WSDAPI"},{5400,"PC-Anywhere"},{5401,"PC-Anywhere"},{5402,"PC-Anywhere"},{5412,"IBM"},{5420,"IBM"},{5430,"IBM"},{5432,"PostgreSQL"},{5433,"PostgreSQL"},{5440,"PostgreSQL"},{5450,"PostgreSQL"},{5460,"PostgreSQL"},{5470,"PostgreSQL"},{5480,"PostgreSQL"},{5490,"PostgreSQL"},{5500,"VNC"},{5501,"VNC"},{5510,"VNC"},{5520,"VNC"},{5530,"VNC"},{5540,"VNC"},{5550,"SIP"},{5554,"Sasser"},{5555,"ADB"},{5556,"ADB"},{5560,"MSSQL"},{5600,"ESM"},{5601,"ESM"},{5631,"PC-Anywhere"},{5632,"PC-Anywhere"},{5666,"NRPE"},{5667,"NRPE"},{5670,"MQTT"},{5671,"AMQP-TLS"},{5672,"AMQP"},{5683,"CoAP"},{5684,"CoAPS"},{5705,"Hadoop"},{5715,"Hadoop"},{5800,"VNC-HTTP"},{5801,"VNC-HTTP"},{5810,"VNC-HTTP"},{5820,"VNC-HTTP"},{5830,"VNC-HTTP"},{5840,"VNC-HTTP"},{5850,"COM"},{5868,"QWK"},{5900,"VNC"},{5901,"VNC"},{5910,"VNC"},{5920,"VNC"},{5930,"VNC"},{5940,"VNC"},{5950,"VNC"},{5960,"VNC"},{5970,"VNC"},{5980,"VNC"},{5984,"CouchDB"},{5985,"WinRM"},{5986,"WinRM-SSL"},{5990,"VNC"},{6000,"X11"},{6001,"X11"},{6010,"X11"},{6020,"X11"},{6030,"X11"},{6040,"X11"},{6050,"X11"},{6060,"X11"},{6070,"X11"},{6080,"X11"},{6090,"X11"},{6100,"X11"},{6110,"X11"},{6120,"X11"},{6129,"X11"},{6251,"TL1"},{6268,"Cisco"},{6300,"Cisco"},{6315,"Cisco"},{6343,"sFlow"},{6346,"Gnutella"},{6347,"Gnutella"},{6379,"Redis"},{6380,"Redis-TLS"},{6390,"Redis"},{6400,"Redis"},{6410,"Redis"},{6420,"Redis"},{6429,"Cisco"},{6430,"Cisco"},{6440,"Cisco"},{6443,"K8s-API"},{6450,"Cisco"},{6471,"Cisco"},{6500,"Cisco"},{6510,"Cisco"},{6514,"Syslog-TLS"},{6520,"Cisco"},{6530,"Cisco"},{6540,"Cisco"},{6550,"Cisco"},{6560,"Cisco"},{6570,"Cisco"},{6580,"VNC"},{6590,"VNC"},{6600,"VNC"},{6646,"Mac"},{6660,"IRC"},{6661,"IRC"},{6662,"IRC"},{6663,"IRC"},{6664,"IRC"},{6665,"IRC"},{6666,"IRC"},{6667,"IRC"},{6668,"IRC"},{6669,"IRC"},{6670,"IRC"},{6680,"IRC"},{6690,"IRC"},{6697,"IRC"},{6700,"IRC"},{6710,"IRC"},{6720,"IRC"},{6730,"IRC"},{6740,"IRC"},{6750,"IRC"},{6760,"IRC"},{6770,"IRC"},{6780,"IRC"},{6790,"IRC"},{6800,"IRC"},{6810,"IRC"},{6820,"IRC"},{6830,"IRC"},{6840,"IRC"},{6850,"Cisco"},{6868,"Cisco"},{6900,"Cisco"},{6901,"Cisco"},{6905,"Cisco"},{6912,"Cisco"},{6935,"Cisco"},{6940,"Cisco"},{6950,"Cisco"},{6970,"Cisco"},{6998,"Cisco"},{6999,"Cisco"},{7000,"Cassandra"},{7001,"WebLogic"},{7002,"WebLogic"},{7010,"WebLogic"},{7020,"WebLogic"},{7030,"WebLogic"},{7040,"WebLogic"},{7050,"WebLogic"},{7060,"WebLogic"},{7070,"Oracle"},{7071,"Oracle"},{7072,"Oracle"},{7073,"Oracle"},{7074,"Oracle"},{7075,"Oracle"},{7076,"Oracle"},{7077,"Oracle"},{7078,"Oracle"},{7079,"Oracle"},{7080,"Oracle"},{7099,"Oracle"},{7100,"X10"},{7101,"WebLogic"},{7110,"Cisco"},{7120,"Cisco"},{7130,"Cisco"},{7140,"Cisco"},{7150,"Cisco"},{7160,"Cisco"},{7170,"Cisco"},{7180,"Cisco"},{7190,"Cisco"},{7199,"Cassandra"},{7200,"Cisco"},{7210,"Cisco"},{7220,"Cisco"},{7230,"Cisco"},{7240,"Cisco"},{7250,"Cisco"},{7260,"Cisco"},{7270,"Cisco"},{7280,"Cisco"},{7290,"Cisco"},{7300,"Cisco"},{7310,"Cisco"},{7320,"Cisco"},{7330,"Cisco"},{7340,"Cisco"},{7350,"Cisco"},{7360,"Cisco"},{7370,"Cisco"},{7380,"Cisco"},{7390,"Cisco"},{7400,"Cisco"},{7410,"Cisco"},{7420,"Cisco"},{7430,"Cisco"},{7440,"Cisco"},{7450,"Cisco"},{7460,"Cisco"},{7470,"Cisco"},{7480,"Cisco"},{7490,"Cisco"},{7500,"Cisco"},{7510,"Cisco"},{7520,"Cisco"},{7530,"Cisco"},{7540,"Cisco"},{7550,"Cisco"},{7560,"Cisco"},{7570,"Cisco"},{7580,"Cisco"},{7590,"Cisco"},{7600,"Cisco"},{7610,"Cisco"},{7620,"Cisco"},{7630,"Cisco"},{7640,"Cisco"},{7650,"Cisco"},{7660,"Cisco"},{7670,"Cisco"},{7680,"Cisco"},{7690,"Cisco"},{7700,"Cisco"},{7710,"Cisco"},{7720,"Cisco"},{7730,"Cisco"},{7740,"Cisco"},{7750,"Cisco"},{7760,"Cisco"},{7770,"Cisco"},{7780,"Cisco"},{7790,"Cisco"},{7800,"Cisco"},{7810,"Cisco"},{7820,"Cisco"},{7830,"Cisco"},{7840,"Cisco"},{7850,"Cisco"},{7860,"Cisco"},{7870,"Cisco"},{7880,"Cisco"},{7890,"Cisco"},{7900,"Cisco"},{7910,"Cisco"},{7920,"Cisco"},{7930,"Cisco"},{7940,"Cisco"},{7950,"Cisco"},{7960,"Cisco"},{7970,"Cisco"},{7980,"Cisco"},{7990,"Cisco"},{8000,"HTTP-Alt"},{8001,"HTTP-Alt"},{8008,"HTTP-Alt"},{8009,"AJP"},{8080,"HTTP-Proxy"},{8081,"HTTP-Alt"},{8118,"Privoxy"},{8123,"Polipo"},{8161,"ActiveMQ"},{8172,"MSSQL"},{8200,"VMware"},{8222,"VMware"},{8243,"HTTPS-Alt"},{8280,"HTTP-Alt"},{8291,"MikroTik"},{8300,"HTTP-Alt"},{8332,"Bitcoin"},{8333,"Bitcoin"},{8384,"Syncthing"},{8400,"CVD"},{8443,"HTTPS-Alt"},{8444,"HTTPS-Alt"},{8472,"VXLAN"},{8500,"Consul"},{8501,"Consul"},{8530,"HTTP"},{8600,"Consul"},{8649,"Ganglia"},{8834,"Nessus"},{8880,"CDA"},{8883,"MQTT-TLS"},{8888,"HTTP-Alt"},{8983,"Solr"},{8998,"Hadoop"},{9000,"HTTP-Alt"},{9001,"Tor"},{9042,"Cassandra"},{9043,"WebLogic"},{9050,"Tor"},{9051,"Tor"},{9060,"WebLogic"},{9080,"HTTP-Alt"},{9090,"Prometheus"},{9091,"Prometheus"},{9092,"Kafka"},{9093,"Kafka"},{9100,"JetDirect"},{9110,"JetDirect"},{9120,"JetDirect"},{9130,"JetDirect"},{9140,"JetDirect"},{9150,"JetDirect"},{9160,"JetDirect"},{9170,"JetDirect"},{9180,"JetDirect"},{9190,"JetDirect"},{9200,"Elasticsearch"},{9201,"Elasticsearch"},{9210,"Elasticsearch"},{9220,"Elasticsearch"},{9290,"Elasticsearch"},{9300,"Elasticsearch"},{9310,"Elasticsearch"},{9418,"Git"},{9443,"HTTPS-Alt"},{9500,"HTTP-Alt"},{9530,"HTTP-Alt"},{9600,"HTTP-Alt"},{9700,"HTTP-Alt"},{9800,"HTTP-Alt"},{9876,"HTTP-Alt"},{9898,"HTTP-Alt"},{9900,"HTTP-Alt"},{9981,"HTTP-Alt"},{9982,"HTTP-Alt"},{9999,"HTTP-Alt"},{10000,"HTTP-Alt"},{10001,"HTTP-Alt"},{10010,"HTTP-Alt"},{10050,"Zabbix"},{10051,"Zabbix"},{10080,"HTTP-Alt"},{10100,"HTTP-Alt"},{10101,"HTTP-Alt"},{10102,"HTTP-Alt"},{10103,"HTTP-Alt"},{10104,"HTTP-Alt"},{10250,"Kubelet"},{10255,"Kubelet-RO"},{10389,"HTTP-Alt"},{10443,"HTTPS-Alt"},{10505,"HTTP-Alt"},{10506,"HTTP-Alt"},{10507,"HTTP-Alt"},{10508,"HTTP-Alt"},{10509,"HTTP-Alt"},{10510,"HTTP-Alt"},{10511,"HTTP-Alt"},{10512,"HTTP-Alt"},{10513,"HTTP-Alt"},{10514,"HTTP-Alt"},{10515,"HTTP-Alt"},{10516,"HTTP-Alt"},{10517,"HTTP-Alt"},{10518,"HTTP-Alt"},{10519,"HTTP-Alt"},{10520,"HTTP-Alt"},{10809,"HTTP-Alt"},{11000,"HTTP-Alt"},{11111,"HTTP-Alt"},{11211,"Memcached"},{11214,"Memcached"},{11215,"Memcached"},{12000,"HTTP-Alt"},{12121,"HTTP-Alt"},{12345,"NetBus"},{12346,"NetBus"},{13337,"HTTP-Alt"},{13722,"HTTP-Alt"},{13723,"HTTP-Alt"},{13724,"HTTP-Alt"},{14000,"HTTP-Alt"},{14141,"HTTP-Alt"},{14142,"HTTP-Alt"},{14143,"HTTP-Alt"},{14144,"HTTP-Alt"},{14145,"HTTP-Alt"},{14146,"HTTP-Alt"},{14147,"HTTP-Alt"},{14148,"HTTP-Alt"},{14149,"HTTP-Alt"},{14150,"HTTP-Alt"},{14250,"HTTP-Alt"},{14441,"HTTPS-Alt"},{14442,"HTTPS-Alt"},{14443,"HTTPS-Alt"},{15000,"HTTP-Alt"},{15010,"HTTP-Alt"},{15345,"HTTP-Alt"},{15555,"HTTP-Alt"},{15660,"HTTP-Alt"},{15672,"RabbitMQ"},{16010,"HTTP-Alt"},{16012,"HTTP-Alt"},{16016,"HTTP-Alt"},{16018,"HTTP-Alt"},{16161,"HTTP-Alt"},{16333,"HTTP-Alt"},{16379,"Redis"},{16380,"Redis"},{16443,"HTTPS-Alt"},{16666,"HTTP-Alt"},{16992,"Intel AMT"},{16993,"Intel AMT"},{16994,"Intel AMT"},{16995,"Intel AMT"},{17010,"HTTP-Alt"},{17017,"HTTP-Alt"},{17171,"HTTP-Alt"},{17273,"HTTP-Alt"},{17500,"Dropbox"},{18080,"HTTP-Alt"},{18081,"HTTP-Alt"},{18082,"HTTP-Alt"},{18086,"HTTP-Alt"},{18088,"HTTP-Alt"},{18090,"HTTP-Alt"},{18091,"HTTP-Alt"},{18092,"HTTP-Alt"},{18093,"HTTP-Alt"},{18094,"HTTP-Alt"},{18095,"HTTP-Alt"},{18096,"HTTP-Alt"},{18101,"HTTP-Alt"},{18200,"HTTP-Alt"},{18300,"HTTP-Alt"},{18400,"HTTP-Alt"},{18500,"HTTP-Alt"},{18600,"HTTP-Alt"},{18700,"HTTP-Alt"},{18800,"HTTP-Alt"},{18881,"HTTP-Alt"},{18882,"HTTP-Alt"},{18900,"HTTP-Alt"},{19000,"HTTP-Alt"},{19080,"HTTP-Alt"},{19101,"HTTP-Alt"},{19200,"HTTP-Alt"},{19300,"HTTP-Alt"},{19350,"HTTP-Alt"},{19494,"HTTP-Alt"},{19638,"HTTP-Alt"},{19801,"HTTP-Alt"},{19842,"HTTP-Alt"},{20000,"HTTP-Alt"},{20001,"HTTP-Alt"},{20002,"HTTP-Alt"},{20005,"HTTP-Alt"},{20007,"HTTP-Alt"},{20008,"HTTP-Alt"},{20009,"HTTP-Alt"},{20010,"HTTP-Alt"},{20011,"HTTP-Alt"},{20012,"HTTP-Alt"},{20013,"HTTP-Alt"},{20014,"HTTP-Alt"},{20015,"HTTP-Alt"},{20016,"HTTP-Alt"},{20017,"HTTP-Alt"},{20018,"HTTP-Alt"},{20019,"HTTP-Alt"},{20020,"HTTP-Alt"},{20021,"HTTP-Alt"},{20022,"HTTP-Alt"},{20023,"HTTP-Alt"},{20024,"HTTP-Alt"},{20025,"HTTP-Alt"},{20101,"HTTP-Alt"},{21000,"HTTP-Alt"},{22222,"HTTP-Alt"},{23456,"HTTP-Alt"},{24444,"HTTP-Alt"},{25565,"Minecraft"},{26000,"HTTP-Alt"},{26208,"HTTP-Alt"},{27000,"HTTP-Alt"},{27017,"MongoDB"},{27018,"MongoDB"},{27019,"MongoDB"},{27374,"Sub7"},{27444,"HTTP-Alt"},{27666,"HTTP-Alt"},{28017,"MongoDB"},{28080,"HTTP-Alt"},{28282,"HTTP-Alt"},{30000,"HTTP-Alt"},{30718,"HTTP-Alt"},{30999,"HTTP-Alt"},{31000,"HTTP-Alt"},{31111,"HTTP-Alt"},{31200,"HTTP-Alt"},{31234,"HTTP-Alt"},{31335,"HTTP-Alt"},{31337,"BackOrifice"},{31338,"BackOrifice"},{31339,"BackOrifice"},{31456,"HTTP-Alt"},{31457,"HTTP-Alt"},{32100,"HTTP-Alt"},{32400,"Plex"},{32401,"Plex"},{32410,"Plex"},{32412,"Plex"},{32413,"Plex"},{32414,"Plex"},{32469,"Plex"},{32764,"Linksys"},{32768,"SunRPC"},{32769,"SunRPC"},{32770,"SunRPC"},{32771,"SunRPC"},{32772,"SunRPC"},{32773,"SunRPC"},{32774,"SunRPC"},{32775,"SunRPC"},{32776,"SunRPC"},{32777,"SunRPC"},{32778,"SunRPC"},{32779,"SunRPC"},{32780,"SunRPC"},{32781,"SunRPC"},{32782,"SunRPC"},{32783,"SunRPC"},{32784,"SunRPC"},{32785,"SunRPC"},{32786,"SunRPC"},{32787,"SunRPC"},{32788,"SunRPC"},{32789,"SunRPC"},{32790,"SunRPC"},{32791,"SunRPC"},{32792,"SunRPC"},{32793,"SunRPC"},{32794,"SunRPC"},{32795,"SunRPC"},{32796,"SunRPC"},{32797,"SunRPC"},{32798,"SunRPC"},{32799,"SunRPC"},{32800,"SunRPC"},{32801,"SunRPC"},{32802,"SunRPC"},{32803,"SunRPC"},{32804,"SunRPC"},{32805,"SunRPC"},{32806,"SunRPC"},{32807,"SunRPC"},{32808,"SunRPC"},{32809,"SunRPC"},{32810,"SunRPC"},{32811,"SunRPC"},{32812,"SunRPC"},{32813,"SunRPC"},{32814,"SunRPC"},{32815,"SunRPC"},{32816,"SunRPC"},{32817,"SunRPC"},{32818,"SunRPC"},{32819,"SunRPC"},{32820,"SunRPC"},{32821,"SunRPC"},{32822,"SunRPC"},{32823,"SunRPC"},{32824,"SunRPC"},{32825,"SunRPC"},{32826,"SunRPC"},{32827,"SunRPC"},{32828,"SunRPC"},{32829,"SunRPC"},{32830,"SunRPC"},{32831,"SunRPC"},{32832,"SunRPC"},{32833,"SunRPC"},{32834,"SunRPC"},{32835,"SunRPC"},{32836,"SunRPC"},{32837,"SunRPC"},{32838,"SunRPC"},{32839,"SunRPC"},{32840,"SunRPC"},{32841,"SunRPC"},{32842,"SunRPC"},{32843,"SunRPC"},{32844,"SunRPC"},{32845,"SunRPC"},{32846,"SunRPC"},{32847,"SunRPC"},{32848,"SunRPC"},{32849,"SunRPC"},{32850,"SunRPC"},{32851,"SunRPC"},{32852,"SunRPC"},{32853,"SunRPC"},{32854,"SunRPC"},{32855,"SunRPC"},{32856,"SunRPC"},{32857,"SunRPC"},{32858,"SunRPC"},{32859,"SunRPC"},{32860,"SunRPC"},{32861,"SunRPC"},{32862,"SunRPC"},{32863,"SunRPC"},{32864,"SunRPC"},{32865,"SunRPC"},{32866,"SunRPC"},{32867,"SunRPC"},{32868,"SunRPC"},{32869,"SunRPC"},{32870,"SunRPC"},{32871,"SunRPC"},{32872,"SunRPC"},{32873,"SunRPC"},{32874,"SunRPC"},{32875,"SunRPC"},{32876,"SunRPC"},{32877,"SunRPC"},{32878,"SunRPC"},{32879,"SunRPC"},{32880,"SunRPC"},{32881,"SunRPC"},{32882,"SunRPC"},{32883,"SunRPC"},{32884,"SunRPC"},{32885,"SunRPC"},{32886,"SunRPC"},{32887,"SunRPC"},{32888,"SunRPC"},{32889,"SunRPC"},{32890,"SunRPC"},{32891,"SunRPC"},{32892,"SunRPC"},{32893,"SunRPC"},{32894,"SunRPC"},{32895,"SunRPC"},{32896,"SunRPC"},{32897,"SunRPC"},{32898,"SunRPC"},{32899,"SunRPC"},{32900,"SunRPC"},{32901,"SunRPC"},{32902,"SunRPC"},{32903,"SunRPC"},{32904,"SunRPC"},{32905,"SunRPC"},{32906,"SunRPC"},{32907,"SunRPC"},{32908,"SunRPC"},{32909,"SunRPC"},{32910,"SunRPC"},{32911,"SunRPC"},{32912,"SunRPC"},{32913,"SunRPC"},{32914,"SunRPC"},{32915,"SunRPC"},{32916,"SunRPC"},{32917,"SunRPC"},{32918,"SunRPC"},{32919,"SunRPC"},{32920,"SunRPC"},{32921,"SunRPC"},{32922,"SunRPC"},{32923,"SunRPC"},{32924,"SunRPC"},{32925,"SunRPC"},{32926,"SunRPC"},{32927,"SunRPC"},{32928,"SunRPC"},{32929,"SunRPC"},{32930,"SunRPC"},{32931,"SunRPC"},{32932,"SunRPC"},{32933,"SunRPC"},{32934,"SunRPC"},{32935,"SunRPC"},{32936,"SunRPC"},{32937,"SunRPC"},{32938,"SunRPC"},{32939,"SunRPC"},{32940,"SunRPC"},{32941,"SunRPC"},{32942,"SunRPC"},{32943,"SunRPC"},{32944,"SunRPC"},{32945,"SunRPC"},{32946,"SunRPC"},{32947,"SunRPC"},{32948,"SunRPC"},{32949,"SunRPC"},{32950,"SunRPC"},{32951,"SunRPC"},{32952,"SunRPC"},{32953,"SunRPC"},{32954,"SunRPC"},{32955,"SunRPC"},{32956,"SunRPC"},{32957,"SunRPC"},{32958,"SunRPC"},{32959,"SunRPC"},{32960,"SunRPC"},{32961,"SunRPC"},{32962,"SunRPC"},{32963,"SunRPC"},{32964,"SunRPC"},{32965,"SunRPC"},{32966,"SunRPC"},{32967,"SunRPC"},{32968,"SunRPC"},{32969,"SunRPC"},{32970,"SunRPC"},{32971,"SunRPC"},{32972,"SunRPC"},{32973,"SunRPC"},{32974,"SunRPC"},{32975,"SunRPC"},{32976,"SunRPC"},{32977,"SunRPC"},{32978,"SunRPC"},{32979,"SunRPC"},{32980,"SunRPC"},{32981,"SunRPC"},{32982,"SunRPC"},{32983,"SunRPC"},{32984,"SunRPC"},{32985,"SunRPC"},{32986,"SunRPC"},{32987,"SunRPC"},{32988,"SunRPC"},{32989,"SunRPC"},{32990,"SunRPC"},{32991,"SunRPC"},{32992,"SunRPC"},{32993,"SunRPC"},{32994,"SunRPC"},{32995,"SunRPC"},{32996,"SunRPC"},{32997,"SunRPC"},{32998,"SunRPC"},{32999,"SunRPC"},{33000,"SunRPC"},{33123,"HTTP-Alt"},{33333,"HTTP-Alt"},{33434,"traceroute"},{33555,"HTTP-Alt"},{33656,"HTTP-Alt"},{34443,"HTTPS-Alt"},{34555,"HTTP-Alt"},{34567,"HTTP-Alt"},{34600,"HTTP-Alt"},{34700,"HTTP-Alt"},{34800,"HTTP-Alt"},{34900,"HTTP-Alt"},{35000,"HTTP-Alt"},{35353,"HTTP-Alt"},{35555,"HTTP-Alt"},{35600,"HTTP-Alt"},{35700,"HTTP-Alt"},{35800,"HTTP-Alt"},{35900,"HTTP-Alt"},{36000,"HTTP-Alt"},{36100,"HTTP-Alt"},{36200,"HTTP-Alt"},{36300,"HTTP-Alt"},{36400,"HTTP-Alt"},{36500,"HTTP-Alt"},{36600,"HTTP-Alt"},{36700,"HTTP-Alt"},{36800,"HTTP-Alt"},{36900,"HTTP-Alt"},{37000,"HTTP-Alt"},{37100,"HTTP-Alt"},{37200,"HTTP-Alt"},{37300,"HTTP-Alt"},{37400,"HTTP-Alt"},{37500,"HTTP-Alt"},{37600,"HTTP-Alt"},{37700,"HTTP-Alt"},{37800,"HTTP-Alt"},{37900,"HTTP-Alt"},{38000,"HTTP-Alt"},{38100,"HTTP-Alt"},{38200,"HTTP-Alt"},{38300,"HTTP-Alt"},{38400,"HTTP-Alt"},{38500,"HTTP-Alt"},{38600,"HTTP-Alt"},{38700,"HTTP-Alt"},{38800,"HTTP-Alt"},{38900,"HTTP-Alt"},{39000,"HTTP-Alt"},{39100,"HTTP-Alt"},{39200,"HTTP-Alt"},{39300,"HTTP-Alt"},{39400,"HTTP-Alt"},{39500,"HTTP-Alt"},{39600,"HTTP-Alt"},{39700,"HTTP-Alt"},{39800,"HTTP-Alt"},{39900,"HTTP-Alt"},{40000,"HTTP-Alt"},{41000,"HTTP-Alt"},{41100,"HTTP-Alt"},{41200,"HTTP-Alt"},{41300,"HTTP-Alt"},{41400,"HTTP-Alt"},{41500,"HTTP-Alt"},{41600,"HTTP-Alt"},{41700,"HTTP-Alt"},{41800,"HTTP-Alt"},{41900,"HTTP-Alt"},{42000,"HTTP-Alt"},{42100,"HTTP-Alt"},{42200,"HTTP-Alt"},{42300,"HTTP-Alt"},{42400,"HTTP-Alt"},{42500,"HTTP-Alt"},{42600,"HTTP-Alt"},{42700,"HTTP-Alt"},{42800,"HTTP-Alt"},{42900,"HTTP-Alt"},{43000,"HTTP-Alt"},{43100,"HTTP-Alt"},{43200,"HTTP-Alt"},{43300,"HTTP-Alt"},{43400,"HTTP-Alt"},{43500,"HTTP-Alt"},{43600,"HTTP-Alt"},{43700,"HTTP-Alt"},{43800,"HTTP-Alt"},{43900,"HTTP-Alt"},{44000,"HTTP-Alt"},{44100,"HTTP-Alt"},{44200,"HTTP-Alt"},{44300,"HTTP-Alt"},{44400,"HTTP-Alt"},{44401,"HTTP-Alt"},{44402,"HTTP-Alt"},{44403,"HTTP-Alt"},{44404,"HTTP-Alt"},{44405,"HTTP-Alt"},{44406,"HTTP-Alt"},{44407,"HTTP-Alt"},{44408,"HTTP-Alt"},{44409,"HTTP-Alt"},{44410,"HTTP-Alt"},{44500,"HTTP-Alt"},{44600,"HTTP-Alt"},{44700,"HTTP-Alt"},{44800,"HTTP-Alt"},{44818,"EtherNet/IP"},{44900,"HTTP-Alt"},{45000,"HTTP-Alt"},{45001,"HTTP-Alt"},{45002,"HTTP-Alt"},{45003,"HTTP-Alt"},{45004,"HTTP-Alt"},{45005,"HTTP-Alt"},{45006,"HTTP-Alt"},{45007,"HTTP-Alt"},{45008,"HTTP-Alt"},{45009,"HTTP-Alt"},{45010,"HTTP-Alt"},{45011,"HTTP-Alt"},{45012,"HTTP-Alt"},{45013,"HTTP-Alt"},{45014,"HTTP-Alt"},{45015,"HTTP-Alt"},{45016,"HTTP-Alt"},{45100,"HTTP-Alt"},{45200,"HTTP-Alt"},{45300,"HTTP-Alt"},{45400,"HTTP-Alt"},{45500,"HTTP-Alt"},{45600,"HTTP-Alt"},{45700,"HTTP-Alt"},{45800,"HTTP-Alt"},{45900,"HTTP-Alt"},{46000,"HTTP-Alt"},{46100,"HTTP-Alt"},{46200,"HTTP-Alt"},{46300,"HTTP-Alt"},{46400,"HTTP-Alt"},{46500,"HTTP-Alt"},{46600,"HTTP-Alt"},{46700,"HTTP-Alt"},{46800,"HTTP-Alt"},{46900,"HTTP-Alt"},{47000,"HTTP-Alt"},{47001,"WinRM"},{47100,"HTTP-Alt"},{47200,"HTTP-Alt"},{47300,"HTTP-Alt"},{47400,"HTTP-Alt"},{47500,"HTTP-Alt"},{47501,"HTTP-Alt"},{47502,"HTTP-Alt"},{47503,"HTTP-Alt"},{47600,"HTTP-Alt"},{47700,"HTTP-Alt"},{47800,"HTTP-Alt"},{47808,"BACnet"},{47900,"HTTP-Alt"},{48000,"HTTP-Alt"},{48001,"HTTP-Alt"},{48002,"HTTP-Alt"},{48003,"HTTP-Alt"},{48004,"HTTP-Alt"},{48005,"HTTP-Alt"},{48006,"HTTP-Alt"},{48007,"HTTP-Alt"},{48008,"HTTP-Alt"},{48009,"HTTP-Alt"},{48010,"HTTP-Alt"},{48100,"HTTP-Alt"},{48101,"HTTP-Alt"},{48200,"HTTP-Alt"},{48300,"HTTP-Alt"},{48400,"HTTP-Alt"},{48500,"HTTP-Alt"},{48600,"HTTP-Alt"},{48700,"HTTP-Alt"},{48800,"HTTP-Alt"},{48899,"HTTP-Alt"},{48900,"HTTP-Alt"},{48999,"HTTP-Alt"},{49000,"HTTP-Alt"},{49100,"HTTP-Alt"},{49151,"HTTP-Alt"},{49152,"Windows-RPC"},{49153,"Windows-RPC"},{49154,"Windows-RPC"},{49155,"Windows-RPC"},{49156,"Windows-RPC"},{49157,"Windows-RPC"},{49158,"Windows-RPC"},{49159,"Windows-RPC"},{49160,"Windows-RPC"},{49161,"Windows-RPC"},{49162,"Windows-RPC"},{49163,"Windows-RPC"},{49164,"Windows-RPC"},{49165,"Windows-RPC"},{49166,"Windows-RPC"},{49167,"Windows-RPC"},{49168,"Windows-RPC"},{49169,"Windows-RPC"},{49170,"Windows-RPC"},{49171,"Windows-RPC"},{49172,"Windows-RPC"},{49173,"Windows-RPC"},{49174,"Windows-RPC"},{49175,"Windows-RPC"},{49176,"Windows-RPC"},{49177,"Windows-RPC"},{49178,"Windows-RPC"},{49179,"Windows-RPC"},{49180,"Windows-RPC"},{49181,"Windows-RPC"},{49182,"Windows-RPC"},{49183,"Windows-RPC"},{49184,"Windows-RPC"},{49185,"Windows-RPC"},{49186,"Windows-RPC"},{49187,"Windows-RPC"},{49188,"Windows-RPC"},{49189,"Windows-RPC"},{49190,"Windows-RPC"},{49191,"Windows-RPC"},{49192,"Windows-RPC"},{49193,"Windows-RPC"},{49194,"Windows-RPC"},{49195,"Windows-RPC"},{49196,"Windows-RPC"},{49197,"Windows-RPC"},{49198,"Windows-RPC"},{49199,"Windows-RPC"},{49200,"Windows-RPC"},{49201,"Windows-RPC"},{49202,"Windows-RPC"},{49203,"Windows-RPC"},{49204,"Windows-RPC"},{49205,"Windows-RPC"},{49206,"Windows-RPC"},{49207,"Windows-RPC"},{49208,"Windows-RPC"},{49209,"Windows-RPC"},{49210,"Windows-RPC"},{50000,"HTTP-Alt"},{50001,"HTTP-Alt"},{50002,"HTTP-Alt"},{50003,"HTTP-Alt"},{50010,"HTTP-Alt"},{50050,"HTTP-Alt"},{50070,"HDFS"},{50075,"HDFS"},{50090,"HDFS"},{50100,"HTTP-Alt"},{50200,"HTTP-Alt"},{50300,"HTTP-Alt"},{50389,"HTTP-Alt"},{50400,"HTTP-Alt"},{50500,"HTTP-Alt"},{50600,"HTTP-Alt"},{50700,"HTTP-Alt"},{50800,"HTTP-Alt"},{50900,"HTTP-Alt"},{51000,"HTTP-Alt"},{51100,"HTTP-Alt"},{51200,"HTTP-Alt"},{51300,"HTTP-Alt"},{51400,"HTTP-Alt"},{51500,"HTTP-Alt"},{51600,"HTTP-Alt"},{51700,"HTTP-Alt"},{51800,"HTTP-Alt"},{51900,"HTTP-Alt"},{52000,"HTTP-Alt"},{52100,"HTTP-Alt"},{52101,"HTTP-Alt"},{52102,"HTTP-Alt"},{52200,"HTTP-Alt"},{52201,"HTTP-Alt"},{52202,"HTTP-Alt"},{52203,"HTTP-Alt"},{52204,"HTTP-Alt"},{52205,"HTTP-Alt"},{52206,"HTTP-Alt"},{52207,"HTTP-Alt"},{52208,"HTTP-Alt"},{52209,"HTTP-Alt"},{52210,"HTTP-Alt"},{52211,"HTTP-Alt"},{52212,"HTTP-Alt"},{52213,"HTTP-Alt"},{52214,"HTTP-Alt"},{52215,"HTTP-Alt"},{52216,"HTTP-Alt"},{52217,"HTTP-Alt"},{52218,"HTTP-Alt"},{52219,"HTTP-Alt"},{52220,"HTTP-Alt"},{52221,"HTTP-Alt"},{52222,"HTTP-Alt"},{52223,"HTTP-Alt"},{52224,"HTTP-Alt"},{52225,"HTTP-Alt"},{52226,"HTTP-Alt"},{52227,"HTTP-Alt"},{52228,"HTTP-Alt"},{52229,"HTTP-Alt"},{52230,"HTTP-Alt"},{52231,"HTTP-Alt"},{52232,"HTTP-Alt"},{52233,"HTTP-Alt"},{52234,"HTTP-Alt"},{52235,"HTTP-Alt"},{52236,"HTTP-Alt"},{52237,"HTTP-Alt"},{52238,"HTTP-Alt"},{52239,"HTTP-Alt"},{52240,"HTTP-Alt"},{52241,"HTTP-Alt"},{52242,"HTTP-Alt"},{52243,"HTTP-Alt"},{52244,"HTTP-Alt"},{52245,"HTTP-Alt"},{52246,"HTTP-Alt"},{52247,"HTTP-Alt"},{52248,"HTTP-Alt"},{52249,"HTTP-Alt"},{52250,"HTTP-Alt"},{52251,"HTTP-Alt"},{52252,"HTTP-Alt"},{52253,"HTTP-Alt"},{52254,"HTTP-Alt"},{52255,"HTTP-Alt"},{52300,"HTTP-Alt"},{52400,"HTTP-Alt"},{52500,"HTTP-Alt"},{52600,"HTTP-Alt"},{52601,"HTTP-Alt"},{52602,"HTTP-Alt"},{52603,"HTTP-Alt"},{52604,"HTTP-Alt"},{52605,"HTTP-Alt"},{52606,"HTTP-Alt"},{52607,"HTTP-Alt"},{52608,"HTTP-Alt"},{52609,"HTTP-Alt"},{52610,"HTTP-Alt"},{52611,"HTTP-Alt"},{52612,"HTTP-Alt"},{52613,"HTTP-Alt"},{52614,"HTTP-Alt"},{52615,"HTTP-Alt"},{52616,"HTTP-Alt"},{52617,"HTTP-Alt"},{52618,"HTTP-Alt"},{52619,"HTTP-Alt"},{52620,"HTTP-Alt"},{52621,"HTTP-Alt"},{52622,"HTTP-Alt"},{52623,"HTTP-Alt"},{52624,"HTTP-Alt"},{52625,"HTTP-Alt"},{52626,"HTTP-Alt"},{52627,"HTTP-Alt"},{52628,"HTTP-Alt"},{52629,"HTTP-Alt"},{52630,"HTTP-Alt"},{52631,"HTTP-Alt"},{52632,"HTTP-Alt"},{52633,"HTTP-Alt"},{52634,"HTTP-Alt"},{52635,"HTTP-Alt"},{52636,"HTTP-Alt"},{52637,"HTTP-Alt"},{52638,"HTTP-Alt"},{52639,"HTTP-Alt"},{52640,"HTTP-Alt"},{52641,"HTTP-Alt"},{52642,"HTTP-Alt"},{52643,"HTTP-Alt"},{52644,"HTTP-Alt"},{52645,"HTTP-Alt"},{52646,"HTTP-Alt"},{52647,"HTTP-Alt"},{52648,"HTTP-Alt"},{52649,"HTTP-Alt"},{52650,"HTTP-Alt"},{52651,"HTTP-Alt"},{52652,"HTTP-Alt"},{52653,"HTTP-Alt"},{52654,"HTTP-Alt"},{52655,"HTTP-Alt"},{52656,"HTTP-Alt"},{52657,"HTTP-Alt"},{52658,"HTTP-Alt"},{52659,"HTTP-Alt"},{52660,"HTTP-Alt"},{52661,"HTTP-Alt"},{52662,"HTTP-Alt"},{52663,"HTTP-Alt"},{52664,"HTTP-Alt"},{52665,"HTTP-Alt"},{52666,"HTTP-Alt"},{52667,"HTTP-Alt"},{52668,"HTTP-Alt"},{52669,"HTTP-Alt"},{52670,"HTTP-Alt"},{52671,"HTTP-Alt"},{52672,"HTTP-Alt"},{52673,"HTTP-Alt"},{52674,"HTTP-Alt"},{52675,"HTTP-Alt"},{52676,"HTTP-Alt"},{52677,"HTTP-Alt"},{52678,"HTTP-Alt"},{52679,"HTTP-Alt"},{52680,"HTTP-Alt"},{52681,"HTTP-Alt"},{52682,"HTTP-Alt"},{52683,"HTTP-Alt"},{52684,"HTTP-Alt"},{52685,"HTTP-Alt"},{52686,"HTTP-Alt"},{52687,"HTTP-Alt"},{52688,"HTTP-Alt"},{52689,"HTTP-Alt"},{52690,"HTTP-Alt"},{52691,"HTTP-Alt"},{52692,"HTTP-Alt"},{52693,"HTTP-Alt"},{52694,"HTTP-Alt"},{52695,"HTTP-Alt"},{52696,"HTTP-Alt"},{52697,"HTTP-Alt"},{52698,"HTTP-Alt"},{52699,"HTTP-Alt"},{52700,"HTTP-Alt"},{52701,"HTTP-Alt"},{52702,"HTTP-Alt"},{52800,"HTTP-Alt"},{52869,"HTTP-Alt"},{52900,"HTTP-Alt"},{53000,"HTTP-Alt"},{53100,"HTTP-Alt"},{53200,"HTTP-Alt"},{53300,"HTTP-Alt"},{53333,"HTTP-Alt"},{53400,"HTTP-Alt"},{53413,"HTTP-Alt"},{53500,"HTTP-Alt"},{53535,"HTTP-Alt"},{53600,"HTTP-Alt"},{53700,"HTTP-Alt"},{53701,"HTTP-Alt"},{53800,"HTTP-Alt"},{53900,"HTTP-Alt"},{54000,"HTTP-Alt"},{54045,"HTTP-Alt"},{54100,"HTTP-Alt"},{54200,"HTTP-Alt"},{54300,"HTTP-Alt"},{54321,"HTTP-Alt"},{54400,"HTTP-Alt"},{54500,"HTTP-Alt"},{54600,"HTTP-Alt"},{54700,"HTTP-Alt"},{54701,"HTTP-Alt"},{54702,"HTTP-Alt"},{54703,"HTTP-Alt"},{54704,"HTTP-Alt"},{54705,"HTTP-Alt"},{54706,"HTTP-Alt"},{54707,"HTTP-Alt"},{54708,"HTTP-Alt"},{54709,"HTTP-Alt"},{54710,"HTTP-Alt"},{54711,"HTTP-Alt"},{54712,"HTTP-Alt"},{54713,"HTTP-Alt"},{54714,"HTTP-Alt"},{54715,"HTTP-Alt"},{54716,"HTTP-Alt"},{54717,"HTTP-Alt"},{54718,"HTTP-Alt"},{54719,"HTTP-Alt"},{54720,"HTTP-Alt"},{54721,"HTTP-Alt"},{54722,"HTTP-Alt"},{54723,"HTTP-Alt"},{54724,"HTTP-Alt"},{54725,"HTTP-Alt"},{54726,"HTTP-Alt"},{54727,"HTTP-Alt"},{54728,"HTTP-Alt"},{54729,"HTTP-Alt"},{54730,"HTTP-Alt"},{54731,"HTTP-Alt"},{54732,"HTTP-Alt"},{54733,"HTTP-Alt"},{54734,"HTTP-Alt"},{54735,"HTTP-Alt"},{54736,"HTTP-Alt"},{54737,"HTTP-Alt"},{54738,"HTTP-Alt"},{54739,"HTTP-Alt"},{54740,"HTTP-Alt"},{54741,"HTTP-Alt"},{54742,"HTTP-Alt"},{54743,"HTTP-Alt"},{54744,"HTTP-Alt"},{54745,"HTTP-Alt"},{54746,"HTTP-Alt"},{54747,"HTTP-Alt"},{54748,"HTTP-Alt"},{54749,"HTTP-Alt"},{54750,"HTTP-Alt"},{54800,"HTTP-Alt"},{54900,"HTTP-Alt"},{55000,"HTTP-Alt"},{55001,"HTTP-Alt"},{55002,"HTTP-Alt"},{55003,"HTTP-Alt"},{55004,"HTTP-Alt"},{55005,"HTTP-Alt"},{55006,"HTTP-Alt"},{55007,"HTTP-Alt"},{55100,"HTTP-Alt"},{55200,"HTTP-Alt"},{55300,"HTTP-Alt"},{55400,"HTTP-Alt"},{55500,"HTTP-Alt"},{55555,"HTTP-Alt"},{55600,"HTTP-Alt"},{55601,"HTTP-Alt"},{55602,"HTTP-Alt"},{55700,"HTTP-Alt"},{55800,"HTTP-Alt"},{55900,"HTTP-Alt"},{56000,"HTTP-Alt"},{56100,"HTTP-Alt"},{56200,"HTTP-Alt"},{56300,"HTTP-Alt"},{56400,"HTTP-Alt"},{56500,"HTTP-Alt"},{56600,"HTTP-Alt"},{56700,"HTTP-Alt"},{56800,"HTTP-Alt"},{56900,"HTTP-Alt"},{57000,"HTTP-Alt"},{57100,"HTTP-Alt"},{57200,"HTTP-Alt"},{57300,"HTTP-Alt"},{57400,"HTTP-Alt"},{57500,"HTTP-Alt"},{57600,"HTTP-Alt"},{57700,"HTTP-Alt"},{57797,"HTTP-Alt"},{57800,"HTTP-Alt"},{57897,"HTTP-Alt"},{57900,"HTTP-Alt"},{58000,"HTTP-Alt"},{58001,"HTTP-Alt"},{58002,"HTTP-Alt"},{58100,"HTTP-Alt"},{58200,"HTTP-Alt"},{58201,"HTTP-Alt"},{58202,"HTTP-Alt"},{58203,"HTTP-Alt"},{58300,"HTTP-Alt"},{58400,"HTTP-Alt"},{58500,"HTTP-Alt"},{58600,"HTTP-Alt"},{58700,"HTTP-Alt"},{58701,"HTTP-Alt"},{58702,"HTTP-Alt"},{58703,"HTTP-Alt"},{58704,"HTTP-Alt"},{58705,"HTTP-Alt"},{58706,"HTTP-Alt"},{58707,"HTTP-Alt"},{58708,"HTTP-Alt"},{58709,"HTTP-Alt"},{58710,"HTTP-Alt"},{58711,"HTTP-Alt"},{58712,"HTTP-Alt"},{58713,"HTTP-Alt"},{58714,"HTTP-Alt"},{58715,"HTTP-Alt"},{58716,"HTTP-Alt"},{58717,"HTTP-Alt"},{58718,"HTTP-Alt"},{58719,"HTTP-Alt"},{58720,"HTTP-Alt"},{58721,"HTTP-Alt"},{58722,"HTTP-Alt"},{58723,"HTTP-Alt"},{58724,"HTTP-Alt"},{58725,"HTTP-Alt"},{58726,"HTTP-Alt"},{58727,"HTTP-Alt"},{58728,"HTTP-Alt"},{58729,"HTTP-Alt"},{58730,"HTTP-Alt"},{58731,"HTTP-Alt"},{58732,"HTTP-Alt"},{58733,"HTTP-Alt"},{58734,"HTTP-Alt"},{58735,"HTTP-Alt"},{58736,"HTTP-Alt"},{58737,"HTTP-Alt"},{58738,"HTTP-Alt"},{58739,"HTTP-Alt"},{58740,"HTTP-Alt"},{58741,"HTTP-Alt"},{58742,"HTTP-Alt"},{58743,"HTTP-Alt"},{58744,"HTTP-Alt"},{58745,"HTTP-Alt"},{58746,"HTTP-Alt"},{58747,"HTTP-Alt"},{58748,"HTTP-Alt"},{58749,"HTTP-Alt"},{58750,"HTTP-Alt"},{58800,"HTTP-Alt"},{58888,"HTTP-Alt"},{58900,"HTTP-Alt"},{59000,"HTTP-Alt"},{59001,"HTTP-Alt"},{59002,"HTTP-Alt"},{59003,"HTTP-Alt"},{59004,"HTTP-Alt"},{59005,"HTTP-Alt"},{59006,"HTTP-Alt"},{59007,"HTTP-Alt"},{59008,"HTTP-Alt"},{59009,"HTTP-Alt"},{59010,"HTTP-Alt"},{59011,"HTTP-Alt"},{59012,"HTTP-Alt"},{59013,"HTTP-Alt"},{59014,"HTTP-Alt"},{59015,"HTTP-Alt"},{59016,"HTTP-Alt"},{59017,"HTTP-Alt"},{59018,"HTTP-Alt"},{59019,"HTTP-Alt"},{59020,"HTTP-Alt"},{59021,"HTTP-Alt"},{59022,"HTTP-Alt"},{59023,"HTTP-Alt"},{59024,"HTTP-Alt"},{59025,"HTTP-Alt"},{59026,"HTTP-Alt"},{59027,"HTTP-Alt"},{59028,"HTTP-Alt"},{59029,"HTTP-Alt"},{59030,"HTTP-Alt"},{59031,"HTTP-Alt"},{59032,"HTTP-Alt"},{59033,"HTTP-Alt"},{59034,"HTTP-Alt"},{59035,"HTTP-Alt"},{59036,"HTTP-Alt"},{59037,"HTTP-Alt"},{59038,"HTTP-Alt"},{59039,"HTTP-Alt"},{59040,"HTTP-Alt"},{59041,"HTTP-Alt"},{59042,"HTTP-Alt"},{59043,"HTTP-Alt"},{59044,"HTTP-Alt"},{59045,"HTTP-Alt"},{59046,"HTTP-Alt"},{59047,"HTTP-Alt"},{59048,"HTTP-Alt"},{59049,"HTTP-Alt"},{59050,"HTTP-Alt"},{59051,"HTTP-Alt"},{59052,"HTTP-Alt"},{59053,"HTTP-Alt"},{59054,"HTTP-Alt"},{59055,"HTTP-Alt"},{59056,"HTTP-Alt"},{59057,"HTTP-Alt"},{59058,"HTTP-Alt"},{59059,"HTTP-Alt"},{59060,"HTTP-Alt"},{59061,"HTTP-Alt"},{59062,"HTTP-Alt"},{59063,"HTTP-Alt"},{59064,"HTTP-Alt"},{59065,"HTTP-Alt"},{59066,"HTTP-Alt"},{59067,"HTTP-Alt"},{59068,"HTTP-Alt"},{59069,"HTTP-Alt"},{59070,"HTTP-Alt"},{59071,"HTTP-Alt"},{59072,"HTTP-Alt"},{59073,"HTTP-Alt"},{59074,"HTTP-Alt"},{59075,"HTTP-Alt"},{59076,"HTTP-Alt"},{59077,"HTTP-Alt"},{59078,"HTTP-Alt"},{59079,"HTTP-Alt"},{59080,"HTTP-Alt"},{59081,"HTTP-Alt"},{59082,"HTTP-Alt"},{59083,"HTTP-Alt"},{59084,"HTTP-Alt"},{59085,"HTTP-Alt"},{59086,"HTTP-Alt"},{59087,"HTTP-Alt"},{59088,"HTTP-Alt"},{59089,"HTTP-Alt"},{59090,"HTTP-Alt"},{59091,"HTTP-Alt"},{59092,"HTTP-Alt"},{59093,"HTTP-Alt"},{59094,"HTTP-Alt"},{59095,"HTTP-Alt"},{59096,"HTTP-Alt"},{59097,"HTTP-Alt"},{59098,"HTTP-Alt"},{59099,"HTTP-Alt"},{59100,"HTTP-Alt"},{59101,"HTTP-Alt"},{59102,"HTTP-Alt"},{59103,"HTTP-Alt"},{59104,"HTTP-Alt"},{59105,"HTTP-Alt"},{59106,"HTTP-Alt"},{59107,"HTTP-Alt"},{59108,"HTTP-Alt"},{59109,"HTTP-Alt"},{59110,"HTTP-Alt"},{59111,"HTTP-Alt"},{59112,"HTTP-Alt"},{59113,"HTTP-Alt"},{59114,"HTTP-Alt"},{59115,"HTTP-Alt"},{59116,"HTTP-Alt"},{59117,"HTTP-Alt"},{59118,"HTTP-Alt"},{59119,"HTTP-Alt"},{59120,"HTTP-Alt"},{59121,"HTTP-Alt"},{59122,"HTTP-Alt"},{59123,"HTTP-Alt"},{59124,"HTTP-Alt"},{59125,"HTTP-Alt"},{59126,"HTTP-Alt"},{59127,"HTTP-Alt"},{59128,"HTTP-Alt"},{59129,"HTTP-Alt"},{59130,"HTTP-Alt"},{59131,"HTTP-Alt"},{59132,"HTTP-Alt"},{59133,"HTTP-Alt"},{59134,"HTTP-Alt"},{59135,"HTTP-Alt"},{59136,"HTTP-Alt"},{59137,"HTTP-Alt"},{59138,"HTTP-Alt"},{59139,"HTTP-Alt"},{59140,"HTTP-Alt"},{59141,"HTTP-Alt"},{59142,"HTTP-Alt"},{59143,"HTTP-Alt"},{59144,"HTTP-Alt"},{59145,"HTTP-Alt"},{59146,"HTTP-Alt"},{59147,"HTTP-Alt"},{59148,"HTTP-Alt"},{59149,"HTTP-Alt"},{59150,"HTTP-Alt"},{59151,"HTTP-Alt"},{59152,"HTTP-Alt"},{59153,"HTTP-Alt"},{59154,"HTTP-Alt"},{59155,"HTTP-Alt"},{59156,"HTTP-Alt"},{59157,"HTTP-Alt"},{59158,"HTTP-Alt"},{59159,"HTTP-Alt"},{59160,"HTTP-Alt"},{59161,"HTTP-Alt"},{59162,"HTTP-Alt"},{59163,"HTTP-Alt"},{59164,"HTTP-Alt"},{59165,"HTTP-Alt"},{59166,"HTTP-Alt"},{59167,"HTTP-Alt"},{59168,"HTTP-Alt"},{59169,"HTTP-Alt"},{59170,"HTTP-Alt"},{59171,"HTTP-Alt"},{59172,"HTTP-Alt"},{59173,"HTTP-Alt"},{59174,"HTTP-Alt"},{59175,"HTTP-Alt"},{59176,"HTTP-Alt"},{59177,"HTTP-Alt"},{59178,"HTTP-Alt"},{59179,"HTTP-Alt"},{59180,"HTTP-Alt"},{59181,"HTTP-Alt"},{59182,"HTTP-Alt"},{59183,"HTTP-Alt"},{59184,"HTTP-Alt"},{59185,"HTTP-Alt"},{59186,"HTTP-Alt"},{59187,"HTTP-Alt"},{59188,"HTTP-Alt"},{59189,"HTTP-Alt"},{59190,"HTTP-Alt"},{59191,"HTTP-Alt"},{59192,"HTTP-Alt"},{59193,"HTTP-Alt"},{59194,"HTTP-Alt"},{59195,"HTTP-Alt"},{59196,"HTTP-Alt"},{59197,"HTTP-Alt"},{59198,"HTTP-Alt"},{59199,"HTTP-Alt"},{59200,"HTTP-Alt"},{0,NULL}
};

static const char* get_service(int port) {
    for (int i = 0; SVC_DB[i].name; ++i)
        if (SVC_DB[i].port == port) return SVC_DB[i].name;
    return "unknown";
}

static void print_json(PortResult* r) {
    printf("RESULT:{\"port\":%d,\"state\":%d,\"service\":\"%s\",\"banner\":\"%s\",\"ttl\":%d,\"window\":%d,\"flags\":\"%s\"}\n",
        r->port, r->state, get_service(r->port), r->banner, r->ttl, r->window_size, r->tcp_flags);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3) {
        fprintf(stderr,"Usage: %s <host> <ports> [timeout_ms] [threads] [mode] [src_port] [ttl] [decoy_ips] [chaos] [scan_delay]\n",argv[0]);
        fprintf(stderr,"  modes: 0=tcp-connect, 1=syn-stealth, 2=fin, 3=xmas, 4=null, 5=ack, 6=window, 7=maimon, 8=protocol-sweep, 9=idle-zombie, 10=anon-self\n");
        return 1;
    }
    ScanContext ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.hostname = argv[1]; ctx.ip = resolve_ip(ctx.hostname);
    if (ctx.ip == 0) { fprintf(stderr,"Failed to resolve hostname\n"); return 1; }
    int ports[131072]; int port_count = parse_ports(argv[2], ports, 131072);
    if (port_count <= 0) { fprintf(stderr,"No valid ports\n"); return 1; }
    ctx.ports = ports; ctx.port_count = port_count;
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : 1500;
    ctx.thread_count = argc > 4 ? atoi(argv[4]) : 16;
    ctx.scan_mode = argc > 5 ? atoi(argv[5]) : 0;
    if (ctx.scan_mode < 0 || ctx.scan_mode > 10) ctx.scan_mode = 0;
    ctx.src_port = argc > 6 ? atoi(argv[6]) : 0;
    ctx.ttl_value = argc > 7 ? atoi(argv[7]) : 0;
    if (argc > 8 && strcmp(argv[8], "none") != 0) {
        char decoy_buf[1024]; strncpy(decoy_buf, argv[8], sizeof(decoy_buf)-1);
        char* d = strtok(decoy_buf, ",");
        while (d && ctx.decoy_count < 32) { ctx.decoys[ctx.decoy_count++] = resolve_ip(d); d = strtok(NULL, ","); }
    }
    ctx.chaos_mode = argc > 9 ? atoi(argv[9]) : 0;
    ctx.scan_delay_us = argc > 10 ? atoi(argv[10]) : 0;
    if (geteuid() != 0 && ctx.scan_mode != 0) {
        fprintf(stderr,"Warning: raw scan modes require root. Falling back to TCP connect.\n");
        ctx.scan_mode = 0;
    }
    pthread_mutex_init(&ctx.result_lock, NULL);
    ctx.src_ip = get_source_ip(ctx.ip);
    struct in_addr ia; ia.s_addr = ctx.ip;
    fprintf(stderr,"SYN_SCANNER target=%s ip=%s ports=%d timeout=%dms threads=%d mode=%s\n",
        ctx.hostname, inet_ntoa(ia), port_count, ctx.timeout_ms, ctx.thread_count, scan_mode_names[ctx.scan_mode]);
    int rc = run_scan(&ctx);
    long long elapsed = now_ms() - ctx.start_time;
    for (int i = 0; i < rc; ++i)
        if (ctx.results[i].state == 1 || ctx.results[i].state == 3)
            print_json(&ctx.results[i]);
    fprintf(stderr,"FINAL:{\"target\":\"%s\",\"total\":%d,\"open\":%d,\"closed\":%d,\"filtered\":%d,\"elapsed_ms\":%lld}\n",
        ctx.hostname, port_count,
        atomic_load(&ctx.open_count), atomic_load(&ctx.closed_count),
        atomic_load(&ctx.filtered_count), elapsed);
    return 0;
}
// vim: ts=4 sw=4 et tw=80
