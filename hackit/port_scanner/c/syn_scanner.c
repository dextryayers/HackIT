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

#define MAX_PORTS         131072
#define MAX_BANNER        8192
#define MAX_WORKERS       64
#define TIMEOUT_MS        1500
#define SYNC_INTERVAL_US  50
#define EPOLL_MAX_EVENTS  65536
#define MAX_RETRIES       2
#define BANNER_READ_TIME  500

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
    PortResult  results[MAX_PORTS];
    atomic_int  result_count;
    pthread_mutex_t result_lock;
    int         scan_mode;
    int         raw_sock;
    int         epoll_fd;
    bool        running;
    long long   start_time;
} ScanContext;

enum {
    SCAN_TCP_CONNECT = 0,
    SCAN_SYN_STEALTH = 1,
    SCAN_FIN = 2,
    SCAN_XMAS = 3,
    SCAN_NULL = 4,
    SCAN_ACK = 5,
    SCAN_WINDOW = 6,
    SCAN_MAIMON = 7,
};

static const char* scan_mode_names[] = {
    "tcp-connect", "syn-stealth", "fin", "xmas",
    "null", "ack", "window", "maimon"
};

typedef struct {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
} PseudoHeader;

static uint16_t checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(struct tcphdr* tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.saddr = saddr;
    pseudo.daddr = daddr;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_len = htons(tcp_len);
    char buf[sizeof(PseudoHeader) + tcp_len];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(PseudoHeader) + tcp_len);
}

static int create_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock >= 0) {
            int one = 1;
            setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        }
    }
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        struct timeval tv = {0, 1000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return sock;
}

static int create_icmp_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock >= 0) {
        struct timeval tv = {0, 500000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return sock;
}

static uint32_t resolve_ip(const char* hostname) {
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1)
        return addr.s_addr;
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

static void send_syn_packet(int raw_sock, uint32_t src, uint32_t dst, int port, int src_port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src;
    ip->daddr = dst;
    tcp->source = htons((uint16_t)src_port);
    tcp->dest = htons((uint16_t)port);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = dst;
    sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&to, sizeof(to));
}

static void send_fin_packet(int raw_sock, uint32_t src, uint32_t dst, int port, int src_port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = src; ip->daddr = dst;
    tcp->source = htons((uint16_t)src_port);
    tcp->dest = htons((uint16_t)port);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5; tcp->fin = 1;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_addr.s_addr = dst;
    sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&to, sizeof(to));
}

static void send_xmas_packet(int raw_sock, uint32_t src, uint32_t dst, int port, int src_port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = src; ip->daddr = dst;
    tcp->source = htons((uint16_t)src_port);
    tcp->dest = htons((uint16_t)port);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5; tcp->fin = 1; tcp->urg = 1; tcp->psh = 1;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_addr.s_addr = dst;
    sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&to, sizeof(to));
}

static void send_null_packet(int raw_sock, uint32_t src, uint32_t dst, int port, int src_port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = src; ip->daddr = dst;
    tcp->source = htons((uint16_t)src_port);
    tcp->dest = htons((uint16_t)port);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_addr.s_addr = dst;
    sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&to, sizeof(to));
}

static void send_ack_packet(int raw_sock, uint32_t src, uint32_t dst, int port, int src_port) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    struct iphdr* ip = (struct iphdr*)packet;
    struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = src; ip->daddr = dst;
    tcp->source = htons((uint16_t)src_port);
    tcp->dest = htons((uint16_t)port);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->ack_seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5; tcp->ack = 1;
    tcp->window = htons(65535);
    tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to)); to.sin_family = AF_INET; to.sin_addr.s_addr = dst;
    sendto(raw_sock, packet, sizeof(packet), 0, (struct sockaddr*)&to, sizeof(to));
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int parse_ports(const char* spec, int* ports, int max) {
    int count = 0;
    if (!spec) return 0;
    char buf[65536];
    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    if (strcmp(buf, "top100") == 0 || strcmp(buf, "top:100") == 0) {
        int top[] = {7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49154,0};
        for (int i = 0; top[i] && count < max; i++) ports[count++] = top[i];
        return count;
    }
    if (strcmp(buf, "all") == 0) {
        for (int p = 1; p <= 65535 && count < max; p++) ports[count++] = p;
        return count;
    }
    char* token = strtok(buf, ",");
    while (token && count < max) {
        char* dash = strchr(token, '-');
        if (dash) {
            int s = atoi(token), e = atoi(dash + 1);
            if (s < 1) s = 1; if (e > 65535) e = 65535;
            for (int p = s; p <= e && count < max; p++) ports[count++] = p;
        } else { int p = atoi(token); if (p >= 1 && p <= 65535) ports[count++] = p; }
        token = strtok(NULL, ",");
    }
    return count;
}

static int connect_port(uint32_t ip, int port, int timeout_ms, char* banner, int banner_size) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip;
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) return 2;
    int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) { close(sock); return 0; }
    struct epoll_event ev;
    int epfd = epoll_create1(0);
    if (epfd < 0) { close(sock); return 2; }
    ev.data.fd = sock;
    ev.events = EPOLLOUT | EPOLLERR;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
    struct epoll_event events[1];
    rc = epoll_wait(epfd, events, 1, timeout_ms);
    close(epfd);
    if (rc <= 0) { close(sock); return rc == 0 ? 2 : 0; }
    int so_err = 0;
    socklen_t err_len = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &err_len);
    if (so_err != 0) { close(sock); return so_err == ECONNREFUSED ? 0 : 2; }
    if (banner && banner_size > 0) {
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
        struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        int total = 0;
        char tmp[MAX_BANNER];
        memset(tmp, 0, sizeof(tmp));
        for (int attempt = 0; attempt < 2 && total < MAX_BANNER - 1; attempt++) {
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n; else break;
        }
        if (total == 0 && (port == 80 || port == 8080 || port == 443 || port == 8443 || port == 8000 || port == 8888)) {
            const char* req = "GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-SYN/1.0\r\n\r\n";
            write(sock, req, strlen(req));
            usleep(100000);
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n;
        } else if (total == 0 && port == 21) {
            usleep(50000);
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n;
            if (total > 0) {
                write(sock, "SYST\r\n", 6);
                usleep(100000);
                n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
                if (n > 0) total += n;
            }
        } else if (total == 0 && (port == 25 || port == 587)) {
            usleep(50000);
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n;
            if (total > 0) {
                write(sock, "EHLO hackit.local\r\n", 19);
                usleep(100000);
                n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
                if (n > 0) total += n;
            }
        } else if (total == 0 && port == 6379) {
            write(sock, "INFO server\r\n", 13);
            usleep(100000);
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n;
        } else if (total == 0 && port == 11211) {
            write(sock, "stats\r\n", 7);
            usleep(100000);
            int n = (int)read(sock, tmp + total, MAX_BANNER - 1 - total);
            if (n > 0) total += n;
        }
        if (total > 0) {
            tmp[total] = 0;
            int out = 0;
            for (int i = 0; i < total && out < banner_size - 1; i++) {
                char c = tmp[i];
                if (c == '\r') continue;
                if (c == '\n') { if (out > 0 && banner[out-1] != ' ') banner[out++] = ' '; continue; }
                if (c >= 32 && c < 127) banner[out++] = c;
            }
            banner[out] = 0;
        }
    }
    close(sock);
    return 1;
}

static void listen_for_synack(int raw_sock, ScanContext* ctx, int epoll_timeout_ms) {
    char buf[65536];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    long long deadline = now_ms() + epoll_timeout_ms;
    while (now_ms() < deadline) {
        int n = recvfrom(raw_sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&from, &from_len);
        if (n <= 0) { usleep(100); continue; }
        if (n < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
        struct iphdr* ip = (struct iphdr*)buf;
        if (ip->protocol != IPPROTO_TCP) continue;
        int ip_hdr_len = ip->ihl * 4;
        struct tcphdr* tcp = (struct tcphdr*)(buf + ip_hdr_len);
        int tcp_len = n - ip_hdr_len;
        if (tcp_len < (int)sizeof(struct tcphdr)) continue;
        int dst_port = ntohs(tcp->dest);
        int src_port = ntohs(tcp->source);
        if (tcp->syn && tcp->ack) {
            int idx = atomic_fetch_add(&ctx->result_count, 1);
            if (idx < MAX_PORTS) {
                PortResult* r = &ctx->results[idx];
                memset(r, 0, sizeof(PortResult));
                r->port = dst_port;
                r->state = 1;
                r->ttl = ip->ttl;
                r->window_size = ntohs(tcp->window);
                strcpy(r->tcp_flags, "SYN/ACK");
                struct in_addr ia; ia.s_addr = from.sin_addr.s_addr;
                strncpy(r->ip, inet_ntoa(ia), sizeof(r->ip) - 1);
                atomic_fetch_add(&ctx->open_count, 1);
            }
        } else if (tcp->rst) {
            bool found = false;
            for (int i = 0; i < ctx->port_count; i++) {
                if (ctx->ports[i] == dst_port) { found = true; break; }
            }
            if (found) {
                int idx = atomic_fetch_add(&ctx->result_count, 1);
                if (idx < MAX_PORTS) {
                    PortResult* r = &ctx->results[idx];
                    memset(r, 0, sizeof(PortResult));
                    r->port = dst_port;
                    r->state = 0;
                    r->ttl = ip->ttl;
                    strcpy(r->tcp_flags, "RST");
                    atomic_fetch_add(&ctx->closed_count, 1);
                }
            }
        }
    }
}

static void* syn_scan_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    int raw_sock = create_raw_socket();
    if (raw_sock < 0) return NULL;
    uint32_t src_ip = get_source_ip(ctx->ip);
    srand((unsigned int)(time(NULL) ^ (uintptr_t)pthread_self()));
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        int port = ctx->ports[idx];
        int src_port = 10000 + (rand() % 55535);
        switch (ctx->scan_mode) {
            case SCAN_SYN_STEALTH: send_syn_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
            case SCAN_FIN: send_fin_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
            case SCAN_XMAS: send_xmas_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
            case SCAN_NULL: send_null_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
            case SCAN_ACK: send_ack_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
            default: send_syn_packet(raw_sock, src_ip, ctx->ip, port, src_port); break;
        }
        if (idx % 256 == 0) usleep(SYNC_INTERVAL_US);
    }
    listen_for_synack(raw_sock, ctx, ctx->timeout_ms + 500);
    close(raw_sock);
    return NULL;
}

static void* connect_scan_worker(void* arg) {
    ScanContext* ctx = (ScanContext*)arg;
    while (1) {
        int idx = atomic_fetch_add(&ctx->next_idx, 1);
        if (idx >= ctx->port_count) break;
        int port = ctx->ports[idx];
        char banner[MAX_BANNER] = {0};
        int state = connect_port(ctx->ip, port, ctx->timeout_ms, banner, sizeof(banner));
        int ri = atomic_fetch_add(&ctx->result_count, 1);
        if (ri < MAX_PORTS) {
            PortResult* r = &ctx->results[ri];
            memset(r, 0, sizeof(PortResult));
            r->port = port;
            r->state = state;
            strncpy(r->banner, banner, sizeof(r->banner) - 1);
            if (state == 1) atomic_fetch_add(&ctx->open_count, 1);
            else if (state == 0) atomic_fetch_add(&ctx->closed_count, 1);
            else atomic_fetch_add(&ctx->filtered_count, 1);
        }
        if (idx % 64 == 0) sched_yield();
    }
    return NULL;
}

static int run_scan(ScanContext* ctx) {
    pthread_t threads[MAX_WORKERS];
    int n_threads = ctx->thread_count;
    if (n_threads > MAX_WORKERS) n_threads = MAX_WORKERS;
    if (n_threads > ctx->port_count) n_threads = ctx->port_count;
    if (n_threads < 1) n_threads = 1;
    ctx->start_time = now_ms();
    ctx->running = true;
    for (int i = 0; i < n_threads; i++)
        pthread_create(&threads[i], NULL,
            ctx->scan_mode == SCAN_TCP_CONNECT ? connect_scan_worker : syn_scan_worker, ctx);
    for (int i = 0; i < n_threads; i++)
        pthread_join(threads[i], NULL);
    return atomic_load(&ctx->result_count);
}

typedef struct { int port; const char* name; } SvcEntry;

static const SvcEntry SVC_DB[] = {
    {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},{53,"DNS"},{80,"HTTP"},{110,"POP3"},{111,"RPC"},{135,"MSRPC"},{139,"NetBIOS"},{143,"IMAP"},{161,"SNMP"},{179,"BGP"},{389,"LDAP"},{443,"HTTPS"},{445,"SMB"},{465,"SMTPS"},{514,"Syslog"},{587,"SMTP-MSA"},{636,"LDAPS"},{873,"RSYNC"},{990,"FTPS"},{992,"Telnets"},{993,"IMAPS"},{995,"POP3S"},{1080,"SOCKS"},{1194,"OpenVPN"},{1352,"LotusNotes"},{1433,"MSSQL"},{1521,"Oracle"},{1723,"PPTP"},{2049,"NFS"},{2375,"Docker"},{2376,"Docker-TLS"},{2379,"etcd"},{3128,"Squid"},{3306,"MySQL"},{3389,"RDP"},{3690,"SVN"},{4369,"EPMD"},{5432,"PostgreSQL"},{5672,"AMQP"},{5900,"VNC"},{5984,"CouchDB"},{5985,"WinRM"},{6379,"Redis"},{6443,"K8s-API"},{8080,"HTTP-Proxy"},{8443,"HTTPS-Alt"},{8500,"Consul"},{9090,"Prometheus"},{9092,"Kafka"},{9200,"Elasticsearch"},{9418,"Git"},{10250,"Kubelet"},{11211,"Memcached"},{15672,"RabbitMQ"},{25565,"Minecraft"},{27017,"MongoDB"},{32400,"Plex"},{0,NULL}
};

static const char* get_service(int port) {
    for (int i = 0; SVC_DB[i].name; i++)
        if (SVC_DB[i].port == port) return SVC_DB[i].name;
    return "unknown";
}

static void print_json_result(PortResult* r) {
    printf("RESULT:{\"port\":%d,\"state\":%d,\"service\":\"%s\",\"banner\":\"%s\",\"product\":\"%s\",\"version\":\"%s\",\"os_hint\":\"%s\",\"confidence\":%.2f,\"risk_score\":%.2f,\"ttl\":%d,\"window\":%d,\"flags\":\"%s\"}\n",
        r->port, r->state, get_service(r->port), r->banner, r->product, r->version,
        r->os_hint, r->confidence, r->risk_score, r->ttl, r->window_size, r->tcp_flags);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <ports> [timeout_ms] [threads] [mode]\n", argv[0]);
        fprintf(stderr, "  modes: 0=tcp-connect, 1=syn-stealth, 2=fin, 3=xmas, 4=null, 5=ack\n");
        fprintf(stderr, "Example: %s 192.168.1.1 22,80,443,1-1000 1500 32 1\n", argv[0]);
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "Warning: SYN scan requires root. Falling back to TCP connect.\n");
    }
    ScanContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.hostname = argv[1];
    ctx.ip = resolve_ip(ctx.hostname);
    if (ctx.ip == 0) { fprintf(stderr, "Failed to resolve hostname\n"); return 1; }
    int ports[MAX_PORTS];
    int port_count = parse_ports(argv[2], ports, MAX_PORTS);
    if (port_count <= 0) { fprintf(stderr, "No valid ports\n"); return 1; }
    ctx.ports = ports;
    ctx.port_count = port_count;
    ctx.timeout_ms = argc > 3 ? atoi(argv[3]) : TIMEOUT_MS;
    ctx.thread_count = argc > 4 ? atoi(argv[4]) : 16;
    ctx.scan_mode = argc > 5 ? atoi(argv[5]) : SCAN_TCP_CONNECT;
    if (ctx.scan_mode < 0 || ctx.scan_mode > SCAN_MAIMON) ctx.scan_mode = SCAN_TCP_CONNECT;
    pthread_mutex_init(&ctx.result_lock, NULL);
    struct in_addr ia; ia.s_addr = ctx.ip;
    fprintf(stderr, "SYN_SCANNER target=%s ip=%s ports=%d timeout=%dms threads=%d mode=%s\n",
        ctx.hostname, inet_ntoa(ia), port_count, ctx.timeout_ms, ctx.thread_count,
        scan_mode_names[ctx.scan_mode]);
    int rc = run_scan(&ctx);
    long long elapsed = now_ms() - ctx.start_time;
    for (int i = 0; i < rc; i++) {
        if (ctx.results[i].state == 1)
            print_json_result(&ctx.results[i]);
    }
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"total\":%d,\"open\":%d,\"closed\":%d,\"filtered\":%d,\"elapsed_ms\":%lld}\n",
        ctx.hostname, port_count,
        atomic_load(&ctx.open_count), atomic_load(&ctx.closed_count),
        atomic_load(&ctx.filtered_count), elapsed);
    return 0;
}
