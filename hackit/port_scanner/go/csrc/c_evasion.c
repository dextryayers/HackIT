#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <signal.h>
#include <poll.h>
#include "optimize.h"

#define MAX_DECOYS 32
#define MAX_BANNER 4096

typedef struct {
    int frag_enabled;
    int mtu;
    int ttl;
    uint32_t spoof_ip;
    int decoy_count;
    uint32_t decoys[MAX_DECOYS];
    int scan_delay_us;
    bool chaos_mode;
    int source_port;
    bool badsum;
} TacticalConfig;

typedef struct PACKED {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
} PseudoHeader;

static ALWAYS_INLINE uint16_t checksum(uint16_t* RESTRICT buf, int len) {
    uint32_t sum = 0;
    int i;
    for (i = 0; i < len / 2; ++i) sum += buf[i];
    if (len & 1) sum += (uint16_t)((unsigned char*)buf)[len - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static ALWAYS_INLINE uint16_t tcp_checksum(struct tcphdr* RESTRICT tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    PseudoHeader pseudo;
    char buf[sizeof(PseudoHeader) + sizeof(struct tcphdr)];
    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.saddr = saddr; pseudo.daddr = daddr;
    pseudo.protocol = IPPROTO_TCP; pseudo.tcp_len = htons((uint16_t)tcp_len);
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &pseudo, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum((uint16_t*)buf, sizeof(PseudoHeader) + tcp_len);
}

static HOT uint32_t resolve_ip(const char* RESTRICT host) {
    struct in_addr a;
    if (likely(inet_pton(AF_INET, host, &a) == 1)) return a.s_addr;
    struct hostent* he = gethostbyname(host);
    if (unlikely(!he || !he->h_addr_list[0])) return 0;
    memcpy(&a.s_addr, he->h_addr_list[0], 4);
    return a.s_addr;
}

static FLATTEN int create_raw_socket(void) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (unlikely(sock < 0)) return -1;
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    return sock;
}

static HOT void send_tcp_packet(int raw_sock, uint32_t src, uint32_t dst, int sport, int dport,
                            int ttl, bool syn, bool ack, bool fin, bool rst, bool badsum,
                            int frag_mtu) {
    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr* ip;
    struct tcphdr* tcp;
    struct sockaddr_in to;
    memset(pkt, 0, sizeof(pkt));
    ip = (struct iphdr*)pkt;
    tcp = (struct tcphdr*)(pkt + sizeof(struct iphdr));
    ip->ihl = 5; ip->version = 4; ip->tos = 0;
    ip->tot_len = htons(sizeof(pkt));
    ip->id = htons((uint16_t)(rand() & 0xFFFF));

    ip->frag_off = htons((frag_mtu > 0 && frag_mtu < (int)sizeof(pkt)) ? 0x2001 : 0x4000);

    ip->ttl = ttl > 0 ? ttl : 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src;
    ip->daddr = dst;
    ip->check = 0;

    tcp->source = htons((uint16_t)sport);
    tcp->dest = htons((uint16_t)dport);
    tcp->seq = htonl((uint32_t)(rand() | (rand() << 16)));
    if (ack) tcp->ack_seq = htonl((uint32_t)(rand() | (rand() << 16)));
    tcp->doff = 5;
    tcp->syn = syn ? 1 : 0;
    tcp->ack = ack ? 1 : 0;
    tcp->fin = fin ? 1 : 0;
    tcp->rst = rst ? 1 : 0;
    tcp->window = htons(65535);

    tcp->check = badsum ? 0xFFFF : tcp_checksum(tcp, sizeof(struct tcphdr), src, dst);

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = dst;
    sendto(raw_sock, pkt, sizeof(pkt), 0, (struct sockaddr*)&to, sizeof(to));
}

HOT int send_tactical_probe(const char* RESTRICT target_ip, int port, TacticalConfig config) {
    uint32_t dst;
    int rs, sport, d;
    uint32_t src_ip;
    int ttl_val;
    uint32_t ds;

    dst = resolve_ip(target_ip);
    if (unlikely(dst == 0)) { fprintf(stderr, "Failed to resolve target\n"); return -1; }
    rs = create_raw_socket();
    if (unlikely(rs < 0)) { fprintf(stderr, "Raw socket requires root\n"); return -1; }
    sport = config.source_port > 0 ? config.source_port : (10000 + rand() % 55535);
    src_ip = config.spoof_ip ? config.spoof_ip : htonl(0x01010101);
    ttl_val = config.ttl > 0 ? config.ttl : 64;
    if (config.chaos_mode) ttl_val = 32 + (rand() % 96);

    send_tcp_packet(rs, src_ip, dst, sport, port, ttl_val, true, false, false, false,
                    config.badsum, config.mtu);

    if (config.decoy_count > 0) {
        for (d = 0; d < config.decoy_count; d++) {
            ds = (uint32_t)(10000 + (rand() % 55535));
            send_tcp_packet(rs, config.decoys[d], dst, (int)ds, port, ttl_val, true, false, false, false,
                            config.badsum, config.mtu);
        }
    }

    if (config.scan_delay_us > 0) {
        struct timespec ts;
        ts.tv_sec = config.scan_delay_us / 1000000;
        ts.tv_nsec = (config.scan_delay_us % 1000000) * 1000;
        nanosleep(&ts, NULL);
    }
    close(rs);
    return 0;
}

HOT int ghost_protocol_scan(const char* RESTRICT target_ip, int start_port, int end_port, TacticalConfig config) {
    int rs, port, frag, sport, d;
    uint32_t dst;
    uint32_t src_ip;
    int ttl_val;
    struct timespec ts;
    ts.tv_sec = config.scan_delay_us / 1000000;
    ts.tv_nsec = (config.scan_delay_us % 1000000) * 1000;

    fprintf(stderr, "GHOST: scanning %s ports %d-%d with frag=%d mtu=%d decoys=%d chaos=%d\n",
        target_ip, start_port, end_port, config.frag_enabled, config.mtu,
        config.decoy_count, config.chaos_mode);
    rs = create_raw_socket();
    if (unlikely(rs < 0)) return -1;
    dst = resolve_ip(target_ip);
    if (unlikely(dst == 0)) { close(rs); return -1; }
    src_ip = config.spoof_ip ? config.spoof_ip : htonl(0x0A000001);
    ttl_val = config.ttl > 0 ? config.ttl : 64;

    for (port = start_port; port <= end_port; port++) {
        if (config.chaos_mode) ttl_val = 32 + (rand() % 96);
        frag = config.frag_enabled ? (config.mtu > 0 ? config.mtu : 32) : 0;
        sport = config.source_port > 0 ? config.source_port : (10000 + rand() % 55535);
        send_tcp_packet(rs, src_ip, dst, sport, port, ttl_val, true, false, false, false,
                        config.badsum, frag);
        if (config.decoy_count > 0) {
            for (d = 0; d < config.decoy_count; d++) {
                send_tcp_packet(rs, config.decoys[d], dst, 10000+(rand()%55535), port, ttl_val,
                                true, false, false, false, config.badsum, frag);
            }
        }
        if (config.scan_delay_us > 0) nanosleep(&ts, NULL);
    }
    close(rs);
    return 0;
}

FLATTEN void apply_chaos_headers(TacticalConfig* config) {
    config->ttl = 32 + (rand() % 96);
    if (likely(config->frag_enabled)) {
        config->mtu = 8 + (rand() % 128);
    }
}

TacticalConfig default_tactical_config(void) {
    TacticalConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.frag_enabled = 0;
    cfg.mtu = 0;
    cfg.ttl = 64;
    cfg.decoy_count = 0;
    cfg.scan_delay_us = 0;
    cfg.chaos_mode = 0;
    cfg.source_port = 0;
    cfg.badsum = 0;
    cfg.spoof_ip = 0;
    return cfg;
}

static int fast_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9')
        n = n * 10 + (*s++ - '0');
    return n;
}

HOT int main(int argc, char** argv) {
    int mode, ret, port, sp, ep;
    char *dash, *d;
    char buf[1024];
    TacticalConfig cfg;

    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)time(NULL));
    if (unlikely(argc < 4)) {
        fprintf(stderr, "Usage: %s <target> <mode> <ports> [ttl] [frag] [mtu] [src_port] [decoy_ips] [chaos] [badsum]\n", argv[0]);
        fprintf(stderr, "  modes: 1=tactical-probe, 2=ghost-scan, 3=chaos-scan\n");
        return 1;
    }
    cfg = default_tactical_config();
    mode = fast_atoi(argv[2]);
    if (argc > 4) cfg.ttl = fast_atoi(argv[4]);
    if (argc > 5) cfg.frag_enabled = fast_atoi(argv[5]);
    if (argc > 6) cfg.mtu = fast_atoi(argv[6]);
    if (argc > 7) cfg.source_port = fast_atoi(argv[7]);
    if (argc > 8 && (argv[8][0] != 'n' || argv[8][1] != 'o' || argv[8][2] != 'n' || argv[8][3] != 'e' || argv[8][4] != '\0')) {
        strncpy(buf, argv[8], sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        d = strtok(buf, ",");
        while (d && cfg.decoy_count < 32) { cfg.decoys[cfg.decoy_count++] = resolve_ip(d); d = strtok(NULL, ","); }
    }
    if (argc > 9) cfg.chaos_mode = fast_atoi(argv[9]);
    if (argc > 10) cfg.badsum = fast_atoi(argv[10]);
    if (cfg.chaos_mode) apply_chaos_headers(&cfg);
    ret = 0;
    if (mode == 1) {
        port = fast_atoi(argv[3]);
        ret = send_tactical_probe(argv[1], port, cfg);
        printf("RESULT:{\"mode\":\"tactical-probe\",\"target\":\"%s\",\"port\":%d,\"status\":%d}\n", argv[1], port, ret);
    } else if (mode == 2 || mode == 3) {
        dash = strchr(argv[3], '-');
        if (dash) { sp = fast_atoi(argv[3]); ep = fast_atoi(dash + 1); }
        else sp = ep = fast_atoi(argv[3]);
        ret = ghost_protocol_scan(argv[1], sp, ep, cfg);
        printf("RESULT:{\"mode\":\"%s\",\"target\":\"%s\",\"ports\":\"%d-%d\",\"status\":%d}\n",
            mode == 2 ? "ghost" : "chaos", argv[1], sp, ep, ret);
    }
    fprintf(stderr, "FINAL:{\"target\":\"%s\",\"mode\":%d,\"result\":%d}\n", argv[1], mode, ret);
    return ret == 0 ? 0 : 1;
}

// vim: ts=4 sw=4 et tw=80
