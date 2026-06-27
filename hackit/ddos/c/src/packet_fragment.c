#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>

#define MAX_FRAGMENTS 64
#define MIN_FRAG_SIZE 48

static int g_fragment_mtu = 1500;
static uint64_t g_frag_sent = 0;
static uint64_t g_frag_dropped = 0;
static uint16_t g_frag_ip_id = 0;
static char g_frag_err[256] = {0};

static __thread unsigned int frag_seed = 0;

static unsigned int frag_rand(void)
{
    if (frag_seed == 0) frag_seed = (unsigned int)(time(NULL) ^ (uintptr_t)&frag_seed);
    frag_seed = frag_seed * 1103515245U + 12345U;
    return frag_seed;
}

static int build_fragment(unsigned char *out, int out_max,
    uint32_t src, uint32_t dst, uint8_t proto,
    const unsigned char *payload, int payload_len,
    int offset, int more_frags, uint16_t ip_id, uint8_t ttl)
{
    int ip_hdr_len = sizeof(struct iphdr);
    int total_len = ip_hdr_len + payload_len;

    if (total_len > out_max) return -1;

    memset(out, 0, (size_t)total_len);
    struct iphdr *ip = (struct iphdr *)out;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)total_len);
    ip->id = htons(ip_id);
    ip->ttl = ttl;
    ip->protocol = proto;
    ip->saddr = src;
    ip->daddr = dst;

    uint16_t frag_off = (uint16_t)((offset / 8) & 0x1FFF);
    if (more_frags) frag_off |= 0x2000;
    ip->frag_off = htons(frag_off);

    memcpy(out + ip_hdr_len, payload, (size_t)payload_len);

    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip; for (int i = 0; i < 10; i++) s += p[i]; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); ip->check = ~s & 0xFFFF; }

    return total_len;
}

EXPORT int fragment_init(int mtu)
{
    if (mtu < 68) mtu = 68;
    if (mtu > 65535) mtu = 65535;

    g_fragment_mtu = mtu;
    g_frag_sent = 0;
    g_frag_dropped = 0;
    g_frag_ip_id = (uint16_t)(frag_rand() & 0xFFFF);
    frag_seed = g_frag_ip_id + (unsigned int)time(NULL);

    return 0;
}

EXPORT int fragment_ip_packet(unsigned char *packet, int pkt_len,
    unsigned char **frags, int *frag_counts, uint16_t ip_id)
{
    if (!packet || !frags || !frag_counts || pkt_len <= 0) {
        snprintf(g_frag_err, sizeof(g_frag_err), "invalid arguments");
        return -1;
    }

    if (pkt_len <= g_fragment_mtu) {
        frags[0] = (unsigned char *)malloc((size_t)pkt_len);
        if (!frags[0]) {
            snprintf(g_frag_err, sizeof(g_frag_err), "malloc: %s", strerror(errno));
            return -1;
        }
        memcpy(frags[0], packet, (size_t)pkt_len);
        *frag_counts = 1;
        return 1;
    }

    int ip_hdr_len = sizeof(struct iphdr);
    int payload_offset = ip_hdr_len;
    int total_payload = pkt_len - payload_offset;
    int max_frag_payload = g_fragment_mtu - ip_hdr_len;

    if (max_frag_payload < MIN_FRAG_SIZE) max_frag_payload = MIN_FRAG_SIZE;

    int frag_count = 0;
    int remaining = total_payload;
    int offset = 0;
    uint16_t id = (ip_id != 0) ? ip_id : g_frag_ip_id++;

    while (remaining > 0 && frag_count < MAX_FRAGMENTS) {
        int frag_payload;
        int is_last = (remaining <= max_frag_payload);

        if (is_last) {
            frag_payload = remaining;
        } else {
            frag_payload = MIN_FRAG_SIZE + (int)(frag_rand() % (max_frag_payload - MIN_FRAG_SIZE + 1));
            if (frag_payload > remaining - MIN_FRAG_SIZE)
                frag_payload = remaining - MIN_FRAG_SIZE;
            if (frag_payload < MIN_FRAG_SIZE)
                frag_payload = MIN_FRAG_SIZE;
            if (frag_payload > max_frag_payload)
                frag_payload = max_frag_payload;
        }

        int frag_pkt_len = ip_hdr_len + frag_payload;
        frags[frag_count] = (unsigned char *)malloc((size_t)frag_pkt_len);
        if (!frags[frag_count]) {
            for (int j = 0; j < frag_count; j++) free(frags[j]);
            snprintf(g_frag_err, sizeof(g_frag_err), "malloc frag: %s", strerror(errno));
            return -1;
        }

        struct iphdr *orig_ip = (struct iphdr *)packet;
        uint8_t ttl = (uint8_t)(64 + (frag_rand() % 32));

        build_fragment(frags[frag_count], frag_pkt_len,
            orig_ip->saddr, orig_ip->daddr, orig_ip->protocol,
            packet + payload_offset + offset, frag_payload,
            offset, !is_last, id, ttl);

        offset += frag_payload;
        remaining -= frag_payload;
        frag_count++;
    }

    *frag_counts = frag_count;
    return frag_count;
}

EXPORT void fragment_randomize(unsigned char **frags, int frag_count)
{
    if (!frags || frag_count <= 1) return;

    for (int i = frag_count - 1; i > 0; i--) {
        int j = (int)(frag_rand() % (unsigned int)(i + 1));
        unsigned char *tmp = frags[i];
        frags[i] = frags[j];
        frags[j] = tmp;
    }
}

EXPORT void fragment_interleave(unsigned char **frags, int frag_count, int delay_ms)
{
    (void)frags;
    (void)frag_count;
    (void)delay_ms;
}

EXPORT void fragment_free(unsigned char **frags, int frag_count)
{
    if (!frags) return;
    for (int i = 0; i < frag_count; i++) {
        if (frags[i]) {
            free(frags[i]);
            frags[i] = NULL;
        }
    }
}

EXPORT void fragment_stats(uint64_t *sent, uint64_t *dropped)
{
    if (sent) *sent = g_frag_sent;
    if (dropped) *dropped = g_frag_dropped;
}
