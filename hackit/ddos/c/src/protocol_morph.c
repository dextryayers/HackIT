#include "../include/protocol_morph.h"
#include "../include/engine.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static struct morph_config_t g_morph_cfg;
static __thread int g_morph_initialized = 0;
static __thread unsigned int morph_rng = 0;

static inline unsigned int morph_rand(void) {
    if (morph_rng == 0) morph_rng = (unsigned int)(time(NULL) ^ (uintptr_t)&morph_rng);
    morph_rng = morph_rng * 1103515245U + 12345U;
    return morph_rng;
}

int morph_init(const morph_config_t *cfg)
{
    if (g_morph_initialized == 0) {
        morph_rng = (unsigned int)(time(NULL) ^ (uintptr_t)&morph_rng);
        g_morph_initialized = 1;
    }

    if (cfg) {
        memcpy(&g_morph_cfg, cfg, sizeof(g_morph_cfg));
    } else {
        g_morph_cfg.ttl_min = 64;
        g_morph_cfg.ttl_max = 128;
        g_morph_cfg.window_min = 65535;
        g_morph_cfg.window_max = 65535;
        g_morph_cfg.sack_ok = true;
        g_morph_cfg.timestamp_ok = true;
        g_morph_cfg.nop_ok = true;
        g_morph_cfg.ws_ok = true;
        g_morph_cfg.morph_interval = 0;
    }

    return 0;
}

uint8_t morph_random_ttl(void)
{
    if (!g_morph_initialized)
        morph_init(NULL);

    uint8_t range = g_morph_cfg.ttl_max - g_morph_cfg.ttl_min;
    if (range == 0)
        return g_morph_cfg.ttl_min;

    return g_morph_cfg.ttl_min + (uint8_t)(morph_rand() % (range + 1));
}

uint16_t morph_random_window(void)
{
    if (!g_morph_initialized)
        morph_init(NULL);

    uint16_t range = g_morph_cfg.window_max - g_morph_cfg.window_min;
    if (range == 0)
        return g_morph_cfg.window_min;

    return g_morph_cfg.window_min + (uint16_t)(morph_rand() % (range + 1));
}

int morph_build_options(uint8_t *buf, const tcp_option_t *opts, int nopts)
{
    int offset = 0;

    if (!buf || !opts || nopts <= 0)
        return 0;

    for (int i = 0; i < nopts; i++) {
        if (offset + opts[i].len > 40)
            break;

        buf[offset++] = opts[i].kind;

        if (opts[i].len > 1) {
            buf[offset++] = opts[i].len;
            if (opts[i].len > 2 && opts[i].data[0] != 0) {
                memcpy(&buf[offset], opts[i].data, opts[i].len - 2);
                offset += opts[i].len - 2;
            }
        }
    }

    while (offset % 4 != 0)
        buf[offset++] = TCPOPT_NOP;

    return offset;
}

uint32_t morph_next_sequence(uint32_t current, uint32_t len)
{
    return current + len;
}

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                   */
/* ------------------------------------------------------------------ */

static void morph_build_mss(tcp_option_t *opt)
{
    opt->kind = TCPOPT_MSS;
    opt->len = 4;
    opt->data[0] = (1460 >> 8) & 0xFF;
    opt->data[1] = 1460 & 0xFF;
}

static void morph_build_wscale(tcp_option_t *opt)
{
    opt->kind = TCPOPT_WINDOW;
    opt->len = 3;
    opt->data[0] = 7;
}

static void morph_build_sack_perm(tcp_option_t *opt)
{
    opt->kind = TCPOPT_SACK_PERM;
    opt->len = 2;
}

static void morph_build_timestamp(tcp_option_t *opt)
{
    uint32_t ts = (uint32_t)(time(NULL) & 0xFFFFFFFF);
    uint32_t ts_echo = 0;

    opt->kind = TCPOPT_TIMESTAMP;
    opt->len = 10;
    opt->data[0] = (uint8_t)(ts >> 24);
    opt->data[1] = (uint8_t)(ts >> 16);
    opt->data[2] = (uint8_t)(ts >> 8);
    opt->data[3] = (uint8_t)(ts);
    opt->data[4] = (uint8_t)(ts_echo >> 24);
    opt->data[5] = (uint8_t)(ts_echo >> 16);
    opt->data[6] = (uint8_t)(ts_echo >> 8);
    opt->data[7] = (uint8_t)(ts_echo);
}

static void morph_build_nop(tcp_option_t *opt)
{
    opt->kind = TCPOPT_NOP;
    opt->len = 1;
    opt->data[0] = 0;
}

int morph_build_options_block(uint8_t *buf, int max_len)
{
    tcp_option_t opts[8];
    int nopts = 0;

    if (!buf || max_len < 4)
        return 0;

    if (g_morph_cfg.nop_ok)
        morph_build_nop(&opts[nopts++]);

    morph_build_mss(&opts[nopts++]);

    if (g_morph_cfg.ws_ok)
        morph_build_wscale(&opts[nopts++]);

    if (g_morph_cfg.sack_ok)
        morph_build_sack_perm(&opts[nopts++]);

    if (g_morph_cfg.timestamp_ok)
        morph_build_timestamp(&opts[nopts++]);

    if (g_morph_cfg.nop_ok && (morph_rand() & 1))
        morph_build_nop(&opts[nopts++]);

    return morph_build_options(buf, opts, nopts);
}

int morph_apply(uint8_t *pkt, size_t pkt_len, uint32_t *seq)
{
    if (!pkt || pkt_len < 40)
        return -1;

    struct iphdr {
        uint8_t  ihl : 4;
        uint8_t  version : 4;
        uint8_t  tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    } *ip;

    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t res1 : 4;
        uint16_t doff : 4;
        uint16_t fin : 1;
        uint16_t syn : 1;
        uint16_t rst : 1;
        uint16_t psh : 1;
        uint16_t ack : 1;
        uint16_t urg : 1;
        uint16_t res2 : 2;
        uint16_t window;
        uint16_t check;
        uint16_t urp;
    } *tcp;

    ip = (struct iphdr *)pkt;
    tcp = (struct tcphdr *)(pkt + ((ip->ihl & 0x0F) * 4));

    ip->ttl = morph_random_ttl();
    tcp->window = morph_random_window();

    uint8_t opts[40];
    int opt_len = morph_build_options_block(opts, sizeof(opts));
    if (opt_len > 0) {
        int tcp_hdr_base = sizeof(*tcp);
        int total_tcp_hdr = tcp_hdr_base + opt_len;
        uint8_t *opt_dst = (uint8_t *)(tcp + 1);

        memmove(opt_dst + opt_len, pkt + 40,
                pkt_len - (uint32_t)((uint8_t *)opt_dst - pkt));
        memcpy(opt_dst, opts, opt_len);

        tcp->doff = (uint16_t)(total_tcp_hdr >> 2);
        ip->tot_len = (uint16_t)(pkt_len + opt_len);
    }

    ip->check = 0;

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)ip;
    for (int i = 0; i < 10; i++)
        sum += ptr[i];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = (uint16_t)(~sum & 0xFFFF);

    tcp->check = 0;

    struct pseudo_hdr {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    } ph;

    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.zero = 0;
    ph.protocol = 6;
    ph.tcp_len = (uint16_t)((tcp->doff * 4) +
                   (pkt_len - ((uint8_t *)tcp - pkt + tcp->doff * 4)));

    sum = 0;
    ptr = (uint16_t *)&ph;
    for (int i = 0; i < 6; i++)
        sum += ptr[i];

    int tcp_bytes = (int)(pkt_len - ((uint8_t *)tcp - pkt));
    ptr = (uint16_t *)tcp;
    for (int i = 0; i < (tcp_bytes + 1) / 2; i++)
        sum += ptr[i];

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    tcp->check = (uint16_t)(~sum & 0xFFFF);

    if (seq)
        *seq = tcp->seq;

    return 0;
}

#pragma GCC diagnostic pop
