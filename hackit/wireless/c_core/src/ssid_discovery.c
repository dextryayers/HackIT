#include "web_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#define MAX_DISCOVERED_APS 512
#define FRAME_BUF 8192
#define PROBE_BUF 4096
#define MAX_VENDOR_LEN 32

typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr;

typedef struct __attribute__((packed)) {
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t capabilities;
} beacon_fixed;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int channel;
    int8_t signal_dbm;
    uint16_t capabilities;
    int security_wpa;
    int security_wpa2;
    int security_wpa3;
    int wps;
    char vendor[MAX_VENDOR_LEN];
    int beacon_count;
    int probe_count;
    uint64_t first_seen;
    uint64_t last_seen;
    int is_hidden;
    int is_wmm;
    int is_80211n;
    int is_80211ac;
    int is_80211ax;
} discovered_ap;

static discovered_ap s_discovered[MAX_DISCOVERED_APS];
static int s_discovered_count = 0;
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

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

static int _set_channel(const char* iface, int ch) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d 2>/dev/null", iface, ch);
    return system(cmd);
}

static int _find_ap(const uint8_t* bssid) {
    for (int i = 0; i < s_discovered_count; i++) {
        if (memcmp(s_discovered[i].bssid, bssid, 6) == 0) return i;
    }
    return -1;
}

static int _add_ap(const uint8_t* bssid) {
    if (s_discovered_count >= MAX_DISCOVERED_APS) return -1;
    int idx = s_discovered_count++;
    memcpy(s_discovered[idx].bssid, bssid, 6);
    memset(s_discovered[idx].ssid, 0, 33);
    s_discovered[idx].channel = 0;
    s_discovered[idx].signal_dbm = -100;
    s_discovered[idx].capabilities = 0;
    s_discovered[idx].security_wpa = 0;
    s_discovered[idx].security_wpa2 = 0;
    s_discovered[idx].security_wpa3 = 0;
    s_discovered[idx].wps = 0;
    memset(s_discovered[idx].vendor, 0, MAX_VENDOR_LEN);
    s_discovered[idx].beacon_count = 0;
    s_discovered[idx].probe_count = 0;
    s_discovered[idx].first_seen = 0;
    s_discovered[idx].last_seen = 0;
    s_discovered[idx].is_hidden = 0;
    s_discovered[idx].is_wmm = 0;
    s_discovered[idx].is_80211n = 0;
    s_discovered[idx].is_80211ac = 0;
    s_discovered[idx].is_80211ax = 0;
    return idx;
}

static void _parse_radiotap_signal(const uint8_t* buf, int len, int8_t* signal) {
    *signal = -100;
    if (len < 4) return;
    int rt_len = buf[2] | (buf[3] << 8);
    if (rt_len < 8 || rt_len > len) return;
    uint32_t present = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
    int off = 8;
    if (present & (1 << 0)) off += 8;
    if (present & (1 << 1)) off += 1;
    if (present & (1 << 2)) off += 1;
    if (present & (1 << 3)) off += 4;
    if (present & (1 << 4)) off += 2;
    if (present & (1 << 5) && off < rt_len) { *signal = (int8_t)buf[off]; }
}

static void _extract_vendor_from_oui(const uint8_t* bssid, char* vendor) {
    const struct { const char* prefix; const char* name; } oui_table[] = {
        {"00:50:F2", "Microsoft"}, {"00:1A:11", "Cisco"}, {"00:1B:63", "Netgear"},
        {"00:1C:10", "Netgear"}, {"00:1D:7E", "Linksys"}, {"00:1E:2A", "D-Link"},
        {"00:21:29", "TP-Link"}, {"00:22:6B", "ASUS"}, {"00:23:CD", "Apple"},
        {"00:24:01", "Samsung"}, {"00:24:6C", "Intel"}, {"00:25:86", "Broadcom"},
        {"00:26:5A", "Zyxel"}, {"00:26:86", "Huawei"}, {"00:27:19", "Ruckus"},
        {"00:15:6D", "Apple"}, {"70:73:CB", "Ubiquiti"}, {"74:DA:38", "TP-Link"},
        {"A0:21:B7", "Google"}, {"08:00:27", "Oracle"}, {NULL, NULL}
    };
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X", bssid[0], bssid[1], bssid[2]);
    for (int i = 0; oui_table[i].prefix; i++) {
        if (strncmp(bssid_str, oui_table[i].prefix, 8) == 0) {
            strncpy(vendor, oui_table[i].name, MAX_VENDOR_LEN - 1);
            return;
        }
    }
    strcpy(vendor, "Unknown");
}

static void _parse_beacon_frame(const uint8_t* buf, int len, int ap_idx, int8_t signal_dbm) {
    discovered_ap* ap = &s_discovered[ap_idx];
    ap->signal_dbm = signal_dbm;
    ap->beacon_count++;
    ap->last_seen = (uint64_t)time(NULL);
    if (ap->first_seen == 0) ap->first_seen = ap->last_seen;
    int off = 24 + 12;
    while (off + 2 <= len) {
        int tag = buf[off];
        int tlen = buf[off + 1];
        if (off + 2 + tlen > len) break;
        switch (tag) {
            case 0:
                if (tlen > 0 && tlen <= 32) {
                    memcpy(ap->ssid, buf + off + 2, tlen);
                    ap->ssid[tlen] = '\0';
                }
                break;
            case 1:
                break;
            case 3:
                if (tlen >= 1) ap->channel = buf[off + 2];
                break;
            case 45:
                if (tlen >= 1 && (buf[off + 2] & 0x01)) ap->is_80211n = 1;
                break;
            case 48:
                if (tlen >= 2) {
                    if (buf[off + 2] & 0x20) ap->security_wpa2 = 1;
                    if (buf[off + 2] & 0x10) ap->security_wpa3 = 1;
                    if (tlen >= 4 && (buf[off + 4] & 0x08)) ap->security_wpa3 = 1;
                }
                break;
            case 61:
                ap->is_80211ac = 1;
                break;
            case 255:
                ap->is_80211ax = 1;
                break;
            case 221:
                if (tlen >= 8 && memcmp(buf + off + 2, "\x00\x50\xF2\x04", 4) == 0) {
                    if (buf[off + 6] == 0x10 && buf[off + 7] & 0x01)
                        ap->wps = 1;
                    ap->security_wpa = 1;
                }
                if (tlen >= 4 && memcmp(buf + off + 2, "\x00\x50\xF2\x02", 4) == 0)
                    ap->security_wpa = 1;
                break;
            case 7:
                if (tlen == 1) ap->is_wmm = 1;
                break;
            default:
                break;
        }
        off += 2 + tlen;
    }
}

static void _parse_probe_response_frame(const uint8_t* buf, int len, int ap_idx, int8_t signal_dbm) {
    discovered_ap* ap = &s_discovered[ap_idx];
    ap->signal_dbm = signal_dbm;
    ap->probe_count++;
    ap->last_seen = (uint64_t)time(NULL);
    int off = 24 + 12;
    while (off + 2 <= len) {
        int tag = buf[off];
        int tlen = buf[off + 1];
        if (off + 2 + tlen > len) break;
        if (tag == 0 && tlen > 0 && tlen <= 32) {
            memcpy(ap->ssid, buf + off + 2, tlen);
            ap->ssid[tlen] = '\0';
        }
        off += 2 + tlen;
    }
}

int capture_beacons(const char* iface, int timeout_sec, int channel) {
    if (!iface) return -1;
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    if (channel > 0) _set_channel(iface, channel);
    uint8_t buf[FRAME_BUF];
    uint64_t end = (uint64_t)time(NULL) * 1000 + timeout_sec * 1000;
    int count = 0;
    while ((uint64_t)time(NULL) * 1000 < end) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {0, 100000};
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            if (channel <= 0 && (count % 5 == 0)) {
                static int ch_idx = 0;
                int chs[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
                _set_channel(iface, chs[ch_idx % 14]);
                ch_idx++;
            }
            continue;
        }
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n < 40) continue;
        int rt_len = buf[2] | (buf[3] << 8);
        if (rt_len + 24 > n) continue;
        dot11_hdr* hdr = (dot11_hdr*)(buf + rt_len);
        uint16_t fc = hdr->frame_control;
        if (((fc >> 2) & 0x03) != 0) continue;
        int subtype = (fc >> 4) & 0x0F;
        if (subtype != 8 && subtype != 5) continue;
        int8_t signal;
        _parse_radiotap_signal(buf, n, &signal);
        pthread_mutex_lock(&s_mutex);
        int idx = _find_ap(hdr->addr2);
        if (idx < 0) {
            idx = _add_ap(hdr->addr2);
            if (idx < 0) { pthread_mutex_unlock(&s_mutex); continue; }
            _extract_vendor_from_oui(hdr->addr2, s_discovered[idx].vendor);
        }
        if (subtype == 8)
            _parse_beacon_frame(buf + rt_len, n - rt_len, idx, signal);
        else
            _parse_probe_response_frame(buf + rt_len, n - rt_len, idx, signal);
        count++;
        pthread_mutex_unlock(&s_mutex);
    }
    close(fd);
    return count;
}

int parse_beacon_frame(const uint8_t* frame, int len, discovered_ap* out) {
    if (!frame || len < 36 || !out) return -1;
    static int temp_idx = 0;
    if (temp_idx >= MAX_DISCOVERED_APS) temp_idx = 0;
    int idx = temp_idx++;
    memcpy(s_discovered[idx].bssid, ((dot11_hdr*)frame)->addr2, 6);
    _parse_beacon_frame(frame, len, idx, -100);
    memcpy(out, &s_discovered[idx], sizeof(discovered_ap));
    return 0;
}

int extract_ssid_from_probe(const uint8_t* frame, int len, char* ssid_out, int ssid_max) {
    if (!frame || len < 26 || !ssid_out || ssid_max <= 0) return -1;
    dot11_hdr* hdr = (dot11_hdr*)frame;
    if (((hdr->frame_control >> 4) & 0x0F) != 4) return -1;
    int off = 24;
    while (off + 2 <= len) {
        int tag = frame[off];
        int tlen = frame[off + 1];
        if (off + 2 + tlen > len) break;
        if (tag == 0 && tlen > 0) {
            int cp = tlen < ssid_max - 1 ? tlen : ssid_max - 1;
            memcpy(ssid_out, frame + off + 2, cp);
            ssid_out[cp] = '\0';
            return cp;
        }
        off += 2 + tlen;
    }
    return 0;
}

int discover_all_ssids(const char* iface, int timeout_sec) {
    if (!iface) return -1;
    s_discovered_count = 0;
    int beacon_count = capture_beacons(iface, timeout_sec, 0);
    int hidden_count = 0;
    for (int i = 0; i < s_discovered_count; i++) {
        if (s_discovered[i].ssid[0] == '\0') {
            s_discovered[i].is_hidden = 1;
            hidden_count++;
        }
    }
    printf("{\"discovery\":\"ssid_c\",\"total_aps\":%d,\"hidden_ssids\":%d,\"beacons_captured\":%d,\"aps\":[",
           s_discovered_count, hidden_count, beacon_count);
    for (int i = 0; i < s_discovered_count; i++) {
        discovered_ap* ap = &s_discovered[i];
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        char sec[32] = "OPEN";
        if (ap->security_wpa3) strcpy(sec, "WPA3");
        else if (ap->security_wpa2) strcpy(sec, "WPA2");
        else if (ap->security_wpa) strcpy(sec, "WPA");
        printf("%s{\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%d,\"signal\":%d,"
               "\"security\":\"%s\",\"wps\":%d,\"vendor\":\"%s\",\"hidden\":%d,"
               "\"n\":%d,\"ac\":%d,\"ax\":%d}",
               i > 0 ? "," : "",
               bssid_str,
               ap->ssid[0] ? ap->ssid : "(hidden)",
               ap->channel,
               ap->signal_dbm,
               sec,
               ap->wps,
               ap->vendor,
               ap->is_hidden,
               ap->is_80211n,
               ap->is_80211ac,
               ap->is_80211ax);
    }
    printf("]}\n");
    fflush(stdout);
    return s_discovered_count;
}
