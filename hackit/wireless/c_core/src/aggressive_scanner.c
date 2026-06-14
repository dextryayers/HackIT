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
#include <math.h>

#define MAX_CHANNELS 128
#define FRAME_BUF 8192
#define MAX_SSID_BUF 64
#define SCAN_2GHZ_START 1
#define SCAN_2GHZ_END   14
#define SCAN_5GHZ_START 36
#define SCAN_5GHZ_END   165
#define SCAN_6GHZ_START 1
#define SCAN_6GHZ_END   233
#define EIRP_UNKNOWN -100

typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} dot11_mgmt_hdr;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int channel;
    int8_t signal_dbm;
    int8_t noise_dbm;
    int is_hidden;
    int security_flags;
    uint16_t capabilities;
    uint64_t timestamp;
    int beacon_count;
    int wps;
} ap_entry;

static ap_entry s_aps[256];
static int s_ap_count = 0;
static int s_channels[128];
static int s_num_channels = 0;
static int s_channels_scanned = 0;

static int _raw_socket(const char* iface) {
    struct sockaddr_ll sll;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    int ifindex = ifr.ifr_ifindex;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    return fd;
}

static int _set_channel(const char* iface, int ch) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct iwreq {
        char ifr_name[IFNAMSIZ];
        union {
            struct iw_freq { int m; short e; } freq;
        } u;
    } wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, iface, IFNAMSIZ - 1);
    if (ch <= 14) {
        wrq.u.freq.m = (int)(2412 + (ch - 1) * 5);
        wrq.u.freq.e = 6;
    } else if (ch <= 165) {
        wrq.u.freq.m = (int)(5000 + ch * 5);
        wrq.u.freq.e = 6;
    } else {
        wrq.u.freq.m = (int)(5935 + (ch - 1) * 5);
        wrq.u.freq.e = 6;
    }
    int ret = ioctl(fd, SIOCSIWFREQ, &wrq);
    close(fd);
    return ret;
}

static int _build_channel_list(int band_2ghz, int band_5ghz, int band_6ghz) {
    int n = 0;
    if (band_2ghz) {
        for (int c = SCAN_2GHZ_START; c <= SCAN_2GHZ_END; c++)
            s_channels[n++] = c;
    }
    if (band_5ghz) {
        for (int c = SCAN_5GHZ_START; c <= SCAN_5GHZ_END; c++)
            s_channels[n++] = c;
    }
    if (band_6ghz) {
        for (int c = SCAN_6GHZ_START; c <= SCAN_6GHZ_END; c++)
            s_channels[n++] = c;
    }
    return n;
}

static int _find_or_add_ap(const uint8_t* bssid) {
    for (int i = 0; i < s_ap_count; i++) {
        if (memcmp(s_aps[i].bssid, bssid, 6) == 0)
            return i;
    }
    if (s_ap_count >= 256) return -1;
    int idx = s_ap_count++;
    memcpy(s_aps[idx].bssid, bssid, 6);
    memset(s_aps[idx].ssid, 0, 33);
    s_aps[idx].channel = 0;
    s_aps[idx].signal_dbm = EIRP_UNKNOWN;
    s_aps[idx].noise_dbm = EIRP_UNKNOWN;
    s_aps[idx].is_hidden = 0;
    s_aps[idx].security_flags = 0;
    s_aps[idx].capabilities = 0;
    s_aps[idx].timestamp = 0;
    s_aps[idx].beacon_count = 0;
    s_aps[idx].wps = 0;
    return idx;
}

static void _parse_beacon_tags(const uint8_t* buf, int len, int off, ap_entry* ap) {
    while (off + 2 <= len) {
        int tag = buf[off];
        int tlen = buf[off + 1];
        if (off + 2 + tlen > len) break;
        if (tag == 0 && tlen > 0 && tlen <= 32) {
            memcpy(ap->ssid, buf + off + 2, tlen);
            ap->ssid[tlen] = '\0';
            ap->is_hidden = 0;
        } else if (tag == 0 && tlen == 0) {
            ap->is_hidden = 1;
        } else if (tag == 3 && tlen == 1) {
            ap->channel = buf[off + 2];
        } else if (tag == 48 && tlen >= 2) {
            ap->security_flags |= (buf[off + 2] & 0x20) ? 1 : 0;
            ap->security_flags |= (buf[off + 2] & 0x10) ? 2 : 0;
            if (tlen >= 4 && (buf[off + 4] & 0x08)) ap->security_flags |= 4;
        } else if (tag == 221 && tlen >= 8) {
            if (memcmp(buf + off + 2, "\x00\x50\xF2\x04", 4) == 0) {
                if (buf[off + 6] == 0x10 && buf[off + 7] & 0x01)
                    ap->wps = 1;
            }
        }
        off += 2 + tlen;
    }
}

static void _parse_radiotap_signal(const uint8_t* buf, int len, int8_t* signal, int8_t* noise) {
    *signal = EIRP_UNKNOWN;
    *noise = EIRP_UNKNOWN;
    if (len < 4) return;
    int rt_len = (buf[2]) | (buf[3] << 8);
    if (rt_len < 8 || rt_len > len) return;
    uint32_t present = buf[4] | (buf[5] << 8) | (buf[6] << 16) | (buf[7] << 24);
    int off = 8;
    if (present & (1 << 0)) off += 8;
    if (present & (1 << 1)) off += 1;
    if (present & (1 << 2)) off += 1;
    if (present & (1 << 3)) off += 4;
    if (present & (1 << 4)) off += 2;
    if (present & (1 << 5)) { if (off + 1 <= rt_len) { *signal = (int8_t)buf[off]; } off += 1; }
    if (present & (1 << 6)) { if (off + 1 <= rt_len) { *noise = (int8_t)buf[off]; } off += 1; }
}

int scan_all_channels(const char* iface, int* channels, int num_channels, int dwell_ms) {
    if (!iface || !channels || num_channels <= 0) return -1;
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    s_ap_count = 0;
    s_channels_scanned = 0;
    uint8_t buf[FRAME_BUF];
    for (int ci = 0; ci < num_channels; ci++) {
        int ch = channels[ci];
        _set_channel(iface, ch);
        uint64_t start = (uint64_t)time(NULL) * 1000;
        uint64_t deadline = start + dwell_ms;
        while (1) {
            uint64_t now = (uint64_t)time(NULL) * 1000;
            if (now >= deadline) break;
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv = {0, 50000};
            int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (ret <= 0) continue;
            int n = recv(fd, buf, sizeof(buf), 0);
            if (n < 30) continue;
            int8_t signal, noise;
            _parse_radiotap_signal(buf, n, &signal, &noise);
            int rt_len = (buf[2]) | (buf[3] << 8);
            if (rt_len + 24 > n) continue;
            dot11_mgmt_hdr* mgmt = (dot11_mgmt_hdr*)(buf + rt_len);
            uint16_t fc = mgmt->frame_control;
            int type = (fc >> 2) & 0x03;
            int subtype = (fc >> 4) & 0x0F;
            if (type != 0) continue;
            if (subtype != 8 && subtype != 5 && subtype != 4) continue;
            int idx = _find_or_add_ap(mgmt->addr2);
            if (idx < 0) continue;
            ap_entry* ap = &s_aps[idx];
            if (signal > EIRP_UNKNOWN) {
                ap->signal_dbm = (ap->signal_dbm == EIRP_UNKNOWN) ? signal : (ap->signal_dbm * 3 + signal) / 4;
            }
            if (noise > EIRP_UNKNOWN) ap->noise_dbm = noise;
            ap->capabilities = mgmt->frame_control;
            ap->timestamp = now;
            ap->beacon_count++;
            if (subtype == 8 || subtype == 5) {
                int tag_off = rt_len + 24 + 12;
                _parse_beacon_tags(buf, n, tag_off, ap);
            }
        }
        s_channels_scanned++;
    }
    close(fd);
    return s_ap_count;
}

int detect_hidden_ssid(const char* iface, int timeout_sec) {
    if (!iface) return -1;
    int fd = _raw_socket(iface);
    if (fd < 0) return -1;
    uint64_t end = (uint64_t)time(NULL) * 1000 + timeout_sec * 1000;
    uint8_t buf[FRAME_BUF];
    uint8_t probe_req[32] = {0};
    dot11_mgmt_hdr* probe_hdr = (dot11_mgmt_hdr*)probe_req;
    probe_hdr->frame_control = 0x0040;
    probe_hdr->duration = 0;
    memset(probe_hdr->addr1, 0xFF, 6);
    memset(probe_hdr->addr2, 0x02, 6);
    memset(probe_hdr->addr3, 0xFF, 6);
    probe_req[24] = 0;
    probe_req[25] = 0;
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    int hidden_found = 0;
    while (1) {
        uint64_t now = (uint64_t)time(NULL) * 1000;
        if (now >= end) break;
        sendto(fd, probe_req, 26, 0, (struct sockaddr*)&dest, sizeof(dest));
        for (int ch = 1; ch <= 11; ch++) {
            _set_channel(iface, ch);
            uint64_t ch_end = now + 200;
            while ((uint64_t)time(NULL) * 1000 < ch_end) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(fd, &rfds);
                struct timeval tv = {0, 20000};
                if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
                int n = recv(fd, buf, sizeof(buf), 0);
                if (n < 30) continue;
                int rt_len = (buf[2]) | (buf[3] << 8);
                if (rt_len + 24 > n) continue;
                dot11_mgmt_hdr* mgmt = (dot11_mgmt_hdr*)(buf + rt_len);
                uint16_t fc = mgmt->frame_control;
                if (((fc >> 2) & 0x03) != 0) continue;
                int subtype = (fc >> 4) & 0x0F;
                if (subtype != 8 && subtype != 5) continue;
                int idx = _find_or_add_ap(mgmt->addr2);
                if (idx < 0) continue;
                int tag_off = rt_len + 24 + 12;
                int tag_len = buf[tag_off + 1];
                if (buf[tag_off] == 0 && tag_len == 0 && !s_aps[idx].is_hidden) {
                    s_aps[idx].is_hidden = 1;
                    hidden_found++;
                }
                if (buf[tag_off] == 0 && tag_len > 0 && s_aps[idx].is_hidden) {
                    memcpy(s_aps[idx].ssid, buf + tag_off + 2, tag_len > 32 ? 32 : tag_len);
                    s_aps[idx].ssid[tag_len > 32 ? 32 : tag_len] = '\0';
                    s_aps[idx].is_hidden = 0;
                }
            }
        }
    }
    close(fd);
    return hidden_found;
}

int get_signal_strength(const char* iface, const uint8_t* bssid) {
    if (!iface || !bssid) return EIRP_UNKNOWN;
    int fd = _raw_socket(iface);
    if (fd < 0) return EIRP_UNKNOWN;
    uint8_t buf[FRAME_BUF];
    int samples[8];
    int sample_count = 0;
    uint64_t end = (uint64_t)time(NULL) * 1000 + 1000;
    while ((uint64_t)time(NULL) * 1000 < end && sample_count < 8) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = {0, 100000};
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) continue;
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n < 30) continue;
        int rt_len = (buf[2]) | (buf[3] << 8);
        if (rt_len + 24 > n) continue;
        dot11_mgmt_hdr* mgmt = (dot11_mgmt_hdr*)(buf + rt_len);
        if (memcmp(mgmt->addr2, bssid, 6) != 0 && memcmp(mgmt->addr3, bssid, 6) != 0) continue;
        int8_t signal, noise;
        _parse_radiotap_signal(buf, n, &signal, &noise);
        if (signal > EIRP_UNKNOWN) samples[sample_count++] = signal;
    }
    close(fd);
    if (sample_count == 0) return EIRP_UNKNOWN;
    int sum = 0;
    for (int i = 0; i < sample_count; i++) sum += samples[i];
    return sum / sample_count;
}

void print_results_json(void) {
    printf("{\"scanner\":\"aggressive_c\",\"count\":%d,\"channels_scanned\":%d,\"aps\":[",
           s_ap_count, s_channels_scanned);
    for (int i = 0; i < s_ap_count; i++) {
        ap_entry* ap = &s_aps[i];
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        char security[32] = "OPEN";
        if (ap->security_flags & 1) strcpy(security, "WPA2");
        if (ap->security_flags & 2) strcpy(security, "WPA3");
        if (ap->security_flags & 4) strcpy(security, "WPA2-ENT");
        printf("%s{\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%d,\"signal\":%d,\"noise\":%d,"
               "\"hidden\":%d,\"security\":\"%s\",\"wps\":%d,\"beacons\":%d}",
               i > 0 ? "," : "",
               bssid_str,
               ap->ssid[0] ? ap->ssid : "(hidden)",
               ap->channel,
               ap->signal_dbm,
               ap->noise_dbm,
               ap->is_hidden,
               security,
               ap->wps,
               ap->beacon_count);
    }
    printf("]}\n");
    fflush(stdout);
}

int web_scan(const char* interface, int scan_sec, int band_2ghz, int band_5ghz, int band_6ghz) {
    s_num_channels = _build_channel_list(band_2ghz, band_5ghz, band_6ghz);
    if (s_num_channels == 0) return -1;
    int dwell_ms = (scan_sec * 1000) / s_num_channels;
    if (dwell_ms < 50) dwell_ms = 50;
    int count = scan_all_channels(interface, s_channels, s_num_channels, dwell_ms);
    detect_hidden_ssid(interface, scan_sec / 2 > 5 ? 5 : scan_sec / 2);
    print_results_json();
    return count;
}

int web_attack(const char* interface, const char* attack, const char* bssid, const char* station, int count, int timeout_sec) {
    (void)interface;
    (void)attack;
    (void)bssid;
    (void)station;
    (void)count;
    (void)timeout_sec;
    return -1;
}

int web_get_scan_results(ScanResults* out) {
    if (!out) return -1;
    out->count = s_ap_count;
    out->channels_scanned = s_channels_scanned;
    out->scan_duration_ms = 0;
    for (int i = 0; i < s_ap_count && i < MAX_APS; i++) {
        snprintf(out->results[i].bssid, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
                 s_aps[i].bssid[0], s_aps[i].bssid[1], s_aps[i].bssid[2],
                 s_aps[i].bssid[3], s_aps[i].bssid[4], s_aps[i].bssid[5]);
        memcpy(out->results[i].ssid, s_aps[i].ssid, MAX_SSID_LEN);
        out->results[i].channel = s_aps[i].channel;
        out->results[i].signal_dbm = s_aps[i].signal_dbm;
        out->results[i].noise_dbm = s_aps[i].noise_dbm;
        out->results[i].is_hidden = s_aps[i].is_hidden;
        out->results[i].wps_supported = s_aps[i].wps;
        if (s_aps[i].security_flags & 1) strcpy(out->results[i].encryption, "WPA2");
        else if (s_aps[i].security_flags & 2) strcpy(out->results[i].encryption, "WPA3");
        else strcpy(out->results[i].encryption, "OPEN");
    }
    return s_ap_count;
}

int web_get_attack_result(AttackResult* out) {
    (void)out;
    return -1;
}

int web_scan_all_channels(const char* interface, int* channels, int num_channels, int dwell_ms) {
    return scan_all_channels(interface, channels, num_channels, dwell_ms);
}
