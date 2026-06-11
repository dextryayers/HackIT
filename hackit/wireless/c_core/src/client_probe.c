#include "client_probe.h"
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

#define HACKIT_80211_RADIOTAP_LEN 12
#define HACKIT_80211_MGMT_HDR_LEN 24
#define HACKIT_80211_ADDR_LEN 6

/* ------------------------------------------------------------------ */

int hackit_parse_probe_request(const uint8_t* frame, size_t len, char* ssid_out, size_t ssid_out_len, uint8_t* sta_mac) {
    if (!frame || len < 24)
        return -1;

    /* Check for Probe Request: type=0, subtype=4 => 0x40 */
    if ((frame[0] & 0xFC) != 0x40)
        return 0;

    /* Offset to skip radiotap if present at start */
    size_t radiotap_len = 0;

    if (len > 12 && frame[0] == 0x00 && frame[1] == 0x00 && frame[2] == 0x0C) {
        radiotap_len = 12;
    }

    size_t mgmt_start = radiotap_len;
    if (mgmt_start + 24 > len)
        return -1;

    if (sta_mac)
        memcpy(sta_mac, &frame[mgmt_start + 10], HACKIT_80211_ADDR_LEN);

    size_t off = mgmt_start + 24;

    if (ssid_out && ssid_out_len > 0)
        ssid_out[0] = '\0';

    while (off + 1 < len) {
        uint8_t id = frame[off];
        uint8_t elen = frame[off + 1];

        if (off + 2 + elen > len)
            break;

        if (id == 0x00 && ssid_out && ssid_out_len > 0) {
            size_t copy_len = (size_t)elen;
            if (copy_len >= ssid_out_len)
                copy_len = ssid_out_len - 1;
            memcpy(ssid_out, &frame[off + 2], copy_len);
            ssid_out[copy_len] = '\0';
        }

        off += 2 + elen;
    }

    return 1;
}

/* ------------------------------------------------------------------ */

#ifdef HACKIT_HAS_PCAP
#ifdef _WIN32
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif

typedef struct {
    void (*callback)(const uint8_t*, size_t);
    volatile int running;
} probe_capture_ctx_t;

static void probe_packet_handler(unsigned char* user, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    probe_capture_ctx_t* ctx = (probe_capture_ctx_t*)user;
    if (!ctx || !ctx->running)
        return;

    if (pkthdr->caplen < 24)
        return;

    if ((packet[0] & 0xFC) == 0x40 && ctx->callback)
        ctx->callback(packet, pkthdr->caplen);
}

int hackit_capture_probe_requests(const char* iface, int duration_ms, void (*callback)(const uint8_t*, size_t)) {
    if (!iface || !callback)
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t* handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "[PROBE] pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    int dlt = pcap_datalink(handle);
    if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11) {
        fprintf(stderr, "[PROBE] Unsupported datalink type: %d\n", dlt);
        pcap_close(handle);
        return -1;
    }

    probe_capture_ctx_t ctx;
    ctx.callback = callback;
    ctx.running = 1;

    int elapsed = 0;
    while (ctx.running && elapsed < duration_ms) {
        struct pcap_pkthdr* hdr;
        const unsigned char* pkt;
        int ret = pcap_next_ex(handle, &hdr, &pkt);

        if (ret == 1 && hdr && pkt)
            probe_packet_handler((unsigned char*)&ctx, hdr, pkt);
        else if (ret == -1)
            break;
        else if (ret == -2)
            break;

        HACKIT_SLEEP_MS(1);
        elapsed += 1;
    }

    ctx.running = 0;
    pcap_close(handle);
    return elapsed;
}

int hackit_get_connected_clients(const char* iface, const char* bssid, char** clients_out, int max_clients) {
    if (!iface || !bssid || !clients_out || max_clients <= 0)
        return -1;

    uint8_t bssid_bytes[6];
    int parsed = 0;
    int pos = 0;
    for (int i = 0; bssid[i] != '\0' && parsed < 6; i++) {
        if (bssid[i] == ':' || bssid[i] == '-') continue;
        char hex[3] = {bssid[i], bssid[i + 1], '\0'};
        if (hex[1] == '\0') break;
        bssid_bytes[parsed++] = (uint8_t)strtoul(hex, NULL, 16);
        i++;
    }

    if (parsed != 6)
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t* handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!handle) {
        fprintf(stderr, "[PROBE] pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    int found = 0;
    int packets_seen = 0;

    while (found < max_clients && packets_seen < 500) {
        struct pcap_pkthdr* hdr;
        const unsigned char* pkt;
        int ret = pcap_next_ex(handle, &hdr, &pkt);

        if (ret != 1 || !hdr || !pkt)
            break;

        packets_seen++;

        if (hdr->caplen < 24)
            continue;

        uint8_t fc = pkt[0];
        uint8_t type = (fc >> 2) & 0x03;

        /* Look for data frames (type=2) */
        if (type != 2)
            continue;

        uint8_t to_ds = (fc >> 8) & 0x01;
        uint8_t from_ds = (fc >> 9) & 0x01;
        const uint8_t* addr1 = &pkt[4];
        const uint8_t* addr2 = &pkt[10];

        const uint8_t* sta_addr = NULL;

        if (to_ds == 1 && from_ds == 0) {
            /* STA -> AP: addr2 is STA */
            if (memcmp(addr1, bssid_bytes, 6) == 0)
                sta_addr = addr2;
        } else if (to_ds == 0 && from_ds == 1) {
            /* AP -> STA: addr1 is STA */
            if (memcmp(addr2, bssid_bytes, 6) == 0)
                sta_addr = addr1;
        }

        if (!sta_addr)
            continue;

        char mac_buf[18];
        snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sta_addr[0], sta_addr[1], sta_addr[2],
                 sta_addr[3], sta_addr[4], sta_addr[5]);

        /* Dedup check */
        int dup = 0;
        for (int j = 0; j < found; j++) {
            if (strcmp(clients_out[j], mac_buf) == 0) {
                dup = 1;
                break;
            }
        }

        if (!dup) {
            clients_out[found] = (char*)malloc(18);
            if (clients_out[found]) {
                memcpy(clients_out[found], mac_buf, 18);
                found++;
            }
        }
    }

    pcap_close(handle);
    printf("[PROBE] Found %d connected clients on '%s'\n", found, iface);
    return found;
}

#else /* !HACKIT_HAS_PCAP */

int hackit_capture_probe_requests(const char* iface, int duration_ms, void (*callback)(const uint8_t*, size_t)) {
    (void)iface; (void)duration_ms; (void)callback;
    fprintf(stderr, "[PROBE] pcap not available. Install libpcap/Npcap for probe capture.\n");
    return -1;
}

int hackit_get_connected_clients(const char* iface, const char* bssid, char** clients_out, int max_clients) {
    (void)iface; (void)bssid; (void)clients_out; (void)max_clients;
    fprintf(stderr, "[PROBE] pcap not available. Install libpcap/Npcap for client discovery.\n");
    return -1;
}

#endif /* HACKIT_HAS_PCAP */
