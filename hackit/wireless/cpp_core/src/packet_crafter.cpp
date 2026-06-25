#include "cpp_bridge.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <array>
#include <mutex>
#include <endian.h>

static std::array<uint32_t, 256> crc32_table;
static std::once_flag crc32_once;

static void crc32_init_impl() {
    uint32_t poly = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (poly & -(c & 1));
        crc32_table[i] = c;
    }
}

static uint32_t calculate_fcs_internal(const uint8_t *data, int len) noexcept {
    std::call_once(crc32_once, crc32_init_impl);
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

/* Hex conversion with reusable buffer – no ostringstream overhead */
static const char* bytes_to_hex_buf(const uint8_t *data, int len) noexcept {
    static thread_local char buf[4096];
    static thread_local char hex[4096 * 2 + 1];
    if (len > 2048) len = 2048;
    for (int i = 0; i < len; i++) {
        unsigned b = data[i];
        hex[i * 2]     = "0123456789abcdef"[b >> 4];
        hex[i * 2 + 1] = "0123456789abcdef"[b & 0xF];
    }
    hex[len * 2] = '\0';
    return hex;
}

static void mac_to_bytes_fast(const char *mac_str, uint8_t *out) noexcept {
    if (!mac_str) { memset(out, 0, 6); return; }
    for (int i = 0; i < 6; i++) {
        unsigned hi = (unsigned char)mac_str[i * 3];
        unsigned lo = (unsigned char)mac_str[i * 3 + 1];
        unsigned b = 0;
        if (hi >= '0' && hi <= '9') b |= (hi - '0') << 4;
        else if (hi >= 'A' && hi <= 'F') b |= (hi - 'A' + 10) << 4;
        else if (hi >= 'a' && hi <= 'f') b |= (hi - 'a' + 10) << 4;
        if (lo >= '0' && lo <= '9') b |= (lo - '0');
        else if (lo >= 'A' && lo <= 'F') b |= (lo - 'A' + 10);
        else if (lo >= 'a' && lo <= 'f') b |= (lo - 'a' + 10);
        out[i] = (uint8_t)b;
    }
}

extern "C" const char* craft_deauth(const char *bssid, const char *station, int reason) noexcept {
    uint8_t bmac[6], smac[6];
    mac_to_bytes_fast(bssid, bmac);
    mac_to_bytes_fast(station, smac);
    uint8_t frame[26]{};
    frame[0] = 0xC0;
    memcpy(&frame[4], smac, 6);
    memcpy(&frame[10], bmac, 6);
    memcpy(&frame[16], bmac, 6);
    frame[24] = (uint8_t)(reason & 0xFF);
    frame[25] = (uint8_t)((reason >> 8) & 0xFF);
    return bytes_to_hex_buf(frame, 26);
}

extern "C" const char* craft_beacon(const char *ssid, const char *bssid, int channel) noexcept {
    uint8_t bmac[6];
    mac_to_bytes_fast(bssid, bmac);
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    std::vector<uint8_t> frame(24 + 12 + 2 + ssid_len + 3 + 10, 0);
    frame[0] = 0x80;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], bmac, 6);
    memcpy(&frame[16], bmac, 6);
    int off = 24;
    /* 802.11 requires little-endian for multi-byte fields */
    uint64_t ts = htole64((uint64_t)time(nullptr));
    memcpy(&frame[off], &ts, 8); off += 8;
    uint16_t bi = htole16(100);
    memcpy(&frame[off], &bi, 2); off += 2;
    uint16_t caps = htole16(0x0431);
    memcpy(&frame[off], &caps, 2); off += 2;
    frame[off++] = 0;
    frame[off++] = (uint8_t)ssid_len;
    if (ssid_len > 0) memcpy(&frame[off], ssid, ssid_len);
    off += ssid_len;
    frame[off++] = 1; frame[off++] = 8;
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(&frame[off], rates, 8); off += 8;
    frame[off++] = 3; frame[off++] = 1; frame[off++] = (uint8_t)channel;
    return bytes_to_hex_buf(frame.data(), (int)frame.size());
}

extern "C" const char* craft_probe(const char *ssid, const char *client_mac) noexcept {
    uint8_t cmac[6];
    mac_to_bytes_fast(client_mac, cmac);
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    std::vector<uint8_t> frame(24 + 2 + ssid_len, 0);
    frame[0] = 0x40;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], cmac, 6);
    memset(&frame[16], 0xFF, 6);
    int off = 24;
    frame[off++] = 0;
    frame[off++] = (uint8_t)ssid_len;
    if (ssid_len > 0) memcpy(&frame[off], ssid, ssid_len);
    return bytes_to_hex_buf(frame.data(), (int)frame.size());
}

extern "C" const char* craft_eapol() noexcept {
    std::vector<uint8_t> frame(24 + 8 + 95, 0);
    frame[0] = 0x08; frame[1] = 0x42;
    memset(&frame[4], 0xFF, 6);
    memset(&frame[10], 0x02, 6);
    memset(&frame[16], 0x02, 6);
    int off = 24;
    frame[off++] = 0xAA; frame[off++] = 0xAA; frame[off++] = 0x03;
    frame[off++] = 0x00; frame[off++] = 0x00; frame[off++] = 0x00;
    frame[off++] = 0x88; frame[off++] = 0x8E;
    frame[off++] = 0x01; frame[off++] = 0x03;
    frame[off++] = 0x00; frame[off++] = 0x5D;
    frame[off++] = 0xFE; frame[off++] = 0x00;
    frame[off++] = 0x89; frame[off++] = 0x00; frame[off++] = 0x20;
    for (int i = 0; i < 32; i++) frame[off++] = (uint8_t)i;
    for (int i = 0; i < 16; i++) frame[off++] = 0;
    for (int i = 0; i < 16; i++) frame[off++] = 0;
    for (int i = 0; i < 16; i++) frame[off++] = (uint8_t)(i * 17);
    uint32_t fcs = calculate_fcs_internal(frame.data(), (int)frame.size());
    frame.push_back((uint8_t)(fcs & 0xFF));
    frame.push_back((uint8_t)((fcs >> 8) & 0xFF));
    frame.push_back((uint8_t)((fcs >> 16) & 0xFF));
    frame.push_back((uint8_t)((fcs >> 24) & 0xFF));
    return bytes_to_hex_buf(frame.data(), (int)frame.size());
}
