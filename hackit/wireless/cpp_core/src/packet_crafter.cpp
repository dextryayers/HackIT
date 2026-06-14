#include "cpp_bridge.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <ctime>

static uint32_t crc32_table[256];
static bool crc32_init_done = false;

static void crc32_init(void) {
    if (crc32_init_done) return;
    uint32_t poly = 0xEDB88320;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (poly & -(c & 1));
        crc32_table[i] = c;
    }
    crc32_init_done = true;
}

static uint32_t calculate_fcs_internal(const uint8_t *data, int len) {
    crc32_init();
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

static std::string bytes_to_hex(const uint8_t *data, int len) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (int i = 0; i < len; i++)
        os << std::setw(2) << (int)data[i];
    return os.str();
}

static void mac_to_bytes(const char *mac_str, uint8_t *out) {
    if (!mac_str || strlen(mac_str) < 17) {
        memset(out, 0, 6);
        return;
    }
    for (int i = 0; i < 6; i++) {
        unsigned int b;
        sscanf(mac_str + i * 3, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

extern "C" const char* craft_deauth(const char *bssid, const char *station, int reason) {
    static std::string result;
    uint8_t bmac[6], smac[6];
    mac_to_bytes(bssid, bmac);
    mac_to_bytes(station, smac);
    uint8_t frame[26];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0xC0;
    frame[1] = 0x00;
    memcpy(&frame[4], smac, 6);
    memcpy(&frame[10], bmac, 6);
    memcpy(&frame[16], bmac, 6);
    frame[24] = (uint8_t)(reason & 0xFF);
    frame[25] = (uint8_t)((reason >> 8) & 0xFF);
    result = bytes_to_hex(frame, 26);
    return result.c_str();
}

extern "C" const char* craft_beacon(const char *ssid, const char *bssid, int channel) {
    static std::string result;
    uint8_t bmac[6];
    mac_to_bytes(bssid, bmac);
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    std::vector<uint8_t> frame;
    frame.resize(24 + 12 + 2 + ssid_len + 3 + 10, 0);
    frame[0] = 0x80;
    frame[1] = 0x00;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], bmac, 6);
    memcpy(&frame[16], bmac, 6);
    int off = 24;
    uint64_t ts = (uint64_t)time(nullptr);
    memcpy(&frame[off], &ts, 8); off += 8;
    uint16_t bi = 100;
    memcpy(&frame[off], &bi, 2); off += 2;
    uint16_t caps = 0x0431;
    memcpy(&frame[off], &caps, 2); off += 2;
    frame[off++] = 0;
    frame[off++] = (uint8_t)ssid_len;
    if (ssid_len > 0) memcpy(&frame[off], ssid, ssid_len);
    off += ssid_len;
    frame[off++] = 1; frame[off++] = 8;
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(&frame[off], rates, 8); off += 8;
    frame[off++] = 3; frame[off++] = 1; frame[off++] = (uint8_t)channel;
    result = bytes_to_hex(frame.data(), (int)frame.size());
    return result.c_str();
}

extern "C" const char* craft_probe(const char *ssid, const char *client_mac) {
    static std::string result;
    uint8_t cmac[6];
    mac_to_bytes(client_mac, cmac);
    int ssid_len = ssid ? (int)strlen(ssid) : 0;
    if (ssid_len > 32) ssid_len = 32;
    std::vector<uint8_t> frame;
    frame.resize(24 + 2 + ssid_len, 0);
    frame[0] = 0x40;
    frame[1] = 0x00;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], cmac, 6);
    memset(&frame[16], 0xFF, 6);
    int off = 24;
    frame[off++] = 0;
    frame[off++] = (uint8_t)ssid_len;
    if (ssid_len > 0) memcpy(&frame[off], ssid, ssid_len);
    result = bytes_to_hex(frame.data(), (int)frame.size());
    return result.c_str();
}

extern "C" const char* craft_eapol(void) {
    static std::string result;
    std::vector<uint8_t> frame(24 + 8 + 95, 0);
    frame[0] = 0x08;
    frame[1] = 0x42;
    memset(&frame[4], 0xFF, 6);
    memset(&frame[10], 0x02, 6);
    memset(&frame[16], 0x02, 6);
    int off = 24;
    frame[off++] = 0xAA;
    frame[off++] = 0xAA;
    frame[off++] = 0x03;
    frame[off++] = 0x00;
    frame[off++] = 0x00;
    frame[off++] = 0x00;
    frame[off++] = 0x88;
    frame[off++] = 0x8E;
    frame[off++] = 0x01;
    frame[off++] = 0x03;
    frame[off++] = 0x00;
    frame[off++] = 0x5D;
    frame[off++] = 0xFE;
    frame[off++] = 0x00;
    frame[off++] = 0x89;
    frame[off++] = 0x00;
    frame[off++] = 0x20;
    for (int i = 0; i < 32; i++) frame[off++] = (uint8_t)i;
    for (int i = 0; i < 16; i++) frame[off++] = 0;
    for (int i = 0; i < 16; i++) frame[off++] = 0;
    for (int i = 0; i < 16; i++) frame[off++] = (uint8_t)(i * 17);
    uint32_t fcs = calculate_fcs_internal(frame.data(), (int)frame.size());
    frame.push_back((uint8_t)(fcs & 0xFF));
    frame.push_back((uint8_t)((fcs >> 8) & 0xFF));
    frame.push_back((uint8_t)((fcs >> 16) & 0xFF));
    frame.push_back((uint8_t)((fcs >> 24) & 0xFF));
    result = bytes_to_hex(frame.data(), (int)frame.size());
    return result.c_str();
}
