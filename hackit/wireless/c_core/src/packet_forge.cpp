#include "packet_forge.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

static void write16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
}

static void copyMac(std::vector<uint8_t>& buf, const uint8_t* mac) {
    if (mac)
        buf.insert(buf.end(), mac, mac + 6);
    else
        buf.insert(buf.end(), 6, 0);
}

static std::vector<uint8_t> makeManagementFrame(
    uint8_t typeSubtype,
    const uint8_t* bssid,
    const uint8_t* sta,
    bool toDs = false,
    bool fromDs = false)
{
    std::vector<uint8_t> frame(24, 0);
    frame[0] = typeSubtype;
    if (toDs) frame[1] |= 0x01;
    if (fromDs) frame[1] |= 0x02;

    // Duration (2 bytes) — zero for polling/management typically
    // Addr1: destination
    // Addr2: source
    // Addr3: BSSID
    copyMac(frame, sta);    // offset 4 — Addr1 (DA)
    copyMac(frame, bssid);  // offset 10 — Addr2 (SA)
    copyMac(frame, bssid);  // offset 16 — Addr3 (BSSID)
    // seq ctrl at offset 22 — skip for now
    return frame;
}

std::vector<uint8_t> ForgeAuthFrame(
    const uint8_t* bssid,
    const uint8_t* sta,
    uint16_t algo,
    uint16_t seq,
    uint16_t status)
{
    auto frame = makeManagementFrame(0xB0, bssid, sta);
    // Authentication frame body:
    write16(frame, algo);     // algorithm
    write16(frame, seq);      // transaction seq
    write16(frame, status);   // status code
    return frame;
}

std::vector<uint8_t> ForgeAssocReq(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid)
{
    auto frame = makeManagementFrame(0x00, bssid, sta);
    // Capability info (2 bytes)
    write16(frame, 0x0001);  // basic rates
    // Listen interval (2 bytes)
    write16(frame, 0x000A);  // 10 beacon intervals
    // Tagged parameters: SSID
    size_t ssidLen = ssid ? std::strlen(ssid) : 0;
    if (ssidLen > 32) ssidLen = 32;
    frame.push_back(0x00);   // tag: SSID
    frame.push_back(static_cast<uint8_t>(ssidLen));
    if (ssid && ssidLen > 0)
        frame.insert(frame.end(), ssid, ssid + ssidLen);
    // Supported rates
    frame.push_back(0x01);
    frame.push_back(0x04);
    frame.push_back(0x02); frame.push_back(0x04); frame.push_back(0x0B); frame.push_back(0x10);
    return frame;
}

std::vector<uint8_t> ForgeProbeResp(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid,
    uint8_t channel)
{
    auto frame = makeManagementFrame(0x50, bssid, sta);
    // Timestamp (8 bytes)
    frame.insert(frame.end(), 8, 0);
    // Beacon interval (2 bytes)
    write16(frame, 0x0064);  // 100 TU
    // Capability info (2 bytes)
    write16(frame, 0x0001);

    // Tagged parameters
    size_t ssidLen = ssid ? std::strlen(ssid) : 0;
    if (ssidLen > 32) ssidLen = 32;
    frame.push_back(0x00);   // SSID
    frame.push_back(static_cast<uint8_t>(ssidLen));
    if (ssid && ssidLen > 0)
        frame.insert(frame.end(), ssid, ssid + ssidLen);
    // Supported rates
    frame.push_back(0x01);
    frame.push_back(0x04);
    frame.push_back(0x02); frame.push_back(0x04); frame.push_back(0x0B); frame.push_back(0x10);
    // DS Parameter Set (channel)
    frame.push_back(0x03);
    frame.push_back(0x01);
    frame.push_back(channel);
    return frame;
}

std::vector<uint8_t> ForgeNullData(const uint8_t* bssid, const uint8_t* sta, bool powerSave) {
    auto frame = makeManagementFrame(0x08, bssid, sta);
    if (powerSave)
        frame[1] |= 0x10;  // Power Management bit
    // Null data frame has no body
    return frame;
}

// C API
extern "C" {

PF_API uint8_t* forge_auth_frame(
    const uint8_t* bssid,
    const uint8_t* sta,
    uint16_t algo,
    uint16_t seq,
    uint16_t status,
    int* out_len)
{
    auto vec = ForgeAuthFrame(bssid, sta, algo, seq, status);
    *out_len = static_cast<int>(vec.size());
    auto* buf = static_cast<uint8_t*>(std::malloc(vec.size()));
    std::memcpy(buf, vec.data(), vec.size());
    return buf;
}

PF_API uint8_t* forge_assoc_req(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid,
    int* out_len)
{
    auto vec = ForgeAssocReq(bssid, sta, ssid);
    *out_len = static_cast<int>(vec.size());
    auto* buf = static_cast<uint8_t*>(std::malloc(vec.size()));
    std::memcpy(buf, vec.data(), vec.size());
    return buf;
}

PF_API uint8_t* forge_probe_resp(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid,
    uint8_t channel,
    int* out_len)
{
    auto vec = ForgeProbeResp(bssid, sta, ssid, channel);
    *out_len = static_cast<int>(vec.size());
    auto* buf = static_cast<uint8_t*>(std::malloc(vec.size()));
    std::memcpy(buf, vec.data(), vec.size());
    return buf;
}

PF_API uint8_t* forge_null_data(
    const uint8_t* bssid,
    const uint8_t* sta,
    int power_save,
    int* out_len)
{
    auto vec = ForgeNullData(bssid, sta, power_save != 0);
    *out_len = static_cast<int>(vec.size());
    auto* buf = static_cast<uint8_t*>(std::malloc(vec.size()));
    std::memcpy(buf, vec.data(), vec.size());
    return buf;
}

PF_API void forge_free(uint8_t* buf) {
    std::free(buf);
}

}
