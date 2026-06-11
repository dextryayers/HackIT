#pragma once

#include <cstdint>
#include <vector>
#include <string>

#ifdef _WIN32
#define PF_API __declspec(dllexport)
#else
#define PF_API
#endif

std::vector<uint8_t> ForgeAuthFrame(
    const uint8_t* bssid,
    const uint8_t* sta,
    uint16_t algo,
    uint16_t seq,
    uint16_t status);

std::vector<uint8_t> ForgeAssocReq(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid);

std::vector<uint8_t> ForgeProbeResp(
    const uint8_t* bssid,
    const uint8_t* sta,
    const char* ssid,
    uint8_t channel);

std::vector<uint8_t> ForgeNullData(
    const uint8_t* bssid,
    const uint8_t* sta,
    bool powerSave);

extern "C" {
    PF_API uint8_t* forge_auth_frame(
        const uint8_t* bssid,
        const uint8_t* sta,
        uint16_t algo,
        uint16_t seq,
        uint16_t status,
        int* out_len);

    PF_API uint8_t* forge_assoc_req(
        const uint8_t* bssid,
        const uint8_t* sta,
        const char* ssid,
        int* out_len);

    PF_API uint8_t* forge_probe_resp(
        const uint8_t* bssid,
        const uint8_t* sta,
        const char* ssid,
        uint8_t channel,
        int* out_len);

    PF_API uint8_t* forge_null_data(
        const uint8_t* bssid,
        const uint8_t* sta,
        int power_save,
        int* out_len);

    PF_API void forge_free(uint8_t* buf);
}
