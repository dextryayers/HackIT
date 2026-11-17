#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#define WPS_API __declspec(dllexport)
#else
#define WPS_API
#endif

class WpsAttack {
public:
    static std::string ComputePinFromMac(const std::string& bssid);
    static std::vector<std::string> GeneratePinCandidates(const std::string& bssid);
    static bool ValidateWpsPin(const std::string& pin);
    // Pixie Dust: unwrap E-S1/E-S2 from M1 (PKE) + attacker-generated M2 (PKR)
    // using the *known* authkey derived from the (leaked) enrollee MAC.
    // Returns hex(PSK) on success, "" if the unwrap IV check fails.
    static std::string ComputePixieDustKey(
        const std::string& pke,
        const std::string& pkr,
        const std::string& e_hash1,
        const std::string& e_hash2,
        const std::string& r_hash1,
        const std::string& r_hash2,
        const std::string& authkey,
        const std::string& essid,
        const std::string& bssid);
};

extern "C" {
    WPS_API const char* wps_compute_pin_from_mac(const char* bssid);
    WPS_API char** wps_generate_pin_candidates(const char* bssid, int* count);
    WPS_API int wps_validate_pin(const char* pin);
    // RFC 3394 AES key unwrap for the Python Pixie Dust engine. Returns the
    // number of plaintext bytes written to `out`, or 0 on failure.
    WPS_API int wps_aes_unwrap(const uint8_t* kek, int kek_len,
                               const uint8_t* wrapped, int wrapped_len,
                               uint8_t* out, int out_cap);
}
