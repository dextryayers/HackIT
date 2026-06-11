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
}
