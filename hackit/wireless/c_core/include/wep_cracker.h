#pragma once

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#define WEP_API __declspec(dllexport)
#else
#define WEP_API
#endif

struct IvKeyByte {
    std::vector<uint8_t> iv;
    uint8_t keybyte;
    int index;
};

class WepCracker {
public:
    WepCracker();
    bool LoadCapture(const std::string& pcapFile);
    int IvCount() const;
    bool FmsAttack(std::string& keyOut);
    bool KorekAttack(std::string& keyOut);
    bool PtwAttack(std::string& keyOut);
    bool IsReady() const;

private:
    std::vector<IvKeyByte> ivs_;
    int minIvs_;
};

extern "C" {
    WEP_API void* wep_cracker_create();
    WEP_API void wep_cracker_destroy(void* handle);
    WEP_API int wep_cracker_load_capture(void* handle, const char* pcap_file);
    WEP_API int wep_cracker_iv_count(void* handle);
    WEP_API int wep_cracker_ptw_attack(void* handle, char* key_out, int key_out_size);
}
