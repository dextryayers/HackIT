#include <stdint.h>
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>

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

struct ArpInfo {
    std::vector<uint8_t> bssid;
    int count;
};

class WepCracker {
public:
    WepCracker();
    ~WepCracker();
    bool LoadCapture(const std::string& pcapFile);
    int IvCount() const;
    bool PtwAttack(std::string& keyOut);
    bool FmsAttack(std::string& keyOut);
    bool KorekAttack(std::string& keyOut);
    bool ArpReplayAttack(const char* iface, const uint8_t* bssid);
    bool IsReady() const;
    std::vector<uint8_t> GetKey() const;

private:
    std::vector<IvKeyByte> ivs_;
    std::vector<uint8_t> keyBytes_;
    std::set<uint32_t> seenIvs_;
    int minIvs_;
    int keyLen_;

    static void swapByte(uint8_t* S, int a, int b);
    static uint8_t predictPtwZ(const uint8_t* S, int j, int depth, int guess);
    static bool isFmsWeak(const uint8_t* iv);
    static int fmsDerive(const uint8_t* iv, uint8_t z);
    static int korekDerive(int cls, const uint8_t* iv, uint8_t z);
};

extern "C" {
    WEP_API void* wep_cracker_create();
    WEP_API void wep_cracker_destroy(void* handle);
    WEP_API int wep_cracker_load_capture(void* handle, const char* pcap_file);
    WEP_API int wep_cracker_iv_count(void* handle);
    WEP_API int wep_cracker_ptw_attack(void* handle, char* key_out, int key_out_size);
    WEP_API int wep_cracker_fms_attack(void* handle, char* key_out, int key_out_size);
    WEP_API int wep_cracker_korek_attack(void* handle, char* key_out, int key_out_size);
}
