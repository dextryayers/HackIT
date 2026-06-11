#include "spectrum_scanner.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <array>
#include <algorithm>
#include <string>
#include <sstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define POPEN  _popen
#define PCLOSE _pclose
#define popen  _popen
#define pclose _pclose
#else
#define POPEN  popen
#define PCLOSE pclose
#endif

// ---- helpers ----------------------------------------------------------------

struct ChannelSample {
    int channel;
    int rssi;   // dBm
};

// Run a shell command and return its stdout as a string.
static std::string run_cmd(const char* cmd) {
    std::string result;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return result;

    char buf[4096];
    while (std::fgets(buf, sizeof(buf), pipe)) {
        result.append(buf);
    }
    pclose(pipe);
    return result;
}

// Parse an integer from s, returning def_val on failure.
static int parse_int(const char* s, int def_val) {
    if (!s) return def_val;
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (end == s) return def_val;
    return static_cast<int>(v);
}

// Return true if channel falls within the requested band.
static bool channel_in_band(int ch, int band) {
    if (band == HACKIT_BAND_2_4GHZ) return (ch >= 1 && ch <= 14);
    if (band == HACKIT_BAND_5GHZ)   return (ch >= 36 && ch <= 165);
    return false;
}

// ---- Linux helpers ----------------------------------------------------------

#ifdef __linux__

// Parse "iw dev <iface> scan" output.
// Each BSS block starts with "BSS " and contains:
//   freq: <MHz>
//   signal: <dBm>
// We map freq → channel and collect RSSI.
static std::vector<ChannelSample> iw_parse_scan(const char* iface) {
    std::vector<ChannelSample> samples;
    std::string cmd = "iw dev ";
    cmd += iface;
    cmd += " scan 2>/dev/null";
    std::string out = run_cmd(cmd.c_str());

    if (out.empty()) return samples;

    std::istringstream iss(out);
    std::string line;
    int cur_freq = 0;
    int cur_rssi = -999;

    while (std::getline(iss, line)) {
        if (line.find("BSS ", 0) == 0) {
            // flush previous entry
            if (cur_freq > 0) {
                int ch = 0;
                if (cur_freq >= 2412 && cur_freq <= 2484) {
                    ch = (cur_freq - 2407) / 5;
                    if (cur_freq == 2484) ch = 14;
                } else if (cur_freq >= 5000 && cur_freq <= 5900) {
                    ch = (cur_freq - 5000) / 5;
                }
                if (ch > 0) samples.push_back({ch, cur_rssi});
            }
            cur_freq  = 0;
            cur_rssi  = -999;
        }

        // signal: -52.00 dBm
        if (line.find("signal:", 0) != std::string::npos) {
            const char* p = line.c_str() + 7;
            while (*p == ' ') ++p;
            cur_rssi = static_cast<int>(std::atof(p));
        }

        // freq: 2437
        if (line.find("freq:", 0) != std::string::npos) {
            const char* p = line.c_str() + 5;
            while (*p == ' ') ++p;
            cur_freq = parse_int(p, 0);
        }
    }

    // flush last entry
    if (cur_freq > 0) {
        int ch = 0;
        if (cur_freq >= 2412 && cur_freq <= 2484) {
            ch = (cur_freq - 2407) / 5;
            if (cur_freq == 2484) ch = 14;
        } else if (cur_freq >= 5000 && cur_freq <= 5900) {
            ch = (cur_freq - 5000) / 5;
        }
        if (ch > 0) samples.push_back({ch, cur_rssi});
    }

    return samples;
}

// Detect available channels via "iw reg get" or "iw phy".
static std::vector<int> detect_channels_linux(int band) {
    std::vector<int> channels;
    std::string out = run_cmd("iw reg get 2>/dev/null");
    if (out.empty()) {
        out = run_cmd("iw phy 2>/dev/null | grep -E '\\* [0-9]+ MHz'");
    }

    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        // Look for lines like "  * 2412 MHz [1]"
        size_t MHz_pos = line.find("MHz");
        if (MHz_pos == std::string::npos) continue;

        size_t star = line.rfind('*', MHz_pos);
        if (star == std::string::npos) continue;

        int freq = parse_int(line.c_str() + star + 1, 0);
        if (freq <= 0) continue;

        int ch = 0;
        if (freq >= 2412 && freq <= 2484) {
            ch = (freq - 2407) / 5;
            if (freq == 2484) ch = 14;
        } else if (freq >= 5000 && freq <= 5900) {
            ch = (freq - 5000) / 5;
        }
        if (ch > 0 && channel_in_band(ch, band)) {
            channels.push_back(ch);
        }
    }

    // Fallback: if nothing detected, provide standard ranges
    if (channels.empty()) {
        if (band == HACKIT_BAND_2_4GHZ) {
            for (int c = 1; c <= 14; ++c) channels.push_back(c);
        } else if (band == HACKIT_BAND_5GHZ) {
            for (int c = 36; c <= 165; c += 4) channels.push_back(c);
        }
    }

    std::sort(channels.begin(), channels.end());
    return channels;
}

// Measure channel utilization by timing clear-channel-assessment via
// "iw dev <iface> survey dump" (only works in monitor mode or when
// interface is up). Returns fractional 0.0..1.0.
static bool iw_utilization(const char* iface, int channel, float* out_util) {
    // Switch channel briefly, then read survey noise/signal data
    std::string cmd = "iw dev ";
    cmd += iface;
    cmd += " survey dump 2>/dev/null";
    std::string out = run_cmd(cmd.c_str());

    // Parse for "in use" survey line on the requested channel
    std::istringstream iss(out);
    std::string line;
    bool found = false;
    int busy_time = 0, total_time = 0;

    while (std::getline(iss, line)) {
        if (line.find("in use") != std::string::npos) {
            found = true;
        }
        if (line.find("busy time") != std::string::npos) {
            const char* p = line.c_str();
            while (*p && !std::isdigit(static_cast<unsigned char>(*p)) && *p != '-') ++p;
            busy_time = parse_int(p, 0);
        }
        if (line.find("channel time") != std::string::npos &&
            line.find("busy") == std::string::npos) {
            const char* p = line.c_str();
            while (*p && !std::isdigit(static_cast<unsigned char>(*p)) && *p != '-') ++p;
            total_time = parse_int(p, 0);
        }
    }

    if (total_time > 0) {
        *out_util = static_cast<float>(busy_time) / static_cast<float>(total_time);
        if (*out_util < 0.0f) *out_util = 0.0f;
        if (*out_util > 1.0f) *out_util = 1.0f;
        return true;
    }

    // Fallback: use "iw dev <iface> link" to check if associated, then
    // estimate utilization from noise floor vs signal.
    // This is a rough heuristic.
    *out_util = 0.0f;
    return false;
}

#endif // __linux__

// ---- Windows helpers --------------------------------------------------------

#ifdef _WIN32

// Parse "netsh wlan show networks mode=bssid" output.
// Extracts channel from "Channel" line and signal from "Signal" line.
static std::vector<ChannelSample> netsh_parse_networks(const char* iface) {
    std::vector<ChannelSample> samples;
    (void)iface; // netsh doesn't filter by interface in the same way

    std::string out = run_cmd("netsh wlan show networks mode=bssid 2>nul");
    if (out.empty()) return samples;

    std::istringstream iss(out);
    std::string line;
    int cur_channel = 0;
    int cur_rssi    = -999;

    while (std::getline(iss, line)) {
        // "  Channel                    : 6"
        if (line.find("Channel") != std::string::npos) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                cur_channel = parse_int(line.c_str() + colon + 1, 0);
            }
        }
        // "  Signal                     : 85%"
        if (line.find("Signal") != std::string::npos) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                const char* p = line.c_str() + colon + 1;
                while (*p == ' ') ++p;
                int pct = parse_int(p, 0);
                // Convert percentage to approximate dBm:  0% ≈ -100, 100% ≈ -30
                cur_rssi = -100 + (pct * 70 / 100);

                if (cur_channel > 0) {
                    samples.push_back({cur_channel, cur_rssi});
                }
                cur_channel = 0;
                cur_rssi    = -999;
            }
        }
    }

    return samples;
}

// Detect available channels from "netsh wlan show drivers".
static std::vector<int> detect_channels_windows(int band) {
    std::vector<int> channels;
    std::string out = run_cmd("netsh wlan show drivers 2>nul");

    // Look for "Frequencies supported" or "Radio types supported" section.
    // Windows doesn't expose channel lists as cleanly as Linux.
    // We parse the "Channels" line from driver output if available.
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("Channel") != std::string::npos &&
            line.find("supported") != std::string::npos) {
            // This line may not exist; fall through to default ranges.
            break;
        }
    }

    // Windows netsh doesn't reliably list individual channels.
    // Provide standard ranges based on regulatory domain assumptions.
    if (band == HACKIT_BAND_2_4GHZ) {
        for (int c = 1; c <= 14; ++c) channels.push_back(c);
    } else if (band == HACKIT_BAND_5GHZ) {
        for (int c = 36; c <= 165; c += 4) channels.push_back(c);
    }

    return channels;
}

static bool win_utilization(const char* iface, int channel, float* out_util) {
    (void)iface;
    (void)channel;

    // Windows doesn't expose per-channel utilization via netsh.
    // Use "netsh wlan show interfaces" to get link quality percentage.
    std::string out = run_cmd("netsh wlan show interfaces 2>nul");
    if (out.empty()) {
        *out_util = 0.0f;
        return false;
    }

    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("Receive rate") != std::string::npos ||
            line.find("Tx rate") != std::string::npos) {
            // Rough heuristic based on rate.
        }
        if (line.find("Signal") != std::string::npos) {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                const char* p = line.c_str() + colon + 1;
                while (*p == ' ') ++p;
                int pct = parse_int(p, 0);
                *out_util = static_cast<float>(pct) / 100.0f;
                if (*out_util > 1.0f) *out_util = 1.0f;
                return true;
            }
        }
    }

    *out_util = 0.0f;
    return false;
}

#endif // _WIN32

// ---- portable fallback for non-Linux/Windows --------------------------------
#if !defined(__linux__) && !defined(_WIN32)

static std::vector<ChannelSample> fallback_scan(const char* iface) {
    (void)iface;
    return {};
}

static std::vector<int> detect_channels_fallback(int band) {
    std::vector<int> channels;
    if (band == HACKIT_BAND_2_4GHZ) {
        for (int c = 1; c <= 14; ++c) channels.push_back(c);
    } else if (band == HACKIT_BAND_5GHZ) {
        for (int c = 36; c <= 165; c += 4) channels.push_back(c);
    }
    return channels;
}

static bool fallback_utilization(const char* iface, int channel, float* out_util) {
    (void)iface; (void)channel;
    *out_util = 0.0f;
    return false;
}

#endif

// ===========================================================================
//  Public C API
// ===========================================================================

extern "C" {

int hackit_spectrum_scan_channels(const char* iface,
                                  int* channels_out,
                                  int* rssi_out,
                                  int  max_results) {
    if (!iface || !channels_out || !rssi_out || max_results <= 0) return 0;

    std::vector<ChannelSample> samples;

#if defined(__linux__)
    samples = iw_parse_scan(iface);
#elif defined(_WIN32)
    samples = netsh_parse_networks(iface);
#else
    samples = fallback_scan(iface);
#endif

    int count = static_cast<int>(samples.size());
    if (count > max_results) count = max_results;

    for (int i = 0; i < count; ++i) {
        channels_out[i] = samples[i].channel;
        rssi_out[i]     = samples[i].rssi;
    }

    return count;
}

// ---------------------------------------------------------------------------

int hackit_spectrum_find_busy(const char* iface, int band) {
    if (!iface) return -1;

    std::vector<ChannelSample> samples;

#if defined(__linux__)
    samples = iw_parse_scan(iface);
#elif defined(_WIN32)
    samples = netsh_parse_networks(iface);
#else
    return -1;
#endif

    int best_ch   = -1;
    int best_rssi = -999;

    for (const auto& s : samples) {
        if (!channel_in_band(s.channel, band)) continue;
        if (s.rssi > best_rssi) {
            best_rssi = s.rssi;
            best_ch   = s.channel;
        }
    }

    return best_ch;
}

// ---------------------------------------------------------------------------

int hackit_spectrum_find_silent(const char* iface, int band) {
    if (!iface) return -1;

    // Detect available channels for the band
    std::vector<int> available;
#if defined(__linux__)
    available = detect_channels_linux(band);
#elif defined(_WIN32)
    available = detect_channels_windows(band);
#else
    available = detect_channels_fallback(band);
#endif

    if (available.empty()) return -1;

    // Scan to see which channels are occupied
    std::vector<ChannelSample> samples;
#if defined(__linux__)
    samples = iw_parse_scan(iface);
#elif defined(_WIN32)
    samples = netsh_parse_networks(iface);
#endif

    // Build a set of occupied channels and their RSSI
    // Use a simple linear scan since channel counts are small.
    struct Occ {
        int ch;
        int rssi;
    };
    std::vector<Occ> occupied;
    for (const auto& s : samples) {
        if (channel_in_band(s.channel, band)) {
            occupied.push_back({s.channel, s.rssi});
        }
    }

    // Find channel with weakest (most negative) RSSI — i.e. quietest.
    int quietest_ch   = available[0];
    int quietest_rssi = 0; // 0 means no signal detected

    // First, check if any available channel is NOT in occupied list → truly silent.
    for (int ch : available) {
        bool found = false;
        for (const auto& occ : occupied) {
            if (occ.ch == ch) { found = true; break; }
        }
        if (!found) return ch; // completely silent — ideal
    }

    // All channels occupied; return the one with lowest RSSI.
    bool first = true;
    for (const auto& occ : occupied) {
        if (!channel_in_band(occ.ch, band)) continue;
        if (first || occ.rssi < quietest_rssi) {
            quietest_rssi = occ.rssi;
            quietest_ch   = occ.ch;
            first = false;
        }
    }

    return quietest_ch;
}

// ---------------------------------------------------------------------------

bool hackit_spectrum_channel_utilization(const char* iface, int channel,
                                         float* out_utilization) {
    if (!iface || channel <= 0 || !out_utilization) return false;

#if defined(__linux__)
    return iw_utilization(iface, channel, out_utilization);
#elif defined(_WIN32)
    return win_utilization(iface, channel, out_utilization);
#else
    return fallback_utilization(iface, channel, out_utilization);
#endif
}

} // extern "C"
