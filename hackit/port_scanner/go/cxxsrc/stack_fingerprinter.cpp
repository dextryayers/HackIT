#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <mutex>
#include <cmath>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string_view>
#include <memory>
#include <unordered_map>


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct OSSignature {
    std::string os_name;
    std::string os_version;
    std::string os_family;
    int expected_ttl;
    int expected_window;
    int expected_mss;
    int expected_wscale;
    bool expects_timestamp;
    bool expects_sack;
    std::string tcp_option_fingerprint;
    std::vector<int> window_range;
    std::vector<int> ttl_range;
    double weight;
};

class StackFingerprinter {
public:
    struct RawProbe {
        int initial_ttl;
        int window_size;
        int mss;
        int wscale;
        bool timestamp;
        bool sack;
        bool nop_padding;
        std::string tcp_options_str;
    };

    struct FingerprintResult {
        std::string os_name;
        std::string os_version;
        std::string os_family;
        double confidence;
        RawProbe probe;
    };

private:
    std::vector<OSSignature> os_signatures;
    std::mutex mtx;

    void init_signatures() noexcept {
        os_signatures = {
            {"Linux", "6.x", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.95},
            {"Linux", "5.x", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.95},
            {"Linux", "4.x", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {29200, 65535}, {60, 64}, 0.93},
            {"Linux", "3.x", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {5840, 65535}, {60, 64}, 0.90},
            {"Linux", "2.6.x", "Linux", 64, 5840, 1460, 0, false, true, "MSS:1460,SACK", {5840, 29200, 65535}, {60, 64}, 0.85},
            {"Linux", "2.4.x", "Linux", 64, 5840, 1460, 0, false, true, "MSS:1460,SACK", {32120, 5840}, {60, 64}, 0.80},
            {"Windows", "11", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 65520, 64240}, {120, 128}, 0.92},
            {"Windows", "10", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 65520, 64240, 8192}, {120, 128}, 0.95},
            {"Windows", "8.1", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.88},
            {"Windows", "8", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.85},
            {"Windows", "7", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.88},
            {"Windows", "Vista", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.83},
            {"Windows", "XP", "Windows", 128, 65535, 1460, 0, false, true, "MSS:1460,SACK", {65535, 8192}, {120, 128}, 0.80},
            {"Windows", "2000", "Windows", 128, 17520, 1460, 0, false, false, "MSS:1460", {17520, 16384, 65535}, {120, 128}, 0.70},
            {"macOS", "14.x Sonoma", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.88},
            {"macOS", "13.x Ventura", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.87},
            {"macOS", "12.x Monterey", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.86},
            {"macOS", "11.x Big Sur", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.85},
            {"macOS", "10.15 Catalina", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.83},
            {"macOS", "10.14 Mojave", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.82},
            {"macOS", "10.13 High Sierra", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.80},
            {"macOS", "10.12 Sierra", "macOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.78},
            {"FreeBSD", "13.x", "FreeBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.85},
            {"FreeBSD", "12.x", "FreeBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520, 65529}, {60, 64}, 0.83},
            {"FreeBSD", "11.x", "FreeBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.80},
            {"FreeBSD", "10.x", "FreeBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535}, {60, 64}, 0.78},
            {"OpenBSD", "7.x", "OpenBSD", 64, 16384, 1460, 3, true, true, "MSS:1460,WScale:3,TSval,SACK", {16384}, {60, 64}, 0.82},
            {"OpenBSD", "6.x", "OpenBSD", 64, 16384, 1460, 3, true, true, "MSS:1460,WScale:3,TSval,SACK,NOP", {16384}, {60, 64}, 0.80},
            {"Solaris", "11", "Solaris", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.75},
            {"Solaris", "10", "Solaris", 64, 65535, 1460, 0, false, true, "MSS:1460,SACK", {65535, 32000}, {60, 64}, 0.72},
            {"Cisco IOS", "15.x", "Cisco", 64, 4128, 1460, 0, false, false, "MSS:1460", {4128, 16384}, {60, 64}, 0.70},
            {"Cisco IOS", "12.x", "Cisco", 64, 16384, 1460, 0, false, false, "MSS:1460", {16384, 4128}, {60, 64}, 0.68},
            {"Android", "14", "Android", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.80},
            {"Android", "13", "Android", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.78},
            {"Android", "12", "Android", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.76},
            {"Android", "11", "Android", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.74},
            {"Android", "10", "Android", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.72},
            {"iOS", "17.x", "iOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.82},
            {"iOS", "16.x", "iOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.80},
            {"iOS", "15.x", "iOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.78},
            {"iOS", "14.x", "iOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.76},
            {"iOS", "13.x", "iOS", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.74},
            {"HP-UX", "11i", "HP-UX", 64, 32768, 1460, 0, false, false, "MSS:1460", {32768, 65535}, {60, 64}, 0.55},
            {"AIX", "7.x", "AIX", 64, 32768, 1460, 0, false, true, "MSS:1460,SACK", {32768, 65535, 16384}, {60, 64}, 0.55},
            {"AIX", "6.x", "AIX", 64, 32768, 1460, 0, false, false, "MSS:1460", {32768, 65535}, {60, 64}, 0.50},
            {"NetBSD", "9.x", "NetBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.68},
            {"NetBSD", "8.x", "NetBSD", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.65},
            {"DragonFly", "6.x", "DragonFly", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.55},
            {"QNX", "6.x", "QNX", 64, 16384, 1460, 0, false, false, "MSS:1460", {16384, 32768}, {60, 64}, 0.45},
            {"VxWorks", "7", "VxWorks", 64, 65535, 1460, 0, false, false, "MSS:1460", {65535, 32768}, {60, 64}, 0.40},
            {"Contiki", "3.x", "Contiki", 64, 536, 536, 0, false, false, "MSS:536", {536}, {60, 64}, 0.35},
            {"Zephyr", "3.x", "Zephyr", 64, 65535, 1460, 0, false, false, "MSS:1460", {65535, 16384}, {60, 64}, 0.30},
            {"Windows Server", "2022", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 65520, 64240}, {120, 128}, 0.88},
            {"Windows Server", "2019", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 65520, 64240, 8192}, {120, 128}, 0.86},
            {"Windows Server", "2016", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.84},
            {"Windows Server", "2012 R2", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.82},
            {"Windows Server", "2012", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.80},
            {"Windows Server", "2008 R2", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.78},
            {"Windows Server", "2008", "Windows", 128, 65535, 1460, 8, true, true, "MSS:1460,WScale:8,TSval,SACK", {65535, 8192}, {120, 128}, 0.76},
            {"Windows Server", "2003", "Windows", 128, 65535, 1460, 0, false, true, "MSS:1460,SACK", {65535, 8192}, {120, 128}, 0.72},
            {"Ubuntu", "22.04", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.82},
            {"Ubuntu", "20.04", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.80},
            {"Ubuntu", "18.04", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.78},
            {"Debian", "12", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.78},
            {"Debian", "11", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.76},
            {"Debian", "10", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.74},
            {"CentOS", "9", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.72},
            {"CentOS", "8", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.70},
            {"CentOS", "7", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.68},
            {"Fedora", "38", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.75},
            {"Fedora", "37", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.73},
            {"Fedora", "36", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.71},
            {"RHEL", "9", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.72},
            {"RHEL", "8", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.70},
            {"RHEL", "7", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.68},
            {"OpenWrt", "22.x", "Linux", 64, 65535, 1460, 7, true, true, "MSS:1460,WScale:7,TSval,SACK", {65535, 65520}, {60, 64}, 0.55},
            {"DD-WRT", "3.x", "Linux", 64, 5840, 1460, 2, true, true, "MSS:1460,WScale:2,TSval,SACK", {5840, 65535}, {60, 64}, 0.45},
        };
    }

    double compute_ttl_match_score(int observed, int expected) noexcept {
        double diff = std::abs(observed - expected);
        if (diff <= 4) return 1.0;
        if (diff <= 16) return 0.7;
        if (diff <= 32) return 0.4;
        return 0.1;
    }

    double compute_window_match_score(int observed, const std::vector<int>& expected_values) noexcept {
        for (int ev : expected_values) {
            if (std::abs(observed - ev) <= 100) return 1.0;
        }
        if (expected_values.empty()) return 0.0;
        int min_expected = *std::min_element(expected_values.begin(), expected_values.end());
        int max_expected = *std::max_element(expected_values.begin(), expected_values.end());
        if (observed >= min_expected && observed <= max_expected) return 0.7;
        return 0.2;
    }

public:
    StackFingerprinter() {
        init_signatures();
    }

    RawProbe extract_probe(int sockfd) {
        RawProbe probe;
        probe.initial_ttl = 64;
        probe.window_size = 65535;
        probe.mss = 1460;
        probe.wscale = 7;
        probe.timestamp = true;
        probe.sack = true;
        probe.nop_padding = false;
        probe.tcp_options_str = "MSS:1460,WScale:7,TSval,SACK";

        struct tcp_info tcpinfo;
        socklen_t len = sizeof(tcpinfo);
        if (getsockopt(sockfd, SOL_TCP, TCP_INFO, &tcpinfo, &len) == 0) {
            probe.mss = tcpinfo.tcpi_snd_mss;
            if (tcpinfo.tcpi_options & TCPI_OPT_WSCALE) {
                probe.wscale = tcpinfo.tcpi_snd_wscale;
            }
            if (tcpinfo.tcpi_options & TCPI_OPT_TIMESTAMPS) {
                probe.timestamp = true;
            }
            if (tcpinfo.tcpi_options & TCPI_OPT_SACK) {
                probe.sack = true;
            }
#ifdef TCPI_OPT_NOP
            if (tcpinfo.tcpi_options & TCPI_OPT_NOP) {
                probe.nop_padding = true;
            }
#endif
            probe.window_size = tcpinfo.tcpi_snd_cwnd;
        }

        std::ostringstream oss;
        oss << "MSS:" << probe.mss
            << ",WScale:" << probe.wscale
            << ",TSval:" << (probe.timestamp ? "Y" : "N")
            << ",SACK:" << (probe.sack ? "Y" : "N")
            << ",NOP:" << (probe.nop_padding ? "Y" : "N");
        probe.tcp_options_str = oss.str();

        return probe;
    }

    RawProbe extract_probe_params(int ttl, int window, int mss, int wscale,
                                   bool ts, bool sack, bool nop) {
        RawProbe probe;
        probe.initial_ttl = ttl;
        probe.window_size = window;
        probe.mss = mss;
        probe.wscale = wscale;
        probe.timestamp = ts;
        probe.sack = sack;
        probe.nop_padding = nop;

        std::ostringstream oss;
        oss << "MSS:" << mss << ",WScale:" << wscale
            << ",TSval:" << (ts ? "Y" : "N")
            << ",SACK:" << (sack ? "Y" : "N")
            << ",NOP:" << (nop ? "Y" : "N");
        probe.tcp_options_str = oss.str();

        return probe;
    }

    FingerprintResult fingerprint(const RawProbe& probe) noexcept {
        FingerprintResult result;
        result.probe = probe;

        double best_score = 0.0;
        std::string best_os = "Unknown";
        std::string best_version = "";
        std::string best_family = "Unknown";

        for (const auto& sig : os_signatures) {
            double score = 0.0;

            double ttl_score = compute_ttl_match_score(probe.initial_ttl, sig.expected_ttl);
            score += ttl_score * 0.30;

            double window_score = compute_window_match_score(probe.window_size, sig.window_range);
            score += window_score * 0.25;

            double mss_score = (probe.mss == sig.expected_mss) ? 1.0 :
                               (std::abs(probe.mss - sig.expected_mss) < 100 ? 0.5 : 0.0);
            score += mss_score * 0.15;

            double wscale_score = (probe.wscale == sig.expected_wscale) ? 1.0 : 0.0;
            score += wscale_score * 0.10;

            double ts_score = (probe.timestamp == sig.expects_timestamp) ? 1.0 : 0.0;
            score += ts_score * 0.08;

            double sack_score = (probe.sack == sig.expects_sack) ? 1.0 : 0.0;
            score += sack_score * 0.07;

            score *= sig.weight;

            if (score > best_score) {
                best_score = score;
                best_os = sig.os_name;
                best_version = sig.os_version;
                best_family = sig.os_family;
            }
        }

        result.os_name = best_os;
        result.os_version = best_version;
        result.os_family = best_family;
        result.confidence = std::min(1.0, best_score * 1.2);

        return result;
    }

    void print_result(const FingerprintResult& result, std::string_view target, int port) noexcept {
        std::cout << "RESULT:{\"target\":\"" << target
                  << "\",\"port\":" << port
                  << ",\"os_name\":\"" << result.os_name
                  << "\",\"os_version\":\"" << result.os_version
                  << "\",\"os_family\":\"" << result.os_family
                  << "\",\"confidence\":" << std::fixed << std::setprecision(4) << result.confidence
                  << ",\"initial_ttl\":" << result.probe.initial_ttl
                  << ",\"window_size\":" << result.probe.window_size
                  << ",\"mss\":" << result.probe.mss
                  << ",\"wscale\":" << result.probe.wscale
                  << ",\"timestamp\":" << (result.probe.timestamp ? "true" : "false")
                  << ",\"sack\":" << (result.probe.sack ? "true" : "false")
                  << ",\"tcp_options\":\"" << result.probe.tcp_options_str
                  << "\"}" << '\n';

        std::cout << "FINAL:{\"target\":\"" << target
                  << "\",\"port\":" << port
                  << ",\"os\":\"" << result.os_name << " " << result.os_version
                  << "\",\"family\":\"" << result.os_family
                  << "\",\"confidence\":" << std::fixed << std::setprecision(4) << result.confidence
                  << "}" << '\n';
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target:port> [ttl] [window] [mss] [wscale] [ts] [sack] [nop]" << '\n';
        std::cerr << "  If no probe params given, attempts TCP_INFO getsockopt on port" << '\n';
        return 1;
    }

    std::string input = argv[1];
    std::string target;
    int port = 0;
    size_t colon = input.find(':');
    if (colon != std::string::npos) {
        target = input.substr(0, colon);
        try { port = std::stoi(input.substr(colon + 1)); }
        catch (...) { port = 0; }
    } else {
        target = input;
    }

    StackFingerprinter fingerprinter;
    StackFingerprinter::RawProbe probe;

    if (argc > 7) {
        int ttl = std::atoi(argv[2]);
        int window = std::atoi(argv[3]);
        int mss = std::atoi(argv[4]);
        int wscale = std::atoi(argv[5]);
        bool ts = (std::string(argv[6]) == "1" || std::string(argv[6]) == "true");
        bool sack = (std::string(argv[7]) == "1" || std::string(argv[7]) == "true");
        bool nop = (argc > 8) ? (std::string(argv[8]) == "1" || std::string(argv[8]) == "true") : false;
        probe = fingerprinter.extract_probe_params(ttl, window, mss, wscale, ts, sack, nop);
    } else {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            struct sockaddr_in addr;
            std::memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (inet_pton(AF_INET, target.c_str(), &addr.sin_addr) <= 0) {
                probe = fingerprinter.extract_probe_params(64, 65535, 1460, 7, true, true, false);
            } else {
                if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    probe = fingerprinter.extract_probe(sockfd);
                } else {
                    probe = fingerprinter.extract_probe_params(64, 65535, 1460, 7, true, true, false);
                }
            }
            close(sockfd);
        } else {
            probe = fingerprinter.extract_probe_params(64, 65535, 1460, 7, true, true, false);
        }
    }

    auto result = fingerprinter.fingerprint(probe);
    fingerprinter.print_result(result, target, port);

    return 0;
}
