/*
 * HackIT Attack Surface Analyzer (C++)
 * Calculates risk scores, severity distribution, and generates suggested actions.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
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


using namespace std;

struct SeverityStats {
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
};

class SurfaceAnalyzer {
public:
    string calculate_attack_surface(int open_ports, int vuln_count) {
        if (open_ports > 50 || vuln_count > 10) return "HIGH";
        if (open_ports > 10 || vuln_count > 3) return "MEDIUM";
        return "LOW";
    }

    vector<string> generate_suggested_actions(const string& service, int port) {
        vector<string> actions;
        string s_lower = service;
        for(auto &c : s_lower) c = tolower(c);

        if (s_lower.find("http") != string::npos) {
            actions.emplace_back("Directory brute-force (HTTP)");
            actions.emplace_back("Vulnerability scan for " + service);
        } else if (s_lower.find("ssh") != string::npos) {
            actions.emplace_back("SSH credential testing (Brute-force check)");
        } else if (s_lower.find("ftp") != string::npos) {
            actions.emplace_back("Anonymous FTP access verification");
        } else if (s_lower.find("mysql") != string::npos || s_lower.find("postgresql") != string::npos) {
            actions.emplace_back("Database remote access security audit");
        }
        
        return actions;
    }
};

extern "C" {
    #ifdef _WIN32
    __declspec(dllexport)
    #endif
    const char* get_surface_intelligence(int open_ports, int vuln_count, const char* services_csv) noexcept {
        static string result;
        SurfaceAnalyzer analyzer;
        
        string surface = analyzer.calculate_attack_surface(open_ports, vuln_count);
        result = "SURFACE:" + surface + "|ACTIONS:";
        
        // Very basic parsing of CSV services to generate actions
        string svcs = services_csv;
        if (!svcs.empty()) {
            auto actions = analyzer.generate_suggested_actions(svcs, 0); 
            for (const auto& a : actions) {
                result += a + ";";
            }
        }
        
        return result.c_str();
    }
}
