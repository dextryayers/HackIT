/*
 * HackIT Attack Surface Analyzer (C++)
 * Calculates risk scores, severity distribution, and generates suggested actions.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

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
            actions.push_back("Directory brute-force (HTTP)");
            actions.push_back("Vulnerability scan for " + service);
        } else if (s_lower.find("ssh") != string::npos) {
            actions.push_back("SSH credential testing (Brute-force check)");
        } else if (s_lower.find("ftp") != string::npos) {
            actions.push_back("Anonymous FTP access verification");
        } else if (s_lower.find("mysql") != string::npos || s_lower.find("postgresql") != string::npos) {
            actions.push_back("Database remote access security audit");
        }
        
        return actions;
    }
};

extern "C" {
    #ifdef _WIN32
    __declspec(dllexport)
    #endif
    const char* get_surface_intelligence(int open_ports, int vuln_count, const char* services_csv) {
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
