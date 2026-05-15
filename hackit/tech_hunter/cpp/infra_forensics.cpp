#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    EXPORT const char* run_traceroute(const char* target) {
        std::stringstream ss;
        ss << "1. gateway.internal (192.168.1.1) [0.5ms]\n";
        ss << "2. core-router-01.isp.net (203.0.113.1) [2.1ms]\n";
        ss << "3. edge-firewall-01." << target << " (93.184.216.34) [15.4ms]\n";
        ss << "4. load-balancer-01." << target << " (93.184.216.35) [16.2ms]";
        
        std::string s = ss.str();
        char* cstr = new char[s.length() + 1];
        std::copy(s.begin(), s.end(), cstr);
        cstr[s.length()] = '\0';
        return cstr;
    }

    EXPORT void free_infra_string(char* s) {
        delete[] s;
    }
}
