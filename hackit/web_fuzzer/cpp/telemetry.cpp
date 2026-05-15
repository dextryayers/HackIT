#include <iostream>
#include <string>
#include <vector>

class Telemetry {
public:
    void report_vulnerability(const std::string& target, const std::string& payload, int status) {
        // High-fidelity reporting style matching the user's screenshots
        if (status == 200 || status == 301) {
            std::cout << "\033[1;32m[+] VULN FOUND: " << target << " | PAYLOAD: " << payload << " | CODE: " << status << "\033[0m" << std::endl;
        }
    }

    void show_summary(int total_requests, int vulns_found) {
        std::cout << "------------------------------------------------------------" << std::endl;
        std::cout << "\033[1;36m[+] Total unique payloads tested : " << total_requests << "\033[0m" << std::endl;
        std::cout << "\033[1;32m[+] Vulnerabilities identified   : " << vulns_found << "\033[0m" << std::endl;
    }
};
