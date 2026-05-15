#include <iostream>
#include <vector>
#include <string>
#include "network_core.hpp"

class InjectorCore {
public:
    void process_shaped_targets(const std::string& json_input) {
        std::cout << "[*] INJECTOR: Receiving prioritized intelligence cluster..." << std::endl;
        // In a real implementation, we would parse the JSON and fuzz based on priority
    }
    
    void high_precision_fuzz(const std::string& target, const std::string& payload) {
        NetworkCore net;
        long status = 0;
        net.send_request(target, status);
        if (status == 200) {
            std::cout << "[+] SUCCESS: " << target << " is vulnerable." << std::endl;
        }
    }
};
