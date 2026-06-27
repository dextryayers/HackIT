#ifndef CPP_DEAUTH_ULTRA_H
#define CPP_DEAUTH_ULTRA_H

#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <functional>

class CppDeauthUltra {
public:
    CppDeauthUltra(const std::string& bssid, const std::string& station = "FF:FF:FF:FF:FF:FF",
                   uint16_t reason = 7);
    ~CppDeauthUltra();

    void add_interface(const std::string& iface, int weight = 1);
    void start(int threads = 4);
    void stop();
    long long total_sent() const { return total_.load(); }
    double pps() const;

private:
    void worker(int fd, int weight);
    int open_socket(const std::string& iface);
    void build_frame(uint8_t* buf, const uint8_t* bssid, const uint8_t* station, uint16_t reason, uint16_t seq);

    struct IfaceSlot {
        std::string name;
        int fd = -1;
        int weight = 1;
    };

    std::vector<IfaceSlot> ifaces_;
    uint8_t bssid_[6], station_[6];
    uint16_t reason_;
    bool targeted_;
    std::atomic<bool> running_{false};
    std::atomic<long long> total_{0};
    std::atomic<long long> pps_count_{0};
    std::vector<std::thread> workers_;
};

#endif
