#ifndef CPP_DEAUTH_ENGINE_H
#define CPP_DEAUTH_ENGINE_H

#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>

class CppDeauthEngine {
public:
    CppDeauthEngine(const std::string& iface, const std::string& bssid,
                    const std::string& station = "FF:FF:FF:FF:FF:FF",
                    uint16_t reason = 7);
    ~CppDeauthEngine();

    void start();
    void stop();
    bool is_running() const { return running_; }
    long long sent() const { return sent_.load(); }

    void set_channel_hop(bool enable) { channel_hop_ = enable; }
    void set_burst_size(int n) { burst_ = n; }

private:
    void loop();
    void build_frame(uint8_t* buf, const uint8_t* bssid, const uint8_t* station, uint16_t reason, uint16_t seq);
    void set_channel(int ch);
    int open_socket();

    std::string iface_;
    uint8_t bssid_[6], station_[6];
    uint16_t reason_;
    bool targeted_;
    std::atomic<bool> running_{false};
    std::atomic<long long> sent_{0};
    std::thread worker_;
    bool channel_hop_{true};
    int burst_{64};
};

#endif
