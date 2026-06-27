#ifndef EVILTWIN_CPP_V2_H
#define EVILTWIN_CPP_V2_H

#include <string>
#include <vector>
#include <array>
#include <atomic>
#include <thread>
#include <cstdint>

class EviltwinBeaconV2 {
public:
    EviltwinBeaconV2(const std::string& iface, const std::vector<std::string>& ssids,
                     const std::vector<std::string>& bssids, uint8_t channel);
    ~EviltwinBeaconV2();

    void start();
    void stop();
    uint64_t sent() const { return sent_.load(); }

    void set_real_bssid(const std::string& bssid);
    void start_deauth();
    void stop_deauth();
    uint64_t deauth_sent() const { return deauth_sent_.load(); }
    std::vector<std::string> get_clients() const;

private:
    void beacon_loop();
    void deauth_loop();
    int open_socket();
    void set_channel(int ch);
    void build_deauth_frame(uint8_t* buf, uint8_t frame_type,
                            const uint8_t* bssid, const uint8_t* station);

    std::string iface_;
    std::vector<std::string> ssids_;
    std::vector<std::array<uint8_t, 6>> bssids_;
    uint8_t channel_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> sent_{0};
    std::thread beacon_worker_;
    std::thread deauth_worker_;

    uint8_t real_bssid_[6];
    bool real_bssid_set_ = false;
    std::vector<std::string> detected_clients_;
    mutable pthread_mutex_t clients_lock_ = PTHREAD_MUTEX_INITIALIZER;
    uint16_t seq_ = 0;

    uint8_t deauth_frame_[64];
    int deauth_frame_len_ = 0;
    uint8_t disassoc_frame_[64];
    int disassoc_frame_len_ = 0;
    std::atomic<uint64_t> deauth_sent_{0};
    std::atomic<bool> deauth_running_{false};
};

#endif
