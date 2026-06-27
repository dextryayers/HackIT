#ifndef EVILTWIN_CPP_V3_H
#define EVILTWIN_CPP_V3_H

#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>

class EviltwinFull {
public:
    EviltwinFull(const std::string& iface, const std::string& ssid,
                 const std::string& bssid, uint8_t channel, int portal_port);
    ~EviltwinFull();

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
    void write_config();
    int open_socket();
    void set_channel(int ch);
    void build_deauth_frame(uint8_t* buf, uint8_t frame_type,
                            const uint8_t* bssid, const uint8_t* station);

    std::string iface_;
    std::string ssid_;
    uint8_t bssid_[6];
    uint8_t channel_;
    int portal_port_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> sent_{0};
    std::thread beacon_thread_;
    std::thread deauth_thread_;

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
