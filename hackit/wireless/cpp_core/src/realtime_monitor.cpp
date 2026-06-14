#include "cpp_bridge.h"
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <map>
#include <vector>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

struct BSSIDStats {
    std::string bssid;
    int packet_count{0};
    int signal_sum{0};
    int signal_samples{0};
    std::vector<int> signal_history;
};

class Monitor {
public:
    Monitor() : running(false), total_packets(0), last_pkt_count(0) {}
    ~Monitor() { stop(); }

    bool start(const char *iface) {
        if (running) return false;
        iface_name = iface ? iface : "";
        fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) { perror("socket"); return false; }
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("ioctl"); close(fd); return false; }
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); close(fd); return false; }
        running = true;
        last_pkt_count = 0;
        last_stats_time = std::chrono::steady_clock::now();
        worker = std::thread(&Monitor::capture_loop, this);
        return true;
    }

    void stop() {
        running = false;
        if (worker.joinable()) worker.join();
        if (fd >= 0) { close(fd); fd = -1; }
    }

    std::string get_stats() {
        std::lock_guard<std::mutex> lock(mtx);
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last_stats_time).count();
        double pkt_sec = elapsed > 0 ? (total_packets - last_pkt_count) / elapsed : 0;
        last_pkt_count = total_packets;
        last_stats_time = now;
        std::ostringstream os;
        os << "{"
            << "\"packets_per_sec\":" << pkt_sec << ","
            << "\"total_packets\":" << total_packets << ","
            << "\"active_bssids\":" << bssid_map.size() << ","
            << "\"channel_util_pct\":" << (pkt_sec > 100 ? 100.0 : pkt_sec / 10.0) << ""
            << "}";
        return os.str();
    }

    std::string get_channel_util() {
        std::lock_guard<std::mutex> lock(mtx);
        int total = 0;
        for (const auto &pair : bssid_map)
            total += pair.second.packet_count;
        std::ostringstream os;
        os << "[";
        bool first = true;
        for (const auto &pair : bssid_map) {
            if (!first) os << ",";
            double util = total > 0 ? (double)pair.second.packet_count / total * 100.0 : 0;
            os << "{\"bssid\":\"" << pair.first << "\",\"utilization\":" << util << "}";
            first = false;
        }
        os << "]";
        return os.str();
    }

    std::string get_signal_history(const char *bssid) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = bssid_map.find(bssid ? bssid : "");
        if (it == bssid_map.end()) return "[]";
        std::ostringstream os;
        os << "[";
        for (size_t i = 0; i < it->second.signal_history.size(); i++) {
            if (i > 0) os << ",";
            os << it->second.signal_history[i];
        }
        os << "]";
        return os.str();
    }

private:
    void capture_loop() {
        uint8_t buf[65536];
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        while (running) {
            int n = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
            if (n < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }
            std::lock_guard<std::mutex> lock(mtx);
            total_packets++;
            if (n >= 16) {
                char bssid_str[18];
                snprintf(bssid_str, sizeof(bssid_str),
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
                std::string key(bssid_str);
                auto &s = bssid_map[key];
                if (s.bssid.empty()) s.bssid = key;
                s.packet_count++;
            }
        }
    }

    int fd{-1};
    std::string iface_name;
    std::atomic<bool> running;
    std::thread worker;
    std::mutex mtx;
    int total_packets;
    int last_pkt_count;
    std::chrono::steady_clock::time_point last_stats_time;
    std::map<std::string, BSSIDStats> bssid_map;
};

static Monitor g_monitor;

extern "C" int monitor_start(const char *iface) {
    return g_monitor.start(iface) ? 0 : -1;
}

extern "C" int monitor_stop(void) {
    g_monitor.stop();
    return 0;
}

extern "C" const char* monitor_get_stats(void) {
    static std::string result;
    result = g_monitor.get_stats();
    return result.c_str();
}

extern "C" const char* monitor_get_channel_util(void) {
    static std::string result;
    result = g_monitor.get_channel_util();
    return result.c_str();
}

extern "C" const char* monitor_get_signal_history(const char *bssid) {
    static std::string result;
    result = g_monitor.get_signal_history(bssid);
    return result.c_str();
}
