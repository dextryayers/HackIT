/*
 * os_detect.cpp — Real TCP/IP OS fingerprinting engine
 * Uses raw SYN probes + banner grabbing + TTL analysis
 * against a 65-entry signature database covering all major OS families.
 *
 * Usage: ./os_detect <host> [ports] [timeout_ms]
 *   ports     comma-separated probe ports (default: 22,80,443,21,25,8080)
 *   timeout   per-probe timeout in ms (default: 2000)
 *
 * Requires root (CAP_NET_RAW) for raw sockets; degraded mode without.
 * Output: RESULT:{ ... } single-line JSON with all fingerprint details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <thread>
#include <mutex>
#include <iomanip>
#include <functional>
#include <memory>
#include <cmath>
#include <unordered_map>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>

// ---------------------------------------------------------------------------
// TCP option kinds (RFC 793, 2018, 1323)
// ---------------------------------------------------------------------------
#define TCPOPT_EOL        0
#define TCPOPT_NOP        1
#define TCPOPT_MSS        2
#define TCPOPT_WSCALE     3
#define TCPOPT_SACK_DATA  4   // Selective ACK data (not SACK-permitted)
#define TCPOPT_SACK_PERM  5   // SACK permitted
#define TCPOPT_TIMESTAMP  8

#pragma pack(push, 1)
struct PseudoHeader {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

struct TcpOption {
    uint8_t kind;
    uint8_t len;
    uint8_t data[6];
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Fingerprint result
// ---------------------------------------------------------------------------
struct ProbeResult {
    uint8_t    ttl{0};
    uint16_t   window{0};
    int        df{-1};       // -1=unknown, 0=no, 1=yes
    uint16_t   mss{0};
    int        wscale{-1};
    int        timestamp{-1}; // -1=unknown, 0=no, 1=yes
    int        sack_ok{-1};  // -1=unknown, 0=no, 1=yes
    bool       sack{false};
    int        nop{-1};      // -1=unknown, 0=no, 1=yes
    bool       connected{false};
    int        rtt_ms{0};
    std::string tcp_options;
};

struct Fingerprint {
    std::string os_family;
    std::string os_name;
    std::string os_version;
    int         confidence{0};
    std::string device_type;
    std::string banner_hint;
    std::string tcp_options;
    std::vector<int> open_ports;
    ProbeResult probe;
};

// ---------------------------------------------------------------------------
// OS Signature database entry
// ---------------------------------------------------------------------------
struct OSSignature {
    std::string family;
    std::string name;
    std::string version;

    // TTL range
    int ttl_min;
    int ttl_max;

    // Window size range (0 = any)
    int win_min;
    int win_max;

    // TCP options
    int  mss;        // 0 = any
    int  wscale;     // -1 = any
    int  df;         // -1 = any, 0 = no, 1 = yes
    int  timestamp;  // -1 = any
    int  sack;       // -1 = any
    int  nop;        // -1 = any

    // Banner patterns: service -> substring
    std::vector<std::pair<std::string,std::string>> banners;

    // Confidence weight when matched
    int weight;

    // Device type
    std::string device;
};

// ---------------------------------------------------------------------------
// 65-entry OS fingerprint signature database
// ---------------------------------------------------------------------------
static const std::vector<OSSignature> kSignatures = {
    // ===== WINDOWS =====
    {"Windows","Windows XP","XP",
     125,130, 65320,65535, 1460,0, 1, 1, 1, 1, {}, 95,"General"},
    {"Windows","Windows XP","XP SP2",
     125,130, 65320,65535, 1460,8, 1, 1, 1, 1, {}, 95,"General"},
    {"Windows","Windows Vista","Vista",
     125,130, 8192,8192, 1460,2, 1, 1, 1, 1, {}, 90,"General"},
    {"Windows","Windows 7","7",
     125,130, 8192,65535, 1460,2, 1, 1, 1, 1, {}, 95,"General"},
    {"Windows","Windows 8","8",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"General"},
    {"Windows","Windows 8.1","8.1",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"General"},
    {"Windows","Windows 10","10 1507-1607",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 92,"General"},
    {"Windows","Windows 10","10 1703-21H2",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 92,"General"},
    {"Windows","Windows 11","11 21H2-23H2",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 92,"General"},
    {"Windows","Windows Server 2003","2003",
     125,130, 65320,65535, 1460,0, 1, 1, 1, 1, {}, 90,"Server"},
    {"Windows","Windows Server 2008","2008",
     125,130, 8192,65535, 1460,2, 1, 1, 1, 1, {}, 90,"Server"},
    {"Windows","Windows Server 2012","2012",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"Server"},
    {"Windows","Windows Server 2016","2016",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"Server"},
    {"Windows","Windows Server 2019","2019",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"Server"},
    {"Windows","Windows Server 2022","2022",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1, {}, 90,"Server"},

    // ===== LINUX =====
    {"Linux","Linux Kernel 2.4","2.4.x",
     60,64, 32120,65535, 1460,0, 1, 1, 1, 1, {}, 88,"General"},
    {"Linux","Linux Kernel 2.6","2.6.x",
     60,64, 5792,5840, 1460,7, 1, 1, 1, 1, {}, 90,"General"},
    {"Linux","Linux Kernel 3.x","3.x",
     60,64, 5792,29200, 1460,7, 1, 1, 1, 1, {}, 90,"General"},
    {"Linux","Linux Kernel 4.x","4.x",
     60,64, 28960,29312, 1460,7, 1, 1, 1, 1, {}, 90,"General"},
    {"Linux","Linux Kernel 5.x","5.x",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1, {}, 90,"General"},
    {"Linux","Linux Kernel 6.x","6.x",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1, {}, 90,"General"},
    {"Linux","Ubuntu","Ubuntu (generic)",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Ubuntu"},{"HTTP","Ubuntu"},{"HTTP","Apache/2"}}, 86,"Server"},
    {"Linux","Debian","Debian",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Debian"},{"HTTP","Debian"}}, 85,"Server"},
    {"Linux","CentOS","CentOS",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","CentOS"},{"HTTP","CentOS"}}, 85,"Server"},
    {"Linux","Fedora","Fedora",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Fedora"},{"HTTP","Fedora"}}, 85,"Server"},
    {"Linux","RHEL","RHEL",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Red Hat"},{"SSH","RHEL"},{"HTTP","Red Hat"}}, 85,"Server"},
    {"Linux","Alpine Linux","Alpine",
     60,64, 14600,29200, 1460,7, 1, 1, 1, 1,
     {{"SSH","Alpine"}}, 80,"Container"},
    {"Linux","Arch Linux","Arch",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Arch"}}, 80,"General"},
    {"Linux","Gentoo","Gentoo",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Gentoo"}}, 80,"General"},
    {"Linux","openSUSE","openSUSE",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","openSUSE"},{"HTTP","openSUSE"}}, 80,"Server"},
    {"Linux","Slackware","Slackware",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"SSH","Slackware"}}, 80,"General"},

    // ===== macOS =====
    {"macOS","macOS Catalina","10.15",
     60,64, 65535,65535, 1460,3, 1, 0, 1, 1, {}, 88,"Desktop"},
    {"macOS","macOS Big Sur","11",
     60,64, 65535,65535, 1460,3, 1, 1, 1, 1, {}, 90,"Desktop"},
    {"macOS","macOS Monterey","12",
     60,64, 65535,65535, 1460,3, 1, 1, 1, 1, {}, 90,"Desktop"},
    {"macOS","macOS Ventura","13",
     60,64, 65535,65535, 1460,3, 1, 1, 1, 1, {}, 90,"Desktop"},
    {"macOS","macOS Sonoma","14",
     60,64, 65535,65535, 1460,3, 1, 1, 1, 1, {}, 90,"Desktop"},

    // ===== BSD =====
    {"BSD","FreeBSD","13.x",
     60,64, 65535,65535, 1460,1, 1, 1, 1, 1, {}, 88,"Server"},
    {"BSD","FreeBSD","14.x",
     60,64, 65535,65535, 1460,3, 1, 1, 1, 1, {}, 88,"Server"},
    {"BSD","OpenBSD","7.x",
     250,255, 16384,65535, 1460,1, 1, 0, 1, 1, {}, 88,"Firewall"},
    {"BSD","NetBSD","10.x",
     60,64, 65535,65535, 1460,0, 1, 1, 1, 1, {}, 85,"Server"},
    {"BSD","DragonFly BSD","6.x",
     60,64, 65535,65535, 1460,1, 1, 1, 1, 1, {}, 85,"Server"},

    // ===== MOBILE =====
    {"Android","Android","9-10",
     60,64, 5792,29200, 1440,7, 1, 1, 1, 1, {}, 80,"Mobile"},
    {"Android","Android","11-12",
     60,64, 5792,29200, 1460,8, 1, 1, 1, 1, {}, 80,"Mobile"},
    {"Android","Android","13-14",
     60,64, 5792,29200, 1460,8, 1, 1, 1, 1, {}, 80,"Mobile"},
    {"iOS","iOS","14-15",
     60,64, 65535,65535, 1440,3, 1, 1, 1, 1, {}, 82,"Mobile"},
    {"iOS","iOS","16-17",
     60,64, 65535,65535, 1440,3, 1, 1, 1, 1, {}, 82,"Mobile"},
    {"iPadOS","iPadOS","16-17",
     60,64, 65535,65535, 1440,3, 1, 1, 1, 1, {}, 82,"Mobile"},

    // ===== NETWORK DEVICES =====
    {"Cisco IOS","Cisco IOS","12.x-15.x",
     250,255, 4128,65535, 536,0, 0, 0, 1, 0, {}, 88,"Router"},
    {"Cisco IOS","Cisco IOS","15.x",
     250,255, 4128,65535, 1460,0, 0, 0, 1, 0, {}, 88,"Router"},
    {"Cisco IOS-XE","Cisco IOS-XE","16.x-17.x",
     250,255, 4128,65535, 1460,0, 1, 0, 1, 0, {}, 85,"Router"},
    {"Cisco NX-OS","Cisco NX-OS","7.x-10.x",
     60,64, 65535,65535, 1460,0, 1, 0, 1, 0, {}, 88,"Switch"},
    {"Juniper JunOS","Juniper JunOS","15.x-22.x",
     60,64, 65535,65535, 1460,0, 1, 0, 1, 0, {}, 88,"Router"},
    {"MikroTik RouterOS","MikroTik RouterOS","6.x-7.x",
     60,64, 65535,65535, 1460,2, 1, 0, 1, 0, {}, 85,"Router"},
    {"Fortinet FortiOS","Fortinet FortiOS","6.x-7.x",
     60,64, 65535,65535, 1460,0, 1, 0, 1, 1,
     {{"HTTP","Fortinet"},{"HTTPS","Fortinet"}}, 88,"Firewall"},
    {"Arista EOS","Arista EOS","4.x",
     60,64, 65535,65535, 1460,0, 1, 0, 1, 1, {}, 85,"Switch"},

    // ===== EMBEDDED =====
    {"OpenWrt","OpenWrt/LEDE","19.x-22.x",
     60,64, 28960,29200, 1460,7, 1, 1, 1, 1, {}, 85,"Router"},
    {"DD-WRT","DD-WRT","v24+",
     60,64, 5792,5840, 1460,0, 1, 0, 1, 1, {}, 80,"Router"},
    {"VxWorks","VxWorks","5.x-7.x",
     60,64, 4096,32768, 1460,0, 0, 0, 0, 0, {}, 88,"Embedded"},
    {"QNX","QNX Neutrino","6.x-7.x",
     60,64, 16384,65535, 1460,0, 1, 0, 1, 1, {}, 85,"RTOS"},

    // ===== SOLARIS =====
    {"Solaris","Solaris","10",
     250,255, 49152,65535, 1460,0, 1, 0, 1, 1, {}, 88,"Server"},
    {"Solaris","Solaris","11",
     250,255, 49152,65535, 1460,2, 1, 0, 1, 1, {}, 90,"Server"},
    {"Solaris","illumos","various",
     250,255, 49152,65535, 1460,2, 1, 0, 1, 1, {}, 85,"Server"},
    {"Solaris","OpenIndiana","various",
     250,255, 49152,65535, 1460,2, 1, 0, 1, 1, {}, 85,"Server"},

    // ===== AIX / HP-UX =====
    {"AIX","IBM AIX","7.1-7.3",
     60,64, 65535,65535, 1460,0, 1, 1, 1, 1,
     {{"SSH","AIX"},{"FTP","AIX"}}, 85,"Server"},
    {"HP-UX","HP-UX","11i v3",
     60,64, 32768,65535, 1460,0, 1, 0, 1, 1, {}, 85,"Server"},

    // ===== CONTAINERS =====
    {"Container","Docker","container",
     60,64, 28960,29200, 1460,7, 1, 1, 1, 1,
     {{"HTTP","Docker"},{"HTTP","docker"},{"HTTP","Docker Build"}}, 85,"Container"},
    {"Container","Kubernetes","node",
     60,64, 28960,29200, 1460,7, 1, 1, 1, 1,
     {{"HTTP","kube-apiserver"},{"HTTPS","kube"},{"HTTP","Kubernetes"}}, 88,"Orchestrator"},
    {"Container","LXC","container",
     60,64, 28960,29200, 1460,7, 1, 1, 1, 1, {}, 70,"Container"},

    // ===== HYPERVISORS =====
    {"VMware","VMware ESXi","6.x-8.x",
     60,64, 65535,65535, 1460,0, 1, 1, 1, 1,
     {{"HTTP","VMware ESXi"},{"HTTPS","VMware"}}, 92,"Hypervisor"},
    {"Xen","Xen","4.x",
     60,64, 65535,65535, 1460,0, 1, 1, 1, 1, {}, 80,"Hypervisor"},
    {"Hyper-V","Microsoft Hyper-V","2012-2022",
     125,130, 65535,65535, 1460,8, 1, 1, 1, 1,
     {{"HTTP","Hyper-V"}}, 85,"Hypervisor"},
    {"Proxmox","Proxmox VE","7.x-8.x",
     60,64, 28960,65535, 1460,7, 1, 1, 1, 1,
     {{"HTTP","Proxmox"},{"HTTPS","Proxmox"}}, 88,"Hypervisor"},
};

// ---------------------------------------------------------------------------
// Signal-safe flag for alarm
// ---------------------------------------------------------------------------
static volatile bool g_timedout = false;
static void sig_alarm(int) { g_timedout = true; }

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t l = s.find_first_not_of(" \t\r\n");
    size_t r = s.find_last_not_of(" \t\r\n");
    return (l == std::string::npos) ? "" : s.substr(l, r - l + 1);
}

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string item;
    while (std::getline(ss, item, d))
        out.push_back(trim(item));
    return out;
}

static bool is_root() { return geteuid() == 0; }

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------
static bool resolve_host(const std::string& host, struct sockaddr_in* addr) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (r != 0 || !res) return false;
    *addr = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);
    return true;
}

static uint16_t checksum(void* buf, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)buf;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(uint8_t*)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~(uint16_t)sum;
}

static uint16_t tcp_checksum(struct iphdr* ip, struct tcphdr* tcp, int tcp_len) {
    PseudoHeader ph;
    ph.src   = ip->saddr;
    ph.dst   = ip->daddr;
    ph.zero  = 0;
    ph.proto = IPPROTO_TCP;
    ph.len   = htons(tcp_len);

    char buf[sizeof(PseudoHeader) + tcp_len + 1];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &ph, sizeof(PseudoHeader));
    memcpy(buf + sizeof(PseudoHeader), tcp, tcp_len);
    return checksum(buf, sizeof(PseudoHeader) + tcp_len);
}

// ---------------------------------------------------------------------------
// Set socket non-blocking
// ---------------------------------------------------------------------------
static bool set_nonblock(int fd, bool nb) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return false;
    fcntl(fd, F_SETFL, nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
    return true;
}

// ---------------------------------------------------------------------------
// TCP SYN probe via raw socket — extracts TCP options from SYN-ACK
// ---------------------------------------------------------------------------
static bool syn_probe(const struct sockaddr_in& dst, int dport,
                      ProbeResult& out, int timeout_ms)
{
    if (!is_root()) return false;

    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw < 0) return false;

    int one = 1;
    if (setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(raw);
        return false;
    }

    // Build IP header
    char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr) + 40];
    memset(pkt, 0, sizeof(pkt));
    struct iphdr* ip  = (struct iphdr*)pkt;
    struct tcphdr* tcp = (struct tcphdr*)(pkt + sizeof(struct iphdr));

    // IP
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(pkt));
    ip->id       = htons(getpid() & 0xFFFF);
    ip->frag_off = htons(0x4000); // DF
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;

    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);
    if (getsockname(raw, (struct sockaddr*)&src, &srclen) < 0) {
        close(raw);
        return false;
    }
    ip->saddr = src.sin_addr.s_addr;
    ip->daddr = dst.sin_addr.s_addr;
    ip->check = checksum(pkt, sizeof(struct iphdr));

    // TCP
    uint16_t sport = 40000 + (getpid() % 10000) + (dport % 1000);
    tcp->source = htons(sport);
    tcp->dest   = htons(dport);
    tcp->seq    = htonl(0xDEADBEEF + dport);
    tcp->ack_seq = 0;
    tcp->doff   = 10; // 40 byte header to fit options
    tcp->syn    = 1;
    tcp->window = htons(65535);
    tcp->check  = 0;
    tcp->urg_ptr = 0;

    // TCP options: MSS, NOP, WScale, NOP, SACK_OK, Timestamp
    uint8_t* opt = (uint8_t*)(tcp) + sizeof(struct tcphdr);
    int olen = 0;
    // MSS
    opt[olen++] = TCPOPT_MSS;
    opt[olen++] = 4;
    *(uint16_t*)(opt + olen) = htons(1460);
    olen += 2;
    // NOP
    opt[olen++] = TCPOPT_NOP;
    // WScale
    opt[olen++] = TCPOPT_WSCALE;
    opt[olen++] = 3;
    opt[olen++] = 7;
    // NOP
    opt[olen++] = TCPOPT_NOP;
    // SACK permitted
    opt[olen++] = TCPOPT_SACK_PERM;
    opt[olen++] = 2;
    // Timestamp
    opt[olen++] = TCPOPT_TIMESTAMP;
    opt[olen++] = 10;
    uint32_t ts = htonl(time(nullptr));
    memcpy(opt + olen, &ts, 4);
    memset(opt + olen + 4, 0, 4);
    olen += 8;
    // Pad to multiple of 4
    while (olen % 4) { opt[olen++] = TCPOPT_EOL; }

    tcp->doff   = (sizeof(struct tcphdr) + olen) / 4;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + olen);
    tcp->check  = tcp_checksum(ip, tcp, sizeof(struct tcphdr) + olen);

    // Send SYN
    struct sockaddr_in d = dst;
    d.sin_port = htons(dport);
    if (sendto(raw, pkt, ntohs(ip->tot_len), 0,
               (struct sockaddr*)&d, sizeof(d)) < 0) {
        close(raw);
        return false;
    }

    // Receive SYN-ACK
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    char buf[512];
    struct sockaddr_in from{};
    socklen_t fromlen = sizeof(from);

    // Send RST for any incoming connection to our sport (to avoid RST from kernel)
    // We'll just ignore packets that aren't what we want

    while (std::chrono::steady_clock::now() < deadline) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(raw, &fds);
        struct timeval tv{0, 200000}; // 200ms

        int rv = select(raw + 1, &fds, nullptr, nullptr, &tv);
        if (rv <= 0) {
            if (rv < 0 && errno != EINTR) break;
            continue;
        }

        fromlen = sizeof(from);
        int n = recvfrom(raw, buf, sizeof(buf), 0,
                         (struct sockaddr*)&from, &fromlen);
        if (n < 0) continue;
        if (from.sin_addr.s_addr != dst.sin_addr.s_addr) continue;

        struct iphdr* rip = (struct iphdr*)buf;
        int ip_hlen = rip->ihl * 4;
        if (n < ip_hlen + (int)sizeof(struct tcphdr)) continue;
        if (rip->protocol != IPPROTO_TCP) continue;

        struct tcphdr* rtcp = (struct tcphdr*)(buf + ip_hlen);
        if (ntohs(rtcp->source) != (uint16_t)dport) continue;
        if (ntohs(rtcp->dest) != sport) continue;
        if (!rtcp->syn || !rtcp->ack) continue;

        // Got SYN-ACK — extract fingerprint data
        out.ttl     = rip->ttl;
        out.window  = ntohs(rtcp->window);
        out.df      = (ntohs(rip->frag_off) & 0x4000) ? 1 : 0;
        out.sack_ok = 1;

        // Parse TCP options
        int tcp_hlen = rtcp->doff * 4;
        int opt_len  = tcp_hlen - sizeof(struct tcphdr);
        if (opt_len > 0) {
            uint8_t* opts = (uint8_t*)rtcp + sizeof(struct tcphdr);
            int i = 0;
            std::string opt_str;
            while (i < opt_len) {
                uint8_t kind = opts[i];
                if (kind == TCPOPT_EOL) { opt_str += "EOL,"; break; }
                if (kind == TCPOPT_NOP) {
                    opt_str += "NOP,"; out.nop = true; i++; continue;
                }
                if (i + 1 >= opt_len) break;
                uint8_t len = opts[i + 1];
                if (len < 2 || i + len > opt_len) break;
                if (kind == TCPOPT_MSS && len >= 4) {
                    out.mss = ntohs(*(uint16_t*)(opts + i + 2));
                    opt_str += "MSS=" + std::to_string(out.mss) + ",";
                } else if (kind == TCPOPT_WSCALE && len >= 3) {
                    out.wscale = opts[i + 2];
                    opt_str += "WScale=" + std::to_string(out.wscale) + ",";
                } else if (kind == TCPOPT_TIMESTAMP && len >= 10) {
                    out.timestamp = 1;
                    opt_str += "TS,";
                } else if (kind == TCPOPT_SACK_PERM) {
                    out.sack_ok = 1;
                    opt_str += "SACK,";
                } else if (kind == 4) { // SACK
                    out.sack = true;
                    opt_str += "SACK,";
                } else {
                    opt_str += "Kind" + std::to_string(kind) + ",";
                }
                i += len;
            }
            out.tcp_options = opt_str;
        }

        // RTT estimate: rough
        close(raw);
        return true;
    }

    close(raw);
    return false;
}

// ---------------------------------------------------------------------------
// Regular TCP connect for banner grabbing + TCP_INFO
// ---------------------------------------------------------------------------
static bool connect_probe(const struct sockaddr_in& dst, int dport,
                          ProbeResult& out, int timeout_ms,
                          std::string& banner)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    // Set timeout
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in d = dst;
    d.sin_port = htons(dport);

    g_timedout = false;
    signal(SIGALRM, sig_alarm);
    alarm(std::max(1, timeout_ms / 1000));

    bool ok = (connect(fd, (struct sockaddr*)&d, sizeof(d)) == 0);
    alarm(0);
    signal(SIGALRM, SIG_DFL);

    if (!ok) {
        close(fd);
        return false;
    }

    out.connected = true;

    // Get TCP_INFO — exposes remote peer's TCP options negotiated during handshake
    struct tcp_info ti;
    socklen_t tlen = sizeof(ti);
    if (getsockopt(fd, SOL_TCP, TCP_INFO, &ti, &tlen) == 0) {
        out.mss        = ti.tcpi_snd_mss;
        out.sack_ok    = (ti.tcpi_options & TCPI_OPT_SACK) ? 1 : 0;
        out.timestamp  = (ti.tcpi_options & TCPI_OPT_TIMESTAMPS) ? 1 : 0;
        // tcpi_snd_wscale = remote's advertised window scale (4-bit field)
        int rwscale = ti.tcpi_snd_wscale;
        if (rwscale > 0 && rwscale <= 14)
            out.wscale = rwscale;
    }

    // Get MSS from TCP_MAXSEG
    int mss = 0;
    socklen_t msslen = sizeof(mss);
    if (getsockopt(fd, SOL_TCP, TCP_MAXSEG, &mss, &msslen) == 0 && mss > 0) {
        out.mss = mss;
    }

    // Get TTL from IP header (not directly available after connect on Linux)
    // Try IP_TTL — this returns the *local* TTL, not the remote's
    // We'll rely on the raw socket method for TTL

    // Banner grab
    // Determine probe based on port
    std::string probe;
    switch (dport) {
        case 21: probe = "QUIT\r\n"; break;
        case 22: probe = "\r\n"; break;
        case 23: probe = "\r\n"; break;
        case 25: probe = "EHLO detect.local\r\nQUIT\r\n"; break;
        case 80: probe = "GET / HTTP/1.0\r\nHost: detect.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; break;
        case 110: probe = "QUIT\r\n"; break;
        case 143: probe = "a001 LOGOUT\r\n"; break;
        case 443:
        case 8443: probe = ""; break; // TLS — skip
        case 3306: probe = ""; break;
        case 5432: probe = "\0"; break;
        case 5900: probe = "RFB 003.003\n"; break;
        case 6379: probe = "PING\r\n"; break;
        case 8080: probe = "GET / HTTP/1.0\r\nHost: detect.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n"; break;
        default:   probe = "\r\n"; break;
    }

    if (!probe.empty()) {
        // Send probe
        g_timedout = false;
        signal(SIGALRM, sig_alarm);
        alarm(std::max(1, timeout_ms / 1000));
        send(fd, probe.data(), probe.size(), 0);
        alarm(0);

        // Read response (first 2KB)
        char buf[2048];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = 0;
            banner = std::string(buf, n);
        }
    } else if (dport == 443 || dport == 8443) {
        // TLS handshake for server identification
        // Send ClientHello and parse ServerHello certificate
        char ch[1024];
        // Minimal TLS 1.2 ClientHello
        const uint8_t tls_ch[] = {
            0x16, 0x03, 0x01, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x03,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x00, 0x00, 0x1e, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x09,
            0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00,
            0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x99, 0x00, 0x00, 0x00, 0x14,
            0x00, 0x12, 0x00, 0x00, 0x0f, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74,
            0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x17, 0x00, 0x00, 0xff,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00,
            0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06,
            0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03,
            0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
        };
        g_timedout = false;
        signal(SIGALRM, sig_alarm);
        alarm(std::max(1, timeout_ms / 1000));
        send(fd, tls_ch, sizeof(tls_ch), 0);
        ssize_t n = recv(fd, ch, sizeof(ch) - 1, 0);
        alarm(0);
        if (n > 0) {
            ch[n] = 0;
            banner = std::string(ch, n);
            // Look for server certificate info
            // Extract CN from certificate if present (simplified)
            std::string b(ch, n);
            size_t p = b.find("CN=");
            if (p != std::string::npos) {
                size_t pe = b.find_first_of("\0\r\n", p);
                if (pe != std::string::npos)
                    banner = b.substr(0, n);
            }
        }
    }

    close(fd);
    return true;
}

// ---------------------------------------------------------------------------
// ICMP ping for TTL guess (raw socket for root, system ping fallback)
// ---------------------------------------------------------------------------
static int ping_ttl(const struct sockaddr_in& dst, int timeout_ms) {
    if (is_root()) {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (fd >= 0) {
            char pkt[64];
            memset(pkt, 0, sizeof(pkt));
            struct icmphdr* icmp = (struct icmphdr*)pkt;
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->un.echo.id = htons(getpid() & 0xFFFF);
            icmp->un.echo.sequence = htons(1);
            icmp->checksum = checksum(pkt, sizeof(pkt));

            struct sockaddr_in d = dst;
            auto start = std::chrono::steady_clock::now();
            sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr*)&d, sizeof(d));

            char buf[512];
            struct sockaddr_in from{};
            socklen_t fromlen = sizeof(from);

            auto deadline = start + std::chrono::milliseconds(timeout_ms);
            while (std::chrono::steady_clock::now() < deadline) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                struct timeval tv{0, 200000};
                if (select(fd + 1, &fds, nullptr, nullptr, &tv) <= 0) continue;
                fromlen = sizeof(from);
                int n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
                if (n < 0) break;
                if (from.sin_addr.s_addr != dst.sin_addr.s_addr) continue;
                struct iphdr* ip = (struct iphdr*)buf;
                int ip_hlen = ip->ihl * 4;
                if (n < ip_hlen + 8) continue;
                struct icmphdr* ricmp = (struct icmphdr*)(buf + ip_hlen);
                if (ricmp->type == ICMP_ECHOREPLY &&
                    ricmp->un.echo.id == icmp->un.echo.id) {
                    int ttl = ip->ttl;
                    close(fd);
                    return ttl;
                }
            }
            close(fd);
        }
    }

    // Fallback: use system ping command and parse TTL
    std::string cmd = "ping -c 1 -W " + std::to_string(std::max(1, timeout_ms/1000)) +
                      " " + std::string(inet_ntoa(dst.sin_addr)) +
                      " 2>/dev/null | grep -o 'ttl=[0-9]*' | head -1 | cut -d= -f2";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return 0;
    char buf[16];
    if (!fgets(buf, sizeof(buf), fp)) { pclose(fp); return 0; }
    pclose(fp);
    int ttl = atoi(buf);
    return (ttl > 0 && ttl < 255) ? ttl : 0;
}

// ---------------------------------------------------------------------------
// Extract meaningful strings from banner
// ---------------------------------------------------------------------------
static std::string extract_banner_info(const std::string& raw) {
    std::string out;
    for (unsigned char c : raw) {
        if (c >= 32 && c < 127) out += c;
        else if (c == '\n' || c == '\r') out += ' ';
    }
    // Squeeze spaces
    std::string res;
    bool sp = false;
    for (char c : out) {
        if (c == ' ') { if (!sp) res += c; sp = true; }
        else { res += c; sp = false; }
    }
    return trim(res);
}

// ---------------------------------------------------------------------------
// Score a signature against probe results
// ---------------------------------------------------------------------------
static int score_signature(const OSSignature& sig, const ProbeResult& pr,
                           const std::map<std::string,std::string>& banners)
{
    int score = 0;
    int max_possible = 0;

    // TTL (weight 15) — only if signature constrains it
    if (sig.ttl_min > 0 || sig.ttl_max < 255) {
        max_possible += 15;
        if (pr.ttl > 0 && pr.ttl >= sig.ttl_min && pr.ttl <= sig.ttl_max)
            score += 15;
        else if (pr.ttl > 0)
            score -= 5;
        // If ttl=0 (no data), mark as unscorable but don't count against
    }

    // Window size (weight 15)
    if (sig.win_min > 0 || sig.win_max < 65535) {
        max_possible += 15;
        if (pr.window > 0 && pr.window >= sig.win_min && pr.window <= sig.win_max)
            score += 15;
        else if (pr.window > 0 && sig.win_min > 0 && pr.window < sig.win_min)
            score += 5;
    }

    // DF (weight 10)
    if (sig.df >= 0 && pr.df >= 0) {
        max_possible += 10;
        if (pr.df == (sig.df != 0))
            score += 10;
        else
            score -= 2;
    } else if (sig.df >= 0 && pr.df < 0) {
        // unknown — don't score but also don't penalize
        max_possible += 10;
    }

    // MSS (weight 15)
    if (sig.mss > 0) {
        max_possible += 15;
        if (pr.mss > 0 && pr.mss == sig.mss)
            score += 15;
        else if (pr.mss > 0 && pr.mss != sig.mss)
            score -= 3; // mismatch
        // missing mss data — no penalty
    }

    // WScale (weight 12)
    if (sig.wscale >= 0) {
        max_possible += 12;
        if (pr.wscale >= 0 && pr.wscale == sig.wscale)
            score += 12;
        else if (pr.wscale >= 0)
            score -= 3;
    }

    // Timestamp (weight 10)
    if (sig.timestamp >= 0 && pr.timestamp >= 0) {
        max_possible += 10;
        if (pr.timestamp == (sig.timestamp != 0))
            score += 10;
        else
            score -= 3;
    } else if (sig.timestamp >= 0 && pr.timestamp < 0) {
        max_possible += 10;
    }

    // SACK OK (weight 10)
    if (sig.sack >= 0 && pr.sack_ok >= 0) {
        max_possible += 10;
        if (pr.sack_ok == (sig.sack != 0))
            score += 10;
        else
            score -= 3;
    } else if (sig.sack >= 0 && pr.sack_ok < 0) {
        max_possible += 10;
    }

    // NOP (weight 5)
    if (sig.nop >= 0 && pr.nop >= 0) {
        max_possible += 5;
        if (pr.nop == (sig.nop != 0))
            score += 5;
    } else if (sig.nop >= 0 && pr.nop < 0) {
        max_possible += 5;
    }

    // Banner matches (weight 20, indivisible)
    int banner_score = 0;
    if (!sig.banners.empty()) {
        max_possible += 20;
        for (auto& bp : sig.banners) {
            auto it = banners.find(bp.first);
            if (it != banners.end()) {
                std::string b = it->second;
                std::string p = bp.second;
                std::transform(b.begin(), b.end(), b.begin(), ::tolower);
                std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                if (b.find(p) != std::string::npos)
                    banner_score += 10;
            }
        }
        score += std::min(banner_score, 20);
    }

    if (max_possible == 0) return 0;
    return (score * sig.weight) / max_possible;
}

// ---------------------------------------------------------------------------
// Main detection logic
// ---------------------------------------------------------------------------
static Fingerprint detect_os(const std::string& host,
                             const std::vector<int>& ports,
                             int timeout_ms)
{
    Fingerprint result;
    struct sockaddr_in dst;
    if (!resolve_host(host, &dst)) {
        result.os_name = "Unknown";
        result.os_family = "Unknown";
        result.confidence = 0;
        return result;
    }

    // Phase 1: ICMP ping for TTL
    int ping_ttl_val = ping_ttl(dst, timeout_ms);
    std::string ip_str = inet_ntoa(dst.sin_addr);

    // Phase 2: SYN probes for TCP fingerprinting (requires root)
    std::vector<ProbeResult> syn_results;
    for (int port : ports) {
        ProbeResult pr;
        if (syn_probe(dst, port, pr, timeout_ms)) {
            pr.connected = true;
            syn_results.push_back(pr);
        }
    }

    // Phase 3: Connect + banner grab
    std::map<int, std::string> raw_banners;
    std::map<std::string, std::string> banners_by_service;
    std::vector<ProbeResult> connect_results;
    for (int port : ports) {
        ProbeResult pr;
        std::string b;
        if (connect_probe(dst, port, pr, timeout_ms, b)) {
            pr.connected = true;

            // Merge with SYN result if available
            bool merged = false;
            for (auto& sr : syn_results) {
                if (sr.window > 0 && sr.ttl > 0) {
                    // SYN has better window/TTL data
                    pr.ttl    = sr.ttl;
                    pr.window = sr.window;
                    pr.df     = sr.df;
                    if (sr.mss > 0) pr.mss = sr.mss;
                    if (sr.wscale >= 0) pr.wscale = sr.wscale;
                    if (sr.timestamp) pr.timestamp = true;
                    if (sr.sack_ok) pr.sack_ok = true;
                    merged = true;
                    break;
                }
            }
            if (!merged && ping_ttl_val > 0 && pr.ttl == 0)
                pr.ttl = ping_ttl_val;

            connect_results.push_back(pr);
            if (!b.empty()) {
                raw_banners[port] = b;
                std::string cleaned = extract_banner_info(b);
                // Map port to service
                std::string svc;
                switch (port) {
                    case 21: svc = "FTP"; break;
                    case 22: svc = "SSH"; break;
                    case 23: svc = "Telnet"; break;
                    case 25: svc = "SMTP"; break;
                    case 80: svc = "HTTP"; break;
                    case 110: svc = "POP3"; break;
                    case 111: svc = "RPC"; break;
                    case 143: svc = "IMAP"; break;
                    case 443: svc = "HTTPS"; break;
                    case 445: svc = "SMB"; break;
                    case 993: svc = "IMAPS"; break;
                    case 995: svc = "POP3S"; break;
                    case 3306: svc = "MySQL"; break;
                    case 3389: svc = "RDP"; break;
                    case 5432: svc = "PostgreSQL"; break;
                    case 5900: svc = "VNC"; break;
                    case 5985: svc = "WinRM"; break;
                    case 5986: svc = "WinRMS"; break;
                    case 6379: svc = "Redis"; break;
                    case 8080: svc = "HTTP-Alt"; break;
                    case 8443: svc = "HTTPS-Alt"; break;
                    case 27017: svc = "MongoDB"; break;
                    case 27018: svc = "MongoDB"; break;
                    default: svc = "Port" + std::to_string(port); break;
                }
                banners_by_service[svc] = cleaned;
            }
        }
    }

    // Phase 4: Aggregate probe results
    ProbeResult best_probe;
    for (auto& pr : syn_results) {
        if (pr.ttl > 0 && pr.window > 0) {
            best_probe = pr;
            break;
        }
    }
    if (best_probe.ttl == 0 && !connect_results.empty()) {
        best_probe = connect_results[0];
        if (ping_ttl_val > 0 && best_probe.ttl == 0)
            best_probe.ttl = ping_ttl_val;
    }
    if (best_probe.ttl == 0 && ping_ttl_val > 0)
        best_probe.ttl = ping_ttl_val;

    // Phase 5: Signature matching
    std::vector<std::pair<int, const OSSignature*>> scored;
    int best_score = 0;

    for (auto& sig : kSignatures) {
        int s = score_signature(sig, best_probe, banners_by_service);
        if (s > 0) {
            scored.emplace_back(s, &sig);
            if (s > best_score) best_score = s;
        }
    }

    // Sort by score descending
    std::sort(scored.begin(), scored.end(),
              [](auto& a, auto& b) { return a.first > b.first; });

    // Phase 6: Build result — prefer signature matches; fall back to TTL/banner
    bool matched = false;
    if (!scored.empty() && best_score > 15) {
        auto& top = scored[0];
        result.os_family  = top.second->family;
        result.os_name    = top.second->name;
        result.os_version = top.second->version;
        result.device_type = top.second->device;
        result.confidence = std::min(90, std::max(5, top.first * 90 / 100));
        matched = true;
    }

    if (!matched) {
        result.os_family = "Unknown";
        result.os_name   = "Unknown";
        result.os_version = "";
        result.device_type = "";

        // TTL-based guess
        if (best_probe.ttl > 0) {
            if (best_probe.ttl <= 64) {
                result.os_family = "Unix/Linux";
                result.os_name   = "Unix-like";
                result.confidence = 20;
            } else if (best_probe.ttl <= 128) {
                result.os_family = "Windows";
                result.os_name   = "Windows";
                result.confidence = 20;
            } else {
                result.os_family = "Network Device";
                result.os_name   = "Network Device";
                result.confidence = 20;
            }
        }

        // Banner-based fallback
        for (auto& [svc, bnr] : banners_by_service) {
            std::string b = bnr;
            std::transform(b.begin(), b.end(), b.begin(), ::tolower);
            int pconf = result.confidence;
            if (b.find("ubuntu") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Ubuntu"; pconf = 35; }
            else if (b.find("debian") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Debian"; pconf = 35; }
            else if (b.find("centos") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "CentOS"; pconf = 35; }
            else if (b.find("fedora") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Fedora"; pconf = 35; }
            else if (b.find("rhel") != std::string::npos || b.find("red hat") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "RHEL"; pconf = 35; }
            else if (b.find("alpine") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Alpine"; pconf = 35; }
            else if (b.find("arch") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Arch"; pconf = 35; }
            else if (b.find("gentoo") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Gentoo"; pconf = 35; }
            else if (b.find("opensuse") != std::string::npos || b.find("suse") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "openSUSE"; pconf = 35; }
            else if (b.find("slackware") != std::string::npos)
                { result.os_family = "Linux"; result.os_name = "Slackware"; pconf = 35; }
            else if (b.find("windows") != std::string::npos || b.find("microsoft") != std::string::npos)
                { result.os_family = "Windows"; result.os_name = "Windows"; pconf = 35; }
            else if (b.find("vmware") != std::string::npos || b.find("esxi") != std::string::npos)
                { result.os_family = "VMware"; result.os_name = "VMware ESXi"; pconf = 40; }
            else if (b.find("docker") != std::string::npos)
                { result.os_family = "Container"; result.os_name = "Docker"; pconf = 40; }
            else if (b.find("kubernetes") != std::string::npos || b.find("kube-") != std::string::npos)
                { result.os_family = "Container"; result.os_name = "Kubernetes"; pconf = 40; }
            else if (b.find("openwrt") != std::string::npos || b.find("lede") != std::string::npos)
                { result.os_family = "Embedded"; result.os_name = "OpenWrt"; pconf = 35; }
            else if (b.find("fortinet") != std::string::npos || b.find("fortios") != std::string::npos)
                { result.os_family = "Fortinet"; result.os_name = "FortiOS"; pconf = 40; }
            else if (b.find("proxmox") != std::string::npos)
                { result.os_family = "Proxmox"; result.os_name = "Proxmox VE"; pconf = 40; }
            else if (b.find("aix") != std::string::npos)
                { result.os_family = "AIX"; result.os_name = "IBM AIX"; pconf = 35; }
            else if (b.find("hp-ux") != std::string::npos || b.find("hpux") != std::string::npos)
                { result.os_family = "HP-UX"; result.os_name = "HP-UX"; pconf = 35; }
            else if (b.find("solaris") != std::string::npos || b.find("sunos") != std::string::npos)
                { result.os_family = "Solaris"; result.os_name = "Solaris"; pconf = 35; }
            else if (b.find("freebsd") != std::string::npos)
                { result.os_family = "BSD"; result.os_name = "FreeBSD"; pconf = 35; }
            else if (b.find("openbsd") != std::string::npos)
                { result.os_family = "BSD"; result.os_name = "OpenBSD"; pconf = 35; }
            else if (b.find("netbsd") != std::string::npos)
                { result.os_family = "BSD"; result.os_name = "NetBSD"; pconf = 35; }
            else if (b.find("cisco") != std::string::npos)
                { result.os_family = "Cisco"; result.os_name = "Cisco IOS"; pconf = 35; }
            else if (b.find("juniper") != std::string::npos || b.find("junos") != std::string::npos)
                { result.os_family = "Juniper"; result.os_name = "JunOS"; pconf = 35; }
            else if (b.find("mikrotik") != std::string::npos || b.find("routeros") != std::string::npos)
                { result.os_family = "MikroTik"; result.os_name = "RouterOS"; pconf = 35; }
            if (pconf > result.confidence) result.confidence = pconf;
        }

        // If we got banners but still unknown, bump confidence slightly
        if (result.os_name == "Unknown" && !banners_by_service.empty())
            result.confidence = std::max(result.confidence, 10);
    }

    // Build TCP options string for output
    {
        std::string opts;
        if (best_probe.mss > 0) opts += "MSS=" + std::to_string(best_probe.mss) + ",";
        if (best_probe.wscale >= 0) opts += "WS=" + std::to_string(best_probe.wscale) + ",";
        if (best_probe.timestamp) opts += "TS,";
        if (best_probe.sack_ok) opts += "SACK,";
        if (best_probe.nop) opts += "NOP,";
        if (best_probe.df) opts += "DF,";
        if (best_probe.tcp_options.empty())
            best_probe.tcp_options = opts;
        result.tcp_options = opts;
    }
    result.probe = best_probe;

    // Add banner hints
    for (auto& [svc, bnr] : banners_by_service) {
        if (!result.banner_hint.empty()) result.banner_hint += "; ";
        result.banner_hint += svc + ": " + bnr.substr(0, 120);
    }

    // Collected open ports
    for (int p : ports) {
        if (raw_banners.count(p))
            result.open_ports.push_back(p);
    }

    return result;
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 32) out += "\\u00" + std::to_string(c/16) +
                                std::to_string(c%16);
        else out += c;
    }
    return out;
}

static std::string to_json(const Fingerprint& fp, const std::string& target,
                           const std::vector<int>& ports, int timeout)
{
    std::ostringstream j;
    j << "RESULT:{\n"
      << "  \"target\":\"" << json_escape(target) << "\",\n"
      << "  \"os_family\":\"" << json_escape(fp.os_family) << "\",\n"
      << "  \"os_name\":\"" << json_escape(fp.os_name) << "\",\n"
      << "  \"os_version\":\"" << json_escape(fp.os_version) << "\",\n"
      << "  \"device_type\":\"" << json_escape(fp.device_type) << "\",\n"
      << "  \"confidence\":" << fp.confidence << ",\n"
      << "  \"ttl\":" << (int)fp.probe.ttl << ",\n"
      << "  \"window_size\":" << fp.probe.window << ",\n"
      << "  \"df\":" << (fp.probe.df == 1 ? "true" : fp.probe.df == 0 ? "false" : "null") << ",\n"
      << "  \"mss\":" << fp.probe.mss << ",\n"
      << "  \"wscale\":" << fp.probe.wscale << ",\n"
      << "  \"timestamp\":" << (fp.probe.timestamp == 1 ? "true" : fp.probe.timestamp == 0 ? "false" : "null") << ",\n"
      << "  \"sack\":" << (fp.probe.sack_ok == 1 ? "true" : fp.probe.sack_ok == 0 ? "false" : "null") << ",\n"
      << "  \"tcp_options\":\"" << json_escape(fp.tcp_options) << "\",\n"
      << "  \"open_ports\":[";
    for (size_t i = 0; i < fp.open_ports.size(); ++i) {
        if (i) j << ",";
        j << fp.open_ports[i];
    }
    j << "],\n"
      << "  \"timeout_ms\":" << timeout << ",\n"
      << "  \"banner_hint\":\"" << json_escape(fp.banner_hint) << "\"\n"
      << "}";
    return j.str();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <host> [ports] [timeout_ms]\n"
                  << "  ports     comma-separated (default: 22,80,443,21,25,8080)\n"
                  << "  timeout   ms per probe (default: 2000)\n";
        return 1;
    }

    std::string host = argv[1];
    std::vector<int> ports = {22, 80, 443, 21, 25, 8080};
    int timeout = 2000;

    if (argc >= 3) {
        std::string pstr = argv[2];
        ports.clear();
        for (auto& s : split(pstr, ',')) {
            if (!s.empty()) ports.push_back(std::stoi(s));
        }
        if (ports.empty()) ports = {22, 80, 443, 21, 25, 8080};
    }
    if (argc >= 4) {
        timeout = std::stoi(argv[3]);
    }

    // Extra ports for comprehensive fingerprinting
    // Add common service ports if not already present
    std::set<int> extra = {22, 80, 443, 21, 25, 8080, 8443, 3306, 5432,
                           6379, 5900, 3389, 445, 143, 110, 993, 995,
                           23, 111, 5985, 5986};
    for (int p : ports) extra.insert(p);
    ports.assign(extra.begin(), extra.end());

    // Run detection
    Fingerprint fp = detect_os(host, ports, timeout);

    // Output JSON
    std::cout << to_json(fp, host, ports, timeout) << std::endl;

    return 0;
}
