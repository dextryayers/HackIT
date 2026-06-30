#define _GNU_SOURCE
#include "dns_engine.h"
#include "optimize.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <functional>
#include <future>
#include <memory>
#include <cmath>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <resolv.h>

static constexpr int DNS_PORT = 53;
static constexpr int DNS_HEADER_SIZE = 12;
static constexpr int MAX_DNS_PACKET = 512;

enum DnsType {
    DNS_A = 1,
    DNS_NS = 2,
    DNS_MX = 15,
    DNS_PTR = 12
};

static uint16_t dns_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    if (len & 1) sum += data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~((uint16_t)sum);
}

static std::string dns_name_to_wire(const std::string &name) {
    std::string wire;
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == std::string::npos) dot = name.size();
        size_t label_len = dot - pos;
        wire += (char)(label_len & 0x3F);
        wire += name.substr(pos, label_len);
        pos = dot + 1;
    }
    wire += '\0';
    return wire;
}

static std::string dns_name_from_wire(const uint8_t* data, size_t len, size_t &pos) {
    std::string name;
    bool jumped = false;
    size_t orig_pos = pos;

    while (pos < len) {
        if (data[pos] == 0) {
            if (!jumped) ++pos;
            break;
        }
        if ((data[pos] & 0xC0) == 0xC0) {
            if (pos + 1 >= len) break;
            uint16_t ptr = ((data[pos] & 0x3F) << 8) | data[pos + 1];
            if (!jumped) pos += 2;
            jumped = true;
            orig_pos = pos;
            pos = ptr;
            continue;
        }
        uint8_t label_len = data[pos];
        if (pos + label_len >= len) break;
        ++pos;
        if (!name.empty()) name += '.';
        for (uint8_t i = 0; i < label_len; ++i) {
            name += (char)data[pos + i];
        }
        pos += label_len;
    }
    if (!jumped) pos = orig_pos;
    return name;
}

static bool set_nonblock(int fd, bool nb) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return false;
    fcntl(fd, F_SETFL, nb ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
    return true;
}

DnsEngine::DnsEngine() {
}

DnsEngine::~DnsEngine() {}

void DnsEngine::set_dns_server(const std::string &server) {
    dns_server_ = server;
}

void DnsEngine::set_cache_ttl(int ttl_seconds) {
    cache_ttl_ = ttl_seconds;
}

void DnsEngine::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

int64_t DnsEngine::now_ms() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

bool DnsEngine::check_cache(const std::string &key, std::vector<std::string> &out) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        if (now_ms() < it->second.expire_time) {
            out = it->second.data;
            ++cache_hits_;
            return true;
        }
        cache_.erase(it);
    }
    ++cache_misses_;
    return false;
}

void DnsEngine::update_cache(const std::string &key, const std::vector<std::string> &data) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    DnsCacheEntry entry;
    entry.data = data;
    entry.expire_time = now_ms() + (int64_t)cache_ttl_ * 1000;
    cache_[key] = entry;
}

bool DnsEngine::query_dns_server(const std::string &dns, const std::string &domain,
                                  int type, std::vector<std::string> &out, int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);

    if (inet_pton(AF_INET, dns.c_str(), &dns_addr.sin_addr) <= 0) {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(dns.c_str(), nullptr, &hints, &res) != 0 || !res) {
            close(fd);
            return false;
        }
        dns_addr = *reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
        dns_addr.sin_port = htons(DNS_PORT);
        freeaddrinfo(res);
    }

    uint8_t pkt[MAX_DNS_PACKET];
    memset(pkt, 0, sizeof(pkt));

    uint16_t tid = (uint16_t)(getpid() & 0xFFFF);
    pkt[0] = (tid >> 8) & 0xFF;
    pkt[1] = tid & 0xFF;
    pkt[2] = 0x01;
    pkt[3] = 0x00;
    pkt[4] = 0x00;
    pkt[5] = 0x01;
    pkt[6] = 0x00;
    pkt[7] = 0x00;
    pkt[8] = 0x00;
    pkt[9] = 0x00;
    pkt[10] = 0x00;
    pkt[11] = 0x00;

    int pos = DNS_HEADER_SIZE;
    std::string wire_name = dns_name_to_wire(domain);
    memcpy(pkt + pos, wire_name.data(), wire_name.size());
    pos += wire_name.size();
    pkt[pos++] = (type >> 8) & 0xFF;
    pkt[pos++] = type & 0xFF;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x01;

    set_nonblock(fd, true);
    if (sendto(fd, pkt, pos, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        close(fd);
        return false;
    }

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    uint8_t recv_buf[MAX_DNS_PACKET];
    struct sockaddr_in from{};
    socklen_t fromlen = sizeof(from);

    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int rv = poll(&pfd, 1, std::max(10, timeout_ms / 10));
        if (rv <= 0) continue;

        fromlen = sizeof(from);
        int n = recvfrom(fd, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr*)&from, &fromlen);
        if (n < DNS_HEADER_SIZE + 4) continue;
        if (from.sin_addr.s_addr != dns_addr.sin_addr.s_addr) continue;

        uint16_t resp_tid = (recv_buf[0] << 8) | recv_buf[1];
        if (resp_tid != tid) continue;

        uint8_t rcode = recv_buf[3] & 0x0F;
        if (rcode != 0) {
            close(fd);
            return false;
        }

        uint16_t qdcount = (recv_buf[4] << 8) | recv_buf[5];
        uint16_t ancount = (recv_buf[6] << 8) | recv_buf[7];

        (void)qdcount;

        size_t offset = DNS_HEADER_SIZE;
        for (uint16_t q = 0; q < qdcount; ++q) {
            dns_name_from_wire(recv_buf, n, offset);
            offset += 4;
        }

        for (uint16_t a = 0; a < ancount; ++a) {
            dns_name_from_wire(recv_buf, n, offset);
            if (offset + 10 > (size_t)n) break;

            uint16_t rtype = (recv_buf[offset] << 8) | recv_buf[offset + 1];
            offset += 2;
            uint16_t rclass = (recv_buf[offset] << 8) | recv_buf[offset + 1];
            offset += 2;
            (void)rclass;
            uint32_t ttl = (recv_buf[offset] << 24) | (recv_buf[offset + 1] << 16) |
                           (recv_buf[offset + 2] << 8) | recv_buf[offset + 3];
            offset += 4;
            (void)ttl;
            uint16_t rdlen = (recv_buf[offset] << 8) | recv_buf[offset + 1];
            offset += 2;

            if (offset + rdlen > (size_t)n) break;

            if (rtype == (uint16_t)type || (type == DNS_A && rtype == DNS_A)) {
                if (rtype == DNS_A && rdlen == 4) {
                    char ip[INET_ADDRSTRLEN];
                    struct in_addr addr;
                    memcpy(&addr, recv_buf + offset, 4);
                    inet_ntop(AF_INET, &addr, ip, sizeof(ip));
                    out.emplace_back(ip);
                } else if (rtype == DNS_MX && rdlen >= 3) {
                    uint16_t pref = (recv_buf[offset] << 8) | recv_buf[offset + 1];
                    (void)pref;
                    size_t mx_pos = offset + 2;
                    std::string mx = dns_name_from_wire(recv_buf, n, mx_pos);
                    if (!mx.empty()) out.emplace_back(mx);
                } else if (rtype == DNS_NS) {
                    size_t ns_pos = offset;
                    std::string ns = dns_name_from_wire(recv_buf, n, ns_pos);
                    if (!ns.empty()) out.emplace_back(ns);
                } else if (rtype == DNS_PTR && rdlen > 2) {
                    size_t ptr_pos = offset;
                    std::string ptr_name = dns_name_from_wire(recv_buf, n, ptr_pos);
                    if (!ptr_name.empty()) out.emplace_back(ptr_name);
                }
            }
            offset += rdlen;
        }

        close(fd);
        return !out.empty();
    }

    close(fd);
    return false;
}

std::vector<std::string> DnsEngine::resolve(const std::string &hostname, int timeout_ms) {
    std::vector<std::string> out;
    if (check_cache(hostname, out)) return out;

    std::string dns = dns_server_.empty() ? "8.8.8.8" : dns_server_;
    if (query_dns_server(dns, hostname, DNS_A, out, timeout_ms)) {
        update_cache(hostname, out);
        return out;
    }

    if (dns != "8.8.8.8") {
        out.clear();
        if (query_dns_server("8.8.8.8", hostname, DNS_A, out, timeout_ms)) {
            update_cache(hostname, out);
            return out;
        }
    }

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int r = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (r == 0 && res) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *addr = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        out.emplace_back(ip);
        freeaddrinfo(res);
        update_cache(hostname, out);
    }
    return out;
}

std::string DnsEngine::reverse_lookup(const std::string &ip) {
    std::string cache_key = "PTR:" + ip;
    std::vector<std::string> cached;
    if (check_cache(cache_key, cached) && !cached.empty()) {
        return cached[0];
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return ip;
    }

    unsigned char* o = (unsigned char*)&addr;
    std::string ptr_domain = std::to_string(o[3]) + "." +
                              std::to_string(o[2]) + "." +
                              std::to_string(o[1]) + "." +
                              std::to_string(o[0]) + ".in-addr.arpa";

    std::vector<std::string> out;
    std::string dns = dns_server_.empty() ? "8.8.8.8" : dns_server_;
    if (query_dns_server(dns, ptr_domain, DNS_PTR, out, 3000)) {
        update_cache(cache_key, out);
        return out[0];
    }

    struct hostent* he = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    if (he && he->h_name) {
        std::string result(he->h_name);
        update_cache(cache_key, {result});
        return result;
    }

    return ip;
}

std::vector<std::string> DnsEngine::resolve_mx(const std::string &domain) {
    std::string cache_key = "MX:" + domain;
    std::vector<std::string> out;
    if (check_cache(cache_key, out)) return out;

    std::string dns = dns_server_.empty() ? "8.8.8.8" : dns_server_;
    query_dns_server(dns, domain, DNS_MX, out, 5000);
    update_cache(cache_key, out);
    return out;
}

std::vector<std::string> DnsEngine::resolve_ns(const std::string &domain) {
    std::string cache_key = "NS:" + domain;
    std::vector<std::string> out;
    if (check_cache(cache_key, out)) return out;

    std::string dns = dns_server_.empty() ? "8.8.8.8" : dns_server_;
    query_dns_server(dns, domain, DNS_NS, out, 5000);
    update_cache(cache_key, out);
    return out;
}

std::future<DnsResult> DnsEngine::resolve_async(const std::string &hostname, int timeout_ms) {
    return std::async(std::launch::async, [this, hostname, timeout_ms]() -> DnsResult {
        DnsResult res;
        auto start = std::chrono::steady_clock::now();
        res.addresses = this->resolve(hostname, timeout_ms);
        auto end = std::chrono::steady_clock::now();
        res.duration_ms = std::chrono::duration_cast<std::chrono::microseconds>(
            end - start).count() / 1000.0;
        res.success = !res.addresses.empty();
        if (!res.success) res.error = "Resolution failed";
        return res;
    });
}

std::future<std::string> DnsEngine::reverse_lookup_async(const std::string &ip) {
    return std::async(std::launch::async, [this, ip]() -> std::string {
        return this->reverse_lookup(ip);
    });
}
