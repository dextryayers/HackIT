#pragma once

#include <string>
#include <vector>
#include <future>
#include <functional>
#include <map>
#include <mutex>

struct DnsResult {
    std::vector<std::string> addresses;
    std::string error;
    double duration_ms{0.0};
    bool success{false};
};

class DnsEngine {
public:
    DnsEngine();
    ~DnsEngine();

    std::vector<std::string> resolve(const std::string &hostname, int timeout_ms);
    std::string reverse_lookup(const std::string &ip);
    std::vector<std::string> resolve_mx(const std::string &domain);
    std::vector<std::string> resolve_ns(const std::string &domain);

    std::future<DnsResult> resolve_async(const std::string &hostname, int timeout_ms);
    std::future<std::string> reverse_lookup_async(const std::string &ip);

    void set_dns_server(const std::string &server);
    void set_cache_ttl(int ttl_seconds);
    void clear_cache();

    int cache_hits() const { return cache_hits_; }
    int cache_misses() const { return cache_misses_; }

private:
    struct DnsCacheEntry {
        std::vector<std::string> data;
        int64_t expire_time{0};
    };

    std::string dns_server_;
    int cache_ttl_{300};
    int cache_hits_{0};
    int cache_misses_{0};

    std::map<std::string, DnsCacheEntry> cache_;
    std::mutex cache_mutex_;

    std::vector<std::string> raw_resolve_ns(const std::string &domain, int type, int timeout_ms);
    bool query_dns_server(const std::string &dns_server, const std::string &domain,
                          int type, std::vector<std::string> &out, int timeout_ms);
    int64_t now_ms() const;
    bool check_cache(const std::string &key, std::vector<std::string> &out);
    void update_cache(const std::string &key, const std::vector<std::string> &data);
};
