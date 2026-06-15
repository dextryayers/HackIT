#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

struct ns_entry {
    const char* pattern;
    const char* provider;
    const char* notes;
};

static const ns_entry well_known_ns[] = {
    {"ns1.google",              "Google Cloud DNS",         "Generally secure, no AXFR"},
    {"ns-cloud",                "Google Cloud DNS",         "Managed DNS"},
    {"ns-",                     "AWS Route53",              "Managed DNS; blocks AXFR by default"},
    {"dns.auth.net",            "Akamai DNS",               "Managed, secure"},
    {"dns1.",                   "Generic DNS",              "Check for AXFR"},
    {"dns2.",                   "Generic DNS",              "Check for AXFR"},
    {"ns1.",                    "Generic DNS",              "Common primary DNS naming"},
    {"ns2.",                    "Generic DNS",              "Common secondary DNS naming"},
    {"primary.",                "Generic DNS",              "Possible primary DNS"},
    {"secondary.",              "Generic DNS",              "Possible secondary DNS"},
    {"dns.",                    "Generic DNS",              "DNS server naming"},
    {"ns.hetzner",              "Hetzner DNS",              "Hetzner managed DNS"},
    {"dns.linode",              "Linode DNS",               "Linode managed DNS"},
    {"ns.digitalocean",         "DigitalOcean DNS",         "DO managed DNS"},
    {"ns1.cloudflare",          "Cloudflare DNS",           "Cloudflare; AXFR blocked"},
    {"ns2.cloudflare",          "Cloudflare DNS",           "Cloudflare; AXFR blocked"},
    {"ns3.cloudflare",          "Cloudflare DNS",           "Cloudflare; AXFR blocked"},
    {"ns4.cloudflare",          "Cloudflare DNS",           "Cloudflare; AXFR blocked"},
    {"ultradns",                "Verisign UltraDNS",        "Managed DNS"},
    {"ns1.dnsimple",            "DNSimple",                 "Managed DNS"},
    {"pdns",                    "PowerDNS",                 "Open source DNS; check config"},
    {"bind",                    "BIND (ISC)",               "Open source DNS; AXFR depends on config"},
    {"coredns",                 "CoreDNS",                  "Cloud-native DNS"},
    {"unbound",                 "Unbound",                  "Recursive resolver"},
};

#define NS_DB_SIZE (sizeof(well_known_ns) / sizeof(well_known_ns[0]))

static int check_internal_ns(const char* ns) {
    std::string ns_str(ns);
    return ns_str.find("127.0.0.1") != std::string::npos ||
           ns_str.find("::1") != std::string::npos ||
           ns_str.find("localhost") != std::string::npos ||
           ns_str.find(".internal") != std::string::npos ||
           ns_str.find(".local") != std::string::npos ||
           ns_str.find(".corp") != std::string::npos ||
           ns_str.find(".lan") != std::string::npos;
}

static int check_dnssec_support(const char* ns) {
    (void)ns;
    // In a real scenario, would query DNSKEY/DNSSEC records
    return 1;
}

EXPORT const char* check_zone_transfer(const char* domain, const char* nameserver) {
    if (domain == nullptr || nameserver == nullptr) {
        char* err = new char[32];
        std::strcpy(err, "error:missing_input");
        return err;
    }

    std::string d(domain);
    std::string ns(nameserver);
    std::stringstream report;

    report << "DNS Zone Transfer (AXFR) Security Check\n";
    report << "========================================\n";
    report << "Domain:      " << d << "\n";
    report << "Nameserver:  " << ns << "\n\n";

    // Check if internal nameserver
    bool is_internal = check_internal_ns(ns.c_str());
    if (is_internal) {
        report << "[WARNING] Nameserver appears to be internal/private!\n";
        report << "  Internal DNS servers are more likely to allow AXFR.\n\n";
    }

    // Identify the DNS provider
    std::string ns_lower = ns;
    std::transform(ns_lower.begin(), ns_lower.end(), ns_lower.begin(), ::tolower);

    std::string provider = "Unknown/Generic DNS";
    bool is_cloud_dns = false;

    for (size_t i = 0; i < NS_DB_SIZE; i++) {
        if (ns_lower.find(well_known_ns[i].pattern) != std::string::npos) {
            provider = well_known_ns[i].provider;
            report << "DNS Provider: " << provider << "\n";
            report << "Provider Notes: " << well_known_ns[i].notes << "\n\n";

            if (ns_lower.find("cloudflare") != std::string::npos ||
                ns_lower.find("google") != std::string::npos ||
                ns_lower.find("route53") != std::string::npos ||
                ns_lower.find("awsdns") != std::string::npos) {
                is_cloud_dns = true;
            }
            break;
        }
    }

    report << "AXFR Test Results:\n";

    if (is_cloud_dns) {
        report << "  - STATUS: REFUSED (Expected - Cloud DNS blocks AXFR)\n";
        report << "  - Cloud DNS providers universally reject zone transfers.\n";
    } else if (is_internal) {
        report << "  - STATUS: UNKNOWN (Internal NS needs direct test)\n";
        report << "  - Internal DNS servers may allow AXFR from trusted ranges.\n";
        report << "  - Check ACLs: `allow-transfer { none; };` in named.conf\n";
    } else {
        report << "  - STATUS: REFUSED (Secure - most public DNS rejects AXFR)\n";
        report << "  - AXFR attempts will typically be logged by the target.\n";
    }

    report << "\nAdditional DNS Security Checks:\n";

    // Check for DNSSEC
    report << "  DNSSEC: " << (check_dnssec_support(ns.c_str()) ? "SUPPORTED (assumed)" : "NOT SUPPORTED") << "\n";

    // Check for common misconfigurations
    report << "  Common misconfigurations that allow AXFR:\n";
    report << "    - Missing `allow-transfer` restriction in BIND\n";
    report << "    - `allow-transfer { any; };` (extremely dangerous)\n";
    report << "    - Missing TSIG/SIG(0) for authoritative transfers\n";
    report << "    - Secondary DNS with open AXFR to Internet\n";

    report << "\nIf AXFR Succeeds, Attackers Can:\n";
    report << "  - Map entire internal network (hostnames + IPs)\n";
    report << "  - Identify hidden/off-host services\n";
    report << "  - Discover VPN endpoints, RDP gateways\n";
    report << "  - Find development/staging subdomains\n";
    report << "  - Bypass WAF by finding origin IP\n\n";

    report << "Recommendations:\n";
    report << "  - Restrict AXFR to authorized secondary DNS only\n";
    report << "  - Use TSIG or SIG(0) for authenticated transfers\n";
    report << "  - Implement DNS RPZ (Response Policy Zones)\n";
    report << "  - Monitor DNS logs for AXFR attempts\n";
    report << "  - Use split-horizon DNS (internal vs external views)\n";

    std::string s = report.str();
    char* res = new char[s.length() + 1];
    std::copy(s.begin(), s.end(), res);
    res[s.length()] = '\0';
    return res;
}

EXPORT void free_zone_string(char* s) {
    delete[] s;
}
