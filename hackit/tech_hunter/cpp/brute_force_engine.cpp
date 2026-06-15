#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

static const char* common_subs[] = {
    "www", "mail", "ftp", "ssh", "admin", "api", "dev", "staging",
    "test", "vpn", "blog", "shop", "cdn", "m", "mobile", "app",
    "webmail", "web", "portal", "login", "auth", "sso", "git",
    "jenkins", "jira", "confluence", "wiki", "docs", "support",
    "help", "status", "monitor", "grafana", "prometheus", "kibana",
    "elastic", "splunk", "nexus", "artifactory", "docker",
    "k8s", "kubernetes", "swarm", "prod", "production", "devops",
    "ci", "cd", "backup", "db", "database", "redis", "mysql",
    "postgres", "mongo", "elasticsearch", "mq", "rabbitmq",
    "kafka", "zookeeper", "consul", "vault", "ldap", "radius",
    "proxy", "gateway", "router", "firewall", "waf", "lb",
    "loadbalancer", "ha", "cluster", "node", "worker", "master",
    "dhcp", "dns", "ntp", "smtp", "imap", "pop3", "sip",
    "call", "phone", "pbx", "video", "stream", "media",
    "download", "upload", "static", "assets", "img", "images",
    "css", "js", "fonts", "template", "theme", "assets",
    "analytics", "metrics", "report", "billing", "payment",
    "checkout", "cart", "order", "tracking", "invoice",
    "partner", "vendor", "supplier", "affiliate", "referral",
    "recruit", "career", "job", "hr", "payroll", "benefits",
    "learn", "training", "academy", "university", "campus",
    "research", "lab", "sandbox", "demo", "preview", "beta",
    "alpha", "canary", "feature", "new", "old", "legacy",
    "archive", "private", "internal", "corp", "office",
    "nyc", "london", "tokyo", "sgp", "fra", "iad", "ams",
    "us", "eu", "asia", "china", "apac", "emea"
};

#define NUM_SUBS (sizeof(common_subs) / sizeof(common_subs[0]))

EXPORT const char* fast_discover(const char* domain) {
    if (domain == nullptr || strlen(domain) == 0) {
        char* empty = new char[1];
        empty[0] = '\0';
        return empty;
    }

    std::string d(domain);
    // Clean domain
    if (d.size() > 1 && d[0] == '.') d = d.substr(1);

    std::string result;

    for (size_t i = 0; i < NUM_SUBS; i++) {
        std::string sub = std::string(common_subs[i]) + "." + d;
        result += sub + "\n";
    }

    char* cstr = new char[result.length() + 1];
    std::copy(result.begin(), result.end(), cstr);
    cstr[result.length()] = '\0';
    return cstr;
}

EXPORT void free_discover_string(char* s) {
    delete[] s;
}

EXPORT const char* fast_discover_parallel(const char* domain, int worker_count) {
    (void)worker_count;
    return fast_discover(domain);
}
