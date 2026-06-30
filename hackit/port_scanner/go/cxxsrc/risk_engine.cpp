#define _GNU_SOURCE
#include "risk_engine.h"
#include "optimize.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <regex>
#include <tuple>
#include <mutex>

RiskEngine::RiskEngine() {
    init_defaults();
}

RiskEngine::~RiskEngine() {}

void RiskEngine::init_defaults() {
    service_base_risk_ = {
        {"SSH", 5.0},
        {"HTTP", 2.0},
        {"HTTPS", 1.5},
        {"FTP", 6.0},
        {"SMTP", 4.0},
        {"POP3", 4.5},
        {"IMAP", 4.5},
        {"MySQL", 7.0},
        {"PostgreSQL", 6.5},
        {"MongoDB", 8.0},
        {"Redis", 8.5},
        {"Memcached", 9.0},
        {"RDP", 8.0},
        {"VNC", 9.0},
        {"Telnet", 9.5},
        {"SMB", 8.0},
        {"SNMP", 7.5},
        {"DNS", 3.0},
        {"DHCP", 3.0},
        {"NTP", 3.5},
        {"LDAP", 5.0},
        {"Kerberos", 4.0},
        {"SIP", 6.0},
        {"RPC", 5.0},
        {"Rsync", 7.0},
        {"Docker", 7.0},
        {"Kubernetes", 7.5},
        {"Elasticsearch", 7.0},
        {"Cassandra", 6.0},
        {"CouchDB", 6.5},
        {"RabbitMQ", 5.0},
        {"ActiveMQ", 5.5},
        {"Jenkins", 6.0},
        {"Git", 5.0},
        {"SVN", 4.5},
        {"OracleDB", 7.5},
        {"MSSQL", 7.0},
    };

    sensitive_ports_ = {
        20, 21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139,
        143, 389, 443, 445, 465, 502, 512, 513, 514, 520, 523,
        587, 593, 636, 873, 902, 993, 995, 1080, 1099, 1194,
        1352, 1433, 1434, 1521, 2049, 2082, 2083, 2222, 2375,
        2376, 3128, 3260, 3306, 3310, 3389, 3478, 3632, 4369,
        4444, 4786, 4848, 4899, 5000, 5432, 5555, 5631, 5632,
        5672, 5800, 5801, 5900, 5901, 5984, 5985, 5986, 6000,
        6001, 6379, 6666, 6667, 6697, 7001, 7002, 7070, 7777,
        7778, 8000, 8009, 8080, 8081, 8089, 8090, 8118, 8140,
        8332, 8333, 8443, 8888, 9000, 9001, 9042, 9090, 9100,
        9160, 9200, 9300, 9418, 9999, 10000, 10001, 11211,
        11214, 11215, 15672, 25565, 27017, 27018, 27019, 28017,
        41443, 50070, 50075, 50090,
    };

    banner_indicators_ = {
        {"default password", 5.0},
        {"default credentials", 5.0},
        {"administrator", 3.0},
        {"authenticated", 2.0},
        {"vulnerable", 4.0},
        {"exploit", 5.0},
        {"backdoor", 9.0},
        {"root", 3.0},
        {"admin", 3.0},
        {"debug", 3.0},
        {"test", 2.0},
        {"demo", 2.0},
        {"example.com", 1.0},
        {"expired", 2.0},
        {"self-signed", 1.0},
        {"deprecated", 3.0},
        {"end of life", 5.0},
        {"eol", 4.0},
        {"unmaintained", 5.0},
        {"no encryption", 4.0},
        {"cleartext", 4.0},
        {"plaintext", 4.0},
        {"anonymous", 3.0},
        {"guest", 3.0},
        {"public", 2.0},
        {"internal", 1.0},
        {"unauthorized", 2.0},
        {"shell", 5.0},
        {"remote", 2.0},
        {"overflow", 5.0},
        {"injection", 5.0},
        {"xss", 4.0},
        {"csrf", 3.0},
        {"directory traversal", 6.0},
        {"rce", 7.0},
        {"remote code execution", 7.0},
        {"sql injection", 6.0},
        {"sqli", 6.0},
        {"information disclosure", 4.0},
    };

    vuln_versions_ = {
        {"SSH", "1.", 5.0},
        {"SSH", "2.0", 3.0},
        {"SSH", "OpenSSH_2.", 8.0},
        {"SSH", "OpenSSH_3.", 5.0},
        {"SSH", "OpenSSH_4.", 4.0},
        {"SSH", "OpenSSH_5.0", 3.0},
        {"SSH", "OpenSSH_5.1", 3.0},
        {"Apache", "1.", 3.0},
        {"Apache", "2.0.", 2.0},
        {"Apache", "2.2.", 2.5},
        {"Nginx", "0.", 4.0},
        {"Nginx", "1.0.", 2.0},
        {"PHP", "4.", 5.0},
        {"PHP", "5.2", 4.0},
        {"PHP", "5.3", 3.0},
        {"PHP", "5.4", 3.0},
        {"PHP", "5.5", 2.0},
        {"PHP", "5.6", 2.0},
        {"IIS", "5.", 4.0},
        {"IIS", "6.", 3.0},
        {"MySQL", "4.", 4.0},
        {"MySQL", "5.0", 3.0},
        {"MySQL", "5.1", 2.5},
        {"MySQL", "5.5", 2.0},
        {"PostgreSQL", "8.", 3.0},
        {"PostgreSQL", "9.0", 2.5},
        {"PostgreSQL", "9.1", 2.0},
        {"OpenSSL", "0.9", 6.0},
        {"OpenSSL", "1.0.0", 3.0},
        {"OpenSSL", "1.0.1", 5.0},
        {"OpenSSL", "1.0.2", 2.0},
        {"ProFTPD", "1.3.3", 5.0},
        {"ProFTPD", "1.3.4", 4.0},
        {"vsFTPd", "2.3.2", 5.0},
        {"vsFTPd", "2.3.4", 8.0},
        {"Tomcat", "5.", 3.0},
        {"Tomcat", "6.", 2.0},
        {"Samba", "3.", 5.0},
        {"Samba", "4.0", 4.0},
        {"WordPress", "2.", 4.0},
        {"WordPress", "3.", 3.0},
        {"WordPress", "4.0", 2.0},
        {"Drupal", "6.", 4.0},
        {"Drupal", "7.", 3.0},
        {"Drupal", "8.0", 3.0},
        {"Joomla", "1.", 4.0},
        {"Joomla", "2.", 3.0},
        {"Joomla", "3.0", 2.0},
    };
}

void RiskEngine::add_custom_rule(int port, double risk_bonus, const std::string &reason) {
    custom_port_rules_[port] = {risk_bonus, reason};
}

void RiskEngine::add_vulnerable_version(const std::string &service, const std::string &version_pattern, double risk_bonus) {
    vuln_versions_.emplace_back(service, version_pattern, risk_bonus);
}

void RiskEngine::set_base_risk_for_service(const std::string &service, double base) {
    service_base_risk_[service] = base;
}

double RiskEngine::base_risk_for_service(const std::string &service) {
    std::string svc = service;
    std::transform(svc.begin(), svc.end(), svc.begin(), ::toupper);
    auto it = service_base_risk_.find(svc);
    if (it != service_base_risk_.end()) return it->second;
    return 3.0;
}

double RiskEngine::port_sensitivity(int port) {
    if (sensitive_ports_.count(port)) {
        if (port == 22) return 1.5;
        if (port == 23) return 4.0;
        if (port == 3306) return 3.0;
        if (port == 3389) return 4.0;
        if (port == 5900 || port == 5901) return 4.0;
        if (port == 11211) return 5.0;
        if (port == 6379) return 4.0;
        if (port == 27017) return 4.0;
        if (port == 9200 || port == 9300) return 3.5;
        if (port == 2375 || port == 2376) return 5.0;
        if (port == 445) return 3.0;
        if (port == 1433 || port == 1434) return 3.5;
        if (port == 5432) return 3.0;
        return 2.0;
    }
    return 0.0;
}

double RiskEngine::version_risk(const std::string &service, const std::string &version) {
    if (version.empty()) return 0.0;

    std::string svc = service;
    std::transform(svc.begin(), svc.end(), svc.begin(), ::toupper);

    double max_bonus = 0.0;
    for (const auto &entry : vuln_versions_) {
        const std::string &pattern_svc = std::get<0>(entry);
        std::string pattern_svc_upper = pattern_svc;
        std::transform(pattern_svc_upper.begin(), pattern_svc_upper.end(), pattern_svc_upper.begin(), ::toupper);

        if (svc.find(pattern_svc_upper) != std::string::npos ||
            pattern_svc_upper.find(svc) != std::string::npos)
        {
            std::string ver = version;
            std::transform(ver.begin(), ver.end(), ver.begin(), ::toupper);
            std::string pattern = std::get<1>(entry);
            std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::toupper);

            if (ver.find(pattern) != std::string::npos) {
                double bonus = std::get<2>(entry);
                if (bonus > max_bonus) max_bonus = bonus;
            }
        }
    }
    return max_bonus;
}

double RiskEngine::banner_keyword_risk(const std::string &banner_lower) {
    double risk = 0.0;
    for (const auto &kv : banner_indicators_) {
        if (banner_lower.find(kv.first) != std::string::npos) {
            risk += kv.second;
        }
    }
    return std::min(risk, 10.0);
}

double RiskEngine::calculate_port_risk(int port, const std::string &service, const std::string &version) {
    double risk = 0.0;

    risk += base_risk_for_service(service);
    risk += port_sensitivity(port);
    risk += version_risk(service, version);

    auto it = custom_port_rules_.find(port);
    if (it != custom_port_rules_.end()) {
        risk += it->second.first;
    }

    risk = std::max(0.0, std::min(risk, 10.0));
    return risk;
}

double RiskEngine::calculate_banner_risk(const std::string &banner) {
    std::string lower = banner;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return banner_keyword_risk(lower);
}

std::string RiskEngine::get_risk_level(double score) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.5) return "MEDIUM";
    if (score >= 2.0) return "LOW";
    return "INFO";
}

RiskAssessment RiskEngine::assess(int port, const std::string &service,
                                  const std::string &version, const std::string &banner)
{
    RiskAssessment ra;
    ra.port = std::to_string(port);
    ra.service = service;
    ra.version = version;

    double svc_base = base_risk_for_service(service);
    if (svc_base > 0) {
        ra.factors.push_back("Service " + service + " has base risk " + std::to_string(svc_base));
    }

    double port_risk = port_sensitivity(port);
    if (port_risk > 0) {
        ra.factors.push_back("Sensitive port " + std::to_string(port) +
                             " (risk bonus: +" + std::to_string(port_risk) + ")");
    }

    double ver_risk = version_risk(service, version);
    if (ver_risk > 0) {
        ra.factors.push_back("Known vulnerable version " + version +
                             " (risk bonus: +" + std::to_string(ver_risk) + ")");
    }

    if (!banner.empty()) {
        double banner_risk = calculate_banner_risk(banner);
        if (banner_risk > 0) {
            ra.factors.push_back("Banner contains risk indicators (+" +
                                 std::to_string(banner_risk) + ")");
        }
    }

    auto it = custom_port_rules_.find(port);
    if (it != custom_port_rules_.end()) {
        ra.factors.push_back(it->second.second + " (+" + std::to_string(it->second.first) + ")");
    }

    ra.score = calculate_port_risk(port, service, version);

    if (!banner.empty()) {
        double banner_adj = calculate_banner_risk(banner) / 10.0;
        ra.score = std::min(10.0, ra.score + banner_adj);
    }

    ra.level = get_risk_level(ra.score);

    if (ra.factors.empty()) {
        ra.factors.push_back("No specific risk factors identified");
    }

    return ra;
}
