#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>

struct RiskAssessment {
    double score{0.0};
    std::string level;
    std::vector<std::string> factors;
    std::string port;
    std::string service;
    std::string version;
};

class RiskEngine {
public:
    RiskEngine();
    ~RiskEngine();

    double calculate_port_risk(int port, const std::string &service, const std::string &version);
    double calculate_banner_risk(const std::string &banner);
    std::string get_risk_level(double score);
    RiskAssessment assess(int port, const std::string &service,
                          const std::string &version, const std::string &banner);

    void add_custom_rule(int port, double risk_bonus, const std::string &reason);
    void add_vulnerable_version(const std::string &service, const std::string &version_pattern, double risk_bonus);
    void set_base_risk_for_service(const std::string &service, double base);

private:
    double base_risk_for_service(const std::string &service);
    double version_risk(const std::string &service, const std::string &version);
    double port_sensitivity(int port);
    double banner_keyword_risk(const std::string &banner_lower);

    std::map<std::string, double> service_base_risk_;
    std::map<int, std::pair<double, std::string>> custom_port_rules_;
    std::vector<std::tuple<std::string, std::string, double>> vuln_versions_;

    std::set<int> sensitive_ports_;
    std::map<std::string, double> banner_indicators_;

    void init_defaults();
};
