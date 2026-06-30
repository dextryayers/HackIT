#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

enum class PortStatus {
    OPEN,
    CLOSED,
    FILTERED,
    UNKNOWN
};

struct RawResult {
    std::string engine_name;
    int port{0};
    PortStatus status{PortStatus::UNKNOWN};
    std::string service;
    std::string version;
    double confidence{0.0};
    std::map<std::string, std::string> metadata;
};

struct CorrelatedResult {
    int port{0};
    PortStatus final_status{PortStatus::UNKNOWN};
    std::string final_service;
    std::string final_version;
    double confidence{0.0};
    int engines_agreed{0};
    int total_engines{0};
    std::vector<std::string> contributing_engines;
    std::map<std::string, std::string> consensus_metadata;
};

class CorrelationEngineV2 {
public:
    CorrelationEngineV2();
    ~CorrelationEngineV2();

    CorrelatedResult correlate(const std::vector<RawResult> &results);
    PortStatus resolve_conflict(const std::vector<PortStatus> &statuses);
    std::string pick_best_service(const std::vector<std::string> &services);

    void set_confidence_threshold(double threshold);
    void set_engine_weight(const std::string &engine_name, double weight);
    void set_majority_required(double fraction);

private:
    double confidence_threshold_{0.3};
    double majority_required_{0.5};
    std::map<std::string, double> engine_weights_;

    struct GroupedResults {
        std::vector<PortStatus> statuses;
        std::vector<std::string> services;
        std::vector<std::string> versions;
        std::vector<double> confidences;
        std::vector<std::string> engines;
        std::map<std::string, std::string> metadata;
    };

    GroupedResults group_by_port(const std::vector<RawResult> &results, int port);
    double weighted_vote(const std::vector<PortStatus> &statuses,
                         const std::vector<double> &confidences,
                         PortStatus target);
    std::map<std::string, int> service_consensus(const std::vector<std::string> &services,
                                                  const std::vector<double> &confidences);
};
