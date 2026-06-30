#define _GNU_SOURCE
#include "correlation_engine_v2.h"
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
#include <mutex>
#include <limits>

CorrelationEngineV2::CorrelationEngineV2() {
    engine_weights_["os_detect"] = 1.0;
    engine_weights_["deep_analyzer"] = 1.0;
    engine_weights_["service_scanner"] = 1.0;
    engine_weights_["tls_scanner"] = 0.9;
    engine_weights_["vuln_matcher"] = 0.8;
    engine_weights_["stack_fingerprinter"] = 0.7;
    engine_weights_["risk_calculator"] = 0.6;
    engine_weights_["banner_grabber"] = 0.8;
    engine_weights_["anomaly_detector"] = 0.7;
}

CorrelationEngineV2::~CorrelationEngineV2() {}

void CorrelationEngineV2::set_confidence_threshold(double threshold) {
    confidence_threshold_ = std::max(0.0, std::min(1.0, threshold));
}

void CorrelationEngineV2::set_engine_weight(const std::string &engine_name, double weight) {
    engine_weights_[engine_name] = std::max(0.0, weight);
}

void CorrelationEngineV2::set_majority_required(double fraction) {
    majority_required_ = std::max(0.0, std::min(1.0, fraction));
}

CorrelationEngineV2::GroupedResults
CorrelationEngineV2::group_by_port(const std::vector<RawResult> &results, int port) {
    GroupedResults grp;
    for (const auto &r : results) {
        if (r.port != port) continue;
        grp.statuses.push_back(r.status);
        grp.services.push_back(r.service);
        grp.versions.push_back(r.version);
        grp.confidences.push_back(r.confidence);
        grp.engines.push_back(r.engine_name);
        for (const auto &kv : r.metadata) {
            grp.metadata[kv.first] = kv.second;
        }
    }
    return grp;
}

double CorrelationEngineV2::weighted_vote(const std::vector<PortStatus> &statuses,
                                           const std::vector<double> &confidences,
                                           PortStatus target)
{
    double total = 0.0;
    for (size_t i = 0; i < statuses.size(); ++i) {
        if (statuses[i] == target) {
            total += confidences[i];
        }
    }
    return total;
}

std::map<std::string, int>
CorrelationEngineV2::service_consensus(const std::vector<std::string> &services,
                                        const std::vector<double> &confidences)
{
    std::map<std::string, int> counts;
    for (size_t i = 0; i < services.size(); ++i) {
        if (services[i].empty()) continue;
        std::string svc = services[i];
        std::transform(svc.begin(), svc.end(), svc.begin(), ::tolower);
        counts[svc] += (int)(confidences[i] * 10);
    }
    return counts;
}

PortStatus CorrelationEngineV2::resolve_conflict(const std::vector<PortStatus> &statuses) {
    if (statuses.empty()) return PortStatus::UNKNOWN;

    int open_count = 0, closed_count = 0, filtered_count = 0;
    for (auto s : statuses) {
        switch (s) {
            case PortStatus::OPEN: ++open_count; break;
            case PortStatus::CLOSED: ++closed_count; break;
            case PortStatus::FILTERED: ++filtered_count; break;
            default: break;
        }
    }

    int total = (int)statuses.size();
    double open_frac = (double)open_count / total;
    double closed_frac = (double)closed_count / total;
    double filtered_frac = (double)filtered_count / total;

    if (open_frac > majority_required_) return PortStatus::OPEN;
    if (closed_frac > majority_required_) return PortStatus::CLOSED;
    if (filtered_frac > majority_required_) return PortStatus::FILTERED;

    if (open_frac >= closed_frac && open_frac >= filtered_frac) return PortStatus::OPEN;
    if (closed_frac >= open_frac && closed_frac >= filtered_frac) return PortStatus::CLOSED;
    if (filtered_frac >= open_frac && filtered_frac >= closed_frac) return PortStatus::FILTERED;

    return PortStatus::UNKNOWN;
}

std::string CorrelationEngineV2::pick_best_service(const std::vector<std::string> &services) {
    std::map<std::string, int> counts;
    for (const auto &s : services) {
        if (s.empty()) continue;
        std::string svc = s;
        std::transform(svc.begin(), svc.end(), svc.begin(), ::tolower);
        counts[svc]++;
    }

    int best_count = 0;
    std::string best_service;
    for (const auto &kv : counts) {
        if (kv.second > best_count) {
            best_count = kv.second;
            best_service = kv.first;
        }
    }

    if (!best_service.empty()) {
        best_service[0] = std::toupper(best_service[0]);
    }

    return best_service;
}

CorrelatedResult CorrelationEngineV2::correlate(const std::vector<RawResult> &results) {
    CorrelatedResult cr;

    if (results.empty()) return cr;

    std::set<int> ports;
    for (const auto &r : results) {
        ports.insert(r.port);
    }

    int best_agreement = 0;
    double best_confidence = 0.0;
    int best_port = 0;
    for (int port : ports) {
        auto grp = group_by_port(results, port);
        if (grp.statuses.empty()) continue;

        double open_score = weighted_vote(grp.statuses, grp.confidences, PortStatus::OPEN);
        double closed_score = weighted_vote(grp.statuses, grp.confidences, PortStatus::CLOSED);
        double filtered_score = weighted_vote(grp.statuses, grp.confidences, PortStatus::FILTERED);

        PortStatus resolved;
        if (open_score >= closed_score && open_score >= filtered_score)
            resolved = PortStatus::OPEN;
        else if (closed_score >= open_score && closed_score >= filtered_score)
            resolved = PortStatus::CLOSED;
        else
            resolved = PortStatus::FILTERED;

        std::string service = pick_best_service(grp.services);

        double confidence = 0.0;
        for (size_t i = 0; i < grp.confidences.size(); ++i) {
            confidence += grp.confidences[i] * engine_weights_[grp.engines[i]];
        }
        confidence /= std::max(1, (int)grp.confidences.size());

        int engines_agreed = 0;
        for (size_t i = 0; i < grp.statuses.size(); ++i) {
            if (grp.statuses[i] == resolved) {
                ++engines_agreed;
            }
        }

        if (engines_agreed > best_agreement ||
            (engines_agreed == best_agreement && confidence > best_confidence))
        {
            best_agreement = engines_agreed;
            best_confidence = confidence;
            best_port = port;

            cr.port = port;
            cr.final_status = resolved;
            cr.final_service = service;
            cr.confidence = confidence;
            cr.engines_agreed = engines_agreed;
            cr.total_engines = (int)grp.statuses.size();
            cr.contributing_engines = grp.engines;
            cr.consensus_metadata = grp.metadata;

            std::map<std::string, int> ver_counts;
            for (const auto &v : grp.versions) {
                if (!v.empty()) ver_counts[v]++;
            }
            int best_ver_count = 0;
            for (const auto &kv : ver_counts) {
                if (kv.second > best_ver_count) {
                    best_ver_count = kv.second;
                    cr.final_version = kv.first;
                }
            }
        }
    }

    return cr;
}
