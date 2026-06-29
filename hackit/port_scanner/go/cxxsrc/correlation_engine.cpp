#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <mutex>
#include <cmath>
#include <string_view>
#include <memory>
#include <unordered_map>


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct ScanResult {
    std::string target;
    int port;
    std::string status;
    std::string service;
    std::string version;
    std::string source;
    double confidence;
};

struct Consensus {
    int port;
    std::string status;
    std::string service;
    std::string version;
    double confidence;
    int total_votes;
    int status_votes;
    bool conflict;
    std::vector<std::string> sources;
};

class CorrelationEngine {
    std::vector<ScanResult> results;
    std::mutex mtx;

    ScanResult parse_line(std::string_view line) {
        ScanResult r;
        r.target = "";
        r.port = 0;
        r.status = "unknown";
        r.service = "";
        r.version = "";
        r.source = "unknown";
        r.confidence = 0.5;

        size_t json_start = line.find('{');
        if (json_start == std::string::npos) return r;

        std::string json = std::string(line.substr(json_start));

        auto extract = [&](std::string_view key) -> std::string {
            std::string ks(key);
            std::string search = "\"" + ks + "\":\"";
            size_t pos = json.find(search);
            if (pos == std::string::npos) {
                search = "\"" + ks + "\":";
                pos = json.find(search);
                if (pos == std::string::npos) return "";
                pos += search.size();
                size_t end = json.find_first_of(",}", pos);
                if (end == std::string::npos) return "";
                return std::string(json.substr(pos, end - pos));
            }
            pos += search.size();
            size_t end = json.find('"', pos);
            if (end == std::string::npos) return "";
            return std::string(json.substr(pos, end - pos));
        };

        r.target = extract("target");
        std::string port_str = extract("port");
        if (!port_str.empty()) {
            try { r.port = std::stoi(port_str); }
            catch (...) {}
        }
        r.status = extract("status");
        r.service = extract("service");
        r.version = extract("version");
        r.source = extract("source");
        std::string conf_str = extract("confidence");
        if (!conf_str.empty()) {
            try { r.confidence = std::stod(conf_str); }
            catch (...) {}
        }

        return r;
    }

public:
    void add_line(std::string_view line) noexcept {
        if (line.find("RESULT:") == 0 || line.find("FINAL:") == 0) {
            std::lock_guard<std::mutex> lock(mtx);
            results.emplace_back(parse_line(line));
        }
    }

    void add_lines_from_stdin() noexcept {
        std::string line;
        while (std::getline(std::cin, line)) {
            add_line(line);
        }
    }

    std::vector<Consensus> correlate() {
        std::lock_guard<std::mutex> lock(mtx);

        std::unordered_map<int, std::vector<ScanResult>> by_port;
        for (const auto& r : results) {
            by_port[r.port].emplace_back(r);
        }

        std::vector<Consensus> consensuses;
consensuses.reserve(256);
for (auto& [port, port_results] : by_port) {
            Consensus c;
            c.port = port;
            c.total_votes = port_results.size();
            c.conflict = false;

            std::unordered_map<std::string, int> status_votes;
            std::unordered_map<std::string, int> service_votes;
            std::unordered_map<std::string, int> version_votes;

            double total_confidence = 0.0;

            for (const auto& r : port_results) {
                status_votes[r.status]++;
                if (!r.service.empty()) service_votes[r.service]++;
                if (!r.version.empty()) version_votes[r.version]++;
                total_confidence += r.confidence;
                c.sources.emplace_back(r.source);
            }

            auto get_winner = [](const std::unordered_map<std::string, int>& votes) -> std::pair<std::string, int> {
                std::string winner;
                int max_votes = 0;
                for (const auto& [key, count] : votes) {
                    if (count > max_votes) {
                        max_votes = count;
                        winner = key;
                    }
                }
                return {winner, max_votes};
            };

            auto [status_win, status_count] = get_winner(status_votes);
            auto [service_win, service_count] = get_winner(service_votes);
            auto [version_win, version_count] = get_winner(version_votes);

            c.status = status_win;
            c.service = service_win;
            c.version = version_win;
            c.status_votes = status_count;

            c.confidence = (status_count / std::max(1.0, (double)port_results.size())) *
                           (total_confidence / port_results.size());

            std::set<std::string> unique_statuses;
            for (const auto& [s, _] : status_votes) unique_statuses.insert(s);
            if (unique_statuses.size() > 1) {
                c.conflict = true;
                if (unique_statuses.count("open") && unique_statuses.count("filtered")) {
                    c.status = "open|filtered";
                    c.confidence *= 0.5;
                }
            }

            consensuses.emplace_back(c);
        }

        std::sort(consensuses.begin(), consensuses.end(),
            [](const Consensus& a, const Consensus& b) {
                return a.port < b.port;
            });

        return consensuses;
    }

    void print_consensus(const std::vector<Consensus>& consensuses) noexcept {
        for (const auto& c : consensuses) {
            std::cout << "RESULT:{\"port\":" << c.port
                      << ",\"status\":\"" << c.status
                      << "\",\"service\":\"" << c.service
                      << "\",\"version\":\"" << c.version
                      << "\",\"confidence\":" << std::fixed << std::setprecision(3) << c.confidence
                      << ",\"total_votes\":" << c.total_votes
                      << ",\"status_votes\":" << c.status_votes
                      << ",\"conflict\":" << (c.conflict ? "true" : "false")
                      << ",\"sources\":" << c.total_votes
                      << "}" << '\n';
        }

        int total = consensuses.size();
        int conflicts = 0;
        double avg_confidence = 0.0;
        for (const auto& c : consensuses) {
            if (c.conflict) conflicts++;
            avg_confidence += c.confidence;
        }
        avg_confidence = total > 0 ? avg_confidence / total : 0.0;

        std::cout << "FINAL:{\"ports_correlated\":" << total
                  << ",\"conflicts_detected\":" << conflicts
                  << ",\"avg_confidence\":" << std::fixed << std::setprecision(3) << avg_confidence
                  << "}" << '\n';
    }
};

int main() {
    CorrelationEngine engine;
    engine.add_lines_from_stdin();
    auto consensus = engine.correlate();
    engine.print_consensus(consensus);
    return 0;
}
