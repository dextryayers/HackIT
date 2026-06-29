#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <thread>
#include <mutex>
#include <unistd.h>
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


struct EngineResult {
    std::string engine;
    int port;
    std::string status;
    std::string service;
    std::string version;
    std::string protocol;
    std::string banner;
    int confidence;
    std::string severity;
    std::vector<std::string> cve;
    std::string cpe;
    std::unordered_map<std::string, std::string> extra;
};

struct CorrelatedPort {
    int port;
    std::string status;
    std::string service;
    std::string version;
    std::string protocol;
    std::string banner;
    int consensus_count;
    int max_confidence;
    double avg_confidence;
    std::string severity;
    std::vector<std::string> cve;
    std::string cpe;
    std::vector<std::string> engines;
    std::unordered_map<std::string, std::string> extra;
    std::vector<std::string> warnings;
};

static std::mutex print_mutex;

static std::string json_escape(std::string_view s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (unsigned char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    r += buf;
                } else {
                    r += c;
                }
        }
    }
    return r;
}

static std::string strip(std::string_view s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    return std::string(s.substr(a, b - a + 1));
}

static std::string extract_json_str(std::string_view s, std::string_view key) {
    std::string search = "\"" + std::string(key) + "\":\"";
    size_t p = s.find(search);
    if (p == std::string::npos) return "";
    p += search.size();
    std::string val;
    while (p < s.size() && s[p] != '"') {
        if (s[p] == '\\' && p + 1 < s.size()) { val += s[p + 1]; p += 2; }
        else { val += s[p]; p++; }
    }
    return val;
}

static int extract_json_int(std::string_view s, std::string_view key) noexcept {
    std::string search = "\"" + std::string(key) + "\":";
    size_t p = s.find(search);
    if (p == std::string::npos) return 0;
    p += search.size();
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) p++;
    std::string val;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') { val += s[p]; p++; }
    return val.empty() ? 0 : std::stoi(val);
}

static std::vector<std::string> extract_json_str_array(std::string_view s, std::string_view key) {
    std::vector<std::string> out;
    std::string search = "\"" + std::string(key) + "\":\"";
    size_t p = s.find(search);
    if (p == std::string::npos) {
        search = "\"" + std::string(key) + "\":[";
        p = s.find(search);
        if (p == std::string::npos) return out;
        p += search.size();
        while (p < s.size()) {
            while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n')) p++;
            if (p >= s.size() || s[p] == ']') break;
            if (s[p] == '"') {
                p++;
                std::string val;
                while (p < s.size() && s[p] != '"') {
                    if (s[p] == '\\' && p + 1 < s.size()) { val += s[p + 1]; p += 2; }
                    else { val += s[p]; p++; }
                }
                if (p < s.size()) p++;
                out.emplace_back(val);
            }
            while (p < s.size() && s[p] != ',' && s[p] != ']') p++;
            if (p < s.size() && s[p] == ',') p++;
        }
        return out;
    }
    // Also handle single string value case
    p += search.size();
    std::string val;
    while (p < s.size() && s[p] != '"') {
        if (s[p] == '\\' && p + 1 < s.size()) { val += s[p + 1]; p += 2; }
        else { val += s[p]; p++; }
    }
    if (!val.empty()) out.emplace_back(val);
    return out;
}

// Parse a JSON result line using manual string operations
static EngineResult parse_result_line(std::string_view line) {
    EngineResult er;

    er.port = extract_json_int(line, "port");
    er.status = extract_json_str(line, "status");
    er.service = extract_json_str(line, "service");
    er.version = extract_json_str(line, "version");
    er.protocol = extract_json_str(line, "protocol");
    er.banner = extract_json_str(line, "banner");
    er.confidence = extract_json_int(line, "confidence");
    er.severity = extract_json_str(line, "severity");
    er.cpe = extract_json_str(line, "cpe");
    er.engine = extract_json_str(line, "engine");
    er.cve = extract_json_str_array(line, "cve");

    return er;
}

// Read all input lines from stdin
static std::vector<EngineResult> read_inputs() {
    std::vector<EngineResult> results;
    std::string line;
    while (std::getline(std::cin, line)) {
        line = strip(line);
        if (line.empty()) continue;

        // Check for RESULT: prefix
        size_t prefix = line.find("RESULT:");
        if (prefix != std::string::npos) {
            std::string json = line.substr(prefix + 7);
            EngineResult er = parse_result_line(json);
            results.emplace_back(er);
        } else if (line.find("FINAL:") != std::string::npos) {
            // Skip final summaries
        }
    }
    return results;
}

// Correlate results from multiple engines
static std::vector<CorrelatedPort> correlate(const std::vector<EngineResult>& inputs) {
    std::unordered_map<int, std::vector<EngineResult>> by_port;

    for (const auto& er : inputs) {
        by_port[er.port].emplace_back(er);
    }

    std::vector<CorrelatedPort> correlated;
correlated.reserve(256);
for (auto& kv : by_port) {
        int port = kv.first;
        auto& results = kv.second;

        CorrelatedPort cp;
        cp.port = port;
        cp.consensus_count = 0;
        cp.max_confidence = 0;
        cp.avg_confidence = 0.0;
        cp.status = "unknown";
        cp.protocol = "tcp";

        std::unordered_map<std::string, int> status_votes;
        std::unordered_map<std::string, int> service_votes;
        std::unordered_map<std::string, int> version_votes;
        std::unordered_map<std::string, int> protocol_votes;
        std::unordered_map<std::string, int> cpe_votes;
        std::unordered_map<std::string, int> severity_votes;
        std::set<std::string> all_cve;
        std::unordered_map<std::string, int> engine_set;

        int total_confidence = 0;

        for (const auto& er : results) {
            status_votes[er.status]++;
            service_votes[er.service]++;
            protocol_votes[er.protocol]++;
            cpe_votes[er.cpe]++;

            if (!er.engine.empty()) {
                engine_set[er.engine]++;
            }
            if (!er.engine.empty()) {
                bool found = false;
                for (const auto& e : cp.engines) {
                    if (e == er.engine) { found = true; break; }
                }
                if (!found) cp.engines.emplace_back(er.engine);
            }

            for (const auto& c : er.cve) {
                all_cve.insert(c);
            }

            if (er.confidence > cp.max_confidence) {
                cp.max_confidence = er.confidence;
            }
            total_confidence += er.confidence;

            // Pick best banner
            if (!er.banner.empty() && cp.banner.empty()) {
                cp.banner = er.banner;
            }

            // Severity
            if (!er.severity.empty()) {
                severity_votes[er.severity]++;
            }

            // Version - pick most common or highest confidence
            if (!er.version.empty()) {
                version_votes[er.version]++;
            }

            // Extra fields
            for (const auto& ex : er.extra) {
                cp.extra[ex.first] = ex.second;
            }
        }

        // Consensus: pick most voted status
        int max_votes = 0;
        for (const auto& sv : status_votes) {
            if (sv.second > max_votes) {
                max_votes = sv.second;
                cp.status = sv.first;
            }
        }

        // Service by majority
        max_votes = 0;
        for (const auto& sv : service_votes) {
            if (sv.second > max_votes) {
                max_votes = sv.second;
                cp.service = sv.first;
            }
        }

        // Protocol by majority
        max_votes = 0;
        for (const auto& pv : protocol_votes) {
            if (pv.second > max_votes) {
                max_votes = pv.second;
                cp.protocol = pv.first;
            }
        }

        // CPE by majority
        max_votes = 0;
        for (const auto& cv : cpe_votes) {
            if (cv.second > max_votes) {
                max_votes = cv.second;
                cp.cpe = cv.first;
            }
        }

        // Version by majority
        max_votes = 0;
        for (const auto& vv : version_votes) {
            if (vv.second > max_votes) {
                max_votes = vv.second;
                cp.version = vv.first;
            }
        }

        // Severity by majority
        max_votes = 0;
        for (const auto& sv : severity_votes) {
            if (sv.second > max_votes) {
                max_votes = sv.second;
                cp.severity = sv.first;
            }
        }

        // Consensus count: engines that agree on status
        cp.consensus_count = status_votes[cp.status];

        // Average confidence
        cp.avg_confidence = results.empty() ? 0.0 : (double)total_confidence / results.size();

        // CVE list sorted
        for (const auto& c : all_cve) {
            cp.cve.emplace_back(c);
        }

        // Warnings for low consensus
        if (cp.consensus_count < 2 && results.size() > 1) {
            cp.warnings.emplace_back("Low consensus: only " + std::to_string(cp.consensus_count) +
                "/" + std::to_string(results.size()) + " engines agree on status");
        }

        if (cp.service == "unknown" || cp.service.empty()) {
            cp.warnings.emplace_back("Service type could not be determined");
        }

        correlated.emplace_back(cp);
    }

    // Sort by port number
    std::sort(correlated.begin(), correlated.end(),
        [](const CorrelatedPort& a, const CorrelatedPort& b) {
            return a.port < b.port;
        });

    return correlated;
}

static void emit_result(const CorrelatedPort& cp) noexcept {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::string json;

    json += "RESULT:{\"port\":";
    json += std::to_string(cp.port);
    json += ",\"status\":\"";
    json += json_escape(cp.status);
    json += "\",\"service\":\"";
    json += json_escape(cp.service);
    json += "\",\"version\":\"";
    json += json_escape(cp.version);
    json += "\",\"protocol\":\"";
    json += json_escape(cp.protocol);
    json += "\",\"banner\":\"";
    json += json_escape(cp.banner);
    json += "\",\"cpe\":\"";
    json += json_escape(cp.cpe);
    json += "\",\"severity\":\"";
    json += json_escape(cp.severity);
    json += "\",\"consensus_count\":";
    json += std::to_string(cp.consensus_count);
    json += ",\"max_confidence\":";
    json += std::to_string(cp.max_confidence);
    json += ",\"avg_confidence\":";
    char conf_buf[16];
    snprintf(conf_buf, sizeof(conf_buf), "%.1f", cp.avg_confidence);
    json += conf_buf;

    json += ",\"engines\":[";
    for (size_t i = 0; i < cp.engines.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(cp.engines[i]) + "\"";
    }
    json += "]";

    json += ",\"cve\":[";
    for (size_t i = 0; i < cp.cve.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + json_escape(cp.cve[i]) + "\"";
    }
    json += "]";

    if (!cp.warnings.empty()) {
        json += ",\"warnings\":[";
        for (size_t i = 0; i < cp.warnings.size(); ++i) {
            if (i > 0) json += ",";
            json += "\"" + json_escape(cp.warnings[i]) + "\"";
        }
        json += "]";
    }

    json += "}";
    printf("%s\n", json.c_str());
    fflush(stdout);
}

static void emit_final(const std::vector<CorrelatedPort>& results) noexcept {
    int open_count = 0;
    int high_conf_count = 0;
    int total_cves = 0;
    for (const auto& cp : results) {
        if (cp.status == "open") open_count++;
        if (cp.max_confidence >= 80) high_conf_count++;
        total_cves += cp.cve.size();
    }

    printf("FINAL:{\"engine\":\"results_correlator\",\"total_ports\":%zu,\"open_ports\":%d,\"high_confidence\":%d,\"total_cves\":%d,\"results\":[\n",
        results.size(), open_count, high_conf_count, total_cves);
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& cp = results[i];
        printf("  {\"port\":%d,\"status\":\"%s\",\"service\":\"%s\",\"version\":\"%s\",\"consensus\":%d,\"confidence\":%d,\"severity\":\"%s\"",
            cp.port, json_escape(cp.status).c_str(), json_escape(cp.service).c_str(),
            json_escape(cp.version).c_str(), cp.consensus_count, cp.max_confidence,
            json_escape(cp.severity).c_str());

        if (!cp.cve.empty()) {
            printf(",\"cves\":[");
            for (size_t j = 0; j < cp.cve.size(); ++j) {
                if (j > 0) printf(",");
                printf("\"%s\"", json_escape(cp.cve[j]).c_str());
            }
            printf("]");
        }
        printf("}%s\n", (i + 1 < results.size()) ? "," : "");
    }
    printf("]}\n");
    fflush(stdout);
}

struct Args {
    std::string target = "127.0.0.1";
    int timeout = 5;
};

static Args parse_args(int argc, char** argv) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target" && i + 1 < argc) args.target = argv[++i];
        else if (arg == "--timeout" && i + 1 < argc) args.timeout = std::atoi(argv[++i]);
    }
    return args;
}

int main(int argc, char** argv) {
    Args args = parse_args(argc, argv);

    if (isatty(fileno(stdin))) {
        fprintf(stderr, "Usage: %s [--target <host>] < input_results.txt\n", argv[0]);
        fprintf(stderr, "Accepts RESULT: lines from port scanner engines on stdin.\n");

        // Provide a sample output for testing
        printf("RESULT:{\"port\":22,\"status\":\"open\",\"service\":\"SSH\",\"version\":\"OpenSSH_8.9p1\",\"protocol\":\"tcp\",\"banner\":\"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\",\"confidence\":95,\"engine\":\"rust_syn_scanner\"}\n");
        printf("RESULT:{\"port\":22,\"status\":\"open\",\"service\":\"SSH\",\"version\":\"8.9p1\",\"protocol\":\"tcp\",\"banner\":\"SSH-2.0-OpenSSH_8.9p1\",\"confidence\":90,\"engine\":\"cpp_service_scanner\"}\n");
        printf("RESULT:{\"port\":80,\"status\":\"open\",\"service\":\"HTTP\",\"version\":\"Apache/2.4.41\",\"protocol\":\"tcp\",\"banner\":\"HTTP/1.1 200 OK\",\"confidence\":92,\"engine\":\"go_port_scanner\"}\n");
        printf("RESULT:{\"port\":80,\"status\":\"open\",\"service\":\"HTTP\",\"version\":\"2.4.41\",\"protocol\":\"tcp\",\"banner\":\"Apache/2.4.41 (Ubuntu)\",\"confidence\":95,\"engine\":\"deep_analyzer\"}\n");
        printf("RESULT:{\"port\":443,\"status\":\"open\",\"service\":\"HTTPS\",\"version\":\"TLSv1.3\",\"protocol\":\"tcp\",\"banner\":\"TLS handshake complete\",\"confidence\":85,\"engine\":\"tls_analyzer_v2\"}\n");
        printf("RESULT:{\"port\":443,\"status\":\"open\",\"service\":\"HTTPS\",\"version\":\"TLSv1.2\",\"protocol\":\"tcp\",\"banner\":\"TLS\",\"confidence\":80,\"engine\":\"vuln_matcher_v2\"}\n");
        printf("FINAL:{\"engine\":\"test_data\"}\n");
        fflush(stdout);
        return 0;
    }

    auto inputs = read_inputs();
    if (inputs.empty()) {
        fprintf(stderr, "No RESULT: lines found on stdin\n");
        return 1;
    }

    auto correlated = correlate(inputs);

    for (const auto& cp : correlated) {
        emit_result(cp);
    }

    emit_final(correlated);
    return 0;
}
