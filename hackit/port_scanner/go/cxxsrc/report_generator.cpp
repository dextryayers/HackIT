#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>
#include <regex>
#include <set>
#include <mutex>
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


struct ReportEntry {
    std::string target;
    int port;
    std::string status;
    std::string service;
    std::string version;
    std::string os;
    double risk_score;
    std::string severity;
    double confidence;
    std::string banner;
    std::vector<std::string> cves;
};

class ReportGenerator {
    std::vector<ReportEntry> entries;
    std::mutex mtx;

    ReportEntry parse_json_line(std::string_view line) {
        ReportEntry e;
        e.port = 0;
        e.risk_score = 0.0;
        e.confidence = 0.0;

        size_t start = line.find('{');
        if (start == std::string::npos) return e;
        std::string json = std::string(line.substr(start));

        auto extract = [&](std::string_view key) -> std::string {
            std::string s = "\"" + std::string(key) + "\":\"";
            size_t pos = json.find(s);
            if (pos == std::string::npos) {
                s = "\"" + std::string(key) + "\":";
                pos = json.find(s);
                if (pos == std::string::npos) return "";
                pos += s.size();
                size_t end = json.find_first_of(",}", pos);
                return (end != std::string::npos) ? std::string(json.substr(pos, end - pos)) : "";
            }
            pos += s.size();
            size_t end = json.find('"', pos);
            return (end != std::string::npos) ? std::string(json.substr(pos, end - pos)) : "";
        };

        e.target = extract("target");
        std::string p = extract("port");
        if (!p.empty()) try { e.port = std::stoi(p); } catch (...) {}
        e.status = extract("status");
        e.service = extract("service");
        e.version = extract("version");
        e.os = extract("os");
        std::string r = extract("risk_score");
        if (!r.empty()) try { e.risk_score = std::stod(r); } catch (...) {}
        e.severity = extract("severity");
        std::string conf = extract("confidence");
        if (!conf.empty()) try { e.confidence = std::stod(conf); } catch (...) {}
        e.banner = extract("banner");

        if (json.find("\"cve_id\"") != std::string::npos) {
            std::string cve = extract("cve_id");
            if (!cve.empty()) e.cves.emplace_back(cve);
        }

        return e;
    }

    std::string escape_html(std::string_view s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                default: out += c;
            }
        }
        return out;
    }

    std::string escape_json(std::string_view s) {
        std::string out;
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c;
            }
        }
        return out;
    }

    std::string escape_csv(std::string_view s) {
        if (s.find(',') != std::string::npos || s.find('"') != std::string::npos || s.find('\n') != std::string::npos) {
            std::string out = "\"";
            for (char c : s) {
                if (c == '"') out += "\"\"";
                else out += c;
            }
            out += "\"";
            return out;
        }
        return std::string(s);
    }

    std::string timestamp() {
        std::time_t t = std::time(nullptr);
        std::tm* tm = std::localtime(&t);
        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        return buf;
    }

    std::string generate_html() {
        std::ostringstream html;
        html << "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
             << "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
             << "<title>Port Scanner Report</title>"
             << "<style>"
             << "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
             << "background:#1a1a2e;color:#e0e0e0;margin:0;padding:20px;}"
             << "h1,h2{color:#00d4ff;border-bottom:1px solid #333;padding-bottom:10px;}"
             << "h3{color:#7ec8e3;}"
             << ".summary{background:#16213e;border-radius:8px;padding:20px;margin:10px 0;}"
             << ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;}"
             << ".stat-card{background:#0f3460;border-radius:6px;padding:15px;text-align:center;}"
             << ".stat-value{font-size:24px;font-weight:bold;color:#00d4ff;}"
             << ".stat-label{font-size:12px;color:#888;margin-top:5px;}"
             << "table{width:100%;border-collapse:collapse;margin:15px 0;background:#16213e;border-radius:8px;overflow:hidden;}"
             << "th{background:#0f3460;color:#00d4ff;padding:12px;text-align:left;font-size:13px;}"
             << "td{padding:10px 12px;border-bottom:1px solid #333;font-size:13px;}"
             << "tr:hover{background:#1a1a3e;}"
             << ".severity-critical{color:#ff4444;font-weight:bold;}"
             << ".severity-high{color:#ff8800;font-weight:bold;}"
             << ".severity-medium{color:#ffcc00;}"
             << ".severity-low{color:#88ccff;}"
             << ".severity-none{color:#888;}"
             << ".open{color:#44ff44;}.filtered{color:#ffcc00;}.closed{color:#888;}"
             << ".footer{text-align:center;color:#666;margin-top:30px;font-size:12px;}"
             << "</style></head><body>";

        html << "<h1>Port Scanner Report</h1>"
             << "<div class=\"summary\"><p>Generated: " << timestamp() << "</p>";

        std::unordered_map<std::string, int> status_counts;
        std::unordered_map<std::string, int> severity_counts;
        std::set<std::string> unique_targets;
        double total_risk = 0.0;
        int risk_count = 0;

        for (const auto& e : entries) {
            unique_targets.insert(e.target);
            status_counts[e.status]++;
            if (!e.severity.empty()) severity_counts[e.severity]++;
            if (e.risk_score > 0) { total_risk += e.risk_score; risk_count++; }
        }

        html << "<div class=\"summary-grid\">"
             << "<div class=\"stat-card\"><div class=\"stat-value\">" << unique_targets.size()
             << "</div><div class=\"stat-label\">Targets</div></div>"
             << "<div class=\"stat-card\"><div class=\"stat-value\">" << entries.size()
             << "</div><div class=\"stat-label\">Ports</div></div>"
             << "<div class=\"stat-card\"><div class=\"stat-value\">" << status_counts["open"]
             << "</div><div class=\"stat-label\">Open Ports</div></div>"
             << "<div class=\"stat-card\"><div class=\"stat-value\">" << status_counts["filtered"]
             << "</div><div class=\"stat-label\">Filtered</div></div>"
             << "<div class=\"stat-card\"><div class=\"stat-value\" style=\"color:"
             << (total_risk / std::max(1, risk_count) >= 7 ? "#ff4444" : "#00d4ff") << "\">"
             << std::fixed << std::setprecision(1) << (risk_count > 0 ? total_risk / risk_count : 0.0)
             << "</div><div class=\"stat-label\">Avg Risk Score</div></div>"
             << "</div></div>";

        html << "<h2>Port Details</h2><table>"
             << "<tr><th>Port</th><th>Status</th><th>Service</th><th>Version</th>"
             << "<th>OS</th><th>Risk</th><th>Severity</th><th>Banner</th></tr>";

        for (const auto& e : entries) {
            html << "<tr>"
                 << "<td>" << e.port << "</td>"
                 << "<td class=\"" << e.status << "\">" << e.status << "</td>"
                 << "<td>" << escape_html(e.service) << "</td>"
                 << "<td>" << escape_html(e.version) << "</td>"
                 << "<td>" << escape_html(e.os) << "</td>"
                 << "<td>" << std::fixed << std::setprecision(1) << e.risk_score << "</td>"
                 << "<td class=\"severity-" << e.severity << "\">" << e.severity << "</td>"
                 << "<td>" << escape_html(e.banner.substr(0, 60)) << "</td>"
                 << "</tr>";
        }
        html << "</table>";

        if (!severity_counts.empty()) {
            html << "<h2>Risk Distribution</h2><table>"
                 << "<tr><th>Severity</th><th>Count</th></tr>";
            for (const auto& [sev, count] : severity_counts) {
                html << "<tr><td class=\"severity-" << sev << "\">" << sev
                     << "</td><td>" << count << "</td></tr>";
            }
            html << "</table>";
        }

        html << "<div class=\"footer\">Generated by HackIT Port Scanner Engine</div>"
             << "</body></html>";
        return html.str();
    }

    std::string generate_json() {
        std::ostringstream json;
        json << "{\n  \"report\": {\n    \"generated\": \"" << timestamp() << "\",\n"
             << "    \"scan_engine\": \"HackIT Port Scanner\",\n"
             << "    \"total_ports\": " << entries.size() << ",\n"
             << "    \"results\": [\n";

        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& e = entries[i];
            json << "      {\"target\":\"" << escape_json(e.target)
                 << "\",\"port\":" << e.port
                 << ",\"status\":\"" << escape_json(e.status)
                 << "\",\"service\":\"" << escape_json(e.service)
                 << "\",\"version\":\"" << escape_json(e.version)
                 << "\",\"os\":\"" << escape_json(e.os)
                 << "\",\"risk_score\":" << std::fixed << std::setprecision(1) << e.risk_score
                 << ",\"severity\":\"" << escape_json(e.severity)
                 << "\",\"confidence\":" << std::fixed << std::setprecision(2) << e.confidence
                 << ",\"banner\":\"" << escape_json(e.banner) << "\""
                 << "}";
            if (i < entries.size() - 1) json << ",";
            json << "\n";
        }

        json << "    ]\n  }\n}";
        return json.str();
    }

    std::string generate_text() {
        std::ostringstream text;
        text << "========================================\n"
             << "  PORT SCANNER REPORT\n"
             << "  Generated: " << timestamp() << "\n"
             << "========================================\n\n";

        std::unordered_map<int, int> status_counts;
        for (const auto& e : entries) status_counts[e.port]++;

        int open = 0, filtered = 0, closed = 0;
        for (const auto& e : entries) {
            if (e.status == "open") open++;
            else if (e.status == "filtered") filtered++;
            else if (e.status == "closed") closed++;
        }

        text << "  Summary:\n";
        text << "    Total Entries: " << entries.size() << "\n";
        text << "    Open:          " << open << "\n";
        text << "    Filtered:      " << filtered << "\n";
        text << "    Closed:        " << closed << "\n\n";
        text << "  Port Details:\n";
        text << "  " << std::string(80, '-') << "\n";
        text << "  " << std::left << std::setw(8) << "Port"
             << std::setw(12) << "Status"
             << std::setw(20) << "Service"
             << std::setw(16) << "Version"
             << std::setw(16) << "OS"
             << std::setw(8) << "Risk"
             << "Severity\n";
        text << "  " << std::string(80, '-') << "\n";

        for (const auto& e : entries) {
            text << "  " << std::left << std::setw(8) << e.port
                 << std::setw(12) << e.status
                 << std::setw(20) << e.service.substr(0, 18)
                 << std::setw(16) << e.version.substr(0, 14)
                 << std::setw(16) << e.os.substr(0, 14)
                 << std::setw(8) << std::fixed << std::setprecision(1) << e.risk_score
                 << e.severity << "\n";
        }
        text << "\n========================================\n";
        return text.str();
    }

public:
    void add_line(std::string_view line) noexcept {
        if (line.find("RESULT:") == 0 || line.find("FINAL:") == 0) {
            std::lock_guard<std::mutex> lock(mtx);
            auto e = parse_json_line(line);
            if (!e.target.empty() || e.port > 0) {
                entries.emplace_back(e);
            }
        }
    }

    void read_stdin() noexcept {
        std::string line;
        while (std::getline(std::cin, line)) {
            add_line(line);
        }
    }

    void generate(std::string_view format, std::string_view output_file) noexcept {
        std::string output;
        if (format == "html") {
            output = generate_html();
        } else if (format == "json") {
            output = generate_json();
        } else {
            output = generate_text();
        }

        if (!output_file.empty() && output_file != "-") {
            std::cerr << "Report written to " << output_file << '\n';
        }

        std::cout << "FINAL:{\"format\":\"" << format
                  << "\",\"entries\":" << entries.size()
                  << ",\"generated\":\"" << timestamp() << "\"}"
                  << '\n';

        if (output_file.empty() || output_file == "-") {
            std::cout << output;
        }
    }
};

int main(int argc, char* argv[]) {
    std::string format = "text";
    std::string output_file;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) format = argv[++i];
        else if (arg == "-o" && i + 1 < argc) output_file = argv[++i];
        else if (arg == "--help") {
            std::cerr << "Usage: " << argv[0] << " [-f format] [-o output]\n";
            std::cerr << "  Formats: text, html, json\n";
            return 0;
        }
    }

    if (format != "text" && format != "html" && format != "json") {
        std::cerr << "Invalid format. Use text, html, or json." << '\n';
        return 1;
    }

    ReportGenerator gen;
    gen.read_stdin();
    gen.generate(format, output_file);

    return 0;
}
