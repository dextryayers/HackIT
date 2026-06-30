#define _GNU_SOURCE
#include "report_generator_v2.h"
#include "optimize.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <cmath>

ReportGeneratorV2::ReportGeneratorV2() {
    company_name_ = "PortStorm Security Scanner";
    report_title_ = "Port Scan Report";
}

ReportGeneratorV2::~ReportGeneratorV2() {}

void ReportGeneratorV2::set_include_raw(bool include) { include_raw_ = include; }
void ReportGeneratorV2::set_include_recommendations(bool include) { include_recommendations_ = include; }
void ReportGeneratorV2::set_company_name(const std::string &name) { company_name_ = name; }
void ReportGeneratorV2::set_report_title(const std::string &title) { report_title_ = title; }

std::string ReportGeneratorV2::json_escape(const std::string &s) {
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

std::string ReportGeneratorV2::port_status_string(PortStatus status) {
    switch (status) {
        case PortStatus::OPEN: return "open";
        case PortStatus::CLOSED: return "closed";
        case PortStatus::FILTERED: return "filtered";
        default: return "unknown";
    }
}

std::string ReportGeneratorV2::risk_level_for_port(int port, const std::string &service) {
    std::string svc = service;
    std::transform(svc.begin(), svc.end(), svc.begin(), ::toupper);

    if (svc == "SSH" || svc == "TELNET") return "HIGH";
    if (port == 23 || port == 3389 || port == 5900 || port == 5901) return "HIGH";
    if (port == 3306 || port == 5432 || port == 27017 || port == 6379) return "HIGH";
    if (port == 445 || port == 139 || port == 135) return "HIGH";
    if (port == 20 || port == 21) return "MEDIUM";
    if (svc == "HTTP" || svc == "HTTPS") return "LOW";
    if (svc == "DNS" || svc == "DHCP" || svc == "NTP") return "LOW";

    if (port < 1024) return "MEDIUM";
    return "INFO";
}

std::string ReportGeneratorV2::recommendation_for_port(int port, const std::string &service,
                                                        const std::string &version)
{
    std::string svc = service;
    std::transform(svc.begin(), svc.end(), svc.begin(), ::toupper);

    if (svc == "SSH") {
        return "Ensure SSH uses key-based authentication, disable password auth, "
               "restrict to specific users, and use a non-standard port if possible.";
    }
    if (svc == "TELNET") {
        return "Replace Telnet with SSH immediately. Telnet transmits data in "
               "cleartext including credentials.";
    }
    if (port == 3306 || svc == "MYSQL") {
        return "Restrict MySQL access to trusted hosts only, use strong passwords, "
               "and consider running on a non-standard port.";
    }
    if (port == 5432 || svc == "POSTGRESQL") {
        return "Configure pg_hba.conf to restrict access, use SSL connections, "
               "and ensure strong authentication.";
    }
    if (port == 6379 || svc == "REDIS") {
        return "Enable Redis authentication (requirepass), disable CONFIG command, "
               "and bind to localhost if possible.";
    }
    if (port == 27017 || svc == "MONGODB") {
        return "Enable MongoDB authentication, use TLS, and restrict network exposure.";
    }
    if (port == 3389) {
        return "Restrict RDP access via VPN or firewall, enable NLA, and use "
               "strong account passwords.";
    }
    if (port == 5900 || svc == "VNC") {
        return "Use VNC over SSH tunnel or replace with a secure remote desktop "
               "solution. VNC is typically unencrypted.";
    }
    if (svc == "FTP") {
        return "Replace FTP with SFTP or FTPS. FTP transmits credentials in cleartext.";
    }
    if (svc == "HTTP" || svc == "HTTP-ALT") {
        return "Redirect all HTTP traffic to HTTPS. Enable HSTS headers.";
    }
    if (svc == "SMTP" && port == 25) {
        return "Disable open relay, enable STARTTLS, and implement SPF/DKIM/DMARC.";
    }
    if (svc == "SMB" || port == 445 || port == 139) {
        return "Disable SMBv1, restrict SMB to trusted networks, and keep patched "
               "to avoid ransomware propagation.";
    }
    if (port == 11211 || svc == "MEMCACHED") {
        return "Bind Memcached to localhost only. This port should never be "
               "publicly accessible due to amplification attack risks.";
    }
    if (svc == "SNMP") {
        return "Use SNMPv3 with encryption. Disable SNMPv1 and SNMPv2c public communities.";
    }
    if (svc == "RSYNC") {
        return "Restrict rsync access with firewall rules and use SSH tunneling.";
    }
    if (svc == "RDP" || port == 3389) {
        return "Restrict RDP access via VPN, enable Network Level Authentication, "
               "and use strong credentials.";
    }
    if (!version.empty()) {
        return "Review version " + version + " for known vulnerabilities and "
               "apply security patches regularly.";
    }
    return "Evaluate whether this port needs to be publicly accessible."
           " Apply principle of least privilege.";
}

std::string ReportGeneratorV2::build_summary_section(const ScanMetadata &meta) {
    std::ostringstream ss;
    ss << "Scan Summary\n";
    ss << "=============\n\n";
    ss << "Target:          " << meta.target << "\n";
    ss << "Start Time:      ";

    if (meta.start_time > 0) {
        time_t t = meta.start_time / 1000;
        struct tm tm;
        localtime_r(&t, &tm);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
        ss << buf << "\n";
    } else {
        ss << "N/A\n";
    }

    ss << "Duration:        " << std::fixed << std::setprecision(1)
       << (meta.duration_ms / 1000.0) << "s (" << meta.duration_ms << "ms)\n";
    ss << "Engines Used:    " << meta.engine_count << "\n";
    ss << "Total Ports:     " << meta.total_ports << "\n";
    ss << "Open Ports:      " << meta.open_count << "\n";
    ss << "Filtered Ports:  " << meta.filtered_count << "\n\n";
    return ss.str();
}

std::string ReportGeneratorV2::build_port_table(const std::vector<CorrelatedResult> &results) {
    std::ostringstream ss;
    ss << "Open Ports (" << results.size() << " found)\n";
    ss << "------------" << std::string(std::max(0, (int)results.size() >= 10 ? 0 : 0), '-') << "\n\n";

    ss << std::left
       << std::setw(8) << "Port"
       << std::setw(12) << "Status"
       << std::setw(20) << "Service"
       << std::setw(16) << "Version"
       << std::setw(12) << "Confidence"
       << std::setw(10) << "Engines"
       << "Risk Level\n";
    ss << std::string(78, '-') << "\n";

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        ss << std::left
           << std::setw(8) << r.port
           << std::setw(12) << port_status_string(r.final_status)
           << std::setw(20) << r.final_service
           << std::setw(16) << r.final_version.substr(0, 14)
           << std::setw(12) << std::to_string((int)(r.confidence * 100)) + "%"
           << std::setw(10) << (std::to_string(r.engines_agreed) + "/" + std::to_string(r.total_engines))
           << risk << "\n";
    }

    ss << "\n";
    return ss.str();
}

std::string ReportGeneratorV2::build_risk_section(const std::vector<CorrelatedResult> &results) {
    std::ostringstream ss;
    ss << "Risk Assessment\n";
    ss << "================\n\n";

    int critical = 0, high = 0, medium = 0, low = 0;

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "CRITICAL") ++critical;
        else if (risk == "HIGH") ++high;
        else if (risk == "MEDIUM") ++medium;
        else if (risk == "LOW") ++low;
    }

    ss << "Risk Distribution:\n";
    ss << "  CRITICAL: " << critical << "\n";
    ss << "  HIGH:     " << high << "\n";
    ss << "  MEDIUM:   " << medium << "\n";
    ss << "  LOW:      " << low << "\n\n";

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "CRITICAL" || risk == "HIGH") {
            ss << "[!] Port " << r.port << "/" << r.final_service
               << " (" << risk << ")\n";
        }
    }

    ss << "\n";
    return ss.str();
}

std::string ReportGeneratorV2::build_recommendations(const std::vector<CorrelatedResult> &results) {
    std::ostringstream ss;
    ss << "Recommendations\n";
    ss << "================\n\n";

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "CRITICAL" || risk == "HIGH") {
            ss << "Port " << r.port << " (" << r.final_service << "):\n";
            ss << "  " << recommendation_for_port(r.port, r.final_service, r.final_version) << "\n\n";
        }
    }

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "MEDIUM") {
            ss << "Port " << r.port << " (" << r.final_service << "):\n";
            ss << "  " << recommendation_for_port(r.port, r.final_service, r.final_version) << "\n\n";
        }
    }

    ss << "General Recommendations:\n";
    ss << "  - Keep all software up to date with the latest security patches\n";
    ss << "  - Use a firewall to restrict access to only necessary ports\n";
    ss << "  - Enable logging and monitoring for all exposed services\n";
    ss << "  - Conduct regular vulnerability assessments\n";
    ss << "  - Implement network segmentation for sensitive services\n";
    ss << "  - Use intrusion detection/prevention systems\n";
    ss << "\n";

    return ss.str();
}

std::string ReportGeneratorV2::generate_text(const std::vector<CorrelatedResult> &results,
                                              const ScanMetadata &meta)
{
    std::ostringstream ss;
    ss << "==============================================\n";
    ss << "  " << report_title_ << "\n";
    ss << "  Generated by " << company_name_ << "\n";
    ss << "==============================================\n\n";

    ss << build_summary_section(meta);
    ss << build_port_table(results);
    ss << build_risk_section(results);

    if (include_recommendations_) {
        ss << build_recommendations(results);
    }

    ss << "==============================================\n";
    ss << "  Report generated at: ";

    auto now = std::chrono::system_clock::now();
    time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm;
    localtime_r(&t, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    ss << buf << "\n";
    ss << "==============================================\n";

    return ss.str();
}

std::string ReportGeneratorV2::generate_json(const std::vector<CorrelatedResult> &results,
                                              const ScanMetadata &meta)
{
    std::ostringstream j;
    j << "{\n";
    j << "  \"report_title\": \"" << json_escape(report_title_) << "\",\n";
    j << "  \"generator\": \"" << json_escape(company_name_) << "\",\n";
    j << "  \"metadata\": {\n";
    j << "    \"target\": \"" << json_escape(meta.target) << "\",\n";
    j << "    \"start_time\": " << meta.start_time << ",\n";
    j << "    \"duration_ms\": " << meta.duration_ms << ",\n";
    j << "    \"engine_count\": " << meta.engine_count << ",\n";
    j << "    \"total_ports\": " << meta.total_ports << ",\n";
    j << "    \"open_count\": " << meta.open_count << ",\n";
    j << "    \"filtered_count\": " << meta.filtered_count << "\n";
    j << "  },\n";
    j << "  \"results\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto &r = results[i];
        j << "    {\n";
        j << "      \"port\": " << r.port << ",\n";
        j << "      \"status\": \"" << port_status_string(r.final_status) << "\",\n";
        j << "      \"service\": \"" << json_escape(r.final_service) << "\",\n";
        j << "      \"version\": \"" << json_escape(r.final_version) << "\",\n";
        j << "      \"confidence\": " << r.confidence << ",\n";
        j << "      \"engines_agreed\": " << r.engines_agreed << ",\n";
        j << "      \"total_engines\": " << r.total_engines << ",\n";
        j << "      \"risk_level\": \"" << risk_level_for_port(r.port, r.final_service) << "\"\n";
        j << "    }";
        if (i + 1 < results.size()) j << ",";
        j << "\n";
    }

    j << "  ]\n";
    j << "}\n";
    return j.str();
}

std::string ReportGeneratorV2::generate_html(const std::vector<CorrelatedResult> &results,
                                              const ScanMetadata &meta)
{
    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n";
    h << "<meta charset=\"UTF-8\">\n";
    h << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    h << "<title>" << json_escape(report_title_) << " - " << json_escape(meta.target) << "</title>\n";
    h << "<style>\n" << css_styles() << "\n</style>\n";
    h << "</head>\n<body>\n";
    h << "<div class=\"container\">\n";

    h << "<div class=\"header\">\n";
    h << "  <h1>" << json_escape(report_title_) << "</h1>\n";
    h << "  <p class=\"subtitle\">Generated by " << json_escape(company_name_) << "</p>\n";
    h << "</div>\n";

    h << "<div class=\"section\">\n";
    h << "  <h2>Scan Summary</h2>\n";
    h << "  <table class=\"summary-table\">\n";
    h << "    <tr><td>Target</td><td>" << json_escape(meta.target) << "</td></tr>\n";

    if (meta.start_time > 0) {
        time_t t = meta.start_time / 1000;
        struct tm tm;
        localtime_r(&t, &tm);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
        h << "    <tr><td>Start Time</td><td>" << buf << "</td></tr>\n";
    }

    h << "    <tr><td>Duration</td><td>" << std::fixed << std::setprecision(1)
      << (meta.duration_ms / 1000.0) << " seconds</td></tr>\n";
    h << "    <tr><td>Engines Used</td><td>" << meta.engine_count << "</td></tr>\n";
    h << "    <tr><td>Total Ports Scanned</td><td>" << meta.total_ports << "</td></tr>\n";
    h << "    <tr><td>Open Ports Found</td><td>" << meta.open_count << "</td></tr>\n";
    h << "    <tr><td>Filtered Ports</td><td>" << meta.filtered_count << "</td></tr>\n";
    h << "  </table>\n";
    h << "</div>\n";

    h << "<div class=\"section\">\n";
    h << "  <h2>Open Ports</h2>\n";
    h << "  <table class=\"port-table\">\n";
    h << "    <tr>\n";
    h << "      <th>Port</th><th>Service</th><th>Version</th><th>Confidence</th><th>Risk Level</th><th>Recommendation</th>\n";
    h << "    </tr>\n";

    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        std::string risk_class;
        if (risk == "CRITICAL") risk_class = "risk-critical";
        else if (risk == "HIGH") risk_class = "risk-high";
        else if (risk == "MEDIUM") risk_class = "risk-medium";
        else risk_class = "risk-low";

        h << "    <tr class=\"" << risk_class << "\">\n";
        h << "      <td>" << r.port << "</td>\n";
        h << "      <td>" << json_escape(r.final_service) << "</td>\n";
        h << "      <td>" << json_escape(r.final_version) << "</td>\n";
        h << "      <td>" << (int)(r.confidence * 100) << "%</td>\n";
        h << "      <td>" << risk << "</td>\n";
        h << "      <td>" << json_escape(recommendation_for_port(r.port, r.final_service, r.final_version)) << "</td>\n";
        h << "    </tr>\n";
    }

    h << "  </table>\n";
    h << "</div>\n";

    h << "<div class=\"section\">\n";
    h << "  <h2>Risk Assessment</h2>\n";

    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "CRITICAL") ++critical;
        else if (risk == "HIGH") ++high;
        else if (risk == "MEDIUM") ++medium;
        else if (risk == "LOW") ++low;
    }

    h << "  <div class=\"risk-summary\">\n";
    if (critical > 0)
        h << "    <span class=\"badge badge-critical\">" << critical << " Critical</span>\n";
    if (high > 0)
        h << "    <span class=\"badge badge-high\">" << high << " High</span>\n";
    if (medium > 0)
        h << "    <span class=\"badge badge-medium\">" << medium << " Medium</span>\n";
    if (low > 0)
        h << "    <span class=\"badge badge-low\">" << low << " Low</span>\n";
    h << "  </div>\n";

    h << "  <ul>\n";
    for (const auto &r : results) {
        if (r.final_status != PortStatus::OPEN) continue;
        std::string risk = risk_level_for_port(r.port, r.final_service);
        if (risk == "CRITICAL" || risk == "HIGH") {
            h << "    <li class=\"risk-" << (risk == "CRITICAL" ? "critical" : "high")
              << "\"><strong>Port " << r.port << " (" << json_escape(r.final_service)
              << ")</strong> - " << risk << " risk</li>\n";
        }
    }
    h << "  </ul>\n";
    h << "</div>\n";

    if (include_recommendations_) {
        h << "<div class=\"section\">\n";
        h << "  <h2>Recommendations</h2>\n";
        h << "  <ul>\n";
        for (const auto &r : results) {
            if (r.final_status != PortStatus::OPEN) continue;
            std::string risk = risk_level_for_port(r.port, r.final_service);
            if (risk == "CRITICAL" || risk == "HIGH" || risk == "MEDIUM") {
                h << "    <li><strong>Port " << r.port << " (" << json_escape(r.final_service)
                  << "):</strong> " << json_escape(recommendation_for_port(r.port, r.final_service, r.final_version)) << "</li>\n";
            }
        }
        h << "  </ul>\n";
        h << "  <h3>General Security Recommendations</h3>\n";
        h << "  <ul>\n";
        h << "    <li>Keep all software up to date with the latest security patches</li>\n";
        h << "    <li>Use a firewall to restrict access to only necessary ports</li>\n";
        h << "    <li>Enable logging and monitoring for all exposed services</li>\n";
        h << "    <li>Conduct regular vulnerability assessments</li>\n";
        h << "    <li>Implement network segmentation for sensitive services</li>\n";
        h << "  </ul>\n";
        h << "</div>\n";
    }

    h << "<div class=\"footer\">\n";
    h << "  <p>" << json_escape(company_name_) << " &copy; 2024-2026</p>\n";
    h << "</div>\n";

    h << "</div>\n";
    h << "</body>\n</html>\n";
    return h.str();
}

std::string ReportGeneratorV2::generate_csv(const std::vector<CorrelatedResult> &results,
                                             const ScanMetadata &meta)
{
    std::ostringstream csv;

    csv << "# " << json_escape(report_title_) << "\n";
    csv << "# Generated by " << json_escape(company_name_) << "\n";
    csv << "# Target: " << json_escape(meta.target) << "\n";
    csv << "# Duration: " << meta.duration_ms << "ms\n";
    csv << "# Scan Time: ";

    auto now = std::chrono::system_clock::now();
    time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm;
    localtime_r(&t, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    csv << buf << "\n";
    csv << "\n";

    csv << "Port,Status,Service,Version,Confidence,Engines Agreed,Total Engines,Risk Level\n";

    for (const auto &r : results) {
        csv << r.port << ","
            << port_status_string(r.final_status) << ","
            << "\"" << json_escape(r.final_service) << "\","
            << "\"" << json_escape(r.final_version) << "\","
            << (int)(r.confidence * 100) << "%,"
            << r.engines_agreed << ","
            << r.total_engines << ","
            << risk_level_for_port(r.port, r.final_service) << "\n";
    }

    return csv.str();
}

std::string ReportGeneratorV2::css_styles() {
    return R"(
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 960px; margin: 0 auto; padding: 20px; }
        .header { background: #1a1a2e; color: #fff; padding: 30px; border-radius: 8px;
                  margin-bottom: 24px; }
        .header h1 { font-size: 24px; margin-bottom: 8px; }
        .header .subtitle { color: #aaa; font-size: 14px; }
        .section { background: #fff; padding: 24px; border-radius: 8px;
                   margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .section h2 { font-size: 18px; color: #1a1a2e; margin-bottom: 16px;
                       padding-bottom: 8px; border-bottom: 2px solid #e0e0e0; }
        .summary-table { width: 100%; border-collapse: collapse; }
        .summary-table td { padding: 8px 12px; border-bottom: 1px solid #e0e0e0; }
        .summary-table td:first-child { font-weight: 600; width: 160px; color: #555; }
        .port-table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        .port-table th { background: #f8f9fa; padding: 10px 12px; text-align: left;
                         font-size: 13px; text-transform: uppercase; color: #666;
                         border-bottom: 2px solid #dee2e6; }
        .port-table td { padding: 10px 12px; border-bottom: 1px solid #e0e0e0;
                         font-size: 14px; }
        .risk-critical { border-left: 4px solid #dc3545; background: #fff5f5; }
        .risk-high { border-left: 4px solid #fd7e14; background: #fff8f0; }
        .risk-medium { border-left: 4px solid #ffc107; }
        .risk-low { border-left: 4px solid #28a745; }
        .risk-summary { margin: 12px 0; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px;
                 font-size: 12px; font-weight: 600; margin-right: 8px; }
        .badge-critical { background: #dc3545; color: #fff; }
        .badge-high { background: #fd7e14; color: #fff; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: #fff; }
        .risk-critical, .risk-high { font-weight: 500; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 12px; }
        ul { padding-left: 20px; }
        li { margin-bottom: 8px; }
        h3 { font-size: 15px; color: #333; margin: 16px 0 8px 0; }
    )";
}
