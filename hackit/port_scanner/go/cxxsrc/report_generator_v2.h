#pragma once

#include "correlation_engine_v2.h"

#include <string>
#include <vector>
#include <map>
#include <cstdint>

struct ScanMetadata {
    std::string target;
    int64_t start_time{0};
    int64_t duration_ms{0};
    int engine_count{0};
    int total_ports{0};
    int open_count{0};
    int filtered_count{0};
    std::string scan_profile;
    std::string scanner_version;
};

class ReportGeneratorV2 {
public:
    ReportGeneratorV2();
    ~ReportGeneratorV2();

    std::string generate_text(const std::vector<CorrelatedResult> &results, const ScanMetadata &meta);
    std::string generate_json(const std::vector<CorrelatedResult> &results, const ScanMetadata &meta);
    std::string generate_html(const std::vector<CorrelatedResult> &results, const ScanMetadata &meta);
    std::string generate_csv(const std::vector<CorrelatedResult> &results, const ScanMetadata &meta);

    void set_include_raw(bool include);
    void set_include_recommendations(bool include);
    void set_company_name(const std::string &name);
    void set_report_title(const std::string &title);

private:
    bool include_raw_{false};
    bool include_recommendations_{true};
    std::string company_name_;
    std::string report_title_;

    std::string build_summary_section(const ScanMetadata &meta);
    std::string build_port_table(const std::vector<CorrelatedResult> &results);
    std::string build_risk_section(const std::vector<CorrelatedResult> &results);
    std::string build_recommendations(const std::vector<CorrelatedResult> &results);
    std::string css_styles();
    std::string json_escape(const std::string &s);
    std::string port_status_string(PortStatus status);
    std::string risk_level_for_port(int port, const std::string &service);
    std::string recommendation_for_port(int port, const std::string &service, const std::string &version);
};
