#pragma once

#include <string>
#include <vector>
#include <map>

struct HttpAnalysis {
    int status_code{0};
    std::string status_text;
    std::map<std::string, std::string> headers;
    std::string title;
    std::string server;
    std::string powered_by;
    std::vector<std::string> technology_stack;
    std::string body_preview;
    std::string redirect_url;
    std::string content_type;
    int content_length{0};
    bool has_form{false};
    bool has_login{false};
    bool has_upload{false};
    int cookie_count{0};
    double response_time_ms{0.0};
    std::string raw_response;
};

class HttpAnalyzer {
public:
    HttpAnalyzer();
    ~HttpAnalyzer();

    HttpAnalysis analyze(const std::string &host, int port, bool use_tls, int timeout_ms);
    std::string extract_title(const std::string &html_body);
    std::map<std::string, std::string> extract_headers(const std::string &response);

    void set_user_agent(const std::string &ua);
    void add_custom_header(const std::string &key, const std::string &value);
    void set_follow_redirects(bool follow);
    void set_max_redirects(int n);
    void set_path(const std::string &path);

private:
    std::string user_agent_;
    std::map<std::string, std::string> custom_headers_;
    bool follow_redirects_{true};
    int max_redirects_{5};
    std::string path_{"/"};

    std::string build_request(const std::string &host, int port);
    std::pair<int, std::string> parse_status_line(const std::string &response);
    void detect_technology(const std::string &headers, const std::string &body,
                           std::vector<std::string> &tech_stack);
    std::string send_request(const std::string &host, int port, bool use_tls,
                             const std::string &request, int timeout_ms);
    std::string tls_send_request(const std::string &host, int port,
                                  const std::string &request, int timeout_ms);
};
