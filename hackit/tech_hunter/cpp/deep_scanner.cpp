#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <regex>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

struct secret_pattern {
    const char* regex;
    const char* name;
    const char* severity;
};

static const secret_pattern secret_db[] = {
    // AWS
    {"AKIA[0-9A-Z]{16}",                    "AWS Access Key ID",            "HIGH"},
    {"AKIA[0-9A-Z]{16}",                    "AWS Access Key (Standard)",    "HIGH"},
    {"ASIA[0-9A-Z]{16}",                    "AWS Temp Access Key",          "HIGH"},
    {"eyJ[a-zA-Z0-9]{10,}",                 "JWT Token",                    "MEDIUM"},

    // Google Cloud
    {"AIza[0-9A-Za-z_-]{35}",               "Google API Key",               "HIGH"},
    {"ya29\\.[0-9A-Za-z_-]{100,}",          "Google OAuth Token",           "CRITICAL"},

    // Stripe
    {"sk_live_[0-9a-zA-Z]{24,}",            "Stripe Live Secret Key",       "CRITICAL"},
    {"sk_test_[0-9a-zA-Z]{24,}",            "Stripe Test Secret Key",       "MEDIUM"},
    {"pk_live_[0-9a-zA-Z]{24,}",            "Stripe Live Publishable Key",  "MEDIUM"},
    {"pk_test_[0-9a-zA-Z]{24,}",            "Stripe Test Publishable Key",  "LOW"},
    {"rk_live_[0-9a-zA-Z]{24,}",            "Stripe Live Restricted Key",   "HIGH"},

    // GitHub
    {"ghp_[0-9a-zA-Z]{36}",                 "GitHub Personal Access Token", "CRITICAL"},
    {"gho_[0-9a-zA-Z]{36}",                 "GitHub OAuth Access Token",    "CRITICAL"},
    {"ghu_[0-9a-zA-Z]{36}",                 "GitHub User Token",            "CRITICAL"},
    {"github_pat_[0-9a-zA-Z]{22,}",         "GitHub Fine-Grained PAT",      "CRITICAL"},

    // GitLab
    {"glpat-[0-9a-zA-Z_-]{20,}",            "GitLab Personal Access Token", "CRITICAL"},

    // Slack
    {"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}", "Slack Bot Token",      "CRITICAL"},
    {"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}", "Slack User Token",     "CRITICAL"},

    // Discord
    {"[MN][A-Za-z\\d]{23}\\.[A-Za-z\\d]{6}\\.[A-Za-z\\d_-]{27}", "Discord Token", "CRITICAL"},

    // Twilio
    {"SK[0-9a-fA-F]{32}",                   "Twilio Secret Key",            "HIGH"},
    {"AC[0-9a-fA-F]{32}",                   "Twilio Account SID",           "MEDIUM"},

    // Facebook / Meta
    {"EAACEdEose0cBA[0-9A-Za-z]+",          "Facebook Access Token",        "HIGH"},
    {"EAAGmnoXvZCY{40,}",                   "Meta/Facebook Token",          "HIGH"},

    // Generic secrets
    {"-----BEGIN RSA PRIVATE KEY-----",     "RSA Private Key",              "CRITICAL"},
    {"-----BEGIN DSA PRIVATE KEY-----",     "DSA Private Key",              "CRITICAL"},
    {"-----BEGIN EC PRIVATE KEY-----",      "EC Private Key",               "CRITICAL"},
    {"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key",          "CRITICAL"},
    {"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key",            "CRITICAL"},
    {"-----BEGIN CERTIFICATE-----",         "TLS Certificate",              "MEDIUM"},

    // Connection strings
    {"mongodb\\+srv://[^\\s]+",             "MongoDB Connection String",    "CRITICAL"},
    {"postgresql://[^:\\s]+:[^@\\s]+",      "PostgreSQL Connection String",  "CRITICAL"},
    {"mysql://[^:\\s]+:[^@\\s]+",           "MySQL Connection String",      "CRITICAL"},
    {"redis://:[^@\\s]+@",                  "Redis Connection String",      "HIGH"},
    {"rabbitmq://[^:\\s]+:[^@\\s]+",        "RabbitMQ Connection String",   "HIGH"},

    // Cloud provider secrets
    {"-----BEGIN AWS SECRET KEY-----",      "AWS Secret Key",               "CRITICAL"},
    {"-----BEGIN AWS PRIVATE KEY-----",     "AWS Private Key",              "CRITICAL"},

    // Password in URL
    {"https://[^:]+:[^@]+@",               "Password in URL",              "HIGH"},
    {"http://[^:]+:[^@]+@",                "Password in HTTP URL",         "HIGH"},
};

#define SECRET_DB_SIZE (sizeof(secret_db) / sizeof(secret_db[0]))

EXPORT const char* deep_payload_scan(const char* body) {
    if (body == nullptr) {
        char* empty = new char[1];
        empty[0] = '\0';
        return empty;
    }

    std::string b_str(body);
    std::stringstream report;
    report << "Deep Payload Scan\n";
    report << "=================\n\n";

    int total_findings = 0;
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    int low_count = 0;

    report << "Secret / Key Detection:\n";

    for (size_t i = 0; i < SECRET_DB_SIZE; i++) {
        try {
            std::regex re(secret_db[i].regex);
            std::smatch match;
            std::string search_str = b_str;
            bool found = false;

            while (std::regex_search(search_str, match, re)) {
                if (!found) {
                    found = true;
                    total_findings++;
                    report << "  [" << secret_db[i].severity << "] " << secret_db[i].name << ": ";

                    // Mask the secret for safety
                    std::string matched = match.str();
                    if (matched.length() > 8) {
                        report << matched.substr(0, 4) << "..." << matched.substr(matched.length() - 4);
                    } else {
                        report << matched;
                    }
                    report << "\n";

                    if (strcmp(secret_db[i].severity, "CRITICAL") == 0) critical_count++;
                    else if (strcmp(secret_db[i].severity, "HIGH") == 0) high_count++;
                    else if (strcmp(secret_db[i].severity, "MEDIUM") == 0) medium_count++;
                    else low_count++;
                }
                search_str = match.suffix();
            }
        } catch (const std::regex_error&) {
            // Skip invalid regex
            continue;
        }
    }

    if (total_findings == 0) {
        report << "  No secrets/keys detected in payload.\n";
    }

    // Additional generic checks (non-regex)
    report << "\nAdditional Content Analysis:\n";

    if (b_str.find("<?php") != std::string::npos) {
        report << "  [INFO] PHP code detected in payload\n";
    }
    if (b_str.find("<?=") != std::string::npos) {
        report << "  [INFO] PHP short tag detected\n";
    }
    if (b_str.find("eval(") != std::string::npos || b_str.find("eval (") != std::string::npos) {
        report << "  [MEDIUM] eval() function call detected\n";
    }
    if (b_str.find("exec(") != std::string::npos || b_str.find("exec (") != std::string::npos) {
        report << "  [MEDIUM] exec() function call detected\n";
    }
    if (b_str.find("system(") != std::string::npos) {
        report << "  [MEDIUM] system() function call detected\n";
    }
    if (b_str.find("base64_decode(") != std::string::npos) {
        report << "  [MEDIUM] base64_decode() - possible backconnect\n";
    }
    if (b_str.find("mysql_fetch_array") != std::string::npos) {
        report << "  [MEDIUM] PHP MySQL error surface\n";
    }
    if (b_str.find("stack trace") != std::string::npos ||
        b_str.find("exception occurred") != std::string::npos ||
        b_str.find("Stack trace:") != std::string::npos) {
        report << "  [HIGH] Stack trace exposed in response\n";
    }
    if (b_str.find("$_GET") != std::string::npos || b_str.find("$_POST") != std::string::npos ||
        b_str.find("$_REQUEST") != std::string::npos || b_str.find("$_SERVER") != std::string::npos) {
        report << "  [INFO] PHP superglobal references\n";
    }
    if (b_str.find("debug_backtrace") != std::string::npos) {
        report << "  [HIGH] debug_backtrace() exposed\n";
    }
    if (b_str.find("phpinfo()") != std::string::npos || b_str.find("phpinfo (") != std::string::npos) {
        report << "  [CRITICAL] phpinfo() call detected\n";
    }
    if (b_str.find("SELECT ") != std::string::npos && b_str.find("FROM ") != std::string::npos) {
        report << "  [MEDIUM] SQL query pattern in payload\n";
    }
    if (b_str.find(" UNION ") != std::string::npos) {
        report << "  [HIGH] UNION SQL keyword detected\n";
    }

    report << "\nSummary:\n";
    report << "  Total findings: " << total_findings << "\n";
    report << "  Critical: " << critical_count << " | High: " << high_count;
    report << " | Medium: " << medium_count << " | Low: " << low_count << "\n";

    std::string s = report.str();
    char* res = new char[s.length() + 1];
    std::copy(s.begin(), s.end(), res);
    res[s.length()] = '\0';
    return res;
}

EXPORT void free_deep_scan_string(char* s) {
    delete[] s;
}
