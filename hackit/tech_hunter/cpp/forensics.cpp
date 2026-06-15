#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

static double calculate_entropy(const char *data) {
    if (data == nullptr || strlen(data) == 0) return 0.0;
    int len = strlen(data);
    std::map<char, int> counts;
    for (int i = 0; i < len; i++) counts[data[i]]++;
    double entropy = 0;
    for (auto const &[c, count] : counts) {
        double p = (double)count / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

struct forensics_check {
    const char* pattern;
    const char* category;
    const char* finding;
    int severity;
};

static const forensics_check body_checks[] = {
    {"eval(atob(",  "OBFUSCATION", "Base64 eval detected - possible payload obfuscation", 2},
    {"eval(String.fromCharCode", "OBFUSCATION", "Character code eval obfuscation", 2},
    {"unescape(",   "OBFUSCATION", "Unescape obfuscation detected", 1},
    {"\\x",
     "OBFUSCATION", "Hex-encoded content in body", 1},
    {"<script>",    "XSS", "Inline script tag (unsanitized)", 2},
    {"javascript:", "XSS", "JavaScript URI scheme detected", 2},
    {"onerror=",    "XSS", "Event handler with error trigger", 1},
    {"onload=",     "XSS", "Event handler with load trigger", 1},
    {"onclick=",    "XSS", "Event handler with click trigger", 1},
    {"onfocus=",    "XSS", "Event handler with focus trigger", 1},

    {"10.0.0.",     "LEAK", "Internal IP (10.0.0.0/8) exposure", 2},
    {"10.",         "LEAK", "Internal IP (10.x.x.x) pattern", 1},
    {"192.168.",    "LEAK", "Internal IP (192.168.x.x) exposure", 2},
    {"172.16.",     "LEAK", "Internal IP (172.16.0.0/12) exposure", 2},
    {"172.17.",     "LEAK", "Internal IP (Docker bridge) exposure", 1},
    {"172.18.",     "LEAK", "Internal IP exposure", 1},
    {"127.0.0.1",   "LEAK", "Localhost reference in body", 1},
    {"localhost",   "LEAK", "Localhost reference in body", 1},
    {".internal",   "LEAK", "Internal DNS suffix exposed", 2},
    {".local",      "LEAK", "Local DNS suffix exposed", 1},

    {"password",    "CREDENTIAL", "Password field/keyword in body", 2},
    {"secret",      "CREDENTIAL", "Secret keyword in body", 2},
    {"api_key",     "CREDENTIAL", "API key variable name detected", 3},
    {"api-secret",  "CREDENTIAL", "API secret variable detected", 3},
    {"access_key",  "CREDENTIAL", "Access key variable detected", 3},
    {"private_key", "CREDENTIAL", "Private key variable detected", 3},
    {"token",       "CREDENTIAL", "Token variable detected", 2},

    {"type=\"hidden\"", "FORM", "Hidden form field detected", 0},
    {"type=hidden", "FORM", "Hidden form field detected", 0},
    {"<form",       "FORM", "Form element detected", 0},
    {"enctype=\"multipart/form-data\"", "FORM", "File upload form detected", 1},

    {"data:application/json", "DATA_EXPOSURE", "Inline JSON data blob", 1},
    {"data:text/javascript", "DATA_EXPOSURE", "Inline JavaScript data URI", 2},
    {"data:text/html", "DATA_EXPOSURE", "Inline HTML data URI - XSS vector", 2},
    {"data:image/svg+xml", "DATA_EXPOSURE", "SVG data URI - possible XSS vector", 2},
};

#define BODY_CHECKS_SIZE (sizeof(body_checks) / sizeof(body_checks[0]))

static const forensics_check header_checks[] = {
    {"X-Frame-Options",         "SECURITY_HEADER", "Missing clickjacking protection", 2},
    {"Content-Security-Policy", "SECURITY_HEADER", "Missing CSP", 2},
    {"Strict-Transport-Security","SECURITY_HEADER", "Missing HSTS", 2},
    {"X-Content-Type-Options",  "SECURITY_HEADER", "Missing nosniff header", 1},
    {"Referrer-Policy",         "SECURITY_HEADER", "Missing referrer policy", 1},
    {"Permissions-Policy",      "SECURITY_HEADER", "Missing permissions policy", 1},
    {"X-Debug-Token",           "DEBUG", "Debug token header exposed", 3},
    {"X-Debug-Exception",       "DEBUG", "Debug exception header exposed", 3},
    {"X-Debug-Exception-Message","DEBUG", "Exception message in header", 3},
    {"X-Powered-By",            "INFO", "Technology stack revealed", 1},
    {"X-Generator",             "INFO", "Generator/Platform revealed", 1},
    {"X-AspNet-Version",        "INFO", "ASP.NET version revealed", 1},
    {"X-AspNetMvc-Version",     "INFO", "ASP.NET MVC version revealed", 1},
    {"X-Runtime",               "INFO", "Runtime version revealed (Ruby/Rack)", 1},
    {"X-Version",               "INFO", "Version info revealed", 1},
    {"Server",                  "INFO", "Server software banner", 0},
};

#define HEADER_CHECKS_SIZE (sizeof(header_checks) / sizeof(header_checks[0]))

EXPORT const char *analyze_security_forensics(const char *body,
                                               const char *headers) {
    std::stringstream report;
    report << "Security Forensics Report\n";
    report << "=========================\n";

    // Entropy analysis
    double body_entropy = body ? calculate_entropy(body) : 0.0;
    double header_entropy = headers ? calculate_entropy(headers) : 0.0;

    report << "\nEntropy Analysis:\n";
    report << "  Body entropy:    " << body_entropy << " bits/byte\n";
    report << "  Header entropy:  " << header_entropy << " bits/byte\n";

    if (body_entropy > 7.0) {
        report << "  ! Body has very high entropy (likely encrypted/compressed/random)\n";
    } else if (body_entropy > 5.5) {
        report << "  ! Body has high entropy (possible obfuscation)\n";
    }

    // Body forensics
    if (body != nullptr && strlen(body) > 0) {
        report << "\nBody Forensics:\n";
        std::string b_str(body);
        int findings = 0;

        for (size_t i = 0; i < BODY_CHECKS_SIZE; i++) {
            if (b_str.find(body_checks[i].pattern) != std::string::npos) {
                findings++;
                report << "  [" << body_checks[i].category << "] "
                       << body_checks[i].finding;
                if (body_checks[i].severity >= 3) report << " (HIGH)";
                else if (body_checks[i].severity >= 2) report << " (MEDIUM)";
                report << "\n";
            }
        }

        if (findings == 0) {
            report << "  No suspicious patterns detected in body.\n";
        }

        // Check for base64-encoded content
        size_t b64_chunks = 0;
        size_t pos = 0;
        while ((pos = b_str.find("AAA", pos)) != std::string::npos) {
            b64_chunks++;
            pos += 3;
        }
        // Reset and check for other signs of encoding
        pos = 0;
        while ((pos = b_str.find("==", pos)) != std::string::npos) {
            // Base64 padding in typical positions
            size_t line_start = (pos > 60) ? pos - 60 : 0;
            std::string context = b_str.substr(line_start, pos - line_start + 2);
            if (context.find_first_not_of(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
                // Likely base64
                break;
            }
            pos += 2;
        }
    }

    // Header forensics
    if (headers != nullptr && strlen(headers) > 0) {
        report << "\nHeader Forensics:\n";
        std::string h_str(headers);
        int findings = 0;

        for (size_t i = 0; i < HEADER_CHECKS_SIZE; i++) {
            if (h_str.find(header_checks[i].pattern) == std::string::npos) {
                findings++;
                report << "  [MISSING " << header_checks[i].category << "] "
                       << header_checks[i].finding;
                if (header_checks[i].severity >= 3) report << " (HIGH)";
                else if (header_checks[i].severity >= 2) report << " (MEDIUM)";
                report << "\n";
            }
        }

        if (findings == 0) {
            report << "  All critical security headers present.\n";
        }
    }

    // Debug headers (present = bad)
    if (headers != nullptr) {
        std::string h_str(headers);
        report << "\nDebug/Info Leak Check:\n";
        bool leak_found = false;
        const char* leak_patterns[] = {
            "X-Debug", "X-Dump", "X-Profile", "X-Trace",
            "X-Exception", "X-Error", "Stack trace", "Exception:",
            "PHP Notice", "PHP Warning", "PHP Fatal error",
            "Warning:", "Fatal:", "Notice:", "Parse error:",
            "SQLSTATE[", "mysql_error", "mysqli_error",
            "pg_last_error", "oci_error", "ODBC error",
            "com_error", "soap_error", nullptr
        };
        for (int i = 0; leak_patterns[i]; i++) {
            if (h_str.find(leak_patterns[i]) != std::string::npos) {
                report << "  ! LEAK: Debug/Error info: " << leak_patterns[i] << "\n";
                leak_found = true;
            }
        }
        if (!leak_found) {
            report << "  No debug/error leaks detected.\n";
        }
    }

    // Summary
    report << "\nSummary:\n";
    double total_entropy = (body_entropy + header_entropy) / 2.0;
    if (total_entropy > 6.0) {
        report << "  Risk level: MEDIUM-HIGH (high entropy, possible obfuscation/payload)\n";
    } else {
        report << "  Risk level: LOW (normal entropy range)\n";
    }

    std::string s = report.str();
    char *res = new char[s.length() + 1];
    strcpy(res, s.c_str());
    return res;
}

EXPORT void free_forensics_string(char *s) { delete[] s; }
