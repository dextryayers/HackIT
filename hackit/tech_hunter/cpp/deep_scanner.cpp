#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

EXPORT const char* deep_payload_scan(const char* body) {
    if (body == nullptr) return "";
    
    std::string b_str = body;
    std::string findings = "";
    
    // Check for API keys or secrets patterns
    if (b_str.find("AKIA") != std::string::npos) findings += "potential:AWS_KEY|";
    if (b_str.find("AIza") != std::string::npos) findings += "potential:GCP_KEY|";
    if (b_str.find("sk_live") != std::string::npos) findings += "potential:STRIPE_KEY|";
    
    // Check for common vulnerability markers
    if (b_str.find("mysql_fetch_array") != std::string::npos) findings += "marker:PHP_MYSQL_ERROR|";
    if (b_str.find("stack trace") != std::string::npos || b_str.find("exception occurred") != std::string::npos) 
        findings += "marker:STACK_TRACE_EXPOSED|";

    char* res = new char[findings.length() + 1];
    std::copy(findings.begin(), findings.end(), res);
    res[findings.length()] = '\0';
    return res;
}
