#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

// Calculate Shannon Entropy of a string
double calculate_entropy(const char *data) {
  if (data == nullptr || strlen(data) == 0)
    return 0.0;

  std::map<char, int> counts;
  int len = strlen(data);
  for (int i = 0; i < len; i++) {
    counts[data[i]]++;
  }

  double entropy = 0;
  for (auto const &[c, count] : counts) {
    double p = (double)count / len;
    entropy -= p * log2(p);
  }
  return entropy;
}

EXPORT const char *analyze_security_forensics(const char *body,
                                              const char *headers) {
  std::string report = "";

  double body_entropy = calculate_entropy(body);
  report += "body_entropy:" + std::to_string(body_entropy) + "|";

  if (headers != nullptr) {
    std::string h_str = headers;
    if (h_str.find("X-Frame-Options") == std::string::npos)
      report += "missing:X-Frame-Options|";
    if (h_str.find("Content-Security-Policy") == std::string::npos)
      report += "missing:CSP|";
    if (h_str.find("Strict-Transport-Security") == std::string::npos)
      report += "missing:HSTS|";
    if (h_str.find("X-Debug-Token") != std::string::npos)
      report += "found:DebugToken|";
    if (h_str.find("X-Powered-By") != std::string::npos)
      report += "info:PoweredByRevealed|";
  }

  // Check for common obfuscation and leak patterns
  if (body != nullptr) {
    std::string b_str = body;
    if (b_str.find("eval(atob(") != std::string::npos)
      report += "suspicious:base64_eval|";
    if (b_str.find("10.0.0.") != std::string::npos ||
        b_str.find("192.168.") != std::string::npos)
      report += "leak:InternalIP|";
    if (b_str.find("password") != std::string::npos &&
        b_str.find("type=\"hidden\"") != std::string::npos)
      report += "found:HiddenPasswordFields|";
  }

  char *res = new char[report.length() + 1];
  strcpy(res, report.c_str());
  return res;
}

EXPORT void free_forensics_string(char *s) { delete[] s; }
