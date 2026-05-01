#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <cstring>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    EXPORT const char* deep_analyze_tech(const char* body, const char* headers) {
        std::string html(body);
        std::string head(headers);
        std::string results = "";

        // Advanced C++ Heuristics
        // 1. Comment Analysis (Often reveals build tools)
        if (html.find("<!-- This page is cached by") != std::string::npos) {
            results += "WP-Cache|";
        }
        if (html.find("<!-- Created by Artisteer") != std::string::npos) {
            results += "Artisteer|";
        }
        
        // 2. Script Ordering & Patterns (High-Precision)
        std::regex next_data_re(R"(__NEXT_DATA__)");
        if (std::regex_search(html, next_data_re)) {
            results += "Next.js|";
        }

        // 3. Header-Body Correlation
        if (head.find("X-Powered-By: PHP") != std::string::npos && html.find("wp-content") != std::string::npos) {
            results += "WordPress|";
        }

        // 4. Advanced CMS Fingerprinting
        if (html.find("/sites/default/files") != std::string::npos) {
            results += "Drupal|";
        }
        
        // 5. App Frameworks
        if (html.find("_nuxt") != std::string::npos) {
            results += "Nuxt.js|";
        }

        if (results.empty()) return "";
        
        // Return results as a pipe-separated string
        char* cstr = new char[results.length() + 1];
        strcpy(cstr, results.c_str());
        return cstr;
    }

    EXPORT void free_string(char* s) {
        delete[] s;
    }
}
