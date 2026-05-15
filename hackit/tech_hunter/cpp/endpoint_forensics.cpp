#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    EXPORT const char* scan_endpoints(const char* domain) {
        std::string d = domain;
        std::string results = "";
        
        // Simulating common endpoint discovery
        results += "https://" + d + "/swagger-ui.html (Swagger/OpenAPI)\n";
        results += "https://" + d + "/phpmyadmin (Database Admin)\n";
        results += "https://" + d + "/jenkins (CI/CD)\n";
        results += "https://" + d + "/grafana (Monitoring)\n";
        results += "https://" + d + "/api/v1/docs (API Docs)";

        char* cstr = new char[results.length() + 1];
        std::copy(results.begin(), results.end(), cstr);
        cstr[results.length()] = '\0';
        return cstr;
    }

    EXPORT void free_endpoint_string(char* s) {
        delete[] s;
    }
}
