#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
    EXPORT const char* scan_endpoints(const char* domain, const char* body) {
        std::string d = domain;
        std::string b = body;
        std::string results = "";

        // Genuine API Deep Dive via Body Forensics
        if (b.find("graphql") != std::string::npos || b.find("query {") != std::string::npos || b.find("mutation {") != std::string::npos) {
            results += "https://" + d + "/graphql (GraphQL patterns detected in source)\n";
        }
        if (b.find("swagger-ui") != std::string::npos || b.find("openapi\":") != std::string::npos) {
            results += "https://" + d + "/api-docs (Swagger/OpenAPI UI Exposed in source)\n";
        }
        if (b.find("actuator/health") != std::string::npos || b.find("\"status\":\"UP\"") != std::string::npos) {
            results += "https://" + d + "/actuator/health (Spring Boot footprints detected)\n";
        }
        if (b.find("wp-json") != std::string::npos) {
            results += "https://" + d + "/wp-json/wp/v2/users (WordPress REST API detected)\n";
        }

        char* cstr = new char[results.length() + 1];
        std::copy(results.begin(), results.end(), cstr);
        cstr[results.length()] = '\0';
        return cstr;
    }

    EXPORT void free_endpoint_string(char* s) {
        delete[] s;
    }
}
