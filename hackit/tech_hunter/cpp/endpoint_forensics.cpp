#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

struct endpoint_pattern {
    const char* pattern;
    const char* path;
    const char* description;
    int severity;
};

static const endpoint_pattern endpoint_db[] = {
    // API frameworks
    {"graphql",              "/graphql",                    "GraphQL API endpoint", 2},
    {"query {",              "/graphql",                    "GraphQL query syntax in body", 2},
    {"mutation {",           "/graphql",                    "GraphQL mutation syntax in body", 2},
    {"__typename",           "/graphql",                    "GraphQL __typename introspection", 2},

    {"swagger-ui",           "/api-docs",                   "Swagger UI exposed", 2},
    {"openapi\":",           "/api-docs",                   "OpenAPI spec detected", 2},
    {"swagger\":",           "/api-docs",                   "Swagger spec detected", 2},
    {"api-docs",             "/api-docs",                   "API docs reference", 2},

    // Spring Boot
    {"actuator/health",      "/actuator/health",            "Spring Boot Actuator health", 2},
    {"actuator/info",        "/actuator/info",              "Spring Boot Actuator info", 2},
    {"actuator/env",         "/actuator/env",               "Spring Boot env (env vars leak)", 3},
    {"actuator/",            "/actuator/*",                 "Spring Boot Actuator endpoint", 3},
    {"\"status\":\"UP\"",    "/actuator/health",            "Spring Boot health status", 2},

    // WordPress
    {"wp-json",              "/wp-json/wp/v2/users",        "WordPress REST API", 2},
    {"wp-content",           "/wp-content/",                "WordPress content dir", 1},
    {"wp-admin",             "/wp-admin/",                  "WordPress admin panel", 2},
    {"wp-includes",          "/wp-includes/",               "WordPress includes dir", 1},
    {"wp-login",             "/wp-login.php",               "WordPress login page", 2},
    {"xmlrpc.php",           "/xmlrpc.php",                 "WordPress XML-RPC", 2},

    // Laravel
    {"laravel",              "/",                           "Laravel framework detected", 1},
    {"_token",               "/",                           "Laravel CSRF token", 1},
    {"laravel_session",      "/",                           "Laravel session cookie", 1},

    // Django
    {"csrfmiddlewaretoken",  "/",                           "Django CSRF token", 1},
    {"sessionid",            "/",                           "Django session cookie", 1},
    {"django",               "/",                           "Django framework detected", 1},
    {"debug=true",           "/",                           "Django debug mode", 3},

    // Ruby on Rails
    {"rails",                "/",                           "Ruby on Rails detected", 1},
    {"_csrf_token",          "/",                           "Rails CSRF token", 1},
    {"authenticity_token",   "/",                           "Rails authenticity token", 1},
    {"rails_admin",          "/admin",                      "Rails Admin panel", 2},

    // ASP.NET
    {"__VIEWSTATE",          "/",                           "ASP.NET ViewState", 1},
    {"__EVENTVALIDATION",    "/",                           "ASP.NET EventValidation", 1},
    {"ASP.NET_SessionId",    "/",                           "ASP.NET Session cookie", 1},
    {"WebResource.axd",      "/WebResource.axd",            "ASP.NET WebResource", 1},

    // Common paths
    {"/api/",                "/api/",                       "API endpoint pattern", 2},
    {"/v1/",                 "/v1/",                        "API version 1", 1},
    {"/v2/",                 "/v2/",                        "API version 2", 1},
    {"/v3/",                 "/v3/",                        "API version 3", 1},
    {"/rest/",               "/rest/",                      "REST API pattern", 2},
    {"/soap/",               "/soap/",                      "SOAP API endpoint", 2},

    // Admin panels
    {"/admin",               "/admin",                      "Admin panel", 2},
    {"/dashboard",           "/dashboard",                  "Dashboard panel", 2},
    {"/cpanel",              "/cpanel",                     "Control panel", 2},

    // Monitoring / DevOps
    {"/health",              "/health",                     "Health check endpoint", 1},
    {"/metrics",             "/metrics",                    "Metrics endpoint", 2},
    {"/prometheus",          "/metrics",                    "Prometheus metrics", 2},
    {"/debug",               "/debug",                      "Debug endpoint", 3},
    {"/console",             "/console",                    "Console endpoint (dangerous)", 3},

    // CI/CD
    {"jenkins",              "/jenkins",                    "Jenkins CI server", 3},
    {"travis",               "/",                           "Travis CI reference", 1},
    {".circleci",            "/",                           "CircleCI reference", 1},
    {"Dockerfile",           "/",                           "Dockerfile exposed", 2},
    {"docker-compose",       "/",                           "Docker Compose exposed", 2},

    // Config / Sensitive files
    {".env",                 "/.env",                       "Environment file exposed", 3},
    {"config.",              "/config/",                    "Config file reference", 2},
    {"database.",            "/database.php",               "Database config reference", 2},
    {"credentials",          "/credentials",                "Credentials file reference", 3},

    // Cloud
    {"s3.amazonaws.com",     "/",                           "AWS S3 bucket reference", 2},
    {"s3.us-east",           "/",                           "AWS S3 bucket (region)", 2},
    {"s3.",                  "/",                           "AWS S3 bucket reference", 2},
    {"storage.googleapis.com", "/",                         "GCP Storage reference", 2},
    {"blob.core.windows.net","/",                           "Azure Blob Storage reference", 2},

    // File upload
    {"upload",               "/upload",                     "File upload endpoint", 2},
    {"/file",                "/file",                       "File serving endpoint", 1},
    {"/download",            "/download",                   "Download endpoint", 1},
    {"/export",              "/export",                     "Export/data leak risk", 2},

    // Auth
    {"oauth",                "/oauth",                      "OAuth endpoint", 2},
    {"/callback",            "/callback",                   "OAuth callback", 2},
    {"/saml",                "/saml",                       "SAML SSO endpoint", 2},
    {"sso",                  "/sso",                        "SSO endpoint", 2},
    {"/token",               "/token",                      "Token endpoint", 2},
    {"/authorize",           "/authorize",                  "OAuth authorize endpoint", 2},

    // WebSockets
    {"ws://",                "/",                           "WebSocket (unencrypted)", 2},
    {"wss://",               "/",                           "WebSocket (encrypted)", 1},
    {"socket.io",            "/socket.io/",                 "Socket.IO endpoint", 1},

    // Server-Sent Events
    {"EventSource",          "/events",                     "Server-Sent Events endpoint", 1},

    // gRPC
    {"grpc",                 "/",                           "gRPC service reference", 1},
    {"grpc-web",             "/",                           "gRPC-Web service", 1},
    {"grpc.reflection",      "/",                           "gRPC reflection service", 2},
};

#define ENDPOINT_DB_SIZE (sizeof(endpoint_db) / sizeof(endpoint_db[0]))

EXPORT const char* scan_endpoints(const char* domain, const char* body) {
    if (domain == nullptr) domain = "";
    if (body == nullptr) body = "";

    std::string d(domain);
    std::string b(body);
    std::stringstream results;

    results << "Endpoint Forensics Report for: " << d << "\n";
    results << "========================================\n";

    int critical = 0, high = 0, medium = 0, info = 0;

    results << "\nDetected Endpoints & Technologies:\n";

    for (size_t i = 0; i < ENDPOINT_DB_SIZE; i++) {
        if (b.find(endpoint_db[i].pattern) != std::string::npos) {
            const char* sev;
            switch (endpoint_db[i].severity) {
                case 3: sev = "CRITICAL"; critical++; break;
                case 2: sev = "HIGH"; high++; break;
                case 1: sev = "MEDIUM"; medium++; break;
                default: sev = "INFO"; info++; break;
            }
            results << "  [" << sev << "] " << endpoint_db[i].path;
            if (endpoint_db[i].path[0] == '/') {
                results << " (" << endpoint_db[i].description << ")\n";
            } else {
                results << " - " << endpoint_db[i].description << "\n";
            }
        }
    }

    if (critical + high + medium + info == 0) {
        results << "  No endpoints or technologies detected.\n";
    }

    results << "\nRisk Assessment:\n";
    results << "  Critical:  " << critical << "\n";
    results << "  High:      " << high << "\n";
    results << "  Medium:    " << medium << "\n";
    results << "  Info:      " << info << "\n";

    if (critical > 0) {
        results << "  WARNING: Critical endpoints exposed (config, debug, credentials)\n";
    }
    if (high > 3) {
        results << "  NOTE: Multiple API/admin endpoints increase attack surface\n";
    }

    std::string s = results.str();
    char* cstr = new char[s.length() + 1];
    std::copy(s.begin(), s.end(), cstr);
    cstr[s.length()] = '\0';
    return cstr;
}

EXPORT void free_endpoint_string(char* s) {
    delete[] s;
}
