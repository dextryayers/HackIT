#include <string>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C"
#endif

struct service_entry {
    int port;
    const char* banner_pattern;
    const char* service_name;
    const char* category;
    int confidence;
    const char* default_version;
};

static const service_entry service_db[] = {
    // Web servers
    {80,   "nginx",          "Nginx",              "Web Server", 95, "detected via version string"},
    {443,  "nginx",          "Nginx (HTTPS)",       "Web Server", 95, ""},
    {8080, "nginx",          "Nginx (Alt Port)",    "Web Server", 90, ""},
    {80,   "Apache",         "Apache HTTPD",        "Web Server", 95, ""},
    {443,  "Apache",         "Apache HTTPD (HTTPS)","Web Server", 95, ""},
    {80,   "Microsoft-IIS",  "Microsoft IIS",       "Web Server", 95, ""},
    {443,  "Microsoft-IIS",  "Microsoft IIS (HTTPS)","Web Server", 95, ""},
    {80,   "Cloudflare",     "Cloudflare Edge",     "CDN/WAF",    90, ""},
    {443,  "Cloudflare",     "Cloudflare Edge (SSL)","CDN/WAF",   90, ""},
    {80,   "Caddy",          "Caddy",               "Web Server", 85, ""},
    {80,   "lighttpd",       "Lighttpd",            "Web Server", 90, ""},
    {80,   "OpenResty",      "OpenResty (Nginx+Lua)","Web Server", 85, ""},
    {80,   "Tengine",        "Tengine (Alibaba)",   "Web Server", 85, ""},

    // SSH
    {22,   "OpenSSH",        "OpenSSH",             "Remote Access", 95, ""},
    {22,   "Dropbear",       "Dropbear SSH",        "Remote Access", 90, ""},
    {22,   "libssh",         "libssh",              "Remote Access", 85, ""},

    // FTP
    {21,   "vsftpd",         "vsftpd",              "FTP Server",  90, ""},
    {21,   "ProFTPD",        "ProFTPD",             "FTP Server",  90, ""},
    {21,   "pure-ftpd",      "Pure-FTPd",           "FTP Server",  90, ""},
    {21,   "FileZilla",      "FileZilla Server",    "FTP Server",  85, ""},

    // Databases
    {3306, "MySQL",          "MySQL",               "Database",    90, "8.0.x (inferred)"},
    {3306, "MariaDB",        "MariaDB",             "Database",    90, "10.x (inferred)"},
    {5432, "PostgreSQL",     "PostgreSQL",          "Database",    90, "15.x (inferred)"},
    {5432, "Postgres",       "PostgreSQL",          "Database",    85, ""},
    {1521, "Oracle",         "Oracle Database",     "Database",    85, ""},
    {1521, "XE",             "Oracle XE",           "Database",    80, ""},
    {1433, "MSSQL",          "Microsoft SQL Server","Database",    90, ""},
    {1433, "SQL Server",     "Microsoft SQL Server","Database",    90, ""},
    {6379, "Redis",          "Redis",               "Cache/NoSQL", 90, ""},
    {27017,"MongoDB",        "MongoDB",             "Database",    90, "6.x (inferred)"},
    {27017,"mongodb",        "MongoDB",             "Database",    90, ""},
    {9042, "Cassandra",      "Apache Cassandra",    "Database",    80, ""},

    // Message queues
    {5672, "RabbitMQ",       "RabbitMQ",            "Message Queue", 85, ""},
    {5672, "AMQP",           "AMQP (Generic)",      "Message Queue", 80, ""},
    {9092, "kafka",          "Apache Kafka",        "Message Queue", 80, ""},

    // Search
    {9200, "elasticsearch",  "Elasticsearch",       "Search Engine", 90, ""},
    {9200, "Elasticsearch",  "Elasticsearch",       "Search Engine", 90, ""},

    // Monitoring
    {3000, "Grafana",        "Grafana",             "Monitoring",   85, ""},
    {9090, "prometheus",     "Prometheus",          "Monitoring",   85, ""},
    {9090, "Prometheus",     "Prometheus",          "Monitoring",   85, ""},

    // VPN / Auth
    {1194, "OpenVPN",        "OpenVPN",             "VPN",          80, ""},
    {1812, "radius",         "FreeRADIUS",          "Authentication", 80, ""},

    // Container / Orchestration
    {2375, "Docker",         "Docker API (unencrypted)", "Container", 90, ""},
    {2376, "Docker",         "Docker API (TLS)",    "Container",    90, ""},
    {6443, "kubernetes",     "Kubernetes API",      "Orchestration",90, ""},
    {10250,"kubelet",        "Kubernetes Kubelet",  "Orchestration",90, ""},
};

#define DB_SIZE (sizeof(service_db) / sizeof(service_db[0]))

static std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

static int fuzzy_match(const std::string& banner, const std::string& pattern) {
    std::string b_lower = to_lower(banner);
    std::string p_lower = to_lower(pattern);
    return b_lower.find(p_lower) != std::string::npos;
}

static void extract_version(const std::string& banner, std::string& version) {
    // Try to extract version string like "X.Y.Z" or "X.Y"
    size_t pos = banner.find("/");
    if (pos == std::string::npos) pos = banner.find(" ");
    if (pos != std::string::npos && pos + 1 < banner.length()) {
        std::string rest = banner.substr(pos + 1);
        // Find first digit
        size_t dpos = rest.find_first_of("0123456789");
        if (dpos != std::string::npos) {
            size_t end = rest.find_first_not_of("0123456789.-_+", dpos);
            if (end == std::string::npos) end = rest.length();
            version = rest.substr(dpos, end - dpos);
        }
    }
}

EXPORT const char* identify_service(int port, const char* banner) {
    if (banner == nullptr) banner = "";

    std::string b_str(banner);
    std::string version;
    extract_version(b_str, version);

    int best_match = -1;
    int best_conf = 0;
    std::string best_version;

    for (size_t i = 0; i < DB_SIZE; i++) {
        if (service_db[i].port == port && fuzzy_match(b_str, service_db[i].banner_pattern)) {
            int conf = service_db[i].confidence;
            // Bonus for version info
            if (!version.empty()) conf += 5;
            if (conf > best_conf) {
                best_conf = conf;
                best_match = i;
                best_version = version;
            }
        }
    }

    // Port-based fallback
    if (best_match == -1) {
        std::string service = "Unknown";
        std::string category = "Generic";

        // Fallback by common port
        switch (port) {
            case 21: service = "FTP Server"; category = "File Transfer"; break;
            case 22: service = "SSH Server"; category = "Remote Access"; break;
            case 23: service = "Telnet"; category = "Remote Access"; break;
            case 25: service = "SMTP (Email)"; category = "Mail"; break;
            case 53: service = "DNS Server"; category = "DNS"; break;
            case 80: service = "HTTP Web Server"; category = "Web"; break;
            case 110: service = "POP3 (Email)"; category = "Mail"; break;
            case 111: service = "RPC Portmapper"; category = "RPC"; break;
            case 123: service = "NTP"; category = "Time"; break;
            case 135: service = "MSRPC"; category = "Windows"; break;
            case 139: service = "NetBIOS"; category = "Windows"; break;
            case 143: service = "IMAP (Email)"; category = "Mail"; break;
            case 161: service = "SNMP"; category = "Monitoring"; break;
            case 389: service = "LDAP"; category = "Directory"; break;
            case 443: service = "HTTPS"; category = "Web"; break;
            case 445: service = "SMB/CIFS"; category = "Windows"; break;
            case 465: service = "SMTPS"; category = "Mail"; break;
            case 514: service = "Syslog"; category = "Logging"; break;
            case 587: service = "SMTP Submission"; category = "Mail"; break;
            case 636: service = "LDAPS"; category = "Directory"; break;
            case 993: service = "IMAPS"; category = "Mail"; break;
            case 995: service = "POP3S"; category = "Mail"; break;
            case 1433: service = "MSSQL"; category = "Database"; break;
            case 1521: service = "Oracle DB"; category = "Database"; break;
            case 2049: service = "NFS"; category = "File System"; break;
            case 2375: service = "Docker API"; category = "Container"; break;
            case 2376: service = "Docker API (TLS)"; category = "Container"; break;
            case 3306: service = "MySQL/MariaDB"; category = "Database"; break;
            case 3389: service = "RDP"; category = "Remote Access"; break;
            case 5432: service = "PostgreSQL"; category = "Database"; break;
            case 5900: service = "VNC"; category = "Remote Access"; break;
            case 5901: service = "VNC (Display :1)"; category = "Remote Access"; break;
            case 6379: service = "Redis"; category = "Cache"; break;
            case 6443: service = "Kubernetes API"; category = "Orchestration"; break;
            case 8080: service = "HTTP Proxy/Alt"; category = "Web"; break;
            case 8443: service = "HTTPS Alt"; category = "Web"; break;
            case 9090: service = "Prometheus/Grafana"; category = "Monitoring"; break;
            case 9200: service = "Elasticsearch"; category = "Search"; break;
            case 9300: service = "Elasticsearch Transport"; category = "Search"; break;
            case 9418: service = "Git"; category = "Version Control"; break;
            case 11211: service = "Memcached"; category = "Cache"; break;
            case 27017: service = "MongoDB"; category = "Database"; break;
            default: service = "Generic Service"; category = "Unknown"; break;
        }

        std::string result = service + " [" + category + "] (port " + std::to_string(port) + ") [confidence: low, no banner match]";
        if (!version.empty()) result += " | version: " + version;

        char* cstr = new char[result.length() + 1];
        std::strcpy(cstr, result.c_str());
        return cstr;
    }

    const service_entry& e = service_db[best_match];
    std::string result = e.service_name;
    result += " [" + std::string(e.category) + "] (port " + std::to_string(port) + ") [confidence: " + std::to_string(best_conf) + "%]";

    if (!best_version.empty()) {
        result += " | version: " + best_version;
    } else if (strlen(e.default_version) > 0) {
        result += " | " + std::string(e.default_version);
    }

    if (b_str.length() > 0) {
        result += " | raw_banner: \"" + b_str + "\"";
    }

    char* cstr = new char[result.length() + 1];
    std::strcpy(cstr, result.c_str());
    return cstr;
}

EXPORT void free_service_string(char* s) {
    delete[] s;
}
