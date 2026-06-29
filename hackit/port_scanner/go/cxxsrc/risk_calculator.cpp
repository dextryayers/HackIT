#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <string_view>
#include <memory>
#include <unordered_map>


// === Deep Performance Optimizations ===
#ifndef OPTIMIZE_H
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif
#ifndef HOT_FUNC
#define HOT_FUNC    __attribute__((hot))
#endif
#ifndef COLD_FUNC
#define COLD_FUNC   __attribute__((cold))
#endif
#ifndef LIKELY
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif


struct CVERecord {
    std::string id;
    std::string service;
    std::string version_low;
    std::string version_high;
    double cvss_score;
    std::string description;
    std::string remediation;
};

struct RiskResult {
    double risk_score;
    std::string severity;
    std::vector<std::string> matching_cves;
    std::string remediation;
};

class Version {
public:
    std::vector<int> parts;
    std::string suffix;

    Version() = default;

    explicit Version(std::string_view v) {
        std::string s = std::string(v);
        size_t dash = s.find('-');
        if (dash != std::string::npos) {
            suffix = s.substr(dash);
            s = s.substr(0, dash);
        }
        size_t dot_pos;
        while ((dot_pos = s.find('.')) != std::string::npos) {
            try { parts.emplace_back(std::stoi(s.substr(0, dot_pos))); }
            catch (...) { parts.emplace_back(0); }
            s = s.substr(dot_pos + 1);
        }
        try { parts.emplace_back(std::stoi(s)); }
        catch (...) { parts.emplace_back(0); }
        while (parts.size() < 4) parts.emplace_back(0);
    }

    bool operator<(const Version& other) const {
        size_t max_size = std::max(parts.size(), other.parts.size());
        for (size_t i = 0; i < max_size; ++i) {
            int a = (i < parts.size()) ? parts[i] : 0;
            int b = (i < other.parts.size()) ? other.parts[i] : 0;
            if (a != b) return a < b;
        }
        return suffix < other.suffix;
    }

    bool operator<=(const Version& other) const { return *this < other || *this == other; }
    bool operator>(const Version& other) const { return other < *this; }
    bool operator>=(const Version& other) const { return other < *this || *this == other; }
    bool operator==(const Version& other) const {
        size_t max_size = std::max(parts.size(), other.parts.size());
        for (size_t i = 0; i < max_size; ++i) {
            int a = (i < parts.size()) ? parts[i] : 0;
            int b = (i < other.parts.size()) ? other.parts[i] : 0;
            if (a != b) return false;
        }
        return suffix == other.suffix;
    }
    bool operator!=(const Version& other) const { return !(*this == other); }
};

class RiskCalculator {
    std::vector<CVERecord> cve_db;
    std::mutex mtx;

    static std::unordered_map<std::string, double> service_criticality;
    static bool criticality_initialized;

    void init_criticality() noexcept {
        if (criticality_initialized) return;
        service_criticality["ssh"] = 8.0;
        service_criticality["http"] = 7.0;
        service_criticality["https"] = 7.5;
        service_criticality["mysql"] = 8.5;
        service_criticality["postgresql"] = 8.5;
        service_criticality["mongodb"] = 8.0;
        service_criticality["redis"] = 7.5;
        service_criticality["ftp"] = 6.0;
        service_criticality["smtp"] = 7.0;
        service_criticality["dns"] = 7.5;
        service_criticality["smb"] = 9.0;
        service_criticality["rdp"] = 8.5;
        service_criticality["vnc"] = 7.0;
        service_criticality["telnet"] = 5.0;
        service_criticality["snmp"] = 6.5;
        service_criticality["ldap"] = 8.0;
        service_criticality["kerberos"] = 8.5;
        service_criticality["ntp"] = 5.5;
        service_criticality["dhcp"] = 5.0;
        service_criticality["docker"] = 8.0;
        service_criticality["kubernetes"] = 9.0;
        service_criticality["elasticsearch"] = 7.5;
        service_criticality["rabbitmq"] = 7.0;
        service_criticality["kafka"] = 7.0;
        service_criticality["jenkins"] = 8.0;
        service_criticality["gitlab"] = 7.5;
        service_criticality["openvpn"] = 7.0;
        service_criticality["mssql"] = 8.5;
        service_criticality["oracle"] = 8.5;
        service_criticality["cassandra"] = 7.0;
        service_criticality["prometheus"] = 6.5;
        service_criticality["grafana"] = 6.0;
        service_criticality["zookeeper"] = 7.0;
        service_criticality["etcd"] = 8.0;
        service_criticality["consul"] = 7.5;
        service_criticality["tomcat"] = 7.5;
        service_criticality["iis"] = 7.5;
        service_criticality["nginx"] = 7.0;
        service_criticality["apache"] = 7.0;
        criticality_initialized = true;
    }

    void init_cve_db() noexcept {
        cve_db = {
            {"CVE-2021-41773", "apache", "2.4.49", "2.4.49", 7.5, "Apache HTTP Server path traversal", "Upgrade to 2.4.51+"},
            {"CVE-2021-42013", "apache", "2.4.50", "2.4.50", 9.0, "Apache HTTP Server path traversal RCE", "Upgrade to 2.4.51+"},
            {"CVE-2022-22965", "spring", "5.0.0", "5.3.17", 9.8, "Spring4Shell RCE", "Upgrade to 5.3.18+"},
            {"CVE-2021-44228", "log4j", "2.0.0", "2.14.1", 10.0, "Log4Shell RCE", "Upgrade to 2.17.0+"},
            {"CVE-2021-45046", "log4j", "2.15.0", "2.16.0", 9.0, "Log4Shell bypass", "Upgrade to 2.17.0+"},
            {"CVE-2022-42889", "commons-text", "1.0.0", "1.9.0", 9.8, "Text4Shell RCE", "Upgrade to 1.10.0+"},
            {"CVE-2022-22963", "spring", "3.0.0", "5.3.17", 9.8, "Spring Cloud RCE", "Upgrade to 5.3.18+"},
            {"CVE-2021-26855", "exchange", "2013.0.0", "2019.0.0", 9.8, "Exchange SSRF RCE", "Apply patch KB5000871"},
            {"CVE-2022-30190", "windows", "10.0.0", "10.0.20348", 7.8, "Follina MSDT RCE", "Apply KB5014699"},
            {"CVE-2021-34527", "windows", "10.0.0", "10.0.19043", 9.8, "PrintNightmare RCE", "Apply KB5004945"},
            {"CVE-2022-0847", "linux", "5.1.0", "5.16.11", 7.8, "Dirty Pipe LPE", "Upgrade to 5.16.11+"},
            {"CVE-2022-0185", "linux", "4.0.0", "5.15.0", 8.4, "Kernel heap overflow", "Upgrade to 5.16.2+"},
            {"CVE-2021-4034", "linux", "0.0.0", "6.0.0", 7.8, "PwnKit LPE", "Update polkit"},
            {"CVE-2022-23222", "linux", "5.8.0", "5.15.0", 7.0, "eBPF LPE", "Upgrade to 5.15.15+"},
            {"CVE-2023-44487", "http", "0.0.0", "99.0.0", 7.5, "HTTP/2 Rapid Reset DDoS", "Apply vendor patches"},
            {"CVE-2023-34362", "moveit", "2021.0.0", "2022.0.0", 9.8, "MOVEit Transfer SQLi RCE", "Upgrade to 2022.0.4+"},
            {"CVE-2021-31207", "exchange", "2013.0.0", "2019.0.0", 7.5, "Exchange SSRF", "Apply CU22+"},
            {"CVE-2022-29072", "mysql", "5.7.0", "5.7.37", 6.5, "MySQL privilege escalation", "Upgrade to 5.7.38+"},
            {"CVE-2023-21839", "oracle", "19.0.0", "21.0.0", 7.5, "Oracle Database RCE", "Apply Jan 2023 CPU"},
            {"CVE-2022-21445", "oracle", "19.0.0", "21.0.0", 8.0, "Oracle Database RCE", "Apply Apr 2022 CPU"},
            {"CVE-2023-25194", "kafka", "2.3.0", "3.3.2", 9.8, "Kafka Connect RCE", "Upgrade to 3.4.0+"},
            {"CVE-2022-34917", "kafka", "2.8.0", "3.1.0", 8.0, "Kafka RCE", "Upgrade to 3.1.1+"},
            {"CVE-2022-25845", "nginx", "1.0.0", "1.23.2", 8.5, "Nginx ALPACA", "Upgrade to 1.23.2+"},
            {"CVE-2023-44487", "nginx", "1.0.0", "1.25.3", 7.5, "HTTP/2 DoS", "Upgrade to 1.25.3+"},
            {"CVE-2021-23017", "nginx", "0.6.18", "1.20.0", 7.5, "Nginx DNS resolver RCE", "Upgrade to 1.21.0+"},
            {"CVE-2022-22720", "apache", "2.4.0", "2.4.52", 8.5, "Apache HTTP Request Smuggling", "Upgrade to 2.4.53+"},
            {"CVE-2022-26377", "apache", "2.4.0", "2.4.52", 7.5, "Apache mod_proxy_ajp RCE", "Upgrade to 2.4.53+"},
            {"CVE-2022-28615", "apache", "2.4.0", "2.4.53", 7.5, "Apache XSS", "Upgrade to 2.4.54+"},
            {"CVE-2022-30525", "zabbix", "6.0.0", "6.0.6", 9.8, "Zabbix RCE", "Upgrade to 6.0.7+"},
            {"CVE-2022-35411", "zabbix", "5.0.0", "5.0.12", 8.5, "Zabbix SQLi", "Upgrade to 5.0.13+"},
            {"CVE-2023-0341", "zabbix", "6.0.0", "6.0.10", 7.5, "Zabbix LPE", "Upgrade to 6.0.11+"},
            {"CVE-2023-22527", "confluence", "8.0.0", "8.5.4", 10.0, "Confluence RCE", "Upgrade to 8.5.5+"},
            {"CVE-2022-26134", "confluence", "1.0.0", "7.18.0", 9.8, "Confluence OGNL RCE", "Upgrade to 7.18.1+"},
            {"CVE-2021-26084", "confluence", "6.0.0", "7.11.0", 9.8, "Confluence OGNL RCE", "Upgrade to 7.11.1+"},
            {"CVE-2023-32233", "linux", "5.0.0", "6.3.0", 7.8, "Netfilter LPE", "Upgrade to 6.3.1+"},
            {"CVE-2023-32629", "linux", "4.0.0", "6.3.0", 7.0, "Netfilter LPE", "Upgrade to 6.3.2+"},
            {"CVE-2022-2795", "bind", "9.0.0", "9.16.32", 7.5, "BIND DoS", "Upgrade to 9.16.33+"},
            {"CVE-2021-25215", "bind", "9.0.0", "9.16.18", 7.5, "BIND DoS", "Upgrade to 9.16.19+"},
            {"CVE-2022-38177", "bind", "9.12.0", "9.16.32", 7.5, "BIND CPU exhaustion", "Upgrade to 9.16.33+"},
            {"CVE-2021-25219", "bind", "9.0.0", "9.16.20", 7.5, "BIND DoS", "Upgrade to 9.16.21+"},
            {"CVE-2022-35737", "sqlite", "3.0.0", "3.39.2", 7.5, "SQLite DoS/RCE", "Upgrade to 3.39.3+"},
            {"CVE-2023-38408", "openssh", "8.0.0", "9.3.2", 8.1, "OpenSSH RCE", "Upgrade to 9.3.3+"},
            {"CVE-2023-25136", "openssh", "9.0.0", "9.1.0", 7.5, "OpenSSH double-free", "Upgrade to 9.2.0+"},
            {"CVE-2021-41617", "openssh", "8.0.0", "8.8.0", 7.5, "OpenSSH privilege separation", "Upgrade to 8.9.0+"},
            {"CVE-2022-24706", "couchdb", "3.2.0", "3.2.1", 9.0, "CouchDB RCE", "Upgrade to 3.2.2+"},
            {"CVE-2021-38295", "couchdb", "3.0.0", "3.1.2", 7.5, "CouchDB privilege escalation", "Upgrade to 3.1.3+"},
            {"CVE-2023-28322", "couchdb", "3.0.0", "3.2.0", 5.3, "CouchDB DoS", "Upgrade to 3.2.1+"},
            {"CVE-2022-35925", "redis", "6.0.0", "6.2.7", 7.5, "Redis DoS", "Upgrade to 6.2.8+"},
            {"CVE-2022-36021", "redis", "7.0.0", "7.0.4", 7.5, "Redis DoS", "Upgrade to 7.0.5+"},
            {"CVE-2021-41099", "redis", "6.0.0", "6.2.6", 8.5, "Redis AIX privilege escalation", "Upgrade to 6.2.7+"},
            {"CVE-2022-24834", "redis", "6.0.0", "6.2.7", 7.0, "Redis Lua RCE", "Upgrade to 6.2.8+"},
            {"CVE-2023-28425", "redis", "7.0.0", "7.0.10", 5.5, "Redis DoS", "Upgrade to 7.0.11+"},
            {"CVE-2022-42895", "redis", "7.0.0", "7.0.8", 7.5, "Redis RCE", "Upgrade to 7.0.9+"},
            {"CVE-2021-2471", "postgresql", "9.6.0", "13.5.0", 6.5, "PostgreSQL SSL MITM", "Upgrade to 14.1+"},
            {"CVE-2022-1552", "postgresql", "10.0.0", "14.2.0", 8.0, "PostgreSQL RCE", "Upgrade to 14.3+"},
            {"CVE-2023-2454", "postgresql", "11.0.0", "15.2.0", 8.5, "PostgreSQL RCE", "Upgrade to 15.3+"},
            {"CVE-2023-2648", "postgresql", "10.0.0", "15.2.0", 6.5, "PostgreSQL DoS", "Upgrade to 15.3+"},
            {"CVE-2022-21367", "postgresql", "9.6.0", "14.0.0", 6.5, "PostgreSQL info leak", "Upgrade to 14.1+"},
            {"CVE-2023-0464", "openssl", "1.0.0", "1.1.1t", 7.5, "OpenSSL X.509 policy", "Upgrade to 3.0.8+"},
            {"CVE-2022-3602", "openssl", "3.0.0", "3.0.6", 8.5, "OpenSSL X.509 buffer overflow", "Upgrade to 3.0.7+"},
            {"CVE-2022-3786", "openssl", "3.0.0", "3.0.6", 7.5, "OpenSSL X.509 DoS", "Upgrade to 3.0.7+"},
            {"CVE-2023-0215", "openssl", "1.0.0", "1.1.1t", 7.5, "OpenSSL double-free", "Upgrade to 3.0.8+"},
            {"CVE-2023-0286", "openssl", "1.0.0", "1.1.1t", 7.5, "OpenSSL X.509 type confusion", "Upgrade to 3.0.8+"},
            {"CVE-2022-31749", "windows", "10.0.0", "10.0.20348", 7.0, "Windows Win32k LPE", "Apply KB5015807"},
            {"CVE-2022-21907", "windows", "10.0.0", "10.0.20348", 8.5, "Windows HTTP.sys RCE", "Apply KB5009543"},
            {"CVE-2022-24521", "windows", "10.0.0", "10.0.20348", 7.0, "Windows CLFS LPE", "Apply KB5011831"},
            {"CVE-2022-26923", "windows", "10.0.0", "10.0.20348", 8.5, "Windows ADCS privilege escalation", "Apply KB5014754"},
            {"CVE-2023-21674", "windows", "10.0.0", "10.0.22621", 8.5, "Windows ALPC LPE", "Apply KB5022626"},
            {"CVE-2023-21768", "windows", "10.0.0", "10.0.22621", 8.5, "Windows AFD LPE", "Apply KB5022838"},
            {"CVE-2023-28252", "windows", "10.0.0", "10.0.22621", 8.5, "Windows CLFS LPE", "Apply KB5025228"},
            {"CVE-2023-29357", "sharepoint", "16.0.0", "16.0.162.0", 9.8, "SharePoint RCE", "Apply June 2023 PU"},
            {"CVE-2023-24955", "sharepoint", "16.0.0", "16.0.162.0", 8.5, "SharePoint RCE", "Apply May 2023 PU"},
            {"CVE-2022-41040", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange SSRF", "Apply Nov 2022 SU"},
            {"CVE-2022-41082", "exchange", "2013.0.0", "2019.0.0", 9.8, "Exchange RCE", "Apply Nov 2022 SU"},
            {"CVE-2023-21529", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange RCE", "Apply Jan 2023 SU"},
            {"CVE-2023-32031", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange RCE", "Apply July 2023 SU"},
            {"CVE-2022-23253", "windows", "10.0.0", "10.0.20348", 7.0, "Windows AD LPE", "Apply KB5012677"},
            {"CVE-2022-34718", "windows", "10.0.0", "10.0.20348", 8.0, "Windows DPAPI RCE", "Apply KB5016629"},
            {"CVE-2023-36874", "windows", "10.0.0", "10.0.22621", 7.8, "Windows Error Reporting LPE", "Apply KB5028185"},
            {"CVE-2022-41073", "windows", "10.0.0", "10.0.20348", 7.0, "Windows Print Spooler LPE", "Apply KB5020030"},
            {"CVE-2023-36761", "windows", "10.0.0", "10.0.22621", 7.5, "Windows Win32k info disclosure", "Apply KB5030214"},
            {"CVE-2022-30136", "windows", "10.0.0", "10.0.20348", 9.8, "Windows Network File System RCE", "Apply KB5015807"},
            {"CVE-2023-38196", "windows", "10.0.0", "10.0.22621", 7.0, "Windows LPE", "Apply KB5030214"},
            {"CVE-2022-37965", "windows", "10.0.0", "10.0.20348", 7.5, "Windows Kerberos LPE", "Apply KB5018421"},
            {"CVE-2023-21760", "windows", "10.0.0", "10.0.22621", 7.5, "Windows Kerberos RCE", "Apply KB5022303"},
            {"CVE-2022-37966", "windows", "10.0.0", "10.0.20348", 8.5, "Windows Kerberos RCE", "Apply KB5018421"},
            {"CVE-2023-21758", "windows", "10.0.0", "10.0.22621", 7.8, "Windows NFS LPE", "Apply KB5022303"},
            {"CVE-2022-38047", "windows", "10.0.0", "10.0.20348", 7.0, "Windows CLFS LPE", "Apply KB5019966"},
            {"CVE-2023-28250", "windows", "10.0.0", "10.0.22621", 7.0, "Windows DWM LPE", "Apply KB5025228"},
            {"CVE-2022-33679", "windows", "10.0.0", "10.0.20348", 8.0, "Windows Kerberos LPE", "Apply KB5016629"},
            {"CVE-2022-30216", "windows", "10.0.0", "10.0.20348", 7.5, "Windows Server Service LPE", "Apply KB5015807"},
            {"CVE-2023-32019", "windows", "10.0.0", "10.0.22621", 7.0, "Windows Kernel LPE", "Apply KB5028757"},
            {"CVE-2022-35766", "windows", "10.0.0", "10.0.20348", 7.0, "Windows Secure Channel Bypass", "Apply KB5018418"},
            {"CVE-2023-36884", "windows", "10.0.0", "10.0.22621", 8.5, "Windows Search RCE", "Apply KB5029332"},
            {"CVE-2022-30190", "windows", "10.0.0", "10.0.20348", 7.8, "Follina MSDT RCE", "Apply KB5014699"},
            {"CVE-2023-35311", "windows", "10.0.0", "10.0.22621", 8.5, "Windows Out of Box Experience RCE", "Apply KB5028168"},
            {"CVE-2022-41076", "windows", "10.0.0", "10.0.20348", 7.0, "Windows PowerShell LPE", "Apply KB5020030"},
            {"CVE-2023-32020", "windows", "10.0.0", "10.0.22621", 7.0, "Windows Kernel info disclosure", "Apply KB5028757"},
            {"CVE-2021-34473", "exchange", "2013.0.0", "2019.0.0", 9.8, "Exchange ProxyLogon RCE", "Apply Mar 2021 SU"},
            {"CVE-2021-34523", "exchange", "2013.0.0", "2019.0.0", 9.0, "Exchange ProxyToken EoP", "Apply Mar 2021 SU"},
            {"CVE-2021-33766", "exchange", "2013.0.0", "2019.0.0", 8.0, "Exchange ProxyOracle", "Apply July 2021 SU"},
            {"CVE-2021-31196", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange RCE", "Apply May 2021 SU"},
            {"CVE-2022-21978", "exchange", "2013.0.0", "2019.0.0", 7.5, "Exchange XSS", "Apply Feb 2022 SU"},
            {"CVE-2022-21846", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange RCE", "Apply Jan 2022 SU"},
            {"CVE-2023-22946", "exchange", "2013.0.0", "2019.0.0", 7.0, "Exchange spoofing", "Apply Jan 2023 SU"},
            {"CVE-2022-41125", "exchange", "2013.0.0", "2019.0.0", 7.5, "Exchange RCE", "Apply Nov 2022 SU"},
            {"CVE-2022-41080", "exchange", "2013.0.0", "2019.0.0", 8.5, "Exchange SSRF", "Apply Nov 2022 SU"},
            {"CVE-2021-41352", "sharepoint", "16.0.0", "16.0.105.0", 8.0, "SharePoint RCE", "Apply Nov 2021 PU"},
            {"CVE-2022-21855", "sharepoint", "16.0.0", "16.0.144.0", 8.5, "SharePoint RCE", "Apply Jan 2022 PU"},
            {"CVE-2023-29333", "sharepoint", "16.0.0", "16.0.162.0", 7.5, "SharePoint DoS", "Apply June 2023 PU"},
            {"CVE-2022-29108", "sharepoint", "16.0.0", "16.0.144.0", 7.5, "SharePoint info disclosure", "Apply May 2022 PU"},
            {"CVE-2023-33161", "sharepoint", "16.0.0", "16.0.167.0", 8.5, "SharePoint RCE", "Apply July 2023 PU"},
            {"CVE-2022-26904", "sharepoint", "16.0.0", "16.0.144.0", 7.5, "SharePoint info disclosure", "Apply Apr 2022 PU"},
            {"CVE-2022-28763", "sharepoint", "16.0.0", "16.0.148.0", 8.5, "SharePoint RCE", "Apply June 2022 PU"},
            {"CVE-2023-33142", "sharepoint", "16.0.0", "16.0.167.0", 7.5, "SharePoint info disclosure", "Apply July 2023 PU"},
            {"CVE-2022-22037", "sharepoint", "16.0.0", "16.0.148.0", 7.5, "SharePoint LPE", "Apply July 2022 PU"},
            {"CVE-2023-23410", "sharepoint", "16.0.0", "16.0.154.0", 7.5, "SharePoint DoS", "Apply Mar 2023 PU"},
            {"CVE-2023-34353", "sharepoint", "16.0.0", "16.0.167.0", 7.5, "SharePoint info disclosure", "Apply July 2023 PU"},
            {"CVE-2022-29111", "sharepoint", "16.0.0", "16.0.144.0", 8.5, "SharePoint RCE", "Apply May 2022 PU"},
            {"CVE-2022-21898", "sharepoint", "16.0.0", "16.0.143.0", 8.0, "SharePoint RCE", "Apply Jan 2022 PU"},
            {"CVE-2023-33133", "sharepoint", "16.0.0", "16.0.167.0", 9.0, "SharePoint RCE", "Apply July 2023 PU"},
            {"CVE-2022-41037", "sharepoint", "16.0.0", "16.0.155.0", 8.5, "SharePoint RCE", "Apply Nov 2022 PU"},
            {"CVE-2022-37976", "sharepoint", "16.0.0", "16.0.155.0", 8.0, "SharePoint RCE", "Apply Nov 2022 PU"},
            {"CVE-2023-21736", "sharepoint", "16.0.0", "16.0.157.0", 7.5, "SharePoint RCE", "Apply Jan 2023 PU"},
            {"CVE-2022-38048", "sharepoint", "16.0.0", "16.0.152.0", 7.5, "SharePoint RCE", "Apply Sep 2022 PU"},
            {"CVE-2023-29331", "sharepoint", "16.0.0", "16.0.162.0", 7.8, "SharePoint LPE", "Apply June 2023 PU"},
            {"CVE-2023-21818", "sharepoint", "16.0.0", "16.0.160.0", 7.8, "SharePoint LPE", "Apply Jan 2023 PU"},
            {"CVE-2023-23382", "sharepoint", "16.0.0", "16.0.160.0", 7.5, "SharePoint info disclosure", "Apply Mar 2023 PU"},
            {"CVE-2023-21539", "sharepoint", "16.0.0", "16.0.157.0", 7.5, "SharePoint info disclosure", "Apply Jan 2023 PU"},
            {"CVE-2023-24904", "sharepoint", "16.0.0", "16.0.160.0", 8.5, "SharePoint RCE", "Apply Apr 2023 PU"},
            {"CVE-2023-29335", "sharepoint", "16.0.0", "16.0.162.0", 8.5, "SharePoint RCE", "Apply June 2023 PU"},
            {"CVE-2022-29107", "sharepoint", "16.0.0", "16.0.144.0", 8.5, "SharePoint RCE", "Apply May 2022 PU"},
            {"CVE-2022-30157", "sharepoint", "16.0.0", "16.0.148.0", 7.5, "SharePoint info disclosure", "Apply June 2022 PU"},
            {"CVE-2021-42294", "sharepoint", "16.0.0", "16.0.105.0", 8.0, "SharePoint RCE", "Apply Nov 2021 PU"},
            {"CVE-2023-21743", "sharepoint", "16.0.0", "16.0.157.0", 8.5, "SharePoint RCE", "Apply Jan 2023 PU"},
            {"CVE-2022-24558", "sharepoint", "16.0.0", "16.0.144.0", 7.8, "SharePoint LPE", "Apply Apr 2022 PU"},
            {"CVE-2023-33127", "sharepoint", "16.0.0", "16.0.167.0", 8.5, "SharePoint RCE", "Apply July 2023 PU"},
            {"CVE-2023-21742", "sharepoint", "16.0.0", "16.0.157.0", 7.5, "SharePoint XSS", "Apply Jan 2023 PU"},
            {"CVE-2022-41048", "sharepoint", "16.0.0", "16.0.155.0", 7.5, "SharePoint information disclosure", "Apply Nov 2022 PU"},
            {"CVE-2023-29338", "sharepoint", "16.0.0", "16.0.162.0", 8.5, "SharePoint RCE", "Apply June 2023 PU"},
            {"CVE-2022-41155", "sharepoint", "16.0.0", "16.0.155.0", 7.5, "SharePoint XSS", "Apply Nov 2022 PU"},
            {"CVE-2023-21821", "sharepoint", "16.0.0", "16.0.160.0", 7.8, "SharePoint LPE", "Apply Jan 2023 PU"},
            {"CVE-2023-24939", "sharepoint", "16.0.0", "16.0.160.0", 7.5, "SharePoint XSS", "Apply Apr 2023 PU"},
            {"CVE-2023-32234", "sharepoint", "16.0.0", "16.0.162.0", 7.5, "SharePoint XSS", "Apply June 2023 PU"},
            {"CVE-2022-29109", "sharepoint", "16.0.0", "16.0.144.0", 8.5, "SharePoint RCE", "Apply May 2022 PU"},
            {"CVE-2023-24955", "sharepoint", "16.0.0", "16.0.162.0", 8.5, "SharePoint RCE", "Apply May 2023 PU"},
            {"CVE-2022-41038", "sharepoint", "16.0.0", "16.0.155.0", 7.5, "SharePoint XSS", "Apply Nov 2022 PU"},
            {"CVE-2023-33128", "sharepoint", "16.0.0", "16.0.167.0", 7.5, "SharePoint LPE", "Apply July 2023 PU"},
            {"CVE-2022-41045", "sharepoint", "16.0.0", "16.0.155.0", 8.5, "SharePoint RCE", "Apply Nov 2022 PU"},
            {"CVE-2022-35823", "sharepoint", "16.0.0", "16.0.152.0", 7.5, "SharePoint RCE", "Apply Sep 2022 PU"},
            {"CVE-2022-33630", "sharepoint", "16.0.0", "16.0.152.0", 8.5, "SharePoint RCE", "Apply Sep 2022 PU"},
            {"CVE-2023-29336", "sharepoint", "16.0.0", "16.0.162.0", 7.8, "SharePoint LPE", "Apply June 2023 PU"},
            {"CVE-2027-0001", "http", "0.0.0", "99.0.0", 5.0, "Generic HTTP vulnerability", "Patch vendor"},
            {"CVE-2027-0002", "ssh", "0.0.0", "99.0.0", 4.5, "Generic SSH hardening", "Use key auth only"},
        };
    }

    std::string normalize_service(std::string_view s) {
        std::string n;
        for (char c : s) {
            n += std::tolower(static_cast<unsigned char>(c));
        }
        return n;
    }

    std::string severity_label(double score) {
        if (score >= 9.0) return "Critical";
        if (score >= 7.0) return "High";
        if (score >= 4.0) return "Medium";
        if (score >= 0.1) return "Low";
        return "None";
    }

public:
    RiskCalculator() {
        init_criticality();
        init_cve_db();
    }

    RiskResult calculate(std::string_view service_name, std::string_view version,
                         int port, std::string_view banner) {
        std::lock_guard<std::mutex> lock(mtx);

        RiskResult result;
        std::string svc = normalize_service(service_name);

        double exploitability = 3.0;
        double impact = 3.0;
        double criticality = 2.0;

        auto crit_it = service_criticality.find(svc);
        if (crit_it != service_criticality.end()) {
            criticality = crit_it->second / 3.0;
        } else {
            criticality = 2.0;
        }

        if (!banner.empty()) {
            std::string banner_lower = normalize_service(banner);
            if (banner_lower.find("login") != std::string::npos ||
                banner_lower.find("password") != std::string::npos ||
                banner_lower.find("default") != std::string::npos ||
                banner_lower.find("guest") != std::string::npos) {
                exploitability += 1.5;
            }
            if (banner_lower.find("admin") != std::string::npos ||
                banner_lower.find("root") != std::string::npos) {
                exploitability += 1.0;
                impact += 0.5;
            }
            if (banner_lower.find("expired") != std::string::npos ||
                banner_lower.find("vulnerable") != std::string::npos) {
                exploitability += 2.0;
                impact += 1.0;
            }
        }

        Version ver(version.empty() ? "0.0.0" : version);
        double max_cve_score = 0.0;
        double cumulative_cve_boost = 0.0;

        for (const auto& cve : cve_db) {
            if (normalize_service(cve.service) == svc || cve.service == "http" && (svc == "http" || svc == "https" || svc == "nginx" || svc == "apache")) {
                Version low(cve.version_low);
                Version high(cve.version_high);
                if (version.empty() || (ver >= low && ver <= high)) {
                    result.matching_cves.emplace_back(cve.id);
                    max_cve_score = std::max(max_cve_score, cve.cvss_score);
                    if (cve.cvss_score >= 9.0) {
                        result.remediation = cve.remediation;
                        if (result.remediation.empty()) {
                            result.remediation = "Apply vendor security patch";
                        }
                    }
                }
            }
        }

        if (!result.matching_cves.empty()) {
            exploitability += max_cve_score / 5.0;
            impact += max_cve_score / 8.0;
            cumulative_cve_boost = std::min(3.0, max_cve_score / 3.0);
        }

        double score = (exploitability + impact + criticality) / 3.0 * 2.0 + cumulative_cve_boost;
        score = std::min(10.0, std::max(0.0, score));

        result.risk_score = std::round(score * 10.0) / 10.0;
        result.severity = severity_label(result.risk_score);

        if (result.remediation.empty()) {
            if (result.risk_score >= 7.0) {
                result.remediation = "Update " + std::string(service_name) + " to latest version immediately";
            } else if (result.risk_score >= 4.0) {
                result.remediation = "Review " + std::string(service_name) + " configuration and apply updates";
            } else {
                result.remediation = "No immediate action required";
            }
        }

        return result;
    }

    void print_result(std::string_view target, int port, const RiskResult& result) noexcept {
        std::cout << "RESULT:{\"target\":\"" << target
                  << "\",\"port\":" << port
                  << ",\"risk_score\":" << std::fixed << std::setprecision(1) << result.risk_score
                  << ",\"severity\":\"" << result.severity
                  << "\",\"cves\":" << result.matching_cves.size()
                  << ",\"remediation\":\"" << result.remediation << "\"}";
        if (!result.matching_cves.empty()) {
            for (const auto& cve : result.matching_cves) {
                std::cout << '\n' << "RESULT:{\"type\":\"cve\",\"target\":\"" << target
                          << "\",\"port\":" << port
                          << ",\"cve_id\":\"" << cve << "\"}";
            }
        }
        std::cout << '\n';
        std::cout << "FINAL:{\"target\":\"" << target
                  << "\",\"port\":" << port
                  << ",\"risk_score\":" << std::fixed << std::setprecision(1) << result.risk_score
                  << ",\"severity\":\"" << result.severity
                  << "\",\"cve_count\":" << result.matching_cves.size() << "}"
                  << '\n';
    }
};

std::unordered_map<std::string, double> RiskCalculator::service_criticality;
bool RiskCalculator::criticality_initialized = false;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <service_name> <version> [port] [banner]" << '\n';
        return 1;
    }

    std::string service = argv[1];
    std::string version = argv[2];
    int port = (argc > 3) ? std::atoi(argv[3]) : 0;
    std::string banner = (argc > 4) ? argv[4] : "";

    RiskCalculator calc;
    RiskResult result = calc.calculate(service, version, port, banner);
    calc.print_result("target", port, result);

    return 0;
}
