#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
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


struct Pattern {
    std::string name;
    std::string regex_str;
    std::regex compiled;
    double weight;
    std::string category;
};

struct MatchResult {
    std::string pattern_name;
    std::string category;
    double score;
    double confidence;
    std::string matched_text;
};

struct OSFingerprint {
    std::string os_name;
    double ttl_weight;
    double window_weight;
    double tcpopt_weight;
    double banner_weight;
};

class PatternAnalyzer {
    static std::unordered_map<std::string, std::regex> regex_cache;
    std::vector<Pattern> patterns;
    std::vector<OSFingerprint> os_signatures;
    std::mutex mtx;

    std::regex compile_regex(std::string_view pattern) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = regex_cache.find(std::string(pattern));
        if (it != regex_cache.end()) return it->second;
        std::regex re(std::string(pattern), std::regex::icase | std::regex::optimize);
        regex_cache[std::string(pattern)] = re;
        return re;
    }

    void init_patterns() noexcept {
        patterns = {
            {"HTTP", "HTTP/\\d\\.\\d|Server:\\s*[A-Za-z]", std::regex(), 0.95, "web"},
            {"HTTPS", "HTTP/\\d\\.\\d.*TLS|SSL", std::regex(), 0.90, "web"},
            {"SSH", "SSH-\\d\\.\\d-", std::regex(), 0.98, "remote"},
            {"FTP", "220.*FTP|530.*Login|FTP server", std::regex(), 0.95, "file"},
            {"SMTP", "220.*SMTP|250.*STARTTLS|ESMTP", std::regex(), 0.95, "mail"},
            {"POP3", "\\+OK.*POP3|-ERR.*POP|USER.*POP", std::regex(), 0.93, "mail"},
            {"IMAP", "\\* OK.*IMAP|CAPABILITY.*IMAP", std::regex(), 0.93, "mail"},
            {"MySQL", "mysql|MariaDB|5\\.\\d\\.\\d", std::regex(), 0.96, "database"},
            {"PostgreSQL", "PostgreSQL|psql|PG::", std::regex(), 0.96, "database"},
            {"MongoDB", "MongoDB|mongos", std::regex(), 0.94, "database"},
            {"Redis", "\\+OK|\\-ERR.*redis|REDIS", std::regex(), 0.95, "cache"},
            {"Memcached", "STAT|VALUE.*memcache|END\\r\\n", std::regex(), 0.90, "cache"},
            {"OpenVPN", "OpenVPN|VPN server", std::regex(), 0.92, "vpn"},
            {"DNS", "DNS|BIND|dnsmasq", std::regex(), 0.93, "network"},
            {"DHCP", "DHCP|dhcpd", std::regex(), 0.88, "network"},
            {"NTP", "NTP|ntpd|ntp\\.", std::regex(), 0.91, "network"},
            {"SNMP", "SNMP|snmpd|public|private", std::regex(), 0.92, "network"},
            {"LDAP", "LDAP|ldap|OpenLDAP", std::regex(), 0.90, "auth"},
            {"Kerberos", "KRB|Kerberos|ASN\\.1", std::regex(), 0.89, "auth"},
            {"RDP", "RDP|Terminal Services|Microsoft Terminal", std::regex(), 0.95, "remote"},
            {"VNC", "RFB|VNC|RealVNC|TightVNC", std::regex(), 0.94, "remote"},
            {"X11", "X\\d{4}|X11|X.Org", std::regex(), 0.87, "remote"},
            {"SMB", "SMB|CIFS|Microsoft.*Network|smbd", std::regex(), 0.95, "file"},
            {"NFS", "NFS|nfsd|Network File System", std::regex(), 0.91, "file"},
            {"Telnet", "Telnet|telnetd|TTY|vt\\d{3}", std::regex(), 0.94, "remote"},
            {"RPC", "RPC|portmap|rpcbind|sunrpc", std::regex(), 0.89, "network"},
            {"SIP", "SIP/\\d\\.\\d|sipd|Asterisk|FreeSWITCH", std::regex(), 0.93, "voip"},
            {"RTP", "RTP|rtp|SRTP", std::regex(), 0.85, "voip"},
            {"IRC", "IRC|ircd|NickServ|ChanServ", std::regex(), 0.92, "chat"},
            {"XMPP", "XMPP|Jabber|jabberd|ejabberd", std::regex(), 0.91, "chat"},
            {"Bitcoin", "Bitcoin|bitcoind|BTC|Satoshi", std::regex(), 0.93, "crypto"},
            {"Ethereum", "Ethereum|geth|Ether|ETH", std::regex(), 0.92, "crypto"},
            {"Elasticsearch", "Elasticsearch|elastic|ES", std::regex(), 0.94, "database"},
            {"Cassandra", "Cassandra|cqlsh|CQL", std::regex(), 0.90, "database"},
            {"RabbitMQ", "RabbitMQ|AMQP|amqp", std::regex(), 0.93, "queue"},
            {"Kafka", "Kafka|kafka|Apache Kafka", std::regex(), 0.91, "queue"},
            {"Jenkins", "Jenkins|jenkins|Hudson", std::regex(), 0.92, "ci"},
            {"GitLab", "GitLab|gitlab", std::regex(), 0.90, "ci"},
            {"Docker", "Docker|docker|container", std::regex(), 0.93, "container"},
            {"Kubernetes", "Kubernetes|k8s|minikube|etcd", std::regex(), 0.92, "container"},
            {"Nginx", "nginx|Nginx/\\d", std::regex(), 0.97, "web"},
            {"Apache", "Apache/\\d|Apache.*Server", std::regex(), 0.97, "web"},
            {"IIS", "Microsoft-IIS|IIS/\\d", std::regex(), 0.96, "web"},
            {"Tomcat", "Apache.*Tomcat|Tomcat|Catalina", std::regex(), 0.94, "web"},
            {"Jetty", "Jetty|jetty", std::regex(), 0.90, "web"},
            {"Node.js", "Node\\.js|nodejs|Express", std::regex(), 0.93, "web"},
            {"Python", "Python|WSGIServer|gunicorn|uWSGI", std::regex(), 0.92, "web"},
            {"PHP", "PHP|PHP/\\d|Zend Engine", std::regex(), 0.94, "web"},
            {"Ruby", "Ruby|Ruby on Rails|WEBrick|Passenger", std::regex(), 0.92, "web"},
            {"Java", "Java|Tomcat|Jetty|JSP|Servlet", std::regex(), 0.91, "web"},
            {"Go", "Go-http|golang|net/http", std::regex(), 0.88, "web"},
            {"CouchDB", "CouchDB|couchdb|Couchbase", std::regex(), 0.90, "database"},
            {"Neo4j", "Neo4j|neo4j|cypher", std::regex(), 0.86, "database"},
            {"SQLite", "SQLite|sqlite", std::regex(), 0.88, "database"},
            {"Oracle", "Oracle|ORACLE|TNS", std::regex(), 0.94, "database"},
            {"MSSQL", "MSSQL|Microsoft SQL|MS SQL|TDS", std::regex(), 0.94, "database"},
            {"DB2", "DB2|IBM DB2|db2", std::regex(), 0.88, "database"},
            {"Squid", "Squid|squid", std::regex(), 0.91, "proxy"},
            {"HAProxy", "HAProxy|haproxy", std::regex(), 0.89, "proxy"},
            {"Varnish", "Varnish|varnish", std::regex(), 0.88, "proxy"},
            {"Lighttpd", "lighttpd|lighttpd/\\d", std::regex(), 0.90, "web"},
            {"Caddy", "Caddy|caddy", std::regex(), 0.86, "web"},
            {"Zookeeper", "ZooKeeper|zookeeper", std::regex(), 0.88, "queue"},
            {"Consul", "Consul|consul", std::regex(), 0.89, "network"},
            {"Etcd", "etcd|etcdserver", std::regex(), 0.90, "database"},
            {"Prometheus", "Prometheus|prometheus", std::regex(), 0.91, "monitoring"},
            {"Grafana", "Grafana|grafana", std::regex(), 0.89, "monitoring"},
            {"Nagios", "Nagios|nagios|NRPE", std::regex(), 0.90, "monitoring"},
            {"Zabbix", "Zabbix|zabbix", std::regex(), 0.90, "monitoring"},
            {"Postfix", "Postfix|postfix|QMQP", std::regex(), 0.92, "mail"},
            {"Sendmail", "Sendmail|sendmail", std::regex(), 0.90, "mail"},
            {"Exim", "Exim|exim", std::regex(), 0.91, "mail"},
            {"Dovecot", "Dovecot|dovecot", std::regex(), 0.92, "mail"},
            {"OpenSSH", "OpenSSH|openssh", std::regex(), 0.97, "remote"},
            {"Dropbear", "Dropbear|dropbear", std::regex(), 0.92, "remote"},
            {"OpenLDAP", "OpenLDAP|openldap|slapd", std::regex(), 0.91, "auth"},
            {"FreeRADIUS", "FreeRADIUS|freeradius|RADIUS", std::regex(), 0.91, "auth"},
            {"OpenVPN", "OpenVPN|openvpn", std::regex(), 0.93, "vpn"},
            {"StrongSwan", "strongSwan|strongswan|IPSec", std::regex(), 0.90, "vpn"},
            {"Mosquitto", "Mosquitto|mosquitto|MQTT", std::regex(), 0.89, "iot"},
            {"CoAP", "CoAP|coap", std::regex(), 0.82, "iot"},
            {"Modbus", "Modbus|modbus", std::regex(), 0.88, "iot"},
            {"BACnet", "BACnet|bacnet", std::regex(), 0.85, "iot"},
            {"S7", "S7|s7comm|Siemens", std::regex(), 0.87, "iot"},
            {"DNP3", "DNP3|dnp3", std::regex(), 0.86, "iot"},
            {"MQTT", "MQTT|mqtt|Mosquitto", std::regex(), 0.91, "iot"},
        };
        for (auto& p : patterns) {
            p.compiled = compile_regex(p.regex_str);
        }
    }

    void init_os_signatures() noexcept {
        os_signatures = {
            {"Linux (generic)", 0.80, 0.70, 0.75, 0.60},
            {"Windows 10/11", 0.30, 0.90, 0.80, 0.85},
            {"Windows 7/8", 0.30, 0.85, 0.75, 0.80},
            {"macOS", 0.40, 0.75, 0.85, 0.70},
            {"FreeBSD", 0.55, 0.65, 0.80, 0.55},
            {"OpenBSD", 0.60, 0.60, 0.70, 0.50},
            {"Solaris", 0.70, 0.50, 0.60, 0.45},
            {"Cisco IOS", 0.75, 0.45, 0.55, 0.65},
            {"Android", 0.50, 0.80, 0.65, 0.55},
            {"iOS", 0.40, 0.85, 0.70, 0.60},
        };
    }

    double compute_ttl_score(int ttl) noexcept {
        if (ttl <= 32) return 0.95;
        if (ttl <= 64) return 0.80;
        if (ttl <= 128) return 0.60;
        return 0.30;
    }

    double compute_window_score(int window) noexcept {
        if (window == 65535 || window == 65520) return 0.90;
        if (window == 8192 || window == 16384) return 0.75;
        if (window == 29200 || window == 5840) return 0.70;
        if (window <= 2048) return 0.50;
        return 0.40;
    }

public:
    PatternAnalyzer() {
        init_patterns();
        init_os_signatures();
    }

    std::vector<MatchResult> analyze_banner(std::string_view banner, std::string_view target, int port) {
        std::vector<MatchResult> results;
        if (banner.empty()) return results;

        std::lock_guard<std::mutex> lock(mtx);

        double total_score = 0.0;
        for (const auto& pattern : patterns) {
            try {
                std::string b(banner);
                std::smatch match;
                if (std::regex_search(b, match, pattern.compiled)) {
                    double confidence = std::min(1.0, pattern.weight * (1.0 + match.length() / 100.0));
                    double score = pattern.weight * confidence;
                    total_score += score;
                    results.push_back({
                        pattern.name,
                        pattern.category,
                        score,
                        confidence,
                        match.str()
                    });
                }
            } catch (const std::regex_error&) {
                continue;
            }
        }

        std::sort(results.begin(), results.end(),
            [](const MatchResult& a, const MatchResult& b) {
                return a.score > b.score;
            });

        if (!results.empty()) {
            double max_score = results[0].score;
            for (auto& r : results) {
                r.confidence = std::min(1.0, r.confidence * (r.score / max_score));
            }
        }

        return results;
    }

    std::pair<std::string, double> detect_os(int ttl, int window, std::string_view tcp_options, std::string_view banner) {
        double best_score = 0.0;
        std::string best_os = "Unknown";

        double ttl_score = compute_ttl_score(ttl);
        double window_score = compute_window_score(window);

        for (const auto& sig : os_signatures) {
            double score = 0.0;
            score += (1.0 - std::abs(ttl_score - sig.ttl_weight)) * 0.35;
            score += (1.0 - std::abs(window_score - sig.window_weight)) * 0.25;
            score += sig.tcpopt_weight * 0.20;
            if (!banner.empty()) {
                for (const auto& word : {"Linux", "Windows", "Ubuntu", "Debian", "FreeBSD", "Darwin", "Unix"}) {
                    if (banner.find(word) != std::string::npos) {
                        if (sig.os_name.find(word) != std::string::npos ||
                            (std::string(word) == "Linux" && sig.os_name.find("Linux") != std::string::npos)) {
                            score += sig.banner_weight * 0.20;
                        }
                    }
                }
            }
            if (score > best_score) {
                best_score = score;
                best_os = sig.os_name;
            }
        }

        return {best_os, best_score};
    }

    void print_results(std::string_view target, int port, const std::vector<MatchResult>& matches,
                       std::string_view os, double os_conf) {
        for (const auto& m : matches) {
            std::cout << "RESULT:{\"target\":\"" << target << "\",\"port\":" << port
                      << ",\"pattern\":\"" << m.pattern_name
                      << "\",\"category\":\"" << m.category
                      << "\",\"score\":" << std::fixed << std::setprecision(3) << m.score
                      << ",\"confidence\":" << std::setprecision(3) << m.confidence
                      << ",\"matched\":\"" << m.matched_text << "\"}"
                      << '\n';
        }
        std::cout << "RESULT:{\"target\":\"" << target << "\",\"port\":" << port
                  << ",\"os\":\"" << os
                  << "\",\"os_confidence\":" << std::fixed << std::setprecision(3) << os_conf
                  << ",\"type\":\"os_detection\"}" << '\n';
        std::cout << "FINAL:{\"target\":\"" << target << "\",\"port\":" << port
                  << ",\"matches\":" << matches.size()
                  << ",\"os\":\"" << os << "\"}" << '\n';
    }
};

std::unordered_map<std::string, std::regex> PatternAnalyzer::regex_cache;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target:port> [banner] [ttl] [window] [tcp_options]" << '\n';
        return 1;
    }

    std::string input = argv[1];
    std::string target;
    int port = 0;
    size_t colon = input.find(':');
    if (colon != std::string::npos) {
        target = input.substr(0, colon);
        try {
            port = std::stoi(input.substr(colon + 1));
        } catch (...) {
            std::cerr << "Invalid port" << '\n';
            return 1;
        }
    } else {
        target = input;
    }

    std::string banner = (argc > 2) ? argv[2] : "";
    int ttl = (argc > 3) ? std::atoi(argv[3]) : 64;
    int window = (argc > 4) ? std::atoi(argv[4]) : 65535;
    std::string tcp_options = (argc > 5) ? argv[5] : "";

    PatternAnalyzer analyzer;
    auto matches = analyzer.analyze_banner(banner, target, port);
    auto [os, os_conf] = analyzer.detect_os(ttl, window, tcp_options, banner);
    analyzer.print_results(target, port, matches, os, os_conf);

    return 0;
}
