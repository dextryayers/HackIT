#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <regex>
#include <mutex>
#include <cmath>
#include <cctype>
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


struct ServiceSignature {
    std::string service_name;
    std::string category;
    std::unordered_map<std::string, double> keyword_weights;
    double prior_probability;
    std::vector<std::string> required_patterns;
    std::vector<std::string> negative_patterns;
};

struct Prediction {
    std::string service_name;
    std::string category;
    double score;
    double confidence;
};

class ServiceClassifier {
    std::vector<ServiceSignature> signatures;
    std::mutex mtx;

    void init_signatures() noexcept {
        signatures = {
            {"HTTP", "web", {{"http", 0.95}, {"server", 0.80}, {"get", 0.70}, {"post", 0.70},
             {"html", 0.65}, {"content-type", 0.75}, {"host", 0.60}, {"user-agent", 0.55},
             {"response", 0.50}, {"status", 0.50}, {"cookie", 0.60}, {"set-cookie", 0.55},
             {"location", 0.50}, {"cache", 0.40}, {"accept", 0.50}}, 0.15, {"HTTP/"}, {}},
            {"HTTPS", "web", {{"https", 0.90}, {"ssl", 0.80}, {"tls", 0.75}, {"certificate", 0.70},
             {"encrypted", 0.60}, {"secure", 0.55}, {"tlsv1", 0.65}, {"openssl", 0.60},
             {"cipher", 0.55}, {"handshake", 0.50}}, 0.08, {"HTTP/", "SSL"}, {}},
            {"SSH", "remote", {{"ssh", 0.98}, {"openssh", 0.90}, {"ssh-2.0", 0.95},
             {"key exchange", 0.80}, {"diffie-hellman", 0.70}, {"hmac", 0.60},
             {"aes", 0.50}, {"password", 0.45}, {"authentication", 0.55}}, 0.10, {"SSH-"}, {}},
            {"FTP", "file", {{"ftp", 0.95}, {"filezilla", 0.70}, {"vsftpd", 0.85},
             {"proftpd", 0.80}, {"pure-ftpd", 0.75}, {"220", 0.60}, {"530", 0.50},
             {"login", 0.45}, {"anonymous", 0.50}, {"password", 0.40}}, 0.06, {"220"}, {}},
            {"SMTP", "mail", {{"smtp", 0.95}, {"esmtp", 0.85}, {"postfix", 0.75},
             {"sendmail", 0.70}, {"exim", 0.70}, {"250", 0.60}, {"220", 0.55},
             {"starttls", 0.60}, {"mail from", 0.50}, {"rcpt to", 0.50}}, 0.05, {"220", "SMTP"}, {}},
            {"POP3", "mail", {{"pop3", 0.95}, {"+ok", 0.80}, {"-err", 0.60}, {"user", 0.55},
             {"pass", 0.50}, {"dovecot", 0.70}, {"mailbox", 0.45}}, 0.03, {"+OK", "POP3"}, {}},
            {"IMAP", "mail", {{"imap", 0.95}, {"dovecot", 0.75}, {"courier", 0.60},
             {"* ok", 0.70}, {"capability", 0.55}, {"login", 0.45}, {"select", 0.40}}, 0.03, {"* OK", "IMAP"}, {}},
            {"MySQL", "database", {{"mysql", 0.98}, {"maria", 0.85}, {"5.", 0.60}, {"8.0", 0.55},
             {"database", 0.50}, {"select", 0.45}, {"from", 0.40}}, 0.05, {"mysql", "MariaDB"}, {}},
            {"PostgreSQL", "database", {{"postgresql", 0.98}, {"psql", 0.80}, {"pg_", 0.65},
             {"database", 0.50}, {"select", 0.45}, {"crdb", 0.40}}, 0.04, {"PostgreSQL"}, {}},
            {"MongoDB", "database", {{"mongodb", 0.98}, {"mongos", 0.80}, {"ismaster", 0.65},
             {"ok", 0.40}}, 0.03, {"MongoDB"}, {}},
            {"Redis", "cache", {{"redis", 0.98}, {"+ok", 0.80}, {"-err", 0.55}, {"ping", 0.60},
             {"set", 0.45}, {"get", 0.45}}, 0.04, {"+OK", "REDIS"}, {}},
            {"Memcached", "cache", {{"memcached", 0.95}, {"stat", 0.70}, {"value", 0.55},
             {"get", 0.45}, {"set", 0.45}}, 0.02, {"STAT"}, {}},
            {"DNS", "network", {{"dns", 0.90}, {"bind", 0.75}, {"dnsmasq", 0.70},
             {"query", 0.50}, {"zone", 0.45}, {"resolution", 0.40}}, 0.05, {"DNS", "BIND"}, {}},
            {"DHCP", "network", {{"dhcp", 0.95}, {"dhcpd", 0.80}, {"offer", 0.55},
             {"acknowledge", 0.45}}, 0.02, {"DHCP"}, {}},
            {"NTP", "network", {{"ntp", 0.95}, {"ntpd", 0.80}, {"clock", 0.50},
             {"sync", 0.45}, {"stratum", 0.40}}, 0.02, {"NTP", "ntpd"}, {}},
            {"SNMP", "network", {{"snmp", 0.95}, {"snmpd", 0.80}, {"public", 0.50},
             {"private", 0.45}, {"community", 0.50}, {"oid", 0.40}}, 0.02, {"SNMP"}, {}},
            {"LDAP", "auth", {{"ldap", 0.95}, {"openldap", 0.80}, {"slapd", 0.70},
             {"directory", 0.50}, {"bind", 0.45}, {"search", 0.40}}, 0.02, {"LDAP"}, {}},
            {"Kerberos", "auth", {{"kerberos", 0.95}, {"krb", 0.85}, {"asn.1", 0.55},
             {"ticket", 0.50}, {"authenticate", 0.50}}, 0.02, {"KRB", "Kerberos"}, {}},
            {"RDP", "remote", {{"rdp", 0.95}, {"terminal", 0.80}, {"microsoft", 0.70},
             {"remote desktop", 0.85}, {"tls", 0.50}, {"connection", 0.45}}, 0.04, {"RDP", "Terminal"}, {}},
            {"VNC", "remote", {{"vnc", 0.95}, {"rfb", 0.85}, {"realvnc", 0.70},
             {"tightvnc", 0.65}, {"authentication", 0.50}}, 0.03, {"RFB", "VNC"}, {}},
            {"SMB", "file", {{"smb", 0.95}, {"cifs", 0.80}, {"microsoft", 0.65},
             {"network", 0.45}, {"share", 0.50}, {"smbd", 0.70}}, 0.05, {"SMB", "CIFS"}, {}},
            {"NFS", "file", {{"nfs", 0.95}, {"nfsd", 0.80}, {"network file", 0.65},
             {"mount", 0.50}, {"export", 0.45}}, 0.02, {"NFS"}, {}},
            {"Telnet", "remote", {{"telnet", 0.95}, {"telnetd", 0.80}, {"tt", 0.50},
             {"vt100", 0.55}, {"login", 0.50}}, 0.02, {"Telnet", "login"}, {}},
            {"RPC", "network", {{"rpc", 0.85}, {"portmap", 0.70}, {"rpcbind", 0.65},
             {"sunrpc", 0.60}, {"nfs", 0.50}}, 0.03, {"RPC", "portmap"}, {}},
            {"SIP", "voip", {{"sip", 0.95}, {"asterisk", 0.75}, {"freeswitch", 0.65},
             {"invite", 0.55}, {"register", 0.50}, {"200 ok", 0.50}}, 0.02, {"SIP/"}, {}},
            {"IRC", "chat", {{"irc", 0.95}, {"ircd", 0.80}, {"nickserv", 0.55},
             {"chanserv", 0.50}, {"join", 0.40}}, 0.02, {"IRC"}, {}},
            {"XMPP", "chat", {{"xmpp", 0.95}, {"jabber", 0.80}, {"ejabberd", 0.65},
             {"stream", 0.45}, {"iq", 0.40}}, 0.01, {"XMPP", "jabber"}, {}},
            {"Bitcoin", "crypto", {{"bitcoin", 0.98}, {"bitcoind", 0.80}, {"satosh", 0.70},
             {"blockchain", 0.55}, {"block", 0.45}}, 0.02, {"Bitcoin"}, {}},
            {"Ethereum", "crypto", {{"ethereum", 0.95}, {"geth", 0.80}, {"eth", 0.70},
             {"web3", 0.50}, {"json-rpc", 0.55}}, 0.01, {"Ethereum"}, {}},
            {"Elasticsearch", "database", {{"elasticsearch", 0.98}, {"elastic", 0.80},
             {"_search", 0.60}, {"_index", 0.55}, {"json", 0.40}}, 0.03, {"elasticsearch", "elastic"}, {}},
            {"Cassandra", "database", {{"cassandra", 0.95}, {"cql", 0.70}, {"cqlsh", 0.60},
             {"keyspace", 0.45}}, 0.01, {"Cassandra"}, {}},
            {"RabbitMQ", "queue", {{"rabbitmq", 0.95}, {"amqp", 0.80}, {"queue", 0.50},
             {"exchange", 0.45}, {"binding", 0.40}}, 0.02, {"RabbitMQ", "AMQP"}, {}},
            {"Kafka", "queue", {{"kafka", 0.95}, {"apache kafka", 0.80}, {"broker", 0.55},
             {"topic", 0.50}, {"producer", 0.45}}, 0.02, {"kafka"}, {}},
            {"Jenkins", "ci", {{"jenkins", 0.98}, {"hudson", 0.70}, {"job", 0.50},
             {"build", 0.45}, {"ci", 0.40}}, 0.02, {"Jenkins"}, {}},
            {"GitLab", "ci", {{"gitlab", 0.98}, {"gitlab ci", 0.80}, {"pipeline", 0.50},
             {"merge request", 0.45}}, 0.01, {"GitLab"}, {}},
            {"Docker", "container", {{"docker", 0.95}, {"container", 0.60}, {"registry", 0.50},
             {"image", 0.45}, {"repository", 0.40}}, 0.03, {"Docker"}, {}},
            {"Kubernetes", "container", {{"kubernetes", 0.95}, {"k8s", 0.75}, {"etcd", 0.60},
             {"kubelet", 0.65}, {"api server", 0.55}, {"pod", 0.45}}, 0.02, {"Kubernetes", "k8s"}, {}},
            {"Nginx", "web", {{"nginx", 0.98}, {"nginx/", 0.95}, {"web server", 0.50}}, 0.07, {"nginx"}, {}},
            {"Apache", "web", {{"apache", 0.98}, {"apache/", 0.95}, {"httpd", 0.80}}, 0.07, {"Apache"}, {}},
            {"IIS", "web", {{"microsoft-iis", 0.95}, {"iis", 0.90}, {"asp.net", 0.70}}, 0.04, {"Microsoft-IIS"}, {}},
            {"Tomcat", "web", {{"tomcat", 0.95}, {"catalina", 0.75}, {"jsp", 0.55}}, 0.02, {"Tomcat", "Catalina"}, {}},
            {"Node.js", "web", {{"node", 0.80}, {"express", 0.75}, {"node.js", 0.90}}, 0.03, {"Node"}, {}},
            {"Python WSGI", "web", {{"python", 0.80}, {"wsgi", 0.70}, {"gunicorn", 0.75},
             {"uwsgi", 0.70}, {"flask", 0.65}}, 0.02, {"Python", "WSGI"}, {}},
            {"PHP", "web", {{"php", 0.95}, {"php/", 0.90}, {"zend", 0.60},
             {"laravel", 0.55}, {"wordpress", 0.50}}, 0.04, {"PHP"}, {}},
            {"Ruby", "web", {{"ruby", 0.85}, {"rails", 0.75}, {"webrick", 0.70},
             {"passenger", 0.65}, {"rack", 0.55}}, 0.02, {"Ruby"}, {}},
            {"Java", "web", {{"java", 0.85}, {"servlet", 0.65}, {"jsp", 0.60},
             {"spring", 0.55}, {"catalina", 0.50}, {"weblogic", 0.50}, {"websphere", 0.45}}, 0.03, {}, {}},
            {"Go net/http", "web", {{"go-http", 0.85}, {"golang", 0.70}, {"net/http", 0.65}}, 0.01, {"Go-http"}, {}},
            {"CouchDB", "database", {{"couchdb", 0.95}, {"couchbase", 0.70}}, 0.01, {"CouchDB"}, {}},
            {"Neo4j", "database", {{"neo4j", 0.95}, {"cypher", 0.65}, {"graph", 0.45}}, 0.01, {"Neo4j"}, {}},
            {"SQLite", "database", {{"sqlite", 0.95}}, 0.01, {"SQLite"}, {}},
            {"Oracle DB", "database", {{"oracle", 0.90}, {"tns", 0.70}, {"oracle database", 0.85}}, 0.03, {"Oracle"}, {}},
            {"MSSQL", "database", {{"mssql", 0.95}, {"sql server", 0.80}, {"tds", 0.60}}, 0.03, {"MSSQL", "Microsoft SQL"}, {}},
            {"DB2", "database", {{"db2", 0.90}, {"ibm db2", 0.80}}, 0.01, {"DB2"}, {}},
            {"Squid", "proxy", {{"squid", 0.95}, {"proxy", 0.60}, {"cache", 0.45}}, 0.02, {"Squid"}, {}},
            {"HAProxy", "proxy", {{"haproxy", 0.95}, {"proxy", 0.50}}, 0.01, {"HAProxy"}, {}},
            {"Varnish", "proxy", {{"varnish", 0.95}}, 0.01, {"Varnish"}, {}},
            {"Lighttpd", "web", {{"lighttpd", 0.95}}, 0.01, {"lighttpd"}, {}},
            {"Caddy", "web", {{"caddy", 0.90}}, 0.01, {"Caddy"}, {}},
            {"ZooKeeper", "queue", {{"zookeeper", 0.95}, {"zookeeper", 0.85}}, 0.02, {"ZooKeeper"}, {}},
            {"Consul", "network", {{"consul", 0.95}, {"service discovery", 0.55}}, 0.01, {"Consul"}, {}},
            {"Etcd", "database", {{"etcd", 0.95}, {"etcdserver", 0.80}}, 0.01, {"etcd"}, {}},
            {"Prometheus", "monitoring", {{"prometheus", 0.95}, {"metrics", 0.55}},
             0.02, {"Prometheus"}, {}},
            {"Grafana", "monitoring", {{"grafana", 0.95}}, 0.01, {"Grafana"}, {}},
            {"Nagios", "monitoring", {{"nagios", 0.95}, {"nrpe", 0.70}, {"nsca", 0.55}}, 0.01, {"Nagios", "NRPE"}, {}},
            {"Zabbix", "monitoring", {{"zabbix", 0.95}, {"zabbix agent", 0.80}}, 0.01, {"Zabbix"}, {}},
            {"Postfix", "mail", {{"postfix", 0.95}, {"qmqp", 0.55}}, 0.02, {"Postfix"}, {}},
            {"Sendmail", "mail", {{"sendmail", 0.90}}, 0.01, {"Sendmail"}, {}},
            {"Exim", "mail", {{"exim", 0.90}}, 0.01, {"Exim"}, {}},
            {"Dovecot", "mail", {{"dovecot", 0.95}}, 0.02, {"Dovecot"}, {}},
            {"OpenSSH", "remote", {{"openssh", 0.98}, {"ssh", 0.85}}, 0.06, {"OpenSSH"}, {}},
            {"Dropbear", "remote", {{"dropbear", 0.95}}, 0.01, {"Dropbear"}, {}},
            {"OpenLDAP", "auth", {{"openldap", 0.90}, {"slapd", 0.70}}, 0.01, {"OpenLDAP", "slapd"}, {}},
            {"FreeRADIUS", "auth", {{"freeradius", 0.90}, {"radius", 0.70}}, 0.01, {"FreeRADIUS"}, {}},
            {"OpenVPN", "vpn", {{"openvpn", 0.95}, {"vpn", 0.50}}, 0.02, {"OpenVPN"}, {}},
            {"Mosquitto", "iot", {{"mosquitto", 0.95}, {"mqtt", 0.75}}, 0.01, {"Mosquitto"}, {}},
            {"CoAP", "iot", {{"coap", 0.90}}, 0.01, {"CoAP"}, {}},
            {"Modbus", "iot", {{"modbus", 0.90}}, 0.01, {"Modbus"}, {}},
            {"MQTT", "iot", {{"mqtt", 0.95}, {"mosquitto", 0.70}}, 0.02, {"MQTT"}, {}},
            {"S7", "iot", {{"s7", 0.85}, {"siemens", 0.65}}, 0.01, {"S7"}, {}},
            {"DNP3", "iot", {{"dnp3", 0.85}}, 0.01, {"DNP3"}, {}},
            {"BACnet", "iot", {{"bacnet", 0.85}}, 0.01, {"BACnet"}, {}},
            {"WinRM", "remote", {{"winrm", 0.90}, {"ws-management", 0.65}}, 0.01, {"WinRM"}, {}},
            {"Splunk", "log", {{"splunk", 0.95}, {"splunkd", 0.80}}, 0.01, {"Splunk"}, {}},
            {"Kibana", "web", {{"kibana", 0.95}}, 0.01, {"Kibana"}, {}},
            {"Ganglia", "monitoring", {{"ganglia", 0.90}, {"gmetad", 0.65}}, 0.01, {"Ganglia"}, {}},
            {"Munin", "monitoring", {{"munin", 0.90}}, 0.01, {"Munin"}, {}},
            {"RethinkDB", "database", {{"rethinkdb", 0.90}}, 0.01, {"RethinkDB"}, {}},
            {"CockroachDB", "database", {{"cockroachdb", 0.90}}, 0.01, {"CockroachDB"}, {}},
            {"Hadoop", "bigdata", {{"hadoop", 0.90}, {"namenode", 0.70}, {"datanode", 0.65}}, 0.01, {"Hadoop"}, {}},
            {"HBase", "bigdata", {{"hbase", 0.90}, {"region server", 0.65}}, 0.01, {"HBase"}, {}},
            {"ActiveMQ", "queue", {{"activemq", 0.90}, {"openwire", 0.55}}, 0.01, {"ActiveMQ"}, {}},
            {"Minecraft", "game", {{"minecraft", 0.95}}, 0.01, {"Minecraft"}, {}},
            {"Mumble", "voip", {{"mumble", 0.90}, {"murmur", 0.75}}, 0.01, {"Mumble"}, {}},
            {"Plex", "media", {{"plex", 0.90}, {"myplex", 0.70}}, 0.01, {"Plex"}, {}},
            {"Syncthing", "sync", {{"syncthing", 0.90}}, 0.01, {"Syncthing"}, {}},
            {"ZeroTier", "network", {{"zerotier", 0.85}}, 0.01, {"ZeroTier"}, {}},
            {"Kubelet", "container", {{"kubelet", 0.95}, {"kubernetes", 0.60}}, 0.02, {"kubelet"}, {}},
            {"etcd", "database", {{"etcd", 0.95}, {"raft", 0.45}}, 0.01, {"etcd"}, {}},
            {"Solr", "search", {{"solr", 0.95}, {"apache solr", 0.80}}, 0.01, {"Solr"}, {}},
            {"SVN", "version-control", {{"svn", 0.80}, {"subversion", 0.75}}, 0.01, {"Subversion"}, {}},
            {"Git", "version-control", {{"git", 0.70}, {"git-daemon", 0.65}}, 0.01, {"git"}, {}},
            {"Rsync", "file", {{"rsync", 0.90}}, 0.01, {"rsync"}, {}},
            {"CUPS", "print", {{"cups", 0.85}, {"ipp", 0.70}}, 0.01, {"CUPS", "IPP"}, {}},
            {"Syslog", "log", {{"syslog", 0.85}, {"rsyslog", 0.70}}, 0.01, {"syslog"}, {}},
        };
    }

    std::vector<std::string> tokenize(std::string_view text) {
        std::vector<std::string> tokens;
        std::string current;
        for (char c : text) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '/' || c == '-' || c == '.' || c == '_') {
                current += std::tolower(static_cast<unsigned char>(c));
            } else {
                if (!current.empty()) {
                    tokens.emplace_back(current);
                    current.clear();
                }
            }
        }
        if (!current.empty()) tokens.emplace_back(current);
        return tokens;
    }

public:
    ServiceClassifier() {
        init_signatures();
    }

    std::vector<Prediction> classify(std::string_view banner, int port) {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<Prediction> predictions;

        if (banner.empty()) return predictions;

        std::string banner_lower;
        for (char c : banner) banner_lower += std::tolower(static_cast<unsigned char>(c));

        auto tokens = tokenize(banner_lower);
        std::set<std::string> token_set(tokens.begin(), tokens.end());

        for (const auto& sig : signatures) {
            bool required_ok = true;
            for (const auto& req : sig.required_patterns) {
                std::string req_lower;
                for (char c : req) req_lower += std::tolower(static_cast<unsigned char>(c));
                if (banner_lower.find(req_lower) == std::string::npos) {
                    required_ok = false;
                    break;
                }
            }
            if (!required_ok) continue;

            bool negative_ok = true;
            for (const auto& neg : sig.negative_patterns) {
                std::string neg_lower;
                for (char c : neg) neg_lower += std::tolower(static_cast<unsigned char>(c));
                if (banner_lower.find(neg_lower) != std::string::npos) {
                    negative_ok = false;
                    break;
                }
            }
            if (!negative_ok) continue;

            double log_prob = std::log(sig.prior_probability);
            double log_not_prob = std::log(1.0 - sig.prior_probability);
            double evidence = 0.0;
            int matched_keywords = 0;

            for (const auto& [keyword, weight] : sig.keyword_weights) {
                std::string kw_lower;
                for (char c : keyword) kw_lower += std::tolower(static_cast<unsigned char>(c));
                bool found = (banner_lower.find(kw_lower) != std::string::npos);

                if (found) {
                    double p_feature_given_service = weight;
                    double p_feature_given_not = 0.01 * (1.0 - weight) + 0.001;
                    log_prob += std::log(p_feature_given_service);
                    log_not_prob += std::log(p_feature_given_not);
                    evidence += weight;
                    matched_keywords++;
                }
            }

            if (matched_keywords == 0) continue;

            double posterior = 1.0 / (1.0 + std::exp(log_not_prob - log_prob));
            double confidence = std::min(1.0, posterior * (1.0 + matched_keywords / 10.0));

            predictions.push_back(Prediction{sig.service_name, sig.category, posterior, confidence});
        }

        std::sort(predictions.begin(), predictions.end(),
            [](const Prediction& a, const Prediction& b) {
                return a.score > b.score;
            });

        if (!predictions.empty()) {
            double max_score = predictions[0].score;
            for (auto& p : predictions) {
                p.confidence = std::min(1.0, p.confidence * (p.score / max_score));
            }
        }

        if (predictions.size() > 3) {
            predictions.resize(3);
        }

        return predictions;
    }

    void print_predictions(const std::vector<Prediction>& predictions, std::string_view target, int port) noexcept {
        for (const auto& p : predictions) {
            std::cout << "RESULT:{\"target\":\"" << target
                      << "\",\"port\":" << port
                      << ",\"service\":\"" << p.service_name
                      << "\",\"category\":\"" << p.category
                      << "\",\"score\":" << std::fixed << std::setprecision(4) << p.score
                      << ",\"confidence\":" << std::setprecision(4) << p.confidence
                      << "}" << '\n';
        }

        std::cout << "FINAL:{\"target\":\"" << target
                  << "\",\"port\":" << port
                  << ",\"predictions\":" << predictions.size()
                  << ",\"top_service\":\"" << (predictions.empty() ? "unknown" : predictions[0].service_name)
                  << "\",\"top_confidence\":" << std::fixed << std::setprecision(4)
                  << (predictions.empty() ? 0.0 : predictions[0].confidence)
                  << "}" << '\n';
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <target:port> <banner>" << '\n';
        return 1;
    }

    std::string input = argv[1];
    std::string target;
    int port = 0;
    size_t colon = input.find(':');
    if (colon != std::string::npos) {
        target = input.substr(0, colon);
        try { port = std::stoi(input.substr(colon + 1)); }
        catch (...) { port = 0; }
    } else {
        target = input;
    }

    std::string banner = argv[2];

    ServiceClassifier classifier;
    auto predictions = classifier.classify(banner, port);
    classifier.print_predictions(predictions, target, port);

    return 0;
}
