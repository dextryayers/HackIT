use rust_port_scanner::*;
use rayon::prelude::*;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const DEFAULT_CONCURRENCY: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriorityLevel {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
}

impl PriorityLevel {
    fn name(&self) -> &'static str {
        match self {
            PriorityLevel::Critical => "critical",
            PriorityLevel::High => "high",
            PriorityLevel::Medium => "medium",
            PriorityLevel::Low => "low",
        }
    }
}

#[derive(Debug, Clone)]
struct PriorityPort {
    port: u16,
    priority: PriorityLevel,
    reason: &'static str,
}

#[derive(Debug, Clone)]
struct CVESignature {
    cve_id: &'static str,
    ports: &'static [u16],
    keywords: &'static [&'static str],
    description: &'static str,
    severity: &'static str,
    cvss: f64,
}

lazy_static::lazy_static! {
    static ref PRIORITY_PORTS: Vec<PriorityPort> = {
        let mut v = Vec::with_capacity(128);
        v.push(PriorityPort { port: 22, priority: PriorityLevel::Critical, reason: "SSH - remote access" });
        v.push(PriorityPort { port: 80, priority: PriorityLevel::Critical, reason: "HTTP - web server" });
        v.push(PriorityPort { port: 443, priority: PriorityLevel::Critical, reason: "HTTPS - web server TLS" });
        v.push(PriorityPort { port: 3306, priority: PriorityLevel::Critical, reason: "MySQL - database" });
        v.push(PriorityPort { port: 3389, priority: PriorityLevel::Critical, reason: "RDP - remote desktop" });
        v.push(PriorityPort { port: 21, priority: PriorityLevel::High, reason: "FTP - file transfer" });
        v.push(PriorityPort { port: 23, priority: PriorityLevel::High, reason: "Telnet - unencrypted remote" });
        v.push(PriorityPort { port: 25, priority: PriorityLevel::High, reason: "SMTP - mail server" });
        v.push(PriorityPort { port: 53, priority: PriorityLevel::High, reason: "DNS - name resolution" });
        v.push(PriorityPort { port: 110, priority: PriorityLevel::High, reason: "POP3 - email retrieval" });
        v.push(PriorityPort { port: 143, priority: PriorityLevel::High, reason: "IMAP - email access" });
        v.push(PriorityPort { port: 445, priority: PriorityLevel::Critical, reason: "SMB - file sharing" });
        v.push(PriorityPort { port: 1433, priority: PriorityLevel::Critical, reason: "MSSQL - database" });
        v.push(PriorityPort { port: 1521, priority: PriorityLevel::Critical, reason: "Oracle DB - database" });
        v.push(PriorityPort { port: 2375, priority: PriorityLevel::Critical, reason: "Docker - container API" });
        v.push(PriorityPort { port: 5432, priority: PriorityLevel::Critical, reason: "PostgreSQL - database" });
        v.push(PriorityPort { port: 6379, priority: PriorityLevel::Critical, reason: "Redis - data store" });
        v.push(PriorityPort { port: 27017, priority: PriorityLevel::Critical, reason: "MongoDB - database" });
        v.push(PriorityPort { port: 8080, priority: PriorityLevel::High, reason: "HTTP-Proxy - web proxy" });
        v.push(PriorityPort { port: 8443, priority: PriorityLevel::High, reason: "HTTPS-Alt - alt TLS" });
        v.push(PriorityPort { port: 9200, priority: PriorityLevel::High, reason: "Elasticsearch - data store" });
        v.push(PriorityPort { port: 11211, priority: PriorityLevel::High, reason: "Memcached - cache" });
        v.push(PriorityPort { port: 135, priority: PriorityLevel::Medium, reason: "MSRPC - Windows RPC" });
        v.push(PriorityPort { port: 139, priority: PriorityLevel::Medium, reason: "NetBIOS - name service" });
        v.push(PriorityPort { port: 161, priority: PriorityLevel::Medium, reason: "SNMP - network mgmt" });
        v.push(PriorityPort { port: 389, priority: PriorityLevel::Medium, reason: "LDAP - directory" });
        v.push(PriorityPort { port: 636, priority: PriorityLevel::Medium, reason: "LDAPS - directory TLS" });
        v.push(PriorityPort { port: 993, priority: PriorityLevel::Medium, reason: "IMAPS - email TLS" });
        v.push(PriorityPort { port: 995, priority: PriorityLevel::Medium, reason: "POP3S - email TLS" });
        v.push(PriorityPort { port: 1080, priority: PriorityLevel::Medium, reason: "SOCKS - proxy" });
        v.push(PriorityPort { port: 1194, priority: PriorityLevel::Medium, reason: "OpenVPN - VPN" });
        v.push(PriorityPort { port: 1723, priority: PriorityLevel::Medium, reason: "PPTP - VPN" });
        v.push(PriorityPort { port: 1883, priority: PriorityLevel::Medium, reason: "MQTT - IoT protocol" });
        v.push(PriorityPort { port: 2049, priority: PriorityLevel::High, reason: "NFS - file system" });
        v.push(PriorityPort { port: 2181, priority: PriorityLevel::High, reason: "ZooKeeper - coordinator" });
        v.push(PriorityPort { port: 2376, priority: PriorityLevel::High, reason: "Docker-TLS - container TLS" });
        v.push(PriorityPort { port: 2379, priority: PriorityLevel::High, reason: "etcd - key-value store" });
        v.push(PriorityPort { port: 3000, priority: PriorityLevel::Medium, reason: "Grafana/Node - dashboard" });
        v.push(PriorityPort { port: 3128, priority: PriorityLevel::Medium, reason: "Squid - proxy cache" });
        v.push(PriorityPort { port: 465, priority: PriorityLevel::Medium, reason: "SMTPS - mail TLS" });
        v.push(PriorityPort { port: 587, priority: PriorityLevel::Medium, reason: "SMTP-MSA - mail submission" });
        v.push(PriorityPort { port: 5900, priority: PriorityLevel::High, reason: "VNC - remote desktop" });
        v.push(PriorityPort { port: 5984, priority: PriorityLevel::Medium, reason: "CouchDB - database" });
        v.push(PriorityPort { port: 6443, priority: PriorityLevel::High, reason: "K8s-API - Kubernetes" });
        v.push(PriorityPort { port: 8500, priority: PriorityLevel::Medium, reason: "Consul - service mesh" });
        v.push(PriorityPort { port: 9042, priority: PriorityLevel::Medium, reason: "Cassandra - database" });
        v.push(PriorityPort { port: 9092, priority: PriorityLevel::Medium, reason: "Kafka - message broker" });
        v.push(PriorityPort { port: 10000, priority: PriorityLevel::Medium, reason: "Webmin - web admin" });
        v.push(PriorityPort { port: 15672, priority: PriorityLevel::Medium, reason: "RabbitMQ - message queue" });
        v.push(PriorityPort { port: 31337, priority: PriorityLevel::High, reason: "BackOrifice - malware" });
        v.push(PriorityPort { port: 12345, priority: PriorityLevel::High, reason: "NetBus - malware" });
        v.push(PriorityPort { port: 27374, priority: PriorityLevel::High, reason: "Sub7 - malware" });
        v
    };
    static ref CVE_DATABASE: Vec<CVESignature> = {
        let mut v = Vec::with_capacity(64);
        v.push(CVESignature { cve_id: "CVE-2014-0160", ports: &[443, 465, 636, 993, 995, 8443], keywords: &["heartbleed"], description: "Heartbleed - OpenSSL memory leak", severity: "CRITICAL", cvss: 7.5 });
        v.push(CVESignature { cve_id: "CVE-2021-44228", ports: &[80, 443, 8080, 8443], keywords: &["log4j", "jndi", "${jndi"], description: "Log4Shell - Apache Log4j RCE", severity: "CRITICAL", cvss: 10.0 });
        v.push(CVESignature { cve_id: "CVE-2017-0144", ports: &[445], keywords: &["smb", "eternalblue", "windows 7", "windows 2008"], description: "EternalBlue - SMB RCE", severity: "CRITICAL", cvss: 8.5 });
        v.push(CVESignature { cve_id: "CVE-2020-0796", ports: &[445], keywords: &["smb v3", "srv2"], description: "SMBGhost - SMBv3 RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2019-0708", ports: &[3389], keywords: &["rdp", "ms-terminal", "bluekeep"], description: "BlueKeep - RDS RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2018-15473", ports: &[22], keywords: &["openssh_7.2", "openssh_7.3", "openssh_7.4"], description: "OpenSSH user enumeration", severity: "MEDIUM", cvss: 5.0 });
        v.push(CVESignature { cve_id: "CVE-2021-3449", ports: &[443, 8443], keywords: &["openssl 1.1.1"], description: "OpenSSL DoS / MITM", severity: "HIGH", cvss: 7.5 });
        v.push(CVESignature { cve_id: "CVE-2021-41773", ports: &[80, 443, 8080], keywords: &["apache/2.4.49"], description: "Apache Path Traversal", severity: "HIGH", cvss: 7.5 });
        v.push(CVESignature { cve_id: "CVE-2021-42013", ports: &[80, 443, 8080], keywords: &["apache/2.4.50"], description: "Apache Path Traversal 2", severity: "CRITICAL", cvss: 9.0 });
        v.push(CVESignature { cve_id: "CVE-2021-22986", ports: &[443, 8443], keywords: &["big-ip", "f5"], description: "F5 BIG-IP iControl RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-26084", ports: &[8080, 443], keywords: &["confluence", "atlassian"], description: "Confluence OGNL RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-1472", ports: &[389, 636], keywords: &["zerologon"], description: "Zerologon - Netlogon EoP", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-26855", ports: &[443, 8443], keywords: &["exchange", "proxylogon"], description: "ProxyLogon - Exchange RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-0688", ports: &[443, 8443], keywords: &["exchange"], description: "Exchange RCE", severity: "HIGH", cvss: 8.8 });
        v.push(CVESignature { cve_id: "CVE-2021-34527", ports: &[445], keywords: &["printnightmare"], description: "PrintNightmare - RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-5902", ports: &[443, 8443], keywords: &["big-ip", "f5"], description: "F5 BIG-IP TMUI RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-22991", ports: &[443, 8443], keywords: &["big-ip"], description: "F5 BIG-IP DoS", severity: "HIGH", cvss: 7.5 });
        v.push(CVESignature { cve_id: "CVE-2020-6287", ports: &[443, 8443], keywords: &["sap netweaver"], description: "SAP NetWeaver RECON", severity: "CRITICAL", cvss: 9.9 });
        v.push(CVESignature { cve_id: "CVE-2021-21972", ports: &[443, 80], keywords: &["vcenter", "vmware"], description: "VMware vCenter RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-2551", ports: &[7001, 7002], keywords: &["weblogic"], description: "WebLogic IIOP RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2019-2725", ports: &[7001], keywords: &["weblogic"], description: "WebLogic wls9-async RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-22986", ports: &[443, 8443], keywords: &["bigip", "f5"], description: "F5 iControl REST RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-26855", ports: &[443, 8443], keywords: &["exchange"], description: "ProxyLogon SSRF", severity: "CRITICAL", cvss: 9.1 });
        v.push(CVESignature { cve_id: "CVE-2020-14882", ports: &[7001, 7002], keywords: &["weblogic"], description: "WebLogic Console RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2017-5638", ports: &[8080, 80, 443], keywords: &["struts", "apache struts"], description: "Struts2 OGNL RCE", severity: "CRITICAL", cvss: 10.0 });
        v.push(CVESignature { cve_id: "CVE-2019-0232", ports: &[8080, 80], keywords: &["tomcat"], description: "Tomcat CGIServlet RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-1938", ports: &[8009, 8080], keywords: &["tomcat", "ajp"], description: "Ghostcat - Tomcat AJP RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-22986", ports: &[443], keywords: &["f5"], description: "F5 BIG-IP iControl", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2020-11651", ports: &[4505, 4506], keywords: &["salt"], description: "SaltStack RCE", severity: "CRITICAL", cvss: 10.0 });
        v.push(CVESignature { cve_id: "CVE-2021-31207", ports: &[443], keywords: &["exchange"], description: "Exchange EAC RCE", severity: "HIGH", cvss: 7.5 });
        v.push(CVESignature { cve_id: "CVE-2022-22965", ports: &[8080, 80, 443], keywords: &["spring", "spring framework"], description: "Spring4Shell RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-22947", ports: &[8080, 80, 443], keywords: &["spring cloud gateway"], description: "Spring Cloud Gateway RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-45046", ports: &[80, 443, 8080], keywords: &["log4j"], description: "Log4Shell variant - RCE", severity: "CRITICAL", cvss: 9.0 });
        v.push(CVESignature { cve_id: "CVE-2022-1388", ports: &[443, 8443], keywords: &["big-ip", "f5"], description: "F5 BIG-IP iControl RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-26134", ports: &[8080, 443], keywords: &["confluence"], description: "Confluence OGNL RCE 2022", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-40346", ports: &[443, 80], keywords: &["haproxy"], description: "HAProxy integer overflow", severity: "HIGH", cvss: 8.3 });
        v.push(CVESignature { cve_id: "CVE-2022-30190", ports: &[80, 443], keywords: &["msdt", "follina"], description: "Follina - MSDT RCE", severity: "HIGH", cvss: 7.8 });
        v.push(CVESignature { cve_id: "CVE-2022-34721", ports: &[443], keywords: &["windows server"], description: "Windows IIS RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2021-40444", ports: &[80, 443], keywords: &["mshtml", "ie"], description: "MSHTML RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-24706", ports: &[9090], keywords: &["prometheus"], description: "Apache CouchDB - Prometheus info leak", severity: "MEDIUM", cvss: 5.3 });
        v.push(CVESignature { cve_id: "CVE-2021-22986", ports: &[443], keywords: &["f5"], description: "F5 TMUI RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-20808", ports: &[443], keywords: &["cisco"], description: "Cisco ASA RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-40684", ports: &[443, 8443], keywords: &["fortinet", "fortigate"], description: "Fortinet auth bypass", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2022-41040", ports: &[443, 8443], keywords: &["exchange"], description: "ProxyNotShell SSRF", severity: "HIGH", cvss: 8.8 });
        v.push(CVESignature { cve_id: "CVE-2023-25194", ports: &[9092], keywords: &["kafka"], description: "Kafka Connect RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-21839", ports: &[7001, 7002], keywords: &["weblogic"], description: "WebLogic RCE 2023", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-25157", ports: &[8080, 80], keywords: &["geoserver"], description: "GeoServer RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-22952", ports: &[443], keywords: &["sugar crm"], description: "SugarCRM RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-27524", ports: &[443, 8080], keywords: &["superset"], description: "Apache Superset RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-25610", ports: &[443, 8443], keywords: &["fortigate", "fortios"], description: "FortiOS RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-28771", ports: &[500, 4500], keywords: &["zyxel"], description: "Zyxell RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-27997", ports: &[443, 8443], keywords: &["fortigate"], description: "FortiOS SSL-VPN RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-27350", ports: &[443, 8080], keywords: &["papercut"], description: "PaperCut RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-23397", ports: &[443], keywords: &["exchange"], description: "Exchange EoP", severity: "HIGH", cvss: 8.8 });
        v.push(CVESignature { cve_id: "CVE-2023-34362", ports: &[8080, 80], keywords: &["mft", "moveit"], description: "MOVEit Transfer RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-3519", ports: &[443, 8443], keywords: &["citrix"], description: "Citrix ADC RCE", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-32784", ports: &[443], keywords: &["keepass"], description: "KeePass master password leak", severity: "MEDIUM", cvss: 5.5 });
        v.push(CVESignature { cve_id: "CVE-2023-34362", ports: &[443], keywords: &["mft", "moveit"], description: "MOVEit SQLi", severity: "CRITICAL", cvss: 9.8 });
        v.push(CVESignature { cve_id: "CVE-2023-46615", ports: &[80, 443], keywords: &["kaspersky"], description: "Kaspersky RCE", severity: "CRITICAL", cvss: 9.8 });
        v
    };
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(22, b"SSH-2.0-HackIT-Probe\r\n".to_vec());
        m.insert(25, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec());
        m.insert(443, b"".to_vec());
        m.insert(445, b"\x00\x00\x00\xa0\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(587, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(636, b"".to_vec());
        m.insert(873, b"@RSYNCD: 31.0\n".to_vec());
        m.insert(993, b"".to_vec());
        m.insert(995, b"".to_vec());
        m.insert(3306, b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec());
        m.insert(5900, b"RFB 003.008\n".to_vec());
        m.insert(6379, b"PING\r\n".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(9090, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(9200, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(27017, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m
    };
}

#[derive(Debug, Clone, Serialize)]
struct VulnResult {
    port: u16,
    state: String,
    service: String,
    priority: &'static str,
    priority_reason: &'static str,
    banner: String,
    matched_cves: Vec<CVEMatch>,
    response_time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct CVEMatch {
    cve_id: String,
    description: String,
    severity: String,
    cvss: f64,
    confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
struct ScanSummary {
    target: String,
    total_ports: usize,
    open_ports: usize,
    by_priority: HashMap<String, usize>,
    critical_cves: usize,
    high_cves: usize,
    elapsed_ms: u64,
}

fn get_port_priority(port: u16) -> &'static PriorityPort {
    for pp in PRIORITY_PORTS.iter() {
        if pp.port == port {
            return pp;
        }
    }
    static DEFAULT_PP: PriorityPort = PriorityPort { port: 0, priority: PriorityLevel::Low, reason: "standard port" };
    &DEFAULT_PP
}

async fn connect_with_timeout(host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream, String> {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(_) => Err("timeout".into()),
    }
}

async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let stream = match connect_with_timeout(host, port, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let (mut reader, mut writer) = stream.into_split();
    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(&probe)).await;
        let _ = writer.shutdown().await;
    }
    let mut buf = vec![0u8; MAX_BANNER];
    match timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => String::new(),
    }
}

fn match_cves(port: u16, banner: &str) -> Vec<CVEMatch> {
    let b = banner.to_lowercase();
    let mut matches = Vec::new();
    for cve in CVE_DATABASE.iter() {
        if !cve.ports.contains(&port) {
            continue;
        }
        let mut matched = false;
        let mut match_count = 0;
        for kw in cve.keywords {
            if b.contains(kw) {
                matched = true;
                match_count += 1;
            }
        }
        if matched {
            let confidence = (match_count as f64 / cve.keywords.len() as f64) * 100.0;
            matches.push(CVEMatch {
                cve_id: cve.cve_id.to_string(),
                description: cve.description.to_string(),
                severity: cve.severity.to_string(),
                cvss: cve.cvss,
                confidence: confidence.min(100.0),
            });
        }
    }
    matches.sort_by(|a, b| b.cvss.partial_cmp(&a.cvss).unwrap_or(Ordering::Equal));
    matches
}

async fn scan_single(host: &str, port: u16, timeout_ms: u64) -> Option<VulnResult> {
    let start = Instant::now();
    let stream = connect_with_timeout(host, port, timeout_ms).await;
    if stream.is_err() { return None; }
    let banner_raw = grab_banner(host, port, timeout_ms).await;
    let sanitized = sanitize_banner(&banner_raw);
    let service = identify_service(&sanitized, port);
    let pp = get_port_priority(port);

    let matched_cves = if !sanitized.is_empty() {
        match_cves(port, &sanitized)
    } else {
        Vec::new()
    };

    Some(VulnResult {
        port,
        state: "open".to_string(),
        service,
        priority: pp.priority.name(),
        priority_reason: pp.reason,
        banner: sanitized,
        matched_cves,
        response_time_ms: start.elapsed().as_millis() as u64,
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <target> <ports> [timeout_ms] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top:N, all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443,3306,6379 3000 concurrency:200", args[0]);
        std::process::exit(1);
    }
    let target = &args[1];
    let ports = parse_ports(&args[2]);
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut concurrency = DEFAULT_CONCURRENCY;
    for arg in &args[3..] {
        if let Ok(ms) = arg.parse::<u64>() {
            timeout_ms = ms;
        } else if let Some(n) = arg.strip_prefix("concurrency:") {
            if let Ok(c) = n.parse::<usize>() {
                concurrency = c.max(1).min(1000);
            }
        }
    }
    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }

    let mut sorted_ports = ports.clone();
    sorted_ports.par_sort_by(|a, b| {
        let pa = get_port_priority(*a).priority as u8;
        let pb = get_port_priority(*b).priority as u8;
        pa.cmp(&pb)
    });

    eprintln!("VULN_PRIORITY_SCANNER target={} ports={} timeout={}ms concurrency={}",
        target, sorted_ports.len(), timeout_ms, concurrency);

    let start = Instant::now();
    let total = sorted_ports.len();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let processed = std::sync::atomic::AtomicUsize::new(0);

    use futures::stream::{self, StreamExt};
    stream::iter(sorted_ports.into_iter())
        .for_each_concurrent(concurrency, |port| {
            let target = target.to_string();
            let tx = tx.clone();
            let processed = &processed;
            async move {
                let result = scan_single(&target, port, timeout_ms).await;
                let count = processed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count % 50 == 0 || count == total {
                    eprintln!("STATUS:{{\"progress\":{:.2},\"message\":\"Scanning port {}/{}\"}}",
                        (count as f64 / total as f64) * 100.0, port, total);
                }
                if let Some(r) = result {
                    let _ = tx.send(r);
                }
            }
        })
        .await;

    drop(tx);
    let mut results: Vec<VulnResult> = Vec::with_capacity(total.min(1000));
    while let Some(r) = rx.recv().await {
        results.push(r);
    }
    results.sort_by(|a, b| {
        let pa = get_port_priority(a.port).priority as u8;
        let pb = get_port_priority(b.port).priority as u8;
        pa.cmp(&pb).then_with(|| a.port.cmp(&b.port))
    });

    let elapsed = start.elapsed().as_millis() as u64;
    let mut by_priority: HashMap<String, usize> = HashMap::new();
    let mut critical_cves = 0;
    let mut high_cves = 0;

    for r in &results {
        *by_priority.entry(r.priority.to_string()).or_insert(0) += 1;
        for cve in &r.matched_cves {
            match cve.severity.as_str() {
                "CRITICAL" => critical_cves += 1,
                "HIGH" => high_cves += 1,
                _ => {}
            }
        }
    }

    for r in &results {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }

    let summary = ScanSummary {
        target: target.to_string(),
        total_ports: total,
        open_ports: results.len(),
        by_priority,
        critical_cves,
        high_cves,
        elapsed_ms: elapsed,
    };
    eprintln!("FINAL:{}", serde_json::to_string(&summary).unwrap());
}
