use rayon::prelude::*;
use regex::Regex;
use rust_port_scanner::*;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 5000;

lazy_static::lazy_static! {
    static ref CVE_SIGNATURES: Vec<(Regex, CVEEntry)> = {
        let mut v = Vec::new();
        v.push((Regex::new(r"(?i)openssh[_-]([0-6]\.[0-9])").unwrap(), CVEEntry { id: "CVE-2024-6387", description: "regreSSHion: Remote code execution in OpenSSH < 9.8", severity: "CRITICAL", cvss: 9.8, affected: "OpenSSH < 9.8", recommendation: "Upgrade OpenSSH to 9.8+ or apply patch" }));
        v.push((Regex::new(r"(?i)openssh[_-]([78]\.[0-9])").unwrap(), CVEEntry { id: "CVE-2024-6387", description: "regreSSHion: Signal handler race condition in OpenSSH", severity: "CRITICAL", cvss: 9.8, affected: "OpenSSH 7.x-8.x", recommendation: "Update to OpenSSH 9.8+" }));
        v.push((Regex::new(r"(?i)openssh[_-](9\.[0-7])").unwrap(), CVEEntry { id: "CVE-2024-6387", description: "regreSSHion: Potentially vulnerable OpenSSH version", severity: "CRITICAL", cvss: 9.8, affected: "OpenSSH 9.0-9.7", recommendation: "Upgrade to OpenSSH 9.8" }));
        v.push((Regex::new(r"(?i)openssh[_-](9\.8[^0-9])").unwrap(), CVEEntry { id: "CVE-2024-6387", description: "OpenSSH 9.8: Check if patched for regreSSHion", severity: "MEDIUM", cvss: 5.0, affected: "OpenSSH 9.8", recommendation: "Verify OpenSSH 9.8p1 is installed" }));
        v.push((Regex::new(r"(?i)apache/2\.4\.49").unwrap(), CVEEntry { id: "CVE-2021-41773", description: "Apache HTTP Server path traversal vulnerability", severity: "CRITICAL", cvss: 9.8, affected: "Apache 2.4.49", recommendation: "Upgrade to Apache 2.4.51+" }));
        v.push((Regex::new(r"(?i)apache/2\.4\.50").unwrap(), CVEEntry { id: "CVE-2021-42013", description: "Apache HTTP Server path traversal (2nd variant)", severity: "CRITICAL", cvss: 9.8, affected: "Apache 2.4.50", recommendation: "Upgrade to Apache 2.4.51+" }));
        v.push((Regex::new(r"(?i)apache/2\.4\.(4[0-8])").unwrap(), CVEEntry { id: "CVE-2021-41773", description: "Apache may be vulnerable to path traversal", severity: "HIGH", cvss: 7.5, affected: "Apache 2.4.40-2.4.48", recommendation: "Upgrade to Apache 2.4.51+" }));
        v.push((Regex::new(r"(?i)apache/1\.[0-9]").unwrap(), CVEEntry { id: "CVE-2006-3747", description: "Apache 1.3: Multiple vulnerabilities (EoL)", severity: "CRITICAL", cvss: 9.1, affected: "Apache 1.x (EoL)", recommendation: "Upgrade to Apache 2.4.x" }));
        v.push((Regex::new(r"(?i)apache/2\.2\.").unwrap(), CVEEntry { id: "CVE-2017-9798", description: "Apache 2.2.x (EoL): Multiple vulnerabilities", severity: "HIGH", cvss: 8.6, affected: "Apache 2.2.x (EoL)", recommendation: "Upgrade to Apache 2.4.x" }));
        v.push((Regex::new(r"(?i)apache/2\.[0-3]\.").unwrap(), CVEEntry { id: "CVE-2017-9798", description: "Apache 2.0-2.3: Outdated and vulnerable", severity: "HIGH", cvss: 8.6, affected: "Apache 2.0-2.3.x", recommendation: "Upgrade to Apache 2.4.x" }));
        v.push((Regex::new(r"(?i)nginx/1\.(1[0-9])\.").unwrap(), CVEEntry { id: "CVE-2021-23017", description: "nginx DNS resolver vulnerability in older versions", severity: "HIGH", cvss: 8.0, affected: "nginx 1.10-1.19.x", recommendation: "Update nginx to 1.20+" }));
        v.push((Regex::new(r"(?i)nginx/1\.(0[0-9])\.").unwrap(), CVEEntry { id: "CVE-2020-12426", description: "nginx 1.0-1.9: Multiple vulnerabilities", severity: "HIGH", cvss: 7.5, affected: "nginx 1.0-1.9.x", recommendation: "Upgrade nginx to 1.20+" }));
        v.push((Regex::new(r"(?i)nginx/[0-9]+\.[0-9]+\.[0-9]+").unwrap(), CVEEntry { id: "VULN-Check", description: "nginx version detected - check for known CVEs", severity: "INFO", cvss: 0.0, affected: "nginx", recommendation: "Verify nginx version is up-to-date" }));
        v.push((Regex::new(r"(?i)iis/[56]\.").unwrap(), CVEEntry { id: "CVE-2017-7269", description: "IIS 5.0/6.0: Remote code execution via WebDAV", severity: "CRITICAL", cvss: 9.8, affected: "IIS 5.0, 6.0", recommendation: "Upgrade IIS version" }));
        v.push((Regex::new(r"(?i)iis/7\.").unwrap(), CVEEntry { id: "CVE-2010-3972", description: "IIS 7.0/7.5: FTP service buffer overflow", severity: "HIGH", cvss: 8.0, affected: "IIS 7.0-7.5", recommendation: "Upgrade to IIS 8.0+" }));
        v.push((Regex::new(r"(?i)iis/([0-9])").unwrap(), CVEEntry { id: "CVE-2023-23410", description: "IIS: HTTP/2 protocol vulnerabilities", severity: "MEDIUM", cvss: 5.0, affected: "IIS", recommendation: "Apply latest Windows updates" }));
        v.push((Regex::new(r"(?i)vsftpd 2\.3\.4").unwrap(), CVEEntry { id: "CVE-2011-2523", description: "vsftpd 2.3.4: Backdoor command execution", severity: "CRITICAL", cvss: 9.8, affected: "vsftpd 2.3.4", recommendation: "Upgrade to vsftpd 3.0+" }));
        v.push((Regex::new(r"(?i)vsftpd 2\.[0-2]\.").unwrap(), CVEEntry { id: "CVE-2011-2523", description: "vsftpd 2.0.x-2.2.x: Potentially vulnerable", severity: "HIGH", cvss: 8.0, affected: "vsftpd 2.0.x-2.2.x", recommendation: "Upgrade to vsftpd 3.0+" }));
        v.push((Regex::new(r"(?i)proftpd 1\.3\.[0-5]").unwrap(), CVEEntry { id: "CVE-2020-9273", description: "ProFTPD 1.3.5-1.3.7: Memory corruption vulnerability", severity: "HIGH", cvss: 8.0, affected: "ProFTPD 1.3.5-1.3.7", recommendation: "Upgrade ProFTPD to 1.3.8+" }));
        v.push((Regex::new(r"(?i)mysql 5\.[0-5]\.").unwrap(), CVEEntry { id: "CVE-2012-2122", description: "MySQL 5.0-5.5: Authentication bypass vulnerability", severity: "HIGH", cvss: 8.0, affected: "MySQL 5.0-5.5", recommendation: "Upgrade to MySQL 5.6+" }));
        v.push((Regex::new(r"(?i)mysql 5\.6\.").unwrap(), CVEEntry { id: "VULN-EoL", description: "MySQL 5.6 reached End of Life in Feb 2024", severity: "HIGH", cvss: 7.5, affected: "MySQL 5.6.x", recommendation: "Upgrade to MySQL 8.0+" }));
        v.push((Regex::new(r"(?i)mysql 5\.7\.").unwrap(), CVEEntry { id: "VULN-EoL", description: "MySQL 5.7 reached End of Life in Oct 2023", severity: "MEDIUM", cvss: 5.0, affected: "MySQL 5.7.x", recommendation: "Upgrade to MySQL 8.0+" }));
        v.push((Regex::new(r"(?i)mysql 8\.[0-3]\.").unwrap(), CVEEntry { id: "CVE-2023-21971", description: "MySQL 8.0.x: Multiple vulnerabilities", severity: "MEDIUM", cvss: 6.5, affected: "MySQL 8.0.x", recommendation: "Apply latest MySQL patches" }));
        v.push((Regex::new(r"(?i)postgresql 9\.[0-5]").unwrap(), CVEEntry { id: "CVE-2019-9192", description: "PostgreSQL 9.x: Multiple security issues (EoL)", severity: "HIGH", cvss: 7.5, affected: "PostgreSQL 9.x (EoL)", recommendation: "Upgrade to PostgreSQL 16+" }));
        v.push((Regex::new(r"(?i)postgresql 1[0-2]").unwrap(), CVEEntry { id: "CVE-2023-2454", description: "PostgreSQL 10-12: Outdated version", severity: "MEDIUM", cvss: 5.0, affected: "PostgreSQL 10-12", recommendation: "Upgrade to PostgreSQL 16+" }));
        v.push((Regex::new(r"(?i)redis_version:([23]\.[0-9])").unwrap(), CVEEntry { id: "CVE-2021-29477", description: "Redis < 6.2: Integer overflow vulnerability", severity: "HIGH", cvss: 8.0, affected: "Redis 2.x-3.x", recommendation: "Upgrade Redis to 7.x+" }));
        v.push((Regex::new(r"(?i)redis_version:4\.[0-9]").unwrap(), CVEEntry { id: "CVE-2021-29477", description: "Redis 4.x: Multiple vulnerabilities", severity: "HIGH", cvss: 7.5, affected: "Redis 4.x", recommendation: "Upgrade Redis to 7.x+" }));
        v.push((Regex::new(r"(?i)redis_version:5\.[0-9]").unwrap(), CVEEntry { id: "CVE-2022-24834", description: "Redis 5.x: Lua sandbox escape vulnerability", severity: "HIGH", cvss: 8.0, affected: "Redis 5.x", recommendation: "Upgrade Redis to 7.x+" }));
        v.push((Regex::new(r"(?i)mongodb 3\.[0-9]").unwrap(), CVEEntry { id: "CVE-2019-2391", description: "MongoDB 3.x: Outdated with known vulnerabilities", severity: "HIGH", cvss: 7.5, affected: "MongoDB 3.x", recommendation: "Upgrade to MongoDB 7.x+" }));
        v.push((Regex::new(r"(?i)mongodb 4\.[0-9]").unwrap(), CVEEntry { id: "VULN-EoL", description: "MongoDB 4.x: Outdated version", severity: "MEDIUM", cvss: 5.0, affected: "MongoDB 4.x", recommendation: "Upgrade to MongoDB 7.x+" }));
        v.push((Regex::new(r"(?i)php/([5-7]\.[0-9])").unwrap(), CVEEntry { id: "CVE-2023-3824", description: "PHP 5.x-7.x: Outdated with known vulnerabilities", severity: "CRITICAL", cvss: 9.1, affected: "PHP 5-7.x", recommendation: "Upgrade to PHP 8.2+" }));
        v.push((Regex::new(r"(?i)exim 4\.[0-8]").unwrap(), CVEEntry { id: "CVE-2023-42115", description: "Exim 4.x: Critical remote code execution", severity: "CRITICAL", cvss: 9.8, affected: "Exim 4.0-4.8x", recommendation: "Upgrade Exim to 4.97+" }));
        v.push((Regex::new(r"(?i)opensmtpd").unwrap(), CVEEntry { id: "CVE-2020-7247", description: "OpenSMTPD: Remote code execution in versions < 6.6.2", severity: "CRITICAL", cvss: 9.8, affected: "OpenSMTPD < 6.6.2", recommendation: "Upgrade OpenSMTPD" }));
        v.push((Regex::new(r"(?i)sendmail [89]\.").unwrap(), CVEEntry { id: "CVE-2022-43819", description: "Sendmail: Outdated version with known issues", severity: "HIGH", cvss: 7.5, affected: "Sendmail 8.x-9.x", recommendation: "Upgrade Sendmail" }));
        v.push((Regex::new(r"(?i)dovecot 2\.[0-2]\.").unwrap(), CVEEntry { id: "CVE-2023-2283", description: "Dovecot 2.0-2.2: Multiple vulnerabilities", severity: "HIGH", cvss: 7.5, affected: "Dovecot 2.0-2.2.x", recommendation: "Upgrade Dovecot to 2.3+" }));
        v.push((Regex::new(r"(?i)pure-ftpd 1\.[0-8]").unwrap(), CVEEntry { id: "CVE-2020-9365", description: "Pure-FTPd 1.0.x-1.0.8: Buffer overflow vulnerability", severity: "HIGH", cvss: 8.0, affected: "Pure-FTPd 1.0-1.0.8", recommendation: "Upgrade Pure-FTPd" }));
        v.push((Regex::new(r"(?i)squid/[34]\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-50269", description: "Squid 3.x-4.x: Multiple vulnerabilities", severity: "HIGH", cvss: 7.5, affected: "Squid 3.x-4.x", recommendation: "Upgrade Squid to 6+" }));
        v.push((Regex::new(r"(?i)squid/5\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-46847", description: "Squid 5.x: HTTP response splitting", severity: "MEDIUM", cvss: 6.1, affected: "Squid 5.x", recommendation: "Upgrade Squid to 6+" }));
        v.push((Regex::new(r"(?i)elasticsearch [12]\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-31418", description: "Elasticsearch 1.x-2.x: Remote code execution vulnerability", severity: "CRITICAL", cvss: 9.0, affected: "Elasticsearch 1.x-2.x", recommendation: "Upgrade to Elasticsearch 8.x+" }));
        v.push((Regex::new(r"(?i)elasticsearch [56]\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-31418", description: "Elasticsearch 5.x-6.x: Log4Shell vulnerable versions", severity: "CRITICAL", cvss: 9.0, affected: "Elasticsearch 5.x-6.x", recommendation: "Upgrade to Elasticsearch 8.x+" }));
        v.push((Regex::new(r"(?i)elasticsearch 7\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-31418", description: "Elasticsearch 7.x: Upgrade recommended", severity: "MEDIUM", cvss: 5.0, affected: "Elasticsearch 7.x", recommendation: "Upgrade to Elasticsearch 8.9+" }));
        v.push((Regex::new(r"(?i)rabbitmq [23]\.[0-9]").unwrap(), CVEEntry { id: "CVE-2022-22992", description: "RabbitMQ 2.x-3.x: Multiple vulnerabilities", severity: "HIGH", cvss: 8.0, affected: "RabbitMQ 2.x-3.x", recommendation: "Upgrade to RabbitMQ 3.12+" }));
        v.push((Regex::new(r"(?i)wordpress 5\.[0-8]").unwrap(), CVEEntry { id: "CVE-2023-45124", description: "WordPress 5.0-5.8: Outdated and vulnerable", severity: "HIGH", cvss: 8.0, affected: "WordPress 5.x (< 5.9)", recommendation: "Upgrade to WordPress 6.x+" }));
        v.push((Regex::new(r"(?i)drupal [78]\.").unwrap(), CVEEntry { id: "CVE-2018-7600", description: "Drupalgeddon2: Remote code execution in Drupal 7/8", severity: "CRITICAL", cvss: 9.8, affected: "Drupal 7.x, 8.x", recommendation: "Upgrade to Drupal 10+" }));
        v.push((Regex::new(r"(?i)joomla 3\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-23752", description: "Joomla 3.x: Information disclosure vulnerability", severity: "MEDIUM", cvss: 5.3, affected: "Joomla 3.x", recommendation: "Upgrade to Joomla 5.x" }));
        v.push((Regex::new(r"(?i)openvpn").unwrap(), CVEEntry { id: "CVE-2024-27903", description: "OpenVPN: Potential vulnerability detected", severity: "MEDIUM", cvss: 5.0, affected: "OpenVPN", recommendation: "Verify OpenVPN is up-to-date" }));
        v.push((Regex::new(r"(?i)openssl/[0-9]\.[0-9]").unwrap(), CVEEntry { id: "CVE-2023-3817", description: "OpenSSL: Multiple vulnerabilities in older versions", severity: "HIGH", cvss: 7.5, affected: "OpenSSL 1.x-3.x", recommendation: "Upgrade to OpenSSL 3.2+" }));
        v.push((Regex::new(r"(?i)tomcat [89]\.").unwrap(), CVEEntry { id: "CVE-2023-41080", description: "Tomcat 8.x-9.x: Outdated version", severity: "HIGH", cvss: 7.0, affected: "Tomcat 8.x-9.x", recommendation: "Upgrade to Tomcat 10+" }));
        v.push((Regex::new(r"(?i)activemq [56]\.").unwrap(), CVEEntry { id: "CVE-2023-46604", description: "ActiveMQ 5.x-6.x: RCE vulnerability", severity: "CRITICAL", cvss: 9.8, affected: "ActiveMQ 5.x-6.x", recommendation: "Upgrade ActiveMQ to latest" }));
        v
    };
    static ref PORT_RISK_MAP: HashMap<u16, (String, String)> = {
        let mut m = HashMap::new();
        m.insert(21, ("MEDIUM".to_string(), "Exposed FTP service - potential for anonymous access, brute force".to_string()));
        m.insert(22, ("MEDIUM".to_string(), "Exposed SSH service - potential brute force target".to_string()));
        m.insert(23, ("HIGH".to_string(), "Telnet is unencrypted - credentials transmitted in cleartext".to_string()));
        m.insert(25, ("MEDIUM".to_string(), "Exposed SMTP service - potential for email spoofing, relay".to_string()));
        m.insert(53, ("LOW".to_string(), "Exposed DNS service - potential for amplification attacks".to_string()));
        m.insert(80, ("LOW".to_string(), "Exposed HTTP service - standard web traffic".to_string()));
        m.insert(110, ("MEDIUM".to_string(), "Exposed POP3 service - unencrypted email retrieval".to_string()));
        m.insert(111, ("MEDIUM".to_string(), "RPC portmapper - potential for RPC enumeration".to_string()));
        m.insert(135, ("HIGH".to_string(), "MSRPC exposed - potential for remote exploitation".to_string()));
        m.insert(139, ("HIGH".to_string(), "NetBIOS exposed - potential for SMB enumeration".to_string()));
        m.insert(143, ("MEDIUM".to_string(), "Exposed IMAP service - potential for credential brute force".to_string()));
        m.insert(161, ("HIGH".to_string(), "SNMP exposed - potential information disclosure".to_string()));
        m.insert(389, ("MEDIUM".to_string(), "LDAP exposed - potential for directory enumeration".to_string()));
        m.insert(443, ("LOW".to_string(), "Exposed HTTPS service - standard encrypted web traffic".to_string()));
        m.insert(445, ("CRITICAL".to_string(), "SMB exposed - potential for EternalBlue, ransomware entry".to_string()));
        m.insert(500, ("LOW".to_string(), "ISAKMP exposed - potential for VPN fingerprinting".to_string()));
        m.insert(1433, ("HIGH".to_string(), "MSSQL exposed - potential for brute force, SQL injection".to_string()));
        m.insert(1521, ("HIGH".to_string(), "Oracle DB exposed - potential for TNS poisoning".to_string()));
        m.insert(1723, ("MEDIUM".to_string(), "PPTP exposed - potential for VPN credential brute force".to_string()));
        m.insert(2049, ("HIGH".to_string(), "NFS exposed - potential for share enumeration".to_string()));
        m.insert(2375, ("CRITICAL".to_string(), "Docker API unauthenticated - full container compromise".to_string()));
        m.insert(3306, ("HIGH".to_string(), "MySQL exposed - potential for brute force, SQL injection".to_string()));
        m.insert(3389, ("CRITICAL".to_string(), "RDP exposed - potential for BlueKeep, brute force".to_string()));
        m.insert(5432, ("HIGH".to_string(), "PostgreSQL exposed - potential for brute force".to_string()));
        m.insert(5900, ("MEDIUM".to_string(), "VNC exposed - potential for unauthenticated access".to_string()));
        m.insert(5985, ("HIGH".to_string(), "WinRM exposed - potential for credential authentication".to_string()));
        m.insert(5986, ("HIGH".to_string(), "WinRM over SSL exposed - potential for credential authentication".to_string()));
        m.insert(6379, ("HIGH".to_string(), "Redis exposed - potential for RCE via unauthenticated access".to_string()));
        m.insert(8080, ("LOW".to_string(), "HTTP proxy exposed - potential for proxying abuse".to_string()));
        m.insert(8443, ("LOW".to_string(), "HTTPS alt port - standard encrypted traffic".to_string()));
        m.insert(9092, ("LOW".to_string(), "Kafka exposed - potential for topic enumeration".to_string()));
        m.insert(9200, ("HIGH".to_string(), "Elasticsearch exposed - potential for data access".to_string()));
        m.insert(11211, ("MEDIUM".to_string(), "Memcached exposed - potential for amplification attacks".to_string()));
        m.insert(27017, ("CRITICAL".to_string(), "MongoDB exposed - potential for data theft (Shodan IoT)".to_string()));
        m
    };
}

#[derive(Debug, Serialize, Clone)]
struct CVEEntry {
    id: &'static str,
    description: &'static str,
    severity: &'static str,
    cvss: f64,
    affected: &'static str,
    recommendation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct VulnResult {
    port: u16,
    protocol: String,
    service: String,
    banner: String,
    vulnerabilities: Vec<CVEMatch>,
    risk_assessment: PortRisk,
}

#[derive(Debug, Clone, Serialize)]
struct CVEMatch {
    cve_id: String,
    description: String,
    severity: String,
    cvss: f64,
    affected: String,
    recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
struct PortRisk {
    risk_level: String,
    risk_description: String,
    warning: String,
}

#[derive(Debug, Serialize)]
struct FinalVulnSummary {
    target: String,
    total_ports: usize,
    total_vulnerabilities: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    elapsed_ms: u64,
}

#[inline]
fn get_probes(port: u16) -> Vec<Vec<u8>> {
    match port {
        80 | 443 | 8080 | 8443 | 8000 | 8888 => {
            vec![
                b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-VulnScan/3.0\r\n\r\n".to_vec(),
                b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            ]
        }
        21 => vec![b"SYST\r\n".to_vec(), b"FEAT\r\n".to_vec()],
        22 => vec![b"SSH-2.0-HackIT-VulnScan\r\n".to_vec()],
        25 | 465 | 587 => vec![b"EHLO hackit.vulnscan\r\n".to_vec()],
        3306 => vec![b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        5432 => vec![b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec()],
        6379 => vec![b"INFO\r\n".to_vec(), b"PING\r\n".to_vec()],
        27017 => vec![b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec()],
        11211 => vec![b"stats\r\n".to_vec()],
        5900 => vec![b"RFB 003.008\n".to_vec()],
        3389 => vec![b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec()],
        1433 => vec![b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00".to_vec()],
        1521 => vec![b"\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x32\x01\x2c\x00\x00\x08\x00\x7f\xff\x7f\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()],
        9200 => vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()],
        9090 => vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()],
        2375 => vec![b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()],
        _ => vec![b"\r\n\r\n".to_vec()],
    }
}

#[inline]
fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    let probes = get_probes(port);
    let mut best_banner = String::new();
    for probe in probes {
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| format!("{}:{}", host, port).parse().unwrap()),
            Duration::from_millis(timeout_ms)
        ) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
            if !probe.is_empty() {
                let _ = stream.write_all(&probe);
                let _ = stream.flush();
            }
            let mut buffer = [0u8; MAX_BANNER];
            match stream.read(&mut buffer) {
                Ok(bytes_read) if bytes_read > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                    if response.len() > best_banner.len() {
                        best_banner = response.to_string();
                    }
                }
                _ => continue,
            }
        }
    }
    best_banner.chars()
        .filter(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .take(1024)
        .collect::<String>()
        .trim()
        .to_string()
}

#[inline]
fn detect_vulnerabilities(banner: &str) -> Vec<CVEMatch> {
    let mut vulns = Vec::new();
    for (re, entry) in CVE_SIGNATURES.iter() {
        if re.is_match(banner) {
            vulns.push(CVEMatch {
                cve_id: entry.id.to_string(),
                description: entry.description.to_string(),
                severity: entry.severity.to_string(),
                cvss: entry.cvss,
                affected: entry.affected.to_string(),
                recommendation: entry.recommendation.to_string(),
            });
        }
    }
    vulns.sort_by(|a, b| b.cvss.partial_cmp(&a.cvss).unwrap_or(std::cmp::Ordering::Equal));
    vulns
}

fn assess_port_risk(port: u16, banner: &str, vulns: &[CVEMatch]) -> PortRisk {
    if !vulns.is_empty() {
        let max_cvss = vulns.iter().map(|v| v.cvss).fold(0.0, f64::max);
        let level = if max_cvss >= 9.0 { "CRITICAL" }
            else if max_cvss >= 7.0 { "HIGH" }
            else if max_cvss >= 4.0 { "MEDIUM" }
            else { "LOW" };
        return PortRisk {
            risk_level: level.to_string(),
            risk_description: format!("{} CVE match(es) found with CVSS score up to {}", vulns.len(), max_cvss),
            warning: "Vulnerabilities detected - immediate attention recommended".to_string(),
        };
    }
    if let Some((risk_level, risk_desc)) = PORT_RISK_MAP.get(&port) {
        PortRisk {
            risk_level: risk_level.clone(),
            risk_description: risk_desc.clone(),
            warning: match risk_level.as_str() {
                "CRITICAL" => "Critical service exposed - immediate action required".to_string(),
                "HIGH" => "High risk service - restrict access or disable if not needed".to_string(),
                "MEDIUM" => "Moderate risk - consider restricting access".to_string(),
                _ => "Low risk - standard service".to_string(),
            },
        }
    } else {
        PortRisk {
            risk_level: "INFO".to_string(),
            risk_description: format!("Port {} is open with no specific risk assessment", port),
            warning: "Routine security check recommended".to_string(),
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--ports" | "-p" => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--help" | "-h" => {
                eprintln!("Usage: {} --target <host> --ports <ports> [--timeout <ms>]", args[0]);
                eprintln!("  Scans for 50+ CVE signatures in service banners");
                eprintln!("  Provides port-based risk assessment");
                eprintln!("  Outputs vulnerabilities with CVSS scores");
                std::process::exit(0);
            }
            _ => {
                if target.is_empty() { target = args[i].clone(); }
                else if port_spec.is_empty() { port_spec = args[i].clone(); }
            }
        }
        i += 1;
    }
    if target.is_empty() || port_spec.is_empty() {
        eprintln!("Usage: {} <target> <ports> [timeout_ms]", args[0]);
        eprintln!("Example: {} scanme.nmap.org 22,80,443,3306 3000", args[0]);
        std::process::exit(1);
    }
    let ports = parse_ports(&port_spec);
    if ports.is_empty() { eprintln!("Error: no valid ports"); std::process::exit(1); }
    eprintln!("VULN_SCAN target={} ports={} timeout={}ms", target, ports.len(), timeout_ms);
    let start = Instant::now();
    let total = ports.len();
    let mut all_vulns: Vec<VulnResult> = Vec::with_capacity(total);
    let mut counts = (0usize, 0usize, 0usize, 0usize, 0usize);
    let vuln_results: Vec<VulnResult> = ports.par_iter()
        .map(|&port| {
            let banner = grab_banner(&target, port, timeout_ms);
            let vulns = detect_vulnerabilities(&banner);
            let risk = assess_port_risk(port, &banner, &vulns);
            let svc = service_for_port(port);
            VulnResult {
                port,
                protocol: "tcp".to_string(),
                service: svc.to_string(),
                banner: banner.chars().take(300).collect(),
                vulnerabilities: vulns,
                risk_assessment: risk,
            }
        })
        .collect();
    for result in &vuln_results {
        for v in &result.vulnerabilities {
            match v.severity.as_str() {
                "CRITICAL" => counts.0 += 1,
                "HIGH" => counts.1 += 1,
                "MEDIUM" => counts.2 += 1,
                "LOW" => counts.3 += 1,
                _ => counts.4 += 1,
            }
        }
    }
    for result in &vuln_results {
        println!("RESULT:{}", serde_json::to_string(result).unwrap());
        all_vulns.push(result.clone());
    }
    let elapsed = start.elapsed().as_millis() as u64;
    let total_vulns: usize = all_vulns.iter().map(|r| r.vulnerabilities.len()).sum();
    let summary = FinalVulnSummary {
        target: target.clone(),
        total_ports: ports.len(),
        total_vulnerabilities: total_vulns,
        critical: counts.0,
        high: counts.1,
        medium: counts.2,
        low: counts.3,
        info: counts.4,
        elapsed_ms: elapsed,
    };
    println!("FINAL:{}", serde_json::to_string(&summary).unwrap());
}
