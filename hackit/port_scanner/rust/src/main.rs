use futures::stream::{self, StreamExt};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (String, Instant)>> = RwLock::new(HashMap::new());
    static ref PROTOCOL_PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(25, b"EHLO hackit.local\r\n".to_vec());
        m.insert(587, b"EHLO hackit.local\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n".to_vec());
        m.insert(8000, b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n".to_vec());
        m.insert(8888, b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(6379, b"INFO server\r\n".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(873, b"@RSYNCD: 31.0\n".to_vec());
        m.insert(22, Vec::new());
        m.insert(443, Vec::new());
        m.insert(8443, Vec::new());
        m.insert(3306, Vec::new());
        m.insert(5432, Vec::new());
        m.insert(27017, Vec::new());
        m
    };

    static ref SERVICE_SIGNATURES: Vec<(&'static str, &'static str, &'static str, &'static str, u16)> = {
        let mut s: Vec<(&'static str, &'static str, &'static str, &'static str, u16)> = Vec::new();

        // SSH
        s.push((r"OpenSSH_(\d+\.\d+)", "SSH", "OpenSSH", "", 22));
        s.push((r"dropbear_(\d+\.\d+)", "SSH", "Dropbear", "", 22));
        s.push((r"SSH-\d+\.\d+-Cisco", "SSH", "Cisco SSH", "Cisco IOS", 22));
        s.push((r"libssh-(\d+\.\d+)", "SSH", "libssh", "", 22));
        s.push((r"PuTTY_Release_(\d+\.\d+)", "SSH", "PuTTY", "Windows", 22));
        s.push((r"BitviseSSH", "SSH", "Bitvise SSH", "Windows", 22));
        s.push((r"OpenSSH.*Win32", "SSH", "OpenSSH", "Windows", 22));
        s.push((r"OpenSSH.*freebsd", "SSH", "OpenSSH", "FreeBSD", 22));
        s.push((r"OpenSSH.*Debian", "SSH", "OpenSSH", "Debian", 22));
        s.push((r"OpenSSH.*Ubuntu", "SSH", "OpenSSH", "Ubuntu", 22));

        // HTTP
        s.push((r"Apache/(\d+\.\d+\.\d+)", "HTTP", "Apache HTTP Server", "", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+)", "HTTP", "Apache HTTP Server", "", 8080));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(CentOS", "HTTP", "Apache HTTP Server", "CentOS", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(Red Hat", "HTTP", "Apache HTTP Server", "Red Hat", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(Debian", "HTTP", "Apache HTTP Server", "Debian", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(Ubuntu", "HTTP", "Apache HTTP Server", "Ubuntu", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(FreeBSD", "HTTP", "Apache HTTP Server", "FreeBSD", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(Win32", "HTTP", "Apache HTTP Server", "Windows", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+) \(Unix", "HTTP", "Apache HTTP Server", "Unix", 80));
        s.push((r"nginx/(\d+\.\d+\.\d+)", "HTTP", "nginx", "", 80));
        s.push((r"nginx", "HTTP", "nginx", "", 80));
        s.push((r"nginx/(\d+\.\d+\.\d+)", "HTTP", "nginx", "", 8080));
        s.push((r"IIS/(\d+\.\d+)", "HTTP", "IIS", "Windows", 80));
        s.push((r"Microsoft-IIS/(\d+\.\d+)", "HTTP", "IIS", "Windows", 80));
        s.push((r"LiteSpeed", "HTTP", "LiteSpeed", "", 80));
        s.push((r"lighttpd/(\d+\.\d+\.\d+)", "HTTP", "Lighttpd", "", 80));
        s.push((r"Caddy", "HTTP", "Caddy", "", 80));
        s.push((r"cowboy", "HTTP", "Cowboy", "", 80));
        s.push((r"GWS", "HTTP", "Google Web Server", "", 80));
        s.push((r"cloudflare", "HTTP", "Cloudflare", "", 80));
        s.push((r"Jetty\((\d+\.\d+\.\d+)", "HTTP", "Jetty", "", 80));
        s.push((r"gunicorn", "HTTP", "Gunicorn", "", 80));
        s.push((r"uvicorn", "HTTP", "Uvicorn", "", 80));
        s.push((r"Werkzeug", "HTTP", "Werkzeug", "", 80));
        s.push((r"Cherokee", "HTTP", "Cherokee", "", 80));
        s.push((r"Node\.?js", "HTTP", "Node.js", "", 80));
        s.push((r"GlassFish", "HTTP", "GlassFish", "", 80));
        s.push((r"WildFly", "HTTP", "WildFly", "", 80));
        s.push((r"TornadoServer", "HTTP", "Tornado", "", 80));
        s.push((r"PHP/(\d+\.\d+\.\d+)", "HTTP", "PHP", "", 80));
        s.push((r"ASP\.NET", "HTTP", "ASP.NET", "Windows", 80));
        s.push((r"Kestrel", "HTTP", "Kestrel", "Windows", 80));
        s.push((r"Express", "HTTP", "Express", "", 80));

        // FTP
        s.push((r"vsFTPd (\d+\.\d+\.\d+)", "FTP", "vsFTPd", "", 21));
        s.push((r"vsFTPd", "FTP", "vsFTPd", "", 21));
        s.push((r"ProFTPD (\d+\.\d+\.\d+)", "FTP", "ProFTPD", "", 21));
        s.push((r"ProFTPD", "FTP", "ProFTPD", "", 21));
        s.push((r"FileZilla Server (\d+\.\d+\.\d+)", "FTP", "FileZilla Server", "Windows", 21));
        s.push((r"FileZilla", "FTP", "FileZilla Server", "Windows", 21));
        s.push((r"Pure-FTPd", "FTP", "Pure-FTPd", "", 21));
        s.push((r"Microsoft FTP Service", "FTP", "Microsoft FTP", "Windows", 21));
        s.push((r"Wu-FTPd", "FTP", "Wu-FTPd", "", 21));
        s.push((r"glFTPd", "FTP", "glFTPd", "", 21));
        s.push((r"Serv-U FTP Server", "FTP", "Serv-U", "Windows", 21));
        s.push((r"Cerberus FTP Server", "FTP", "Cerberus", "Windows", 21));
        s.push((r"BulletProof FTP Server", "FTP", "BulletProof", "Windows", 21));
        s.push((r"Titan FTP Server", "FTP", "Titan", "Windows", 21));
        s.push((r"Apache FtpServer", "FTP", "Apache FtpServer", "", 21));

        // SMTP
        s.push((r"Postfix", "SMTP", "Postfix", "", 25));
        s.push((r"Exim (\d+\.\d+)", "SMTP", "Exim", "", 25));
        s.push((r"Exim", "SMTP", "Exim", "", 25));
        s.push((r"Sendmail (\d+\.\d+\.\d+)", "SMTP", "Sendmail", "", 25));
        s.push((r"Sendmail", "SMTP", "Sendmail", "", 25));
        s.push((r"Microsoft ESMTP MAIL Service", "SMTP", "Microsoft Exchange", "Windows", 25));
        s.push((r"MailEnable", "SMTP", "MailEnable", "Windows", 25));
        s.push((r"qmail", "SMTP", "Qmail", "", 25));
        s.push((r"Courier", "SMTP", "Courier", "", 25));
        s.push((r"OpenSMTPD", "SMTP", "OpenSMTPD", "", 25));
        s.push((r"IceWarp", "SMTP", "IceWarp", "", 25));
        s.push((r"Zimbra", "SMTP", "Zimbra", "", 25));

        // POP3
        s.push((r"Dovecot.*ready", "POP3", "Dovecot", "", 110));
        s.push((r"Courier", "POP3", "Courier", "", 110));
        s.push((r"Qpopper", "POP3", "Qpopper", "", 110));
        s.push((r"Microsoft.*POP3", "POP3", "Microsoft POP3", "Windows", 110));
        s.push((r"Cyrus.*POP3", "POP3", "Cyrus", "", 110));
        s.push((r"MailEnable.*POP3", "POP3", "MailEnable", "Windows", 110));

        // IMAP
        s.push((r"Dovecot.*ready", "IMAP", "Dovecot", "", 143));
        s.push((r"Courier", "IMAP", "Courier", "", 143));
        s.push((r"Cyrus.*IMAP", "IMAP", "Cyrus", "", 143));
        s.push((r"Microsoft.*IMAP", "IMAP", "Microsoft Exchange", "Windows", 143));
        s.push((r"Zimbra", "IMAP", "Zimbra", "", 143));
        s.push((r"MailEnable.*IMAP", "IMAP", "MailEnable", "Windows", 143));

        // MySQL/MariaDB
        s.push((r"mysql_native_password", "MySQL", "MySQL", "", 3306));
        s.push((r"5\.5\.\d+", "MySQL", "MySQL 5.5", "", 3306));
        s.push((r"5\.6\.\d+", "MySQL", "MySQL 5.6", "", 3306));
        s.push((r"5\.7\.\d+", "MySQL", "MySQL 5.7", "", 3306));
        s.push((r"8\.\d+\.\d+", "MySQL", "MySQL 8.x", "", 3306));
        s.push((r"10\.\d+\.\d+.*MariaDB", "MariaDB", "MariaDB 10.x", "", 3306));
        s.push((r"MariaDB", "MariaDB", "MariaDB", "", 3306));

        // PostgreSQL
        s.push((r"PostgreSQL", "PostgreSQL", "PostgreSQL", "", 5432));

        // Redis
        s.push((r"redis_version:(\d+\.\d+\.\d+)", "Redis", "Redis", "", 6379));
        s.push((r"redis_mode:(\w+)", "Redis", "Redis", "", 6379));
        s.push((r"role:(\w+)", "Redis", "Redis", "", 6379));

        // MongoDB
        s.push((r"MongoDB", "MongoDB", "MongoDB", "", 27017));

        // CouchDB
        s.push((r"CouchDB", "CouchDB", "CouchDB", "", 5984));

        // Elasticsearch
        s.push((r"[Ee]lasticsearch", "Elasticsearch", "Elasticsearch", "", 9200));

        // Memcached
        s.push((r"STAT pid", "Memcached", "Memcached", "", 11211));

        // Cassandra
        s.push((r"Cassandra", "Cassandra", "Cassandra", "", 9042));

        // Docker
        s.push((r"Docker", "Docker", "Docker", "", 2375));
        s.push((r"Docker", "Docker", "Docker", "", 2376));

        // Kubernetes
        s.push((r"kubernetes", "Kubernetes", "Kubernetes", "", 6443));
        s.push((r"kube-apiserver", "Kubernetes", "Kubernetes", "", 6443));

        // etcd
        s.push((r"etcd", "etcd", "etcd", "", 2379));
        s.push((r"etcd", "etcd", "etcd", "", 2380));

        // CI/CD
        s.push((r"Jenkins|X-Jenkins", "CI/CD", "Jenkins", "", 8080));
        s.push((r"GitLab", "CI/CD", "GitLab", "", 80));
        s.push((r"Gitea", "CI/CD", "Gitea", "", 3000));
        s.push((r"Nexus Repository", "CI/CD", "Nexus", "", 8081));
        s.push((r"Artifactory", "CI/CD", "Artifactory", "", 8081));

        // MQ
        s.push((r"RabbitMQ", "MQ", "RabbitMQ", "", 5672));
        s.push((r"RabbitMQ", "MQ", "RabbitMQ", "", 15672));
        s.push((r"ActiveMQ", "MQ", "ActiveMQ", "", 61616));
        s.push((r"kafka", "MQ", "Kafka", "", 9092));
        s.push((r"NATS", "MQ", "NATS", "", 4222));

        // Monitoring
        s.push((r"Prometheus", "Monitoring", "Prometheus", "", 9090));
        s.push((r"Grafana", "Monitoring", "Grafana", "", 3000));
        s.push((r"Nagios", "Monitoring", "Nagios", "", 80));
        s.push((r"Zabbix", "Monitoring", "Zabbix", "", 80));
        s.push((r"CheckMK", "Monitoring", "CheckMK", "", 80));

        // Proxies
        s.push((r"HAProxy", "Proxy", "HAProxy", "", 80));
        s.push((r"Squid", "Proxy", "Squid", "", 3128));
        s.push((r"Varnish", "Proxy", "Varnish", "", 80));
        s.push((r"Traefik", "Proxy", "Traefik", "", 80));
        s.push((r"Envoy", "Proxy", "Envoy", "", 80));

        // VPN
        s.push((r"OpenVPN", "VPN", "OpenVPN", "", 1194));
        s.push((r"WireGuard", "VPN", "WireGuard", "", 51820));
        s.push((r"StrongSwan", "VPN", "StrongSwan", "", 500));

        // Embedded
        s.push((r"OpenWrt", "Embedded", "OpenWrt", "OpenWrt", 80));
        s.push((r"DD-WRT|dd.wrt", "Embedded", "DD-WRT", "DD-WRT", 80));
        s.push((r"pfSense", "Embedded", "pfSense", "pfSense", 80));
        s.push((r"OPNsense", "Embedded", "OPNsense", "OPNsense", 80));

        // Misc
        s.push((r"@RSYNCD:", "Misc", "rsync", "", 873));
        s.push((r"ZooKeeper", "Misc", "ZooKeeper", "", 2181));
        s.push((r"Consul", "Misc", "Consul", "", 8500));
        s.push((r"Vault", "Misc", "Vault", "", 8200));
        s.push((r"Plex", "Misc", "Plex", "", 32400));
        s.push((r"Bitcoin", "Misc", "Bitcoin", "", 8332));
        s.push((r"Bitcoin", "Misc", "Bitcoin", "", 8333));
        s.push((r"Minecraft", "Misc", "Minecraft", "", 25565));
        s.push((r"git", "Misc", "Git Daemon", "", 9418));
        s.push((r"EPMD", "Misc", "EPMD (Erlang)", "", 4369));
        s.push((r"JetDirect", "Misc", "JetDirect", "", 9100));

        s
    };

    static ref OS_PATTERNS: Vec<(&'static str, &'static str, f64)> = {
        let mut o: Vec<(&'static str, &'static str, f64)> = Vec::new();
        o.push((r"Windows NT 10\.0", "Windows 10/11", 95.0));
        o.push((r"Windows NT 6\.3", "Windows 8.1/Server 2012 R2", 90.0));
        o.push((r"Windows NT 6\.2", "Windows 8/Server 2012", 90.0));
        o.push((r"Windows NT 6\.1", "Windows 7/Server 2008 R2", 90.0));
        o.push((r"Windows NT 6\.0", "Windows Vista/Server 2008", 90.0));
        o.push((r"Windows NT 5\.\d+", "Windows 2000/XP/2003", 90.0));
        o.push((r"Win32|Win64|Windows", "Windows", 70.0));
        o.push((r"(?i)ubuntu", "Ubuntu", 90.0));
        o.push((r"(?i)debian", "Debian", 90.0));
        o.push((r"(?i)centos", "CentOS", 90.0));
        o.push((r"Red Hat|redhat", "Red Hat Enterprise Linux", 90.0));
        o.push((r"(?i)fedora", "Fedora", 90.0));
        o.push((r"(?i)suse", "SUSE Linux", 85.0));
        o.push((r"(?i)freebsd", "FreeBSD", 95.0));
        o.push((r"(?i)openbsd", "OpenBSD", 95.0));
        o.push((r"(?i)netbsd", "NetBSD", 95.0));
        o.push((r"(?i)darwin", "macOS (Darwin)", 95.0));
        o.push((r"Cisco IOS", "Cisco IOS", 95.0));
        o.push((r"Cisco ASA", "Cisco ASA", 95.0));
        o.push((r"(?i)juniper", "Juniper", 90.0));
        o.push((r"(?i)mikrotik", "MikroTik RouterOS", 90.0));
        o.push((r"(?i)ubiquiti", "Ubiquiti", 85.0));
        o.push((r"Palo Alto", "Palo Alto Networks", 90.0));
        o.push((r"(?i)fortinet", "Fortinet", 90.0));
        o.push((r"(?i)openwrt", "OpenWrt", 90.0));
        o.push((r"DD-WRT|dd.wrt", "DD-WRT", 90.0));
        o.push((r"(?i)pfsense", "pfSense", 90.0));
        o.push((r"(?i)opnsense", "OPNsense", 90.0));
        o.push((r"(?i)synology", "Synology DSM", 90.0));
        o.push((r"(?i)qnap", "QNAP", 85.0));
        o.push((r"(?i)vmware", "VMware", 90.0));
        o.push((r"(?i)proxmox", "Proxmox VE", 90.0));
        o.push((r"Raspberry Pi", "Raspberry Pi OS", 85.0));
        o.push((r"(?i)alpine", "Alpine Linux", 85.0));
        o.push((r"(?i)archlinux", "Arch Linux", 85.0));
        o.push((r"(?i)gentoo", "Gentoo", 85.0));
        o
    };
}

#[derive(Debug, Clone, Serialize)]
struct ScanResult {
    port: u16,
    state: String,
    protocol: Option<String>,
    product: Option<String>,
    version: Option<String>,
    os_hint: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct JsonOutput {
    host: String,
    scan_time_ms: u64,
    ports_scanned: usize,
    ports_open: usize,
    results: Vec<ScanResult>,
}

fn resolve_host(host: &str) -> Option<String> {
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ip, expiry)) = cache.get(host) {
            if expiry.elapsed() < DNS_CACHE_TTL {
                return Some(ip.clone());
            }
        }
    }
    let addr = format!("{}:0", host);
    if let Some(ok) = addr.to_socket_addrs().ok()?.find(|a| a.is_ipv4()) {
        let ip = ok.ip().to_string();
        let mut cache = DNS_CACHE.write().unwrap();
        cache.insert(host.to_string(), (ip.clone(), Instant::now()));
        Some(ip)
    } else {
        None
    }
}

#[inline]
fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::with_capacity(1024);

    match input.trim().to_lowercase().as_str() {
        "all" => return (1..=65535).collect(),
        "top100" => {
            return vec![
                7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
                135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543,
                544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
                1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
                3306, 3389, 3986, 4000, 4001, 4662, 4899, 5000, 5001, 5050, 5060, 5101, 5190,
                5357, 5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
                8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49154,
            ];
        }
        _ => {}
    }

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.trim().parse().unwrap_or(1);
            let e: u16 = end.trim().parse().unwrap_or(65535);
            for p in s..=e {
                ports.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }

    ports.sort();
    ports.dedup();
    ports
}

#[inline]
async fn connect_with_timeout(host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream, String> {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(_) => Err("timeout".to_string()),
    }
}

async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> String {
    let stream = match connect_with_timeout(host, port, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return String::new(),
    };

    let (mut reader, mut writer) = stream.into_split();
    let probe = PROTOCOL_PROBES.get(&port).cloned().unwrap_or_default();

    if !probe.is_empty() {
        let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(&probe)).await;
    }

    let mut buf = vec![0u8; 4096];
    match timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => String::new(),
    }
}

#[inline]
fn compile_regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

#[inline]
fn match_service_signatures(port: u16, banner: &str) -> Vec<(&'static str, &'static str, &'static str, &'static str, Option<String>)> {
    let mut matched = Vec::new();
    for &(pattern, proto, product, os_hint, sig_port) in SERVICE_SIGNATURES.iter() {
        if sig_port != port {
            continue;
        }
        let re = compile_regex(pattern);
        if let Some(caps) = re.captures(banner) {
            let version = caps.get(1).map(|m| m.as_str().to_string());
            matched.push((proto, product, os_hint, pattern, version));
        }
    }
    matched
}

#[inline]
fn detect_os(banner: &str) -> (String, f64) {
    for &(pattern, os, confidence) in OS_PATTERNS.iter() {
        let re = compile_regex(pattern);
        if re.is_match(banner) {
            return (os.to_string(), confidence);
        }
    }
    ("Unknown".to_string(), 0.0)
}

fn top_match(
    matches: &[(&'static str, &'static str, &'static str, &'static str, Option<String>)],
) -> Option<(&'static str, &'static str, &'static str, Option<String>)> {
    matches.first().map(|&(proto, product, os_hint, _, ref ver)| {
        (proto, product, os_hint, ver.clone())
    })
}

async fn scan_port(host: &str, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    connect_with_timeout(host, port, timeout_ms).await.ok()?;

    let banner = grab_banner(host, port, timeout_ms).await;
    let matches = match_service_signatures(port, &banner);
    let (os_name, _) = detect_os(&banner);

    let os_hint = if os_name != "Unknown" {
        Some(os_name)
    } else {
        matches
            .iter()
            .find(|&&(_, _, os, _, _)| !os.is_empty())
            .map(|&(_, _, os, _, _)| os.to_string())
    };

    let (protocol, product, version) = if let Some((proto, prod, _os, ver)) = top_match(&matches) {
        (Some(proto.to_string()), Some(prod.to_string()), ver)
    } else {
        (None, None, None)
    };

    let banner_clean = if banner.len() > 200 {
        Some(format!("{}...", &banner[..200]))
    } else if banner.is_empty() {
        None
    } else {
        Some(banner)
    };

    Some(ScanResult {
        port,
        state: "open".to_string(),
        protocol,
        product,
        version,
        os_hint,
        banner: banner_clean,
    })
}

async fn scan_target(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<ScanResult> {
    let results = std::sync::Arc::new(Mutex::new(Vec::new()));

    stream::iter(ports.iter().copied())
        .map(|port| {
            let host = host.to_string();
            let results = std::sync::Arc::clone(&results);
            async move {
                if let Some(r) = scan_port(&host, port, timeout_ms).await {
                    let mut guard = results.lock().await;
                    guard.push(r);
                }
            }
        })
        .buffer_unordered(concurrency)
        .collect::<Vec<()>>()
        .await;

    let mut guard = results.lock().await;
    guard.sort_by(|a, b| a.port.cmp(&b.port));
    guard.clone()
}

fn print_text(results: &[ScanResult], host: &str, elapsed_ms: u64) {
    let open = results.iter().filter(|r| r.state == "open").count();
    println!(
        "\nResults for {} ({} ports, {} open, {:.2}s)",
        host,
        results.len(),
        open,
        elapsed_ms as f64 / 1000.0
    );
    println!("{:-<72}", "");
    println!("{:<8} {:<8} {:<14} {:<20} {:<8}", "PORT", "STATE", "SERVICE", "PRODUCT", "OS");
    println!("{:-<72}", "");
    for r in results {
        println!(
            "{:<8} {:<8} {:<14} {:<20} {:<8}",
            format!("{}/tcp", r.port),
            r.state,
            r.protocol.as_deref().unwrap_or("-"),
            r.product.as_deref().unwrap_or("-"),
            r.os_hint.as_deref().unwrap_or("-"),
        );
    }
    println!("{:-<72}", "");
    for r in results {
        if let Some(ref v) = r.version {
            println!("  Port {} version: {}", r.port, v);
        }
        if let Some(ref b) = r.banner {
            println!("  Port {} banner: {}", r.port, b);
        }
    }
}

fn print_json(results: &[ScanResult], host: &str, elapsed_ms: u64) {
    let open = results.iter().filter(|r| r.state == "open").count();
    let output = JsonOutput {
        host: host.to_string(),
        scan_time_ms: elapsed_ms,
        ports_scanned: results.len(),
        ports_open: open,
        results: results.to_vec(),
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <ports> [timeout_ms] [format:text|json] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top100, all");
        eprintln!("  timeout_ms: connection timeout (default 1500)");
        eprintln!("  format: text (default) or json");
        eprintln!("  concurrency:N: max parallel scans (default 100)");
        std::process::exit(1);
    }

    let host = &args[1];
    let ports = parse_ports(&args[2]);

    let mut timeout_ms: u64 = 1500;
    let mut output_format = "text";
    let mut concurrency: usize = 100;

    for arg in &args[3..] {
        if let Ok(ms) = arg.parse::<u64>() {
            timeout_ms = ms;
        } else if let Some(n) = arg.strip_prefix("concurrency:") {
            if let Ok(c) = n.parse::<usize>() {
                concurrency = c.max(1);
            }
        } else {
            output_format = arg;
        }
    }

    if ports.is_empty() {
        eprintln!("No valid ports specified");
        std::process::exit(1);
    }

    eprintln!(
        "Scanning {} ({} ports, timeout={}ms, concurrency={})...",
        host,
        ports.len(),
        timeout_ms,
        concurrency
    );

    let start = std::time::Instant::now();
    let results = scan_target(host, &ports, timeout_ms, concurrency).await;
    let elapsed = start.elapsed().as_millis() as u64;

    if output_format == "json" {
        print_json(&results, host, elapsed);
    } else {
        print_text(&results, host, elapsed);
    }
}
