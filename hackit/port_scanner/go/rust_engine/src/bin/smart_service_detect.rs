use rust_port_scanner::*;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const DEFAULT_CONCURRENCY: usize = 50;

#[derive(Debug, Clone)]
struct ServiceSig {
    port: u16,
    keywords: Vec<&'static str>,
    name: &'static str,
    category: &'static str,
    confidence: u8,
    version_hint: Option<&'static str>,
}

lazy_static::lazy_static! {
    static ref SERVICE_SIGNATURES: Vec<ServiceSig> = {
        let mut v = Vec::with_capacity(256);
        v.push(ServiceSig { port: 22, keywords: vec!["openssh_", "ssh-2.0-", "ssh-1.99-"], name: "OpenSSH", category: "remote-access", confidence: 90, version_hint: Some("openssh_") });
        v.push(ServiceSig { port: 22, keywords: vec!["dropbear_"], name: "Dropbear SSH", category: "remote-access", confidence: 95, version_hint: Some("dropbear_") });
        v.push(ServiceSig { port: 22, keywords: vec!["libssh"], name: "libssh", category: "remote-access", confidence: 85, version_hint: Some("libssh_") });
        v.push(ServiceSig { port: 21, keywords: vec!["vsftpd"], name: "vsftpd", category: "ftp", confidence: 90, version_hint: Some("vsftpd") });
        v.push(ServiceSig { port: 21, keywords: vec!["proftpd"], name: "ProFTPD", category: "ftp", confidence: 90, version_hint: Some("proftpd") });
        v.push(ServiceSig { port: 21, keywords: vec!["pure-ftpd"], name: "Pure-FTPd", category: "ftp", confidence: 90, version_hint: Some("pure-ftpd") });
        v.push(ServiceSig { port: 21, keywords: vec!["filezilla"], name: "FileZilla FTP", category: "ftp", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 21, keywords: vec!["microsoft ftp", "msftp"], name: "MS FTP", category: "ftp", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["apache/", "apache-"], name: "Apache HTTPD", category: "http", confidence: 95, version_hint: Some("apache/") });
        v.push(ServiceSig { port: 80, keywords: vec!["nginx/", "nginx-"], name: "nginx", category: "http", confidence: 95, version_hint: Some("nginx/") });
        v.push(ServiceSig { port: 80, keywords: vec!["microsoft-iis/", "iis/"], name: "IIS", category: "http", confidence: 95, version_hint: Some("microsoft-iis/") });
        v.push(ServiceSig { port: 80, keywords: vec!["lighttpd/"], name: "Lighttpd", category: "http", confidence: 90, version_hint: Some("lighttpd/") });
        v.push(ServiceSig { port: 80, keywords: vec!["litespeed"], name: "LiteSpeed", category: "http", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["openresty/"], name: "OpenResty", category: "http", confidence: 90, version_hint: Some("openresty/") });
        v.push(ServiceSig { port: 80, keywords: vec!["caddy/"], name: "Caddy", category: "http", confidence: 90, version_hint: Some("caddy/") });
        v.push(ServiceSig { port: 80, keywords: vec!["tomcat"], name: "Tomcat", category: "http", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["gunicorn"], name: "Gunicorn", category: "http", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["jetty"], name: "Jetty", category: "http", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["cherokee"], name: "Cherokee", category: "http", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["php/"], name: "PHP", category: "http", confidence: 70, version_hint: Some("php/") });
        v.push(ServiceSig { port: 80, keywords: vec!["cloudflare"], name: "Cloudflare", category: "http", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["akamai"], name: "Akamai", category: "http", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 80, keywords: vec!["node.js", "nodejs"], name: "Node.js", category: "http", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 443, keywords: vec!["apache/", "apache-"], name: "Apache HTTPD (TLS)", category: "http", confidence: 95, version_hint: Some("apache/") });
        v.push(ServiceSig { port: 443, keywords: vec!["nginx/", "nginx-"], name: "nginx (TLS)", category: "http", confidence: 95, version_hint: Some("nginx/") });
        v.push(ServiceSig { port: 443, keywords: vec!["cloudflare"], name: "Cloudflare (TLS)", category: "http", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 443, keywords: vec!["microsoft-iis/"], name: "IIS (TLS)", category: "http", confidence: 90, version_hint: Some("microsoft-iis/") });
        v.push(ServiceSig { port: 25, keywords: vec!["postfix"], name: "Postfix", category: "mail", confidence: 90, version_hint: Some("postfix") });
        v.push(ServiceSig { port: 25, keywords: vec!["exim"], name: "Exim", category: "mail", confidence: 90, version_hint: Some("exim") });
        v.push(ServiceSig { port: 25, keywords: vec!["sendmail"], name: "Sendmail", category: "mail", confidence: 85, version_hint: Some("sendmail") });
        v.push(ServiceSig { port: 25, keywords: vec!["microsoft esmtp", "exchange"], name: "MS Exchange", category: "mail", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 25, keywords: vec!["qmail"], name: "qmail", category: "mail", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 110, keywords: vec!["+ok pop", "pop3", "apop"], name: "POP3", category: "mail", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 143, keywords: vec!["* ok", "imap"], name: "IMAP", category: "mail", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 3306, keywords: vec!["mysql", "mariadb"], name: "MySQL/MariaDB", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 3306, keywords: vec!["percona"], name: "Percona MySQL", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 5432, keywords: vec!["postgresql", "postgres"], name: "PostgreSQL", category: "database", confidence: 90, version_hint: Some("postgresql") });
        v.push(ServiceSig { port: 6379, keywords: vec!["redis_version", "redis_mode", "+ok"], name: "Redis", category: "database", confidence: 90, version_hint: Some("redis_version:") });
        v.push(ServiceSig { port: 27017, keywords: vec!["mongodb"], name: "MongoDB", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 9200, keywords: vec!["elasticsearch", "cluster_name"], name: "Elasticsearch", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 11211, keywords: vec!["stat pid", "stat curr", "stats"], name: "Memcached", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 9042, keywords: vec!["cassandra"], name: "Cassandra", category: "database", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 5984, keywords: vec!["couchdb"], name: "CouchDB", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 1433, keywords: vec!["microsoft sql", "mssql"], name: "MSSQL", category: "database", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 1521, keywords: vec!["oracle"], name: "Oracle DB", category: "database", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 5900, keywords: vec!["rfb 00", "rfb 003", "rfb 004"], name: "VNC", category: "remote-access", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 3389, keywords: vec!["ms-terminal", "remote desktop", "rdp"], name: "RDP", category: "remote-access", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 8443, keywords: vec!["prometheus"], name: "Prometheus", category: "monitoring", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 9090, keywords: vec!["prometheus"], name: "Prometheus", category: "monitoring", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 3000, keywords: vec!["grafana"], name: "Grafana", category: "monitoring", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 2375, keywords: vec!["docker"], name: "Docker Engine", category: "container", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 2376, keywords: vec!["docker"], name: "Docker Engine (TLS)", category: "container", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 6443, keywords: vec!["kubernetes"], name: "Kubernetes API", category: "container", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 5672, keywords: vec!["amqp"], name: "RabbitMQ", category: "message-queue", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 15672, keywords: vec!["rabbitmq"], name: "RabbitMQ Management", category: "message-queue", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 9092, keywords: vec!["kafka"], name: "Kafka", category: "message-queue", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 1883, keywords: vec!["mqtt"], name: "MQTT", category: "iot", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 873, keywords: vec!["rsyncd", "@rsync"], name: "Rsync", category: "file-transfer", confidence: 90, version_hint: None });
        v.push(ServiceSig { port: 389, keywords: vec!["ldap"], name: "LDAP", category: "directory", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 636, keywords: vec!["ldap"], name: "LDAPS", category: "directory", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 53, keywords: vec!["dns"], name: "DNS", category: "infrastructure", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 161, keywords: vec!["snmp"], name: "SNMP", category: "infrastructure", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 5060, keywords: vec!["sip/2.0", "sip:"], name: "SIP", category: "voip", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 1080, keywords: vec!["socks"], name: "SOCKS Proxy", category: "proxy", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 3128, keywords: vec!["squid"], name: "Squid Proxy", category: "proxy", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 2181, keywords: vec!["zookeeper"], name: "ZooKeeper", category: "coordinator", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 8500, keywords: vec!["consul"], name: "Consul", category: "service-discovery", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 2379, keywords: vec!["etcd"], name: "etcd", category: "coordinator", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 25565, keywords: vec!["minecraft"], name: "Minecraft", category: "game", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 6000, keywords: vec!["x11"], name: "X11", category: "display", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 2000, keywords: vec!["cisco"], name: "Cisco SCCP", category: "voip", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 1723, keywords: vec!["pptp"], name: "PPTP VPN", category: "vpn", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 1194, keywords: vec!["openvpn"], name: "OpenVPN", category: "vpn", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 3260, keywords: vec!["iscsi"], name: "iSCSI", category: "storage", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 2049, keywords: vec!["nfs"], name: "NFS", category: "storage", confidence: 80, version_hint: None });
        v.push(ServiceSig { port: 10000, keywords: vec!["webmin"], name: "Webmin", category: "management", confidence: 85, version_hint: None });
        v.push(ServiceSig { port: 12345, keywords: vec!["netbus"], name: "NetBus", category: "malware", confidence: 75, version_hint: None });
        v.push(ServiceSig { port: 31337, keywords: vec!["back orifice", "backorifice"], name: "BackOrifice", category: "malware", confidence: 75, version_hint: None });
        v
    };
    static ref PROBES: HashMap<u16, Vec<Vec<u8>>> = {
        let mut m: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        m.insert(21, vec![b"SYST\r\n".to_vec(), b"FEAT\r\n".to_vec()]);
        m.insert(22, vec![b"SSH-2.0-HackIT-Probe\r\n".to_vec()]);
        m.insert(25, vec![b"EHLO hackit.discovery\r\n".to_vec()]);
        m.insert(53, vec![b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec()]);
        m.insert(80, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec()]);
        m.insert(110, vec![b"CAPA\r\n".to_vec()]);
        m.insert(143, vec![b"A1 CAPABILITY\r\n".to_vec()]);
        m.insert(389, vec![b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec()]);
        m.insert(443, vec![b"".to_vec()]);
        m.insert(587, vec![b"EHLO hackit.discovery\r\n".to_vec()]);
        m.insert(636, vec![b"".to_vec()]);
        m.insert(873, vec![b"@RSYNCD: 31.0\n".to_vec()]);
        m.insert(993, vec![b"".to_vec()]);
        m.insert(995, vec![b"".to_vec()]);
        m.insert(3306, vec![b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()]);
        m.insert(5432, vec![b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec()]);
        m.insert(5900, vec![b"RFB 003.008\n".to_vec()]);
        m.insert(6379, vec![b"PING\r\n".to_vec(), b"INFO\r\n".to_vec()]);
        m.insert(8080, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec()]);
        m.insert(8443, vec![b"".to_vec()]);
        m.insert(9090, vec![b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec()]);
        m.insert(9200, vec![b"GET / HTTP/1.0\r\n\r\n".to_vec()]);
        m.insert(11211, vec![b"stats\r\n".to_vec()]);
        m.insert(27017, vec![b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec()]);
        m
    };
    static ref PORT_BASE: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(21, "FTP"); m.insert(22, "SSH"); m.insert(23, "Telnet");
        m.insert(25, "SMTP"); m.insert(53, "DNS"); m.insert(80, "HTTP");
        m.insert(110, "POP3"); m.insert(111, "RPC"); m.insert(135, "MSRPC");
        m.insert(139, "NetBIOS"); m.insert(143, "IMAP"); m.insert(161, "SNMP");
        m.insert(389, "LDAP"); m.insert(443, "HTTPS"); m.insert(445, "SMB");
        m.insert(465, "SMTPS"); m.insert(500, "ISAKMP"); m.insert(587, "SMTP-MSA");
        m.insert(631, "IPP"); m.insert(636, "LDAPS"); m.insert(873, "Rsync");
        m.insert(990, "FTPS"); m.insert(992, "Telnets"); m.insert(993, "IMAPS");
        m.insert(995, "POP3S"); m.insert(1080, "SOCKS"); m.insert(1194, "OpenVPN");
        m.insert(1433, "MSSQL"); m.insert(1521, "Oracle-DB"); m.insert(1723, "PPTP");
        m.insert(1883, "MQTT"); m.insert(2049, "NFS"); m.insert(2181, "ZooKeeper");
        m.insert(2375, "Docker"); m.insert(2376, "Docker-TLS"); m.insert(2379, "etcd");
        m.insert(3000, "Grafana"); m.insert(3128, "Squid"); m.insert(3260, "iSCSI");
        m.insert(3306, "MySQL"); m.insert(3389, "RDP"); m.insert(5432, "PostgreSQL");
        m.insert(5672, "AMQP"); m.insert(5900, "VNC"); m.insert(5984, "CouchDB");
        m.insert(6379, "Redis"); m.insert(6443, "K8s-API"); m.insert(8080, "HTTP-Proxy");
        m.insert(8443, "HTTPS-Alt"); m.insert(8500, "Consul"); m.insert(9090, "Prometheus");
        m.insert(9092, "Kafka"); m.insert(9200, "Elasticsearch"); m.insert(11211, "Memcached");
        m.insert(15672, "RabbitMQ"); m.insert(25565, "Minecraft"); m.insert(27017, "MongoDB");
        m
    };
}

#[derive(Debug, Clone, Serialize)]
struct MatchResult {
    service_name: String,
    category: String,
    confidence: f64,
    version: String,
    matched_keyword: String,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceResult {
    port: u16,
    state: String,
    service: String,
    banner: String,
    best_match: Option<MatchResult>,
    alternative_matches: Vec<MatchResult>,
    probe_count: usize,
    response_time_ms: u64,
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

async fn multi_probe_banner(host: &str, port: u16, timeout_ms: u64) -> (String, usize) {
    let probes = PROBES.get(&port).cloned().unwrap_or_else(|| vec![b"\r\n".to_vec()]);
    let mut best_banner = String::new();
    let mut count = 0;
    for probe in &probes {
        let stream = match connect_with_timeout(host, port, timeout_ms).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (mut reader, mut writer) = stream.into_split();
        if !probe.is_empty() {
            let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(probe)).await;
            let _ = writer.shutdown().await;
        }
        let mut buf = vec![0u8; MAX_BANNER];
        if let Ok(Ok(n)) = timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
            if n > 0 {
                let resp = String::from_utf8_lossy(&buf[..n]).to_string();
                if resp.len() > best_banner.len() {
                    best_banner = resp;
                }
            }
        }
        count += 1;
    }
    (best_banner, count)
}

fn score_match(port: u16, banner: &str) -> (Option<MatchResult>, Vec<MatchResult>) {
    let b = banner.to_lowercase();
    let mut scored: Vec<(i32, &ServiceSig)> = Vec::new();

    for sig in SERVICE_SIGNATURES.iter() {
        if sig.port != port {
            continue;
        }
        let mut found = false;
        for kw in &sig.keywords {
            if b.contains(kw) {
                found = true;
                break;
            }
        }
        if found {
            scored.push((sig.confidence as i32, sig));
        }
    }

    if scored.is_empty() {
        for sig in SERVICE_SIGNATURES.iter() {
            if sig.port == port { continue; }
            let mut found = false;
            for kw in &sig.keywords {
                if b.contains(kw) {
                    found = true;
                    break;
                }
            }
            if found {
                let penalty = -20;
                scored.push((sig.confidence as i32 + penalty, sig));
            }
        }
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let best = scored.first();
    let rest: Vec<MatchResult> = scored.iter().skip(1).take(5).map(|(score, sig)| {
        let conf = (*score).max(0) as f64;
        let mut version = String::new();
        if let Some(hint) = sig.version_hint {
            if let Some(pos) = b.find(hint) {
                let start = pos + hint.len();
                let ver: String = banner[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '_').collect();
                if !ver.is_empty() {
                    version = ver.trim_matches('.').trim_matches('_').to_string();
                }
            }
        }
        MatchResult {
            service_name: sig.name.to_string(),
            category: sig.category.to_string(),
            confidence: conf.min(100.0),
            version,
            matched_keyword: String::new(),
        }
    }).collect();

    let best_result = best.map(|(score, sig)| {
        let conf = (*score).max(0) as f64;
        let mut version = String::new();
        if let Some(hint) = sig.version_hint {
            if let Some(pos) = b.find(hint) {
                let start = pos + hint.len();
                let ver: String = banner[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '_').collect();
                if !ver.is_empty() {
                    version = ver.trim_matches('.').trim_matches('_').to_string();
                }
            }
        }
        MatchResult {
            service_name: sig.name.to_string(),
            category: sig.category.to_string(),
            confidence: conf.min(100.0),
            version,
            matched_keyword: String::new(),
        }
    });

    (best_result, rest)
}

async fn scan_single(host: &str, port: u16, timeout_ms: u64) -> Option<ServiceResult> {
    let start = Instant::now();
    let stream = connect_with_timeout(host, port, timeout_ms).await;
    if stream.is_err() { return None; }
    let (banner, probe_count) = multi_probe_banner(host, port, timeout_ms).await;
    let sanitized = sanitize_banner(&banner);
    let (best_match, alternatives) = score_match(port, &sanitized);
    let service_name = best_match.as_ref()
        .map(|m| m.service_name.clone())
        .unwrap_or_else(|| {
            PORT_BASE.get(&port).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string())
        });
    Some(ServiceResult {
        port,
        state: "open".to_string(),
        service: service_name,
        banner: sanitized,
        best_match,
        alternative_matches: alternatives,
        probe_count,
        response_time_ms: start.elapsed().as_millis() as u64,
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <target> <ports> [timeout_ms] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top:N, all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443 3000 concurrency:50", args[0]);
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
                concurrency = c.max(1).min(500);
            }
        }
    }
    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }
    eprintln!("SMART_SERVICE_DETECT target={} ports={} timeout={}ms concurrency={}",
        target, ports.len(), timeout_ms, concurrency);

    let start = Instant::now();
    let total = ports.len();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let processed = std::sync::atomic::AtomicUsize::new(0);

    use futures::stream::{self, StreamExt};
    stream::iter(ports.into_iter())
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
    let mut results: Vec<ServiceResult> = Vec::with_capacity(total.min(1000));
    while let Some(r) = rx.recv().await {
        results.push(r);
    }
    results.sort_by(|a, b| a.port.cmp(&b.port));

    let analyzed: Vec<ServiceResult> = results.into_par_iter().map(|mut r| {
        if let Some(ref best) = r.best_match {
            r.service = best.service_name.clone();
        }
        r
    }).collect();

    let elapsed = start.elapsed().as_millis() as u64;
    for r in &analyzed {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }
    eprintln!("FINAL:{{\"target\":\"{}\",\"total\":{},\"open\":{},\"elapsed_ms\":{}}}",
        target, total, analyzed.len(), elapsed);
}
