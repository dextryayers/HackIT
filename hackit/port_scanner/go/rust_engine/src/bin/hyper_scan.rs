use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 1500;
const DEFAULT_CONCURRENCY: usize = 500;

lazy_static::lazy_static! {
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(25, b"EHLO hackit.local\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-RS/2.0\r\nAccept: */*\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec());
        m.insert(443, b"".to_vec());
        m.insert(587, b"EHLO hackit.local\r\n".to_vec());
        m.insert(636, b"".to_vec());
        m.insert(873, b"@RSYNCD: 31.0\n".to_vec());
        m.insert(993, b"".to_vec());
        m.insert(995, b"".to_vec());
        m.insert(2375, b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(3128, b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n".to_vec());
        m.insert(3306, b"".to_vec());
        m.insert(5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec());
        m.insert(5900, b"RFB 003.008\n".to_vec());
        m.insert(5984, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(6379, b"INFO server\r\n".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: HackIT-RS/2.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(9090, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(9200, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(27017, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m
    };
}

#[derive(Debug, Clone, Serialize)]
struct ScanResult {
    port: u16,
    state: String,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
    os_hint: Option<String>,
    banner: Option<String>,
    banner_len: usize,
    rtt_ms: u64,
    tls: bool,
}

#[derive(Debug, Clone, Serialize)]
struct FinalOutput {
    host: String,
    total_ports: usize,
    open_ports: usize,
    elapsed_ms: u64,
    results: Vec<ScanResult>,
}

fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    match input.trim().to_lowercase().as_str() {
        "all" => return (1..=65535).collect(),
        "top100" => {
            return vec![7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,
                135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
                554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,
                1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4000,
                4001,4662,4899,5000,5001,5050,5060,5101,5190,5357,5432,5555,5631,5666,
                5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
                9999,10000,32768,49152,49154];
        }
        _ => {}
    }
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse().unwrap_or(1);
            let e: u16 = end.parse().unwrap_or(65535);
            for p in s..=e { ports.push(p); }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

fn service_name(port: u16) -> Option<String> {
    let svc = match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 111 => "RPC", 135 => "MSRPC", 139 => "NetBIOS",
        143 => "IMAP", 161 => "SNMP", 179 => "BGP", 389 => "LDAP", 443 => "HTTPS",
        445 => "SMB", 465 => "SMTPS", 514 => "Syslog", 587 => "SMTP-MSA",
        636 => "LDAPS", 873 => "RSYNC", 990 => "FTPS", 993 => "IMAPS",
        995 => "POP3S", 1080 => "SOCKS", 1194 => "OpenVPN", 1433 => "MSSQL",
        1521 => "Oracle", 1723 => "PPTP", 2049 => "NFS", 2375 => "Docker",
        2376 => "Docker-TLS", 2379 => "etcd", 3128 => "Squid", 3306 => "MySQL",
        3389 => "RDP", 3690 => "SVN", 4369 => "EPMD", 5432 => "PostgreSQL",
        5672 => "AMQP", 5900 => "VNC", 5984 => "CouchDB", 5985 => "WinRM",
        6379 => "Redis", 6443 => "K8s-API", 8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt", 8500 => "Consul", 9090 => "Prometheus",
        9092 => "Kafka", 9200 => "Elasticsearch", 10250 => "Kubelet",
        11211 => "Memcached", 15672 => "RabbitMQ", 25565 => "Minecraft",
        27017 => "MongoDB", 32400 => "Plex", _ => return None,
    };
    Some(svc.to_string())
}

async fn connect_with_retry(host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream, String> {
    let addr = format!("{}:{}", host, port);
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(_) => Err("timeout".into()),
    }
}

async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> (String, u64) {
    let start = Instant::now();
    let stream = match connect_with_retry(host, port, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return (String::new(), start.elapsed().as_millis() as u64),
    };
    let (mut reader, mut writer) = stream.into_split();
    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = timeout(
            Duration::from_millis(timeout_ms / 2),
            writer.write_all(&probe),
        ).await;
    }
    let mut buf = vec![0u8; MAX_BANNER];
    let banner = match timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => String::new(),
    };
    let elapsed = start.elapsed().as_millis() as u64;
    (banner, elapsed)
}

fn sanitize_banner(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '\r' => {},
            '\n' => { if !out.ends_with(' ') { out.push(' '); } },
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => {}
        }
    }
    if out.len() > 500 {
        out.truncate(500);
        out.push_str("...");
    }
    out
}

fn detect_tls(host: &str, port: u16, timeout_ms: u64) -> bool {
    let stream = std::net::TcpStream::connect_timeout(
        &format!("{}:{}", host, port).parse().unwrap(),
        Duration::from_millis(timeout_ms),
    );
    if stream.is_err() { return false; }
    let mut s = stream.unwrap();
    s.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    s.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let ch: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x31,
        0x01, 0x00, 0x00, 0x2d, 0x03, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02,
        0x00, 0x2f, 0x00, 0x35,
        0x01, 0x00,
    ];
    use std::io::Write;
    let _ = s.set_nonblocking(false);
    let _ = (&mut s as &mut dyn Write).write(ch);
    let mut resp = [0u8; 1024];
    use std::io::Read;
    match (&mut s as &mut dyn Read).read(&mut resp) {
        Ok(n) if n > 0 && resp[0] == 0x16 => true,
        _ => false,
    }
}

fn match_signature(port: u16, banner: &str) -> (Option<String>, Option<String>, Option<String>) {
    let b = banner.to_lowercase();
    let patterns: Vec<(u16, &[&str], &str, &str)> = vec![
        (22, &["openssh_"], "OpenSSH", "SSH"),
        (22, &["dropbear"], "Dropbear", "SSH"),
        (22, &["libssh"], "libssh", "SSH"),
        (80, &["apache/", "apache-"], "Apache httpd", "HTTP"),
        (80, &["nginx/", "nginx-"], "nginx", "HTTP"),
        (80, &["microsoft-iis/"], "IIS", "HTTP"),
        (80, &["lighttpd/"], "Lighttpd", "HTTP"),
        (80, &["litespeed"], "LiteSpeed", "HTTP"),
        (80, &["php/"], "PHP", "HTTP"),
        (80, &["cloudflare"], "Cloudflare", "HTTP"),
        (21, &["vsftpd"], "vsftpd", "FTP"),
        (21, &["proftpd"], "ProFTPD", "FTP"),
        (21, &["pure-ftpd"], "Pure-FTPd", "FTP"),
        (21, &["filezilla"], "FileZilla", "FTP"),
        (21, &["microsoft ftp"], "MS FTP", "FTP"),
        (25, &["postfix"], "Postfix", "SMTP"),
        (25, &["exim"], "Exim", "SMTP"),
        (25, &["sendmail"], "Sendmail", "SMTP"),
        (25, &["microsoft esmtp"], "MS Exchange", "SMTP"),
        (3306, &["mysql", "mariadb"], "MySQL/MariaDB", "MySQL"),
        (5432, &["postgresql"], "PostgreSQL", "PostgreSQL"),
        (6379, &["redis_version", "redis_mode"], "Redis", "Redis"),
        (27017, &["mongodb"], "MongoDB", "MongoDB"),
        (9200, &["elasticsearch", "cluster_name"], "Elasticsearch", "Elasticsearch"),
        (11211, &["stat pid", "stat curr"], "Memcached", "Memcached"),
        (5900, &["rfb 00", "rfb 03", "rfb 04"], "VNC", "VNC"),
        (3389, &["ms-terminal"], "MS RDP", "RDP"),
        (8443, &["prometheus"], "Prometheus", "Monitoring"),
        (9090, &["prometheus"], "Prometheus", "Monitoring"),
        (3000, &["grafana"], "Grafana", "Monitoring"),
        (2375, &["docker"], "Docker", "Docker"),
        (2376, &["docker"], "Docker-TLS", "Docker"),
        (6443, &["kubernetes"], "Kubernetes", "Kubernetes"),
        (5672, &["amqp"], "RabbitMQ", "MQ"),
        (15672, &["rabbitmq"], "RabbitMQ", "MQ"),
        (5984, &["couchdb"], "CouchDB", "CouchDB"),
        (873, &["rsyncd"], "Rsync", "Rsync"),
    ];
    for &(p, keywords, product_name, service_name) in &patterns {
        if p == port {
            for kw in keywords {
                if b.contains(kw) {
                    let ver = parse_version(banner, product_name);
                    return (Some(service_name.to_string()), Some(product_name.to_string()), ver);
                }
            }
        }
    }
    (None, None, None)
}

fn parse_version(banner: &str, product: &str) -> Option<String> {
    let b = banner.to_lowercase();
    let markers: Vec<&str> = match product {
        "OpenSSH" | "Dropbear" => vec!["openssh_", "dropbear_", "libssh_"],
        "Apache httpd" => vec!["apache/"],
        "nginx" => vec!["nginx/"],
        "IIS" => vec!["microsoft-iis/"],
        "vsftpd" => vec!["vsftpd"],
        "ProFTPD" => vec!["proftpd"],
        "PHP" => vec!["php/"],
        "Lighttpd" => vec!["lighttpd/"],
        "Postfix" => vec!["postfix"],
        "Exim" => vec!["exim "],
        _ => vec![],
    };
    for marker in markers {
        if let Some(pos) = b.find(marker) {
            let start = pos + marker.len();
            let rest = &banner[start..];
            let ver: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == 'p' || *c == '_').collect();
            if !ver.is_empty() {
                let clean: String = ver.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                if !clean.is_empty() { return Some(clean); }
            }
        }
    }
    None
}

async fn scan_port(host: &str, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    let start = Instant::now();
    let stream = connect_with_retry(host, port, timeout_ms).await;
    if stream.is_err() { return None; }
    let conn_ms = start.elapsed().as_millis() as u64;
    let (banner, _banner_ms) = grab_banner(host, port, timeout_ms).await;
    let sanitized = sanitize_banner(&banner);
    let tls = if port == 443 || port == 8443 || port == 993 || port == 995 || port == 636 {
        detect_tls(host, port, timeout_ms)
    } else { false };
    let (service, product, version) = if !sanitized.is_empty() {
        match_signature(port, &sanitized)
    } else {
        (service_name(port.clone()), None, None)
    };
    let os_hint = None;
    Some(ScanResult {
        port,
        state: "open".to_string(),
        service: service.or_else(|| service_name(port)),
        product,
        version,
        os_hint,
        banner: if sanitized.is_empty() { None } else { Some(sanitized.clone()) },
        banner_len: sanitized.len(),
        rtt_ms: conn_ms,
        tls,
    })
}

async fn scan_target(
    host: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
) -> Vec<ScanResult> {
    let results = Arc::new(Mutex::new(Vec::new()));
    stream::iter(ports.iter().copied())
        .map(|port| {
            let host = host.to_string();
            let results = Arc::clone(&results);
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

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <ports> [timeout_ms] [concurrency:N] [format:text|json]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top100, all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443,8080 2000 concurrency:500 json", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let ports = parse_ports(&args[2]);
    let mut timeout_ms: u64 = DEFAULT_TIMEOUT_MS;
    let mut concurrency: usize = DEFAULT_CONCURRENCY;
    let mut output_format = "text";
    for arg in &args[3..] {
        if let Ok(ms) = arg.parse::<u64>() {
            timeout_ms = ms;
        } else if let Some(n) = arg.strip_prefix("concurrency:") {
            if let Ok(c) = n.parse::<usize>() {
                concurrency = c.max(1).min(10000);
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
        "HYPER_SCAN target={} ports={} timeout={}ms concurrency={}",
        host, ports.len(), timeout_ms, concurrency
    );
    let start = Instant::now();
    let results = scan_target(host, &ports, timeout_ms, concurrency).await;
    let elapsed = start.elapsed().as_millis() as u64;
    for r in &results {
        let svc = r.service.as_deref().unwrap_or("-");
        let prod = r.product.as_deref().unwrap_or("");
        let ver = r.version.as_deref().unwrap_or("");
        let banner = r.banner.as_deref().unwrap_or("");
        let mut b_clean: String = banner.chars().filter(|&c| c != '"').collect();
        if b_clean.len() > 200 { b_clean.truncate(200); }
        println!("RESULT:{{\"port\":{},\"state\":\"{}\",\"service\":\"{}\",\"product\":\"{}\",\"version\":\"{}\",\"banner\":\"{}\",\"rtt_ms\":{},\"tls\":{}}}",
            r.port, r.state, svc, prod, ver, b_clean, r.rtt_ms, r.tls);
    }
    eprintln!("FINAL:{{\"target\":\"{}\",\"total\":{},\"open\":{},\"elapsed_ms\":{}}}",
        host, ports.len(), results.len(), elapsed);
}
