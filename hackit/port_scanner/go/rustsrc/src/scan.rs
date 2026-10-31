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
use std::sync::Mutex;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (String, Instant)>> = RwLock::new(HashMap::new());
    static ref RE_CACHE: Mutex<HashMap<String, Regex>> = Mutex::new(HashMap::new());
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(25, b"EHLO hackit.local\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: PortStorm-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec());
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
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: hackit\r\nUser-Agent: PortStorm-RS/3.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(9090, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(9200, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(27017, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m
    };

    static ref SERVICE_SIGNATURES: Vec<(&'static str, &'static str, &'static str, &'static str, u16)> = {
        let mut s: Vec<(&'static str, &'static str, &'static str, &'static str, u16)> = Vec::new();
        s.push((r"OpenSSH_(\d+\.\d+)", "SSH", "OpenSSH", "", 22));
        s.push((r"dropbear_(\d+\.\d+)", "SSH", "Dropbear", "", 22));
        s.push((r"SSH-\d+\.\d+-Cisco", "SSH", "Cisco SSH", "Cisco IOS", 22));
        s.push((r"libssh-(\d+\.\d+)", "SSH", "libssh", "", 22));
        s.push((r"PuTTY_Release_(\d+\.\d+)", "SSH", "PuTTY", "Windows", 22));
        s.push((r"Apache/(\d+\.\d+\.\d+)", "HTTP", "Apache HTTP Server", "", 80));
        s.push((r"Apache/(\d+\.\d+\.\d+)", "HTTP", "Apache HTTP Server", "", 8080));
        s.push((r"nginx/(\d+\.\d+\.\d+)", "HTTP", "nginx", "", 80));
        s.push((r"nginx", "HTTP", "nginx", "", 80));
        s.push((r"IIS/(\d+\.\d+)", "HTTP", "IIS", "Windows", 80));
        s.push((r"Microsoft-IIS/(\d+\.\d+)", "HTTP", "IIS", "Windows", 80));
        s.push((r"LiteSpeed", "HTTP", "LiteSpeed", "", 80));
        s.push((r"lighttpd/(\d+\.\d+\.\d+)", "HTTP", "Lighttpd", "", 80));
        s.push((r"Caddy", "HTTP", "Caddy", "", 80));
        s.push((r"cloudflare", "HTTP", "Cloudflare", "", 80));
        s.push((r"gunicorn", "HTTP", "Gunicorn", "", 80));
        s.push((r"Node\.?js", "HTTP", "Node.js", "", 80));
        s.push((r"PHP/(\d+\.\d+\.\d+)", "HTTP", "PHP", "", 80));
        s.push((r"ASP\.NET", "HTTP", "ASP.NET", "Windows", 80));
        s.push((r"Express", "HTTP", "Express", "", 80));
        s.push((r"vsFTPd (\d+\.\d+\.\d+)", "FTP", "vsFTPd", "", 21));
        s.push((r"ProFTPD (\d+\.\d+\.\d+)", "FTP", "ProFTPD", "", 21));
        s.push((r"FileZilla Server (\d+\.\d+\.\d+)", "FTP", "FileZilla Server", "Windows", 21));
        s.push((r"Pure-FTPd", "FTP", "Pure-FTPd", "", 21));
        s.push((r"Microsoft FTP Service", "FTP", "Microsoft FTP", "Windows", 21));
        s.push((r"Postfix", "SMTP", "Postfix", "", 25));
        s.push((r"Exim (\d+\.\d+)", "SMTP", "Exim", "", 25));
        s.push((r"Sendmail (\d+\.\d+\.\d+)", "SMTP", "Sendmail", "", 25));
        s.push((r"Microsoft ESMTP MAIL Service", "SMTP", "Microsoft Exchange", "Windows", 25));
        s.push((r"Dovecot.*ready", "POP3", "Dovecot", "", 110));
        s.push((r"Dovecot.*ready", "IMAP", "Dovecot", "", 143));
        s.push((r"mysql_native_password", "MySQL", "MySQL", "", 3306));
        s.push((r"MariaDB", "MySQL", "MariaDB", "", 3306));
        s.push((r"PostgreSQL", "PostgreSQL", "PostgreSQL", "", 5432));
        s.push((r"Redis", "Redis", "Redis", "", 6379));
        s.push((r"MongoDB", "MongoDB", "MongoDB", "", 27017));
        s
    };
}

fn is_open(state: &str) -> bool {
    state == "open"
}

fn resolve_cached(host: &str) -> Option<String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ip, expiry)) = cache.get(host) {
            if expiry.elapsed() < DNS_CACHE_TTL {
                return Some(ip.clone());
            }
        }
    }
    if let Ok(addr) = format!("{}:0", host).to_socket_addrs() {
        if let Some(sa) = addr.filter(|a| a.is_ipv4()).next() {
            let ip = sa.ip().to_string();
            let mut cache = DNS_CACHE.write().unwrap();
            cache.insert(host.to_string(), (ip.clone(), Instant::now()));
            return Some(ip);
        }
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub banner: String,
    pub reason: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub banner_protocol: String,
    #[serde(skip_serializing_if = "is_zero", default)]
    pub banner_confidence: f64,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub banner_mismatch: bool,
}

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}

fn detect_service(banner: &str, port: u16) -> (String, String, String) {
    for (pattern, service, product, version_hint, _sig_port) in SERVICE_SIGNATURES.iter() {
        let re_owned = {
            let mut cache = RE_CACHE.lock().unwrap();
            cache.entry(pattern.to_string()).or_insert_with(|| Regex::new(pattern).unwrap()).clone()
        };
        if let Some(caps) = re_owned.captures(banner) {
            let version = if caps.len() > 1 {
                caps[1].to_string()
            } else {
                version_hint.to_string()
            };
            return (service.to_string(), product.to_string(), version);
        }
        }
    let service = match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP",
        53 => "DNS", 80 => "HTTP", 110 => "POP3", 111 => "RPC",
        135 => "MSRPC", 139 => "NetBIOS-SSN", 143 => "IMAP",
        389 => "LDAP", 443 => "HTTPS", 445 => "SMB", 465 => "SMTPS",
        514 => "Syslog", 587 => "SMTP", 636 => "LDAPS", 873 => "Rsync",
        993 => "IMAPS", 995 => "POP3S", 1080 => "SOCKS", 1433 => "MSSQL",
        1521 => "Oracle-DB", 2049 => "NFS", 2375 => "Docker", 3128 => "Squid",
        3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL", 5900 => "VNC",
        5984 => "CouchDB", 6379 => "Redis", 8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt",
        9090 => "HTTP-Alt", 9200 => "Elasticsearch", 11211 => "Memcached",
        27017 => "MongoDB", 50070 => "HDFS",
        _ => "Unknown"
    };
    (service.to_string(), String::new(), String::new())
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub workers: usize,
    pub timeout_ms: u64,
    pub retries: u32,
    pub delay_ms: u64,
    pub randomize: bool,
    pub banners: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { workers: 500, timeout_ms: 1500, retries: 1, delay_ms: 0, randomize: false, banners: true }
    }
}

async fn scan_port(host: &str, port: u16, opts: &ScanOptions) -> PortResult {
    let ip = match resolve_cached(host) {
        Some(ip) => ip,
        None => return PortResult {
            port, state: "error".into(), service: String::new(),
            product: String::new(), version: String::new(),
            banner: String::new(), reason: "dns resolution failed".into(),
            banner_protocol: String::new(), banner_confidence: 0.0, banner_mismatch: false,
        },
    };

    let addr = format!("{}:{}", ip, port);
    let mut last: Option<PortResult> = None;

    // Retries only apply to inconclusive states — a closed port is an answer.
    for attempt in 0..=opts.retries {
        let start = Instant::now();
        let stream = timeout(
            Duration::from_millis(opts.timeout_ms),
            TcpStream::connect(&addr),
        ).await;

        let result = match stream {
            Ok(Ok(sock)) => {
                drop(sock);
                let info = if opts.banners {
                    crate::banner::probe_port(&ip, port, opts.timeout_ms).await
                } else {
                    crate::banner::BannerInfo::default()
                };
                let (service, product, version) = detect_service(&info.banner, port);
                let elapsed = start.elapsed();
                let undecoded = info.protocol.is_empty() || info.protocol == "unknown";

                PortResult {
                    port,
                    state: "open".into(),
                    service: if undecoded {
                        "unknown".into()
                    } else if info.product.is_empty() {
                        service
                    } else {
                        info.product.clone()
                    },
                    product: if info.product.is_empty() { product } else { info.product },
                    // No decode means no version — raw text is not evidence.
                    version: if undecoded {
                        String::new()
                    } else if info.version.is_empty() {
                        version
                    } else {
                        info.version
                    },
                    banner: info.banner,
                    reason: format!("tcp-response in {:?}", elapsed),
                    banner_protocol: info.protocol,
                    banner_confidence: info.confidence,
                    banner_mismatch: info.mismatch,
                }
            }
            Ok(Err(e)) => PortResult {
                port, state: "closed".into(), service: String::new(),
                product: String::new(), version: String::new(),
                banner: String::new(), reason: format!("{}", e),
                banner_protocol: String::new(), banner_confidence: 0.0, banner_mismatch: false,
            },
            Err(_) => PortResult {
                port, state: "filtered".into(), service: String::new(),
                product: String::new(), version: String::new(),
                banner: String::new(), reason: "timeout".into(),
                banner_protocol: String::new(), banner_confidence: 0.0, banner_mismatch: false,
            },
        };

        if result.state != "filtered" {
            return result;
        }
        last = Some(result);
        if attempt < opts.retries {
            // Back off slightly so a rate-limited target is not hammered.
            tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
        }
    }

    last.unwrap_or(PortResult {
        port, state: "filtered".into(), service: String::new(),
        product: String::new(), version: String::new(),
        banner: String::new(), reason: "timeout".into(),
        banner_protocol: String::new(), banner_confidence: 0.0, banner_mismatch: false,
    })
}

pub async fn run_scan(target: &str, port_spec: &str, opts: &ScanOptions, json: bool) {
    let mut ports = parse_ports(port_spec);
    if opts.randomize {
        use rand::seq::SliceRandom;
        ports.shuffle(&mut rand::thread_rng());
    }
    let total = ports.len();
    let ip = resolve_cached(target).unwrap_or_else(|| target.to_string());
    let workers = opts.workers.max(1);
    let delay_ms = opts.delay_ms;

    if !json {
        println!("[RUST] Scanning {} ({}) — {} ports, {} workers", target, ip, total, workers);
    }

    let start = Instant::now();
    let results: Vec<PortResult> = stream::iter(ports)
        .map(|port| {
            let opts = opts.clone();
            async move {
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                scan_port(target, port, &opts).await
            }
        })
        .buffer_unordered(workers)
        .collect()
        .await;

    let elapsed = start.elapsed();
    let open: Vec<_> = results.iter().filter(|r| r.state == "open").collect();

    if json {
        let output = serde_json::to_string(&serde_json::json!({
            "engine": "rust",
            "target": target,
            "total": total,
            "open": open.len(),
            "duration_ms": elapsed.as_millis(),
            "ports": &results,
        })).unwrap_or_default();
        for r in &results {
            if r.state == "open" {
                println!(r#"RESULT:{{"port":{},"state":"{}"}}"#, r.port, r.state);
            }
        }
        println!("FINAL:{}", output);
    } else {
        println!("\n[RUST] Results — {} open, {} closed, {} filtered ({} total, {:?})",
            open.len(), results.iter().filter(|r| r.state == "closed").count(),
            results.iter().filter(|r| r.state == "filtered").count(), total, elapsed);
        for r in &results {
            if r.state == "open" {
                println!("  PORT={:<5} STATE={:<8} SERVICE={:<15} PRODUCT={} {}",
                    r.port, r.state, r.service, r.product, r.version);
            }
        }
    }
}

/// Default scan surface: real service ports, ordered by how often they are
/// found open. A bare scan never walks 1-65535.
pub static UNIVERSAL_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 53, 110, 143, 993, 995,
    3306, 3389, 445, 139, 135, 8080, 8443, 8000, 8888, 9000,
    6379, 27017, 5432, 1433, 1521, 11211, 5672, 9200, 9300, 2375,
    2376, 6443, 10250, 5000, 5001, 3000, 9090, 9100, 9091, 7001,
    7002, 8009, 8081, 8082, 8090, 8161, 8500, 8880, 8983, 9418,
    5900, 5901, 5902, 5903, 5800, 6080, 873, 111, 2049, 3260,
    631, 515, 548, 5985, 5986, 47001, 49152, 587, 465, 2525,
    4190, 5060, 5061, 1720, 1723, 1883, 8883, 1935, 554, 8554,
    1936, 10000, 10001, 50000, 61616, 15672, 15692, 4369, 25672, 8600,
    5601, 9092, 2181, 2888, 3888, 9042, 9160, 7199, 2379, 2380,
];

fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    let normalized = spec.trim().to_lowercase();
    match normalized.as_str() {
        "all" | "full" => return (1..=65535).collect(),
        "top100" | "top" | "default" | "" => return UNIVERSAL_PORTS.to_vec(),
        _ => {}
    }
    if let Some(n) = normalized.strip_prefix("top") {
        let n = n.trim_start_matches(':').parse::<usize>().unwrap_or(100);
        return UNIVERSAL_PORTS.iter().copied().take(n).collect();
    }
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.trim().parse().unwrap_or(1);
            let e: u16 = end.trim().parse().unwrap_or(65535);
            for p in s..=e.min(65535) {
                ports.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}
