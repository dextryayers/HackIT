//! banner.rs — protocol-accurate banner capture for the Rust engine.
//!
//! Mirrors the Go probe engine: an ordered probe plan per port, an
//! accumulating reader, and protocol-specific decoders. The old path sent at
//! most one payload and read once, which truncated every multi-line greeting
//! and mislabelled anything that did not answer on the first read.

use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const BANNER_MAX: usize = 16384;
const IDLE_GAP: Duration = Duration::from_millis(120);
const GREET_WAIT: Duration = Duration::from_millis(450);
const PROBE_WAIT: Duration = Duration::from_millis(900);

#[derive(Debug, Clone, Serialize, Default)]
pub struct BannerInfo {
    pub banner: String,
    pub protocol: String,
    pub product: String,
    pub version: String,
    pub confidence: f64,
    pub evidence: String,
    pub mismatch: bool,
}

#[derive(Clone)]
struct Stage {
    name: &'static str,
    payload: Vec<u8>,
    greeting: bool,
    settle: Duration,
}

impl Stage {
    fn greet(name: &'static str) -> Self {
        Stage { name, payload: Vec::new(), greeting: true, settle: GREET_WAIT }
    }
    fn send(name: &'static str, payload: Vec<u8>) -> Self {
        Stage { name, payload, greeting: false, settle: PROBE_WAIT }
    }
    fn send_fast(name: &'static str, payload: Vec<u8>) -> Self {
        Stage { name, payload, greeting: false, settle: Duration::from_millis(400) }
    }
}

fn generic_http(host: &str, port: u16) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) PortStorm/3.1\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        host, port
    )
    .into_bytes()
}

fn greets(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 110 | 119 | 143 | 194 | 445 | 465 | 587 | 636 | 873 | 990 | 993 | 995
            | 1521..=1527 | 2222..=2230 | 3306..=3312 | 3389..=3392 | 5432..=5440 | 5671
            | 5672 | 5900..=5910 | 6379..=6385 | 6660 | 6667 | 6697 | 9042 | 9160
            | 11211 | 16379 | 27017..=27025
    )
}

fn definitely_not_http(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 110 | 143 | 465 | 587 | 636 | 990 | 993 | 995 | 1521..=1527
            | 1883 | 2222 | 3306..=3312 | 3389 | 5222 | 5432..=5440 | 5671 | 5672
            | 5900..=5910 | 6379..=6385 | 8883 | 9042 | 11211 | 25565 | 27017..=27025
    )
}

fn definitely_not_tls(port: u16) -> bool {
    matches!(
        port,
        21 | 22 | 23 | 25 | 110 | 143 | 1883 | 3306 | 5222 | 5672 | 6379 | 6667 | 11211 | 25565 | 27017
    )
}

fn plan(port: u16, host: &str) -> Vec<Stage> {
    let mut out: Vec<Stage> = Vec::with_capacity(6);

    if greets(port) {
        out.push(Stage::greet("greeting"));
    }

    match port {
        25 | 465 | 587 | 2525 => out.push(Stage::send("smtp", b"EHLO hackit.local\r\n".to_vec())),
        110 => out.push(Stage::send("pop3", b"CAPA\r\n".to_vec())),
        143 => out.push(Stage::send("imap", b"a1 CAPABILITY\r\n".to_vec())),
        119 => out.push(Stage::send("nntp", b"MODE READER\r\n".to_vec())),
        21 => {
            out.push(Stage::send("ftp", b"FEAT\r\n".to_vec()));
            out.push(Stage::send_fast("ftp-tls", b"AUTH TLS\r\n".to_vec()));
        }
        5432..=5440 => {
            out.push(Stage::send("postgres-ssl", vec![0, 0, 0, 8, 4, 210, 22, 47]));
            out.push(Stage::send("postgres-startup", postgres_startup()));
        }
        6379..=6385 => out.push(Stage::send("redis", b"INFO server\r\n".to_vec())),
        16379 => out.push(Stage::send("redis-cluster", b"CLUSTER INFO\r\n".to_vec())),
        27017..=27025 => out.push(Stage::send("mongodb", mongo_ismaster())),
        1433 => out.push(Stage::send("mssql", mssql_prelogin())),
        1521..=1527 => out.push(Stage::send("oracle-tns", oracle_connect())),
        9042 | 9043 | 9044 => out.push(Stage::send("cassandra", cassandra_startup(4))),
        9160 => out.push(Stage::send("cassandra-thrift", vec![0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])),
        5900..=5910 => out.push(Stage::send("vnc", b"RFB 003.008\n".to_vec())),
        3389..=3392 => out.push(Stage::send("rdp", rdp_negotiate())),
        389 | 3268 => out.push(Stage::send("ldap", vec![0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00])),
        5672 | 5671 => out.push(Stage::send("amqp", b"AMQP\x00\x00\x09\x01".to_vec())),
        1883 | 8883 => out.push(Stage::send("mqtt", vec![0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
        9092..=9097 => out.push(Stage::send("kafka", kafka_api_versions())),
        4222 | 6222 => out.push(Stage::send("nats", b"CONNECT {\"verbose\":false}\r\nPING\r\n".to_vec())),
        11211..=11215 => out.push(Stage::send("memcached", b"stats\r\n".to_vec())),
        2181 => {
            out.push(Stage::send("zookeeper", b"srvr".to_vec()));
            out.push(Stage::send_fast("zookeeper-ruok", b"ruok".to_vec()));
        }
        2375 | 2376 | 4243 => out.push(Stage::send("docker", format!("GET /version HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", host, port).into_bytes())),
        6443 | 6444 | 8001 => out.push(Stage::send("kubernetes", format!("GET /version HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", host, port).into_bytes())),
        9200..=9210 => out.push(Stage::send("elasticsearch", format!("GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", host, port).into_bytes())),
        445 => out.push(Stage::send("smb", smb_negotiate())),
        873 => out.push(Stage::send("rsync", b"@RSYNCD: 31.0\n".to_vec())),
        25565 => out.push(Stage::send("minecraft", minecraft_handshake(host, port))),
        554 | 8554 => out.push(Stage::send("rtsp", b"OPTIONS rtsp://localhost RTSP/1.0\r\nCSeq: 1\r\n\r\n".to_vec())),
        5060 => out.push(Stage::send("sip", b"OPTIONS sip:probe@localhost SIP/2.0\r\nVia: SIP/2.0/TCP localhost\r\nFrom: <sip:probe@localhost>;tag=1\r\nTo: <sip:probe@localhost>\r\nCall-ID: 1@localhost\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n".to_vec())),
        _ => {}
    }

    if !out.iter().any(|s| s.name == "http") && !definitely_not_http(port) {
        out.push(Stage::send("http", generic_http(host, port)));
    }
    if !out.iter().any(|s| s.name == "tls") && !definitely_not_tls(port) {
        out.push(Stage { name: "tls", payload: Vec::new(), greeting: true, settle: PROBE_WAIT });
    }
    out.push(Stage::send_fast("crlf", b"\r\n".to_vec()));
    out
}

async fn read_until_quiet(sock: &mut TcpStream, first: Duration, limit: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];

    match timeout(first, sock.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => out.extend_from_slice(&buf[..n]),
        _ => return out,
    }
    loop {
        if out.len() >= limit {
            break;
        }
        match timeout(IDLE_GAP, sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let room = limit - out.len();
                let take = n.min(room);
                out.extend_from_slice(&buf[..take]);
            }
            _ => break,
        }
    }
    out
}

async fn run_stage(ip: &str, port: u16, st: &Stage, deadline: Duration) -> BannerInfo {
    let addr = format!("{}:{}", ip, port);
    let sock = match timeout(deadline, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return BannerInfo::default(),
    };
    let mut sock = sock;

    if !st.greeting && !st.payload.is_empty() {
        if timeout(deadline, sock.write_all(&st.payload)).await.is_err() {
            return BannerInfo::default();
        }
    }
    let raw = read_until_quiet(&mut sock, st.settle, BANNER_MAX).await;
    if raw.is_empty() {
        return BannerInfo::default();
    }
    let mut info = decode(port, &raw, st.name);
    info.evidence = st.name.to_string();
    info
}

/// Full probe of one port. Walks the plan, keeps the strongest decode.
pub async fn probe_port(ip: &str, port: u16, timeout_ms: u64) -> BannerInfo {
    let deadline = Duration::from_millis(timeout_ms.max(600).min(5000));
    let stages = plan(port, ip);
    let mut best = BannerInfo::default();

    for st in stages.iter().take(6) {
        let res = run_stage(ip, port, st, deadline).await;
        if res.banner.is_empty() && res.protocol.is_empty() {
            continue;
        }
        if res.confidence > best.confidence
            || (res.confidence == best.confidence && res.banner.len() > best.banner.len())
        {
            best = res;
        }
        if best.confidence >= 0.80 {
            break;
        }
    }
    finalize(&mut best, port);
    best
}

fn finalize(info: &mut BannerInfo, port: u16) {
    info.banner = info.banner.split_whitespace().collect::<Vec<_>>().join(" ");
    if info.banner.chars().count() > 260 {
        info.banner = info.banner.chars().take(260).collect::<String>() + "…";
    }
    if !info.protocol.is_empty() && !port_is_expected(&info.protocol, port) {
        info.mismatch = true;
        if info.confidence > 0.55 {
            info.confidence -= 0.05;
        }
    }
    if info.confidence == 0.0 && !info.banner.is_empty() {
        info.confidence = 0.4;
    }
}

fn expected_ports(proto: &str) -> &'static [u16] {
    match proto {
        "ftp" => &[21, 2100, 2121, 8021],
        "ssh" => &[22, 222, 2022, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230],
        "smtp" => &[25, 465, 587, 2525],
        "pop3" => &[110, 995],
        "imap" => &[143, 993],
        "mysql" => &[3306, 3307, 3308, 3309, 3310, 3311, 3312, 33060],
        "redis" => &[6379, 6380, 6381, 6382, 6383, 6384, 6385, 16379, 26379],
        "mongodb" => &[27017, 27018, 27019, 27020, 27021, 27022, 27023, 27024, 27025],
        "memcached" => &[11211, 11212, 11213, 11214, 11215],
        "vnc" => &[5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910],
        "rsync" => &[873],
        _ => &[],
    }
}

fn port_is_expected(proto: &str, port: u16) -> bool {
    let ports = expected_ports(proto);
    ports.is_empty() || ports.contains(&port)
}

// ── payload builders ────────────────────────────────────────────────

fn postgres_startup() -> Vec<u8> {
    let params = b"user\0hackit\0database\0postgres\0\0";
    let mut msg = vec![0u8; 8];
    let len = (8 + params.len()) as u32;
    msg[0..4].copy_from_slice(&len.to_be_bytes());
    msg[4..8].copy_from_slice(&196608u32.to_be_bytes());
    msg.extend_from_slice(params);
    msg
}

fn mongo_ismaster() -> Vec<u8> {
    let mut doc = vec![
        0x13, 0x00, 0x00, 0x00, 0x10, b'i', b's', b'm', b'a', b's', b't', b'e', b'r', 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
    ];
    let mut msg: Vec<u8> = Vec::with_capacity(64);
    msg.extend_from_slice(&[0u8; 4]);
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&2004u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(b"admin.$cmd\0");
    msg.extend_from_slice(&[0, 0, 0, 0]);
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    msg.append(&mut doc);
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_le_bytes());
    msg
}

fn mssql_prelogin() -> Vec<u8> {
    vec![
        0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00,
        0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00,
        0x26, 0x00, 0x01, 0xff, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
}

fn oracle_connect() -> Vec<u8> {
    let mut pkt: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x39, 0x01, 0x2c, 0x00, 0x00, 0x08,
        0x00, 0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x3a,
    ];
    pkt.extend_from_slice(b"(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))");
    let len = pkt.len() as u16;
    pkt[0..2].copy_from_slice(&len.to_be_bytes());
    pkt
}

fn cassandra_startup(version: u8) -> Vec<u8> {
    let mut body: Vec<u8> = vec![0x00, 0x01, 0x00, 0x0b];
    body.extend_from_slice(b"CQL_VERSION");
    body.push(0x00);
    body.push(0x05);
    body.extend_from_slice(b"3.0.0");
    let mut out: Vec<u8> = vec![version, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

fn rdp_negotiate() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x00, 0x00, 0x00,
    ]
}

fn smb_negotiate() -> Vec<u8> {
    let mut out: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00, 0xfe, b'S', b'M', b'B'];
    out.extend_from_slice(&0x0040u16.to_le_bytes()); // StructureSize
    out.extend_from_slice(&4u16.to_le_bytes()); // DialectCount
    out.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&[0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03]);
    let len = (out.len() - 4) as u32;
    out[0..4].copy_from_slice(&len.to_be_bytes());
    out
}

fn kafka_api_versions() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&18i16.to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&1i32.to_be_bytes());
    body.extend_from_slice(&6i16.to_be_bytes());
    body.extend_from_slice(b"hackit");
    let mut out = vec![0u8; 4];
    out.extend_from_slice(&body);
    let len = body.len() as u32;
    out[0..4].copy_from_slice(&len.to_be_bytes());
    out
}

fn minecraft_handshake(host: &str, port: u16) -> Vec<u8> {
    let mut payload: Vec<u8> = vec![0x00, 0x04];
    payload.extend_from_slice(host.as_bytes());
    payload.push((port >> 8) as u8);
    payload.push((port & 0xff) as u8);
    payload.push(0x01);
    let mut out: Vec<u8> = vec![payload.len() as u8];
    out.extend_from_slice(&payload);
    out.extend_from_slice(&[0x01, 0x00]);
    out
}

// ── decoders ────────────────────────────────────────────────────────

lazy_static! {
    static ref HTTP_STATUS: Regex = Regex::new(r"(?i)^HTTP/\d\.\d\s+\d{3}").unwrap();
    static ref HTTP_SERVER: Regex = Regex::new(r"(?i)^server:\s*(.+)$").unwrap();
    static ref HTTP_TITLE: Regex = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap();
    static ref VERSION_RE: Regex = Regex::new(r"\d+\.\d+").unwrap();
}

fn is_tls(raw: &[u8]) -> bool {
    raw.len() >= 5 && raw[0] == 0x16 && raw[1] == 0x03 && raw[2] <= 0x04
}

fn decode(port: u16, raw: &[u8], _stage: &str) -> BannerInfo {
    let mut info = BannerInfo::default();

    if is_tls(raw) {
        info.protocol = "tls".into();
        info.product = "TLS".into();
        info.banner = match raw.get(2) {
            Some(0x01) => "TLS 1.0 handshake",
            Some(0x02) => "TLS 1.1 handshake",
            Some(0x03) => "TLS 1.2 handshake",
            Some(0x04) => "TLS 1.3 handshake",
            _ => "TLS handshake",
        }
        .into();
        info.confidence = 0.9;
        return info;
    }

    if let Some(v) = decode_mysql(raw) {
        info.protocol = "mysql".into();
        info.product = "MySQL".into();
        info.version = v.clone();
        info.banner = format!("MySQL {}", v);
        info.confidence = 0.98;
        return info;
    }

    let text = sanitize(raw);
    if text.starts_with("SSH-") {
        let line = first_line(&text);
        let (product, version) = parse_ssh(&line);
        info.protocol = "ssh".into();
        info.product = product;
        info.version = version;
        info.banner = line;
        info.confidence = 0.99;
        return info;
    }

    if text.starts_with("RFB ") {
        let line = first_line(&text);
        info.protocol = "vnc".into();
        info.product = "VNC".into();
        info.version = line.trim_start_matches("RFB ").trim().to_string();
        info.banner = line;
        info.confidence = 0.97;
        return info;
    }

    if is_redis(raw) {
        let ver = redis_version(&text);
        info.protocol = "redis".into();
        info.product = "Redis".into();
        info.version = ver.clone();
        info.banner = if ver.is_empty() { first_line(&text) } else { format!("Redis {}", ver) };
        info.confidence = 0.95;
        return info;
    }

    if is_mongo(raw) {
        info.protocol = "mongodb".into();
        info.product = "MongoDB".into();
        info.version = bson_version(raw);
        info.banner = if info.version.is_empty() {
            "MongoDB".into()
        } else {
            format!("MongoDB {}", info.version)
        };
        info.confidence = 0.93;
        return info;
    }

    if raw.len() > 8 && raw[..16.min(raw.len())].windows(3).any(|w| w == b"SMB") {
        info.protocol = "smb".into();
        info.product = "SMB".into();
        info.version = smb_dialect(raw);
        info.banner = format!("SMB {}", info.version);
        info.confidence = 0.95;
        return info;
    }

    if raw.len() >= 11 && raw[0] == 0x03 && raw[1] == 0x00 {
        info.protocol = "rdp".into();
        info.product = "RDP".into();
        info.banner = "RDP (X.224 negotiation)".into();
        info.confidence = 0.88;
        return info;
    }

    if raw.starts_with(b"AMQP") {
        info.protocol = "amqp".into();
        info.product = "RabbitMQ".into();
        info.banner = "AMQP connection.start".into();
        info.confidence = 0.95;
        return info;
    }

    if raw.len() >= 4 && raw[0] == 0x20 && raw[1] == 0x02 {
        info.protocol = "mqtt".into();
        info.product = "MQTT".into();
        info.banner = "MQTT CONNACK".into();
        info.confidence = 0.9;
        return info;
    }

    if HTTP_STATUS.is_match(&text) {
        return decode_http(&text, false);
    }

    if let Some((proto, product, conf)) = classify_text(port, &text) {
        info.protocol = proto.to_string();
        info.product = product.to_string();
        info.version = text_version(&text, proto);
        info.banner = summarize(&text);
        info.confidence = conf;
        return info;
    }

    if !text.is_empty() {
        info.protocol = "unknown".into();
        info.banner = truncate(&text, 220);
        info.confidence = 0.3;
    }
    info
}

fn split_product_version(header: &str) -> Option<(String, String)> {
    let header = header.trim();
    if header.is_empty() {
        return None;
    }
    if let Some(idx) = header.find('/') {
        let product = header[..idx].trim().to_string();
        let rest = header[idx + 1..].trim();
        let version = rest
            .split_whitespace()
            .next()
            .map(|v| v.trim_end_matches(';').to_string())
            .filter(|v| VERSION_RE.is_match(v))
            .unwrap_or_default();
        return Some((product, version));
    }
    let mut it = header.split_whitespace();
    let product = it.next()?.to_string();
    let version = it
        .find(|v| VERSION_RE.is_match(v))
        .map(|v| v.trim_end_matches(';').to_string())
        .unwrap_or_default();
    Some((product, version))
}

fn decode_http(text: &str, tls: bool) -> BannerInfo {
    let mut info = BannerInfo {
        protocol: if tls { "https".into() } else { "http".into() },
        product: "HTTP".into(),
        confidence: if tls { 0.99 } else { 0.9 },
        ..Default::default()
    };
    let mut parts: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if HTTP_STATUS.is_match(t) {
            parts.push(t.to_string());
        } else if let Some(c) = HTTP_SERVER.captures(t) {
            let server = c.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
            parts.push(format!("Server: {}", server));
            if let Some((p, v)) = split_product_version(&server) {
                info.product = p;
                info.version = v;
            }
            info.confidence = 0.97;
        } else {
            let low = t.to_ascii_lowercase();
            if low.starts_with("x-powered-by:") || low.starts_with("via:") || low.starts_with("content-type:") {
                parts.push(t.to_string());
            }
        }
        if parts.len() >= 5 {
            break;
        }
    }
    if let Some(c) = HTTP_TITLE.captures(text) {
        let title = c.get(1).map(|m| m.as_str().split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default();
        if !title.is_empty() && title.len() < 120 {
            parts.push(format!("Title: {}", title));
        }
    }
    info.banner = if parts.is_empty() { truncate(text, 160) } else { parts.join(" | ") };
    info
}

fn classify_text(port: u16, text: &str) -> Option<(&'static str, &'static str, f64)> {
    let low = text.to_ascii_lowercase();
    let rules: &[(&str, &str, &[&str], f64)] = &[
        ("ftp", "FTP", &[" 220 ", "vsftpd", "proftpd", "pure-ftpd", "filezilla"], 0.92),
        ("smtp", "SMTP", &["esmtp", "postfix", "exim", "sendmail", "smtp"], 0.9),
        ("pop3", "POP3", &["+ok", "pop3", "dovecot"], 0.88),
        ("imap", "IMAP", &["* ok", "imap", "dovecot", "cyrus"], 0.88),
        ("telnet", "Telnet", &["login:", "password:"], 0.7),
        ("memcached", "Memcached", &["curr_items", "version "], 0.85),
        ("rsync", "rsync", &["@rsyncd"], 0.97),
        ("zookeeper", "ZooKeeper", &["imok", "mode:"], 0.85),
        ("elasticsearch", "Elasticsearch", &["you know, for search", "lucene_version"], 0.95),
        ("prometheus", "Prometheus", &["# help", "# type"], 0.85),
        ("sip", "SIP", &["sip/2.0"], 0.92),
        ("rtsp", "RTSP", &["rtsp/1.0"], 0.95),
        ("xmpp", "XMPP", &["stream:stream", "jabber"], 0.9),
        ("irc", "IRC", &["ircd", "notice auth"], 0.85),
    ];
    for (proto, product, needles, conf) in rules {
        if needles.iter().any(|n| low.contains(n)) {
            let mut c = *conf;
            if !port_is_expected(proto, port) {
                c -= 0.10;
            }
            return Some((proto, product, c));
        }
    }
    None
}

fn text_version(text: &str, proto: &str) -> String {
    let re = match proto {
        "ftp" => Some(Regex::new(r"(?i)(?:vsftpd|proftpd|pure-ftpd|filezilla)[^\d]*([\d.]+)").ok()),
        "smtp" => Some(Regex::new(r"(?i)(?:postfix|exim|sendmail|opensmtpd)[^\d]*([\d.]+)").ok()),
        "memcached" => Some(Regex::new(r"(?i)VERSION\s+([\d.]+)").ok()),
        "rsync" => Some(Regex::new(r"(?i)@rsyncd:\s*([\d.]+)").ok()),
        _ => None,
    };
    re.flatten()
        .and_then(|r| r.captures(text))
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        .unwrap_or_default()
}

fn decode_mysql(raw: &[u8]) -> Option<String> {
    if raw.len() < 6 || raw[3] != 0x00 || raw[4] != 0x0a {
        return None;
    }
    let rest = &raw[5..];
    let end = rest.iter().position(|b| *b == 0)?;
    if end == 0 || end > 64 {
        return None;
    }
    let v = String::from_utf8_lossy(&rest[..end]).to_string();
    if v.chars().any(|c| c.is_ascii_digit()) {
        Some(v)
    } else {
        None
    }
}

fn is_redis(raw: &[u8]) -> bool {
    matches!(raw.first(), Some(b'+') | Some(b'-') | Some(b':') | Some(b'$') | Some(b'*'))
        && raw.windows(2).any(|w| w == b"\r\n")
}

fn redis_version(text: &str) -> String {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("redis_version:").map(|v| v.trim().to_string()))
        .unwrap_or_default()
}

fn is_mongo(raw: &[u8]) -> bool {
    if raw.len() < 16 {
        return false;
    }
    let len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if len > raw.len() {
        return false;
    }
    let op = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    op == 1 || op == 2004 || op == 2013
}

fn bson_version(raw: &[u8]) -> String {
    let needle = b"version\0";
    let idx = match raw.windows(needle.len()).position(|w| w == needle) {
        Some(i) => i,
        None => return String::new(),
    };
    let start = idx + needle.len();
    if start + 4 > raw.len() {
        return String::new();
    }
    let n = u32::from_le_bytes([raw[start], raw[start + 1], raw[start + 2], raw[start + 3]]) as usize;
    if n <= 1 || n > 32 || start + 4 + n > raw.len() {
        return String::new();
    }
    String::from_utf8_lossy(&raw[start + 4..start + 4 + n - 1]).to_string()
}

fn smb_dialect(raw: &[u8]) -> String {
    if raw.len() < 10 {
        return String::new();
    }
    let d = u16::from_le_bytes([raw[8], raw[9]]);
    match d {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "2.x",
    }
    .to_string()
}

fn parse_ssh(line: &str) -> (String, String) {
    let mut parts = line.splitn(3, '-');
    let _ = parts.next();
    let _ = parts.next();
    match parts.next() {
        Some(software) => {
            let mut it = software.split(|c| c == '_' || c == ' ');
            let product = it.next().unwrap_or("SSH").to_string();
            let version = it.next().unwrap_or("").to_string();
            (product, version)
        }
        None => ("SSH".to_string(), String::new()),
    }
}

fn sanitize(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in String::from_utf8_lossy(raw).chars() {
        if ch == '\n' || ch == '\r' || ch == '\t' || (' '..='~').contains(&ch) {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_string()
}

fn summarize(text: &str) -> String {
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(2)
        .collect();
    truncate(&lines.join(" | "), 220)
}

fn truncate(text: &str, n: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= n {
        flat
    } else {
        flat.chars().take(n).collect::<String>() + "…"
    }
}
