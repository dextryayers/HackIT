use rust_port_scanner::*;
use futures::stream::{self, StreamExt};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const MAX_BANNER: usize = 8192;
const DEFAULT_TIMEOUT_MS: u64 = 1500;
const DEFAULT_CONCURRENCY: usize = 1000;

lazy_static::lazy_static! {
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(22, b"SSH-2.0-HackIT-Probe\r\n".to_vec());
        m.insert(25, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(53, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\nAccept: */*\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec());
        m.insert(443, b"".to_vec());
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
struct ScanResult {
    port: u16,
    state: String,
    service: String,
    product: String,
    version: String,
    banner: String,
    rtt_ms: u64,
    tls: bool,
}

#[derive(Debug, Clone, Serialize)]
struct RawScan {
    port: u16,
    banner: String,
    rtt_ms: u64,
    tls: bool,
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

async fn detect_tls(host: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", host, port);
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
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(mut s)) => {
            let _ = tokio::io::AsyncWriteExt::write_all(&mut s, ch).await;
            let mut resp = [0u8; 1024];
            match timeout(Duration::from_millis(timeout_ms), s.read(&mut resp)).await {
                Ok(Ok(n)) if n > 0 && resp[0] == 0x16 => true,
                _ => false,
            }
        }
        _ => false,
    }
}

async fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> (String, u64) {
    let start = Instant::now();
    let stream = match connect_with_timeout(host, port, timeout_ms).await {
        Ok(s) => s,
        Err(_) => return (String::new(), start.elapsed().as_millis() as u64),
    };
    let (mut reader, mut writer) = stream.into_split();
    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(&probe)).await;
        let _ = writer.shutdown().await;
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

async fn scan_port(host: &str, port: u16, timeout_ms: u64) -> Option<RawScan> {
    let start = Instant::now();
    let stream = connect_with_timeout(host, port, timeout_ms).await;
    if stream.is_err() { return None; }
    let conn_ms = start.elapsed().as_millis() as u64;
    let (banner, _) = grab_banner(host, port, timeout_ms).await;
    let tls = if port == 443 || port == 8443 || port == 993 || port == 995 || port == 636 {
        detect_tls(host, port, timeout_ms).await
    } else { false };
    Some(RawScan { port, banner, rtt_ms: conn_ms, tls })
}

fn analyze_banner(port: u16, banner: &str, tls: bool) -> (String, String, String) {
    let sanitized = sanitize_banner(banner);
    let service = identify_service(&sanitized, port);
    let version = extract_service_version(&sanitized);
    let product = if tls { format!("{} (TLS)", service) } else { service.clone() };
    (service, product, version)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <target> <ports> [timeout_ms] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top:N, all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443,8443 2000 concurrency:1000", args[0]);
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
                concurrency = c.max(1).min(10000);
            }
        }
    }
    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }
    eprintln!("HYPER_PARALLEL_TCP target={} ports={} timeout={}ms concurrency={}",
        target, ports.len(), timeout_ms, concurrency);

    let start = Instant::now();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    stream::iter(ports.iter().copied())
        .map(|port| {
            let target = target.to_string();
            async move {
                scan_port(&target, port, timeout_ms).await
            }
        })
        .buffer_unordered(concurrency)
        .for_each(|result| {
            let tx = tx.clone();
            async move {
                if let Some(r) = result {
                    let _ = tx.send(r);
                }
            }
        })
        .await;

    drop(tx);
    let mut raws: Vec<RawScan> = Vec::with_capacity(ports.len().min(1000));
    while let Some(r) = rx.recv().await {
        raws.push(r);
    }

    let analyzed: Vec<ScanResult> = raws.par_iter().map(|raw| {
        let (service, product, version) = analyze_banner(raw.port, &raw.banner, raw.tls);
        let banner = sanitize_banner(&raw.banner);
        ScanResult {
            port: raw.port,
            state: "open".to_string(),
            service,
            product,
            version,
            banner,
            rtt_ms: raw.rtt_ms,
            tls: raw.tls,
        }
    }).collect();

    let elapsed = start.elapsed().as_millis() as u64;
    for r in &analyzed {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }
    eprintln!("FINAL:{{\"target\":\"{}\",\"total\":{},\"open\":{},\"elapsed_ms\":{}}}",
        target, ports.len(), analyzed.len(), elapsed);
}
