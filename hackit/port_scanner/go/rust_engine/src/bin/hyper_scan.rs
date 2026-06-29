use mimalloc::MiMalloc;
use rust_port_scanner::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

const MAX_BANNER: usize = 4096;
const DEFAULT_TIMEOUT_MS: u64 = 1500;
const DEFAULT_CONCURRENCY: usize = 1000;

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

#[derive(Debug, Serialize)]
struct ScanOut {
    port: u16,
    state: String,
    service: String,
    banner: String,
    rtt_ms: u64,
}

async fn scan_one(host: &str, port: u16, timeout_ms: u64) -> Option<ScanOut> {
    let start = Instant::now();
    let addr = format!("{}:{}", host, port);
    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await;
    let mut stream = match stream {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let rtt_ms = start.elapsed().as_millis() as u64;

    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = timeout(
            Duration::from_millis(timeout_ms / 2),
            stream.write_all(&probe),
        ).await;
    }

    let mut buf = vec![0u8; MAX_BANNER];
    let banner = match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => sanitize(&buf[..n]),
        _ => String::new(),
    };

    let service = service_name(port).unwrap_or_default();
    Some(ScanOut { port, state: "open".to_string(), service, banner, rtt_ms })
}

fn sanitize(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len().min(256));
    for c in s.chars() {
        match c {
            '\r' => {},
            '\n' => { if !out.ends_with(' ') { out.push(' '); } },
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => {}
        }
    }
    if out.len() > 256 { out.truncate(256); }
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <ports> [timeout_ms] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top100, all");
        std::process::exit(1);
    }
    let host = &args[1];
    let ports = parse_ports(&args[2]);
    let mut timeout_ms: u64 = DEFAULT_TIMEOUT_MS;
    let mut concurrency: usize = DEFAULT_CONCURRENCY;
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
        eprintln!("No valid ports specified");
        std::process::exit(1);
    }

    eprintln!("HYPER_SCAN target={} ports={} timeout={}ms concurrency={}",
        host, ports.len(), timeout_ms, concurrency);

    let start = Instant::now();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let results: Vec<ScanOut> = futures::future::join_all(
        ports.iter().map(|&port| {
            let host = host.to_string();
            let sem = sem.clone();
            async move {
                let _permit = sem.acquire().await.ok();
                scan_one(&host, port, timeout_ms).await
            }
        })
    ).await.into_iter().filter_map(|r| r).collect();

    let elapsed = start.elapsed().as_millis() as u64;
    for r in &results {
        let b: String = r.banner.chars().filter(|&c| c != '"' && c != '\\').collect();
        println!(r#"RESULT:{{"port":{},"state":"{}","service":"{}","banner":"{}","rtt_ms":{}}}"#,
            r.port, r.state, r.service, b, r.rtt_ms);
    }
    eprintln!("FINAL:{{\"target\":\"{}\",\"total\":{},\"open\":{},\"elapsed_ms\":{}}}",
        host, ports.len(), results.len(), elapsed);
}
