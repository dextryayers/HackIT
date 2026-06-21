use rust_port_scanner::*;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_TIMEOUT_MS: u64 = 2000;
const DEFAULT_INTERVAL_SECS: u64 = 60;
const DEFAULT_CONCURRENCY: usize = 100;

lazy_static::lazy_static! {
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(22, b"SSH-2.0-HackIT-Probe\r\n".to_vec());
        m.insert(25, b"EHLO hackit.discovery\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(443, b"".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(3306, b"".to_vec());
        m.insert(5432, b"".to_vec());
        m.insert(6379, b"PING\r\n".to_vec());
        m
    };
}

#[derive(Debug, Clone, Serialize)]
struct PortState {
    port: u16,
    status: String,
    service: String,
    last_seen_open: Option<u64>,
    last_seen_closed: Option<u64>,
    changes: u64,
}

#[derive(Debug, Clone, Serialize)]
struct StateChange {
    timestamp: u64,
    port: u16,
    old_status: String,
    new_status: String,
    service: String,
}

#[derive(Debug, Clone, Serialize)]
struct MonitorMetrics {
    target: String,
    total_ports_monitored: usize,
    currently_open: usize,
    total_changes: u64,
    uptime_seconds: u64,
    scan_cycles: u64,
    scans_succeeded: u64,
    scans_failed: u64,
    avg_response_ms: f64,
    ports_state: Vec<PortState>,
}

struct MonitorConfig {
    target: String,
    ports: Vec<u16>,
    timeout_ms: u64,
    interval_secs: u64,
    concurrency: usize,
}

async fn check_port(host: &str, port: u16, timeout_ms: u64) -> Option<(u64, String)> {
    let ip = resolve_host(host).unwrap_or_else(|| host.to_string());
    let addr = format!("{}:{}", ip, port);
    let start = Instant::now();
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let rtt = start.elapsed().as_millis() as u64;
            let (mut reader, mut writer) = stream.into_split();
            let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
            if !probe.is_empty() {
                let _ = timeout(Duration::from_millis(timeout_ms / 2), writer.write_all(&probe)).await;
                let _ = writer.shutdown().await;
            }
            let mut buf = vec![0u8; 1024];
            let banner = match timeout(Duration::from_millis(timeout_ms), reader.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    buf.truncate(n);
                    sanitize_banner(&String::from_utf8_lossy(&buf))
                }
                _ => String::new(),
            };
            Some((rtt, banner))
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <target> <ports> [interval_secs] [timeout_ms] [concurrency:N]", args[0]);
        eprintln!("  ports: comma-separated (22,80), ranges (1-1024), top:N, all");
        eprintln!("Example: {} scanme.nmap.org 22,80,443,8080 30 2000 concurrency:100", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];
    let ports = parse_ports(&args[2]);
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut interval_secs = DEFAULT_INTERVAL_SECS;
    let mut concurrency = DEFAULT_CONCURRENCY;

    for arg in &args[3..] {
        if let Some(n) = arg.strip_prefix("concurrency:") {
            if let Ok(c) = n.parse::<usize>() {
                concurrency = c.max(1).min(1000);
            }
        } else if let Ok(secs) = arg.parse::<u64>() {
            if secs < 3600 {
                interval_secs = secs.max(5);
            } else {
                timeout_ms = secs;
            }
        }
    }

    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }

    let config = MonitorConfig {
        target: target.to_string(),
        ports,
        timeout_ms,
        interval_secs,
        concurrency,
    };

    eprintln!("REAL_TIME_MONITOR target={} ports={} interval={}s timeout={}ms concurrency={}",
        config.target, config.ports.len(), config.interval_secs, config.timeout_ms, config.concurrency);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    tokio::spawn(async move {
        let mut sig = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SIGHUP not supported: {}", e);
                return;
            }
        };
        sig.recv().await;
        eprintln!("SIGHUP received - reloading config");
        r.store(false, Ordering::SeqCst);
    });

    let mut state_map: HashMap<u16, PortState> = HashMap::with_capacity(config.ports.len());
    for &port in &config.ports {
        state_map.insert(port, PortState {
            port,
            status: "unknown".to_string(),
            service: service_for_port(port).to_string(),
            last_seen_open: None,
            last_seen_closed: None,
            changes: 0,
        });
    }

    let start_time = Instant::now();
    let mut scan_cycles: u64 = 0;
    let mut scans_succeeded: u64 = 0;
    let mut scans_failed: u64 = 0;
    let mut total_rtt: u64 = 0;
    let mut rtt_samples: u64 = 0;

    while running.load(Ordering::SeqCst) {
        let cycle_start = Instant::now();
        scan_cycles += 1;

        let total = config.ports.len();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let processed = std::sync::atomic::AtomicUsize::new(0);

        use futures::stream::{self, StreamExt};
        stream::iter(config.ports.iter().copied())
            .for_each_concurrent(config.concurrency, |port| {
                let target = config.target.clone();
                let tx = tx.clone();
                let processed = &processed;
                async move {
                    let result = check_port(&target, port, config.timeout_ms).await;
                    let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                    if count % 100 == 0 || count == total {
                        eprintln!("STATUS:{{\"progress\":{:.2},\"message\":\"Cycle {} port {}/{}\"}}",
                            (count as f64 / total as f64) * 100.0, scan_cycles, port, total);
                    }
                    if count == total {
                        let _ = tx.send((port, result));
                    } else {
                        let _ = tx.send((port, result));
                    }
                }
            })
            .await;

        drop(tx);

        let now = start_time.elapsed().as_secs();
        let mut changed_events: Vec<StateChange> = Vec::with_capacity(16);
        let mut open_count = 0;

        while let Some((port, result)) = rx.recv().await {
            let entry = state_map.entry(port).or_insert_with(|| PortState {
                port,
                status: "unknown".to_string(),
                service: service_for_port(port).to_string(),
                last_seen_open: None,
                last_seen_closed: None,
                changes: 0,
            });

            let previous = entry.status.clone();

            match result {
                Some((rtt, banner)) => {
                    scans_succeeded += 1;
                    total_rtt += rtt;
                    rtt_samples += 1;
                    let svc = if !banner.is_empty() {
                        identify_service(&banner, port)
                    } else {
                        service_for_port(port).to_string()
                    };
                    entry.service = svc;
                    entry.last_seen_open = Some(now);
                    entry.status = "open".to_string();
                    open_count += 1;
                }
                None => {
                    scans_failed += 1;
                    entry.last_seen_closed = Some(now);
                    entry.status = "closed".to_string();
                }
            }

            if previous != entry.status && previous != "unknown" {
                entry.changes += 1;
                changed_events.push(StateChange {
                    timestamp: now,
                    port,
                    old_status: previous,
                    new_status: entry.status.clone(),
                    service: entry.service.clone(),
                });
            }
        }

        let avg_ms = if rtt_samples > 0 {
            total_rtt as f64 / rtt_samples as f64
        } else { 0.0 };

        for event in &changed_events {
            println!("CHANGE:{}", serde_json::to_string(event).unwrap());
        }

        let metrics = MonitorMetrics {
            target: config.target.clone(),
            total_ports_monitored: config.ports.len(),
            currently_open: open_count,
            total_changes: state_map.values().map(|s| s.changes).sum(),
            uptime_seconds: now,
            scan_cycles,
            scans_succeeded,
            scans_failed,
            avg_response_ms: avg_ms,
            ports_state: state_map.values().cloned().collect(),
        };
        eprintln!("METRICS:{}", serde_json::to_string(&metrics).unwrap());

        let cycle_duration = cycle_start.elapsed();
        let sleep_duration = Duration::from_secs(config.interval_secs).saturating_sub(cycle_duration);

        if config.interval_secs > 0 {
            tokio::time::sleep(sleep_duration).await;
        }
    }

    eprintln!("Monitor stopped for target={} after {} cycles", config.target, scan_cycles);
}
