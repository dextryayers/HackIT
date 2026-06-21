use rust_port_scanner::*;
use futures::stream::{self, StreamExt};
use regex;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_MS: u64 = 3000;
const DEFAULT_WORKERS: usize = 200;

#[derive(Debug, Serialize, Clone)]
struct PortResult {
    port: u16,
    status: String,
    service: String,
    banner: String,
    version: String,
    protocol: String,
    response_time_ms: f64,
}

#[derive(Debug, Serialize, Clone)]
struct VulnInfo {
    cve_id: String,
    description: String,
    severity: String,
    cvss: f64,
}

#[derive(Debug, Serialize, Clone)]
struct ServiceInfo {
    product: String,
    version: String,
    extra_info: String,
    cpe: String,
    confidence: f64,
}

#[derive(Debug, Serialize, Clone)]
struct OSInfo {
    os_name: String,
    os_version: String,
    confidence: f64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct PipelineStage {
    name: String,
    enabled: bool,
    elapsed_ms: u64,
    results_count: usize,
}

#[derive(Debug, Serialize)]
struct FinalMassResult {
    target: String,
    total_ports_scanned: usize,
    open_ports: usize,
    services_detected: usize,
    vulnerabilities_found: usize,
    os_guess: String,
    elapsed_ms: u64,
    stages: Vec<PipelineStage>,
    results: Vec<PortResult>,
}

lazy_static::lazy_static! {
    static ref PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(21, b"SYST\r\n".to_vec());
        m.insert(22, b"SSH-2.0-HackIT-MassScan\r\n".to_vec());
        m.insert(25, b"EHLO hackit.masscan\r\n".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-MassScan/3.0\r\nAccept: */*\r\n\r\n".to_vec());
        m.insert(110, b"CAPA\r\n".to_vec());
        m.insert(143, b"A1 CAPABILITY\r\n".to_vec());
        m.insert(443, b"".to_vec());
        m.insert(3306, b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec());
        m.insert(6379, b"PING\r\n".to_vec());
        m.insert(5900, b"RFB 003.008\n".to_vec());
        m.insert(3389, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-MassScan/3.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(27017, b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m
    };
    static ref VULN_SIGNATURES: Vec<(regex::Regex, VulnInfo)> = {
        let mut v = Vec::new();
        v.push((regex::Regex::new(r"(?i)openssh[_-]([0-6]\.[0-9])").unwrap(), VulnInfo { cve_id: "CVE-2024-6387".into(), description: "regreSSHion: RCE in OpenSSH < 9.8".into(), severity: "CRITICAL".into(), cvss: 9.8 }));
        v.push((regex::Regex::new(r"(?i)apache/2\.4\.49").unwrap(), VulnInfo { cve_id: "CVE-2021-41773".into(), description: "Apache path traversal".into(), severity: "CRITICAL".into(), cvss: 9.8 }));
        v.push((regex::Regex::new(r"(?i)vsftpd 2\.3\.4").unwrap(), VulnInfo { cve_id: "CVE-2011-2523".into(), description: "vsftpd backdoor".into(), severity: "CRITICAL".into(), cvss: 9.8 }));
        v.push((regex::Regex::new(r"(?i)mysql 5\.[0-5]").unwrap(), VulnInfo { cve_id: "VULN-EoL".into(), description: "MySQL 5.x EoL".into(), severity: "HIGH".into(), cvss: 7.5 }));
        v.push((regex::Regex::new(r"(?i)redis_version:[23]\.").unwrap(), VulnInfo { cve_id: "CVE-2021-29477".into(), description: "Redis old version".into(), severity: "HIGH".into(), cvss: 8.0 }));
        v.push((regex::Regex::new(r"(?i)php/([5-7]\.[0-9])").unwrap(), VulnInfo { cve_id: "CVE-2023-3824".into(), description: "PHP old version".into(), severity: "CRITICAL".into(), cvss: 9.1 }));
        v
    };
}

fn scan_port_sync(host: &str, port: u16, timeout_ms: u64) -> Option<PortResult> {
    let host = resolve_host(host).unwrap_or_else(|| host.to_string());
    let start = Instant::now();
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_millis(timeout_ms),
    );
    let mut sock = match stream {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
    let probe = PROBES.get(&port).cloned().unwrap_or_else(|| b"\r\n".to_vec());
    if !probe.is_empty() {
        let _ = sock.write_all(&probe);
        let _ = sock.flush();
    }
    let mut buf = [0u8; 4096];
    let banner = match sock.read(&mut buf) {
        Ok(n) if n > 0 => {
            String::from_utf8_lossy(&buf[..n]).chars()
                .filter(|&c| c.is_ascii_graphic() || c == ' ')
                .take(300)
                .collect::<String>()
        }
        _ => String::new(),
    };
    let elapsed = start.elapsed().as_millis() as f64;
    let svc = service_for_port(port);
    let version = extract_service_version(&banner);
    Some(PortResult {
        port,
        status: "open".to_string(),
        service: svc.to_string(),
        banner,
        version,
        protocol: "tcp".to_string(),
        response_time_ms: elapsed,
    })
}

fn guess_os_from_ports(ports: &[u16], ping_ttl: i32) -> (String, f64) {
    let has_rdp = ports.contains(&3389);
    let has_smb = ports.contains(&445);
    let has_msrpc = ports.contains(&135) || ports.contains(&139);
    let has_ssh = ports.contains(&22);
    let has_http = ports.contains(&80) || ports.contains(&443);
    let has_mysql = ports.contains(&3306);
    let has_afp = ports.contains(&548);
    let (os, conf) = if has_rdp || has_smb || has_msrpc {
        if ping_ttl <= 64 && has_ssh { ("Windows (with SSH/WSL)".to_string(), 70.0) }
        else { ("Windows".to_string(), 85.0) }
    } else if has_afp {
        ("macOS".to_string(), 80.0)
    } else if has_ssh && has_http && has_mysql {
        ("Linux (LAMP Server)".to_string(), 90.0)
    } else if has_ssh && has_http {
        ("Linux/Unix".to_string(), 80.0)
    } else if has_http {
        ("Web Server (Linux/Windows)".to_string(), 55.0)
    } else if has_ssh {
        if ping_ttl <= 64 { ("Linux/Unix".to_string(), 70.0) }
        else { ("Windows (with SSH)".to_string(), 50.0) }
    } else {
        let ttl_guess = if ping_ttl <= 64 { "Linux/Unix" } else if ping_ttl <= 128 { "Windows" } else { "Network Device" };
        (format!("{} (TTL-based)", ttl_guess), 35.0)
    };
    (os, conf)
}

fn detect_vulns_in_banner(banner: &str) -> Vec<VulnInfo> {
    let mut vulns = Vec::new();
    for (re, info) in VULN_SIGNATURES.iter() {
        if re.is_match(banner) {
            vulns.push(info.clone());
        }
    }
    vulns
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut workers = DEFAULT_WORKERS;
    let mut stages = vec!["tcp".to_string(), "service".to_string(), "os".to_string(), "vuln".to_string()];
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--ports" | "-p" => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--workers" | "-w" => { i += 1; if i < args.len() { workers = args[i].parse().unwrap_or(DEFAULT_WORKERS); } }
            "--stages" => { i += 1; if i < args.len() { stages = args[i].split(',').map(|s| s.trim().to_lowercase()).collect(); } }
            "--help" | "-h" => {
                eprintln!("Usage: {} --target <host> [--ports <ports>] [--timeout <ms>] [--workers <N>] [--stages tcp,service,os,vuln]", args[0]);
                eprintln!("  Default ports: top1000");
                std::process::exit(0);
            }
            _ => {
                if target.is_empty() { target = args[i].clone(); }
                else if port_spec.is_empty() { port_spec = args[i].clone(); }
            }
        }
        i += 1;
    }
    if target.is_empty() {
        eprintln!("Usage: {} <target> [ports] [timeout_ms] [stages:tcp,service,os,vuln]", args[0]);
        eprintln!("Example: {} scanme.nmap.org --ports 22,80,443 --stages tcp,service,os,vuln", args[0]);
        std::process::exit(1);
    }
    if port_spec.is_empty() { port_spec = "top100".to_string(); }
    let ports = parse_ports(&port_spec);
    let tcp_enabled = stages.contains(&"tcp".to_string()) || stages.contains(&"all".to_string());
    let service_enabled = stages.contains(&"service".to_string());
    let os_enabled = stages.contains(&"os".to_string());
    let vuln_enabled = stages.contains(&"vuln".to_string());
    eprintln!("MASS_SCAN target={} ports={} timeout={}ms workers={} stages={:?}", target, ports.len(), timeout_ms, workers, stages);
    let start_total = Instant::now();
    let mut stage_results: Vec<PipelineStage> = Vec::with_capacity(5);
    let mut open_ports_list: Vec<PortResult> = Vec::new();
    let mut all_service_info: HashMap<u16, (String, String)> = HashMap::new();
    let mut all_vulns: Vec<(u16, VulnInfo)> = Vec::new();
    let mut os_guess = ("Unknown".to_string(), 0.0);

    if tcp_enabled || service_enabled {
        let tcp_start = Instant::now();
        let total = ports.len();
        eprintln!("STATUS:{{\"progress\":0,\"message\":\"TCP discovery: scanning {} ports\"}}", total);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        stream::iter(ports.into_iter())
            .for_each_concurrent(workers, |port| {
                let target = target.clone();
                let tx = tx.clone();
                async move {
                    let result = tokio::task::spawn_blocking(move || {
                        scan_port_sync(&target, port, timeout_ms)
                    }).await.ok().flatten();
                    if let Some(r) = result {
                        let _ = tx.send(r);
                    }
                }
            })
            .await;
        drop(tx);
        let mut results: Vec<PortResult> = Vec::with_capacity(total.min(1000));
        while let Some(r) = rx.recv().await {
            results.push(r);
        }
        results.sort_by(|a, b| a.port.cmp(&b.port));
        open_ports_list = results;
        open_ports_list.shrink_to_fit();
        let tcp_elapsed = tcp_start.elapsed().as_millis() as u64;
        stage_results.push(PipelineStage {
            name: "TCP Discovery".to_string(),
            enabled: true,
            elapsed_ms: tcp_elapsed,
            results_count: open_ports_list.len(),
        });
        eprintln!("STATUS:{{\"progress\":25,\"message\":\"Discovery complete: {} open ports found\"}}", open_ports_list.len());
        for r in &open_ports_list {
            println!("RESULT:{}", serde_json::to_string(r).unwrap());
        }
        if service_enabled && !open_ports_list.is_empty() {
            let svc_start = Instant::now();
            eprintln!("STATUS:{{\"progress\":30,\"message\":\"Service detection on {} ports\"}}", open_ports_list.len());
            let svc_ports: Vec<u16> = open_ports_list.iter().map(|r| r.port).collect();
            for (idx, &port) in svc_ports.iter().enumerate() {
                let progress = 25.0 + (idx as f64 / svc_ports.len() as f64 * 15.0);
                eprintln!("STATUS:{{\"progress\":{:.1},\"message\":\"Service detection: port {} = {}\"}}", progress, port, service_for_port(port));
            }
            for result in &open_ports_list {
                let version = extract_service_version(&result.banner);
                if !version.is_empty() {
                    all_service_info.insert(result.port, (service_for_port(result.port).to_string(), version));
                }
            }
            let svc_elapsed = svc_start.elapsed().as_millis() as u64;
            stage_results.push(PipelineStage {
                name: "Service Detection".to_string(),
                enabled: true,
                elapsed_ms: svc_elapsed,
                results_count: all_service_info.len(),
            });
        }
        if os_enabled {
            let os_start = Instant::now();
            eprintln!("STATUS:{{\"progress\":45,\"message\":\"OS fingerprinting\"}}");
            let ping_ttl = get_ping_ttl(&target);
            let open_port_nums: Vec<u16> = open_ports_list.iter().map(|r| r.port).collect();
            os_guess = guess_os_from_ports(&open_port_nums, ping_ttl);
            eprintln!("STATUS:{{\"progress\":50,\"message\":\"OS guess: {} ({}%)\"}}", os_guess.0, os_guess.1);
            let os_elapsed = os_start.elapsed().as_millis() as u64;
            stage_results.push(PipelineStage {
                name: "OS Detection".to_string(),
                enabled: true,
                elapsed_ms: os_elapsed,
                results_count: 1,
            });
        }
        if vuln_enabled && !open_ports_list.is_empty() {
            let vuln_start = Instant::now();
            eprintln!("STATUS:{{\"progress\":55,\"message\":\"Vulnerability scanning on {} ports\"}}", open_ports_list.len());
            for result in &open_ports_list {
                let vulns = detect_vulns_in_banner(&result.banner);
                for v in vulns {
                    all_vulns.push((result.port, v));
                }
            }
            let vuln_elapsed = vuln_start.elapsed().as_millis() as u64;
            stage_results.push(PipelineStage {
                name: "Vulnerability Scan".to_string(),
                enabled: true,
                elapsed_ms: vuln_elapsed,
                results_count: all_vulns.len(),
            });
            for (port, v) in &all_vulns {
                let voutput = serde_json::json!({
                    "type": "vulnerability",
                    "port": port,
                    "cve_id": &v.cve_id,
                    "description": &v.description,
                    "severity": &v.severity,
                    "cvss": v.cvss,
                });
                println!("RESULT:{}", voutput);
            }
        }
    }
    let elapsed_total = start_total.elapsed().as_millis() as u64;
    let final_out = FinalMassResult {
        target: target.clone(),
        total_ports_scanned: open_ports_list.len(),
        open_ports: open_ports_list.len(),
        services_detected: all_service_info.len(),
        vulnerabilities_found: all_vulns.len(),
        os_guess: format!("{} ({}%)", os_guess.0, os_guess.1 as u8),
        elapsed_ms: elapsed_total,
        stages: stage_results,
        results: open_ports_list,
    };
    eprintln!("STATUS:{{\"progress\":100,\"message\":\"Scan complete\"}}");
    println!("FINAL:{}", serde_json::to_string(&final_out).unwrap());
}
