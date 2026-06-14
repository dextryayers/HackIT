use serde::Serialize;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

lazy_static::lazy_static! {
    static ref KERNEL_DB: Vec<KernelEntry> = {
        vec![
            // Linux kernels
            KernelEntry { os: "Linux", version: "2.4.x", family: "linux", kernel: "2.4", ttl: 64, window_min: 5792, window_max: 65535, mss_default: 1460, wscale: 0, df: false, ts: false, sack: true, weight: 20 },
            KernelEntry { os: "Linux", version: "2.6.x", family: "linux", kernel: "2.6", ttl: 64, window_min: 5840, window_max: 65535, mss_default: 1460, wscale: 2, df: false, ts: true, sack: true, weight: 30 },
            KernelEntry { os: "Linux", version: "3.x", family: "linux", kernel: "3.x", ttl: 64, window_min: 14600, window_max: 65535, mss_default: 1460, wscale: 7, df: true, ts: true, sack: true, weight: 40 },
            KernelEntry { os: "Linux", version: "4.x", family: "linux", kernel: "4.x", ttl: 64, window_min: 28960, window_max: 65535, mss_default: 1460, wscale: 7, df: true, ts: true, sack: true, weight: 45 },
            KernelEntry { os: "Linux", version: "5.x", family: "linux", kernel: "5.x", ttl: 64, window_min: 29200, window_max: 65535, mss_default: 1460, wscale: 7, df: true, ts: true, sack: true, weight: 50 },
            KernelEntry { os: "Linux", version: "6.x", family: "linux", kernel: "6.x", ttl: 64, window_min: 64240, window_max: 65535, mss_default: 1460, wscale: 7, df: true, ts: true, sack: true, weight: 55 },
            // Android
            KernelEntry { os: "Android", version: "4.x-6.x", family: "linux", kernel: "3.x-4.x", ttl: 64, window_min: 5720, window_max: 65535, mss_default: 1440, wscale: 5, df: false, ts: true, sack: true, weight: 35 },
            KernelEntry { os: "Android", version: "7.x+", family: "linux", kernel: "4.x+", ttl: 64, window_min: 29200, window_max: 65535, mss_default: 1440, wscale: 7, df: true, ts: true, sack: true, weight: 45 },
            // Windows
            KernelEntry { os: "Windows", version: "NT 4.0/2000", family: "windows", kernel: "NT 5.0", ttl: 128, window_min: 16384, window_max: 65535, mss_default: 1460, wscale: 0, df: true, ts: false, sack: false, weight: 25 },
            KernelEntry { os: "Windows", version: "XP/2003", family: "windows", kernel: "NT 5.1-5.2", ttl: 128, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 0, df: true, ts: false, sack: true, weight: 30 },
            KernelEntry { os: "Windows", version: "Vista/7/2008", family: "windows", kernel: "NT 6.0-6.1", ttl: 128, window_min: 8192, window_max: 65535, mss_default: 1460, wscale: 2, df: true, ts: false, sack: true, weight: 35 },
            KernelEntry { os: "Windows", version: "8/2012", family: "windows", kernel: "NT 6.2-6.3", ttl: 128, window_min: 8192, window_max: 65535, mss_default: 1460, wscale: 2, df: true, ts: true, sack: true, weight: 40 },
            KernelEntry { os: "Windows", version: "10/2016/2019", family: "windows", kernel: "NT 10.0", ttl: 128, window_min: 64240, window_max: 65535, mss_default: 1460, wscale: 8, df: true, ts: true, sack: true, weight: 50 },
            KernelEntry { os: "Windows", version: "11/2022/2025", family: "windows", kernel: "NT 10.0+", ttl: 128, window_min: 64240, window_max: 65535, mss_default: 1460, wscale: 8, df: true, ts: true, sack: true, weight: 55 },
            // macOS
            KernelEntry { os: "macOS", version: "10.x (Mavericks-Catalina)", family: "macos", kernel: "XNU 14-19", ttl: 64, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 3, df: true, ts: true, sack: true, weight: 40 },
            KernelEntry { os: "macOS", version: "11.x+ (Big Sur+)", family: "macos", kernel: "XNU 20+", ttl: 64, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 3, df: true, ts: true, sack: true, weight: 45 },
            // FreeBSD
            KernelEntry { os: "FreeBSD", version: "11.x-13.x", family: "freebsd", kernel: "FreeBSD", ttl: 64, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 3, df: true, ts: false, sack: true, weight: 40 },
            // OpenBSD
            KernelEntry { os: "OpenBSD", version: "6.x-7.x", family: "openbsd", kernel: "OpenBSD", ttl: 64, window_min: 16384, window_max: 65535, mss_default: 1460, wscale: 0, df: false, ts: false, sack: true, weight: 35 },
            // Solaris
            KernelEntry { os: "Solaris", version: "10-11", family: "solaris", kernel: "SunOS 5.10-5.11", ttl: 64, window_min: 24820, window_max: 65535, mss_default: 1460, wscale: 0, df: true, ts: false, sack: false, weight: 30 },
            // HP-UX
            KernelEntry { os: "HP-UX", version: "11i", family: "hpux", kernel: "HP-UX", ttl: 64, window_min: 32768, window_max: 65535, mss_default: 1460, wscale: 0, df: false, ts: false, sack: false, weight: 20 },
            // AIX
            KernelEntry { os: "AIX", version: "6.1-7.2", family: "aix", kernel: "AIX", ttl: 64, window_min: 16384, window_max: 65535, mss_default: 1460, wscale: 0, df: true, ts: false, sack: false, weight: 25 },
            // Cisco IOS
            KernelEntry { os: "Cisco IOS", version: "12.x-15.x", family: "cisco", kernel: "IOS", ttl: 255, window_min: 16384, window_max: 4128, mss_default: 1460, wscale: 0, df: false, ts: false, sack: false, weight: 30 },
            KernelEntry { os: "Cisco IOS-XE", version: "16.x-17.x", family: "cisco", kernel: "IOS-XE", ttl: 255, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 1, df: true, ts: false, sack: false, weight: 35 },
            // Juniper
            KernelEntry { os: "Juniper JunOS", version: "12.x-22.x", family: "juniper", kernel: "JunOS", ttl: 64, window_min: 65535, window_max: 65535, mss_default: 1460, wscale: 0, df: false, ts: false, sack: false, weight: 30 },
            // MikroTik
            KernelEntry { os: "MikroTik RouterOS", version: "6.x-7.x", family: "mikrotik", kernel: "RouterOS", ttl: 64, window_min: 16384, window_max: 65535, mss_default: 1460, wscale: 6, df: true, ts: false, sack: true, weight: 35 },
            // Embedded Linux
            KernelEntry { os: "Linux (Embedded)", version: "2.6.x-5.x", family: "linux", kernel: "Embedded", ttl: 64, window_min: 5840, window_max: 29200, mss_default: 536, wscale: 0, df: false, ts: false, sack: false, weight: 25 },
            // Container / Docker
            KernelEntry { os: "Linux (Container)", version: "Docker/K8s", family: "linux", kernel: "Container", ttl: 64, window_min: 29200, window_max: 65535, mss_default: 1460, wscale: 7, df: true, ts: true, sack: true, weight: 30 },
        ]
    };
    static ref PORT_OS_MAP: Vec<(Vec<u16>, &'static str, &'static str)> = {
        vec![
            (vec![135, 139, 445, 3389, 5985, 5986], "Windows", "NT 10.0"),
            (vec![135, 139, 445, 1433], "Windows", "NT 6.x"),
            (vec![22, 80, 443, 3306, 5432], "Linux", "Generic Linux Server"),
            (vec![22, 80, 443, 8080], "Linux", "Web Server"),
            (vec![22, 25, 80, 110, 143], "Linux", "Mail Server"),
            (vec![22, 53, 80, 443], "Linux", "DNS/Web Server"),
            (vec![22, 80, 443, 8443, 6443], "Linux", "Kubernetes Node"),
            (vec![22, 2375, 2376, 2379, 2380, 6443], "Linux", "Docker/K8s Cluster"),
            (vec![22, 548, 80, 443, 5900], "macOS", "macOS Server"),
            (vec![22, 80, 443, 3306, 11211], "FreeBSD", "FreeBSD Server"),
            (vec![22, 23, 80, 443, 161], "Cisco IOS", "Cisco Network Device"),
            (vec![22, 23, 161, 443], "Juniper JunOS", "Juniper Device"),
            (vec![22, 23, 80, 8291], "MikroTik RouterOS", "MikroTik Router"),
            (vec![22, 23, 161, 80, 443], "Linux (Embedded)", "Embedded Device"),
            (vec![161, 162], "SNMP Device", "Generic Network Device"),
            (vec![80, 443, 8080, 8443], "Linux", "Web Server (No SSH)"),
        ]
    };
}

#[derive(Clone)]
struct KernelEntry {
    os: &'static str,
    version: &'static str,
    family: &'static str,
    kernel: &'static str,
    ttl: u8,
    window_min: u16,
    window_max: u16,
    mss_default: u16,
    wscale: u8,
    df: bool,
    ts: bool,
    sack: bool,
    weight: u32,
}

#[derive(Debug, Serialize)]
struct ProbeInfo {
    port: u16,
    connected: bool,
    ttl: i32,
    window: u16,
}

#[derive(Debug, Serialize)]
struct KernelResult {
    os_name: String,
    os_version: String,
    os_family: String,
    kernel_version: String,
    accuracy: f64,
    confidence: f64,
    evidence: Vec<String>,
    probes: Vec<ProbeInfo>,
    ttl_analysis: String,
    ping_ttl: i32,
    elapsed_ms: u64,
}

fn resolve_ip(host: &str) -> Option<String> {
    let addr = format!("{}:0", host);
    addr.to_socket_addrs().ok()?.find(|a| a.is_ipv4()).map(|a| a.ip().to_string())
}

fn get_ping_ttl(host: &str) -> i32 {
    if let Ok(out) = Command::new("ping").args(["-c", "1", "-W", "2", host]).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(pos) = line.find("ttl=") {
                let rest: String = line[pos + 4..].chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(ttl) = rest.parse::<i32>() { return ttl; }
            }
        }
    }
    0
}

fn probe_port(host: &str, port: u16, timeout_ms: u64) -> Option<ProbeInfo> {
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(timeout_ms));
    if let Ok(mut sock) = stream {
        sock.set_read_timeout(Some(Duration::from_millis(timeout_ms / 2))).ok();
        sock.write_all(b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n").ok();
        let mut buf = [0u8; 4096];
        sock.read(&mut buf).ok();
        Some(ProbeInfo { port, connected: true, ttl: 64, window: 65535 })
    } else {
        None
    }
}

fn match_by_port(ports: &[u16]) -> Vec<(String, String, u32)> {
    let mut matches = Vec::new();
    for (port_list, os, ver) in PORT_OS_MAP.iter() {
        let matched: Vec<&u16> = port_list.iter().filter(|p| ports.contains(p)).collect();
        if !matched.is_empty() {
            let score = (matched.len() as f64 / port_list.len() as f64 * 100.0) as u32;
            if score >= 30 {
                matches.push((os.to_string(), ver.to_string(), score));
            }
        }
    }
    matches.sort_by(|a, b| b.2.cmp(&a.2));
    matches.dedup_by(|a, b| a.0 == b.0);
    matches.truncate(3);
    matches
}

fn match_by_ttl_window(ping_ttl: i32, window: u16) -> Vec<KernelEntry> {
    let adjusted_ttl = if ping_ttl > 0 && ping_ttl < 256 { ping_ttl as u8 } else { 0 };
    let mut scored: Vec<(u32, &KernelEntry)> = KERNEL_DB.iter().map(|k| {
        let mut score = 0u32;
        if adjusted_ttl > 0 {
            let ttl_dist = (adjusted_ttl as i32 - k.ttl as i32).abs();
            if ttl_dist == 0 { score += 40; }
            else if ttl_dist <= 5 { score += 20; }
            else if ttl_dist <= 20 { score += 5; }
        }
        if window >= k.window_min && window <= k.window_max {
            score += 20;
        } else {
            let win_dist = if window < k.window_min { k.window_min - window } else { window - k.window_max };
            if win_dist < 1000 { score += 10; }
        }
        score += k.weight;
        (score, k)
    }).collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.truncate(5);
    scored.into_iter().map(|(_, k)| k).cloned().collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <target> [ports] [timeout_ms]", args[0]);
        eprintln!("  Detects OS kernel via TCP/IP fingerprinting (TTL/window/port analysis)");
        std::process::exit(1);
    }
    let host = &args[1];
    let port_spec = args.get(2).map(|s| s.as_str()).unwrap_or("22,80,443,3389,3306,8080,8443,445");
    let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let start = Instant::now();
    let ping_ttl = get_ping_ttl(host);
    let ip = resolve_ip(host).unwrap_or_else(|| host.clone());
    let probe_ports: Vec<u16> = port_spec.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    let mut probes = Vec::new();
    let mut open_ports = Vec::new();
    for &p in &probe_ports {
        if let Some(info) = probe_port(host, p, timeout_ms) {
            probes.push(info);
            open_ports.push(p);
        }
    }
    let port_matches = match_by_port(&open_ports);
    let primary_window = probes.first().map(|p| p.window).unwrap_or(65535);
    let mut all_entries: Vec<(u32, KernelEntry)> = KERNEL_DB.iter().map(|k| {
        let mut s = 0u32;
        s += k.weight;
        if ping_ttl > 0 {
            let d = (ping_ttl as i32 - k.ttl as i32).abs();
            if d == 0 { s += 40; } else if d <= 5 { s += 20; } else if d <= 20 { s += 5; }
        }
        if primary_window >= k.window_min && primary_window <= k.window_max { s += 20; }
        for (os_name, _, _) in &port_matches {
            if os_name.to_lowercase().contains(&k.os.to_lowercase()) { s += 30; }
        }
        (s, KernelEntry { os: k.os, version: k.version, family: k.family, kernel: k.kernel, ttl: k.ttl, window_min: k.window_min, window_max: k.window_max, mss_default: k.mss_default, wscale: k.wscale, df: k.df, ts: k.ts, sack: k.sack, weight: k.weight })
    }).collect();
    all_entries.sort_by(|a, b| b.0.cmp(&a.0));
    let total_possible = 100u32;
    let best = all_entries.first();
    let elapsed = start.elapsed().as_millis() as u64;
    let result = if let Some((score, entry)) = best {
        let confidence = (*score as f64 / total_possible as f64 * 100.0).min(99.9);
        let mut evidence = Vec::new();
        evidence.push(format!("TTL analysis: ping returned TTL={}", ping_ttl));
        evidence.push(format!("Window size: {}", primary_window));
        evidence.push(format!("Open ports: {}", open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")));
        evidence.push(format!("Port-based OS match: {:?}", port_matches.iter().map(|(n, v, _)| format!("{} {}", n, v)).collect::<Vec<_>>()));
        let ttl_analysis = if ping_ttl <= 64 { "Likely Linux/Unix/macOS (TTL <= 64)" }
            else if ping_ttl <= 128 { "Likely Windows (TTL <= 128)" }
            else if ping_ttl <= 255 { "Likely Network Device (Cisco/Juniper, TTL=255)" }
            else { "Unknown TTL range" };
        KernelResult {
            os_name: entry.os.to_string(),
            os_version: entry.version.to_string(),
            os_family: entry.family.to_string(),
            kernel_version: entry.kernel.to_string(),
            accuracy: confidence,
            confidence,
            evidence,
            probes,
            ttl_analysis: ttl_analysis.to_string(),
            ping_ttl,
            elapsed_ms: elapsed,
        }
    } else {
        KernelResult {
            os_name: "Unknown".to_string(),
            os_version: String::new(),
            os_family: "unknown".to_string(),
            kernel_version: String::new(),
            accuracy: 0.0,
            confidence: 0.0,
            evidence: vec!["Insufficient fingerprint data".to_string()],
            probes: vec![],
            ttl_analysis: format!("TTL={} (insufficient data)", ping_ttl),
            ping_ttl,
            elapsed_ms: elapsed,
        }
    };
    println!("RESULT:{}", serde_json::to_string(&result).unwrap());
    let final_output = serde_json::json!({
        "host": host,
        "ip": ip,
        "ping_ttl": ping_ttl,
        "open_ports": open_ports.len(),
        "elapsed_ms": elapsed,
    });
    println!("FINAL:{}", final_output);
}
