use rust_port_scanner::*;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_BANNER: usize = 4096;
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const DEFAULT_WORKERS: usize = 50;

#[derive(Debug, Clone, Serialize)]
struct ScanResult {
    port: u16,
    status: String,
    service: String,
    banner: String,
    version: String,
    protocol: String,
    ttl: u8,
    response_time_ms: f64,
}

#[derive(Debug, Serialize)]
struct StatusUpdate {
    progress: f64,
    message: String,
}

#[derive(Debug, Serialize)]
struct FinalSummary {
    target: String,
    total_ports: usize,
    open_ports: usize,
    filtered: usize,
    closed: usize,
    elapsed_ms: u64,
}

lazy_static::lazy_static! {
    static ref UDP_PROBES: HashMap<u16, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(53, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01".to_vec());
        m.insert(67, b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(68, b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(69, b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(80, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(111, b"\x80\x00\x00\x00".to_vec());
        m.insert(123, b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(135, b"\x04\x00\x2f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(137, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(161, b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec());
        m.insert(162, b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec());
        m.insert(177, b"\x01\x00\x00\x00".to_vec());
        m.insert(389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00".to_vec());
        m.insert(443, b"\x16\x03\x01\x00\x01\x01\x00\x00\x2d\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(500, b"\x30\x2a\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x1d\x02\x02\x01\x4a\x02\x01\x00\x02\x01\x00\x30\x10\x30\x0e\x06\x08\x2b\x06\x01\x02\x01\x01\x02\x00\x00\x00".to_vec());
        m.insert(514, b"".to_vec());
        m.insert(520, b"\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(521, b"\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(546, b"".to_vec());
        m.insert(547, b"".to_vec());
        m.insert(554, b"".to_vec());
        m.insert(623, b"".to_vec());
        m.insert(631, b"".to_vec());
        m.insert(636, b"".to_vec());
        m.insert(873, b"@RSYNCD: 31.0\n".to_vec());
        m.insert(992, b"".to_vec());
        m.insert(993, b"".to_vec());
        m.insert(994, b"".to_vec());
        m.insert(995, b"".to_vec());
        m.insert(1080, b"\x05\x01\x00".to_vec());
        m.insert(1110, b"".to_vec());
        m.insert(1194, b"\x38\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(1234, b"".to_vec());
        m.insert(1433, b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00".to_vec());
        m.insert(1434, b"\x03\x00\x00\x00".to_vec());
        m.insert(1645, b"".to_vec());
        m.insert(1701, b"".to_vec());
        m.insert(1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec());
        m.insert(2049, b"".to_vec());
        m.insert(2181, b"".to_vec());
        m.insert(2375, b"GET /containers/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(2376, b"".to_vec());
        m.insert(3128, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(3306, b"\x0a\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(3389, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec());
        m.insert(3478, b"".to_vec());
        m.insert(4500, b"".to_vec());
        m.insert(5000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(5060, b"OPTIONS sip:localhost SIP/2.0\r\nVia: SIP/2.0/UDP hackit.local;branch=z9hG4bK\r\nMax-Forwards: 70\r\nTo: <sip:test@localhost>\r\nCSeq: 1 OPTIONS\r\nCall-ID: 123456@hackit\r\nFrom: <sip:test@localhost>;tag=root\r\nContent-Length: 0\r\n\r\n".to_vec());
        m.insert(5353, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec());
        m.insert(5672, b"".to_vec());
        m.insert(5683, b"\x40\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00".to_vec());
        m.insert(5900, b"RFB 003.008\n".to_vec());
        m.insert(6000, b"".to_vec());
        m.insert(6379, b"PING\r\n".to_vec());
        m.insert(8000, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec());
        m.insert(8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT-RS/3.0\r\n\r\n".to_vec());
        m.insert(8443, b"".to_vec());
        m.insert(8888, b"".to_vec());
        m.insert(9000, b"".to_vec());
        m.insert(9090, b"".to_vec());
        m.insert(9100, b"".to_vec());
        m.insert(9200, b"".to_vec());
        m.insert(10000, b"".to_vec());
        m.insert(11211, b"stats\r\n".to_vec());
        m.insert(25565, b"\xfe\x01\xfa".to_vec());
        m.insert(27017, b"".to_vec());
        m.insert(30718, b"".to_vec());
        m.insert(31337, b"".to_vec());
        m.insert(32400, b"".to_vec());
        m.insert(32764, b"".to_vec());
        m.insert(49152, b"".to_vec());
        m.insert(65535, b"".to_vec());
        m
    };
    static ref SERVICE_MAP: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        m.insert(53, "DNS"); m.insert(67, "DHCP-Server"); m.insert(68, "DHCP-Client");
        m.insert(69, "TFTP"); m.insert(80, "HTTP"); m.insert(111, "RPC");
        m.insert(123, "NTP"); m.insert(135, "MSRPC"); m.insert(137, "NetBIOS-NS");
        m.insert(161, "SNMP"); m.insert(162, "SNMP-Trap"); m.insert(177, "XDMCP");
        m.insert(389, "LDAP"); m.insert(443, "HTTPS"); m.insert(500, "ISAKMP");
        m.insert(514, "Syslog"); m.insert(520, "RIP"); m.insert(521, "RIPng");
        m.insert(546, "DHCPv6-Client"); m.insert(547, "DHCPv6-Server");
        m.insert(554, "RTSP"); m.insert(623, "IPMI"); m.insert(631, "IPP");
        m.insert(636, "LDAPS"); m.insert(873, "Rsync"); m.insert(992, "Telnets");
        m.insert(993, "IMAPS"); m.insert(994, "IRCS"); m.insert(995, "POP3S");
        m.insert(1080, "SOCKS"); m.insert(1194, "OpenVPN");
        m.insert(1433, "MSSQL"); m.insert(1434, "MSSQL-UD");
        m.insert(1701, "L2TP"); m.insert(1900, "UPnP"); m.insert(2000, "Cisco-SCCP");
        m.insert(2049, "NFS"); m.insert(2181, "ZooKeeper");
        m.insert(2375, "Docker"); m.insert(2376, "Docker-TLS");
        m.insert(3128, "Squid"); m.insert(3306, "MySQL"); m.insert(3389, "RDP");
        m.insert(3478, "STUN"); m.insert(4500, "IPsec-NAT");
        m.insert(5000, "UPnP"); m.insert(5060, "SIP");
        m.insert(5353, "mDNS"); m.insert(5432, "PostgreSQL");
        m.insert(5672, "AMQP"); m.insert(5683, "CoAP"); m.insert(5900, "VNC");
        m.insert(6000, "X11"); m.insert(6379, "Redis");
        m.insert(8000, "HTTP-Alt"); m.insert(8080, "HTTP-Alt");
        m.insert(8443, "HTTPS-Alt"); m.insert(8888, "HTTP-Alt");
        m.insert(9000, "CSListener"); m.insert(9090, "Prometheus");
        m.insert(9100, "JetDirect"); m.insert(9200, "Elasticsearch");
        m.insert(10000, "Webmin"); m.insert(11211, "Memcached");
        m.insert(25565, "Minecraft"); m.insert(27017, "MongoDB");
        m.insert(30718, "HTTP-Alt"); m.insert(31337, "BackOrifice");
        m.insert(32400, "Plex"); m.insert(32764, "WRT-Config");
        m.insert(49152, "Windows-RPC"); m.insert(49153, "Windows-RPC");
        m.insert(49154, "Windows-RPC"); m.insert(49155, "Windows-RPC");
        m.insert(49156, "Windows-RPC"); m.insert(49157, "Windows-RPC");
        m.insert(49158, "Windows-RPC"); m.insert(49159, "Windows-RPC");
        m.insert(49160, "Windows-RPC"); m.insert(49161, "Windows-RPC");
        m.insert(49162, "Windows-RPC"); m.insert(49163, "Windows-RPC");
        m.insert(49164, "Windows-RPC"); m.insert(49165, "Windows-RPC");
        m.insert(49166, "Windows-RPC"); m.insert(49167, "Windows-RPC");
        m.insert(49168, "Windows-RPC"); m.insert(49169, "Windows-RPC");
        m.insert(49170, "Windows-RPC"); m.insert(49171, "Windows-RPC");
        m.insert(49172, "Windows-RPC"); m.insert(49173, "Windows-RPC");
        m.insert(49174, "Windows-RPC"); m.insert(49175, "Windows-RPC");
        m.insert(49176, "Windows-RPC"); m.insert(49177, "Windows-RPC");
        m.insert(49178, "Windows-RPC"); m.insert(49179, "Windows-RPC");
        m.insert(49180, "Windows-RPC"); m.insert(49181, "Windows-RPC");
        m.insert(49182, "Windows-RPC"); m.insert(49183, "Windows-RPC");
        m.insert(49184, "Windows-RPC"); m.insert(49185, "Windows-RPC");
        m.insert(49186, "Windows-RPC"); m.insert(49187, "Windows-RPC");
        m.insert(49188, "Windows-RPC"); m.insert(49189, "Windows-RPC");
        m.insert(49190, "Windows-RPC"); m.insert(49191, "Windows-RPC");
        m.insert(49192, "Windows-RPC"); m.insert(65535, "Unknown");
        m
    };
}

fn identify_service(port: u16) -> &'static str {
    SERVICE_MAP.get(&port).copied().unwrap_or("unknown")
}

async fn udp_probe_async(host: &str, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    let start = Instant::now();
    let host_resolved = resolve_host(host).unwrap_or_else(|| host.to_string());
    use tokio::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let addr = format!("{}:{}", host_resolved, port);
    let probe = UDP_PROBES.get(&port).cloned().unwrap_or_else(|| b"\x00".to_vec());
    let _ = socket.send_to(&probe, &addr).await.ok()?;
    let mut buf = [0u8; MAX_BANNER];
    let recv = tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv_from(&mut buf)).await;
    let elapsed = start.elapsed().as_millis() as f64;
    match recv {
        Ok(Ok((n, _))) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n.min(MAX_BANNER)]).to_string();
            let clean: String = banner.chars().filter(|&c| c.is_ascii_graphic() || c == ' ').take(500).collect();
            let service = identify_service(port);
            Some(ScanResult {
                port,
                status: "open".to_string(),
                service: service.to_string(),
                banner: clean,
                version: String::new(),
                protocol: "udp".to_string(),
                ttl: 64,
                response_time_ms: elapsed,
            })
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} --target <host> --ports <ports> [--timeout <ms>] [--workers <N>]", args[0]);
        eprintln!("  ports: comma-separated (53,161), ranges (1-1024), top:N, all");
        eprintln!("Example: {} --target 192.168.1.1 --ports 53,161,123 --timeout 3000 --workers 50", args[0]);
        std::process::exit(1);
    }
    let mut target = String::new();
    let mut port_spec = String::new();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut workers = DEFAULT_WORKERS;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--ports" | "-p" => { i += 1; if i < args.len() { port_spec = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--workers" | "-w" => { i += 1; if i < args.len() { workers = args[i].parse().unwrap_or(DEFAULT_WORKERS); } }
            _ => {}
        }
        i += 1;
    }
    if target.is_empty() || port_spec.is_empty() {
        eprintln!("Error: --target and --ports are required");
        std::process::exit(1);
    }
    let ports = parse_ports(&port_spec);
    if ports.is_empty() {
        eprintln!("Error: no valid ports specified");
        std::process::exit(1);
    }
    eprintln!("UDP_SCANNER target={} ports={} timeout={}ms workers={}", target, ports.len(), timeout_ms, workers);
    let total = ports.len();
    let processed = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    stream::iter(ports.into_iter())
        .for_each_concurrent(workers, |port| {
            let target = target.clone();
            let tx = tx.clone();
            let processed = Arc::clone(&processed);
            async move {
                let result = udp_probe_async(&target, port, timeout_ms).await;
                if let Some(r) = result {
                    let _ = tx.send(r);
                }
                let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                if count % 50 == 0 || count == total {
                    let progress = (count as f64 / total as f64 * 100.0 * 100.0).round() / 100.0;
                    eprintln!("STATUS:{{\"progress\":{},\"message\":\"Scanning port {}/{}\"}}", progress, port, total);
                }
            }
        })
        .await;
    drop(tx);
    let mut final_results: Vec<ScanResult> = Vec::with_capacity(total.min(1000));
    while let Some(r) = rx.recv().await {
        final_results.push(r);
    }
    final_results.sort_by(|a, b| a.port.cmp(&b.port));
    final_results.shrink_to_fit();
    let open_count = final_results.len();
    let filtered = 0;
    let closed = total.saturating_sub(open_count).saturating_sub(filtered);
    let elapsed = start_time.elapsed().as_millis() as u64;
    for r in &final_results {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }
    let summary = FinalSummary {
        target: target.clone(),
        total_ports: total,
        open_ports: open_count,
        filtered,
        closed,
        elapsed_ms: elapsed,
    };
    println!("FINAL:{}", serde_json::to_string(&summary).unwrap());
}
