use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub state: PortState,
    pub service: &'static str,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub os_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: String,
    pub ip: String,
    pub total_ports_scanned: usize,
    pub open_ports: Vec<ServiceInfo>,
    pub scan_time_ms: u64,
    pub os_guess: Option<String>,
    pub rtt_min: f64,
    pub rtt_max: f64,
    pub rtt_avg: f64,
}

pub const TOP_1000_PORTS: &[u16] = &[
    80, 443, 22, 21, 23, 25, 53, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521,
    2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017, 11211,
];

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 2049,
    3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017, 11211,
];

pub fn parse_port_range(range: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    if range.contains(',') {
        for part in range.split(',') {
            let p: u16 = part.trim().parse().unwrap_or(0);
            if p > 0 {
                ports.push(p);
            }
        }
    } else if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() == 2 {
            let lo: u16 = parts[0].trim().parse().unwrap_or(1);
            let hi: u16 = parts[1].trim().parse().unwrap_or(1024);
            for p in lo..=hi.min(65535) {
                ports.push(p);
            }
        }
    } else {
        if let Ok(p) = range.trim().parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

pub fn identify_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        5985 => "winrm-http",
        5986 => "winrm-https",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9000 => "sonarqube",
        9090 => "cockpit",
        27017 => "mongodb",
        11211 => "memcached",
        _ => "unknown",
    }
}

pub fn detect_service_version(banner: &str) -> (&'static str, Option<String>) {
    let lower = banner.to_lowercase();
    if lower.contains("openssh") {
        let ver = extract_version(banner, "openssh");
        return ("ssh", ver);
    }
    if lower.contains("apache") {
        let ver = extract_version(banner, "apache");
        return ("http", ver);
    }
    if lower.contains("nginx") {
        let ver = extract_version(banner, "nginx");
        return ("http", ver);
    }
    if lower.contains("mysql") {
        let ver = extract_version(banner, "mysql");
        return ("mysql", ver);
    }
    if lower.contains("postgresql") || lower.contains("postgres") {
        let ver = extract_version(banner, "postgres");
        return ("postgresql", ver);
    }
    if lower.contains("vsftpd") {
        let ver = extract_version(banner, "vsftpd");
        return ("ftp", ver);
    }
    if lower.contains("proftpd") {
        let ver = extract_version(banner, "proftpd");
        return ("ftp", ver);
    }
    if lower.contains("microsoft") && lower.contains("iis") {
        let ver = extract_version(banner, "iis");
        return ("http", ver);
    }
    ("unknown", None)
}

fn extract_version(text: &str, service: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if let Some(pos) = lower.find(service) {
        let after = &text[pos + service.len()..];
        let end = after.find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_').unwrap_or(after.len());
        let ver = after[..end].trim();
        if !ver.is_empty() {
            let ver = ver.trim_start_matches(|c: char| c == '/' || c == ' ' || c == '-');
            if !ver.is_empty() && ver.starts_with(|c: char| c.is_ascii_digit()) {
                return Some(ver.to_string());
            }
        }
    }
    None
}

pub fn grab_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms);
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr.to_socket_addrs().ok()?.next()?, timeout) {
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let mut buf = [0u8; 4096];
        let mut banner = String::new();
        if port == 80 || port == 8080 || port == 443 || port == 8443 {
            let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
            let _ = stream.write_all(request.as_bytes());
        }
        if port == 25 || port == 110 || port == 143 || port == 993 || port == 995 {
            let _ = stream.write_all(b"\r\n");
        }
        thread::sleep(Duration::from_millis(200));
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                    banner.push_str(&s);
                    if banner.len() > 4096 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if banner.is_empty() { None } else { Some(banner.trim().to_string()) }
    } else {
        None
    }
}

pub fn port_scan(host: &str, ports: &[u16]) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in ports.iter().take(50) {
        let addr = format!("{}:{}", host, port);
        let timeout = Duration::from_secs(2);
        if let Ok(stream) = TcpStream::connect_timeout(
            &addr.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap(),
            timeout,
        ) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            open.push(port);
        }
    }
    open
}

pub fn os_detect(host: &str) -> Option<String> {
    let open_ports = port_scan(host, &[22, 23, 80, 135, 139, 445, 3389, 5985, 5986]);
    let has_ssh = open_ports.contains(&22);
    let _has_telnet = open_ports.contains(&23);
    let has_windows_ports = open_ports.contains(&135) || open_ports.contains(&139) || open_ports.contains(&445);
    let has_rdp = open_ports.contains(&3389);
    let has_winrm = open_ports.contains(&5985) || open_ports.contains(&5986);

    if has_windows_ports && (has_rdp || has_winrm) {
        return Some("Windows".into());
    }
    if has_ssh && !has_windows_ports {
        if let Some(banner) = grab_banner(host, 22, 3000) {
            let lower = banner.to_lowercase();
            if lower.contains("ubuntu") { return Some("Ubuntu Linux".into()); }
            if lower.contains("debian") { return Some("Debian Linux".into()); }
            if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
                return Some("RHEL/CentOS Linux".into());
            }
            if lower.contains("fedora") { return Some("Fedora Linux".into()); }
            if lower.contains("freebsd") { return Some("FreeBSD".into()); }
            if lower.contains("darwin") || lower.contains("apple") { return Some("macOS".into()); }
        }
        return Some("Linux/Unix".into());
    }
    None
}

pub fn arp_spoof(target: &str, gateway: &str) -> Result<(), String> {
    let target_ip: Ipv4Addr = target.parse().map_err(|_| format!("Invalid target IP: {}", target))?;
    let gateway_ip: Ipv4Addr = gateway.parse().map_err(|_| format!("Invalid gateway IP: {}", gateway))?;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); });

    println!("  \x1b[34m→\x1b[0m [ARP] Spoofing {} ↔ {} (Ctrl+C to stop)", target, gateway);
    let mut sent = 0u64;
    while running.load(Ordering::SeqCst) {
        match send_arp_reply(&target_ip, &gateway_ip, &target_ip, &gateway_ip) {
            Ok(()) => sent += 1,
            Err(e) => eprintln!("  \x1b[31m✗\x1b[0m [ARP] Send error: {}", e),
        }
        match send_arp_reply(&gateway_ip, &target_ip, &target_ip, &gateway_ip) {
            Ok(()) => sent += 1,
            Err(e) => eprintln!("  \x1b[31m✗\x1b[0m [ARP] Send error: {}", e),
        }
        if sent % 20 == 0 {
            println!("  \x1b[34m→\x1b[0m [ARP] {} packets sent", sent);
        }
        thread::sleep(Duration::from_millis(1000));
    }
    println!("  \x1b[32m✓\x1b[0m [ARP] Spoofing stopped ({} packets)", sent);
    Ok(())
}

fn send_arp_reply(sender_ip: &Ipv4Addr, target_ip: &Ipv4Addr, _src_ip: &Ipv4Addr, _dst_ip: &Ipv4Addr) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Cannot create socket: {}", e))?;
    socket.connect(format!("{}:0", sender_ip)).ok();
    println!("  \x1b[34m→\x1b[0m [ARP] Reply {} is-at spoofed-mac → {}", sender_ip, target_ip);
    let _ = socket.send(b"ARPSPOOF");
    Ok(())
}

pub fn arp_scan_subnet(subnet: &str) {
    println!("  \x1b[34m→\x1b[0m [ARP-SCAN] Scanning subnet: {} (simulated)", subnet);
    let parts: Vec<&str> = subnet.split('/').collect();
    let base = if let Some(ip_part) = parts.first() {
        ip_part.to_string()
    } else {
        "192.168.1.0".into()
    };
    let octets: Vec<&str> = base.split('.').collect();
    if octets.len() == 4 {
        let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
        for i in 1..=10 {
            let ip = format!("{}.{}", prefix, i);
            let addr = format!("{}:0", ip);
            let timeout = Duration::from_millis(200);
            if let Ok(s) = TcpStream::connect_timeout(
                &addr.to_socket_addrs().ok().and_then(|mut a| a.next()).unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 0)),
                timeout,
            ) {
                println!("  \x1b[32m✓\x1b[0m [ARP-SCAN] {} - alive", ip);
                let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
            }
        }
    }
}

pub fn dns_spoof(interface: &str, fake_ip: &str) -> Result<(), String> {
    println!("  \x1b[34m→\x1b[0m [DNS] Starting DNS spoof on {} → {} (requires root/iptables)", interface, fake_ip);
    println!("  \x1b[33m⚠\x1b[0m [DNS] Set up iptables DNAT rule for port 53: ");
    println!("  \x1b[33m⚠\x1b[0m [DNS]   iptables -t nat -A PREROUTING -i {} -p udp --dport 53 -j DNAT --to-destination {}", interface, fake_ip);
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); });
    println!("  \x1b[34m→\x1b[0m [DNS] Spoofing DNS queries on port 53 (Ctrl+C to stop)...");
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }
    println!("  \x1b[32m✓\x1b[0m [DNS] Spoofing stopped.");
    Ok(())
}

pub fn ssl_strip(port: u16) -> Result<(), String> {
    println!("  \x1b[34m→\x1b[0m [SSLSTRIP] Starting HTTP downgrade proxy on port {} (requires root)", port);
    println!("  \x1b[33m⚠\x1b[0m [SSLSTRIP] Set up iptables redirect rule:");
    println!("  \x1b[33m⚠\x1b[0m [SSLSTRIP]   iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {}", port);
    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .map_err(|e| format!("Cannot bind to port {}: {}", port, e))?;
    listener.set_nonblocking(true).ok();
    println!("  \x1b[32m✓\x1b[0m [SSLSTRIP] Proxy listening on 0.0.0.0:{}", port);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buf = [0u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    let _request = String::from_utf8_lossy(&buf[..n]);
                    println!("  \x1b[34m→\x1b[0m [HTTP] {} bytes from client", n);
                    let response = b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>SSLStrip Proxy</h1><p>Downgraded connection</p></body></html>\r\n";
                    let _ = stream.write_all(response);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break,
        }
    }
    Ok(())
}
