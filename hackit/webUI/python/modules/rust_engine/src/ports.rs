use crate::common::{TOP_PORTS, PortResult, PortBanner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn check_port(host: &str, port: u16) -> Option<PortResult> {
    let addr = format!("{}:{}", host, port);
    tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(&addr))
        .await.ok().and_then(|r| r.ok())?;
    let service = TOP_PORTS.iter().find(|(p,_)| *p == port).map(|(_,s)| s.to_string()).unwrap_or_else(|| "unknown".to_string());
    Some(PortResult { port, service, state: "open".to_string() })
}

pub async fn scan(host: &str) -> Vec<PortResult> {
    let mut handles = Vec::new();
    for &(port, _) in TOP_PORTS {
        let h = host.to_string();
        handles.push(tokio::spawn(async move { check_port(&h, port).await }));
    }
    let mut ports = Vec::new();
    for h in handles { if let Ok(Some(p)) = h.await { ports.push(p); } }
    ports.sort_by_key(|p| p.port);
    ports
}

const SERVICE_PROBES: &[(u16, &[u8])] = &[
    (21, b"SYST\r\n"),
    (23, b"\r\n"),
    (25, b"EHLO probe.local\r\n"),
    (80, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    (110, b"CAPA\r\n"),
    (143, b"a001 CAPABILITY\r\n"),
    (443, b"\x16\x03\x01\x00\x02\x01\x00"),
    (445, b"\x00\x00\x00\x90"),
    (587, b"EHLO probe.local\r\n"),
    (8080, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    (8443, b"\x16\x03\x01\x00\x02\x01\x00"),
    (6379, b"PING\r\n"),
    (27017, b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (3306, b"\x0a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x33\x00"),
    (5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
];

pub async fn banner_grab(host: &str) -> Vec<PortBanner> {
    let mut handles = Vec::new();
    for &(port, _) in TOP_PORTS.iter().take(200) {
        let h = host.to_string();
        handles.push(tokio::spawn(async move { grab_banner(&h, port).await }));
    }
    let mut banners = Vec::new();
    for h in handles { if let Ok(Some(b)) = h.await { banners.push(b); } }
    banners.sort_by_key(|b| b.port);
    banners
}

fn detect_service_from_banner(port: u16, banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if b.contains("220") && (b.contains("ftp") || b.contains("vsftpd") || b.contains("proftpd")) { return Some("FTP".into()); }
    if b.contains("ssh") || b.contains("openssh") { return Some("SSH".into()); }
    if b.contains("smtp") || b.contains("esmtp") || b.contains("postfix") || b.contains("sendmail") || b.contains("exim") { return Some("SMTP".into()); }
    if b.contains("pop3") || b.contains("+ok") || b.contains("-err") { return Some("POP3".into()); }
    if b.contains("imap") || b.contains("ok") && b.contains("capability") { return Some("IMAP".into()); }
    if b.contains("http") || b.contains("nginx") || b.contains("apache") || b.contains("iis") || b.contains("cloudflare") { return Some("HTTP".into()); }
    if banner.starts_with('\x16') && banner.len() > 5 { return Some("TLS/SSL".into()); }
    if b.contains("redis") || b.contains("+pong") { return Some("Redis".into()); }
    if b.contains("mysql") || b.contains("mariadb") || b.contains("5.") || b.contains("8.") && port == 3306 { return Some("MySQL".into()); }
    if b.contains("postgresql") || banner.as_bytes().first() == Some(&0) { return Some("PostgreSQL".into()); }
    if b.contains("mongodb") { return Some("MongoDB".into()); }
    if b.contains("sip") || b.contains("sips") { return Some("SIP".into()); }
    if b.contains("rtsp") { return Some("RTSP".into()); }
    None
}

fn detect_os_from_banner(banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if b.contains("ubuntu") || b.contains("debian") { Some("Linux (Debian)") }
    else if b.contains("centos") || b.contains("red hat") || b.contains("rhel") || b.contains("fedora") { Some("Linux (RHEL/Fedora)") }
    else if b.contains("freebsd") { Some("FreeBSD") }
    else if b.contains("windows") || b.contains("microsoft") || b.contains("win32") || b.contains("iis") { Some("Windows") }
    else if b.contains("darwin") || b.contains("apple") { Some("macOS") }
    else if b.contains("solaris") || b.contains("sunos") { Some("Solaris") }
    else if b.contains("alpine") { Some("Linux (Alpine)") }
    else if b.contains("nginx") || b.contains("apache") { Some("Web Server") }
    else { None }.map(|s| s.to_string())
}

async fn grab_banner(host: &str, port: u16) -> Option<PortBanner> {
    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(&addr)
    ).await.ok().and_then(|r| r.ok())?;

    let service = TOP_PORTS.iter().find(|(p,_)| *p == port).map(|(_,s)| s.to_string()).unwrap_or_else(|| "unknown".to_string());
    let probe = SERVICE_PROBES.iter().find(|(p,_)| *p == port).map(|(_,b)| *b);

    if let Some(p) = probe {
        let _ = stream.write_all(p).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf)
    ).await.ok().and_then(|r| r.ok()).unwrap_or(0);

    let banner = if n > 0 { Some(String::from_utf8_lossy(&buf[..n.min(1024)]).to_string()) } else { None };

    let detected = banner.as_ref().and_then(|b| detect_service_from_banner(port, b));
    let os_hint = banner.as_ref().and_then(|b| detect_os_from_banner(b));

    Some(PortBanner { port, service: detected.unwrap_or(service), banner, os_hint })
}
