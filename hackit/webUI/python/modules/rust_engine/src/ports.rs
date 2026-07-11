use crate::common::{TOP_PORTS, PortResult, PortBanner};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_CONCURRENT: usize = 200;
const CONNECT_TIMEOUT_SECS: u64 = 3;
const BANNER_TIMEOUT_SECS: u64 = 4;

async fn check_port(host: &str, port: u16, sem: Arc<Semaphore>) -> Option<PortResult> {
    let _permit = sem.acquire().await.unwrap();
    let addr = format!("{}:{}", host, port);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr)
    ).await.ok().and_then(|r| r.ok())?;
    drop(stream);
    let service = TOP_PORTS.iter()
        .find(|(p,_)| *p == port)
        .map(|(_,s)| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    Some(PortResult { port, service, state: "open".to_string() })
}

pub async fn scan(host: &str) -> Vec<PortResult> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let host = host.to_string();
    let mut handles = Vec::new();
    for &(port, _) in TOP_PORTS {
        let h = host.clone();
        let s = sem.clone();
        handles.push(tokio::spawn(async move { check_port(&h, port, s).await }));
    }
    let mut ports = Vec::new();
    for h in handles {
        if let Ok(Some(p)) = h.await { ports.push(p); }
    }
    ports.sort_by_key(|p| p.port);
    ports
}

const SERVICE_PROBES: &[(u16, &[u8])] = &[
    (21, b"SYST\r\n"),
    (22, b"\r\n"),
    (23, b"\r\n"),
    (25, b"EHLO probe.local\r\n"),
    (53, b"\x00\x1e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"),
    (80, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT/2.0\r\n\r\n"),
    (110, b"CAPA\r\n"),
    (111, b"\r\n"),
    (135, b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00"),
    (139, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (143, b"a001 CAPABILITY\r\n"),
    (389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
    (443, b"\x16\x03\x01\x00\x60\x01\x00\x00\x5c\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9\xcc\xa8\xc0\x13\xc0\x09\xc0\x14\xc0\x0a\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x00\x00"),
    (445, b"\x00\x00\x00\x90\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (500, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
    (587, b"EHLO probe.local\r\n"),
    (993, b""),
    (995, b""),
    (1433, b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (1521, b"\x00\x3c\x00\x00\x01\x00\x00\x00\x01\x34\x01\x2c\x00\x00\x08\x00\x7f\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (2049, b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa5\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (3306, b"\x0a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x33\x00"),
    (3389, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x0b\x00\x00\x00"),
    (5432, b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
    (5900, b"\x52\x46\x42\x20\x30\x30\x33\x2e\x30\x30\x38"),
    (5901, b"\x52\x46\x42\x20\x30\x30\x33\x2e\x30\x30\x38"),
    (6379, b"PING\r\n"),
    (8080, b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: HackIT/2.0\r\n\r\n"),
    (8443, b"\x16\x03\x01\x00\x60\x01\x00\x00\x5c\x03\x03"),
    (9090, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
    (27017, b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
];

fn detect_service_from_banner(port: u16, banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if b.contains("220") && (b.contains("ftp") || b.contains("vsftpd") || b.contains("proftpd") || b.contains("pure-ftpd")) { return Some("FTP".into()); }
    if b.contains("ssh") || b.contains("openssh") || b.contains("dropbear") { return Some("SSH".into()); }
    if b.contains("smtp") || b.contains("esmtp") || b.contains("postfix") || b.contains("sendmail") || b.contains("exim") || b.contains("qmail") { return Some("SMTP".into()); }
    if b.contains("pop3") || (b.starts_with("+ok") || b.starts_with("-err")) { return Some("POP3".into()); }
    if b.contains("imap") || (b.contains("ok") && b.contains("capability")) { return Some("IMAP".into()); }
    if b.contains("http/") || b.contains("nginx") || b.contains("apache") || b.contains("iis") || b.contains("cloudflare") || b.contains("caddy") || b.contains("lighttpd") || b.contains("gunicorn") || b.contains("openresty") { return Some("HTTP".into()); }
    if b.starts_with('\x16') && banner.len() > 5 { return Some("TLS/SSL".into()); }
    if b.contains("redis") || b.contains("+pong") || b.contains("redis-server") { return Some("Redis".into()); }
    if b.contains("mysql") || b.contains("mariadb") || banner.contains("5.") || (banner.contains("8.") && port == 3306) { return Some("MySQL/MariaDB".into()); }
    if b.contains("postgresql") || banner.as_bytes().first() == Some(&0) { return Some("PostgreSQL".into()); }
    if b.contains("mongodb") { return Some("MongoDB".into()); }
    if b.contains("sip/") || b.contains("sip.") { return Some("SIP".into()); }
    if b.contains("rtsp") { return Some("RTSP".into()); }
    if b.contains("ms-sql") || b.contains("mssql") || (port == 1433 && b.contains("sql")) { return Some("MSSQL".into()); }
    if b.contains("oracle") || b.contains("tns") { return Some("Oracle DB".into()); }
    if b.contains("ldap") || b.contains("openldap") { return Some("LDAP".into()); }
    if b.contains("smtps") || (port == 465 && b.contains("error")) { return Some("SMTPS".into()); }
    if b.contains("squid") || b.contains("proxy") && b.contains("http") { return Some("HTTP Proxy".into()); }
    if b.contains("docker") || b.contains("container") { return Some("Docker".into()); }
    if b.contains("memcached") { return Some("Memcached".into()); }
    if b.contains("cassandra") { return Some("Cassandra".into()); }
    if b.contains("elasticsearch") || b.contains("elastic") { return Some("Elasticsearch".into()); }
    if b.contains("kafka") { return Some("Kafka".into()); }
    if b.contains("rabbitmq") || b.contains("amqp") { return Some("RabbitMQ/AMQP".into()); }
    if b.contains("vnc") || b.contains("rfb 0") || b.contains("rfb 00") { return Some("VNC".into()); }
    if b.contains("rdp") || b.contains("terminal") || (port == 3389) { return Some("RDP".into()); }
    if port == 53 && b.len() > 0 { return Some("DNS".into()); }
    None
}

fn detect_os_from_banner(banner: &str) -> Option<String> {
    let b = banner.to_lowercase();
    if b.contains("ubuntu") || b.contains("debian") { Some("Linux (Debian/Ubuntu)") }
    else if b.contains("centos") || b.contains("red hat") || b.contains("rhel") || b.contains("fedora") || b.contains("rocky") || b.contains("almalinux") { Some("Linux (RHEL/Fedora)") }
    else if b.contains("freebsd") || b.contains("openbsd") || b.contains("netbsd") { Some("BSD") }
    else if b.contains("windows") || b.contains("microsoft") || b.contains("win32") || b.contains("win64") || b.contains("iis") { Some("Windows") }
    else if b.contains("darwin") || b.contains("apple") || b.contains("mac os") { Some("macOS") }
    else if b.contains("solaris") || b.contains("sunos") || b.contains("oracle solaris") { Some("Solaris") }
    else if b.contains("alpine") { Some("Linux (Alpine)") }
    else if b.contains("suse") || b.contains("opensuse") { Some("Linux (SUSE)") }
    else if b.contains("arch") || b.contains("manjaro") { Some("Linux (Arch)") }
    else if b.contains("nginx/") || b.contains("apache/") || b.contains("caddy/") || b.contains("lighttpd/") { Some("Web Server") }
    else { None }.map(|s| s.to_string())
}

fn extract_server_header(banner: &str) -> Option<String> {
    for line in banner.lines() {
        let l = line.to_lowercase();
        if l.starts_with("server:") {
            return Some(line.split(':').nth(1)?.trim().to_string());
        }
    }
    None
}

async fn grab_banner(host: &str, port: u16, sem: Arc<Semaphore>) -> Option<PortBanner> {
    let _permit = sem.acquire().await.unwrap();
    let addr = format!("{}:{}", host, port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(&addr)
    ).await.ok().and_then(|r| r.ok())?;

    let service = TOP_PORTS.iter()
        .find(|(p,_)| *p == port)
        .map(|(_,s)| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let probe = SERVICE_PROBES.iter().find(|(p,_)| *p == port).map(|(_,b)| *b);

    if let Some(p) = probe {
        if !p.is_empty() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                stream.write_all(p)
            ).await.ok();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(BANNER_TIMEOUT_SECS),
        stream.read(&mut buf)
    ).await.ok().and_then(|r| r.ok()).unwrap_or(0);

    let banner_text = if n > 0 {
        Some(String::from_utf8_lossy(&buf[..n.min(2048)]).to_string())
    } else {
        None
    };

    let server_header = banner_text.as_ref().and_then(|b| extract_server_header(b));
    let detected = banner_text.as_ref().and_then(|b| detect_service_from_banner(port, b));
    let os_hint = banner_text.as_ref().and_then(|b| detect_os_from_banner(b));

    let final_service = detected.or(server_header).unwrap_or(service);

    Some(PortBanner { port, service: final_service, banner: banner_text, os_hint })
}

pub async fn banner_grab(host: &str) -> Vec<PortBanner> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let host = host.to_string();
    let mut handles = Vec::new();
    for &(port, _) in TOP_PORTS.iter().take(250) {
        let h = host.clone();
        let s = sem.clone();
        handles.push(tokio::spawn(async move { grab_banner(&h, port, s).await }));
    }
    let mut banners = Vec::new();
    for h in handles {
        if let Ok(Some(b)) = h.await { banners.push(b); }
    }
    banners.sort_by_key(|b| b.port);
    banners
}
