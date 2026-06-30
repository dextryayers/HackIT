use regex::Regex;
use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use lazy_static::lazy_static;

lazy_static! {
    static ref RE_SERVER: Mutex<Regex> = Mutex::new(Regex::new(r"(?im)^server:\s*(.+)$").unwrap());
    static ref RE_POWERED: Mutex<Regex> = Mutex::new(Regex::new(r"(?im)^x-powered-by:\s*(.+)$").unwrap());
    static ref RE_CONTENT: Mutex<Regex> = Mutex::new(Regex::new(r"(?im)^content-type:\s*(.+)$").unwrap());
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub server: String,
    pub powered_by: String,
    pub content_type: String,
    pub status_line: String,
}

pub async fn probe_http(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let sock = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: PortStorm-RS/3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host
    );
    let _ = timeout(
        Duration::from_millis(timeout_ms),
        sock.writable(),
    )
    .await;
    let mut s = sock;
    s.write_all(request.as_bytes()).await.ok()?;
    let mut buf = vec![0u8; 16384];
    let n = timeout(Duration::from_millis(timeout_ms), s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

pub async fn probe_https(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    use rustls::ClientConfig;
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    let addr = format!("{}:{}", host, port);
    let tcp = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr))
        .await
        .ok()?
        .ok()?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates({
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
            root_store
        })
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let dns_name = rustls::ServerName::try_from(host).ok()?;
    let mut tls = timeout(
        Duration::from_millis(timeout_ms),
        connector.connect(dns_name, tcp),
    )
    .await
    .ok()?
    .ok()?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: PortStorm-RS/3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host
    );
    timeout(
        Duration::from_millis(timeout_ms),
        tls.write_all(request.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = vec![0u8; 16384];
    let n = timeout(Duration::from_millis(timeout_ms), tls.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}

pub fn extract_server_info(response: &str) -> ServerInfo {
    let server = RE_SERVER
        .lock()
        .unwrap()
        .captures(response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let powered_by = RE_POWERED
        .lock()
        .unwrap()
        .captures(response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let content_type = RE_CONTENT
        .lock()
        .unwrap()
        .captures(response)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let status_line = response
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    ServerInfo {
        server,
        powered_by,
        content_type,
        status_line,
    }
}
