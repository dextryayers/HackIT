use crate::common::{ScanConfig, build_client, SslIntelResult, SslSecurityHeader};
use std::time::Duration;
use tokio::task;
use tokio::net::TcpStream;
use std::sync::Arc;

const COMMON_PORTS: &[u16] = &[443, 8443, 993, 995, 465, 587, 636, 989, 990];

const SECURITY_HEADERS: &[(&str, &str, &str)] = &[
    ("strict-transport-security", "HSTS", "Protects against protocol downgrade attacks"),
    ("content-security-policy", "CSP", "Prevents XSS and data injection attacks"),
    ("x-frame-options", "X-Frame-Options", "Prevents clickjacking"),
    ("x-content-type-options", "X-Content-Type-Options", "Prevents MIME sniffing"),
    ("x-xss-protection", "X-XSS-Protection", "Legacy XSS protection"),
    ("referrer-policy", "Referrer-Policy", "Controls referrer information leakage"),
    ("permissions-policy", "Permissions-Policy", "Controls browser features"),
    ("cross-origin-opener-policy", "COOP", "Isolates browsing context"),
    ("cross-origin-resource-policy", "CORP", "Controls resource loading"),
    ("cross-origin-embedder-policy", "COEP", "Prevents cross-origin leaks"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> SslIntelResult {
    let client = build_client(15).unwrap_or_default();
    let host = target.trim().to_string();
    let timeout = Duration::from_secs(8);
    let sem = Arc::new(tokio::sync::Semaphore::new(20));
    let mut handles = Vec::new();

    for &port in COMMON_PORTS {
        let host = host.clone();
        let sem = sem.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let addr = format!("{}:{}", host, port);
            match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        }));
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(port)) = h.await {
            open_ports.push(port);
        }
    }

    let http_info = check_http_headers(&client, &host).await;
    let security_hdrs = check_security_headers(&client, &host).await;

    SslIntelResult {
        host,
        open_ports,
        certificate: None,
        http_headers: http_info,
        security_headers: security_hdrs,
    }
}

async fn check_http_headers(client: &reqwest::Client, host: &str) -> Vec<(String, String)> {
    let url = format!("https://{}", host);
    match tokio::time::timeout(Duration::from_secs(8), client.get(&url).send()).await {
        Ok(Ok(resp)) => {
            let mut headers = Vec::new();
            for (key, value) in resp.headers() {
                if let Ok(v) = value.to_str() {
                    headers.push((key.to_string(), v.to_string()));
                }
            }
            headers
        }
        _ => vec![],
    }
}

async fn check_security_headers(client: &reqwest::Client, host: &str) -> Vec<SslSecurityHeader> {
    let url = format!("https://{}", host);
    let headers = match tokio::time::timeout(Duration::from_secs(8), client.get(&url).send()).await {
        Ok(Ok(resp)) => resp.headers().clone(),
        _ => return vec![],
    };

    let mut results = Vec::new();
    for &(header, name, desc) in SECURITY_HEADERS {
        let present = headers.get(header).is_some();
        let value = headers.get(header)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        results.push(SslSecurityHeader {
            name: name.to_string(),
            header: header.to_string(),
            present,
            value,
            description: desc.to_string(),
        });
    }
    results
}
