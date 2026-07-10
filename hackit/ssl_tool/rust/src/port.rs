use crate::types::*;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

pub async fn scan_port(host: &str, port: u16, tmo: Duration) -> PortScanReport {
    let mut r = PortScanReport::default();
    r.target = host.to_string();

    let addr = format!("{}:{}", host, port);

    let open = match timeout(tmo / 2, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    };

    r.total_scanned = 1;
    if open {
        let pi = PortInfo {
            port,
            open: true,
            service: String::new(),
            tls: port == 443,
            banner: String::new(),
            cert_cn: String::new(),
            protocol: String::new(),
            state: "OPEN".to_string(),
            reason: "syn-ack".to_string(),
            ttl: 0,
            latency_ms: 0.0,
        };
        r.open_ports.push(pi);
        r.total_open = 1;
    }

    r
}
