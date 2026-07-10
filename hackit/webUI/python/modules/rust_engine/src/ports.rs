use crate::common::{TOP_PORTS, PortResult};

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
