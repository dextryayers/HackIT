use serde::{Serialize, Deserialize};
use tokio::net::TcpStream;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub service: String,
    pub state: String,
}

pub async fn scan_common_ports(host: &str) -> Vec<PortInfo> {
    let mut open_ports = Vec::new();
    let common_ports = vec![
        (80, "http"), (443, "https"), (8080, "http-proxy"), (8443, "https-alt"),
        (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
        (110, "pop3"), (143, "imap"), (3306, "mysql"), (5432, "postgresql"),
        (6379, "redis"), (27017, "mongodb"), (3389, "rdp"),
    ];

    let mut tasks = Vec::new();

    for (port, service) in common_ports {
        let host = host.to_string();
        tasks.push(tokio::spawn(async move {
            let addr = format!("{}:{}", host, port);
            match timeout(Duration::from_millis(500), TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => Some(PortInfo {
                    port,
                    service: service.to_string(),
                    state: "open".to_string(),
                }),
                _ => None,
            }
        }));
    }

    for task in tasks {
        if let Ok(Some(port_info)) = task.await {
            open_ports.push(port_info);
        }
    }

    open_ports
}
