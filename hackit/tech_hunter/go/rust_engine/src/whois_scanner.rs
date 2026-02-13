use serde::{Serialize, Deserialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Clone)]
pub struct WhoisInfo {
    pub registrar: String,
    pub creation_date: String,
    pub expiration_date: String,
    pub name_servers: Vec<String>,
    pub raw: Option<String>,
}

pub async fn fetch_whois(domain: &str) -> Option<WhoisInfo> {
    if domain.is_empty() { return None; }
    
    match query_whois_server("whois.iana.org", domain).await {
        Ok(iana_res) => {
            let mut server = "whois.verisign-grs.com"; 
            for line in iana_res.lines() {
                if line.to_lowercase().starts_with("whois:") {
                    server = line.split(':').nth(1).unwrap_or(server).trim();
                    break;
                }
            }
            
            match query_whois_server(server, domain).await {
                Ok(raw) => Some(parse_whois(&raw)),
                Err(_) => Some(parse_whois(&iana_res)),
            }
        },
        Err(_) => None,
    }
}

async fn query_whois_server(server: &str, query: &str) -> Result<String, std::io::Error> {
    let addr = format!("{}:43", server);
    let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timeout")),
    };
    
    stream.write_all(format!("{}\r\n", query).as_bytes()).await?;
    
    let mut res = String::new();
    let mut buffer = [0; 4096];
    
    loop {
        match timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => res.push_str(&String::from_utf8_lossy(&buffer[..n])),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Read timeout")),
        }
    }
    
    Ok(res)
}

fn parse_whois(raw: &str) -> WhoisInfo {
    let mut registrar = "Unknown".to_string();
    let mut creation_date = "Unknown".to_string();
    let mut expiration_date = "Unknown".to_string();
    let mut name_servers = Vec::new();
    
    for line in raw.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("registrar:") {
            registrar = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line_lower.contains("creation date:") || line_lower.contains("created:") {
            creation_date = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line_lower.contains("registry expiry date:") || line_lower.contains("expires:") {
            expiration_date = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line_lower.contains("name server:") || line_lower.contains("nserver:") {
            let ns = line.split(':').nth(1).unwrap_or("").trim().to_string();
            if !ns.is_empty() {
                name_servers.push(ns);
            }
        }
    }
    
    WhoisInfo {
        registrar,
        creation_date,
        expiration_date,
        name_servers,
        raw: Some(raw.chars().take(1000).collect()),
    }
}
