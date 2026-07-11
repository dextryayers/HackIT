use crate::common::*;
use crate::{progress, progress_done};

pub async fn lookup(target: &str) -> AsnNetworkResult {
    progress!("asn_network", "running");
    let mut result = AsnNetworkResult { target: target.into(), ..Default::default() };
    if let Some(client) = build_client(10) {
        let ip = if target.contains('.') && !target.chars().all(|c| c.is_digit(10) || c == '.') {
            use std::net::ToSocketAddrs;
            format!("{}:0", target).to_socket_addrs().ok().and_then(|mut a| a.next()).map(|a| a.ip().to_string()).unwrap_or_default()
        } else { target.to_string() };
        if !ip.is_empty() {
            if let Ok(resp) = client.get(&format!("https://ipinfo.io/{}/json", ip)).send().await {
                if let Ok(text) = resp.text().await {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        result.asn = val.get("org").and_then(|v| v.as_str()).map(|s| s.to_string());
                        result.country = val.get("country").and_then(|v| v.as_str()).map(|s| s.to_string());
                        result.org = val.get("org").and_then(|v| v.as_str()).map(|s| s.to_string());
                        result.ip_ranges.push(ip.clone());
                    }
                }
            }
        }
    }
    progress_done!("asn_network");
    result
}
