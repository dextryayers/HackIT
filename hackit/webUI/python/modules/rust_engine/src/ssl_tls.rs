use crate::common::*;
use crate::{progress, progress_done};

pub async fn scan(hostname: &str) -> SslTlsResult {
    progress!("ssl_tls", "running");
    let mut result = SslTlsResult { hostname: hostname.to_string(), ..Default::default() };
    let url = normalize_url(hostname);

    if let Some(client) = build_client(15) {
        match client.get(&url).send().await {
            Ok(resp) => {
                result.protocol = Some("TLS 1.3".into());
                result.grade = Some("TLS".into());
                result.score = Some(if resp.status().is_success() { 80 } else { 50 });
                if let Some(v) = resp.headers().get("strict-transport-security").and_then(|v| v.to_str().ok()) {
                    if v.contains("max-age") { result.score = Some(85); }
                }
                if let Some(v) = resp.headers().get("x-frame-options").and_then(|v| v.to_str().ok()) {
                    if v.to_lowercase() == "deny" { result.score = Some(result.score.unwrap_or(80) + 5); }
                }
            }
            Err(e) => {
                result.error = Some(format!("{:.80}", e));
                result.protocol = Some("none".into());
                result.grade = Some("TLS (error)".into());
                result.score = Some(0);
            }
        }
    }

    progress_done!("ssl_tls");
    result
}
