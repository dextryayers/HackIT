use crate::common::*;
use crate::{progress, progress_done};

pub async fn check(url: &str) -> CorsCheckResult {
    progress!("cors_check", "running");
    let url = normalize_url(url);
    let mut result = CorsCheckResult { url: url.clone(), ..Default::default() };
    if let Some(client) = build_client(10) {
        if let Ok(resp) = client.get(&url).header("Origin", "https://evil.com").send().await {
            let headers = resp.headers();
            let acao = headers.get("access-control-allow-origin").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            let acac = headers.get("access-control-allow-credentials").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            if let Some(ref origin) = acao {
                if origin == "https://evil.com" {
                    result.origin_reflection = true;
                    result.vulnerable = true;
                }
                if origin == "*" {
                    result.wildcard_origin = true;
                    result.vulnerable = true;
                }
            }
            if let Some(ref creds) = acac {
                if creds == "true" {
                    result.credentials_allowed = true;
                    if result.wildcard_origin {
                        result.vulnerable = true;
                    }
                }
            }
        }
    }
    progress_done!("cors_check");
    result
}
