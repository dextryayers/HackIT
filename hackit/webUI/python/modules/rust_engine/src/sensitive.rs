use crate::common::{SENSITIVE_PATHS, SensitiveResult, SensitiveFile, build_client};

pub async fn scan(url: &str) -> SensitiveResult {
    let base = if url.starts_with("http") { url.trim_end_matches('/').to_string() } else { format!("https://{}", url.trim_end_matches('/')) };
    let mut found = Vec::new();
    let client = match build_client(5) { Some(c) => c, None => return SensitiveResult { url: base, found } };
    let mut handles = Vec::new();
    for path in SENSITIVE_PATHS {
        let full = format!("{}/{}", base, path);
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            if let Ok(resp) = c.get(&full).send().await {
                let status = resp.status().as_u16();
                if status != 404 && status != 403 && status != 301 && status != 302 && status != 0 {
                    let size = resp.headers().get("content-length").and_then(|v| v.to_str().ok()).map(|s| format!("{}B", s));
                    return Some(SensitiveFile { path: full, status, size });
                }
            }
            None
        }));
    }
    for h in handles { if let Ok(Some(f)) = h.await { found.push(f); } }
    SensitiveResult { url: base, found }
}
