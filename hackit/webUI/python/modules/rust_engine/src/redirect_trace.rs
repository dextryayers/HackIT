use crate::common::*;
use crate::{progress, progress_done};

pub async fn trace(url: &str) -> RedirectTraceResult {
    progress!("redirect_trace", "running");
    let url = normalize_url(url);
    let mut result = RedirectTraceResult { url: url.clone(), final_url: url.clone(), chain: vec![] };
    if let Some(client) = build_client(10) {
        let mut current = url.clone();
        for _ in 0..10 {
            match client.get(&current).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    result.chain.push(RedirectHop { url: current.clone(), status });
                    if status == 301 || status == 302 || status == 303 || status == 307 || status == 308 {
                        if let Some(location) = resp.headers().get("location").and_then(|v| v.to_str().ok()).map(|s| s.to_string()) {
                            current = if location.starts_with("http") { location } else {
                                let base = current.trim_end_matches('/');
                                format!("{}/{}", base, location.trim_start_matches('/'))
                            };
                            continue;
                        }
                    }
                    result.final_url = current;
                    break;
                }
                Err(_) => {
                    result.chain.push(RedirectHop { url: current.clone(), status: 0 });
                    result.final_url = current;
                    break;
                }
            }
        }
    }
    progress_done!("redirect_trace");
    result
}
