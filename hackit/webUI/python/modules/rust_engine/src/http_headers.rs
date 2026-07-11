use crate::common::*;
use crate::{progress, progress_done};

pub async fn analyze(url: &str) -> HttpHeadersResult {
    progress!("http_headers", "running");
    let mut result = HttpHeadersResult { url: url.to_string(), ..Default::default() };
    let url = normalize_url(url);

    if let Some(client) = build_client(15) {
        match client.get(&url).send().await {
            Ok(resp) => {
                result.status_code = Some(resp.status().as_u16());
                let mut all_headers = Vec::new();
                for (name, value) in resp.headers().iter() {
                    if let Ok(v) = value.to_str() {
                        all_headers.push((name.as_str().to_string(), v.to_string()));
                    }
                }
                result.all_headers = all_headers;

                if let Some(v) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
                    result.server = Some(v.to_string());
                }

                let security_headers = [
                    ("content-security-policy", "csp"),
                    ("strict-transport-security", "hsts"),
                    ("access-control-allow-origin", "cors"),
                    ("x-frame-options", "x_frame"),
                    ("x-content-type-options", "x_content_type"),
                    ("referrer-policy", "referrer_policy"),
                ];

                let mut score = 0u32;
                let mut missing = Vec::new();
                let key_headers = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"];

                for (hdr, field) in &security_headers {
                    if let Some(val) = resp.headers().get(*hdr).and_then(|v| v.to_str().ok()) {
                        score += 20;
                        match *field {
                            "csp" => result.csp = Some(val.to_string()),
                            "hsts" => result.hsts = Some(val.to_string()),
                            "cors" => result.cors = Some(val.to_string()),
                            "x_frame" => result.x_frame = Some(val.to_string()),
                            "x_content_type" => result.x_content_type = Some(val.to_string()),
                            "referrer_policy" => result.referrer_policy = Some(val.to_string()),
                            _ => {}
                        }
                    } else if key_headers.contains(hdr) {
                        missing.push(hdr.to_string());
                    }
                }

                result.missing_headers = missing;
                result.security_score = Some(score.min(100));
            }
            Err(e) => {
                result.error = Some(format!("{:.80}", e));
            }
        }
    }

    progress_done!("http_headers");
    result
}
