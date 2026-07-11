use crate::common::*;
use crate::{progress, progress_done};
use regex::Regex;

pub async fn analyze(url: &str) -> JsAnalysisResult {
    progress!("js_analysis", "running");
    let mut result = JsAnalysisResult { url: url.into(), ..Default::default() };
    let url = normalize_url(url);
    if let Some(client) = build_client(15) {
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(html) = resp.text().await {
                let re = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();
                let script_urls: Vec<String> = re.captures_iter(&html).map(|c| c[1].to_string()).collect();
                let inline_re = Regex::new(r#"<script[^>]*>([^<]+)</script>"#).unwrap();
                let inline_scripts: Vec<String> = inline_re.captures_iter(&html).map(|c| c[1].to_string()).collect();
                let to_fetch = script_urls.iter().take(3).cloned().collect::<Vec<_>>();
                for js_url in &to_fetch {
                    let js_url_abs = if js_url.starts_with("http") { js_url.clone() } else {
                        format!("{}/{}", url.trim_end_matches('/'), js_url.trim_start_matches('/'))
                    };
                    if let Ok(js_resp) = client.get(&js_url_abs).send().await {
                        if let Ok(js_text) = js_resp.text().await {
                            result.files_analyzed += 1;
                            let api_key_re = Regex::new(r#"(["'])(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9]{10,})\1"#).unwrap();
                            for cap in api_key_re.captures_iter(&js_text) {
                                result.api_keys.push(cap[0].to_string().chars().take(50).collect());
                            }
                            let url_re = Regex::new(r#"["'](https?://[^"']+)["']"#).unwrap();
                            for cap in url_re.captures_iter(&js_text) {
                                let found_url = cap[1].to_string();
                                if found_url.len() > 10 && found_url.len() < 200 && !result.urls.contains(&found_url) {
                                    result.urls.push(found_url);
                                }
                            }
                        }
                    }
                }
                for js in &inline_scripts {
                    if js.contains("apiKey") || js.contains("api_key") || js.contains("token") {
                        result.suspicious.push("Inline script may contain sensitive data".into());
                    }
                }
            }
        }
    }
    result.endpoints = result.urls.iter().filter(|u| u.contains("/api/") || u.contains("/graphql") || u.contains("/rest/")).take(10).cloned().collect();
    progress_done!("js_analysis");
    result
}
