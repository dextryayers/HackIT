use crate::config::{ScanConfig, DirResult, ScanOutput};
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}};
use std::time::Duration;
use futures::future::join_all;
use std::collections::HashSet;
use tokio::time::sleep;

pub async fn run_scan(config: ScanConfig) -> ScanOutput {
    let mut client_builder = Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .danger_accept_invalid_certs(true);

    if !config.follow_redirects {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
    } else {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::limited(config.max_redirects));
    }

    if config.http2 {
        client_builder = client_builder.use_rustls_tls();
    }

    if let Some(proxy_url) = &config.proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(p);
        }
    }

    let user_agent = config.user_agent.clone().unwrap_or_else(|| "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TechHunter/DirFinder".to_string());
    client_builder = client_builder.user_agent(user_agent);

    let client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => return ScanOutput { target: config.target, results: vec![], error: Some(format!("Client Build Error: {}", e)), tech_stack: None, waf_detected: None },
    };

    let mut results = Vec::new();
    let base_url = config.target.trim_end_matches('/').to_string();
    let method = Method::from_bytes(config.method.to_uppercase().as_bytes()).unwrap_or(Method::GET);

    let mut headers = HeaderMap::new();
    for (k, v) in &config.headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            headers.insert(name, val);
        }
    }
    if let Some(cookie) = &config.cookie {
        if let Ok(val) = HeaderValue::from_str(cookie) {
            headers.insert(reqwest::header::COOKIE, val);
        }
    }
    if let Some(auth) = &config.auth {
        let auth_val = format!("Basic {}", base64::encode(auth));
        if let Ok(val) = HeaderValue::from_str(&auth_val) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }
    }

    let mut scanned_paths = HashSet::new();
    let mut paths_to_scan = config.paths.clone();

    // Extension expansion
    if !config.extensions.is_empty() {
        let mut expanded = Vec::new();
        for p in &paths_to_scan {
            expanded.push(p.clone());
            if !p.ends_with('/') {
                for ext in &config.extensions {
                    expanded.push(format!("{}.{}", p, ext.trim_start_matches('.')));
                }
            }
        }
        paths_to_scan = expanded;
    }

    // Main scan loop
    for chunk in paths_to_scan.chunks(config.threads) {
        let mut tasks = Vec::new();
        for path in chunk {
            if scanned_paths.contains(path) { continue; }
            scanned_paths.insert(path.clone());

            let full_url = if path.starts_with('/') {
                format!("{}{}", base_url, path)
            } else {
                format!("{}/{}", base_url, path)
            };

            let cl = client.clone();
            let p = path.clone();
            let m = method.clone();
            let h = headers.clone();
            let cfg = config.clone();

            tasks.push(tokio::spawn(async move {
                let mut last_error = None;
                for _ in 0..=cfg.retries {
                    let mut req = cl.request(m.clone(), &full_url).headers(h.clone());
                    if let Some(body) = &cfg.data {
                        req = req.body(body.clone());
                    }

                    match req.send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let size = resp.content_length().unwrap_or(0);
                            
                            // Filtering
                            if !cfg.include_status.is_empty() && !cfg.include_status.contains(&status) { return None; }
                            if cfg.exclude_status.contains(&status) { return None; }
                            if !cfg.include_length.is_empty() && !cfg.include_length.contains(&size) { return None; }
                            if cfg.exclude_length.contains(&size) { return None; }
                            
                            // Default 404 ignore
                            if status == 404 && cfg.include_status.is_empty() { return None; }

                            let content_type = resp.headers()
                                .get("content-type")
                                .map(|v| v.to_str().unwrap_or("unknown").to_string())
                                .unwrap_or_else(|| "unknown".to_string());
                            
                            let redirect = if resp.status().is_redirection() {
                                resp.headers().get("location").map(|v| v.to_str().unwrap_or("").to_string())
                            } else {
                                None
                            };

                            return Some(DirResult {
                                path: p,
                                status,
                                size,
                                content_type,
                                redirect,
                                title: None, // Could extract title later
                            });
                        }
                        Err(e) => {
                            last_error = Some(e);
                            if cfg.delay_ms > 0 {
                                sleep(Duration::from_millis(cfg.delay_ms)).await;
                            }
                        }
                    }
                }
                None
            }));

            if config.delay_ms > 0 {
                sleep(Duration::from_millis(config.delay_ms)).await;
            }
        }

        let chunk_results = join_all(tasks).await;
        for res in chunk_results {
            if let Ok(Some(dir_res)) = res {
                results.push(dir_res);
            }
        }
    }

    ScanOutput {
        target: base_url,
        results,
        error: None,
        tech_stack: None,
        waf_detected: None,
    }
}
