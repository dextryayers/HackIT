use crate::config::{ScanConfig, DirResult, ScanOutput};
use reqwest::{Client, Method, header::{HeaderMap, HeaderName, HeaderValue}};
use std::time::Duration;
use futures::future::join_all;
use std::collections::HashSet;
use tokio::time::sleep;
use rand::seq::SliceRandom;
use colored::*;
use std::fs;

pub async fn run_scan(config: ScanConfig) -> ScanOutput {
    let mut client_builder = Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .danger_accept_invalid_certs(true);

    // Load User Agents for Anonymity
    let ua_list = match fs::read_to_string("db/user-agents.txt") {
        Ok(content) => content.lines().map(|s| s.to_string()).collect::<Vec<String>>(),
        Err(_) => vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64) HackIt/DirFinder".to_string()],
    };

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

    let mut scanned_paths = HashSet::new();
    let mut paths_to_scan = config.paths.clone();

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
            let uas = ua_list.clone();

            tasks.push(tokio::spawn(async move {
                let mut last_error = None;
                for _ in 0..=cfg.retries {
                    // Strong Anonymity: Rotate User-Agent per request
                    let ua = uas.choose(&mut rand::thread_rng()).unwrap_or(&uas[0]);
                    let mut req = cl.request(m.clone(), &full_url)
                        .headers(h.clone())
                        .header("User-Agent", ua);

                    if let Some(body) = &cfg.data {
                        req = req.body(body.clone());
                    }

                    match req.send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let size = resp.content_length().unwrap_or(0);
                            
                            let status_str_col = match status {
                                200..=299 => status.to_string().green().bold(),
                                300..=399 => status.to_string().yellow(), // Yellow for 3xx
                                401 | 403 => status.to_string().magenta().bold(),
                                404 => status.to_string().red(),
                                400 => status.to_string().truecolor(128, 128, 128), // Gray for 400
                                500..=599 => status.to_string().blue(),
                                _ => status.to_string().white(),
                            };

                            let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
                            let size_str = if size < 1024 {
                                format!("{}B", size)
                            } else if size < 1024 * 1024 {
                                format!("{}KB", size / 1024)
                            } else {
                                format!("{}MB", size / (1024 * 1024))
                            };

                            // Format exactly like screenshot: [15:04:05] 200 -    178B - /admin
                            println!("[{}] {} - {:>7} - {}", 
                                timestamp.white(), // White timestamp
                                status_str_col, 
                                size_str.white(), 
                                format!("/{}", p.trim_start_matches('/')).cyan()
                            );

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
                                title: None,
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
