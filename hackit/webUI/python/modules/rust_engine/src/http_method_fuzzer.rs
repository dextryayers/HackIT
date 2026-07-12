use crate::common::{ScanConfig, build_client};
use crate::common::HttpMethodFuzzResult;
use std::time::Duration;
use tokio::task;

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
    "TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL",
    "LOCK", "UNLOCK", "SEARCH", "REPORT",
];

const FUZZ_PATHS: &[&str] = &[
    "/", "/admin", "/api", "/config", "/backup", "/test",
    "/upload", "/delete", "/edit", "/create", "/update",
    "/shell", "/cmd", "/exec", "/debug",
];

pub async fn scan(target: &str, _config: &ScanConfig) -> HttpMethodFuzzResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let base_url = format!("https://{}", domain);
    let timeout = Duration::from_secs(6);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(20));
    let mut handles = Vec::new();

    for &path in FUZZ_PATHS {
        for &method in METHODS {
            let url = format!("{}{}", base_url, path);
            let client = client.clone();
            let sem = sem.clone();
            let method_str = method.to_string();

            handles.push(task::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let resp = client.request(
                    reqwest::Method::from_bytes(method_str.as_bytes()).ok()?,
                    &url,
                ).timeout(timeout).send().await.ok()?;
                let status = resp.status().as_u16();
                let content_length = resp.content_length().unwrap_or(0) as usize;

                Some(crate::common::MethodTestResult {
                    method: method_str,
                    path: path.to_string(),
                    status,
                    content_length,
                    allowed: status != 404 && status != 405 && status < 500,
                })
            }));
        }
    }

    let mut results = Vec::new();
    let mut enabled_count = 0;

    for h in handles {
        if let Ok(Some(r)) = h.await {
            if r.allowed {
                enabled_count += 1;
            }
            results.push(r);
        }
    }

    let mut enabled_methods: Vec<String> = results.iter()
        .filter(|r| r.allowed)
        .map(|r| format!("{} /{} -> {}", r.method, r.path, r.status))
        .collect();
    enabled_methods.sort();
    enabled_methods.dedup();

    let mut methods_by_path: Vec<(String, Vec<String>)> = Vec::new();
    for &path in FUZZ_PATHS {
        let m: Vec<String> = results.iter()
            .filter(|r| r.path == path && r.allowed)
            .map(|r| format!("{} (HTTP {})", r.method, r.status))
            .collect();
        if !m.is_empty() {
            methods_by_path.push((path.to_string(), m));
        }
    }

    HttpMethodFuzzResult {
        domain,
        paths_tested: FUZZ_PATHS.len(),
        methods_tested: METHODS.len(),
        total_requests: FUZZ_PATHS.len() * METHODS.len(),
        enabled_endpoints: enabled_count,
        enabled_methods,
        methods_by_path,
        raw_results: results.into_iter().take(100).collect(),
    }
}
