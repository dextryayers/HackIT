use crate::common::*;
use crate::{progress, progress_done};
use regex::Regex;
use std::time::Duration;

const DEFAULT_TIMEOUT: u64 = 30;
const RATE_LIMIT_TPS: usize = 5;
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

fn get_timeout() -> u64 {
    std::env::var("PASTE_SCAN_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT)
}

fn contains_credentials(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("password")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("token")
        || lower.contains("auth")
        || lower.contains("credential")
        || lower.contains("bearer")
        || lower.contains("-----begin")
        || lower.contains("private key")
}

fn snippet(text: &str, max: usize) -> Option<String> {
    if text.is_empty() {
        None
    } else if text.len() > max {
        Some(text[..max].to_owned())
    } else {
        Some(text.to_owned())
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            b' ' => '+'.to_string(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

async fn fetch_with_limiter(
    client: &reqwest::Client,
    url: &str,
    limiter: &RateLimiter,
) -> Option<String> {
    limiter.acquire().await;
    client
        .get(url)
        .header("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(get_timeout()))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()
}

async fn psbdmp_search(
    client: &reqwest::Client,
    target: &str,
    limiter: &RateLimiter,
) -> Vec<PasteEntry> {
    let url = format!("https://psbdmp.ws/api/search/{}", target);
    let body = match fetch_with_limiter(client, &url, limiter).await {
        Some(b) => b,
        None => return vec![],
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let items = match json.get("data").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return vec![],
    };
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let content = item.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let title = item.get("title").and_then(|v| v.as_str()).map(|s| s.to_owned());
        entries.push(PasteEntry {
            source: format!("psbdmp.ws/{}", id),
            title,
            snippet: snippet(content, 200),
            contains_credentials: contains_credentials(content),
        });
    }
    entries
}

async fn pastebin_search(
    client: &reqwest::Client,
    target: &str,
    limiter: &RateLimiter,
) -> Vec<PasteEntry> {
    let api_key = std::env::var("PASTEBIN_API_KEY").ok();
    let search_url = format!("https://pastebin.com/search?q={}", target);
    let body = match fetch_with_limiter(client, &search_url, limiter).await {
        Some(b) => b,
        None => return vec![],
    };
    let paste_ids = extract_pastebin_ids(&body);
    if paste_ids.is_empty() {
        return vec![];
    }
    let mut entries = Vec::new();
    for pid in &paste_ids {
        if let Some(entry) = if let Some(ref key) = api_key {
            fetch_pastebin_raw(client, key, pid, limiter).await
        } else {
            None
        } {
            entries.push(entry);
        } else {
            entries.push(PasteEntry {
                source: format!("pastebin.com/{}", pid),
                title: None,
                snippet: None,
                contains_credentials: false,
            });
        }
    }
    entries
}

fn extract_pastebin_ids(html: &str) -> Vec<String> {
    let re = match Regex::new(r#"(?:href="|/)([a-zA-Z0-9]{8,})"#) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut ids = Vec::new();
    for cap in re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let id = m.as_str();
            if id.len() == 8 && id.chars().all(|c| c.is_ascii_alphanumeric()) {
                ids.push(id.to_owned());
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids.truncate(10);
    ids
}

async fn fetch_pastebin_raw(
    client: &reqwest::Client,
    api_key: &str,
    paste_id: &str,
    limiter: &RateLimiter,
) -> Option<PasteEntry> {
    limiter.acquire().await;
    let params = [
        ("api_option", "show_paste"),
        ("api_key", api_key),
        ("paste_id", paste_id),
    ];
    let resp = client
        .post("https://pastebin.com/api/api_raw.php")
        .header("User-Agent", USER_AGENT)
        .form(&params)
        .timeout(Duration::from_secs(get_timeout()))
        .send()
        .await
        .ok()?;
    let text = resp.text().await.ok()?;
    if text.contains("API limit") || text.contains("Bad API request") || text.is_empty() {
        return None;
    }
    Some(PasteEntry {
        source: format!("pastebin.com/{}", paste_id),
        title: None,
        snippet: snippet(&text, 200),
        contains_credentials: contains_credentials(&text),
    })
}

async fn gist_search(
    client: &reqwest::Client,
    target: &str,
    limiter: &RateLimiter,
) -> Vec<PasteEntry> {
    let url = format!(
        "https://api.github.com/search/code?q={}&per_page=20",
        urlencode(target)
    );
    limiter.acquire().await;
    let resp = match client
        .get(&url)
        .header("User-Agent", "HackIT/1.0")
        .header("Accept", "application/vnd.github.v3+json")
        .timeout(Duration::from_secs(get_timeout()))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let items = match json.get("items").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return vec![],
    };
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let html_url = item.get("html_url").and_then(|v| v.as_str()).unwrap_or("");
        let path = item.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let repo_name = item
            .get("repository")
            .and_then(|r| r.get("full_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        entries.push(PasteEntry {
            source: format!("github/{}", repo_name),
            title: Some(format!("File: {}", path)),
            snippet: Some(html_url.to_owned()),
            contains_credentials: false,
        });
    }
    entries
}

async fn google_paste_search(
    client: &reqwest::Client,
    target: &str,
    limiter: &RateLimiter,
) -> Vec<PasteEntry> {
    let query = format!(
        "site:pastebin.com OR site:psbdmp.ws OR site:paste.ee OR site:dpaste.com {}",
        target
    );
    let url = format!(
        "https://www.google.com/search?q={}&num=20",
        urlencode(&query)
    );
    limiter.acquire().await;
    let body = match client
        .get(&url)
        .header("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(get_timeout()))
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return vec![],
        },
        Err(_) => return vec![],
    };
    let href_re = match Regex::new(r#"href="(https?://(?:www\.)?(?:pastebin|psbdmp|paste|dpaste)[^"]*)"#) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut entries = Vec::new();
    for cap in href_re.captures_iter(&body) {
        if let Some(m) = cap.get(1) {
            let found_url = m.as_str();
            if !found_url.contains("google.com") {
                entries.push(PasteEntry {
                    source: found_url.to_owned(),
                    title: None,
                    snippet: None,
                    contains_credentials: false,
                });
            }
        }
    }
    entries
}

pub async fn scan(target: &str) -> PasteScanResult {
    progress!("paste_scan", "running");
    let mut result = PasteScanResult {
        target: target.to_owned(),
        matches: vec![],
    };
    let timeout = get_timeout();
    if let Some(client) = build_client(timeout) {
        let limiter = RateLimiter::new(RATE_LIMIT_TPS);
        result.matches.extend(psbdmp_search(&client, target, &limiter).await);
        result.matches.extend(pastebin_search(&client, target, &limiter).await);
        result.matches.extend(gist_search(&client, target, &limiter).await);
        result.matches.extend(google_paste_search(&client, target, &limiter).await);
    }
    progress_done!("paste_scan");
    result
}
