use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use regex::Regex;
use lazy_static::lazy_static;
use url::Url;

lazy_static! {
    static ref PARAM_REGEX: Regex = Regex::new(r"(\?|\&)([^=]+)\=([^&\s]+)").unwrap();
    static ref JS_PARAM_REGEX: Regex = Regex::new(r#"(?i)(?:["']|&|\?|var |let |const )([a-z0-9_-]+)\s*[:=]\s*["']"#).unwrap();
    static ref USER_AGENTS: Vec<&'static str> = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.45",
    ];
    static ref HARDCODED_EXTENSIONS: Vec<&'static str> = vec![
        ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
        ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp4", ".txt"
    ];
}

pub struct IntelEngine {
    client: Client,
    max_retries: u32,
}

impl IntelEngine {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            max_retries: 3,
        }
    }

    /// Check if the URL has a blacklisted extension
    fn has_extension(&self, url: &str) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            let path = parsed.path();
            for ext in HARDCODED_EXTENSIONS.iter() {
                if path.to_lowercase().ends_with(ext) {
                    return true;
                }
            }
        }
        false
    }

    /// Clean URL by removing redundant ports and standardizing query
    fn clean_url(&self, url: &str) -> String {
        if let Ok(mut parsed) = Url::parse(url) {
            // Remove redundant ports
            if (parsed.scheme() == "http" && parsed.port() == Some(80)) || 
               (parsed.scheme() == "https" && parsed.port() == Some(443)) {
                let _ = parsed.set_port(None);
            }

            // ParamSpider logic: replace parameter values with FUZZ
            let mut query_pairs: Vec<(String, String)> = Vec::new();
            for (key, _) in parsed.query_pairs() {
                query_pairs.push((key.into_owned(), "FUZZ".to_string()));
            }

            if !query_pairs.is_empty() {
                let mut new_query = String::new();
                for (i, (k, v)) in query_pairs.iter().enumerate() {
                    if i > 0 { new_query.push('&'); }
                    new_query.push_str(&format!("{}={}", k, v));
                }
                parsed.set_query(Some(&new_query));
            }
            return parsed.to_string();
        }
        url.to_string()
    }

    /// High-performance passive harvesting with ParamSpider logic
    pub async fn fetch_wayback(&self, domain: &str) -> Vec<String> {
        let url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&collapse=urlkey&fl=original", domain);
        let mut results = HashSet::new();

        for i in 0..self.max_retries {
            let ua = USER_AGENTS[rand::random::<usize>() % USER_AGENTS.len()];
            match self.client.get(&url).header("User-Agent", ua).send().await {
                Ok(resp) => {
                    if let Ok(data) = resp.json::<Value>().await {
                        if let Some(rows) = data.as_array() {
                            for row in rows.iter().skip(1) {
                                if let Some(u) = row.get(0).and_then(|v| v.as_str()) {
                                    if (u.contains('?') || u.contains('=')) && !self.has_extension(u) {
                                        results.insert(self.clean_url(u));
                                    }
                                }
                            }
                        }
                        return results.into_iter().collect();
                    }
                }
                Err(_) => {
                    eprintln!("[!] RUST: Error fetching Wayback for {}. Retrying {}/{}...", domain, i+1, self.max_retries);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
        results.into_iter().collect()
    }

    /// Advanced JS mining for hidden parameters
    pub async fn mine_js_params(&self, js_urls: Vec<String>) -> HashSet<String> {
        let mut params = HashSet::new();
        for url in js_urls {
            if let Ok(resp) = self.client.get(&url).send().await {
                if let Ok(text) = resp.text().await {
                    for cap in JS_PARAM_REGEX.captures_iter(&text) {
                        if let Some(m) = cap.get(1) {
                            params.insert(m.as_str().to_string());
                        }
                    }
                }
            }
        }
        params
    }

    /// Standardizing URLs for Fuzzing (ParamSpider style)
    pub fn fuzzify(&self, url: &str) -> String {
        PARAM_REGEX.replace_all(url, "$1$2=FUZZ").to_string()
    }
}
