use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

pub struct AdvancedCrawler {
    client: Client,
    max_depth: u32,
    visited: HashSet<String>,
}

impl AdvancedCrawler {
    pub fn new(max_depth: u32) -> Self {
        Self {
            client: Client::builder()
                .user_agent("HackIt-Tactical-Crawler/3.0")
                .timeout(std::time::Duration::from_secs(5)) // Faster timeout
                .danger_accept_invalid_certs(true)
                .pool_max_idle_per_host(20)
                .build()
                .unwrap(),
            max_depth,
            visited: HashSet::new(),
        }
    }

    pub async fn crawl(&mut self, start_url: &str) -> Vec<String> {
        let mut discovered_urls = Vec::new();
        self.crawl_recursive(start_url, 0, &mut discovered_urls).await;
        discovered_urls
    }

    async fn crawl_recursive(&mut self, url: &str, depth: u32, results: &mut Vec<String>) {
        if depth > self.max_depth || self.visited.contains(url) {
            return;
        }

        self.visited.insert(url.to_string());
        println!("[*] CRAWLER: Visiting {} (Depth {})", url, depth);

        let resp = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return,
        };

        let body = match resp.text().await {
            Ok(t) => t,
            Err(_) => return,
        };

        // 1. Extract links for recursion
        let html = Html::parse_document(&body);
        let selector = Selector::parse("a[href]").unwrap();
        
        let mut next_urls = Vec::new();
        let base_url = Url::parse(url).unwrap();

        for element in html.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(abs_url) = base_url.join(href) {
                    if abs_url.host_str() == base_url.host_str() {
                        let abs_str = abs_url.to_string();
                        if abs_str.contains('?') || abs_str.contains('=') {
                            results.push(abs_str.clone());
                        }
                        next_urls.push(abs_str);
                    }
                }
            }
        }

        // 2. Extract parameters from JS content and analyze DOM
        let js_selector = Selector::parse("script[src]").unwrap();
        for element in html.select(&js_selector) {
            if let Some(src) = element.value().attr("src") {
                if let Ok(js_url) = base_url.join(src) {
                    if let Ok(js_text) = self.fetch_with_retry(&js_url.to_string()).await {
                        // Use SecretFinder to find hidden gems
                        let secrets = crate::secret_finder::SecretFinder::find_secrets(&js_text);
                        for s in secrets { println!("[!] SECRET: {}", s); }
                        
                        // Use DomAnalyzer for form fields
                        let dom_params = crate::dom_analyzer::DomAnalyzer::analyze_forms(&js_text);
                        for p in dom_params { results.push(format!("{}?{}=FUZZ", url, p)); }
                    }
                }
            }
        }

        // Recursive call
        for next in next_urls {
            Box::pin(self.crawl_recursive(&next, depth + 1, results)).await;
        }
    }

    async fn fetch_with_retry(&self, url: &str) -> Result<String, reqwest::Error> {
        self.client.get(url).send().await?.text().await
    }
}
