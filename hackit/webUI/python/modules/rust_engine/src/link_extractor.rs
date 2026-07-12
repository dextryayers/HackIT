use crate::common::{ScanConfig, build_client};
use crate::common::LinkExtractorResult;
use std::time::Duration;
use tokio::task;
use regex::Regex;

const FOLLOW_DEPTH: usize = 2;
const MAX_PAGES: usize = 50;

pub async fn scan(target: &str, _config: &ScanConfig) -> LinkExtractorResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let base_url = format!("https://{}", domain);
    let timeout = Duration::from_secs(8);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(20));

    let mut all_internal = std::collections::HashSet::new();
    let mut all_external = std::collections::HashSet::new();
    let mut all_resources = std::collections::HashSet::new();
    let mut all_emails = std::collections::HashSet::new();
    let mut pages_visited = std::collections::HashSet::new();
    let mut queue = vec![base_url.clone()];
    let mut page_count = 0;

    let url_re = Regex::new(r#"(?:href|src)=["']([^"']+)["']"#).unwrap();
    let email_re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    let resource_re = Regex::new(r"\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|gz|tar)$").unwrap();

    while !queue.is_empty() && page_count < MAX_PAGES {
        let batch: Vec<String> = queue.drain(..queue.len().min(10)).collect();
        let mut batch_handles = Vec::new();

        for url in batch {
            if pages_visited.contains(&url) { continue; }
            pages_visited.insert(url.clone());
            page_count += 1;
            let client = client.clone();
            let sem = sem.clone();
            let url_re = url_re.clone();
            let email_re = email_re.clone();
            let resource_re = resource_re.clone();
            let domain = domain.clone();

            batch_handles.push(task::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let resp = client.get(&url).timeout(timeout).send().await.ok()?;
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let mut internal = Vec::new();
                let mut external = Vec::new();
                let mut resources = Vec::new();
                let mut emails = Vec::new();

                for cap in url_re.captures_iter(&body) {
                    let link = cap[1].to_string();
                    if link.starts_with("http") || link.starts_with("//") {
                        let full = if link.starts_with("//") {
                            format!("https:{}", link)
                        } else {
                            link
                        };
                        if full.contains(&domain) {
                            internal.push(full);
                        } else {
                            external.push(full);
                        }
                    } else if link.starts_with('/') {
                        internal.push(format!("https://{}{}", domain, link));
                    }
                }

                for cap in resource_re.captures_iter(&body) {
                    resources.push(cap[0].to_string());
                }

                for cap in email_re.captures_iter(&body) {
                    emails.push(cap[0].to_string().to_lowercase());
                }

                Some((internal, external, resources, emails, status))
            }));
        }

        for h in batch_handles {
            if let Ok(Some((internal, external, resources, emails, _status))) = h.await {
                for url in internal {
                    if !pages_visited.contains(&url) && !queue.contains(&url) {
                        queue.push(url.clone());
                    }
                    all_internal.insert(url);
                }
                for url in external { all_external.insert(url); }
                for r in resources { all_resources.insert(r); }
                for e in emails { all_emails.insert(e); }
            }
        }
    }

    let mut internal_vec: Vec<String> = all_internal.into_iter().collect();
    let mut external_vec: Vec<String> = all_external.into_iter().collect();
    let mut resources_vec: Vec<String> = all_resources.into_iter().collect();
    let mut emails_vec: Vec<String> = all_emails.into_iter().collect();
    internal_vec.sort();
    external_vec.sort();
    resources_vec.sort();
    emails_vec.sort();

    LinkExtractorResult {
        domain,
        pages_visited: pages_visited.len(),
        total_internal_links: internal_vec.len(),
        total_external_links: external_vec.len(),
        total_resources: resources_vec.len(),
        total_emails: emails_vec.len(),
        internal_links: internal_vec.into_iter().take(100).collect(),
        external_links: external_vec.into_iter().take(100).collect(),
        resources: resources_vec.into_iter().take(50).collect(),
        emails: emails_vec.into_iter().take(50).collect(),
    }
}
