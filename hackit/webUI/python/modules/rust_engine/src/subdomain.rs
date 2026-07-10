use crate::common::{COMMON_PREFIXES, SubdomainResult};
use std::collections::HashSet;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub async fn enumerate(domain: &str) -> Vec<SubdomainResult> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    if let Ok(resp) = reqwest::get(&format!("https://crt.sh/?q=%25.{}&output=json", domain)).await {
        if let Ok(text) = resp.text().await {
            if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                for item in &items {
                    if let Some(name) = item.get("name_value").and_then(|v| v.as_str()) {
                        for part in name.split('\n') {
                            let s = part.trim().to_lowercase();
                            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                                results.push(SubdomainResult { subdomain: s, resolution: None, source: "crt.sh".to_string() });
                            }
                        }
                    }
                }
            }
        }
    }
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    for prefix in COMMON_PREFIXES {
        let sub = format!("{}.{}", prefix, domain);
        if !seen.insert(sub.clone()) { continue; }
        let ip = resolver.lookup(&sub, trust_dns_resolver::proto::rr::RecordType::A).await
            .map(|r| r.iter().next().map(|a| a.to_string()).unwrap_or_default()).ok();
        results.push(SubdomainResult { subdomain: sub, resolution: ip, source: "DNS Brute Force".to_string() });
    }
    results
}
