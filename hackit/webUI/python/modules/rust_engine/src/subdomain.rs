use crate::common::{COMMON_PREFIXES, SubdomainResult};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;

async fn resolve_sub(resolver: &TokioAsyncResolver, sub: &str) -> Option<String> {
    resolver.lookup(sub, RecordType::A).await
        .ok().and_then(|r| r.iter().next().map(|a| a.to_string()))
}

pub async fn check_wildcard(domain: &str) -> bool {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let random = format!("xwznonexistent{}.{}", ts, domain);
    resolver.lookup(&random, RecordType::A).await.is_ok()
}

pub async fn enumerate(domain: &str) -> Vec<SubdomainResult> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    let has_wildcard = check_wildcard(domain).await;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    // Source 1: crt.sh
    if let Ok(resp) = reqwest::get(&format!("https://crt.sh/?q=%25.{}&output=json&limit=500", domain)).await {
        if let Ok(text) = resp.text().await {
            if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                for item in &items {
                    if let Some(name) = item.get("name_value").and_then(|v| v.as_str()) {
                        for part in name.split('\n') {
                            let s = part.trim().to_lowercase();
                            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                                let ip = if !has_wildcard { resolve_sub(&resolver, &s).await } else { None };
                                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "crt.sh".to_string() });
                            }
                        }
                    }
                }
            }
        }
    }

    // Source 2: AlienVault OTX
    if let Ok(resp) = reqwest::get(&format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain)).await {
        if let Ok(text) = resp.text().await {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(passive) = data["passive_dns"].as_array() {
                    for entry in passive {
                        if let Some(host) = entry["hostname"].as_str() {
                            let s = host.to_lowercase();
                            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                                let ip = entry["address"].as_str().map(|a| a.to_string())
                                    .or_else(|| if !has_wildcard { None } else { None });
                                let ip = if ip.is_none() && !has_wildcard { resolve_sub(&resolver, &s).await } else { ip };
                                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "AlienVault OTX".to_string() });
                            }
                        }
                    }
                }
            }
        }
    }

    // Source 3: ThreatCrowd
    if let Ok(resp) = reqwest::get(&format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain)).await {
        if let Ok(text) = resp.text().await {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(subs) = data["subdomains"].as_array() {
                    for sub in subs {
                        if let Some(s) = sub.as_str().map(|s| s.to_lowercase()) {
                            if s.ends_with(domain) && seen.insert(s.clone()) {
                                let ip = if !has_wildcard { resolve_sub(&resolver, &s).await } else { None };
                                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "ThreatCrowd".to_string() });
                            }
                        }
                    }
                }
            }
        }
    }

    // Source 4: DNS brute force
    for prefix in COMMON_PREFIXES {
        let sub = format!("{}.{}", prefix, domain);
        if !seen.insert(sub.clone()) { continue; }
        let ip = resolver.lookup(&sub, RecordType::A).await
            .ok().and_then(|r| r.iter().next().map(|a| a.to_string()));
        if ip.is_some() || has_wildcard {
            results.push(SubdomainResult { subdomain: sub, resolution: ip, source: "DNS Brute Force".to_string() });
        }
    }

    results
}
