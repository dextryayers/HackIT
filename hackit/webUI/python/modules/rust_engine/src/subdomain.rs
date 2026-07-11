use crate::common::{
    COMMON_PREFIXES, ClientPool, RateLimiter, ScanConfig, SubdomainResult,
};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

// ── Global config (optionally set from main.rs) ──
static CONFIG: OnceLock<ScanConfig> = OnceLock::new();

pub fn set_scan_config(config: ScanConfig) {
    let _ = CONFIG.set(config);
}

fn config_or_default() -> ScanConfig {
    CONFIG.get().cloned().unwrap_or_default()
}

// ── Shared resources (lazily initialised) ──

fn client_pool() -> &'static ClientPool {
    static POOL: OnceLock<ClientPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let t = config_or_default().module_timeout("subdomain", 30);
        ClientPool::with_timeout(t)
    })
}

fn rate_limiter() -> Arc<RateLimiter> {
    static RL: OnceLock<Arc<RateLimiter>> = OnceLock::new();
    RL.get_or_init(|| RateLimiter::new(50)).clone()
}

fn brute_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| {
        let max = config_or_default().module_max("subdomain", 50) as usize;
        Semaphore::new(max)
    })
}

// ── DNS resolution helper ──

async fn resolve_sub(resolver: &TokioAsyncResolver, sub: &str) -> Option<String> {
    resolver
        .lookup(sub, RecordType::A)
        .await
        .ok()
        .and_then(|r| r.iter().next().map(|a| a.to_string()))
}

// ── Wildcard detection ──

pub async fn check_wildcard(domain: &str) -> bool {
    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let random = format!("xwznonexistent{}.{}", ts, domain);
    resolver.lookup(&random, RecordType::A).await.is_ok()
}

// ── Source: crt.sh ──

async fn source_crtsh(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json&limit=500", domain);
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let items: Vec<serde_json::Value> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut results = Vec::new();
    for item in &items {
        let name = match item.get("name_value").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        for part in name.split('\n') {
            let s = part.trim().to_lowercase();
            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                let ip = if !has_wildcard {
                    resolve_sub(resolver, &s).await
                } else {
                    None
                };
                results.push(SubdomainResult {
                    subdomain: s,
                    resolution: ip,
                    source: "crt.sh".to_string(),
                });
            }
        }
    }
    results
}

// ── Source: AlienVault OTX ──

async fn source_alienvault(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let passive = match data["passive_dns"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    for entry in passive {
        let host = match entry["hostname"].as_str() {
            Some(h) => h,
            None => continue,
        };
        let s = host.to_lowercase();
        if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
            let ip = if !has_wildcard {
                let from_api = entry["address"].as_str().map(|a| a.to_string());
                if from_api.is_some() {
                    from_api
                } else {
                    resolve_sub(resolver, &s).await
                }
            } else {
                None
            };
            results.push(SubdomainResult {
                subdomain: s,
                resolution: ip,
                source: "AlienVault OTX".to_string(),
            });
        }
    }
    results
}

// ── Source: ThreatCrowd ──

async fn source_threatcrowd(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
        domain
    );
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let subs = match data["subdomains"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() {
            Some(s) => s.to_lowercase(),
            None => continue,
        };
        if s.ends_with(domain) && seen.insert(s.clone()) {
            let ip = if !has_wildcard {
                resolve_sub(resolver, &s).await
            } else {
                None
            };
            results.push(SubdomainResult {
                subdomain: s,
                resolution: ip,
                source: "ThreatCrowd".to_string(),
            });
        }
    }
    results
}

// ── Source: PassiveTotal (optional, PASSIVETOTAL_API_KEY) ──

async fn source_passivetotal(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = match std::env::var("PASSIVETOTAL_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return Vec::new(),
    };
    let url = format!(
        "https://api.passivetotal.org/v2/enrichment/subdomains?query=*.{}",
        domain
    );
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client
        .get(&url)
        .header("X-API-Key", &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let subs = match data["subdomains"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() {
            Some(s) => s,
            None => continue,
        };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard {
                resolve_sub(resolver, &fqdn).await
            } else {
                None
            };
            results.push(SubdomainResult {
                subdomain: fqdn,
                resolution: ip,
                source: "PassiveTotal".to_string(),
            });
        }
    }
    results
}

// ── Source: SecurityTrails (optional, SECURITYTRAILS_API_KEY) ──

async fn source_securitytrails(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = match std::env::var("SECURITYTRAILS_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return Vec::new(),
    };
    let url = format!(
        "https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false",
        domain
    );
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client
        .get(&url)
        .header("APIKEY", &api_key)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let subs = match data["subdomains"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() {
            Some(s) => s,
            None => continue,
        };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard {
                resolve_sub(resolver, &fqdn).await
            } else {
                None
            };
            results.push(SubdomainResult {
                subdomain: fqdn,
                resolution: ip,
                source: "SecurityTrails".to_string(),
            });
        }
    }
    results
}

// ── Source: Shodan DNS (optional, SHODAN_API_KEY) ──

async fn source_shodan(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = match std::env::var("SHODAN_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return Vec::new(),
    };
    let url = format!(
        "https://api.shodan.io/dns/domain/{}?key={}",
        domain, api_key
    );
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let text = match resp.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let subs = match data["subdomains"].as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() {
            Some(s) => s,
            None => continue,
        };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard {
                resolve_sub(resolver, &fqdn).await
            } else {
                None
            };
            results.push(SubdomainResult {
                subdomain: fqdn,
                resolution: ip,
                source: "Shodan".to_string(),
            });
        }
    }
    results
}

// ── Source: DNS brute force (concurrent, semaphore-limited) ──

async fn source_dns_bruteforce(
    domain: &str,
    seen: &mut HashSet<String>,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let candidates: Vec<String> = COMMON_PREFIXES
        .iter()
        .filter_map(|prefix| {
            let sub = format!("{}.{}", prefix, domain);
            if seen.insert(sub.clone()) {
                Some(sub)
            } else {
                None
            }
        })
        .collect();

    let sem = brute_semaphore();
    let mut tasks = Vec::with_capacity(candidates.len());
    for sub in candidates {
        let r = resolver.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let ip = resolve_sub(&r, &sub).await;
            (sub, ip)
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok((sub, ip)) = task.await {
            if ip.is_some() || has_wildcard {
                results.push(SubdomainResult {
                    subdomain: sub,
                    resolution: ip,
                    source: "DNS Brute Force".to_string(),
                });
            }
        }
    }
    results
}

// ── Public entry point ──

pub async fn enumerate(domain: &str) -> Vec<SubdomainResult> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    let has_wildcard = check_wildcard(domain).await;

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    results.extend(source_crtsh(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_alienvault(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_threatcrowd(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_passivetotal(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_securitytrails(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_shodan(domain, &mut seen, has_wildcard, &resolver).await);
    results.extend(source_dns_bruteforce(domain, &mut seen, has_wildcard, &resolver).await);

    results
}
