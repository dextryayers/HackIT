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

static CONFIG: OnceLock<ScanConfig> = OnceLock::new();

pub fn set_scan_config(config: ScanConfig) {
    let _ = CONFIG.set(config);
}

fn config_or_default() -> ScanConfig {
    CONFIG.get().cloned().unwrap_or_default()
}

fn client_pool() -> &'static ClientPool {
    static POOL: OnceLock<ClientPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let t = config_or_default().module_timeout("subdomain", 30);
        ClientPool::with_timeout(t)
    })
}

fn rate_limiter() -> Arc<RateLimiter> {
    static RL: OnceLock<Arc<RateLimiter>> = OnceLock::new();
    RL.get_or_init(|| RateLimiter::new(100)).clone()
}

fn brute_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| {
        let max = config_or_default().module_max("subdomain", 100) as usize;
        Semaphore::new(max)
    })
}

async fn resolve_sub(resolver: &TokioAsyncResolver, sub: &str) -> Option<String> {
    resolver
        .lookup(sub, RecordType::A)
        .await
        .ok()
        .and_then(|r| r.iter().next().map(|a| a.to_string()))
}

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

async fn fetch_json(client: &reqwest::Client, url: &str) -> Option<serde_json::Value> {
    rate_limiter().acquire().await;
    let resp = client.get(url).send().await.ok()?;
    let text = resp.text().await.ok()?;
    serde_json::from_str(&text).ok()
}

async fn source_crtsh(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json&limit=1000", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let items = match data {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for item in &items {
        let name = match item.get("name_value").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        for part in name.split('\n') {
            let s = part.trim().to_lowercase();
            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                let ip = if !has_wildcard { resolve_sub(resolver, &s).await } else { None };
                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "crt.sh".into() });
            }
        }
    }
    results
}

async fn source_alienvault(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let passive = match data {
        Some(ref v) => v["passive_dns"].as_array(),
        None => return Vec::new(),
    };
    let Some(arr) = passive else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for entry in arr {
        let host = match entry["hostname"].as_str() { Some(h) => h, None => continue };
        let s = host.to_lowercase();
        if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
            let ip = if !has_wildcard {
                let from_api = entry["address"].as_str().map(|a| a.to_string());
                match from_api { Some(a) => Some(a), None => resolve_sub(resolver, &s).await }
            } else { None };
            results.push(SubdomainResult { subdomain: s, resolution: ip, source: "AlienVault OTX".into() });
        }
    }
    results
}

async fn source_threatcrowd(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let subs = match data {
        Some(ref v) => v["subdomains"].as_array(),
        None => return Vec::new(),
    };
    let Some(arr) = subs else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in arr {
        let s = match sub.as_str() { Some(s) => s.to_lowercase(), None => continue };
        if s.ends_with(domain) && seen.insert(s.clone()) {
            let ip = if !has_wildcard { resolve_sub(resolver, &s).await } else { None };
            results.push(SubdomainResult { subdomain: s, resolution: ip, source: "ThreatCrowd".into() });
        }
    }
    results
}

async fn source_passivetotal(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = std::env::var("PASSIVETOTAL_API_KEY").ok().filter(|k| !k.is_empty());
    let Some(key) = api_key else { return Vec::new() };
    let url = format!("https://api.passivetotal.org/v2/enrichment/subdomains?query=*.{}", domain);
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).header("X-API-Key", &key).send().await { Ok(r) => r, Err(_) => return Vec::new() };
    let text = match resp.text().await { Ok(t) => t, Err(_) => return Vec::new() };
    let data: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return Vec::new() };
    let subs = match data["subdomains"].as_array() { Some(a) => a, None => return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() { Some(s) => s, None => continue };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard { resolve_sub(resolver, &fqdn).await } else { None };
            results.push(SubdomainResult { subdomain: fqdn, resolution: ip, source: "PassiveTotal".into() });
        }
    }
    results
}

async fn source_securitytrails(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = std::env::var("SECURITYTRAILS_API_KEY").ok().filter(|k| !k.is_empty());
    let Some(key) = api_key else { return Vec::new() };
    let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false", domain);
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).header("APIKEY", &key).send().await { Ok(r) => r, Err(_) => return Vec::new() };
    let text = match resp.text().await { Ok(t) => t, Err(_) => return Vec::new() };
    let data: serde_json::Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => return Vec::new() };
    let subs = match data["subdomains"].as_array() { Some(a) => a, None => return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in subs {
        let s = match sub.as_str() { Some(s) => s, None => continue };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard { resolve_sub(resolver, &fqdn).await } else { None };
            results.push(SubdomainResult { subdomain: fqdn, resolution: ip, source: "SecurityTrails".into() });
        }
    }
    results
}

async fn source_shodan(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let api_key = std::env::var("SHODAN_API_KEY").ok().filter(|k| !k.is_empty());
    let Some(key) = api_key else { return Vec::new() };
    let url = format!("https://api.shodan.io/dns/domain/{}?key={}", domain, key);
    let data = fetch_json(&client_pool().client(), &url).await;
    let subs = match data { Some(ref v) => v["subdomains"].as_array(), None => return Vec::new() };
    let Some(arr) = subs else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in arr {
        let s = match sub.as_str() { Some(s) => s, None => continue };
        let fqdn = format!("{}.{}", s, domain).to_lowercase();
        if seen.insert(fqdn.clone()) {
            let ip = if !has_wildcard { resolve_sub(resolver, &fqdn).await } else { None };
            results.push(SubdomainResult { subdomain: fqdn, resolution: ip, source: "Shodan".into() });
        }
    }
    results
}

async fn source_bufferover(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://dns.bufferover.run/dns?q=.{}", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let entries = match data {
        Some(ref v) => v["FDNS_A"].as_array().or_else(|| v["RDNS"].as_array()),
        None => return Vec::new(),
    };
    let Some(arr) = entries else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for entry in arr {
        let line = match entry.as_str() { Some(s) => s, None => continue };
        let parts: Vec<&str> = line.split(',').collect();
        let host = parts.last().unwrap_or(&"").trim().to_lowercase();
        if host.ends_with(domain) && !host.contains('*') && seen.insert(host.clone()) {
            let ip = parts.first().and_then(|p| {
                let trimmed = p.trim();
                if trimmed.contains('.') { Some(trimmed.to_string()) } else { None }
            });
            let resolution = if !has_wildcard {
                match ip { Some(a) => Some(a), None => resolve_sub(resolver, &host).await }
            } else { None };
            results.push(SubdomainResult { subdomain: host, resolution, source: "BufferOver".into() });
        }
    }
    results
}

async fn source_rapiddns(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://rapiddns.io/subdomain/{}?full=1", domain);
    let client = client_pool().client();
    rate_limiter().acquire().await;
    let resp = match client.get(&url).header("User-Agent", "Mozilla/5.0").send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let html = match resp.text().await { Ok(t) => t, Err(_) => return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    let pattern = format!(r#"[\w.-]+\.{}"#, regex::escape(domain));
    if let Ok(re) = regex::Regex::new(&pattern) {
        for m in re.find_iter(&html) {
            let s = m.as_str().to_lowercase();
            if s.ends_with(domain) && seen.insert(s.clone()) {
                let ip = if !has_wildcard { resolve_sub(resolver, &s).await } else { None };
                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "RapidDNS".into() });
            }
        }
    }
    results
}

async fn source_urlscan(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}&size=100", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let results_arr = match data {
        Some(ref v) => v["results"].as_array(),
        None => return Vec::new(),
    };
    let Some(arr) = results_arr else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for item in arr {
        let page = match item.get("page") { Some(p) => p, None => continue };
        let host = match page["domain"].as_str().or_else(|| page["asn"].as_str()) {
            Some(h) => h.to_lowercase(),
            None => continue,
        };
        if host.ends_with(domain) && !host.contains('*') && seen.insert(host.clone()) {
            let ip = if !has_wildcard {
                let from_api = page["ip"].as_str().map(|a| a.to_string());
                match from_api { Some(a) => Some(a), None => resolve_sub(resolver, &host).await }
            } else { None };
            results.push(SubdomainResult { subdomain: host, resolution: ip, source: "URLScan".into() });
        }
    }
    results
}

async fn source_certspotter(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let items = match data {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for item in &items {
        let dns_names = match item["dns_names"].as_array() { Some(a) => a, None => continue };
        for name in dns_names {
            let s = match name.as_str() { Some(s) => s.trim().to_lowercase(), None => continue };
            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                let ip = if !has_wildcard { resolve_sub(resolver, &s).await } else { None };
                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "CertSpotter".into() });
            }
        }
    }
    results
}

async fn source_facebook_ct(
    domain: &str,
    has_wildcard: bool,
    resolver: &TokioAsyncResolver,
) -> Vec<SubdomainResult> {
    let url = format!("https://graph.facebook.com/certificates?query=*.{}&limit=1000&fields=domains&pretty=0", domain);
    let data = fetch_json(&client_pool().client(), &url).await;
    let items = match data {
        Some(ref v) => v["data"].as_array(),
        None => return Vec::new(),
    };
    let Some(arr) = items else { return Vec::new() };
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for item in arr {
        let domains = match item["domains"].as_array() { Some(a) => a, None => continue };
        for d in domains {
            let s = match d.as_str() { Some(s) => s.trim().to_lowercase(), None => continue };
            if s.ends_with(domain) && !s.contains('*') && seen.insert(s.clone()) {
                let ip = if !has_wildcard { resolve_sub(resolver, &s).await } else { None };
                results.push(SubdomainResult { subdomain: s, resolution: ip, source: "Facebook CT".into() });
            }
        }
    }
    results
}

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
            if seen.insert(sub.clone()) { Some(sub) } else { None }
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
                results.push(SubdomainResult { subdomain: sub, resolution: ip, source: "DNS Brute Force".into() });
            }
        }
    }
    results
}

pub async fn enumerate(domain: &str) -> Vec<SubdomainResult> {
    let has_wildcard = check_wildcard(domain).await;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    let (crtsh, alienvault, threatcrowd, bufferover, rapiddns, urlscan, certspotter, fbct, pt, st, shodan) = tokio::join!(
        source_crtsh(domain, has_wildcard, &resolver),
        source_alienvault(domain, has_wildcard, &resolver),
        source_threatcrowd(domain, has_wildcard, &resolver),
        source_bufferover(domain, has_wildcard, &resolver),
        source_rapiddns(domain, has_wildcard, &resolver),
        source_urlscan(domain, has_wildcard, &resolver),
        source_certspotter(domain, has_wildcard, &resolver),
        source_facebook_ct(domain, has_wildcard, &resolver),
        source_passivetotal(domain, has_wildcard, &resolver),
        source_securitytrails(domain, has_wildcard, &resolver),
        source_shodan(domain, has_wildcard, &resolver),
    );

    let mut seen = HashSet::new();
    let mut results = Vec::new();

    let all_sources = [crtsh, alienvault, threatcrowd, bufferover, rapiddns, urlscan, certspotter, fbct, pt, st, shodan];
    for source in all_sources {
        for r in source {
            if seen.insert(r.subdomain.clone()) {
                results.push(r);
            }
        }
    }

    results.extend(source_dns_bruteforce(domain, &mut seen, has_wildcard, &resolver).await);

    results
}
