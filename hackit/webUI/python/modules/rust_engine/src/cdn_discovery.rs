use crate::common::*;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

const CDN_HEADER_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"]),
    ("Cloudflare", &["server: cloudflare"]),
    ("CloudFront", &["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-*"]),
    ("CloudFront", &["server: cloudfront"]),
    ("Fastly", &["x-fastly-request-id", "x-served-by", "x-cache", "x-cache-hits", "x-timer"]),
    ("Fastly", &["server: fastly"]),
    ("Akamai", &["x-akamai-transformed", "x-akamai-request-id", "x-akamai-staging"]),
    ("Akamai", &["server: akamai"]),
    ("StackPath", &["x-stackpath-*", "server: stackpath"]),
    ("Edgecast", &["x-ec-*", "server: edgecast"]),
    ("Varnish", &["x-varnish", "via: varnish"]),
    ("LiteSpeed", &["server: litespeed"]),
    ("Imperva", &["x-iinfo", "x-cdn", "x-incapsula-*"]),
    ("Sucuri", &["x-sucuri-id", "x-sucuri-cache"]),
];

const ORIGIN_HOSTNAMES: &[&str] = &[
    "origin", "direct", "origin-www", "backend", "app", "api", "server",
    "web", "lb", "loadbalancer", "proxy", "node", "edge-skip", "bypass",
    "direct-www", "origin-backend", "internal", "real", "true-host",
    "no-cdn", "cdn-origin", "origin-server",
];

fn make_resolver() -> TokioAsyncResolver {
    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
}

async fn lookup_timeout(
    resolver: &TokioAsyncResolver,
    name: &str,
    rtype: RecordType,
    secs: u64,
) -> Vec<String> {
    match tokio::time::timeout(Duration::from_secs(secs), resolver.lookup(name, rtype)).await {
        Ok(Ok(answers)) => answers.iter().map(|a| a.to_string()).collect(),
        _ => Vec::new(),
    }
}

fn header_matches(headers: &[(String, String)], lower_key: &str, lower_val: &str) -> bool {
    headers.iter().any(|(k, v)| {
        if let Some(val_pattern) = lower_key.strip_prefix("server: ") {
            k == "server" && v.contains(val_pattern)
        } else if lower_key.ends_with("-*") {
            let prefix = lower_key.trim_end_matches("-*");
            k.starts_with(prefix)
        } else {
            k == lower_key || (k.contains(lower_key) && v.contains(lower_val))
        }
    })
}

fn detect_cdn_from_headers(headers: &[(String, String)]) -> Vec<CdnProvider> {
    let mut seen = HashSet::new();
    let mut providers = Vec::new();
    for (name, patterns) in CDN_HEADER_SIGNATURES {
        if seen.contains(name) {
            continue;
        }
        for pattern in *patterns {
            let lower = pattern.to_lowercase();
            let (key_part, _) = lower.split_once(": ").unwrap_or((&lower, ""));
            if header_matches(headers, key_part, "") {
                seen.insert(name);
                providers.push(CdnProvider {
                    name: name.to_string(),
                    detected_by: format!("header: {}", pattern),
                    confidence: "High".into(),
                });
                break;
            }
        }
    }
    providers
}

async fn check_multiple_layers(
    client: &reqwest::Client,
    url: &str,
    providers: &mut Vec<CdnProvider>,
) {
    let mut attempt = 0;
    let mut current_url = url.to_string();
    let mut seen = HashSet::new();

    while attempt < 5 {
        let resp = match client.get(&current_url).send().await {
            Ok(r) => r,
            _ => break,
        };
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_lowercase(),
                )
            })
            .collect();

        for provider in detect_cdn_from_headers(&headers) {
            if seen.insert(provider.name.clone()) {
                providers.push(provider);
            }
        }

        let next = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        match next {
            Some(n) if n != current_url => current_url = n,
            _ => break,
        }
        attempt += 1;
    }
}

async fn historical_dns_lookup(domain: &str, origin_ips: &mut Vec<String>) {
    let resolver = make_resolver();
    let mut seen = HashSet::new();

    let record_types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::NS,
        RecordType::MX,
    ];

    for rtype in &record_types {
        let results = lookup_timeout(&resolver, domain, *rtype, 5).await;
        for ip in &results {
            if let Some(addr) = IpAddr::from_str(ip).ok() {
                if seen.insert(addr.to_string()) {
                    let label = format!("{} DNS", rtype_to_str(*rtype));
                    let entry = format!("{} ({})", addr, label);
                    if !origin_ips.contains(&entry) {
                        origin_ips.push(entry);
                    }
                }
            }
        }
    }
}

fn rtype_to_str(rtype: RecordType) -> &'static str {
    match rtype {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::NS => "NS",
        RecordType::MX => "MX",
        _ => "OTHER",
    }
}

async fn check_origin_hostnames(
    client: &reqwest::Client,
    domain: &str,
    origin_ips: &mut Vec<String>,
) {
    let resolver = make_resolver();
    for prefix in ORIGIN_HOSTNAMES {
        let hostname = format!("{}.{}", prefix, domain);
        let ips = lookup_timeout(&resolver, &hostname, RecordType::A, 4).await;
        for ip in ips {
            if let Ok(addr) = IpAddr::from_str(&ip) {
                let entry = format!("{} -> {} (origin hostname)", hostname, addr);
                if !origin_ips.contains(&entry) {
                    origin_ips.push(entry);
                }
                _ = try_fetch_via_ip(client, domain, &addr).await;
            }
        }
    }
}

async fn try_fetch_via_ip(
    client: &reqwest::Client,
    domain: &str,
    ip: &IpAddr,
) -> Option<String> {
    let url = format!("https://{}/", ip);
    let resp = client
        .get(&url)
        .header("Host", domain)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    if status < 500 {
        Some(format!("{}:{}", ip, status))
    } else {
        None
    }
}

async fn scan_subdomains(
    client: &reqwest::Client,
    domain: &str,
    origin_ips: &mut Vec<String>,
) {
    let prefixes = [
        "www", "cdn", "static", "assets", "img", "media", "api", "app",
        "mail", "admin", "blog", "shop", "m", "mobile", "dev",
        "staging", "test", "prod", "origin", "direct", "lb",
    ];

    let resolver = make_resolver();
    let main_ips: HashSet<String> = lookup_timeout(&resolver, domain, RecordType::A, 5)
        .await
        .into_iter()
        .filter_map(|s| IpAddr::from_str(&s).ok())
        .map(|a| a.to_string())
        .collect();

    for prefix in &prefixes {
        let sub = format!("{}.{}", prefix, domain);
        let ips = lookup_timeout(&resolver, &sub, RecordType::A, 4).await;
        for ip_str in &ips {
            if let Ok(addr) = IpAddr::from_str(ip_str) {
                let addr_str = addr.to_string();
                if !main_ips.contains(&addr_str) {
                    let entry = format!("{} -> {} (different from main)", sub, addr_str);
                    if !origin_ips.contains(&entry) {
                        origin_ips.push(entry);
                    }
                    _ = try_fetch_via_ip(client, domain, &addr).await;
                }
            }
        }
    }
}

async fn check_common_cnames(domain: &str, providers: &mut Vec<CdnProvider>, origin_ips: &mut Vec<String>) {
    let resolver = make_resolver();
    let cnames = lookup_timeout(&resolver, domain, RecordType::CNAME, 5).await;

    for cname in &cnames {
        let lower = cname.to_lowercase();

        let cdn_from_cname = if lower.contains("cloudfront.net") {
            Some("CloudFront")
        } else if lower.contains("akamaiedge.net") || lower.contains("akamai.net") {
            Some("Akamai")
        } else if lower.contains("fastly.net") || lower.contains("fastlylb.net") {
            Some("Fastly")
        } else if lower.contains("cloudflare.net") || lower.contains("cloudflare.com") {
            Some("Cloudflare")
        } else if lower.contains("stackpath.net") || lower.contains("stackpathedge.com") {
            Some("StackPath")
        } else if lower.contains("edgecast.net") || lower.contains("verizon.net") {
            Some("Edgecast")
        } else if lower.contains("azureedge.net") || lower.contains("azurefd.net") {
            Some("Azure CDN")
        } else if lower.contains("cdn77.net") || lower.contains("c77.net") {
            Some("CDN77")
        } else if lower.contains("keycdn.com") || lower.contains("kxcdn.com") {
            Some("KeyCDN")
        } else if lower.contains("bunnycdn.net") || lower.contains("b-cdn.net") {
            Some("BunnyCDN")
        } else {
            None
        };

        if let Some(cdn) = cdn_from_cname {
            let already = providers.iter().any(|p| p.name == cdn);
            if !already {
                providers.push(CdnProvider {
                    name: cdn.to_string(),
                    detected_by: format!("CNAME: {}", cname),
                    confidence: "High".into(),
                });
            }
        }

        let cname_ips = lookup_timeout(&resolver, &cname.trim_end_matches('.'), RecordType::A, 5).await;
        for ip_str in &cname_ips {
            if let Ok(addr) = IpAddr::from_str(ip_str) {
                let entry = format!("{} -> {} (CNAME target)", cname.trim_end_matches('.'), addr);
                if !origin_ips.contains(&entry) {
                    origin_ips.push(entry);
                }
            }
        }
    }
}

pub async fn discover(target: &str) -> CdnDiscoveryResult {
    let url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    };
    let domain = url
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    let client = match build_client(15) {
        Some(c) => c,
        None => {
            return CdnDiscoveryResult {
                target: target.to_string(),
                cdn_providers: Vec::new(),
                origin_ips: Vec::new(),
                error: Some("Failed to build HTTP client".into()),
            };
        }
    };

    let mut providers: Vec<CdnProvider> = Vec::new();
    let mut origin_ips: Vec<String> = Vec::new();

    check_common_cnames(&domain, &mut providers, &mut origin_ips).await;

    check_multiple_layers(&client, &url, &mut providers).await;

    historical_dns_lookup(&domain, &mut origin_ips).await;

    check_origin_hostnames(&client, &domain, &mut origin_ips).await;

    scan_subdomains(&client, &domain, &mut origin_ips).await;

    let mut seen = HashSet::new();
    providers.retain(|p| seen.insert(p.name.clone()));

    origin_ips.sort();
    origin_ips.dedup();

    CdnDiscoveryResult {
        target: target.to_string(),
        cdn_providers: providers,
        origin_ips,
        error: None,
    }
}
