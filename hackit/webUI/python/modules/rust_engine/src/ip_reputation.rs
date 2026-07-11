use crate::common::*;
use crate::{progress, progress_done};
use std::time::Duration;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

const DEFAULT_TIMEOUT_SECS: u64 = 15;

const DNSBLS: &[&str] = &[
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl.dronebl.org",
    "spam.dnsbl.sorbs.net",
    "all.s5h.net",
];

fn reverse_ip(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some(format!("{}.{}.{}.{}", parts[3], parts[2], parts[1], parts[0]))
}

async fn check_abuseipdb(client: &reqwest::Client, ip: &str, limiter: &RateLimiter) -> Option<IpReputationSource> {
    let key = std::env::var("ABUSEIPDB_API_KEY").ok().filter(|k| !k.is_empty())?;
    limiter.acquire().await;

    let resp = client
        .get(format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}", ip))
        .header("Key", &key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;

    let body = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let data = json.get("data")?;
    let is_malicious = data.get("abuseConfidenceScore").and_then(|v| v.as_u64()).unwrap_or(0) > 0;
    let confidence = data.get("abuseConfidenceScore").and_then(|v| v.as_u64()).unwrap_or(0);
    let reports = data.get("totalReports").and_then(|v| v.as_u64()).unwrap_or(0);

    Some(IpReputationSource {
        name: "AbuseIPDB".to_string(),
        is_malicious,
        confidence: format!("{}%", confidence),
        reports: reports as u32,
    })
}

async fn check_virustotal(client: &reqwest::Client, ip: &str, limiter: &RateLimiter) -> Option<IpReputationSource> {
    let key = std::env::var("VIRUSTOTAL_API_KEY").ok().filter(|k| !k.is_empty())?;
    limiter.acquire().await;

    let resp = client
        .get(format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip))
        .header("x-apikey", &key)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;

    let body = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let attributes = json.get("data")?.get("attributes")?;
    let stats = attributes.get("last_analysis_stats")?;
    let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
    let total = stats.get("undetected").and_then(|v| v.as_u64()).unwrap_or(0)
        + stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0)
        + malicious
        + stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0)
        + stats.get("timeout").and_then(|v| v.as_u64()).unwrap_or(0);

    Some(IpReputationSource {
        name: "VirusTotal".to_string(),
        is_malicious: malicious > 0,
        confidence: format!("{}/{} malicious", malicious, total),
        reports: total as u32,
    })
}

async fn check_alienvault(client: &reqwest::Client, ip: &str, limiter: &RateLimiter) -> Option<IpReputationSource> {
    limiter.acquire().await;

    let resp = client
        .get(format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/reputation", ip))
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;

    let body = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let reputation = json.get("reputation")?;

    let is_malicious = reputation.as_i64().unwrap_or(0) > 0;
    let count = json.get("pulse_info")
        .and_then(|p| p.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Some(IpReputationSource {
        name: "AlienVault OTX".to_string(),
        is_malicious,
        confidence: if is_malicious { format!("reputation: {}", reputation) } else { "clean".to_string() },
        reports: count as u32,
    })
}

async fn check_xforce(client: &reqwest::Client, ip: &str, limiter: &RateLimiter) -> Option<IpReputationSource> {
    let key = std::env::var("XFORCE_API_KEY").ok().filter(|k| !k.is_empty())?;
    let password = std::env::var("XFORCE_API_PASSWORD").ok().filter(|k| !k.is_empty())?;
    limiter.acquire().await;

    let resp = client
        .get(format!("https://api.xforce.ibmcloud.com/api/ipr/{}", ip))
        .basic_auth(&key, Some(&password))
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .send()
        .await
        .ok()?;

    let body = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let score_val = json.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
    let _cats = json.get("categoryDescriptions")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();

    Some(IpReputationSource {
        name: "IBM X-Force".to_string(),
        is_malicious: score_val > 0,
        confidence: format!("score: {}", score_val),
        reports: score_val as u32,
    })
}

async fn check_dnsbl(resolver: &TokioAsyncResolver, ip: &str) -> Vec<String> {
    let rev_ip = match reverse_ip(ip) {
        Some(r) => r,
        None => return vec![],
    };

    let mut listed: Vec<String> = Vec::new();
    for dnsbl in DNSBLS {
        let query = format!("{}.{}", rev_ip, dnsbl);
        if let Ok(response) = resolver.ipv4_lookup(&query).await {
            if response.iter().next().is_some() {
                listed.push(dnsbl.to_string());
            }
        }
    }
    listed
}

fn compute_threat_score(sources: &[IpReputationSource], total_reports: u32, dnsbl_count: usize) -> u32 {
    let malicious_count = sources.iter().filter(|s| s.is_malicious).count() as u32;
    let source_count = sources.len() as u32;

    if source_count == 0 && dnsbl_count == 0 {
        return 0;
    }

    let mut score: u32 = 0;

    if source_count > 0 {
        let ratio = malicious_count * 100 / source_count;
        score += ratio * 6 / 10;
    }

    let report_contrib = if total_reports > 1000 {
        20
    } else if total_reports > 100 {
        15
    } else if total_reports > 10 {
        10
    } else if total_reports > 0 {
        5
    } else {
        0
    };
    score += report_contrib;

    let dnsbl_contrib = (dnsbl_count as u32 * 20).min(20);
    score += dnsbl_contrib;

    score.min(100)
}

fn extract_categories(sources: &[IpReputationSource]) -> Vec<String> {
    let mut cats: Vec<String> = Vec::new();
    for s in sources {
        if s.is_malicious {
            cats.push(format!("flagged_by_{}", s.name.to_lowercase().replace(' ', "_")));
        }
    }
    cats
}

pub async fn check(target: &str) -> IpReputationResult {
    progress!("ip_reputation", "running");

    let mut sources: Vec<IpReputationSource> = Vec::new();
    let error: Option<String> = None;

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            progress_done!("ip_reputation");
            return IpReputationResult {
                ip: target.to_string(),
                is_malicious: false,
                threat_score: 0,
                total_reports: 0,
                sources: vec![],
                categories: vec![],
                last_report: None,
                error: Some(format!("Failed to create HTTP client: {}", e)),
            };
        }
    };

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let abuse_limiter = RateLimiter::new(2);
    let vt_limiter = RateLimiter::new(4);
    let otx_limiter = RateLimiter::new(4);
    let xforce_limiter = RateLimiter::new(4);

    let (abuse, vt, otx, xforce, dnsbl) = tokio::join!(
        check_abuseipdb(&client, target, &abuse_limiter),
        check_virustotal(&client, target, &vt_limiter),
        check_alienvault(&client, target, &otx_limiter),
        check_xforce(&client, target, &xforce_limiter),
        check_dnsbl(&resolver, target),
    );

    if let Some(s) = abuse { sources.push(s); }
    if let Some(s) = vt { sources.push(s); }
    if let Some(s) = otx { sources.push(s); }
    if let Some(s) = xforce { sources.push(s); }

    let dnsbl_sources: Vec<IpReputationSource> = dnsbl.iter().map(|d| IpReputationSource {
        name: format!("DNSBL:{}", d),
        is_malicious: true,
        confidence: "blacklisted".to_string(),
        reports: 1,
    }).collect();

    let total_reports: u32 = sources.iter().map(|s| s.reports).sum();
    let any_malicious = sources.iter().any(|s| s.is_malicious) || !dnsbl_sources.is_empty();
    let threat_score = compute_threat_score(&sources, total_reports, dnsbl.len());
    let categories = extract_categories(&sources);

    let mut all_sources = sources;
    all_sources.extend(dnsbl_sources);

    progress_done!("ip_reputation");
    IpReputationResult {
        ip: target.to_string(),
        is_malicious: any_malicious,
        threat_score,
        total_reports,
        sources: all_sources,
        categories,
        last_report: None,
        error,
    }
}
