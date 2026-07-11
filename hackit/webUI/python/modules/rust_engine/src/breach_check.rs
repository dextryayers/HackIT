use crate::common::*;
use crate::{progress, progress_done};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::Duration;

const HIBP_POST_DELAY_MS: u64 = 500;
const DEFAULT_TIMEOUT_SECS: u64 = 15;

struct LocalBreach {
    name: &'static str,
    data_types: &'static str,
    keywords: &'static [&'static str],
}

const LOCAL_BREACHES: &[LocalBreach] = &[
    LocalBreach { name: "Collection #1", data_types: "Email, Password", keywords: &["collection#1", "collection1", "collection_1"] },
    LocalBreach { name: "LinkedIn (2012)", data_types: "Email, Password", keywords: &["linkedin"] },
    LocalBreach { name: "Adobe (2013)", data_types: "Email, Password", keywords: &["adobe"] },
    LocalBreach { name: "Dropbox (2012)", data_types: "Email, Password", keywords: &["dropbox"] },
    LocalBreach { name: "Ashley Madison (2015)", data_types: "Email, Name", keywords: &["ashley", "ashleymadison"] },
    LocalBreach { name: "MySpace (2008)", data_types: "Email, Password", keywords: &["myspace", "my_space"] },
    LocalBreach { name: "Twitter/X (2022)", data_types: "Email, Name", keywords: &["twitter"] },
    LocalBreach { name: "Facebook (2019)", data_types: "Phone, Name, ID", keywords: &["facebook", "fb"] },
    LocalBreach { name: "Data Enrichment", data_types: "Email, Personal", keywords: &["data_enrichment", "enrichment"] },
    LocalBreach { name: "Exploit.in", data_types: "Email, Password", keywords: &["exploit", "exploit.in"] },
    LocalBreach { name: "Anti Public", data_types: "Email, Password", keywords: &["antipublic", "anti_public"] },
    LocalBreach { name: "Verifications.io", data_types: "Email, Personal", keywords: &["verification", "verifications"] },
    LocalBreach { name: "Collection #2-5", data_types: "Email, Password", keywords: &["collection2", "collection_2"] },
    LocalBreach { name: "Onliner Spambot", data_types: "Email", keywords: &["onliner", "spambot"] },
    LocalBreach { name: "Sony (2011)", data_types: "Email, Password", keywords: &["sony", "playstation"] },
    LocalBreach { name: "Equifax (2017)", data_types: "SSN, Personal", keywords: &["equifax"] },
    LocalBreach { name: "Marriott/Starwood (2018)", data_types: "Passport, Personal", keywords: &["marriott", "starwood"] },
    LocalBreach { name: "Have I Been Pwned", data_types: "Email", keywords: &["haveibeenpwned", "hibp", "email"] },
];

fn sha1_hex(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.trim().to_lowercase().as_bytes());
    hex::encode(hasher.finalize()).to_uppercase()
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.trim().to_lowercase().as_bytes());
    hex::encode(hasher.finalize())
}

fn exact_match(target_lower: &str, keyword: &str) -> bool {
    target_lower
        .split(|c: char| !c.is_alphanumeric() && c != '#')
        .any(|word| word == keyword)
}

fn check_local(target: &str) -> Vec<BreachEntry> {
    let lower = target.to_lowercase();
    LOCAL_BREACHES
        .iter()
        .map(|breach| {
            let matches = breach.keywords.iter().any(|k| exact_match(&lower, k));
            BreachEntry {
                source: breach.name.to_string(),
                data_type: breach.data_types.to_string(),
                exposed: matches,
                description: if matches {
                    Some(format!("Target matches known breach: {}", breach.name))
                } else {
                    None
                },
            }
        })
        .collect()
}

async fn check_hibp(
    client: &reqwest::Client,
    target: &str,
    hibp_limiter: &RateLimiter,
    timeout: Duration,
) -> Vec<BreachEntry> {
    let hash = sha1_hex(target);
    let prefix = &hash[..5];

    hibp_limiter.acquire().await;

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let resp = match client
        .get(&url)
        .header("Add-Padding", "true")
        .timeout(timeout)
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

    tokio::time::sleep(Duration::from_millis(HIBP_POST_DELAY_MS)).await;

    let suffix = &hash[5..];
    for line in body.lines() {
        if let Some(pos) = line.find(':') {
            if line[..pos].eq_ignore_ascii_case(suffix) {
                return vec![BreachEntry {
                    source: "Have I Been Pwned (k-Anonymity)".to_string(),
                    data_type: "Password Hash".to_string(),
                    exposed: true,
                    description: Some(
                        "SHA1 hash prefix matched in HIBP password breach database".to_string(),
                    ),
                }];
            }
        }
    }

    vec![]
}

async fn check_dehashed(
    client: &reqwest::Client,
    target: &str,
    api_key: &str,
    timeout: Duration,
) -> Vec<BreachEntry> {
    let resp = match client
        .get("https://dehashed.com/api/v1/search")
        .query(&[("query", target)])
        .basic_auth(api_key, Some(""))
        .header("Accept", "application/json")
        .timeout(timeout)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    if !resp.status().is_success() {
        return vec![];
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let total = json.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
    if total > 0 {
        vec![BreachEntry {
            source: "DeHashed".to_string(),
            data_type: "Email, Password".to_string(),
            exposed: true,
            description: Some(format!("Target found in DeHashed ({} result(s))", total)),
        }]
    } else {
        vec![]
    }
}

async fn check_leakcheck(
    client: &reqwest::Client,
    target: &str,
    api_key: &str,
    timeout: Duration,
) -> Vec<BreachEntry> {
    let resp = match client
        .get("https://leakcheck.net/api/public")
        .query(&[("check", target), ("key", api_key)])
        .timeout(timeout)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };

    if !resp.status().is_success() {
        return vec![];
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let found = json.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
    if found {
        let count = json.get("count").and_then(|v| v.as_u64()).unwrap_or(1);
        vec![BreachEntry {
            source: "LeakCheck".to_string(),
            data_type: "Email, Password".to_string(),
            exposed: true,
            description: Some(format!("Target found in LeakCheck ({} entry/ies)", count)),
        }]
    } else {
        vec![]
    }
}

pub async fn check(target: &str) -> BreachCheckResult {
    progress!("breach_check", "running");

    // 1. Local exact-match breach database
    let mut checks: Vec<BreachEntry> = check_local(target);

    // Build a shared HTTP client
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            progress_done!("breach_check");
            return BreachCheckResult {
                target: target.to_string(),
                checks,
            };
        }
    };

    // 2. HIBP k-anonymity (free, no API key required)
    //    RateLimiter gives 1 token/sec; extra sleep ensures ~1.5s between requests
    let hibp_limiter = RateLimiter::new(1);
    let hibp_results =
        check_hibp(&client, target, &hibp_limiter, Duration::from_secs(DEFAULT_TIMEOUT_SECS)).await;
    checks.extend(hibp_results);

    // 3. DeHashed (optional, via DEHASHED_API_KEY env var)
    if let Ok(key) = std::env::var("DEHASHED_API_KEY") {
        if !key.is_empty() {
            let results =
                check_dehashed(&client, target, &key, Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                    .await;
            checks.extend(results);
        }
    }

    // 4. LeakCheck (optional, via LEAKCHECK_API_KEY env var)
    if let Ok(key) = std::env::var("LEAKCHECK_API_KEY") {
        if !key.is_empty() {
            let results =
                check_leakcheck(&client, target, &key, Duration::from_secs(DEFAULT_TIMEOUT_SECS))
                    .await;
            checks.extend(results);
        }
    }

    progress_done!("breach_check");
    BreachCheckResult {
        target: target.to_string(),
        checks,
    }
}
