use crate::common::*;
use sha1::{Sha1, Digest};
use std::time::Duration;

const HIBP_API_BASE: &str = "https://haveibeenpwned.com/api/v3";
const PWNED_PASSWORDS_BASE: &str = "https://api.pwnedpasswords.com/range";
const USER_AGENT: &str = "HackIT-Engine/1.0";
const RATE_LIMIT_MS: u64 = 1500;
const MAX_BREACHES: usize = 50;

const COMMON_PASSWORDS: &[&str] = &[
    "password123", "123456", "password", "qwerty", "admin",
];

fn sha1_hex(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize()).to_uppercase()
}

struct HibpResponse {
    breaches: Vec<EmailBreachEntry>,
    error: Option<String>,
}

async fn check_hibp_breaches(
    client: &reqwest::Client,
    email: &str,
    api_key: &str,
    limiter: &RateLimiter,
) -> HibpResponse {
    limiter.acquire().await;

    let url = format!(
        "{}/breachedaccount/{}?truncateResponse=false",
        HIBP_API_BASE, email
    );

    let response = match client
        .get(&url)
        .header("User-Agent", USER_AGENT)
        .header("hibp-api-key", api_key)
        .timeout(Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tokio::time::sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
            return HibpResponse {
                breaches: Vec::new(),
                error: Some(format!("HIBP request failed: {}", e)),
            };
        }
    };

    tokio::time::sleep(Duration::from_millis(RATE_LIMIT_MS)).await;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return HibpResponse {
            breaches: Vec::new(),
            error: None,
        };
    }

    if !response.status().is_success() {
        return HibpResponse {
            breaches: Vec::new(),
            error: Some(format!(
                "HIBP returned status {}",
                response.status().as_u16()
            )),
        };
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            return HibpResponse {
                breaches: Vec::new(),
                error: Some(format!("Failed to read HIBP response: {}", e)),
            };
        }
    };

    let json: Vec<serde_json::Value> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return HibpResponse {
                breaches: Vec::new(),
                error: Some(format!("Failed to parse HIBP response: {}", e)),
            };
        }
    };

    let breaches: Vec<EmailBreachEntry> = json
        .into_iter()
        .take(MAX_BREACHES)
        .map(|entry| EmailBreachEntry {
            name: entry
                .get("Name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            date: entry
                .get("BreachDate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            data_types: entry
                .get("DataClasses")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();

    HibpResponse { breaches, error: None }
}

async fn check_password_hibp(
    client: &reqwest::Client,
    password: &str,
    limiter: &RateLimiter,
) -> bool {
    limiter.acquire().await;

    let hash = sha1_hex(password);
    let prefix = &hash[..5];
    let suffix = &hash[5..];
    let url = format!("{}/{}", PWNED_PASSWORDS_BASE, prefix);

    let response = match client
        .get(&url)
        .header("User-Agent", USER_AGENT)
        .header("Add-Padding", "true")
        .timeout(Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            tokio::time::sleep(Duration::from_millis(RATE_LIMIT_MS)).await;
            return false;
        }
    };

    tokio::time::sleep(Duration::from_millis(RATE_LIMIT_MS)).await;

    let body = match response.text().await {
        Ok(b) => b,
        Err(_) => return false,
    };

    for line in body.lines() {
        if let Some(pos) = line.find(':') {
            if line[..pos].eq_ignore_ascii_case(suffix) {
                return true;
            }
        }
    }

    false
}

async fn check_common_passwords(client: &reqwest::Client, limiter: &RateLimiter) -> bool {
    for password in COMMON_PASSWORDS {
        if check_password_hibp(client, password, limiter).await {
            return true;
        }
    }
    false
}

pub async fn check(email: &str) -> EmailBreachCheckResult {
    let email = email.trim().to_lowercase();

    if !email.contains('@') {
        return EmailBreachCheckResult {
            email,
            is_breached: false,
            breach_count: 0,
            breaches: Vec::new(),
            pwned_password: false,
            error: Some("Invalid email format".to_string()),
        };
    }

    let client = match build_client(30) {
        Some(c) => c,
        None => {
            return EmailBreachCheckResult {
                email,
                is_breached: false,
                breach_count: 0,
                breaches: Vec::new(),
                pwned_password: false,
                error: Some("Failed to create HTTP client".to_string()),
            };
        }
    };

    let limiter = RateLimiter::new(1);

    let api_key = std::env::var("HIBP_API_KEY").ok();
    let (breaches, error) = if let Some(ref key) = api_key {
        let result = check_hibp_breaches(&client, &email, key, &limiter).await;
        (result.breaches, result.error)
    } else {
        (Vec::new(), Some("HIBP_API_KEY not set".to_string()))
    };

    let pwned_password = check_common_passwords(&client, &limiter).await;

    let is_breached = !breaches.is_empty();
    let breach_count = breaches.len() as u32;

    EmailBreachCheckResult {
        email,
        is_breached,
        breach_count,
        breaches,
        pwned_password,
        error,
    }
}
