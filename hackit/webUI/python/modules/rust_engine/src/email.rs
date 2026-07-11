use crate::common::{EmailResult, build_client};
use regex::Regex;
use std::collections::HashSet;

const EMAIL_PREFIXES: &[&str] = &[
    "admin", "info", "support", "sales", "contact", "webmaster", "hostmaster",
    "postmaster", "abuse", "noreply", "help", "billing", "marketing", "press",
    "jobs", "hr", "pr", "feedback", "hello", "team", "careers", "newsletter",
    "register", "subscribe", "unsubscribe", "blog", "community", "developer",
    "dev", "engineering", "tech", "security", "dmca", "legal", "copyright",
    "partner", "service", "shop", "store", "investor", "media", "social",
    "partners", "recruiting", "recruitment", "training", "education", "events",
    "speakers", "editor", "editors", "founder", "ceo", "cto", "cfo", "coo",
    "cmo", "cio", "cso", "cpo", "chairman", "director", "manager", "management",
    "office", "offices", "operations", "logistics", "shipping", "returns",
    "orders", "order", "customer", "customers", "client", "clients", "user",
    "users", "account", "accounts", "login", "signup", "signup", "enquiries",
    "enquiry", "inquiries", "inquiry", "quote", "quotes", "request", "requests",
    "complaints", "complaint", "issues", "issue", "problem", "problems",
    "suggestions", "suggestion", "business", "businessdev", "bd", "corporate",
    "company", "administrator", "sysadmin", "system", "systems", "it",
    "itsupport", "helpdesk", "noc", "network", "server", "servers", "db",
    "database", "backup", "backups", "monitoring", "monitor", "alerts", "alert",
    "status", "uptime", "emergency", "911", "report", "reports", "reporting",
    "analytics", "analysis", "data", "dataprivacy", "privacy", "gdpr",
    "compliance", "audit", "audits", "quality", "qa", "testing", "test",
    "staging", "devops", "release", "deploy", "deployment", "build", "ci", "cd",
    "infra", "infrastructure", "customersupport", "clientsupport", "techsupport",
    "forum", "forums", "moderator", "moderators", "news", "announce",
    "announcements", "update", "updates", "changelog", "docs", "documentation",
    "wiki", "knowledge", "knowledgebase", "faq", "api", "apis", "integration",
    "integrations", "plugin", "plugins", "extension", "extensions", "app",
    "apps", "mobile", "ios", "android", "iphone", "ipad", "mac", "windows",
    "linux", "desktop", "webapp", "no-reply", "donotreply", "do-not-reply",
    "mailer-daemon", "daemon", "root", "mailer", "mta", "smtp", "imap", "pop3",
    "spam", "ham", "whitelist", "blacklist", "optout", "opt-out", "optin",
    "opt-in", "confirm", "confirmation", "verify", "verification", "activation",
    "welcome", "invite", "invitation", "referral", "refer", "friend", "friends",
    "family",
];

const DISPOSABLE_DOMAINS: &[&str] = &[
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com", "trashmail.com",
    "mailnator.com", "temp-mail.org", "fakeinbox.com", "mailexpire.com",
    "dispostable.com", "spamgourmet.com", "mohmal.com", "emailondeck.com",
];

fn is_rfc5322_valid(email: &str) -> bool {
    let parts: Vec<&str> = email.rsplitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[1];
    let domain_part = parts[0];
    if local.is_empty() || domain_part.is_empty() {
        return false;
    }
    if local.len() > 64 || domain_part.len() > 255 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if !local.chars().all(|c| c.is_alphanumeric() || "._%+-".contains(c)) {
        return false;
    }
    if domain_part.starts_with('.') || domain_part.ends_with('.') || domain_part.contains("..") {
        return false;
    }
    let labels: Vec<&str> = domain_part.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|l| !l.is_empty() && l.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

fn categorize_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("");
    let domain_part = email.split('@').nth(1).unwrap_or("");

    if DISPOSABLE_DOMAINS.iter().any(|d| domain_part.contains(d)) {
        return "disposable".to_string();
    }

    let role_prefixes = [
        "admin", "info", "support", "sales", "contact", "webmaster", "hostmaster",
        "postmaster", "abuse", "noreply", "help", "billing", "marketing", "press",
        "jobs", "hr", "pr", "feedback", "hello", "team", "careers", "newsletter",
        "register", "subscribe", "unsubscribe", "security", "dmca", "legal", "partner",
        "service", "shop", "store", "investor", "noc", "it", "sysadmin", "root",
        "daemon", "mailer-daemon", "no-reply", "donotreply", "office", "manager",
        "ceo", "cto", "cfo", "coo", "cio", "director", "enquiries", "complaints",
        "orders", "account", "billing", "customers", "community", "qa", "testing",
        "press", "media", "jobs", "hr", "recruiting", "legal", "privacy",
    ];

    if role_prefixes.iter().any(|p| local == *p) {
        return "role-based".to_string();
    }

    if local.contains('.') && local.chars().all(|c| c.is_alphabetic() || c == '.' || c == '-') {
        return "personal".to_string();
    }

    "unknown".to_string()
}

fn generate_prefix_emails(domain: &str) -> Vec<String> {
    let mut emails: Vec<String> = EMAIL_PREFIXES.iter()
        .map(|p| format!("{}@{}", p, domain))
        .filter(|e| is_rfc5322_valid(e))
        .collect();
    emails.sort();
    emails.dedup();
    emails
}

async fn fetch_page(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = client
        .get(url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .ok()?;
    resp.text().await.ok()
}

fn extract_emails(text: &str, domain: &str, re: &Regex) -> Vec<String> {
    re.find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|e| e.ends_with(domain) && is_rfc5322_valid(e))
        .collect()
}

async fn scrape_page_emails(client: &reqwest::Client, domain: &str) -> Vec<String> {
    let re = match Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        Ok(r) => r,
        _ => return Vec::new(),
    };

    let urls = [
        format!("https://{}", domain),
        format!("https://www.{}", domain),
        format!("https://{}/contact", domain),
        format!("https://{}/about", domain),
        format!("https://{}/team", domain),
    ];
    let mut results = Vec::new();
    for url in &urls {
        if let Some(body) = fetch_page(client, url).await {
            results.extend(extract_emails(&body, domain, &re));
        }
    }
    results
}

async fn google_discover(client: &reqwest::Client, domain: &str) -> Vec<String> {
    let re = match Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        Ok(r) => r,
        _ => return Vec::new(),
    };
    let encoded: String = format!("site:{} email OR @{}", domain, domain)
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "+".to_string(),
            other => format!("%{:02X}", other as u8),
        })
        .collect();
    let url = format!("https://www.google.com/search?q={}", encoded);
    match fetch_page(client, &url).await {
        Some(body) => extract_emails(&body, domain, &re),
        None => Vec::new(),
    }
}

async fn hunter_discover(client: &reqwest::Client, domain: &str) -> Vec<String> {
    let api_key = match std::env::var("HUNTER_API_KEY") {
        Ok(k) => k,
        _ => return Vec::new(),
    };
    let url = format!(
        "https://api.hunter.io/v2/domain-search?domain={}&api_key={}",
        domain, api_key
    );
    let body = match fetch_page(client, &url).await {
        Some(b) => b,
        None => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        _ => return Vec::new(),
    };
    let mut emails = Vec::new();
    if let Some(data) = json.get("data") {
        if let Some(emails_arr) = data.get("emails").and_then(|e| e.as_array()) {
            for entry in emails_arr {
                if let Some(val) = entry.get("value").and_then(|v| v.as_str()) {
                    if is_rfc5322_valid(val) {
                        emails.push(val.to_string());
                    }
                }
            }
        }
    }
    emails
}

async fn skymem_discover(client: &reqwest::Client, domain: &str) -> Vec<String> {
    let re = match Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        Ok(r) => r,
        _ => return Vec::new(),
    };
    let url = format!("https://www.skymem.info/srch?q={}", domain);
    match fetch_page(client, &url).await {
        Some(body) => extract_emails(&body, domain, &re),
        None => Vec::new(),
    }
}

async fn check_hibp(client: &reqwest::Client, email: &str) -> Option<Vec<String>> {
    let api_key = std::env::var("HIBP_API_KEY").ok()?;
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
        email
    );
    let resp = client
        .get(&url)
        .header("hibp-api-key", &api_key)
        .header("user-agent", "hackit-engine")
        .send()
        .await
        .ok()?;
    if resp.status().as_u16() == 404 {
        return Some(Vec::new());
    }
    if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
        return None;
    }
    let text = resp.text().await.ok()?;
    let breaches: Vec<serde_json::Value> = serde_json::from_str(&text).ok()?;
    let names: Vec<String> = breaches
        .iter()
        .filter_map(|b| b.get("Name").and_then(|n| n.as_str().map(String::from)))
        .collect();
    Some(names)
}

pub async fn discover(domain: &str) -> EmailResult {
    let client = match build_client(15) {
        Some(c) => c,
        None => {
            let patterns = generate_prefix_emails(domain);
            return EmailResult {
                domain: domain.to_string(),
                count: patterns.len(),
                patterns,
            };
        }
    };

    let mut all_emails: HashSet<String> = HashSet::new();

    for email in generate_prefix_emails(domain) {
        all_emails.insert(email);
    }

    for email in scrape_page_emails(&client, domain).await {
        all_emails.insert(email);
    }

    for email in google_discover(&client, domain).await {
        all_emails.insert(email);
    }

    for email in hunter_discover(&client, domain).await {
        all_emails.insert(email);
    }

    for email in skymem_discover(&client, domain).await {
        all_emails.insert(email);
    }

    let mut categorized: Vec<(String, String, Vec<String>)> = Vec::new();
    for email in &all_emails {
        let category = categorize_email(email);
        let breaches = check_hibp(&client, email).await.unwrap_or_default();
        categorized.push((email.clone(), category, breaches));
    }

    let mut patterns: Vec<String> = categorized
        .into_iter()
        .map(|(email, cat, breaches)| {
            if breaches.is_empty() {
                format!("{} [{}]", email, cat)
            } else {
                format!("{} [{}] breaches: {}", email, cat, breaches.join(", "))
            }
        })
        .collect();
    patterns.sort();

    EmailResult {
        domain: domain.to_string(),
        count: all_emails.len(),
        patterns,
    }
}
