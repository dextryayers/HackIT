use regex::Regex;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use lazy_static::lazy_static;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ContactInfo {
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub social_links: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct JSReconInfo {
    pub endpoints: Vec<String>,
    pub api_calls: Vec<String>,
    pub hidden_routes: Vec<String>,
    pub api_keys: Vec<String>,
}

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    static ref PHONE_REGEX: Regex = Regex::new(r"(\+?\d{1,4}[\s.-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4,6}").unwrap();
    static ref SOCIAL_REGEX: Regex = Regex::new(r"(facebook\.com|twitter\.com|linkedin\.com|instagram\.com|github\.com|youtube\.com)/[a-zA-Z0-9._-]+").unwrap();
    static ref ENDPOINT_REGEX: Regex = Regex::new(r#"(?i)["'](/(?:api|v1|v2|v3|auth|login|graphql|admin|debug|internal|status|uploads|storage)[a-z0-9/._-]*)["']"#).unwrap();
    static ref API_CALL_REGEX: Regex = Regex::new(r#"(?i)(?:fetch|axios|ajax|get|post)\s*\(\s*["']([^"']+)["']"#).unwrap();
    
    // API Key Patterns
    static ref FIREBASE_REGEX: Regex = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();
    static ref AWS_KEY_REGEX: Regex = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    static ref GOOGLE_MAPS_REGEX: Regex = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();
    static ref SLACK_TOKEN_REGEX: Regex = Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap();
}

pub fn extract_js_recon(body: &str) -> JSReconInfo {
    let mut endpoints = HashSet::new();
    let mut api_calls = HashSet::new();
    let mut hidden_routes = HashSet::new();
    let mut api_keys = HashSet::new();

    // Extract Endpoints
    for cap in ENDPOINT_REGEX.captures_iter(body) {
        endpoints.insert(cap[1].to_string());
    }

    // Extract API Calls
    for cap in API_CALL_REGEX.captures_iter(body) {
        api_calls.insert(cap[1].to_string());
    }

    // Extract API Keys
    for cap in FIREBASE_REGEX.captures_iter(body) { api_keys.insert(format!("Firebase/Google: {}", &cap[0])); }
    for cap in AWS_KEY_REGEX.captures_iter(body) { api_keys.insert(format!("AWS Key: {}", &cap[0])); }
    for cap in SLACK_TOKEN_REGEX.captures_iter(body) { api_keys.insert(format!("Slack Token: {}", &cap[0])); }

    // Heuristic for hidden routes (common patterns in modern frameworks)
    let re_routes = Regex::new(r#"(?i)path:\s*["'](/[a-z0-9/._-]*)["']"#).unwrap();
    for cap in re_routes.captures_iter(body) {
        hidden_routes.insert(cap[1].to_string());
    }

    JSReconInfo {
        endpoints: endpoints.into_iter().collect(),
        api_calls: api_calls.into_iter().collect(),
        hidden_routes: hidden_routes.into_iter().collect(),
        api_keys: api_keys.into_iter().collect(),
    }
}

pub fn extract_contacts(body: &str) -> ContactInfo {
    let mut emails = HashSet::new();
    let mut phones = HashSet::new();
    let mut social_links = HashSet::new();

    // Extract Emails
    for cap in EMAIL_REGEX.captures_iter(body) {
        emails.insert(cap[0].to_string());
    }

    // Extract Phones (with basic filtering to avoid noise)
    for cap in PHONE_REGEX.captures_iter(body) {
        let phone = cap[0].trim().to_string();
        if phone.len() >= 10 { // Simple heuristic to filter out small numbers
            phones.insert(phone);
        }
    }

    // Extract Social Links
    for cap in SOCIAL_REGEX.captures_iter(body) {
        social_links.insert(format!("https://{}", &cap[0]));
    }

    ContactInfo {
        emails: emails.into_iter().collect(),
        phones: phones.into_iter().collect(),
        social_links: social_links.into_iter().collect(),
    }
}
