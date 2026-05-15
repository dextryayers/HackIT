use regex::Regex;
use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("API Key", Regex::new(r#"(?i)(?:api_key|apikey|key|access_token|auth_token|token)\s*[:=]\s*['"]([a-zA-Z0-9\-_=]{16,})['"]"#).unwrap()),
        ("Generic Secret", Regex::new(r#"(?i)(?:secret|password|passwd|pwd|auth|credential|creds)\s*[:=]\s*['"]([^'"]{6,})['"]"#).unwrap()),
        ("Firebase", Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap()),
        ("AWS", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        ("Private Key", Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap()),
        ("Vulnerable Path", Regex::new(r"/(?:admin|debug|config|setup|test|dev|internal|backup)/[a-z0-9_\-/\.]+").unwrap()),
    ];
}

pub struct SecretFinder;

impl SecretFinder {
    pub fn find_secrets(content: &str) -> HashSet<String> {
        let mut discovered = HashSet::new();
        for (name, re) in SECRET_PATTERNS.iter() {
            for cap in re.captures_iter(content) {
                if let Some(m) = cap.get(0) {
                    discovered.insert(format!("[{}] Found: {}", name, m.as_str()));
                }
            }
        }
        discovered
    }

    pub fn extract_potential_params(content: &str) -> HashSet<String> {
        let mut params = HashSet::new();
        // Look for parameters in comments or random strings
        let re = Regex::new(r"([a-zA-Z0-9_-]+)\s*[:=]\s*").unwrap();
        for cap in re.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                params.insert(m.as_str().to_string());
            }
        }
        params
    }
}
