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

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    static ref PHONE_REGEX: Regex = Regex::new(r"(\+?\d{1,4}[\s.-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4,6}").unwrap();
    static ref SOCIAL_REGEX: Regex = Regex::new(r"(facebook\.com|twitter\.com|linkedin\.com|instagram\.com|github\.com|youtube\.com)/[a-zA-Z0-9._-]+").unwrap();
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
