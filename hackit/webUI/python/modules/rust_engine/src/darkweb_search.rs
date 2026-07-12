use crate::common::{ScanConfig, build_client, DarkwebSearchResult, DarkwebSourceInfo};
use std::time::Duration;
use tokio::task;

const CLEARNET_DARKWEB_SOURCES: &[(&str, &str)] = &[
    ("Ahmia", "https://ahmia.fi/search/?q={}"),
    ("Ahmia API", "https://ahmia.fi/api/v1/search/?q={}"),
    ("ONIONLAND API", "https://onionland.io/api/v1/search?q={}"),
    ("DarkSearch", "https://darksearch.io/api/search?query={}"),
    ("Ahmia Stats", "https://ahmia.fi/api/v1/stats/?q={}"),
    ("Torch Clearnet", "https://torsearch.net/search?query={}"),
    ("Darknet Live", "https://darknetlive.com/search?q={}"),
    ("Dark Web Links", "https://darkweblinks.com/search?q={}"),
    ("Deep Web Links", "https://deepweblinks.com/search?q={}"),
    ("Hidden Wiki", "https://thehiddenwiki.com/search?q={}"),
    ("OnionLand Search", "https://onionland.io/search?q={}"),
    ("Breach Directory", "https://breachdirectory.org/search?q={}"),
    ("IntelligenceX", "https://intelx.io/?s={}"),
    ("Pulsedive", "https://pulsedive.com/search?q={}"),
    ("Shodan InternetDB", "https://internetdb.shodan.io/{}"),
];

const DARK_WEB_KEYWORDS: &[&str] = &[
    "leak", "breach", "hack", "stolen", "exposed", "dump", "database",
    "credentials", "password", "credit card", "ssn", "passport",
    "ransomware", "malware", "c2", "command and control",
    "exploit", "zero-day", "0day", "vulnerability",
    "phishing", "scam", "fraud", "counterfeit",
    "drug", "narcotic", "cocaine", "heroin", "meth",
    "weapon", "firearm", "ammunition", "explosive",
    "forged", "fake", "counterfeit", "illegal",
    "tor", "onion", "i2p", "darknet", "deepweb",
    "marketplace", "forum", "board", "community",
];

pub async fn scan(target: &str, _config: &ScanConfig) -> DarkwebSearchResult {
    let client = build_client(15).unwrap_or_default();
    let query = target.trim().to_string();
    let timeout = Duration::from_secs(15);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(20));
    let mut handles = Vec::new();

    for &(name, url_tpl) in CLEARNET_DARKWEB_SOURCES {
        let url = url_tpl.replace("{}", &query);
        let client = client.clone();
        let sem = sem.clone();
        let query = query.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let mentions = text.to_lowercase().matches(&query.to_lowercase()).count();
            if status == 200 && mentions > 0 {
                Some(DarkwebSourceInfo {
                    source: name.to_string(),
                    url,
                    status,
                    mentions,
                    snippet: text.chars().take(200).collect(),
                })
            } else {
                None
            }
        }));
    }

    let mut sources_found = Vec::new();
    let mut total_mentions = 0;
    let mut all_snippets = Vec::new();

    for h in handles {
        if let Ok(Some(r)) = h.await {
            total_mentions += r.mentions;
            all_snippets.push(r.snippet);
            sources_found.push(DarkwebSourceInfo {
                source: r.source,
                url: r.url,
                status: r.status,
                mentions: r.mentions,
                snippet: String::new(),
            });
        }
    }

    let keywords_detected: Vec<String> = DARK_WEB_KEYWORDS.iter()
        .filter(|kw| {
            let lower = target.to_lowercase();
            lower.contains(*kw)
        })
        .map(|s| s.to_string())
        .collect();

    let risk = assess_risk(total_mentions, &keywords_detected);

    DarkwebSearchResult {
        query,
        sources_checked: CLEARNET_DARKWEB_SOURCES.len(),
        sources_found: sources_found.len(),
        total_mentions,
        sources: sources_found,
        keywords_detected,
        risk_assessment: risk,
    }
}

fn assess_risk(mentions: usize, keywords: &[String]) -> String {
    if mentions > 100 || keywords.len() > 5 {
        "CRITICAL".to_string()
    } else if mentions > 50 || keywords.len() > 3 {
        "HIGH".to_string()
    } else if mentions > 10 || keywords.len() > 1 {
        "MEDIUM".to_string()
    } else if mentions > 0 {
        "LOW".to_string()
    } else {
        "NONE".to_string()
    }
}
