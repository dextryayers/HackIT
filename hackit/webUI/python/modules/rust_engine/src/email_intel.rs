use crate::common::{ScanConfig, build_client};
use crate::common::EmailIntelResult;
use std::time::Duration;
use tokio::task;
use regex::Regex;

const SEARCH_ENGINES: &[(&str, &str)] = &[
    ("Bing", "https://www.bing.com/search?q=%22%40{domain}%22&count=50"),
    ("DuckDuckGo", "https://duckduckgo.com/html/?q=%22%40{domain}%22"),
    ("Yandex", "https://yandex.com/search/?text=%22%40{domain}%22"),
    ("Baidu", "https://www.baidu.com/s?wd=%22%40{domain}%22"),
    ("Yahoo", "https://search.yahoo.com/search?p=%22%40{domain}%22"),
    ("Mojeek", "https://www.mojeek.com/search?q=%22%40{domain}%22"),
    ("Swisscows", "https://swisscows.com/web?query=%22%40{domain}%22"),
    ("Exalead", "https://www.exalead.com/search/web/results/?q=%22%40{domain}%22"),
];

const DIRECT_SOURCES: &[(&str, &str)] = &[
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
    ("HackerTarget", "https://api.hackertarget.com/pagelinks/?q={domain}"),
    ("GitHub Search", "https://api.github.com/search/code?q=%22%40{domain}%22&per_page=50"),
    ("GitHub Gist", "https://api.github.com/search/gists?q=%22%40{domain}%22&per_page=50"),
    ("Pastebin Search", "https://pastebin.com/search?q={domain}"),
    ("Google Groups", "https://groups.google.com/groups/search?q=%22%40{domain}%22&num=50"),
    ("Reddit", "https://www.reddit.com/search.json?q=%22%40{domain}%22&limit=50"),
    ("Wayback", "http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&limit=200"),
];

const ROLE_PREFIXES: &[&str] = &[
    "info", "contact", "support", "sales", "admin", "help", "hello",
    "careers", "jobs", "hr", "billing", "accounts", "finance", "marketing",
    "pr", "press", "media", "partners", "business", "enquiries", "mail",
    "office", "team", "webmaster", "postmaster", "hostmaster", "abuse",
    "noreply", "feedback", "newsletter", "social", "community", "legal",
    "privacy", "security", "engineering", "tech", "it", "devops", "system",
    "network", "recruitment", "compliance", "billing", "accounts",
];

const COMMON_NAMES: &[&str] = &[
    "john", "jane", "mike", "david", "sarah", "alex", "chris", "jordan",
    "pat", "sam", "morgan", "casey", "taylor", "riley", "quinn", "avery",
    "noah", "liam", "emma", "olivia", "william", "james", "robert", "michael",
    "mary", "jennifer", "linda", "elizabeth", "barbara", "susan",
];

pub async fn scan(target: &str, _config: &ScanConfig) -> EmailIntelResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let email_re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    let timeout = Duration::from_secs(12);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(40));
    let mut handles = Vec::new();

    for &(name, url_tpl) in SEARCH_ENGINES {
        let url = url_tpl.replace("{domain}", &domain);
        let client = client.clone();
        let sem = sem.clone();
        let email_re = email_re.clone();
        let domain = domain.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let text = resp.text().await.ok()?;
            let emails: Vec<String> = email_re.find_iter(&text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|e| e.ends_with(&format!(".{}", domain)) || e.ends_with(&format!("@{}", domain)))
                .collect();
            Some((name.to_string(), emails))
        }));
    }

    for &(name, url_tpl) in DIRECT_SOURCES {
        let url = url_tpl.replace("{domain}", &domain);
        let client = client.clone();
        let sem = sem.clone();
        let email_re = email_re.clone();
        let domain = domain.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let text = resp.text().await.ok()?;
            let emails: Vec<String> = email_re.find_iter(&text)
                .map(|m| m.as_str().to_lowercase())
                .filter(|e| e.ends_with(&format!(".{}", domain)) || e.ends_with(&format!("@{}", domain)))
                .collect();
            Some((name.to_string(), emails))
        }));
    }

    let mut all_emails: Vec<String> = Vec::new();
    let mut source_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for h in handles {
        if let Ok(Some((source, emails))) = h.await {
            for e in &emails {
                if !all_emails.contains(e) {
                    all_emails.push(e.clone());
                }
            }
            if !emails.is_empty() {
                *source_counts.entry(source).or_insert(0) += emails.len();
            }
        }
    }

    let role_emails: Vec<String> = ROLE_PREFIXES.iter()
        .map(|p| format!("{}@{}", p, domain))
        .collect();

    let patterns = analyze_patterns(&all_emails);

    EmailIntelResult {
        domain,
        emails_found: all_emails.clone(),
        total_count: all_emails.len(),
        role_based: role_emails,
        sources: source_counts.into_iter().collect(),
        patterns,
    }
}

fn analyze_patterns(emails: &[String]) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut first_last = 0;
    let mut first_li = 0;
    let mut fi_last = 0;
    let mut underscore = 0;
    let mut hyphen = 0;
    let mut numeric = 0;

    let dot_re = Regex::new(r"^[a-z]+\.[a-z]+$").unwrap();
    let short_re = Regex::new(r"^[a-z]+\.[a-z]{1}$").unwrap();
    let fi_re = Regex::new(r"^[a-z]{1}\.[a-z]+$").unwrap();
    let num_re = Regex::new(r"^[a-z]+[0-9]").unwrap();

    for email in emails {
        let local = email.split('@').next().unwrap_or("");
        if dot_re.is_match(local) { first_last += 1; }
        if short_re.is_match(local) { first_li += 1; }
        if fi_re.is_match(local) { fi_last += 1; }
        if local.contains('_') { underscore += 1; }
        if local.contains('-') { hyphen += 1; }
        if num_re.is_match(local) { numeric += 1; }
    }

    if first_last > 0 { patterns.push(format!("first.last pattern: {} emails", first_last)); }
    if first_li > 0 { patterns.push(format!("first.initial pattern: {} emails", first_li)); }
    if fi_last > 0 { patterns.push(format!("initial.last pattern: {} emails", fi_last)); }
    if underscore > 0 { patterns.push(format!("underscore separator: {} emails", underscore)); }
    if hyphen > 0 { patterns.push(format!("hyphen separator: {} emails", hyphen)); }
    if numeric > 0 { patterns.push(format!("numeric suffix: {} emails", numeric)); }
    patterns
}
