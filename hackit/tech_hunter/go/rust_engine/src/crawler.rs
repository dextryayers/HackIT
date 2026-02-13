use reqwest::Client;
use std::collections::HashSet;
use url::Url;
use crate::info_extractor::{self, ContactInfo};
use crate::fingerprint;
use std::collections::HashMap;

pub async fn crawl_and_extract(
    base_url: &str,
    client: &Client,
    max_depth: usize,
) -> (HashMap<String, String>, ContactInfo) {
    let mut visited = HashSet::new();
    let mut to_visit = vec![base_url.to_string()];
    let mut all_techs = HashMap::new();
    let mut all_contacts = ContactInfo::default();
    
    let base_parsed = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return (all_techs, all_contacts),
    };
    let host = base_parsed.host_str().unwrap_or("");

    // Passive & Interesting Path Probing
    let interesting_paths = vec![
        "robots.txt",
        "sitemap.xml",
        ".env",
        ".git/config",
        "wp-json/",
        "admin/",
        "login/",
        "api/",
        "config.php",
        "phpinfo.php",
    ];

    for path in interesting_paths {
        if let Ok(target) = base_parsed.join(path) {
            to_visit.push(target.to_string());
        }
    }

    for _ in 0..max_depth {
        let mut next_to_visit = Vec::new();
        for url in to_visit {
            if visited.contains(&url) || visited.len() >= 20 { // Increased to 20 pages for deeper scan
                continue;
            }
            visited.insert(url.clone());

            if let Ok(resp) = client.get(&url).send().await {
                let status = resp.status();
                let headers: HashMap<String, String> = resp.headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                
                // Also check technologies from headers on EVERY subpage
                let header_techs = fingerprint::detect_technologies("", &headers);
                for (k, v) in header_techs {
                    all_techs.insert(k, v);
                }

                if let Ok(body) = resp.text().await {
                    // 1. Detect Techs on this page body
                    let techs = fingerprint::detect_technologies(&body, &headers);
                    for (k, v) in techs {
                        all_techs.insert(k, v);
                    }

                    // 2. Extract Contacts on this page
                    let contacts = info_extractor::extract_contacts(&body);
                    all_contacts.emails.extend(contacts.emails);
                    all_contacts.phones.extend(contacts.phones);
                    all_contacts.social_links.extend(contacts.social_links);

                    // 3. Find more links if it's a successful HTML page
                    if status.is_success() && headers.get("content-type").map_or(false, |ct| ct.contains("text/html")) {
                        let links = find_links(&body, &base_parsed);
                        for link in links {
                            if let Ok(parsed_link) = Url::parse(&link) {
                                // Only stay on same host and avoid non-http links
                                if parsed_link.host_str() == Some(host) && parsed_link.scheme().starts_with("http") {
                                    // Avoid common media files to save bandwidth
                                    let path = parsed_link.path().to_lowercase();
                                    if !path.ends_with(".jpg") && !path.ends_with(".png") && 
                                       !path.ends_with(".gif") && !path.ends_with(".pdf") &&
                                       !path.ends_with(".css") && !path.ends_with(".zip") {
                                        next_to_visit.push(link);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        to_visit = next_to_visit;
        if to_visit.is_empty() { break; }
    }

    // Deduplicate contacts
    all_contacts.emails.sort();
    all_contacts.emails.dedup();
    all_contacts.phones.sort();
    all_contacts.phones.dedup();
    all_contacts.social_links.sort();
    all_contacts.social_links.dedup();

    (all_techs, all_contacts)
}

fn find_links(body: &str, base_url: &Url) -> Vec<String> {
    let mut links = Vec::new();
    let re = regex::Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
    for cap in re.captures_iter(body) {
        let link = &cap[1];
        if let Ok(abs_url) = base_url.join(link) {
            links.push(abs_url.to_string());
        }
    }
    links
}
