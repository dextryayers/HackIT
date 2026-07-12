use crate::common::{ScanConfig, build_client};
use crate::common::HttpArchiveScanResult;
use crate::common::ArchiveSnapshot;
use std::time::Duration;

const CDX_API: &str = "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&fl=timestamp,original,statuscode,length,mimetype&limit=1000&filter=statuscode:200";

const ARCHIVE_KEYS: &[(&str, &str)] = &[
    ("wayback", "archive.org"),
    ("cachedview", "cachedview.com"),
    ("googlecache", "webcache.googleusercontent.com"),
    ("ccindex", "commoncrawl.org"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> HttpArchiveScanResult {
    let client = build_client(30).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let timeout = Duration::from_secs(20);

    let cdx_url = CDX_API.replace("{}", &domain);
    let mut snapshots = Vec::new();
    let mut total_pages = 0;
    let mut years_found = std::collections::HashSet::new();
    let mut statuses = std::collections::HashMap::new();

    match tokio::time::timeout(timeout, client.get(&cdx_url).send()).await {
        Ok(Ok(resp)) => {
            if let Ok(body) = resp.text().await {
                let mut lines: Vec<&str> = body.lines().filter(|l| !l.is_empty() && *l != "[[" && !l.starts_with("[\"timestamp")).collect();
                lines.truncate(500);
                for line in lines {
                    let clean = line.trim_matches(|c| c == '[' || c == ']' || c == ',');
                    let parts: Vec<&str> = clean.split(',').map(|s| s.trim().trim_matches('"')).collect();
                    if parts.len() >= 5 {
                        let timestamp = parts[0].to_string();
                        let original_url = parts[1].to_string();
                        let status_code = parts[2].to_string();
                        let length_str = parts[3].to_string();
                        let mime_type = parts[4].to_string();
                        let length: usize = length_str.parse().unwrap_or(0);
                        let year = if timestamp.len() >= 4 { timestamp[..4].to_string() } else { "?".to_string() };
                        years_found.insert(year.clone());
                        *statuses.entry(status_code.clone()).or_insert(0) += 1;
                        if snapshots.len() < 100 {
                            let wayback_url = format!("https://web.archive.org/web/{}/{}", timestamp, original_url);
                            snapshots.push(ArchiveSnapshot {
                                timestamp,
                                original_url,
                                status_code,
                                length,
                                mime_type,
                                wayback_url,
                            });
                        }
                        total_pages += 1;
                    }
                }
            }
        }
        _ => {}
    }

    let mut years: Vec<String> = years_found.into_iter().collect();
    years.sort();

    HttpArchiveScanResult {
        domain,
        total_snapshots: total_pages,
        years_covered: years.join(", "),
        unique_years: years.len(),
        status_distribution: statuses.into_iter().collect(),
        snapshots: snapshots.into_iter().take(100).collect(),
        archives_checked: ARCHIVE_KEYS.len(),
    }
}
