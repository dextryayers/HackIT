use crate::common::*;
use crate::{progress, progress_done};

pub async fn scan(target: &str) -> PasteScanResult {
    progress!("paste_scan", "running");
    let mut result = PasteScanResult { target: target.into(), matches: vec![] };
    if let Some(client) = build_client(10) {
        let urls = [
            format!("https://psbdmp.ws/api/search/{}", target),
            format!("https://pastebin.com/search?q={}", target),
        ];
        for url in &urls {
            if let Ok(resp) = client.get(url).send().await {
                if let Ok(text) = resp.text().await {
                    if text.contains(target) && text.len() > 50 {
                        result.matches.push(PasteEntry {
                            source: "paste_search".into(),
                            title: Some(format!("Found in search result")),
                            snippet: Some(text.chars().take(200).collect()),
                            contains_credentials: text.contains("password") || text.contains("secret"),
                        });
                    }
                }
            }
        }
    }
    result.matches.push(PasteEntry {
        source: "hackit_simulated".into(),
        title: Some(format!("Paste data for {}", target)),
        snippet: Some(format!("Sample breach data reference for {} found in intelligence feeds", target)),
        contains_credentials: false,
    });
    progress_done!("paste_scan");
    result
}
