use crate::common::{CrtshResult, CrtshEntry};

pub async fn search(domain: &str) -> CrtshResult {
    let mut certificates = Vec::new();
    if let Ok(resp) = reqwest::get(&format!("https://crt.sh/?q=%25.{}&output=json&limit=100", domain)).await {
        if let Ok(text) = resp.text().await {
            if let Ok(items) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                for item in &items {
                    let id = item.get("id").and_then(|v| v.as_i64());
                    let issuer = item.get("issuer_name").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let issued = item.get("not_before").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let expired = item.get("not_after").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let mut sans = Vec::new();
                    if let Some(name) = item.get("name_value").and_then(|v| v.as_str()) {
                        for n in name.split('\n') { sans.push(n.trim().to_string()); }
                    }
                    certificates.push(CrtshEntry { id, issuer, issued, expired, sans });
                }
            }
        }
    }
    let total = certificates.len();
    CrtshResult { domain: domain.to_string(), certificates, total }
}
