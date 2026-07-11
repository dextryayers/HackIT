use crate::common::*;
use crate::{progress, progress_done};

pub async fn lookup(domain: &str) -> WhoisResult {
    progress!("whois", "running");
    let mut result = WhoisResult { domain: domain.to_string(), ..Default::default() };
    if let Some(client) = build_client(10) {
        let url = format!("https://rdap.org/domain/{}", domain);
        match client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(events) = data["events"].as_array() {
                            for ev in events {
                                let action = ev["eventAction"].as_str().unwrap_or("");
                                let date = ev["eventDate"].as_str().unwrap_or("");
                                match action {
                                    "registration" => result.creation_date = Some(date.into()),
                                    "expiration" => result.expiration_date = Some(date.into()),
                                    "last changed" => result.updated_date = Some(date.into()),
                                    _ => {}
                                }
                            }
                        }
                        if let Some(entities) = data["entities"].as_array() {
                            for ent in entities {
                                let roles = ent["roles"].as_array().map(|r| r.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()).unwrap_or_default();
                                if roles.contains(&"registrar") {
                                    if let Some(vcard) = ent["vcardArray"].as_array() {
                                        for item in vcard {
                                            if let Some(arr) = item.as_array() {
                                                if arr.len() > 3 {
                                                    if arr[0].as_str() == Some("fn") {
                                                        result.registrar = arr[3].as_str().map(|s| s.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if roles.contains(&"registrant") {
                                    if let Some(vcard) = ent["vcardArray"].as_array() {
                                        for item in vcard {
                                            if let Some(arr) = item.as_array() {
                                                if arr.len() > 3 {
                                                    match arr[0].as_str() {
                                                        Some("fn") => result.registrant_org = arr[3].as_str().map(|s| s.to_string()),
                                                        Some("adr") => {
                                                            if let Some(adr_arr) = arr[3].as_array() {
                                                                if adr_arr.len() > 6 {
                                                                    result.registrant_country = adr_arr[6].as_str().map(|s| s.to_string());
                                                                }
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(ns) = data["nameservers"].as_array() {
                            for n in ns {
                                if let Some(lfh) = n["ldhName"].as_str() {
                                    result.name_servers.push(lfh.to_lowercase().trim_end_matches('.').to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => { result.error = Some(format!("{:.80}", e)); }
        }
    }
    progress_done!("whois");
    result
}
