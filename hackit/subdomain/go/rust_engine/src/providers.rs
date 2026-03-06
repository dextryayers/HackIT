use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use reqwest::blocking::Client;
use std::time::Duration;
use regex::Regex;

pub fn rust_fetch_osint(domain: &str) -> Vec<String> {
    let mut subs = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
        .build()
        .unwrap_or_else(|_| Client::new());

    // 1. CRT.sh (Rust implementation is faster)
    let crt_url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    if let Ok(resp) = client.get(&crt_url).send() {
        if let Ok(json) = resp.json::<Vec<serde_json::Value>>() {
            for entry in json {
                if let Some(name) = entry["name_value"].as_str() {
                    for sub in name.split('\n') {
                        let clean = sub.trim_start_matches("*.").to_lowercase();
                        if clean.ends_with(domain) {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
    }

    // 2. Anubis (Fast JSON API)
    let anubis_url = format!("https://jldc.me/anubis/subdomains/{}", domain);
    if let Ok(resp) = client.get(&anubis_url).send() {
        if let Ok(json) = resp.json::<Vec<String>>() {
            for sub in json {
                if sub.ends_with(domain) {
                    subs.push(sub.to_lowercase());
                }
            }
        }
    }

    // 3. HackerTarget (Simple Text API)
    let ht_url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    if let Ok(resp) = client.get(&ht_url).send() {
        if let Ok(text) = resp.text() {
            for line in text.lines() {
                if let Some(sub) = line.split(',').next() {
                    let clean = sub.to_lowercase();
                    if clean.ends_with(domain) {
                        subs.push(clean);
                    }
                }
            }
        }
    }

    // 4. AlienVault OTX (Reliable API)
    let otx_url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns", domain);
    if let Ok(resp) = client.get(&otx_url).send() {
        if let Ok(json) = resp.json::<serde_json::Value>() {
            if let Some(passive_dns) = json["passive_dns"].as_array() {
                for entry in passive_dns {
                    if let Some(hostname) = entry["hostname"].as_str() {
                        let clean = hostname.to_lowercase();
                        if clean.ends_with(domain) {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
    }

    // 5. ThreatCrowd (OSINT)
    let tc_url = format!("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}", domain);
    if let Ok(resp) = client.get(&tc_url).send() {
        if let Ok(json) = resp.json::<serde_json::Value>() {
            if let Some(subdomains) = json["subdomains"].as_array() {
                for s in subdomains {
                    if let Some(sub) = s.as_str() {
                        let clean = sub.to_lowercase();
                        if clean.ends_with(domain) {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
    }

    // 6. Wayback Machine CDX (Deep History)
    let wayback_url = format!("http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey", domain);
    if let Ok(resp) = client.get(&wayback_url).send() {
        if let Ok(json) = resp.json::<Vec<Vec<String>>>() {
            for row in json.into_iter().skip(1) { // Skip header
                if !row.is_empty() {
                    let url = &row[0];
                    let clean_url = url.replace("http://", "").replace("https://", "");
                    let domain_part = clean_url.split('/').next().unwrap_or("").to_lowercase();
                    if domain_part.ends_with(domain) {
                        subs.push(domain_part);
                    }
                }
            }
        }
    }

    // 7. Sonar (Omnisint) - Fast API
    let sonar_url = format!("https://sonar.omnisint.io/subdomains/{}", domain);
    if let Ok(resp) = client.get(&sonar_url).send() {
        if let Ok(json) = resp.json::<Vec<String>>() {
            for sub in json {
                if sub.ends_with(domain) {
                    subs.push(sub.to_lowercase());
                }
            }
        }
    }

    // 8. UrlScan.io (Public Search)
    let urlscan_url = format!("https://urlscan.io/api/v1/search/?q=domain:{}&size=100", domain);
    if let Ok(resp) = client.get(&urlscan_url).send() {
        if let Ok(json) = resp.json::<serde_json::Value>() {
            if let Some(results) = json["results"].as_array() {
                for r in results {
                    if let Some(sub) = r["page"]["domain"].as_str() {
                        let clean = sub.to_lowercase();
                        if clean.ends_with(domain) {
                            subs.push(clean);
                        }
                    }
                }
            }
        }
    }

    subs.sort();
    subs.dedup();
    subs
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_osint_scan(domain: *const c_char) -> *mut c_char {
    if domain.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(domain) };
    let domain_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let results = rust_fetch_osint(domain_str);
    let final_result = results.join(",");
    
    CString::new(final_result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_get_title(url: *const c_char) -> *mut c_char {
    if url.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(url) };
    let url_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| Client::new());

    if let Ok(resp) = client.get(url_str).send() {
        if let Ok(body) = resp.text() {
            let re = Regex::new(r"(?i)<title>(.*?)</title>").unwrap();
            if let Some(cap) = re.captures(&body) {
                let title = cap.get(1).map_or("", |m| m.as_str()).trim();
                return CString::new(title).unwrap().into_raw();
            }
        }
    }

    CString::new("").unwrap().into_raw()
}
