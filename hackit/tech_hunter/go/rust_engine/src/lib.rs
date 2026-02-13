use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

mod fingerprint;
mod tls_analyzer;
mod waf_detector;
mod port_analyzer;
mod vulnerability_matcher;
mod whois_scanner;
mod info_extractor;
mod crawler;
mod dns_analyzer;
mod header_analyzer;
mod path_scanner;
mod subdomain_enum;
mod server_analyzer;
mod db_detector;
mod provide;

use crate::tls_analyzer::RustTLSInfo;
use crate::vulnerability_matcher::Vulnerability;
use crate::whois_scanner::WhoisInfo;
use crate::port_analyzer::PortInfo;
use crate::info_extractor::ContactInfo;
use crate::dns_analyzer::DNSInfo;
use crate::header_analyzer::HeaderSecurity;
use crate::path_scanner::PathDiscovery;
use crate::subdomain_enum::SubdomainInfo;
use crate::server_analyzer::ServerDetails;
use crate::db_detector::DBDetails;

#[derive(Serialize, Deserialize)]
pub struct RustScanResult {
    pub url: String,
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body_snippet: String,
    pub response_time_ms: u128,
    pub error: Option<String>,
    pub favicon_hash: Option<String>,
    pub tls_info: Option<RustTLSInfo>,
    pub detected_techs: std::collections::HashMap<String, String>,
    pub waf_info: Vec<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub whois: Option<WhoisInfo>,
    pub open_ports: Vec<PortInfo>,
    pub contact_info: ContactInfo,
    pub dns_info: DNSInfo,
    pub header_security: HeaderSecurity,
    pub path_discoveries: Vec<PathDiscovery>,
    pub subdomains: Vec<SubdomainInfo>,
    pub server_details: ServerDetails,
    pub db_details: Option<DBDetails>,
    pub advanced_analysis: Option<provide::advanced_analyzer::AdvancedAnalysis>,
    pub expert_vulnerabilities: Vec<provide::expert_exploit_finder::ExpertVulnerability>,
    pub behavioral_techs: Vec<String>,
    pub cloud_audit: Option<provide::cloud_metadata_scanner::CloudAudit>,
}

#[no_mangle]
pub extern "C" fn rust_fetch_url(
    c_url: *const c_char,
    timeout_secs: u64,
    follow_redirects: bool,
    verify_ssl: bool,
    user_agent: *const c_char,
    proxy_url: *const c_char,
    http2_only: bool,
    fetch_favicon: bool,
    deep_scan: bool,
) -> *mut c_char {
    let url = unsafe {
        if c_url.is_null() {
            return CString::new("{\"error\": \"Null URL\"}").unwrap().into_raw();
        }
        let raw_url = CStr::from_ptr(c_url).to_string_lossy().into_owned();
        if !raw_url.starts_with("http://") && !raw_url.starts_with("https://") {
            format!("http://{}", raw_url)
        } else {
            raw_url
        }
    };

    let ua = unsafe {
        if user_agent.is_null() {
            "TechHunter-Rust-Core/1.0".to_string()
        } else {
            CStr::from_ptr(user_agent).to_string_lossy().into_owned()
        }
    };

    let proxy = unsafe {
        if proxy_url.is_null() {
            None
        } else {
            let p = CStr::from_ptr(proxy_url).to_string_lossy().into_owned();
            if p.is_empty() { None } else { Some(p) }
        }
    };

    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => return CString::new(format!("{{\"error\": \"Runtime error: {}\"}}", e)).unwrap().into_raw(),
    };

    let result = rt.block_on(async {
        fetch_url_async(&url, timeout_secs, follow_redirects, verify_ssl, &ua, proxy, http2_only, fetch_favicon, deep_scan).await
    });

    let json_res = serde_json::to_string(&result).unwrap_or_else(|_| "{\"error\": \"Serialization error\"}".to_string());
    CString::new(json_res).unwrap().into_raw()
}

async fn fetch_url_async(
    url: &str,
    timeout_secs: u64,
    follow_redirects: bool,
    verify_ssl: bool,
    ua: &str,
    proxy_url: Option<String>,
    http2_only: bool,
    fetch_favicon: bool,
    deep_scan: bool,
) -> RustScanResult {
    let start = Instant::now();
    
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(!verify_ssl)
        .redirect(redirect_policy)
        .cookie_store(true);

    // Apply Stealth Headers if deep_scan is on
    let mut final_headers = reqwest::header::HeaderMap::new();
    if deep_scan {
        let stealth_headers = provide::stealth_engine::get_random_stealth_headers();
        for (k, v) in stealth_headers {
            if let Ok(name) = reqwest::header::HeaderName::from_bytes(k.as_bytes()) {
                if let Ok(val) = reqwest::header::HeaderValue::from_str(&v) {
                    final_headers.insert(name, val);
                }
            }
        }
    } else {
        final_headers.insert(reqwest::header::USER_AGENT, reqwest::header::HeaderValue::from_str(&ua).unwrap());
    }
    
    client_builder = client_builder.default_headers(final_headers);

    if http2_only {
        client_builder = client_builder.http2_prior_knowledge();
    }

    if let Some(p) = proxy_url {
        if let Ok(proxy) = reqwest::Proxy::all(p) {
            client_builder = client_builder.proxy(proxy);
        }
    }

    let client = match client_builder.build() {
            Ok(c) => c,
            Err(e) => return error_result(url, format!("Client build error: {}", e)),
        };

    let result = match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let mut headers = std::collections::HashMap::new();
            for (name, value) in resp.headers().iter() {
                headers.insert(
                    name.to_string(),
                    value.to_str().unwrap_or("").to_string()
                );
            }

            let mut tls_info = None;
            if url.starts_with("https") {
                 tls_info = tls_analyzer::analyze_tls(url);
             }

            let (full_body, _body_snippet) = match resp.bytes().await {
                Ok(b) => {
                    let full_limit = std::cmp::min(b.len(), 102400); // 100KB for detection
                    let snippet_limit = std::cmp::min(b.len(), 2048); // 2KB for output
                    (
                        String::from_utf8_lossy(&b[..full_limit]).into_owned(),
                        String::from_utf8_lossy(&b[..snippet_limit]).into_owned()
                    )
                },
                Err(_) => ("".to_string(), "".to_string()),
            };

            let mut detected_techs = fingerprint::detect_technologies(&full_body, &headers);
            let waf_info = waf_detector::detect_waf_cdn(&headers);
            let vulnerabilities = vulnerability_matcher::match_vulnerabilities(&detected_techs);
            
            let host = url::Url::parse(url).map(|u| u.host_str().unwrap_or("").to_string()).unwrap_or_default();
            let whois = whois_scanner::fetch_whois(&host).await;
            let open_ports = port_analyzer::scan_common_ports(&host).await;
            let dns_info = dns_analyzer::analyze_dns(&host).await;
            let header_security = header_analyzer::analyze_headers(&headers);
            
            let mut contact_info = info_extractor::extract_contacts(&full_body);

            if deep_scan {
                let (deep_techs, deep_contacts) = crawler::crawl_and_extract(url, &client, 2).await;
                // Merge deep techs
                for (k, v) in deep_techs {
                    detected_techs.insert(k, v);
                }
                // Merge deep contacts
                contact_info.emails.extend(deep_contacts.emails);
                contact_info.phones.extend(deep_contacts.phones);
                contact_info.social_links.extend(deep_contacts.social_links);
                
                // Deduplicate
                contact_info.emails.sort(); contact_info.emails.dedup();
                contact_info.phones.sort(); contact_info.phones.dedup();
                contact_info.social_links.sort(); contact_info.social_links.dedup();
            }

            let path_discoveries = if deep_scan {
                path_scanner::scan_sensitive_paths(url).await
            } else {
                Vec::new()
            };

            let subdomains = if deep_scan {
                subdomain_enum::enumerate_subdomains(&host).await
            } else {
                Vec::new()
            };

            let server_details = server_analyzer::analyze_server(&headers, &full_body, &host);
            let db_details = db_detector::detect_database(&headers, &full_body);
            let advanced_analysis = Some(provide::advanced_analyzer::analyze_behaviours(&full_body, &headers));
            let expert_vulnerabilities = provide::expert_exploit_finder::find_expert_vulns(&full_body, &headers);
            let behavioral_techs = provide::behavioral_fingerprint::detect_expert_behavior(&full_body, &headers);
            let cloud_audit = Some(provide::cloud_metadata_scanner::audit_cloud_infra(&headers));

            let mut result = RustScanResult {
                url: url.to_string(),
                status,
                headers,
                body_snippet: full_body.chars().take(2000).collect(),
                response_time_ms: start.elapsed().as_millis(),
                error: None,
                favicon_hash: None,
                tls_info,
                detected_techs,
                waf_info,
                vulnerabilities,
                whois,
                open_ports,
                contact_info,
                dns_info,
                header_security,
                path_discoveries,
                subdomains,
                server_details,
                db_details,
                advanced_analysis,
                expert_vulnerabilities,
                behavioral_techs,
                cloud_audit,
            };

            if fetch_favicon {
                if let Ok(target_url) = url::Url::parse(url) {
                    if let Ok(favicon_url) = target_url.join("/favicon.ico") {
                        if let Ok(fav_resp) = client.get(favicon_url).send().await {
                            if fav_resp.status().is_success() {
                                if let Ok(bytes) = fav_resp.bytes().await {
                                    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
                                    let mut shodan_base64 = String::new();
                                    for (i, c) in encoded.chars().enumerate() {
                                        shodan_base64.push(c);
                                        if (i + 1) % 76 == 0 {
                                            shodan_base64.push('\n');
                                        }
                                    }
                                    if !shodan_base64.ends_with('\n') {
                                        shodan_base64.push('\n');
                                    }

                                    use std::io::Cursor;
                                    let mut cursor = Cursor::new(shodan_base64.as_bytes());
                                    if let Ok(hash) = murmur3::murmur3_32(&mut cursor, 0) {
                                        result.favicon_hash = Some(hash.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            result
        },
        Err(e) => error_result(url, format!("Request error: {}", e)),
    };

    result
}

fn error_result(url: &str, err: String) -> RustScanResult {
    RustScanResult {
        url: url.to_string(),
        status: 0,
        headers: std::collections::HashMap::new(),
        body_snippet: "".to_string(),
        response_time_ms: 0,
        error: Some(err),
        favicon_hash: None,
        tls_info: None,
        detected_techs: std::collections::HashMap::new(),
        waf_info: Vec::new(),
        vulnerabilities: Vec::new(),
        whois: None,
        open_ports: Vec::new(),
        contact_info: ContactInfo::default(),
        dns_info: DNSInfo::default(),
        header_security: HeaderSecurity::default(),
        path_discoveries: Vec::new(),
        subdomains: Vec::new(),
        server_details: ServerDetails::default(),
        db_details: None,
        advanced_analysis: None,
        expert_vulnerabilities: Vec::new(),
        behavioral_techs: Vec::new(),
        cloud_audit: None,
    }
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
