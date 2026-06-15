pub mod dns_history;
pub mod security_headers;
pub mod waf_engine;
pub mod web_server_fingerprint;
pub mod tech_scanner;

use std::ffi::{CStr, CString};
use reqwest::blocking::Client;
use std::time::Duration;
use regex::Regex;
use serde_json::json;

fn c_str_to_str(ptr: *const i8) -> &'static str {
    if ptr.is_null() { return ""; }
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

fn str_to_c_str(s: &str) -> *mut i8 {
    CString::new(s).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
}

#[no_mangle]
pub extern "C" fn rust_fetch_url(url: *const i8) -> *mut i8 {
    let url_str = c_str_to_str(url);
    if url_str.is_empty() { return str_to_c_str("{}"); }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent("TechHunter/3.0 (Asset Mapping)")
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut status = 0u16;
    let mut body = String::new();
    let mut desc = String::from("No brief available.");
    let mut title = String::from("No Title");
    let mut content_type = String::new();

    if let Ok(resp) = client.get(url_str).send() {
        status = resp.status().as_u16();
        content_type = resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if let Ok(text) = resp.text() {
            body = text.clone();

            if let Ok(re_title) = Regex::new(r"(?i)<title>(.*?)</title>") {
                if let Some(cap) = re_title.captures(&text) {
                    title = cap.get(1).map_or("", |m| m.as_str()).trim().to_string();
                }
            }

            if let Ok(re_desc) = Regex::new(r#"(?i)<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']"#) {
                if let Some(cap) = re_desc.captures(&text) {
                    desc = cap.get(1).map_or("", |m| m.as_str()).trim().to_string();
                }
            } else if let Ok(re_desc2) = Regex::new(r#"(?i)<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["']"#) {
                if let Some(cap) = re_desc2.captures(&text) {
                    desc = cap.get(1).map_or("", |m| m.as_str()).trim().to_string();
                }
            }
        }
    }

    let result = json!({
        "status": status,
        "title": title,
        "description": desc,
        "body": body,
        "content_type": content_type,
        "url": url_str,
    });

    CString::new(result.to_string()).unwrap_or_else(|_| CString::new("{}").unwrap()).into_raw()
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut i8) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); };
    }
}

#[no_mangle]
pub extern "C" fn fetch_dns_history(target: *const i8) -> *mut i8 {
    let domain = c_str_to_str(target);
    let json = dns_history::get_history_json(domain);
    str_to_c_str(&json)
}

#[no_mangle]
pub extern "C" fn free_dns_history_string(s: *mut i8) {
    if !s.is_null() {         unsafe { let _ = CString::from_raw(s); }; }
}

#[no_mangle]
pub extern "C" fn detect_waf(headers_raw: *const i8) -> *mut i8 {
    let headers = c_str_to_str(headers_raw);
    let json = waf_engine::get_waf_json(headers);
    str_to_c_str(&json)
}

#[no_mangle]
pub extern "C" fn free_waf_string(s: *mut i8) {
    if !s.is_null() {         unsafe { let _ = CString::from_raw(s); }; }
}

#[no_mangle]
pub extern "C" fn audit_security_headers(headers_raw: *const i8) -> *mut i8 {
    let headers = c_str_to_str(headers_raw);
    let json = security_headers::get_audit_json(headers);
    str_to_c_str(&json)
}

#[no_mangle]
pub extern "C" fn free_header_string(s: *mut i8) {
    if !s.is_null() {         unsafe { let _ = CString::from_raw(s); }; }
}

#[no_mangle]
pub extern "C" fn fingerprint_web_app(headers_raw: *const i8) -> *mut i8 {
    let headers = c_str_to_str(headers_raw);
    let json = web_server_fingerprint::get_fingerprint_json(headers);
    str_to_c_str(&json)
}

#[no_mangle]
pub extern "C" fn free_fingerprint_string(s: *mut i8) {
    if !s.is_null() {         unsafe { let _ = CString::from_raw(s); }; }
}

#[no_mangle]
pub extern "C" fn scan_tech_stack(headers_raw: *const i8, body_raw: *const i8) -> *mut i8 {
    let headers = c_str_to_str(headers_raw);
    let body = c_str_to_str(body_raw);
    let json = tech_scanner::get_tech_json(headers, body);
    str_to_c_str(&json)
}

#[no_mangle]
pub extern "C" fn free_tech_string(s: *mut i8) {
    if !s.is_null() {         unsafe { let _ = CString::from_raw(s); }; }
}
