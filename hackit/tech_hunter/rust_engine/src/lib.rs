pub mod dns_history;
pub mod security_headers;
pub mod waf_engine;
pub mod web_server_fingerprint;
pub mod tech_scanner;

use std::ffi::{CStr, CString};

#[no_mangle]
pub extern "C" fn rust_fetch_url(url: *const i8) -> *mut i8 {
    let c_str = unsafe { CStr::from_ptr(url) };
    let url_str = c_str.to_str().unwrap_or("");
    // In a real scenario, this would use reqwest/curl
    // For this simulation, we return a JSON with status 200 and a body snippet
    let res = format!(r#"{{"status": 200, "body": "<html><title>Simulated</title><body><h1>Target: {}</h1><script src='jquery.js'></script></body></html>"}}"#, url_str);
    CString::new(res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut i8) {
    if !s.is_null() {
        unsafe { CString::from_raw(s) };
    }
}

#[no_mangle]
pub extern "C" fn fetch_dns_history(target: *const i8) -> *mut i8 {
    let c_str = unsafe { CStr::from_ptr(target) };
    let domain = c_str.to_str().unwrap_or("");
    let json = dns_history::get_history_json(domain);
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_dns_history_string(s: *mut i8) {
    if !s.is_null() {
        unsafe { CString::from_raw(s) };
    }
}

#[no_mangle]
pub extern "C" fn detect_waf(headers_json: *const i8) -> *mut i8 {
    let c_str = unsafe { CStr::from_ptr(headers_json) };
    let headers_raw = c_str.to_str().unwrap_or("{}");
    let json = waf_engine::get_waf_json(headers_raw);
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_waf_string(s: *mut i8) {
    if !s.is_null() {
        unsafe { CString::from_raw(s) };
    }
}

#[no_mangle]
pub extern "C" fn audit_security_headers(headers_json: *const i8) -> *mut i8 {
    let c_str = unsafe { CStr::from_ptr(headers_json) };
    let headers_raw = c_str.to_str().unwrap_or("{}");
    let json = security_headers::get_audit_json(headers_raw);
    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_header_string(s: *mut i8) {
    if !s.is_null() {
        unsafe { CString::from_raw(s) };
    }
}

#[no_mangle]
pub extern "C" fn fingerprint_web_app(headers_json: *const i8) -> *mut i8 {
    let c_str = unsafe { CStr::from_ptr(headers_json) };
    let headers_raw = c_str.to_str().unwrap_or("{}");
    let json_res = web_server_fingerprint::get_fingerprint_json(headers_raw);
    CString::new(json_res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_fingerprint_string(s: *mut i8) {
    if !s.is_null() { unsafe { CString::from_raw(s) }; }
}

#[no_mangle]
pub extern "C" fn scan_tech_stack(headers_json: *const i8, body: *const i8) -> *mut i8 {
    let c_headers = unsafe { CStr::from_ptr(headers_json) };
    let c_body = unsafe { CStr::from_ptr(body) };
    let h_raw = c_headers.to_str().unwrap_or("{}");
    let b_raw = c_body.to_str().unwrap_or("");
    
    // Original tech scanner logic
    let mut json = tech_scanner::get_tech_json(h_raw, b_raw);

    // Rate Limiting Heuristics
    if h_raw.contains("X-RateLimit") || h_raw.contains("Retry-After") {
        json = json.replace("\"analytics\":", "\"rate_limiting\": \"Detected via Headers\", \"analytics\":");
    }

    // API Versioning Heuristics
    if b_raw.contains("/api/v1/") || b_raw.contains("/api/v2/") || b_raw.contains("/api/v3/") {
        json = json.replace("\"analytics\":", "\"api_versioning\": \"Detected (/api/vX/)\", \"analytics\":");
    }

    CString::new(json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_tech_string(s: *mut i8) {
    if !s.is_null() { unsafe { CString::from_raw(s) }; }
}
