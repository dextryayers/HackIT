use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use tokio::runtime::Runtime;
use lazy_static::lazy_static;

mod behavior;
mod dns_security;
mod fingerprint;
mod intelligence;
mod metadata_extractor;
mod os_detector;
mod tls_forensics;
mod waf_detector;

lazy_static! {
    static ref GLOBAL_RT: Runtime = Runtime::new().expect("Failed to create global runtime");
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
        CStr::from_ptr(c_url).to_string_lossy().into_owned()
    };

    let ua = unsafe {
        if user_agent.is_null() {
            "TechHunter/3.0".to_string()
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

    let result = GLOBAL_RT.block_on(async {
        fetch_url_async(&url, timeout_secs, follow_redirects, verify_ssl, &ua, proxy, http2_only, fetch_favicon, deep_scan).await
    });

    let json_res = serde_json::to_string(&result).unwrap_or_else(|_| "{\"error\": \"Serialization error\"}".to_string());
    CString::new(json_res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_rust_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

async fn fetch_url_async(
    url: &str,
    timeout: u64,
    _follow: bool,
    _verify: bool,
    ua: &str,
    _proxy: Option<String>,
    _http2: bool,
    _favicon: bool,
    _deep: bool,
) -> RustScanResult {
    let client = reqwest::Client::builder()
        .user_agent(ua)
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let start = Instant::now();
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => return RustScanResult {
            url: url.to_string(),
            status: 0,
            headers: HashMap::new(),
            body_snippet: String::new(),
            response_time_ms: 0,
            error: Some(e.to_string()),
            detected_techs: HashMap::new(),
            waf_info: Vec::new(),
            industry_hint: None,
            description: None,
            os_info: None,
            tls_issuer: None,
            phone: None,
            address: None,
        },
    };

    let duration = start.elapsed().as_millis() as i64;
    let status = resp.status().as_u16() as i32;
    let mut headers = HashMap::new();
    for (k, v) in resp.headers() {
        headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
    }

    let body = resp.text().await.unwrap_or_default();
    let body_snippet = if body.len() > 5000 { body[..5000].to_string() } else { body.clone() };

    let mut detected_techs = fingerprint::analyze(&body, &headers);
    let waf_info = waf_detector::detect_waf(&headers);
    let behaviors = behavior::analyze_behavior(&headers, status);
    let intel = intelligence::analyze_intelligence(&body, &headers);
    // Note: TXT records are usually analyzed from a real lookup, but here we pass body as signal
    let dns_sec = dns_security::analyze_dns_security(&vec![body.clone()]);
    let metadata = metadata_extractor::extract_metadata(&body);
    let os_info = os_detector::detect_os(&headers, &body);
    let tls_info = tls_forensics::analyze_tls(&headers);
    
    // Add behavior signals
    for b in behaviors {
        detected_techs.insert(b.clone(), TechInfo {
            name: b,
            confidence: 100,
            category: "Behavior Signal".to_string(),
            version: None,
        });
    }
    
    // Add intel signals to techs for now or handle separately
    for signal in intel.signals {
        detected_techs.insert(signal.clone(), TechInfo {
            name: signal,
            confidence: intel.score,
            category: "Intelligence Signal".to_string(),
            version: None,
        });
    }

    RustScanResult {
        url: url.to_string(),
        status,
        headers,
        body_snippet,
        response_time_ms: duration,
        error: None,
        detected_techs,
        waf_info,
        industry_hint: Some(metadata.industry_hint),
        description: Some(metadata.description),
        os_info: Some(os_info),
        tls_issuer: tls_info.map(|t| t.issuer),
        phone: Some(metadata.phone),
        address: Some(metadata.address),
    }
}

use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
struct RustScanResult {
    url: String,
    status: i32,
    headers: HashMap<String, String>,
    body_snippet: String,
    response_time_ms: i64,
    error: Option<String>,
    detected_techs: HashMap<String, TechInfo>,
    waf_info: Vec<String>,
    industry_hint: Option<String>,
    description: Option<String>,
    os_info: Option<String>,
    tls_issuer: Option<String>,
    phone: Option<String>,
    address: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TechInfo {
    name: String,
    confidence: i32,
    category: String,
    version: Option<String>,
}
