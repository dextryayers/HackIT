/*
 * HackIT Deep Vulnerability Orchestrator (Rust)
 * Multi-vector probing and advanced exploit signature chaining.
 */

use regex::Regex;

pub struct DeepProbeResult {
    pub risk_score: u8,
    pub findings: Vec<String>,
}

pub fn orchestrate_deep_scan(host: &str, port: u16, banner: &str) -> DeepProbeResult {
    let mut findings = Vec::new();
    let mut risk_score = 0;

    // Advanced Regex for deep identification
    let deep_regexes = vec![
        (Regex::new(r"(?i)admin").unwrap(), "Sensitive 'admin' keyword found in banner"),
        (Regex::new(r"(?i)debug").unwrap(), "Potential debug mode enabled"),
        (Regex::new(r"(?i)internal").unwrap(), "Potential internal resource exposure"),
    ];

    for (re, msg) in deep_regexes {
        if re.is_match(banner) {
            findings.push(msg.to_string());
            risk_score += 2;
        }
    }

    if risk_score > 10 { risk_score = 10; }

    DeepProbeResult { risk_score, findings }
}

#[no_mangle]
pub unsafe extern "C" fn rust_perform_deep_scan(host: *const std::os::raw::c_char, port: u16, banner: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let c_host = std::ffi::CStr::from_ptr(host).to_str().unwrap_or("");
    let c_banner = std::ffi::CStr::from_ptr(banner).to_str().unwrap_or("");
    
    let result = orchestrate_deep_scan(c_host, port, c_banner);
    
    let mut output = format!("DEEP_SCAN_RISK: {}\n", result.risk_score);
    for finding in result.findings {
        output.push_str(&format!("  » {}\n", finding));
    }
    
    std::ffi::CString::new(output).unwrap().into_raw()
}
