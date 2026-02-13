mod fast_scanner;
mod os_fingerprint;
mod advanced_modules;
mod core_engine;
pub use fast_scanner::*;
pub use os_fingerprint::*;
pub use advanced_modules::*;
pub use core_engine::*;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::net::{ToSocketAddrs};
use std::time::Duration;
use regex::Regex;
use lazy_static::lazy_static;
use tokio::runtime::Runtime;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout as tokio_timeout;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().expect("Failed to create Tokio runtime");
    static ref FINGERPRINTS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"(?i)ssh-2\.0-openssh_([0-9._p]+)").unwrap(), "OpenSSH"),
        (Regex::new(r"(?i)ssh-2\.0-([a-z0-9._-]+)").unwrap(), "SSH"),
        (Regex::new(r"(?i)ftp.*220[ \-]([a-z0-9._-]+)").unwrap(), "FTP"),
        (Regex::new(r"(?i)server: nginx/([0-9.]+)").unwrap(), "Nginx"),
        (Regex::new(r"(?i)server: apache/([0-9.]+)").unwrap(), "Apache"),
        (Regex::new(r"(?i)server: microsoft-iis/([0-9.]+)").unwrap(), "IIS"),
        (Regex::new(r"(?i)mysql[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MySQL"),
        (Regex::new(r"(?i)mariadb[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MariaDB"),
        (Regex::new(r"(?i)postgresql ([0-9.]+)").unwrap(), "PostgreSQL"),
        (Regex::new(r"(?i)redis_version:([0-9.]+)").unwrap(), "Redis"),
        (Regex::new(r"(?i)mongodb [v]?([0-9.]+)").unwrap(), "MongoDB"),
        (Regex::new(r"(?i)220.*(smtp|esmtp).*([0-9.]+)").unwrap(), "SMTP"),
        (Regex::new(r"(?i)http/1\.[01]").unwrap(), "HTTP"),
        (Regex::new(r"(?i)html").unwrap(), "HTTP"),
        (Regex::new(r"(?i)microsoft-httpapi/([0-9.]+)").unwrap(), "HTTPAPI"),
        (Regex::new(r"(?i)lite speed").unwrap(), "LiteSpeed"),
        (Regex::new(r"(?i)cloudflare").unwrap(), "Cloudflare"),
        (Regex::new(r"(?i)squid/([0-9.]+)").unwrap(), "Squid Proxy"),
        (Regex::new(r"(?i)varnish").unwrap(), "Varnish Cache"),
        (Regex::new(r"(?i)mikrotik http proxy").unwrap(), "MikroTik"),
        (Regex::new(r"(?i)winrm").unwrap(), "WinRM"),
        (Regex::new(r"(?i)rdp").unwrap(), "RDP"),
    ];
}

#[no_mangle]
pub unsafe extern "C" fn rust_extract_version(banner: *const c_char, _service: *const c_char) -> *mut c_char {
    let c_banner = CStr::from_ptr(banner).to_str().unwrap_or("");
    
    for (regex, _name) in FINGERPRINTS.iter() {
        if let Some(captures) = regex.captures(c_banner) {
            if captures.len() > 1 {
                if let Some(version) = captures.get(1) {
                    return CString::new(version.as_str()).unwrap().into_raw();
                }
            }
        }
    }
    
    CString::new("").unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_scan_port(host: *const c_char, port: i32, timeout_ms: i32) -> *mut c_char {
    let c_str = CStr::from_ptr(host);
    let host_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("error").unwrap().into_raw(),
    };

    let addr_str = format!("{}:{}", host_str, port);
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Use Tokio for high-performance async connect scan
    let result = RUNTIME.block_on(async {
        match tokio_timeout(timeout, AsyncTcpStream::connect(&addr_str)).await {
            Ok(Ok(_)) => "open",
            Ok(Err(e)) => {
                let err_msg = e.to_string().to_lowercase();
                if err_msg.contains("refused") {
                    "closed"
                } else {
                    "closed"
                }
            }
            Err(_) => "filtered", // Timeout
        }
    });

    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_syn_scan(host: *const c_char, port: i32, timeout_ms: i32) -> *mut c_char {
    // On Windows without Npcap, we use a super-fast async connect scan
    // which behaves similarly for discovery.
    rust_scan_port(host, port, timeout_ms)
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_string(s: *mut c_char) {
    if s.is_null() { return; }
    let _ = CString::from_raw(s);
}

#[no_mangle]
pub unsafe extern "C" fn rust_fingerprint_service(banner: *const c_char) -> *mut c_char {
    let c_banner = CStr::from_ptr(banner).to_str().unwrap_or("");
    
    for (regex, name) in FINGERPRINTS.iter() {
        if regex.is_match(c_banner) {
            return CString::new(*name).unwrap().into_raw();
        }
    }
    
    CString::new("unknown").unwrap().into_raw()
}
