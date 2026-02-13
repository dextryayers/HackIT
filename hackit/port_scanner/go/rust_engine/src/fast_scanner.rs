use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use regex::Regex;
use lazy_static::lazy_static;
use tokio::runtime::Runtime;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout as tokio_timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

lazy_static! {
    pub static ref RUNTIME: Runtime = Runtime::new().expect("Failed to create Tokio runtime");
    pub static ref FINGERPRINTS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"(?i)ssh-2\.0-openssh_([0-9._p]+)").unwrap(), "SSH"),
        (Regex::new(r"(?i)ssh-2\.0-([a-z0-9._-]+)").unwrap(), "SSH"),
        (Regex::new(r"(?i)ftp.*220[ \-]([a-z0-9._-]+)").unwrap(), "FTP"),
        (Regex::new(r"(?i)server: nginx/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)server: apache/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)server: microsoft-iis/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)mysql[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MYSQL"),
        (Regex::new(r"(?i)mariadb[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MYSQL"),
        (Regex::new(r"(?i)postgresql ([0-9.]+)").unwrap(), "POSTGRESQL"),
        (Regex::new(r"(?i)redis_version:([0-9.]+)").unwrap(), "REDIS"),
        (Regex::new(r"(?i)mongodb [v]?([0-9.]+)").unwrap(), "MONGODB"),
        (Regex::new(r"(?i)220.*(smtp|esmtp).*([0-9.]+)").unwrap(), "SMTP"),
        (Regex::new(r"(?i)http/1\.[01]").unwrap(), "HTTP"),
        (Regex::new(r"(?i)html").unwrap(), "HTTP"),
        (Regex::new(r"(?i)dovecot").unwrap(), "IMAP/POP3"),
    ];
}

#[repr(C)]
pub struct RustScanResult {
    pub port: i32,
    pub state: *mut c_char,
    pub service: *mut c_char,
    pub banner: *mut c_char,
    pub version: *mut c_char,
}

#[no_mangle]
pub unsafe extern "C" fn rust_fast_scan(host: *const c_char, port: i32, timeout_ms: i32, stealth: bool) -> *mut RustScanResult {
    let c_host = CStr::from_ptr(host).to_str().unwrap_or("");
    let addr = format!("{}:{}", c_host, port);
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Anonymous Plus: Adaptive Delay
    if stealth {
        let delay = (port % 50) as u64; // Jitter delay
        RUNTIME.block_on(async { sleep(Duration::from_millis(delay)).await });
    }

    let result = RUNTIME.block_on(async {
        match tokio_timeout(timeout, AsyncTcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let mut banner = String::new();
                let mut buffer = [0u8; 1024];

                // Special probes for certain ports to trigger banner
                match port {
                    80 | 8080 | 443 | 8443 => {
                        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                    },
                    21 => { /* FTP sends banner automatically */ },
                    25 | 587 => { let _ = stream.write_all(b"HELO rust-scanner\r\n").await; },
                    _ => {}
                }

                // Try to read banner
                if let Ok(Ok(n)) = tokio_timeout(Duration::from_millis(800), stream.read(&mut buffer)).await {
                    if n > 0 {
                        banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                    }
                }

                let mut service = "UNKNOWN".to_string();
                let mut version = String::new();

                for (regex, name) in FINGERPRINTS.iter() {
                    if let Some(captures) = regex.captures(&banner) {
                        service = name.to_string();
                        if captures.len() > 1 {
                            version = captures.get(1).map_or("", |m| m.as_str()).to_string();
                        }
                        break;
                    }
                }

                // Fallback for empty banner
                if service == "UNKNOWN" {
                    service = match port {
                        21 => "FTP", 22 => "SSH", 23 => "TELNET", 25 => "SMTP", 53 => "DNS",
                        80 => "HTTP", 110 => "POP3", 111 => "RPCBIND", 143 => "IMAP",
                        443 => "HTTP", 445 => "MICROSOFT-DS", 1433 => "MSSQL", 1521 => "ORACLE",
                        3306 => "MYSQL", 5432 => "POSTGRESQL", 6379 => "REDIS", 27017 => "MONGODB",
                        _ => "UNKNOWN"
                    }.to_string();
                }

                (true, service, banner, version)
            }
            _ => (false, "CLOSED".to_string(), String::new(), String::new()),
        }
    });

    let res = if result.0 {
        RustScanResult {
            port,
            state: CString::new("open").unwrap().into_raw(),
            service: CString::new(result.1).unwrap().into_raw(),
            banner: CString::new(result.2).unwrap().into_raw(),
            version: CString::new(result.3).unwrap().into_raw(),
        }
    } else {
        RustScanResult {
            port,
            state: CString::new("closed").unwrap().into_raw(),
            service: CString::new("UNKNOWN").unwrap().into_raw(),
            banner: CString::new("").unwrap().into_raw(),
            version: CString::new("").unwrap().into_raw(),
        }
    };

    Box::into_raw(Box::new(res))
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_scan_result(ptr: *mut RustScanResult) {
    if ptr.is_null() { return; }
    let res = Box::from_raw(ptr);
    if !res.state.is_null() { let _ = CString::from_raw(res.state); }
    if !res.service.is_null() { let _ = CString::from_raw(res.service); }
    if !res.banner.is_null() { let _ = CString::from_raw(res.banner); }
    if !res.version.is_null() { let _ = CString::from_raw(res.version); }
}
