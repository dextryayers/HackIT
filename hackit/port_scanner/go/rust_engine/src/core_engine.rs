use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::ptr;

use crate::fast_scanner::{RustScanResult, FINGERPRINTS, RUNTIME};

#[repr(C)]
pub struct RustMassScanReport {
    pub results: *mut RustScanResult,
    pub count: usize,
    pub total_scanned: usize,
}

struct SafeScanResult {
    port: i32,
    state: String,
    service: String,
    banner: String,
    version: String,
}

#[no_mangle]
pub unsafe extern "C" fn rust_ultimate_mass_scan(
    host: *const c_char,
    ports_ptr: *const c_int,
    ports_count: usize,
    threads: usize,
    timeout_ms: u64,
    stealth: bool
) -> *mut RustMassScanReport {
    let c_host = CStr::from_ptr(host).to_str().unwrap_or("");
    let ports: Vec<i32> = std::slice::from_raw_parts(ports_ptr, ports_count).to_vec();
    let host_str = Arc::new(c_host.to_string());
    let semaphore = Arc::new(Semaphore::new(threads));
    
    let (tx, mut rx) = tokio::sync::mpsc::channel(ports_count);

    RUNTIME.spawn(async move {
        let mut tasks = Vec::new();
        for port in ports {
            let host_clone = Arc::clone(&host_str);
            let sem_clone = Arc::clone(&semaphore);
            let tx_clone = tx.clone();
            
            let task = tokio::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                
                if stealth {
                    let delay = (port % 30) as u64;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }

                let addr = format!("{}:{}", host_clone, port);
                
                let scan_result = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
                    Ok(Ok(mut stream)) => {
                        let mut banner = String::new();
                        let mut buffer = [0u8; 1024];
                        
                        use tokio::io::{AsyncWriteExt, AsyncReadExt};
                        match port {
                            80 | 443 | 8080 => { let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await; },
                            21 | 22 => {}, 
                            _ => { let _ = stream.write_all(b"\r\n\r\n").await; }
                        }

                        if let Ok(Ok(n)) = timeout(Duration::from_millis(800), stream.read(&mut buffer)).await {
                            if n > 0 {
                                banner = String::from_utf8_lossy(&buffer[..n]).to_string();
                            }
                        }

                        let mut service = "UNKNOWN".to_string();
                        let mut version = String::new();

                        if !banner.is_empty() {
                            use regex::Regex;
                            let fingerprints: &Vec<(Regex, &'static str)> = &FINGERPRINTS;
                            for (regex, name) in fingerprints.iter() {
                                if let Some(captures) = regex.captures(&banner) {
                                    service = name.to_string();
                                    if captures.len() > 1 {
                                        version = captures.get(1).map_or("", |m| m.as_str()).trim().to_string();
                                    }
                                    break;
                                }
                            }
                        }

                        if service == "UNKNOWN" {
                            service = match port {
                                21 => "FTP", 22 => "SSH", 23 => "TELNET", 25 => "SMTP", 53 => "DNS",
                                80 => "HTTP", 110 => "POP3", 143 => "IMAP", 443 => "HTTP",
                                3306 => "MYSQL", 5432 => "POSTGRESQL", 6379 => "REDIS",
                                _ => "UNKNOWN"
                            }.to_string();
                        }

                        Some(SafeScanResult {
                            port,
                            state: "open".to_string(),
                            service,
                            banner,
                            version,
                        })
                    }
                    _ => None,
                };

                let _ = tx_clone.send(scan_result).await;
            });
            tasks.push(task);
        }
        for task in tasks {
            let _ = task.await;
        }
    });

    let mut found_results = Vec::new();
    let mut processed = 0;
    
    while processed < ports_count {
        if let Some(res_opt) = rx.blocking_recv() {
            if let Some(res) = res_opt {
                found_results.push(RustScanResult {
                    port: res.port,
                    state: CString::new(res.state).unwrap().into_raw(),
                    service: CString::new(res.service).unwrap().into_raw(),
                    banner: CString::new(res.banner).unwrap().into_raw(),
                    version: CString::new(res.version).unwrap().into_raw(),
                });
            }
        }
        processed += 1;
    }

    let count = found_results.len();
    let results_ptr = if count > 0 {
        let mut v = found_results.into_boxed_slice();
        let p = v.as_mut_ptr();
        std::mem::forget(v);
        p
    } else {
        ptr::null_mut()
    };

    Box::into_raw(Box::new(RustMassScanReport {
        results: results_ptr,
        count,
        total_scanned: ports_count,
    }))
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_mass_scan_report(ptr: *mut RustMassScanReport) {
    if ptr.is_null() { return; }
    let report = Box::from_raw(ptr);
    if !report.results.is_null() {
        let results = std::slice::from_raw_parts_mut(report.results, report.count);
        for res in results {
            if !res.state.is_null() { let _ = CString::from_raw(res.state); }
            if !res.service.is_null() { let _ = CString::from_raw(res.service); }
            if !res.banner.is_null() { let _ = CString::from_raw(res.banner); }
            if !res.version.is_null() { let _ = CString::from_raw(res.version); }
        }
        let _ = Box::from_raw(report.results);
    }
}
