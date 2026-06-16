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
        (Regex::new(r"(?i)220.*pure-ftpd").unwrap(), "FTP (Pure-FTPd)"),
        (Regex::new(r"(?i)ftp.*220[ \-]([a-z0-9._-]+)").unwrap(), "FTP"),
        (Regex::new(r"(?i)220.*proftpd").unwrap(), "FTP (ProFTPD)"),
        (Regex::new(r"(?i)220.*vsftpd").unwrap(), "FTP (vsFTPd)"),
        (Regex::new(r"(?i)server: nginx/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)server: apache/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)server: microsoft-iis/([0-9.]+)").unwrap(), "HTTP"),
        (Regex::new(r"(?i)server: litespeed").unwrap(), "HTTP (LiteSpeed)"),
        (Regex::new(r"(?i)server: cloudflare").unwrap(), "HTTP (Cloudflare)"),
        (Regex::new(r"(?i)server: caddy").unwrap(), "HTTP (Caddy)"),
        (Regex::new(r"(?i)server: openresty").unwrap(), "HTTP (OpenResty)"),
        (Regex::new(r"(?i)mysql[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MYSQL"),
        (Regex::new(r"(?i)mariadb[ \-]([0-9.-]+[a-z0-9.-]*)").unwrap(), "MYSQL"),
        (Regex::new(r"(?i)postgresql ([0-9.]+)").unwrap(), "POSTGRESQL"),
        (Regex::new(r"(?i)redis_version:([0-9.]+)").unwrap(), "REDIS"),
        (Regex::new(r"(?i)mongodb [v]?([0-9.]+)").unwrap(), "MONGODB"),
        (Regex::new(r"(?i)220.*(exim|postfix|sendmail|courier)").unwrap(), "SMTP"),
        (Regex::new(r"(?i)220.*(smtp|esmtp).*([0-9.]+)").unwrap(), "SMTP"),
        (Regex::new(r"(?i)exim\s+([0-9.]+)").unwrap(), "SMTP (Exim)"),
        (Regex::new(r"(?i)+ok.*dovecot").unwrap(), "POP3 (Dovecot)"),
        (Regex::new(r"(?i)+\s*ok.*dovecot").unwrap(), "IMAP (Dovecot)"),
        (Regex::new(r"(?i)http/1\.[01]").unwrap(), "HTTP"),
        (Regex::new(r"(?i)html").unwrap(), "HTTP"),
        (Regex::new(r"(?i)dovecot").unwrap(), "IMAP/POP3 (Dovecot)"),
        (Regex::new(r"(?i)cpanel").unwrap(), "cPanel"),
        (Regex::new(r"(?i)webmin").unwrap(), "Webmin"),
        (Regex::new(r"(?i)plesk").unwrap(), "Plesk"),
        (Regex::new(r"(?i)smb").unwrap(), "SMB"),
        (Regex::new(r"(?i)rfb ([\d.]+)").unwrap(), "VNC"),
        (Regex::new(r"(?i)sip/2\.0").unwrap(), "SIP"),
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

                // Adaptive timeout based on service type
                let read_timeout = match port {
                    80 | 8080 | 443 | 8443 | 2082 | 2083 => Duration::from_millis(1500),
                    21 | 22 | 25 | 587 | 465 | 110 | 143 | 993 | 995 => Duration::from_millis(2000),
                    3306 | 5432 | 6379 => Duration::from_millis(1000),
                    _ => Duration::from_millis(800),
                };

                match port {
                    80 | 8080 | 443 | 8443 | 2082 | 2083 => {
                        let _ = stream.write_all(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
                    },
                    21 => {
                        let _ = stream.write_all(b"SYST\r\n").await;
                    },
                    25 | 587 | 465 => { let _ = stream.write_all(b"EHLO hackit-recon\r\n").await; },
                    110 | 995 => { let _ = stream.write_all(b"CAPA\r\n").await; },
                    143 | 993 => { let _ = stream.write_all(b"A001 CAPABILITY\r\n").await; },
                    3389 => { 
                        let _ = stream.write_all(&[0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]).await;
                    },
                    1433 => {
                        let _ = stream.write_all(&[0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01, 0x55, 0x00, 0x00, 0x00]).await;
                    },
                    5900 => {
                        let _ = stream.write_all(b"RFB 003.008\n").await;
                    },
                    _ => {
                        let _ = stream.write_all(b"\r\n\r\n").await;
                    }
                }

                if let Ok(Ok(n)) = tokio_timeout(read_timeout, stream.read(&mut buffer)).await {
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

                if service == "UNKNOWN" {
                    service = match port {
                        21 => "FTP", 22 => "SSH", 23 => "TELNET", 25 => "SMTP", 53 => "DNS",
                        80 => "HTTP", 110 => "POP3", 111 => "RPCBIND", 143 => "IMAP",
                        161 => "SNMP", 389 => "LDAP",
                        443 => "HTTP", 445 => "MICROSOFT-DS", 465 => "SMTPS",
                        587 => "SMTP", 636 => "LDAPS",
                        993 => "IMAPS", 995 => "POP3S",
                        1433 => "MSSQL", 1521 => "ORACLE",
                        2082 => "cPanel", 2083 => "cPanel SSL",
                        3128 => "SQUID", 3306 => "MYSQL",
                        5432 => "POSTGRESQL", 5900 => "VNC",
                        6379 => "REDIS", 8080 => "HTTP", 8443 => "HTTPS",
                        9090 => "HTTP", 27017 => "MONGODB",
                        _ => "UNKNOWN"
                    }.to_string();
                }

                (true, "open".to_string(), service, banner, version)
            },
            Ok(Err(e)) => {
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("refused") {
                    (false, "closed".to_string(), "UNKNOWN".to_string(), String::new(), String::new())
                } else {
                    (false, "filtered".to_string(), "UNKNOWN".to_string(), "(no response)".to_string(), String::new())
                }
            },
            Err(_) => {
                (false, "filtered".to_string(), "UNKNOWN".to_string(), "(timeout)".to_string(), String::new())
            }
        }
    });

    let res = RustScanResult {
        port,
        state: CString::new(result.1).unwrap().into_raw(),
        service: CString::new(result.2).unwrap().into_raw(),
        banner: CString::new(result.3).unwrap().into_raw(),
        version: CString::new(result.4).unwrap().into_raw(),
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
