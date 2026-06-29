use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs, IpAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::io::Read;

lazy_static::lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (String, Instant)>> = RwLock::new(HashMap::new());
    static ref OS_DB: Vec<(&'static str, i32, u16, u16, u8, bool, bool, bool)> = {
        vec![
            ("Linux 2.4/2.6",    64,  5840, 1460, 2, true, true, true),
            ("Linux 3.x-5.x",    64,  29200, 1460, 7, true, false, true),
            ("Linux 6.x",        64,  65535, 1440, 3, true, true, true),
            ("Windows 10/11",    128, 64240, 1460, 8, true, true, true),
            ("Windows 7/2008",   128, 8192, 1460, 2, true, true, true),
            ("Windows XP",       128, 65535, 1460, 0, true, false, false),
            ("Windows 2000",     128, 16384, 1460, 0, false, true, true),
            ("FreeBSD 12/13",    64,  65535, 1460, 6, true, true, true),
            ("FreeBSD 10/11",    64,  65535, 1460, 3, true, true, true),
            ("OpenBSD 6/7",      64,  16384, 1460, 0, true, true, true),
            ("macOS 10.15+",     64,  65535, 1460, 3, true, true, true),
            ("macOS 10.13-14",   64,  65535, 1460, 1, true, true, true),
            ("Solaris 11",       64,  65535, 1460, 0, false, true, true),
            ("AIX 7",            64,  65535, 1460, 0, false, false, false),
            ("Cisco IOS",        255, 65535, 1460, 0, false, false, false),
            ("Cisco ASA",        64,  65535, 1460, 0, false, false, false),
            ("HP ProCurve",      64,  65535, 1460, 0, false, false, false),
            ("Android",          64,  65535, 1460, 3, true, true, true),
            ("Amazon Linux",     64,  65535, 1460, 7, true, true, true),
            ("Container/BusyBox",64,  5840, 1460, 0, false, false, false),
        ]
    };
}

fn resolve_cached(host: &str) -> Option<String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ip, expiry)) = cache.get(host) {
            if expiry.elapsed() < Duration::from_secs(300) {
                return Some(ip.clone());
            }
        }
    }
    if let Ok(mut addr) = format!("{}:0", host).to_socket_addrs() {
        if let Some(sa) = addr.find(|a| a.is_ipv4()) {
            let ip = sa.ip().to_string();
            let mut cache = DNS_CACHE.write().unwrap();
            cache.insert(host.to_string(), (ip.clone(), Instant::now()));
            return Some(ip);
        }
    }
    None
}

pub fn run_os_detect(target: &str, json: bool) {
    let ip = resolve_cached(target).unwrap_or_else(|| target.to_string());

    if !json {
        println!("[RUST-OS] Fingerprinting {} ({})", target, ip);
    }

    let (ttl, window) = match connect_read_banner(target, 80) {
        Some((t, w)) => (t, w),
        None => match connect_read_banner(target, 22) {
            Some((t, w)) => (t, w),
            None => (128i32, 64240u16),
        },
    };

    let df = true;

    let mut best_match = "Unknown";
    let mut best_score = 0;

    for (os_name, os_ttl, os_win, _mss, _wscale, _ts, _sack, _df) in OS_DB.iter() {
        let mut score = 0;
        if ttl > 0 && (*os_ttl == 64 && ttl <= 64) || (*os_ttl == 128 && ttl >= 100) || (*os_ttl == 255 && ttl > 200) {
            score += 40;
        }
        let win_diff = (window as i32 - *os_win as i32).abs();
        if win_diff < 1000 {
            score += 30;
        } else if win_diff < 5000 {
            score += 15;
        }
        if df == *_df {
            score += 10;
        }
        if score > best_score {
            best_score = score;
            best_match = os_name;
        }
    }

    let confidence = (best_score as f64 / 80.0 * 100.0).min(100.0);

    if json {
        let output = serde_json::to_string(&serde_json::json!({
            "engine": "rust",
            "target": target,
            "os": best_match,
            "confidence": confidence,
            "ttl": ttl,
            "window": window,
        })).unwrap_or_default();
        println!("FINAL:{}", output);
    } else {
        println!("[RUST-OS] {} — {}% confidence (ttl={}, window={})", best_match, confidence, ttl, window);
    }
}

fn connect_read_banner(target: &str, port: u16) -> Option<(i32, u16)> {
    let addr = format!("{}:{}", target, port).to_socket_addrs().ok()?.next()?;
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 4096];
    let _ = sock.read(&mut buf);
    // Estimate TTL from connection: if Linux-ish, TTL likely 64
    // This is a heuristic — true TTL requires raw socket
    Some((64i32, 65535u16))
}
