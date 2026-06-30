use rayon::prelude::*;
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

lazy_static::lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (String, Instant)>> = RwLock::new(HashMap::new());
}

const MIN_PORT: u16 = 1;
const MAX_PORT: u16 = 65535;

#[derive(Debug)]
struct TCPProbe {
    ttl: i32,
    window: u16,
    mss: u16,
    wscale: u8,
    df: bool,
    timestamps: bool,
    sack: bool,
    port: u16,
    connected: bool,
}

#[derive(Debug)]
struct OSFingerprint {
    os_name: String,
    os_version: String,
    confidence: f64,
    ttl: i32,
    window: u16,
    mss: u16,
    wscale: u8,
    df: bool,
    timestamps: bool,
    sack: bool,
    signature: String,
}

fn resolve_ip(host: &str) -> Option<std::net::IpAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip);
    }
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ip_str, expiry)) = cache.get(host) {
            if expiry.elapsed() < DNS_CACHE_TTL {
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    let addr = format!("{}:0", host);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(a) = addrs.find(|a| a.is_ipv4()) {
            let ip = a.ip();
            let mut cache = DNS_CACHE.write().unwrap();
            cache.insert(host.to_string(), (ip.to_string(), Instant::now()));
            return Some(ip);
        }
    }
    None
}

fn read_tcp_info(fd: std::os::unix::io::RawFd) -> (u16, u8, bool, bool, u16, bool) {
    let mut mss: u16 = 0;
    let mut wscale: u8 = 0;
    let mut timestamps = false;
    let mut sack = false;
    let mut window: u16 = 0;
    let mut df = true;

    unsafe {
        // TCP_MAXSEG for reliable MSS
        let mut mss_val: libc::c_int = 0;
        let mut mss_len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG,
            &mut mss_val as *mut _ as *mut libc::c_void, &mut mss_len,
        ) == 0 && mss_val > 0 {
            mss = mss_val as u16;
        }

        // TCP_INFO for wscale, timestamps, sack, window
        let mut info: libc::tcp_info = std::mem::zeroed();
        let mut info_len: libc::socklen_t = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        if libc::getsockopt(
            fd, libc::IPPROTO_TCP, libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void, &mut info_len,
        ) == 0 {
            if mss == 0 {
                let smss = info.tcpi_snd_mss;
                if smss > 0 { mss = smss as u16; }
            }
            wscale = info.tcpi_snd_wscale as u8;
            timestamps = (info.tcpi_options & libc::TCPI_OPT_TIMESTAMPS) != 0;
            sack = (info.tcpi_options & libc::TCPI_OPT_SACK) != 0;
            let rwnd = info.tcpi_rcv_space;
            if rwnd > 0 && rwnd < 655360 { window = rwnd as u16; }
        }
    }

    (mss, wscale, timestamps, sack, window, df)
}

fn probe_port(host: &str, port: u16, timeout_ms: u64) -> Option<TCPProbe> {
    let addr = format!("{}:{}", host, port);
    let sock = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_millis(timeout_ms),
    );
    let sock = match sock {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms / 2)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(timeout_ms / 2)));
    let _ = sock.set_nonblocking(false);

    // Read real TCP/IP stack params from socket
    let fd = sock.as_raw_fd();
    let (mss, wscale, timestamps, sack, window, df) = read_tcp_info(fd);

    // Get actual TTL from ICMP ping
    let ttl = get_ping_ttl(host);

    // Banner grab — send protocol-appropriate probe
    let mut buf = [0u8; 4096];
    let n = {
        let probe = match port {
            80 | 8080 | 8000 | 8888 => b"GET / HTTP/1.0\r\nHost: hackit\r\n\r\n" as &[u8],
            21 => b"SYST\r\n",
            25 | 587 => b"EHLO hackit\r\n",
            110 => b"CAPA\r\n",
            143 => b"A1 CAPABILITY\r\n",
            443 | 8443 => b"",
            3306 => b"",
            5432 => b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            6379 => b"PING\r\n",
            873 => b"@RSYNCD: 31.0\n",
            5900 => b"RFB 003.008\n",
            11211 => b"stats\r\n",
            27017 => b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10\x69\x73\x6d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00",
            _ => b"\r\n",
        };
        if !probe.is_empty() {
            let _ = (&sock).write(probe);
        }
        let _ = (&sock).read(&mut buf).ok().unwrap_or(0)
    };

    drop(sock);
    Some(TCPProbe {
        ttl,
        window: if window > 0 { window } else { 65535 },
        mss: if mss > 0 { mss } else { 1460 },
        wscale,
        df,
        timestamps,
        sack,
        port,
        connected: n > 0,
    })
}

fn get_ping_ttl(host: &str) -> i32 {
    if let Ok(out) = Command::new("ping")
        .args(&["-c", "1", "-W", "2", host])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if line.contains("ttl=") {
                if let Some(pos) = line.find("ttl=") {
                    let rest = &line[pos + 4..];
                    let ttl_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(ttl) = ttl_str.parse::<i32>() {
                        return ttl;
                    }
                }
            }
        }
    }
    0
}

fn classify_os(probes: &[TCPProbe]) -> OSFingerprint {
    let valid: Vec<&TCPProbe> = probes.iter().filter(|p| p.connected).collect();
    let mut fp = OSFingerprint {
        os_name: "Unknown".to_string(),
        os_version: "".to_string(),
        confidence: 0.0,
        ttl: 64,
        window: 65535,
        mss: 1460,
        wscale: 7,
        df: true,
        timestamps: true,
        sack: true,
        signature: String::new(),
    };
    if valid.is_empty() { return fp; }
    let avg_ttl: i32 = valid.iter().map(|p| p.ttl).sum::<i32>() / valid.len() as i32;
    let avg_win: u16 = valid.iter().map(|p| p.window).sum::<u16>() / valid.len() as u16;
    let avg_mss: u16 = if valid.iter().any(|p| p.mss > 0) {
        let mss_vals: Vec<u16> = valid.iter().filter(|p| p.mss > 0).map(|p| p.mss).collect();
        mss_vals.iter().sum::<u16>() / mss_vals.len() as u16
    } else { 0 };
    let avg_wscale: u8 = if valid.iter().any(|p| p.wscale > 0) {
        let ws_vals: Vec<u8> = valid.iter().filter(|p| p.wscale > 0).map(|p| p.wscale).collect();
        ws_vals.iter().sum::<u8>() / ws_vals.len() as u8
    } else { 0 };
    let df_all = valid.iter().all(|p| p.df);
    let ts_all = valid.iter().all(|p| p.timestamps);
    let sack_all = valid.iter().all(|p| p.sack);
    fp.ttl = avg_ttl;
    fp.window = avg_win;
    fp.mss = avg_mss;
    fp.wscale = avg_wscale;
    fp.df = df_all;
    fp.timestamps = ts_all;
    fp.sack = sack_all;
    fp.signature = format!("T={} W={} M={} WS={} DF={} TS={} SACK={}",
        avg_ttl, avg_win, avg_mss, avg_wscale, df_all as i32, ts_all as i32, sack_all as i32);
    if avg_ttl <= 64 {
        if avg_win == 5840 || avg_win == 29200 {
            fp.os_name = "Linux".into(); fp.os_version = "2.6.x - 5.x".into(); fp.confidence = 85.0;
        } else if avg_win == 65535 && avg_mss == 1460 {
            fp.os_name = "Linux".into(); fp.os_version = "Modern (5.x+ / 6.x)".into(); fp.confidence = 90.0;
        } else if avg_win == 65535 && avg_mss == 1440 {
            fp.os_name = "FreeBSD / macOS".into(); fp.os_version = "Modern".into(); fp.confidence = 80.0;
        } else if avg_win == 16384 || avg_win == 14600 {
            fp.os_name = "Linux".into(); fp.os_version = "Embedded / Android".into(); fp.confidence = 75.0;
        } else if avg_win == 65535 && avg_mss == 1360 {
            fp.os_name = "macOS".into(); fp.os_version = "Ventura+".into(); fp.confidence = 85.0;
        } else if avg_win == 65535 && avg_mss == 1380 {
            fp.os_name = "iOS / iPadOS".into(); fp.os_version = "Modern".into(); fp.confidence = 80.0;
        } else {
            fp.os_name = "Unix-like".into(); fp.os_version = "Generic".into(); fp.confidence = 50.0;
        }
    } else if avg_ttl <= 128 {
        if avg_win == 8192 || avg_win == 64240 {
            if avg_mss == 1460 { fp.os_name = "Windows".into(); fp.os_version = "10/11 / Server 2016+".into(); fp.confidence = 95.0; }
            else { fp.os_name = "Windows".into(); fp.os_version = "Modern".into(); fp.confidence = 85.0; }
        } else if avg_win == 65535 {
            fp.os_name = "Windows".into(); fp.os_version = "XP/2003 (Legacy)".into(); fp.confidence = 80.0;
        } else if avg_win == 16384 {
            fp.os_name = "Windows".into(); fp.os_version = "Vista/2008".into(); fp.confidence = 85.0;
        } else if avg_win == 65535 && avg_mss == 1380 {
            fp.os_name = "Windows".into(); fp.os_version = "11 / Server 2022".into(); fp.confidence = 90.0;
        } else {
            fp.os_name = "Windows".into(); fp.os_version = "Generic".into(); fp.confidence = 60.0;
        }
    } else if avg_ttl <= 255 {
        if avg_win == 4128 || avg_win == 512 {
            fp.os_name = "Cisco IOS".into(); fp.os_version = "Generic".into(); fp.confidence = 85.0;
        } else if avg_mss == 1500 || avg_mss == 1460 {
            fp.os_name = "Network Device".into(); fp.os_version = "Generic Router/Switch".into(); fp.confidence = 65.0;
        } else if avg_wscale == 0 && avg_mss == 536 {
            fp.os_name = "Legacy / Embedded".into(); fp.os_version = "Minimal TCP stack".into(); fp.confidence = 70.0;
        } else {
            fp.os_name = "Infrastructure".into(); fp.os_version = "Solaris / HP-UX / AIX".into(); fp.confidence = 55.0;
        }
    }
    if avg_ttl == 64 || avg_ttl == 128 || avg_ttl == 255 {
        fp.confidence = (fp.confidence + 5.0).min(100.0);
    }
    fp
}

#[inline]
fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::with_capacity(1024);
    match input.trim().to_lowercase().as_str() {
        "all" => return (MIN_PORT..=MAX_PORT).collect(),
        "auto" | "top100" => {
            return vec![22,80,443,21,25,3389,110,445,139,143,53,135,3306,8080,587,993,995,465,23,8443,8000,8888,3000,9200,6379,27017,5432,2375,11211,1433,1521,5672,9090,6443,10250,2379,5985,2376,5900,4369,50000,9042,28015,7001,8500,8200];
        }
        _ => {}
    }
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let s: u16 = start.parse().unwrap_or(MIN_PORT);
            let e: u16 = end.parse().unwrap_or(MAX_PORT);
            for p in s..=e { ports.push(p); }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort(); ports.dedup(); ports
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host> [ports] [timeout_ms]", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} scanme.nmap.org 22,80,443 2000", args[0]);
        eprintln!("  {} 192.168.1.1 auto", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let port_spec = if args.len() > 2 { &args[2] } else { "22,80,443" };
    let timeout_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1500);
    let ports = parse_ports(port_spec);
    if ports.is_empty() {
        eprintln!("No valid ports");
        std::process::exit(1);
    }
    let ip = match resolve_ip(host) {
        Some(ip) => ip,
        None => { eprintln!("Failed to resolve host"); std::process::exit(1); }
    };
    eprintln!("OS_DETECT target={} ip={} ports={} timeout={}ms", host, ip, ports.len(), timeout_ms);
    let mut probes = Vec::with_capacity(8);
    let probe_ports: Vec<u16> = ports.iter().take(8).copied().collect();
    let probe_results: Vec<Option<TCPProbe>> = probe_ports.par_iter()
        .map(|&port| probe_port(host, port, timeout_ms))
        .collect();
    for probe in probe_results.into_iter().flatten() {
        probes.push(probe);
    }
    let fp = classify_os(&probes);
    println!("RESULT:{{\"os_name\":\"{}\",\"os_version\":\"{}\",\"confidence\":{:.0},\"ttl\":{},\"window\":{},\"mss\":{},\"wscale\":{},\"df\":{},\"timestamps\":{},\"sack\":{},\"signature\":\"{}\"}}",
        fp.os_name, fp.os_version, fp.confidence,
        fp.ttl, fp.window, fp.mss, fp.wscale,
        fp.df, fp.timestamps, fp.sack, fp.signature);
}
