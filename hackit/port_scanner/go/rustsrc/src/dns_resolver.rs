use lazy_static::lazy_static;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const DNS_PORT: u16 = 53;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_TTL: Duration = Duration::from_secs(300);

lazy_static! {
    static ref DNS_CACHE: RwLock<HashMap<String, (Vec<IpAddr>, Instant)>> = RwLock::new(HashMap::new());
}

fn get_nameservers() -> Vec<String> {
    let mut servers = Vec::new();
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(ns) = line.strip_prefix("nameserver ") {
                let addr = ns.trim().to_string();
                if !servers.contains(&addr) {
                    servers.push(addr);
                }
            }
        }
    }
    if servers.is_empty() {
        servers.push("8.8.8.8".to_string());
        servers.push("1.1.1.1".to_string());
    }
    servers
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut raw = Vec::new();
    for label in name.split('.') {
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
    }
    raw.push(0);
    raw
}

fn build_query(host: &str, qtype: u16) -> Vec<u8> {
    let name = encode_name(host);
    let mut msg = Vec::with_capacity(12 + name.len() + 4);
    msg.extend(&[0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    msg.extend(&name);
    msg.extend(&qtype.to_be_bytes());
    msg.extend(&[0x00, 0x01]);
    msg
}

fn parse_ipv4(data: &[u8], off: usize) -> Option<IpAddr> {
    if off + 4 > data.len() {
        return None;
    }
    Some(IpAddr::V4(Ipv4Addr::new(data[off], data[off + 1], data[off + 2], data[off + 3])))
}

fn parse_ipv6(data: &[u8], off: usize) -> Option<IpAddr> {
    if off + 16 > data.len() {
        return None;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[off..off + 16]);
    Some(IpAddr::V6(Ipv6Addr::from(buf)))
}

fn parse_response(data: &[u8]) -> Vec<IpAddr> {
    if data.len() < 12 {
        return vec![];
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return vec![];
    }
    let mut off = 12usize;
    while off < data.len() {
        let b = data[off];
        if b == 0 {
            off += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            off += 2;
            break;
        }
        off += 1 + b as usize;
    }
    off += 4;
    let mut ips = Vec::new();
    for _ in 0..ancount {
        if off >= data.len() {
            break;
        }
        if data[off] & 0xC0 == 0xC0 {
            off += 2;
        } else {
            while off < data.len() && data[off] != 0 {
                off += 1 + data[off] as usize;
            }
            off += 1;
        }
        if off + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        if off + 2 > data.len() {
            break;
        }
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + rdlen > data.len() {
            break;
        }
        match rtype {
            1 => {
                if let Some(ip) = parse_ipv4(data, off) {
                    ips.push(ip);
                }
            }
            28 => {
                if let Some(ip) = parse_ipv6(data, off) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
        off += rdlen;
    }
    ips
}

fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut s = String::new();
            for &b in o.iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0F, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

fn decode_name(data: &[u8], mut off: usize, end: usize) -> (String, usize) {
    let mut name = String::new();
    loop {
        if off >= end {
            break;
        }
        let b = data[off];
        if b == 0 {
            off += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            if off + 1 >= end {
                break;
            }
            let ptr = (((b & 0x3F) as usize) << 8) | data[off + 1] as usize;
            if ptr < end {
                let (rest, _) = decode_name(data, ptr, end);
                if !name.is_empty() && !rest.is_empty() {
                    name.push('.');
                }
                name.push_str(&rest);
            }
            off += 2;
            break;
        }
        let label_len = b as usize;
        if off + 1 + label_len > end {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[off + 1..off + 1 + label_len]));
        off += 1 + label_len;
    }
    (name, off)
}

fn parse_ptr(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 {
        return None;
    }
    let mut off = 12usize;
    while off < data.len() {
        let b = data[off];
        if b == 0 {
            off += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            off += 2;
            break;
        }
        off += 1 + b as usize;
    }
    off += 4;
    for _ in 0..ancount {
        if off >= data.len() {
            return None;
        }
        if data[off] & 0xC0 == 0xC0 {
            off += 2;
        } else {
            while off < data.len() && data[off] != 0 {
                off += 1 + data[off] as usize;
            }
            off += 1;
        }
        if off + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 8;
        if off + 2 > data.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;
        if off + rdlen > data.len() {
            return None;
        }
        if rtype == 12 {
            let (name, _) = decode_name(data, off, off + rdlen);
            return Some(name);
        }
        off += rdlen;
    }
    None
}

pub async fn resolve_host(host: &str) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    {
        let cache = DNS_CACHE.read().unwrap();
        if let Some((ips, expiry)) = cache.get(host) {
            if expiry.elapsed() < CACHE_TTL {
                return ips.clone();
            }
        }
    }
    let servers = get_nameservers();
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap_or_else(|_| panic!("dns bind failed"));
    let q_a = build_query(host, 1);
    let q_aaaa = build_query(host, 28);
    let mut all_ips = Vec::new();
    for server in &servers {
        let addr = format!("{}:{}", server, DNS_PORT);
        let _ = sock.send_to(&q_a, &addr).await;
        let _ = sock.send_to(&q_aaaa, &addr).await;
        let mut buf = [0u8; 1500];
        let deadline = Instant::now() + DNS_TIMEOUT;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    for ip in parse_response(&buf[..n]) {
                        if !all_ips.contains(&ip) {
                            all_ips.push(ip);
                        }
                    }
                }
                _ => break,
            }
        }
        if !all_ips.is_empty() {
            break;
        }
    }
    if !all_ips.is_empty() {
        let mut cache = DNS_CACHE.write().unwrap();
        cache.insert(host.to_string(), (all_ips.clone(), Instant::now()));
    }
    all_ips
}

pub async fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let servers = get_nameservers();
    let q = build_query(&ptr_name(ip), 12);
    let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap_or_else(|_| panic!("dns bind failed"));
    for server in &servers {
        let addr = format!("{}:{}", server, DNS_PORT);
        let _ = sock.send_to(&q, &addr).await;
        let mut buf = [0u8; 1500];
        match timeout(DNS_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Some(name) = parse_ptr(&buf[..n]) {
                    return Some(name);
                }
            }
            _ => {}
        }
    }
    None
}
