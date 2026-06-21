use rayon::prelude::*;
use serde::Serialize;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DEFAULT_DNS_SERVER: &str = "8.8.8.8";

#[derive(Debug, Clone, Serialize)]
struct DNSRecord {
    record_type: String,
    name: String,
    value: String,
    ttl: u32,
    priority: Option<u16>,
}

#[derive(Debug, Serialize)]
struct DNSInfo {
    nxdomain: bool,
    authoritative: bool,
    dnssec: bool,
    axfr_available: bool,
    recursion_available: bool,
    server: String,
}

#[derive(Debug, Serialize)]
struct DNSEnumResult {
    target: String,
    records: Vec<DNSRecord>,
    info: DNSInfo,
    total_records: usize,
    elapsed_ms: u64,
}

#[inline(always)]
fn build_dns_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(512);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes());
    for part in name.split('.') {
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt
}

fn parse_dns_response(data: &[u8]) -> (bool, bool, bool, bool, Vec<(String, String, u32, Option<u16>)>) {
    if data.len() < 12 { return (false, false, false, false, vec![]); }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    let aa = (flags & 0x0400) != 0;
    let rd = (flags & 0x0100) != 0;
    let nxdomain = rcode == 3;
    let dnssec = data.len() > 12 && data[12..].windows(4).any(|w| w == b"\x00\x29\x05\x00");
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);
    let mut results = Vec::new();
    let mut offset = 12usize;
    while offset < data.len() && data[offset] != 0 {
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2;
            break;
        }
        offset += 1 + data[offset] as usize;
    }
    offset += 5;
    let total_records = ancount + nscount + arcount;
    for _ in 0..total_records {
        if offset + 10 > data.len() { break; }
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2;
        } else {
            while offset < data.len() && data[offset] != 0 {
                if data[offset] & 0xC0 == 0xC0 { offset += 2; break; }
                offset += 1 + data[offset] as usize;
            }
            offset += 1;
        }
        if offset + 10 > data.len() { break; }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ttl = u32::from_be_bytes([data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]]);
        let rdlength = u16::from_be_bytes([data[offset + 6], data[offset + 7]]) as usize;
        offset += 8;
        if offset + rdlength > data.len() { break; }
        let type_name = match qtype {
            1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR",
            15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 41 => "OPT",
            65 => "HTTPS", 99 => "SPF", 108 => "RP", 241 => "IXFR",
            252 => "AXFR", 257 => "CAA", 32768 => "ID", _ => "OTHER",
        };
        let value = match qtype {
            1 => {
                if rdlength == 4 {
                    format!("{}.{}.{}.{}", data[offset], data[offset + 1], data[offset + 2], data[offset + 3])
                } else { data[offset..offset + rdlength].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().concat() }
            }
            28 => {
                if rdlength == 16 {
                    let parts: Vec<String> = (0..8).map(|i| {
                        format!("{:02x}{:02x}", data[offset + i * 2], data[offset + i * 2 + 1])
                    }).collect();
                    parts.join(":")
                } else { data[offset..offset + rdlength].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().concat() }
            }
            2 | 5 | 12 => {
                let mut name_strings: Vec<String> = Vec::new();
                let mut p = offset;
                let mut jumped = false;
                let mut jump_offset = 0;
                while p < data.len() {
                    if data[p] == 0 { if !jumped { p += 1; } break; }
                    if data[p] & 0xC0 == 0xC0 {
                        if !jumped {
                            jump_offset = p + 2;
                            jumped = true;
                        }
                        p = ((data[p] & 0x3F) as usize) << 8 | data[p + 1] as usize;
                        continue;
                    }
                    let len = data[p] as usize;
                    if p + 1 + len > data.len() { break; }
                    if !name_strings.is_empty() { name_strings.push(".".to_string()); }
                    name_strings.push(String::from_utf8_lossy(&data[p + 1..p + 1 + len]).to_string());
                    p += 1 + len;
                }
                let name = name_strings.concat();
                name
            }
            15 => {
                let priority = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let mut name_strings: Vec<String> = Vec::new();
                let mut p = offset + 2;
                while p < offset + rdlength {
                    if data[p] & 0xC0 == 0xC0 {
                        let target_p = ((data[p] & 0x3F) as usize) << 8 | data[p + 1] as usize;
                        let _ = target_p;
                        break;
                    }
                    if data[p] == 0 { break; }
                    let len = data[p] as usize;
                    if p + 1 + len > offset + rdlength { break; }
                    if !name_strings.is_empty() { name_strings.push(".".to_string()); }
                    name_strings.push(String::from_utf8_lossy(&data[p + 1..p + 1 + len]).to_string());
                    p += 1 + len;
                }
                let exchange = name_strings.concat();
                format!("{} {}", priority, exchange)
            }
            16 | 99 => {
                let txt = String::from_utf8_lossy(&data[offset..offset + rdlength]);
                txt.trim_matches('"').to_string()
            }
            6 => {
                let mut p = offset;
                let mut parts = Vec::new();
                for _ in 0..2 {
                    let mut name_strs: Vec<String> = Vec::new();
                    while p < offset + rdlength {
                        if data[p] == 0 { p += 1; break; }
                        if data[p] & 0xC0 == 0xC0 { p += 2; break; }
                        let len = data[p] as usize;
                        if p + 1 + len > offset + rdlength { break; }
                        if !name_strs.is_empty() { name_strs.push(".".to_string()); }
                        name_strs.push(String::from_utf8_lossy(&data[p + 1..p + 1 + len]).to_string());
                        p += 1 + len;
                    }
                    parts.push(name_strs.concat());
                }
                if p + 20 <= offset + rdlength {
                    let serial = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
                    let refresh = u32::from_be_bytes([data[p + 4], data[p + 5], data[p + 6], data[p + 7]]);
                    let retry = u32::from_be_bytes([data[p + 8], data[p + 9], data[p + 10], data[p + 11]]);
                    let expire = u32::from_be_bytes([data[p + 12], data[p + 13], data[p + 14], data[p + 15]]);
                    let _minimum = u32::from_be_bytes([data[p + 16], data[p + 17], data[p + 18], data[p + 19]]);
                    format!("{} {} {} {} {} {}",
                        parts.get(0).unwrap_or(&String::new()),
                        parts.get(1).unwrap_or(&String::new()),
                        serial, refresh, retry, expire)
                } else { String::new() }
            }
            _ => {
                if rdlength <= 256 {
                    String::from_utf8_lossy(&data[offset..offset + rdlength]).to_string()
                    } else { data[offset..offset + rdlength].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("") }
            }
        };
        let priority = if qtype == 15 {
            Some(u16::from_be_bytes([data[offset - 8], data[offset - 7]]))
        } else { None };
        results.push((type_name.to_string(), value, ttl, priority));
        offset += rdlength;
    }
    (nxdomain, aa, dnssec, rd, results)
}

#[inline]
fn dns_query(target: &str, server: &str, qtype: u16, timeout_ms: u64) -> Vec<DNSRecord> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let id = rand::random::<u16>();
    let query = build_dns_query(target, qtype, id);
    let addr = format!("{}:53", server);
    if sock.send_to(&query, &addr).is_err() { return vec![]; }
    let mut buf = [0u8; 4096];
    if sock.recv_from(&mut buf).is_err() { return vec![]; }
    let (_, _, _, _, records) = parse_dns_response(&buf);
    let type_name = match qtype {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR",
        15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", 99 => "SPF",
        108 => "RP", 257 => "CAA", _ => "OTHER",
    };
    records.into_iter().map(|(_, val, ttl, prio)| DNSRecord {
        record_type: type_name.to_string(),
        name: target.to_string(),
        value: val,
        ttl,
        priority: prio,
    }).collect()
}

fn reverse_dns(ip: &str, server: &str, timeout_ms: u64) -> Vec<DNSRecord> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 { return vec![]; }
    let ptr_name = format!("{}.{}.{}.{}.in-addr.arpa", parts[3], parts[2], parts[1], parts[0]);
    dns_query(&ptr_name, server, 12, timeout_ms)
}

fn try_axfr(target: &str, server: &str, timeout_ms: u64) -> Vec<DNSRecord> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let id = rand::random::<u16>();
    let query = build_dns_query(target, 252, id);
    let addr = format!("{}:53", server);
    if sock.send_to(&query, &addr).is_err() { return vec![]; }
    let mut buf = [0u8; 16384];
    if sock.recv_from(&mut buf).is_err() { return vec![]; }
    let (_, _, _, _, records) = parse_dns_response(&buf);
    records.into_iter().map(|(_rt, val, ttl, prio)| DNSRecord {
        record_type: "AXFR".to_string(),
        name: target.to_string(),
        value: val,
        ttl,
        priority: prio,
    }).collect()
}

fn get_server_info(target: &str, server: &str, timeout_ms: u64) -> (bool, bool, bool, bool) {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return (false, false, false, false),
    };
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let query = build_dns_query(target, 1, 0xAAAA);
    let addr = format!("{}:53", server);
    if sock.send_to(&query, &addr).is_err() { return (false, false, false, false); }
    let mut buf = [0u8; 4096];
    if sock.recv_from(&mut buf).is_err() { return (false, false, false, false); }
    let (nxdomain, aa, dnssec, rd, _) = parse_dns_response(&buf);
    (nxdomain, aa, dnssec, rd)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut target = String::new();
    let mut server = DEFAULT_DNS_SERVER.to_string();
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => { i += 1; if i < args.len() { target = args[i].clone(); } }
            "--server" | "-s" => { i += 1; if i < args.len() { server = args[i].clone(); } }
            "--timeout" => { i += 1; if i < args.len() { timeout_ms = args[i].parse().unwrap_or(DEFAULT_TIMEOUT_MS); } }
            "--help" | "-h" => {
                eprintln!("Usage: {} --target <domain> [--server <dns>] [--timeout <ms>]", args[0]);
                eprintln!("  Enumerates: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA, SPF");
                eprintln!("  Attempts zone transfer (AXFR)");
                eprintln!("  Default server: 8.8.8.8");
                std::process::exit(0);
            }
            _ => {
                if target.is_empty() { target = args[i].clone(); }
                else if server == DEFAULT_DNS_SERVER { server = args[i].clone(); }
            }
        }
        i += 1;
    }
    if target.is_empty() {
        eprintln!("Usage: {} <domain> [dns_server]", args[0]);
        eprintln!("  Enumerates: A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, SPF, PTR, AXFR");
        std::process::exit(1);
    }
    eprintln!("DNS_ENUM target={} server={} timeout={}ms", target, server, timeout_ms);
    let start = Instant::now();
    let qtypes: Vec<(u16, &str)> = vec![
        (1, "A"), (28, "AAAA"), (15, "MX"), (2, "NS"), (16, "TXT"),
        (6, "SOA"), (5, "CNAME"), (33, "SRV"), (257, "CAA"), (99, "SPF"),
        (108, "RP"),
    ];
    let qtotal = qtypes.len();
    let mut all_records: Vec<DNSRecord> = Vec::with_capacity(qtotal * 10);
    let query_results: Vec<Vec<DNSRecord>> = qtypes.par_iter()
        .map(|&(qtype, type_name)| {
            eprintln!("STATUS:{{\"progress\":{:.1},\"message\":\"Querying {} records for {}\"}}",
                (0.0), type_name, target);
            let records = dns_query(&target, &server, qtype, timeout_ms);
            records
        })
        .collect();
    for (idx, records) in query_results.iter().enumerate() {
        let _pct = idx as f64 / qtotal as f64 * 100.0;
        for r in records {
            println!("RESULT:{}", serde_json::to_string(r).unwrap());
        }
        all_records.extend(records.iter().cloned());
    }
    eprintln!("STATUS:{{\"progress\":50.0,\"message\":\"Performing reverse PTR lookup\"}}");
    let a_ips: Vec<String> = all_records.iter().filter(|r| r.record_type == "A").map(|r| r.value.clone()).collect();
    for ip in a_ips {
        let ptr_records = reverse_dns(&ip, &server, timeout_ms);
        for r in &ptr_records {
            println!("RESULT:{}", serde_json::to_string(r).unwrap());
            all_records.push(DNSRecord {
                record_type: "PTR".to_string(),
                name: format!("{}.in-addr.arpa", ip),
                value: r.value.clone(),
                ttl: r.ttl,
                priority: None,
            });
        }
    }
    eprintln!("STATUS:{{\"progress\":75.0,\"message\":\"Attempting zone transfer (AXFR)\"}}");
    let axfr_results = try_axfr(&target, &server, timeout_ms);
    for r in &axfr_results {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }
    let axfr_available = !axfr_results.is_empty();
    all_records.extend(axfr_results);
    eprintln!("STATUS:{{\"progress\":90.0,\"message\":\"Gathering server information\"}}");
    let server_info = get_server_info(&target, &server, timeout_ms);
    let elapsed = start.elapsed().as_millis() as u64;
    let total_records = all_records.len();
    let info = DNSInfo {
        nxdomain: server_info.0,
        authoritative: server_info.1,
        dnssec: server_info.2,
        axfr_available,
        recursion_available: server_info.3,
        server: server.clone(),
    };
    let result = DNSEnumResult {
        target: target.clone(),
        records: all_records,
        info,
        total_records,
        elapsed_ms: elapsed,
    };
    println!("FINAL:{}", serde_json::to_string(&result).unwrap());
}
