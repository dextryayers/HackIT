use serde::Serialize;
use std::net::UdpSocket;
use std::time::{Duration, Instant};
use std::env;

#[derive(Debug, Serialize)]
struct DNSResult {
    record_type: String,
    name: String,
    value: String,
    ttl: u32,
}

#[derive(Debug, Serialize)]
struct DNSDetect {
    target: String,
    server: String,
    results: Vec<DNSResult>,
    elapsed_ms: u64,
    nxdomain: bool,
    dnssec: bool,
    axfr_available: bool,
    recursion: bool,
}

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

fn parse_dns_response(data: &[u8]) -> (bool, bool, bool, Vec<(String, String, u32)>) {
    if data.len() < 12 { return (false, false, false, vec![]); }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000F;
    let aa = (flags & 0x0400) != 0;
    let nxdomain = rcode == 3;
    let dnssec = data.len() > 12 && data[12..].windows(4).any(|w| w == b"\x00\x29\x05\x00");
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let mut results = Vec::new();
    let mut offset = 12usize;
    while offset < data.len() && data[offset] != 0 { offset += 1 + data[offset] as usize; }
    offset += 5;
    for _ in 0..ancount {
        if offset + 10 > data.len() { break; }
        offset += 2;
        if offset + 8 > data.len() { break; }
        let qtype = u16::from_be_bytes([data[offset - 2], data[offset - 1]]);
        let ttl = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let rdlength = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
        offset += 6;
        if offset + rdlength > data.len() { break; }
        let type_name = match qtype {
            1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 15 => "MX",
            16 => "TXT", 28 => "AAAA", 33 => "SRV", 41 => "OPT", 65 => "HTTPS",
            99 => "SPF", 257 => "CAA", _ => "OTHER",
        }.to_string();
        let value = match qtype {
            1 | 28 if rdlength == 4 || rdlength == 16 => {
                (0..rdlength).map(|i| if qtype == 1 && i == 3 { format!("{}", data[offset + i]) } else { format!("{}", data[offset + i]) }).collect::<Vec<_>>().join(".")
            },
            _ => String::from_utf8_lossy(&data[offset..offset + rdlength]).to_string(),
        };
        results.push((type_name, value, ttl));
        offset += rdlength;
    }
    (nxdomain, aa, dnssec, results)
}

fn dns_query(target: &str, server: &str, qtype: u16, timeout_ms: u64) -> Vec<DNSResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let id = rand::random::<u16>();
    let query = build_dns_query(target, qtype, id);
    let addr = format!("{}:53", server);
    if sock.send_to(&query, &addr).is_err() { return vec![]; }
    let mut buf = [0u8; 4096];
    if sock.recv_from(&mut buf).is_err() { return vec![]; }
    let (_, _, _, records) = parse_dns_response(&buf);
    let type_name = match qtype {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 15 => "MX",
        16 => "TXT", 28 => "AAAA", 33 => "SRV", 99 => "SPF", 257 => "CAA", _ => "OTHER",
    };
    records.into_iter().map(|(_, val, ttl)| DNSResult {
        record_type: type_name.to_string(),
        name: target.to_string(),
        value: val,
        ttl,
    }).collect()
}

fn try_axfr(target: &str, server: &str, timeout_ms: u64) -> Vec<DNSResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok();
    let id = rand::random::<u16>();
    let query = build_dns_query(target, 252, id);
    let addr = format!("{}:53", server);
    if sock.send_to(&query, &addr).is_err() { return vec![]; }
    let mut buf = [0u8; 4096];
    if sock.recv_from(&mut buf).is_err() { return vec![]; }
    let (_, _, _, records) = parse_dns_response(&buf);
    let mut results = Vec::new();
    for (_, val, ttl) in records {
        results.push(DNSResult {
            record_type: "AXFR".to_string(),
            name: target.to_string(),
            value: val,
            ttl,
        });
    }
    results
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <target> [dns_server]", args[0]);
        eprintln!("  Detects: A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA, AXFR, DNSSEC");
        std::process::exit(1);
    }
    let target = &args[1];
    let server = args.get(2).cloned().unwrap_or_else(|| "8.8.8.8".to_string());
    let start = Instant::now();
    let mut all_results = Vec::new();
    let qtypes = [(1, "A"), (28, "AAAA"), (15, "MX"), (2, "NS"), (16, "TXT"), (6, "SOA"), (5, "CNAME"), (33, "SRV"), (257, "CAA"), (99, "SPF")];
    for &(qtype, _) in &qtypes {
        let res = dns_query(target, &server, qtype, 3000);
        let type_name = qtypes.iter().find(|&&(t, _)| t == qtype).map(|&(_, n)| n).unwrap_or("OTHER");
        for r in &res {
            let output = serde_json::json!({
                "type": "dns_record",
                "record_type": type_name,
                "name": &r.name,
                "value": &r.value,
                "ttl": r.ttl,
            });
            println!("RESULT:{}", output);
        }
        all_results.extend(res);
    }
    let axfr_results = try_axfr(target, &server, 5000);
    if !axfr_results.is_empty() {
        for r in &axfr_results {
            let output = serde_json::json!({
                "type": "dns_record",
                "record_type": "AXFR",
                "name": &r.name,
                "value": &r.value,
                "ttl": r.ttl,
            });
            println!("RESULT:{}", output);
        }
    }
    let last_result = {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(3000))).ok();
        let query = build_dns_query(target, 1, 0xAAAA);
        let addr = format!("{}:53", server);
        if sock.send_to(&query, &addr).is_ok() {
            let mut buf = [0u8; 4096];
            if sock.recv_from(&mut buf).is_ok() {
                let (nxdomain, aa, dnssec, _) = parse_dns_response(&buf);
                (nxdomain, aa, dnssec)
            } else { (false, false, false) }
        } else { (false, false, false) }
    };
    let elapsed = start.elapsed().as_millis() as u64;
    let final_output = serde_json::json!({
        "target": target,
        "dns_server": server,
        "total_records": all_results.len(),
        "axfr_available": !axfr_results.is_empty(),
        "nxdomain": last_result.0,
        "authoritative": last_result.1,
        "dnssec": last_result.2,
        "elapsed_ms": elapsed,
    });
    println!("FINAL:{}", final_output);
}
