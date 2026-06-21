use serde::Serialize;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DEFAULT_TIMEOUT_MS: u64 = 5000;
const DNS_SERVER: &str = "1.1.1.1:53";
const DNS_CACHE_TTL_SECS: u64 = 300;
const MAX_DNS_PACKET: usize = 4096;

lazy_static::lazy_static! {
    static ref DNS_RECORD_CACHE: RwLock<HashMap<String, (Vec<DNSAnswer>, Instant)>> = RwLock::new(HashMap::new());
}

#[derive(Debug, Clone, Serialize)]
struct DNSAnswer {
    query_type: String,
    name: String,
    value: String,
    ttl: u32,
    priority: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
struct DNSQueryResult {
    domain: String,
    query_type: String,
    answers: Vec<DNSAnswer>,
    authority: Vec<String>,
    additional: Vec<String>,
    rcode: String,
    dnssec: bool,
    cached: bool,
    elapsed_ms: u64,
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

fn parse_dns_response(data: &[u8]) -> (Vec<DNSAnswer>, Vec<String>, Vec<String>, String, bool) {
    if data.len() < 12 {
        return (vec![], vec![], vec![], "NXDOMAIN".to_string(), false);
    }
    let _id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let rcode = flags & 0x000f;
    let dnssec = (flags & 0x0080) != 0;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let rcode_str = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }.to_string();

    if rcode != 0 || ancount == 0 {
        return (vec![], vec![], vec![], rcode_str, dnssec);
    }

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(data, offset);
        if offset + 4 > data.len() { break; }
        offset += 4;
    }

    let mut answers = Vec::with_capacity(ancount);
    let mut authority = Vec::new();
    let mut additional = Vec::new();

    for _ in 0..ancount {
        if offset >= data.len() { break; }
        let (name, new_offset) = parse_name(data, offset);
        offset = new_offset;
        if offset + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > data.len() { break; }

        let type_str = match rtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            99 => "SPF",
            257 => "CAA",
            _ => "OTHER",
        }.to_string();

        let value = match rtype {
            1 | 28 if rdlength >= 4 => {
                if rtype == 1 {
                    format!("{}.{}.{}.{}", data[offset], data[offset + 1], data[offset + 2], data[offset + 3])
                } else {
                    let mut s = String::new();
                    for i in 0..rdlength.min(16) {
                        if i > 0 && i % 2 == 0 { s.push(':'); }
                        s.push_str(&format!("{:02x}", data[offset + i]));
                    }
                    s
                }
            }
            5 | 2 => {
                let (pname, _) = parse_name(data, offset);
                pname
            }
            15 => {
                if rdlength >= 2 {
                    let priority = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let (exchange, _) = parse_name(data, offset + 2);
                    format!("{} {}", priority, exchange)
                } else { String::new() }
            }
            16 => {
                let mut parts = Vec::new();
                let mut pos = offset;
                let end = offset + rdlength;
                while pos < end {
                    let len = data[pos] as usize;
                    pos += 1;
                    if pos + len > end { break; }
                    if let Ok(s) = String::from_utf8(data[pos..pos + len].to_vec()) {
                        parts.push(s);
                    }
                    pos += len;
                }
                parts.join("")
            }
            6 => {
                let (mname, off) = parse_name(data, offset);
                let (rname, off) = parse_name(data, off);
                if off + 20 <= data.len() {
                    let serial = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                    format!("{} {} serial:{}", mname, rname, serial)
                } else { format!("{} {}", mname, rname) }
            }
            33 => {
                let priority = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let weight = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
                let (target, _) = parse_name(data, offset + 6);
                format!("{} {} {} {}", priority, weight, port, target)
            }
            _ => data[offset..offset + rdlength.min(32)].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().concat(),
        };

        let mx_priority = if rtype == 15 && rdlength >= 2 {
            Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
        } else { None };

        answers.push(DNSAnswer {
            query_type: type_str,
            name: name.clone(),
            value,
            ttl,
            priority: mx_priority,
        });
        offset += rdlength;
    }

    for _ in 0..nscount {
        if offset >= data.len() { break; }
        let (name, new_offset) = parse_name(data, offset);
        offset = new_offset;
        if offset + 10 > data.len() { break; }
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10 + rdlength;
        authority.push(name);
    }

    for _ in 0..arcount {
        if offset >= data.len() { break; }
        let (name, new_offset) = parse_name(data, offset);
        offset = new_offset;
        if offset + 10 > data.len() { break; }
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10 + rdlength;
        additional.push(name);
    }

    (answers, authority, additional, rcode_str, dnssec)
}

fn skip_name(data: &[u8], mut offset: usize) -> usize {
    loop {
        if offset >= data.len() { break; }
        let len = data[offset] as usize;
        if len == 0 { return offset + 1; }
        if (len & 0xc0) == 0xc0 { return offset + 2; }
        offset += 1 + len;
    }
    offset + 1
}

fn parse_name(data: &[u8], mut offset: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;

    loop {
        if offset >= data.len() { break; }
        let len = data[offset] as usize;
        if len == 0 {
            if !jumped { end_offset = offset + 1; }
            break;
        }
        if (len & 0xc0) == 0xc0 {
            let ptr = (((len & 0x3f) as u16) << 8) | data[offset + 1] as u16;
            if !jumped { end_offset = offset + 2; }
            offset = ptr as usize;
            jumped = true;
            continue;
        }
        offset += 1;
        if offset + len > data.len() { break; }
        if let Ok(s) = std::str::from_utf8(&data[offset..offset + len]) {
            labels.push(s.to_string());
        }
        offset += len;
    }

    (labels.join("."), end_offset)
}

async fn dns_over_tcp(domain: &str, qtype: u16, timeout_ms: u64) -> Result<(Vec<DNSAnswer>, Vec<String>, Vec<String>, String, bool), String> {
    let query = build_dns_query(domain, qtype, 0x1337);
    let mut pkt = Vec::with_capacity(query.len() + 2);
    pkt.extend_from_slice(&(query.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&query);

    let stream = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(DNS_SERVER)).await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect error: {}", e))?;

    let (mut reader, mut writer) = stream.into_split();
    writer.write_all(&pkt).await.map_err(|e| format!("write error: {}", e))?;

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_millis(timeout_ms), reader.read_exact(&mut len_buf)).await
        .map_err(|_| "read length timeout".to_string())?
        .map_err(|e| format!("read length error: {}", e))?;

    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > MAX_DNS_PACKET {
        return Err("invalid response length".to_string());
    }

    let mut resp = vec![0u8; resp_len];
    timeout(Duration::from_millis(timeout_ms), reader.read_exact(&mut resp)).await
        .map_err(|_| "read response timeout".to_string())?
        .map_err(|e| format!("read response error: {}", e))?;

    Ok(parse_dns_response(&resp))
}

fn qtype_from_str(s: &str) -> u16 {
    match s.to_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => 1,
    }
}

fn cache_key(domain: &str, qtype: u16) -> String {
    format!("{}:{}", domain.to_lowercase(), qtype)
}

async fn resolve_with_cache(domain: &str, qtype: u16, timeout_ms: u64) -> (DNSQueryResult, bool) {
    let key = cache_key(domain, qtype);

    {
        let cache = DNS_RECORD_CACHE.read().unwrap();
        if let Some((answers, expiry)) = cache.get(&key) {
            if expiry.elapsed() < Duration::from_secs(DNS_CACHE_TTL_SECS) {
                let result = DNSQueryResult {
                    domain: domain.to_string(),
                    query_type: match qtype { 1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", _ => "OTHER" }.to_string(),
                    answers: answers.clone(),
                    authority: vec![],
                    additional: vec![],
                    rcode: "NOERROR".to_string(),
                    dnssec: false,
                    cached: true,
                    elapsed_ms: 0,
                };
                return (result, true);
            }
        }
    }

    let start = Instant::now();
    match dns_over_tcp(domain, qtype, timeout_ms).await {
        Ok((answers, authority, additional, rcode, dnssec)) => {
            let elapsed = start.elapsed().as_millis() as u64;
            let mut cache = DNS_RECORD_CACHE.write().unwrap();
            cache.insert(key.clone(), (answers.clone(), Instant::now()));

            let result = DNSQueryResult {
                domain: domain.to_string(),
                query_type: match qtype { 1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", _ => "OTHER" }.to_string(),
                answers,
                authority,
                additional,
                rcode,
                dnssec,
                cached: false,
                elapsed_ms: elapsed,
            };
            (result, false)
        }
        Err(e) => {
            let result = DNSQueryResult {
                domain: domain.to_string(),
                query_type: match qtype { 1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV", _ => "OTHER" }.to_string(),
                answers: vec![],
                authority: vec![],
                additional: vec![],
                rcode: format!("ERROR:{}", e),
                dnssec: false,
                cached: false,
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
            (result, false)
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <domain> [query_type] [timeout_ms]", args[0]);
        eprintln!("  query_type: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, ANY (default: A)");
        eprintln!("Example: {} example.com MX", args[0]);
        eprintln!("Example: {} example.com A 3000", args[0]);
        std::process::exit(1);
    }

    let domain = &args[1];
    let qtype_str = if args.len() > 2 { &args[2] } else { "A" };
    let timeout_ms = if args.len() > 3 {
        args[3].parse().unwrap_or(DEFAULT_TIMEOUT_MS)
    } else {
        DEFAULT_TIMEOUT_MS
    };

    let qtype = qtype_from_str(qtype_str);
    eprintln!("DNS_OVER_HTTPS domain={} query_type={} timeout={}ms server={}",
        domain, qtype_str, timeout_ms, DNS_SERVER);

    let (result, _) = resolve_with_cache(domain, qtype, timeout_ms).await;
    println!("RESULT:{}", serde_json::to_string(&result).unwrap());
}
