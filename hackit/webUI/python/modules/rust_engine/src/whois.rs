use crate::common::*;
use crate::{progress, progress_done};
use std::sync::OnceLock;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

/// RDAP providers tried in order until one succeeds
const RDAP_PROVIDERS: &[&str] = &[
    "https://rdap.org/domain/",
    "https://rdap.apnic.net/domain/",
    "https://rdap.ripe.net/domain/",
];

/// WHOIS server routing by TLD
const TLD_WHOIS: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com"),
    ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"),
    ("info", "whois.afilias.net"),
    ("biz", "whois.neulevel.biz"),
    ("io", "whois.nic.io"),
    ("co", "whois.nic.co"),
    ("uk", "whois.nic.uk"),
    ("de", "whois.denic.de"),
    ("eu", "whois.eu"),
    ("ru", "whois.tcinet.ru"),
    ("au", "whois.auda.org.au"),
    ("ca", "whois.cira.ca"),
    ("fr", "whois.nic.fr"),
    ("nl", "whois.domain-registry.nl"),
    ("br", "whois.registro.br"),
    ("us", "whois.nic.us"),
    ("xyz", "whois.nic.xyz"),
    ("top", "whois.nic.top"),
    ("tech", "whois.nic.tech"),
    ("online", "whois.nic.online"),
    ("site", "whois.nic.site"),
    ("space", "whois.nic.space"),
    ("host", "whois.nic.host"),
    ("name", "whois.nic.name"),
    ("mobi", "whois.afilias.net"),
    ("pro", "whois.nic.pro"),
    ("edu", "whois.educause.edu"),
    ("gov", "whois.dotgov.gov"),
    ("int", "whois.iana.org"),
    ("aero", "whois.information.aero"),
    ("asia", "whois.nic.asia"),
    ("cat", "whois.nic.cat"),
    ("coop", "whois.nic.coop"),
    ("jobs", "whois.nic.jobs"),
    ("tel", "whois.nic.tel"),
    ("travel", "whois.nic.travel"),
    ("app", "whois.nic.google"),
    ("dev", "whois.nic.google"),
    ("cloud", "whois.nic.cloud"),
    ("me", "whois.nic.me"),
    ("cc", "whois.nic.cc"),
    ("tv", "whois.nic.tv"),
    ("ws", "whois.nic.ws"),
    ("in", "whois.nic.in"),
    ("cn", "whois.cnnic.cn"),
    ("jp", "whois.jprs.jp"),
    ("kr", "whois.kr"),
    ("sg", "whois.sgnic.sg"),
    ("hk", "whois.hkirc.hk"),
];

fn extract_tld(domain: &str) -> Option<&str> {
    let (_, tld) = domain.rsplit_once('.')?;
    Some(tld)
}

fn whois_server_for_tld(tld: &str) -> Option<&'static str> {
    TLD_WHOIS.iter().find(|(k, _)| *k == tld).map(|(_, v)| *v)
}

fn client_pool() -> &'static ClientPool {
    static POOL: OnceLock<ClientPool> = OnceLock::new();
    POOL.get_or_init(|| ClientPool::with_timeout(15))
}

/// Resolve nameserver hostnames to IP addresses
async fn resolve_nameserver_ips(nameservers: &[String]) {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    for ns in nameservers {
        let _ = timeout(Duration::from_secs(5), resolver.lookup_ip(ns)).await;
    }
}

/// Extract the vcard lines from an RDAP entity (skipping the "vcard" label)
fn vcard_lines(ent: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    let arr = ent["vcardArray"].as_array()?;
    if arr.len() < 2 {
        return None;
    }
    arr[1].as_array()
}

/// Get the last element of a vcard line as a string
fn vcard_str(line: &[serde_json::Value]) -> Option<&str> {
    line.last().and_then(|v| v.as_str())
}

/// Get the last element of a vcard line as a reference
fn vcard_val(line: &[serde_json::Value]) -> Option<&serde_json::Value> {
    line.last()
}

/// Parse RDAP JSON response into WhoisResult
fn parse_rdap_response(data: &serde_json::Value, result: &mut WhoisResult) {
    if let Some(events) = data["events"].as_array() {
        for ev in events {
            let action = match ev["eventAction"].as_str() {
                Some(a) => a,
                None => continue,
            };
            let date = match ev["eventDate"].as_str() {
                Some(d) => d,
                None => continue,
            };
            match action {
                "registration" => result.creation_date = Some(date.into()),
                "expiration" => result.expiration_date = Some(date.into()),
                "last changed" => result.updated_date = Some(date.into()),
                _ => {}
            }
        }
    }

    if let Some(ns) = data["nameservers"].as_array() {
        for n in ns {
            if let Some(lfh) = n["ldhName"].as_str() {
                let clean = lfh.to_lowercase().trim_end_matches('.').to_string();
                if !result.name_servers.contains(&clean) {
                    result.name_servers.push(clean);
                }
            }
        }
    }

    let entities = match data["entities"].as_array() {
        Some(e) => e,
        None => return,
    };

    for ent in entities {
        let roles: Vec<&str> = ent["roles"]
            .as_array()
            .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        if roles.contains(&"registrar") {
            if let Some(lines) = vcard_lines(ent) {
                for line in lines {
                    let arr = match line.as_array() {
                        Some(a) if a.len() >= 2 => a,
                        _ => continue,
                    };
                    if arr[0].as_str() == Some("fn") {
                        if let Some(val) = vcard_str(arr) {
                            result.registrar = Some(val.into());
                        }
                    }
                }
            }
        }

        if roles.contains(&"registrant") {
            if let Some(lines) = vcard_lines(ent) {
                for line in lines {
                    let arr = match line.as_array() {
                        Some(a) if a.len() >= 2 => a,
                        _ => continue,
                    };
                    match arr[0].as_str() {
                        Some("fn") => {
                            if let Some(val) = vcard_str(arr) {
                                result.registrant_org = Some(val.into());
                            }
                        }
                        Some("adr") => {
                            if let Some(adr_arr) = vcard_val(arr).and_then(|v| v.as_array()) {
                                if adr_arr.len() > 6 {
                                    if let Some(country) = adr_arr[6].as_str() {
                                        if result.registrant_country.is_none() {
                                            result.registrant_country = Some(country.into());
                                        }
                                    }
                                }
                            }
                        }
                        Some("email") => {
                            if let Some(val) = vcard_str(arr) {
                                if result.abuse_email.is_none() && val.contains('@') {
                                    result.abuse_email = Some(val.into());
                                }
                            }
                        }
                        Some("tel") => {
                            if let Some(val) = vcard_str(arr) {
                                // Extract phone number from "tel:+1.1234567890" or similar
                                let phone = val.trim_start_matches("tel:").to_string();
                                if !phone.is_empty() && result.registrant_org.is_none() {
                                    // Store phone if no org found (best-effort)
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if roles.contains(&"abuse") && result.abuse_email.is_none() {
            if let Some(lines) = vcard_lines(ent) {
                for line in lines {
                    let arr = match line.as_array() {
                        Some(a) if a.len() >= 2 => a,
                        _ => continue,
                    };
                    if arr[0].as_str() == Some("email") {
                        if let Some(val) = vcard_str(arr) {
                            result.abuse_email = Some(val.into());
                        }
                    }
                }
            }
        }
    }
}

/// Attempt RDAP lookup across multiple providers. Returns true if any succeeded.
async fn rdap_lookup(client: &reqwest::Client, domain: &str, result: &mut WhoisResult) -> bool {
    for provider in RDAP_PROVIDERS {
        let url = format!("{}{}", provider, domain);
        match timeout(Duration::from_secs(10), client.get(&url).send()).await {
            Ok(Ok(resp)) => {
                if !resp.status().is_success() {
                    continue;
                }
                let body = match timeout(Duration::from_secs(10), resp.text()).await {
                    Ok(Ok(b)) => b,
                    _ => continue,
                };
                let data: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                parse_rdap_response(&data, result);
                return true;
            }
            _ => continue,
        }
    }
    false
}

/// Parse raw WHOIS response text into WhoisResult
fn parse_raw_whois(response: &str, result: &mut WhoisResult) {
    for line in response.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('%')
            || trimmed.starts_with('#')
            || trimmed.starts_with("NOTICE:")
            || trimmed.starts_with("TERMS OF USE")
            || trimmed.starts_with(">>>")
            || trimmed.starts_with("<<<")
        {
            continue;
        }
        let colon = match trimmed.find(':') {
            Some(p) => p,
            None => continue,
        };
        let key = trimmed[..colon].trim().to_lowercase();
        let value = trimmed[colon + 1..].trim();

        match key.as_str() {
            "registrar" => {
                if result.registrar.is_none() {
                    result.registrar = Some(value.into());
                }
            }
            "creation date" | "created date" | "created" | "domain created" | "domain creation date" => {
                if result.creation_date.is_none() {
                    result.creation_date = Some(value.into());
                }
            }
            "registry expiry date" | "expiration date" | "expiry date" | "expires"
            | "domain expires" | "domain expiration date" => {
                if result.expiration_date.is_none() {
                    result.expiration_date = Some(value.into());
                }
            }
            "updated date" | "last updated" | "modified" | "domain last modified"
            | "domain last updated" => {
                if result.updated_date.is_none() {
                    result.updated_date = Some(value.into());
                }
            }
            "name server" | "nameserver" | "nserver" => {
                let ns = value.to_lowercase().trim_end_matches('.').to_string();
                if !result.name_servers.contains(&ns) {
                    result.name_servers.push(ns);
                }
            }
            "registrant organization" | "org" | "organization" => {
                if result.registrant_org.is_none() {
                    result.registrant_org = Some(value.into());
                }
            }
            "registrant country" | "country" => {
                if result.registrant_country.is_none() {
                    result.registrant_country = Some(value.into());
                }
            }
            "registrar abuse contact email" | "abuse email" | "abuse-contact" | "abuse contact email" => {
                if result.abuse_email.is_none() && value.contains('@') {
                    result.abuse_email = Some(value.into());
                }
            }
            _ => {}
        }
    }
}

/// Perform raw WHOIS lookup on port 43 using TLD-based server routing
async fn raw_whois_lookup(domain: &str, result: &mut WhoisResult) -> bool {
    let tld = match extract_tld(domain) {
        Some(t) => t,
        None => {
            result.error = Some(format!("Could not extract TLD from {}", domain));
            return false;
        }
    };
    let server = match whois_server_for_tld(tld) {
        Some(s) => s,
        None => {
            result.error = Some(format!("No WHOIS server configured for TLD .{}", tld));
            return false;
        }
    };
    let addr = format!("{}:43", server);
    let stream = match timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            result.error = Some(format!("WHOIS connect to {}: {:.80}", server, e));
            return false;
        }
        Err(_) => {
            result.error = Some(format!("WHOIS connect to {} timed out", server));
            return false;
        }
    };
    let (rx, mut tx) = stream.into_split();
    let query = format!("{}\r\n", domain);
    if let Err(e) = timeout(Duration::from_secs(5), tx.write_all(query.as_bytes())).await {
        result.error = Some(format!("WHOIS write error: {:.80}", e));
        return false;
    }
    let _ = timeout(Duration::from_secs(2), tx.shutdown()).await;
    let mut reader = BufReader::new(rx);
    let mut response = String::new();
    let mut line_buf = String::new();
    loop {
        line_buf.clear();
        match timeout(Duration::from_secs(10), reader.read_line(&mut line_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => response.push_str(&line_buf),
            _ => break,
        }
    }
    if response.is_empty() {
        result.error = Some(format!("Empty response from WHOIS server {}", server));
        return false;
    }
    parse_raw_whois(&response, result);
    true
}

pub async fn lookup(domain: &str) -> WhoisResult {
    progress!("whois", "running");
    let mut result = WhoisResult {
        domain: domain.to_string(),
        ..Default::default()
    };

    let client = client_pool().client();
    let rdap_ok = rdap_lookup(client, domain, &mut result).await;

    if rdap_ok {
        if !result.name_servers.is_empty() {
            resolve_nameserver_ips(&result.name_servers).await;
        }
    } else {
        let whois_ok = raw_whois_lookup(domain, &mut result).await;
        if !whois_ok && result.error.is_none() {
            result.error = Some(format!("All WHOIS/RDAP lookups failed for {}", domain));
        }
    }

    progress_done!("whois");
    result
}
