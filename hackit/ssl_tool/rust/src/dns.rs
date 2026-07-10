use crate::types::*;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use tokio::time::{timeout, Duration};
use std::net::IpAddr;

pub async fn dns_lookup(host: &str) -> DNSReport {
    let mut r = DNSReport::default();

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());

    // A/AAAA
    match timeout(Duration::from_secs(5), resolver.lookup_ip(host)).await {
        Ok(Ok(response)) => {
            for ip in response.iter() {
                match ip {
                    IpAddr::V4(v4) => r.a_records.push(v4.to_string()),
                    IpAddr::V6(v6) => r.aaaa_records.push(v6.to_string()),
                }
            }
        }
        _ => r.issues.push("A/AAAA lookup failed".to_string()),
    }

    // MX
    match timeout(Duration::from_secs(5), resolver.mx_lookup(host)).await {
        Ok(Ok(response)) => {
            for rec in response.iter() {
                r.mx_records.push(format!("{} (pref={})", rec.exchange(), rec.preference()));
            }
        }
        _ => {}
    }

    // NS
    match timeout(Duration::from_secs(5), resolver.ns_lookup(host)).await {
        Ok(Ok(response)) => {
            for rec in response.iter() {
                r.ns_servers.push(rec.to_string());
            }
        }
        _ => {}
    }

    // SOA
    match timeout(Duration::from_secs(5), resolver.soa_lookup(host)).await {
        Ok(Ok(response)) => {
            for rec in response.iter() {
                r.soa_record = format!("{:?}", rec);
            }
        }
        _ => {}
    }

    // TXT (for SPF, DMARC, DKIM)
    match timeout(Duration::from_secs(5), resolver.txt_lookup(host)).await {
        Ok(Ok(response)) => {
            for rec in response.iter() {
                let txt_str = rec.iter().map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join("");
                r.txt_records.push(txt_str.clone());
                if txt_str.to_lowercase().starts_with("v=spf1") {
                    r.spf = txt_str;
                    r.spf_record_valid = true;
                }
            }
        }
        _ => {}
    }

    // DMARC
    let dmarc_host = format!("_dmarc.{}", host);
    match timeout(Duration::from_secs(5), resolver.txt_lookup(&dmarc_host)).await {
        Ok(Ok(response)) => {
            for rec in response.iter() {
                let txt_str = rec.iter().map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join("");
                if txt_str.to_lowercase().starts_with("v=dmarc") {
                    r.dmarc = txt_str;
                    r.dmarc_record_valid = true;
                }
            }
        }
        _ => {}
    }

    // DKIM (common selectors)
    for selector in &["default", "google", "selector1", "selector2", "dkim", "mx"] {
        let dkim_host = format!("{}._domainkey.{}", selector, host);
        match timeout(Duration::from_secs(3), resolver.txt_lookup(&dkim_host)).await {
            Ok(Ok(response)) => {
                for rec in response.iter() {
                    let txt_str = rec.iter().map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>().join("");
                    if txt_str.contains("v=DKIM1") || txt_str.contains("p=") {
                        r.dkim_detect = true;
                        r.dkim_records.push(format!("{}: {}", selector, txt_str));
                    }
                }
            }
            _ => {}
        }
    }

    // CNAME
    match timeout(Duration::from_secs(5), resolver.lookup(host, RecordType::CNAME)).await {
        Ok(Ok(response)) => {
            for rec in response.record_iter() {
                if let Some(cname) = rec.data().and_then(|d| d.as_cname()) {
                    r.cname_records.push(cname.to_string());
                }
            }
        }
        _ => {}
    }

    // CAA
    match timeout(Duration::from_secs(5), resolver.lookup(host, RecordType::CAA)).await {
        Ok(Ok(response)) => {
            for rec in response.record_iter() {
                if let Some(data) = rec.data() {
                    r.caa_records.push(format!("{:?}", data));
                }
            }
            if !r.caa_records.is_empty() {
                r.caa = r.caa_records.first().cloned().unwrap_or_default();
            }
        }
        _ => {}
    }

    r.issues = build_dns_issues(&r);
    r
}

fn build_dns_issues(r: &DNSReport) -> Vec<String> {
    let mut issues = Vec::new();
    if r.a_records.is_empty() && r.aaaa_records.is_empty() {
        issues.push("No A or AAAA records found".to_string());
    }
    if r.spf.is_empty() {
        issues.push("No SPF record - email spoofing protection missing".to_string());
    }
    if r.dmarc.is_empty() {
        issues.push("No DMARC record - email authentication policy missing".to_string());
    }
    if r.caa_records.is_empty() {
        issues.push("No CAA record - certificate authority authorization missing".to_string());
    }
    if r.mx_records.is_empty() {
        issues.push("No MX records - email delivery may be affected".to_string());
    }
    issues
}
