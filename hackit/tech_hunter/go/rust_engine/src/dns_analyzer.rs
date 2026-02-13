use serde::{Serialize, Deserialize};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DNSInfo {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub soa_record: Option<String>,
}

pub async fn analyze_dns(host: &str) -> DNSInfo {
    let mut dns = DNSInfo::default();
    
    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return dns,
    };

    // A Records
    if let Ok(lookup) = resolver.ipv4_lookup(host).await {
        dns.a_records = lookup.iter().map(|ip| ip.to_string()).collect();
    }

    // AAAA Records
    if let Ok(lookup) = resolver.ipv6_lookup(host).await {
        dns.aaaa_records = lookup.iter().map(|ip| ip.to_string()).collect();
    }

    // MX Records
    if let Ok(lookup) = resolver.mx_lookup(host).await {
        dns.mx_records = lookup.iter().map(|mx| format!("{} (priority: {})", mx.exchange(), mx.preference())).collect();
    }

    // TXT Records
    if let Ok(lookup) = resolver.txt_lookup(host).await {
        dns.txt_records = lookup.iter().map(|txt| txt.to_string()).collect();
    }

    // NS Records
    if let Ok(lookup) = resolver.ns_lookup(host).await {
        dns.ns_records = lookup.iter().map(|ns| ns.to_string()).collect();
    }

    // SOA Record
    if let Ok(lookup) = resolver.soa_lookup(host).await {
        if let Some(soa) = lookup.iter().next() {
            dns.soa_record = Some(format!("MNAME: {}, RNAME: {}", soa.mname(), soa.rname()));
        }
    }

    dns
}
