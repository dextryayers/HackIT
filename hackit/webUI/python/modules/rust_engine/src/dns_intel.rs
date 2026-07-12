use crate::common::ScanConfig;
use crate::common::DnsIntelResult;
use std::str::FromStr;
use tokio::task;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

const DNS_RECORD_TYPES: &[&str] = &["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SRV", "CAA", "SOA", "PTR"];

const DNSSEC_RECORDS: &[&str] = &["DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3"];

const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "webmail", "email", "vpn",
    "remote", "gateway", "portal", "admin", "panel", "dashboard", "api",
    "dev", "staging", "test", "beta", "alpha", "demo", "sandbox", "ci",
    "cd", "build", "deploy", "git", "gitlab", "jenkins", "sonar",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "cache", "memcached", "cdn", "static", "assets", "img", "images",
    "media", "video", "stream", "live", "chat", "socket", "ws",
    "auth", "login", "sso", "oauth", "id", "identity", "saml",
    "search", "solr", "elastic", "sphinx", "logging", "log", "logs",
    "monitor", "grafana", "prometheus", "nagios", "zabbix",
    "backup", "bak", "old", "legacy", "archive", "dump",
    "status", "health", "ping", "info", "version", "docs", "doc",
    "blog", "news", "forum", "community", "support", "help", "faq",
    "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "crm", "erp", "hr", "intranet", "internal", "corp", "corporate",
    "owa", "exchange", "autodiscover", "autoconfig",
];

const CLOUD_PROVIDERS: &[(&str, &str)] = &[
    ("AWS", ".amazonaws.com"),
    ("Azure", ".azurewebsites.net"),
    ("Azure CDN", ".azureedge.net"),
    ("GCP", ".googleapis.com"),
    ("Cloudflare", ".cloudflare.com"),
    ("Vercel", ".vercel.app"),
    ("Netlify", ".netlify.app"),
    ("Heroku", ".herokuapp.com"),
    ("DigitalOcean", ".digitalocean.com"),
    ("Linode", ".linode.com"),
    ("Alibaba Cloud", ".aliyuncs.com"),
    ("Oracle Cloud", ".oraclecloud.com"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> DnsIntelResult {
    let domain = target.trim().to_lowercase();

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let mut handles = Vec::new();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(50));

    for &rtype in DNS_RECORD_TYPES {
        let resolver = resolver.clone();
        let domain = domain.clone();
        let sem = sem.clone();
        let rtype = rtype.to_string();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let record_type = match rtype.as_str() {
                "A" => trust_dns_proto::rr::RecordType::A,
                "AAAA" => trust_dns_proto::rr::RecordType::AAAA,
                "MX" => trust_dns_proto::rr::RecordType::MX,
                "NS" => trust_dns_proto::rr::RecordType::NS,
                "TXT" => trust_dns_proto::rr::RecordType::TXT,
                "CNAME" => trust_dns_proto::rr::RecordType::CNAME,
                "SRV" => trust_dns_proto::rr::RecordType::SRV,
                "CAA" => trust_dns_proto::rr::RecordType::CAA,
                "SOA" => trust_dns_proto::rr::RecordType::SOA,
                "PTR" => trust_dns_proto::rr::RecordType::PTR,
                _ => return None,
            };
            let answers = resolver.lookup(
                trust_dns_resolver::proto::rr::Name::from_str(&domain).ok()?,
                record_type,
            ).await.ok()?;
            let records: Vec<String> = answers.iter().map(|r| r.to_string()).collect();
            if records.is_empty() { None } else { Some((rtype, records)) }
        }));
    }

    let mut a_records = Vec::new();
    let mut aaaa_records = Vec::new();
    let mut mx_records = Vec::new();
    let mut ns_records = Vec::new();
    let mut txt_records = Vec::new();
    let mut cname_records = Vec::new();
    let mut srv_records = Vec::new();
    let mut caa_records = Vec::new();
    let mut soa_records = Vec::new();
    let mut ptr_records = Vec::new();
    let mut all_records: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for h in handles {
        if let Ok(Some((rtype, records))) = h.await {
            match rtype.as_str() {
                "A" => a_records = records.clone(),
                "AAAA" => aaaa_records = records.clone(),
                "MX" => mx_records = records.clone(),
                "NS" => ns_records = records.clone(),
                "TXT" => txt_records = records.clone(),
                "CNAME" => cname_records = records.clone(),
                "SRV" => srv_records = records.clone(),
                "CAA" => caa_records = records.clone(),
                "SOA" => soa_records = records.clone(),
                "PTR" => ptr_records = records.clone(),
                _ => {}
            }
            all_records.insert(rtype, records);
        }
    }

    let cloud_provider = detect_cloud_provider(&domain, &cname_records, &ns_records);
    let dnssec_enabled = !txt_records.iter().any(|r| r.contains("v=spf1") && r.contains("dnssec"));

    DnsIntelResult {
        domain,
        records: all_records,
        a_records,
        aaaa_records,
        mx_records,
        ns_records,
        txt_records,
        cname_records,
        srv_records,
        caa_records,
        soa_records,
        ptr_records,
        cloud_provider,
        dnssec_enabled,
    }
}

fn detect_cloud_provider(domain: &str, cnames: &[String], ns_records: &[String]) -> String {
    let all = format!("{} {} {}", domain, cnames.join(" "), ns_records.join(" "));
    let lower = all.to_lowercase();
    for &(name, pattern) in CLOUD_PROVIDERS {
        if lower.contains(pattern) {
            return name.to_string();
        }
    }
    "Unknown".to_string()
}

fn empty_result(domain: &str) -> DnsIntelResult {
    DnsIntelResult {
        domain: domain.to_string(),
        records: std::collections::HashMap::new(),
        a_records: vec![],
        aaaa_records: vec![],
        mx_records: vec![],
        ns_records: vec![],
        txt_records: vec![],
        cname_records: vec![],
        srv_records: vec![],
        caa_records: vec![],
        soa_records: vec![],
        ptr_records: vec![],
        cloud_provider: "Unknown".to_string(),
        dnssec_enabled: false,
    }
}
