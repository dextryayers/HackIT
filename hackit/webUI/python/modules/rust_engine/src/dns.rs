use crate::common::DnsResult;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;

pub async fn enumerate(domain: &str) -> DnsResult {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
    let mut r = DnsResult::default();
    if let Ok(answers) = resolver.lookup(domain, RecordType::A).await { for ip in answers.iter() { r.a.push(ip.to_string()); } }
    if let Ok(answers) = resolver.lookup(domain, RecordType::AAAA).await { for ip in answers.iter() { r.aaaa.push(ip.to_string()); } }
    if let Ok(answers) = resolver.lookup(domain, RecordType::MX).await { for mx in answers.iter() { r.mx.push(mx.to_string()); } }
    if let Ok(answers) = resolver.lookup(domain, RecordType::NS).await { for ns in answers.iter() { r.ns.push(ns.to_string()); } }
    if let Ok(answers) = resolver.lookup(domain, RecordType::TXT).await { for txt in answers.iter() { r.txt.push(txt.to_string()); } }
    if let Ok(answers) = resolver.lookup(domain, RecordType::CNAME).await { for cname in answers.iter() { r.cname.push(cname.to_string()); } }
    r
}
