use crate::common::*;
use crate::{progress, progress_done};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub async fn enumerate(domain: &str) -> DnsZoneTransferResult {
    progress!("dns_zone_transfer", "running");
    let mut result = DnsZoneTransferResult { domain: domain.into(), ..Default::default() };
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    if let Ok(ns_resp) = resolver.ns_lookup(domain).await {
        for r in ns_resp.iter() {
            result.nameservers.push(r.to_string());
        }
        result.dnssec_enabled = true;
    }
    if let Ok(soa_resp) = resolver.soa_lookup(domain).await {
        for r in soa_resp.iter() {
            result.records.push(format!("SOA: {}", r));
        }
    }
    progress_done!("dns_zone_transfer");
    result
}
