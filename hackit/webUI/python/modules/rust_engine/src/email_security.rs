use crate::common::*;
use crate::{progress, progress_done};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub async fn check(domain: &str) -> EmailSecurityResult {
    progress!("email_security", "running");
    let mut result = EmailSecurityResult { domain: domain.into(), ..Default::default() };
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    if let Ok(txt) = resolver.txt_lookup(domain).await {
        for r in txt.iter() {
            let val = r.to_string();
            if val.starts_with("v=spf1") {
                result.spf_record = Some(val.clone());
                result.spf_valid = val.contains("include:") || val.contains("ip4:") || val.contains("a") || val.contains("mx");
            }
        }
    }
    let dkim_domain = format!("default._domainkey.{}", domain);
    if let Ok(txt) = resolver.txt_lookup(&dkim_domain).await {
        for r in txt.iter() {
            let val = r.to_string();
            if val.contains("v=DKIM1") || val.contains("dkim") {
                result.dkim_record = Some(val.chars().take(200).collect());
                result.dkim_valid = true;
            }
        }
    }
    let dmarc_domain = format!("_dmarc.{}", domain);
    if let Ok(txt) = resolver.txt_lookup(&dmarc_domain).await {
        for r in txt.iter() {
            let val = r.to_string();
            if val.starts_with("v=DMARC1") {
                result.dmarc_record = Some(val.clone());
                if let Some(policy) = val.split(';').find(|s| s.trim().starts_with("p=")) {
                    result.dmarc_policy = Some(policy.trim().to_string());
                }
                result.dmarc_valid = true;
            }
        }
    }
    let mut score = 0u32;
    if result.spf_valid { score += 33; }
    if result.dkim_valid { score += 33; }
    if result.dmarc_valid { score += 34; }
    result.score = Some(score);
    progress_done!("email_security");
    result
}
