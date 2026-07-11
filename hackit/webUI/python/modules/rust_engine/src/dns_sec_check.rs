use crate::common::*;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;
use tokio::time::{timeout, Duration};

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

fn make_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = QUERY_TIMEOUT;
    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
}

async fn lookup_records(
    resolver: &TokioAsyncResolver,
    domain: &str,
    rtype: RecordType,
) -> Vec<String> {
    match timeout(QUERY_TIMEOUT, resolver.lookup(domain, rtype)).await {
        Ok(Ok(answers)) => answers.iter().map(|a| a.to_string()).collect(),
        _ => Vec::new(),
    }
}

async fn lookup_txt_aggregate(
    resolver: &TokioAsyncResolver,
    domain: &str,
) -> Vec<String> {
    let records = lookup_records(resolver, domain, RecordType::TXT).await;
    records.iter().flat_map(|r| {
        r.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>()
    }).collect()
}

fn algorithm_from_dnskey(rdata: &str) -> Option<String> {
    let parts: Vec<&str> = rdata.split_whitespace().collect();
    for part in parts {
        if let Ok(num) = part.parse::<u8>() {
            return Some(match num {
                5 => "RSASHA1".into(),
                7 => "RSASHA1-NSEC3-SHA1".into(),
                8 => "RSASHA256".into(),
                10 => "RSASHA512".into(),
                13 => "ECDSA-P256SHA256".into(),
                14 => "ECDSA-P384SHA384".into(),
                15 => "ED25519".into(),
                16 => "ED448".into(),
                _ => format!("Unknown({})", num),
            });
        }
    }
    None
}

fn algorithm_from_ds(rdata: &str) -> Option<String> {
    let parts: Vec<&str> = rdata.split_whitespace().collect();
    for part in parts {
        if let Ok(num) = part.parse::<u8>() {
            return Some(match num {
                1 => "SHA1".into(),
                2 => "SHA256".into(),
                3 => "GOST-R-34.11-94".into(),
                4 => "SHA384".into(),
                _ => format!("Unknown({})", num),
            });
        }
    }
    None
}

fn parse_nsec_algo(records: &[String]) -> Option<String> {
    for r in records {
        let parts: Vec<&str> = r.split_whitespace().collect();
        for part in &parts {
            if let Ok(num) = part.parse::<u8>() {
                if (1..=255).contains(&num) {
                    return Some(match num {
                        1 => "SHA1".into(),
                        2 => "SHA256".into(),
                        _ => format!("NSEC3-SHA{}", num),
                    });
                }
            }
        }
    }
    None
}

fn parse_caa(records: &[String]) -> Option<String> {
    for r in records {
        if r.to_lowercase().contains("issue") || r.to_lowercase().contains("iodef") {
            let cleaned = r.trim_matches('"').to_string();
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}

fn analyze_spf(txt_records: &[String]) -> Option<bool> {
    for r in txt_records {
        let lower = r.to_lowercase();
        if lower.starts_with("v=spf1") {
            if lower.contains("-all") {
                return Some(true);
            } else if lower.contains("~all") || lower.contains("?all") {
                return Some(false);
            } else if lower.contains("+all") {
                return Some(false);
            }
            let has_redirect = lower.contains("redirect=");
            if lower.contains("all") || has_redirect {
                return Some(false);
            }
            return Some(false);
        }
    }
    None
}

fn parse_dmarc(txt_records: &[String]) -> Option<String> {
    for r in txt_records {
        let lower = r.to_lowercase().replace('"', "").replace(' ', "");
        if lower.starts_with("v=dmarc") {
            let parts: Vec<&str> = lower.split(';').collect();
            for part in parts {
                let trimmed = part.trim();
                if let Some(policy_val) = trimmed.strip_prefix("p=").or_else(|| trimmed.strip_prefix(" p=")) {
                    let p = policy_val.trim().to_lowercase();
                    if p == "none" || p == "quarantine" || p == "reject" {
                        return Some(p);
                    }
                }
            }
            return Some("none".into());
        }
    }
    None
}

fn check_txt_issues(
    spf_strong: Option<bool>,
    dmarc_policy: Option<String>,
    txt_records: &[String],
) -> Vec<String> {
    let mut issues = Vec::new();

    let has_spf = txt_records.iter().any(|r| r.to_lowercase().starts_with("v=spf1"));
    if !has_spf {
        issues.push("Missing SPF record".into());
    } else if spf_strong == Some(false) {
        issues.push("Weak SPF policy (softfail/neutral, should use -all)".into());
    }

    let has_dmarc = txt_records.iter().any(|r| r.to_lowercase().replace(' ', "").starts_with("v=dmarc"));
    if !has_dmarc {
        issues.push("Missing DMARC record".into());
    } else {
        match dmarc_policy.as_deref() {
            Some("none") => issues.push("DMARC policy is 'none' (monitoring only, no enforcement)".into()),
            Some("quarantine") => {}
            Some("reject") => {}
            Some(_) => issues.push("DMARC policy set but not recognized".into()),
            None => issues.push("Could not parse DMARC policy from record".into()),
        }
    }

    let has_dkim = txt_records.iter().any(|r| r.contains("v=DKIM1") || r.contains("o=~") || r.contains("k=rsa"));
    if !has_dkim {
        issues.push("No DKIM record found (signing not detected)".into());
    }

    issues
}

pub async fn check(domain: &str) -> DnsSecCheckResult {
    let resolver = make_resolver();

    let (dnskey, ds, rrsig, tlsa, caa_records, txt_records, nsec3, nsec) = tokio::join!(
        lookup_records(&resolver, domain, RecordType::DNSKEY),
        lookup_records(&resolver, domain, RecordType::DS),
        lookup_records(&resolver, domain, RecordType::RRSIG),
        lookup_records(&resolver, domain, RecordType::TLSA),
        lookup_records(&resolver, domain, RecordType::CAA),
        lookup_txt_aggregate(&resolver, domain),
        lookup_records(&resolver, domain, RecordType::NSEC3),
        lookup_records(&resolver, domain, RecordType::NSEC),
    );

    let dnssec_enabled = !dnskey.is_empty() || !ds.is_empty() || !rrsig.is_empty();

    let mut algorithms: Vec<String> = Vec::new();
    for r in &dnskey {
        if let Some(algo) = algorithm_from_dnskey(r) {
            if !algorithms.contains(&algo) {
                algorithms.push(algo);
            }
        }
    }
    for r in &ds {
        if let Some(algo) = algorithm_from_ds(r) {
            if !algorithms.contains(&algo) {
                algorithms.push(algo);
            }
        }
    }

    let nssec_algo = if !nsec3.is_empty() {
        parse_nsec_algo(&nsec3)
    } else if !nsec.is_empty() {
        parse_nsec_algo(&nsec)
    } else {
        None
    };

    let dane_enabled = !tlsa.is_empty();

    let caa_policy = if !caa_records.is_empty() {
        parse_caa(&caa_records)
    } else {
        None
    };

    let spf_strong = analyze_spf(&txt_records);
    let dmarc_policy = parse_dmarc(&txt_records);
    let txt_issues = check_txt_issues(spf_strong, dmarc_policy.clone(), &txt_records);

    let mut r = DnsSecCheckResult {
        domain: domain.to_string(),
        dnssec_enabled,
        has_dnskey: !dnskey.is_empty(),
        has_ds: !ds.is_empty(),
        has_rrsig: !rrsig.is_empty(),
        algorithms,
        nssec_algo,
        dane_enabled,
        caa_policy: caa_policy.clone(),
        spf_strong,
        dmarc_policy: dmarc_policy.clone(),
        txt_issues,
        error: None,
    };

    if !dnssec_enabled && caa_policy.is_none() && !dane_enabled && spf_strong.is_none() && dmarc_policy.is_none() {
        r.error = Some("DNSSEC disabled; no CAA, DANE, SPF, or DMARC records found".into());
    }

    r
}
