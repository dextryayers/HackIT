use crate::common::{ScanConfig};
use crate::common::DomainPermutationResult;
use std::time::Duration;
use tokio::task;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use crate::common::PermutationResult;

const TLD_SWAPS: &[&str] = &[
    ".com", ".net", ".org", ".io", ".co", ".app", ".dev", ".ai",
    ".gov", ".edu", ".mil", ".biz", ".info", ".me", ".tv", ".cc",
    ".xyz", ".club", ".online", ".site", ".shop", ".store",
];

const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];

fn generate_permutations(domain: &str) -> Vec<String> {
    let mut perms = Vec::new();
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 { return perms; }
    let name = parts[0];
    let orig_tld = format!(".{}", parts[parts.len() - 1]);

    for &tld in TLD_SWAPS {
        if tld != orig_tld {
            perms.push(format!("{}{}", name, tld));
        }
    }

    if name.len() > 3 {
        for i in 0..name.len() {
            let mut chars: Vec<char> = name.chars().collect();
            for &v in VOWELS {
                if chars[i] == v {
                    for &v2 in VOWELS {
                        if v != v2 {
                            chars[i] = v2;
                            perms.push(format!("{}{}", chars.iter().collect::<String>(), orig_tld));
                        }
                    }
                }
            }
        }
    }

    if name.len() > 2 {
        perms.push(format!("{}s{}", name, orig_tld));
        perms.push(format!("{}{}", name, orig_tld.replacen(".", ".", 1)));
        perms.push(format!("{}{}", name, orig_tld.replacen(".", "-", 1)));
    }

    if name.len() > 4 {
        let doubled = format!("{}{}", name, name);
        perms.push(format!("{}{}", doubled, orig_tld));
    }

    let common_prefixes = ["my", "the", "get", "go", "try", "new", "old", "best"];
    let common_suffixes = ["app", "site", "online", "web", "hq", "shop", "store", "blog"];
    for p in &common_prefixes {
        perms.push(format!("{}{}{}", p, name, orig_tld));
    }
    for s in &common_suffixes {
        perms.push(format!("{}{}{}", name, s, orig_tld));
    }

    perms.sort();
    perms.dedup();
    perms.truncate(200);
    perms
}

pub async fn scan(target: &str, _config: &ScanConfig) -> DomainPermutationResult {
    let domain = target.trim().to_lowercase();
    let permutations = generate_permutations(&domain);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(20));
    let mut handles = Vec::new();

    for perm in permutations.clone() {
        let resolver = resolver.clone();
        let sem = sem.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                resolver.lookup_ip(perm.clone()),
            ).await;
            match result {
                Ok(Ok(response)) => {
                    let ips: Vec<String> = response.iter().map(|ip| ip.to_string()).collect();
                    Some(PermutationResult {
                        domain: perm,
                        resolves: true,
                        ips: ips.into_iter().take(5).collect(),
                    })
                }
                _ => Some(PermutationResult {
                    domain: perm,
                    resolves: false,
                    ips: vec![],
                }),
            }
        }));
    }

    let mut results = Vec::new();
    let mut resolve_count = 0;
    for h in handles {
        if let Ok(Some(r)) = h.await {
            if r.resolves { resolve_count += 1; }
            results.push(r);
        }
    }

    let registered: Vec<PermutationResult> = results.iter()
        .filter(|r| r.resolves)
        .cloned()
        .collect();

    DomainPermutationResult {
        domain: domain.clone(),
        permutations_generated: permutations.len(),
        registered_count: resolve_count,
        total_checked: results.len(),
        registered,
        tld_swaps_tested: TLD_SWAPS.len(),
    }
}
