use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubdomainInfo {
    pub subdomain: String,
    pub ip: String,
    pub status: String,
}

pub async fn enumerate_subdomains(domain: &str) -> Vec<SubdomainInfo> {
    let mut results = Vec::new();
    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return results,
    };

    let common_prefixes = vec![
        "www", "dev", "staging", "api", "v1", "v2", "blog", "shop", "m", 
        "mail", "smtp", "pop", "ns1", "ns2", "admin", "portal", "dashboard",
        "test", "beta", "old", "new", "vpn", "remote", "support", "help",
        "billing", "account", "docs", "git", "gitlab", "jenkins", "docker",
        "kube", "k8s", "cdn", "assets", "static", "images", "media", "video",
        "app", "mobile", "auth", "login", "secure", "proxy", "lb", "db", "sql",
    ];

    for prefix in common_prefixes {
        let subdomain = format!("{}.{}", prefix, domain);
        if let Ok(lookup) = resolver.lookup_ip(&subdomain).await {
            if let Some(ip) = lookup.iter().next() {
                results.push(SubdomainInfo {
                    subdomain: subdomain.clone(),
                    ip: ip.to_string(),
                    status: "Active".to_string(),
                });
            }
        }
    }

    results
}
