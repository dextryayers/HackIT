use std::env;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::Resolver;
use std::time::Duration;
use rayon::prelude::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: subdomain_resolver <domain1,domain2,...>");
        std::process::exit(1);
    }

    let domains_str = &args[1];
    let domain_list: Vec<&str> = domains_str.split(',').collect();

    let mut config = ResolverConfig::new();
    if let Ok(ip) = "1.1.1.1:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "8.8.8.8:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "9.9.9.9:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "1.0.0.1:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 2;
    opts.use_hosts_file = false;

    let resolver = Resolver::new(config, opts).unwrap_or_else(|_| {
        Resolver::from_system_conf().unwrap()
    });

    let results: Vec<String> = domain_list.par_iter().map(|&domain| {
        let domain_trimmed = domain.trim();
        let mut ips = Vec::new();
        let mut cname = String::new();

        if let Ok(lookup) = resolver.lookup_ip(domain_trimmed) {
            for ip in lookup.iter() {
                ips.push(ip.to_string());
            }
        }

        if let Ok(lookup) = resolver.lookup(domain_trimmed, RecordType::CNAME) {
            if let Some(c) = lookup.iter().filter_map(|r| r.as_cname()).next() {
                cname = c.to_string().trim_end_matches('.').to_string();
            }
        }

        let result = serde_json::json!({
            "subdomain": domain_trimmed,
            "ips": ips,
            "cname": cname,
            "resolved": !ips.is_empty()
        });
        format!("RESULT:{}", result)
    }).collect();

    for r in &results {
        println!("{}", r);
    }

    let final_json = serde_json::json!({
        "total": domain_list.len(),
        "resolved": results.iter().filter(|r| r.contains("\"resolved\":true")).count()
    });
    println!("FINAL:{}", final_json);
}
