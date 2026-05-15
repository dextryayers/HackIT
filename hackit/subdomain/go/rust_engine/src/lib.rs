use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use reqwest::blocking::Client;
use serde::Deserialize;
use once_cell::sync::Lazy;
use std::time::Duration;
use rayon::prelude::*;

mod providers;
pub use providers::*;

/**
 * HackIT Industrial Subdomain Recon Engine (Rust-Core v3.5)
 * Multi-Engine Orchestration for Subdomain Takeover & High-Speed DNS
 */

#[derive(Debug, Deserialize)]
struct Signature {
    platform: String,
    cname: Vec<String>,
    fingerprints: Vec<String>,
    vulnerable: bool,
}

// Expanded Professional Takeover Signatures
static SIGNATURES: Lazy<Vec<Signature>> = Lazy::new(|| {
    let data = r#"[
        {
            "platform": "GitHub Pages",
            "cname": ["github.io", "github.com"],
            "fingerprints": ["There isn't a GitHub Pages site here", "For root domains (example.com), you must create a CNAME record"],
            "vulnerable": true
        },
        {
            "platform": "Heroku",
            "cname": ["herokudns.com", "herokuapp.com"],
            "fingerprints": ["herokuhosted.com/exceptions/nosuchapp.html", "no such app", "<title>No such app</title>"],
            "vulnerable": true
        },
        {
            "platform": "Azure",
            "cname": ["azurewebsites.net", "cloudapp.net", "azureedge.net", "windows.net"],
            "fingerprints": ["404 Not Found", "The resource you are looking for has been removed", "Web Site not found", "404 - Web Site not found"],
            "vulnerable": true
        },
        {
            "platform": "AWS S3",
            "cname": ["s3.amazonaws.com", "s3-website", "s3.eu-central-1.amazonaws.com"],
            "fingerprints": ["The specified bucket does not exist", "NoSuchBucket", "Bucket name is not valid"],
            "vulnerable": true
        },
        {
            "platform": "Shopify",
            "cname": ["myshopify.com"],
            "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!", "This shop is currently unavailable"],
            "vulnerable": true
        },
        {
            "platform": "Zendesk",
            "cname": ["zendesk.com"],
            "fingerprints": ["Help Center Closed", "No help center found", "this help center no longer exists"],
            "vulnerable": true
        },
        {
            "platform": "Ghost",
            "cname": ["ghost.io"],
            "fingerprints": ["The thing you were looking for is no longer here", "Ghost - The professional publishing platform"],
            "vulnerable": true
        },
        {
            "platform": "WPEngine",
            "cname": ["wpengine.com"],
            "fingerprints": ["The site you were looking for could not be found"],
            "vulnerable": true
        },
        {
            "platform": "CloudFront",
            "cname": ["cloudfront.net"],
            "fingerprints": ["Bad request. We can't connect to the server for this app or website at this time."],
            "vulnerable": true
        },
        {
            "platform": "Netlify",
            "cname": ["netlify.app", "netlify.com"],
            "fingerprints": ["Not Found", "404 not found"],
            "vulnerable": true
        }
    ]"#;
    serde_json::from_str(data).unwrap_or_else(|_| vec![])
});

#[unsafe(no_mangle)]
pub extern "C" fn rust_check_subdomain_takeover(domain: *const c_char) -> *mut c_char {
    if domain.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(domain) };
    let domain_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = perform_advanced_subdomain_check(domain_str);
    
    let c_string = CString::new(result).unwrap();
    c_string.into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_resolve_dns_batch(domains: *const c_char) -> *mut c_char {
    if domains.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(domains) };
    let domains_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let domain_list: Vec<&str> = domains_str.split(',').collect();
    
    // Industrial Resolver Configuration (Massive Parallelism)
    let mut config = ResolverConfig::new();
    if let Ok(ip) = "1.1.1.1:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "8.8.8.8:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "9.9.9.9:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }
    if let Ok(ip) = "1.0.0.1:53".parse() { config.add_name_server(NameServerConfig::new(ip, Protocol::Udp)); }

    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(3);
    opts.attempts = 3; 
    opts.use_hosts_file = false; 

    let resolver = Resolver::new(config, opts).unwrap_or_else(|_| {
        Resolver::from_system_conf().unwrap_or_else(|_| Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap())
    });

    let results: Vec<String> = domain_list.par_iter().map(|&domain| {
        let mut all_ips = Vec::new();
        
        // Accurate Dual-Stack Resolution (IPv4 + IPv6)
        if let Ok(lookup) = resolver.lookup_ip(domain) {
            for ip in lookup.iter() {
                all_ips.push(ip.to_string());
            }
        }

        if all_ips.is_empty() {
            format!("{}:NOT_FOUND", domain)
        } else {
            all_ips.sort();
            all_ips.dedup();
            format!("{}:{}", domain, all_ips.join(";"))
        }
    }).collect();

    let final_result = results.join("|");
    CString::new(final_result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_resolve_dns(domain: *const c_char) -> *mut c_char {
    if domain.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = unsafe { CStr::from_ptr(domain) };
    let domain_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return CString::new("ERROR").unwrap().into_raw(),
    };

    match resolver.lookup_ip(domain_str) {
        Ok(lookup) => {
            let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
            let result = ips.join(",");
            CString::new(result).unwrap().into_raw()
        },
        Err(_) => CString::new("NOT_FOUND").unwrap().into_raw(),
    }
}

fn perform_advanced_subdomain_check(domain: &str) -> String {
    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return "ERROR:Failed to init resolver".to_string(),
    };

    // Recursive CNAME Forensic Tracking
    let mut current_target = domain.to_string();
    let mut cname_chain = Vec::new();
    
    for _ in 0..3 {
        match resolver.lookup(&current_target, RecordType::CNAME) {
            Ok(lookup) => {
                if let Some(c) = lookup.iter().filter_map(|r| r.as_cname()).next() {
                    let c_str = c.to_string().trim_end_matches('.').to_string();
                    if c_str == current_target { break; }
                    cname_chain.push(c_str.clone());
                    current_target = c_str;
                } else { break; }
            },
            Err(_) => break,
        }
    }

    if cname_chain.is_empty() {
        return "SAFE:No CNAME chain detected".to_string();
    }

    let final_cname = cname_chain.last().unwrap();

    // Deep Signature Audit
    for sig in SIGNATURES.iter() {
        let matches_cname = sig.cname.iter().any(|c| final_cname.contains(c));
        
        if matches_cname {
            if verify_http_takeover(domain, &sig.fingerprints) {
                return format!("VULNERABLE:{} Takeover possible on {} (CNAME: {})", sig.platform, domain, final_cname);
            }
            
            // If CNAME matches but fingerprints don't, check if CNAME itself resolves
            match resolver.lookup_ip(final_cname) {
                Ok(_) => return format!("INFO:CNAME chain found to {} ({}) - Likely claimed", final_cname, sig.platform),
                Err(_) => return format!("VULNERABLE:{} Takeover likely (CNAME {} is dangling)", sig.platform, final_cname),
            }
        }
    }

    format!("INFO:CNAME chain found to {} - No signature matched", final_cname)
}

fn verify_http_takeover(domain: &str, fingerprints: &[String]) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_else(|_| Client::new());

    let protocols = ["https://", "http://"];
    
    for proto in protocols {
        let url = format!("{}{}", proto, domain);
        if let Ok(resp) = client.get(&url).send() {
            if let Ok(body) = resp.text() {
                for fp in fingerprints {
                    if body.contains(fp) {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}
