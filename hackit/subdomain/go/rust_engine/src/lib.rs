use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use trust_dns_resolver::proto::rr::RecordType;
use reqwest::blocking::Client;
use serde::Deserialize;
use once_cell::sync::Lazy;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct Signature {
    platform: String,
    cname: Vec<String>,
    fingerprints: Vec<String>,
    vulnerable: bool,
}

static SIGNATURES: Lazy<Vec<Signature>> = Lazy::new(|| {
    let data = r#"[
        {
            "platform": "GitHub Pages",
            "cname": ["github.io"],
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
            "cname": ["azurewebsites.net", "cloudapp.net", "azureedge.net"],
            "fingerprints": ["404 Not Found", "The resource you are looking for has been removed", "Web Site not found"],
            "vulnerable": true
        },
        {
            "platform": "AWS S3",
            "cname": ["s3.amazonaws.com", "s3-website"],
            "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
            "vulnerable": true
        },
        {
            "platform": "Shopify",
            "cname": ["myshopify.com"],
            "fingerprints": ["Sorry, this shop is currently unavailable", "Only one step left!"],
            "vulnerable": true
        },
        {
            "platform": "Zendesk",
            "cname": ["zendesk.com"],
            "fingerprints": ["Help Center Closed", "No help center found"],
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

fn perform_advanced_subdomain_check(domain: &str) -> String {
    let resolver = match Resolver::new(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(r) => r,
        Err(_) => return "ERROR:Failed to init resolver".to_string(),
    };

    // 1. CNAME Lookup using generic lookup method
    let cname = match resolver.lookup(domain, RecordType::CNAME) {
        Ok(lookup) => {
            lookup.iter()
                .filter_map(|r| r.as_cname())
                .next()
                .map(|c| c.to_string().trim_end_matches('.').to_string())
                .unwrap_or_default()
        },
        Err(_) => String::new(),
    };

    if cname.is_empty() {
        return "SAFE:No CNAME found".to_string();
    }

    // 2. Signature Matching
    for sig in SIGNATURES.iter() {
        let matches_cname = sig.cname.iter().any(|c| cname.contains(c));
        
        if matches_cname {
            // 3. HTTP Verification (Checking fingerprints)
            if verify_http_takeover(domain, &sig.fingerprints) {
                return format!("VULNERABLE:{} Subdomain Takeover possible on {} (CNAME: {})", sig.platform, domain, cname);
            }
            
            // If CNAME matches but fingerprints don't, check if CNAME itself resolves
            match resolver.lookup_ip(&cname) {
                Ok(_) => return format!("INFO:CNAME found to {} ({}) - Likely claimed but check manually", cname, sig.platform),
                Err(_) => return format!("VULNERABLE:{} Subdomain Takeover likely (CNAME {} does not resolve)", sig.platform, cname),
            }
        }
    }

    format!("INFO:CNAME found to {} - No known signature matched", cname)
}

fn verify_http_takeover(domain: &str, fingerprints: &[String]) -> bool {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
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
