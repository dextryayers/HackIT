use std::collections::HashMap;

pub struct WAFInfo {
    pub name: String,
    pub detected: bool,
}

pub fn detect_waf_cdn(headers: &HashMap<String, String>) -> Vec<String> {
    let mut detected = Vec::new();
    
    let waf_signatures = vec![
        ("Cloudflare", vec!["cf-ray", "cf-cache-status", "__cfduid"]),
        ("Akamai", vec!["x-akamai-transformed", "akamai-origin-hop"]),
        ("AWS WAF", vec!["x-amzn-requestid", "x-amz-cf-id"]),
        ("Imperva", vec!["x-iinfo", "incap_ses"]),
        ("Sucuri", vec!["x-sucuri-id", "x-sucuri-cache"]),
        ("ModSecurity", vec!["x-mod-security"]),
        ("F5 BIG-IP", vec!["x-cbi-node", "ts01813138"]),
        ("Barracuda", vec!["barra_counter_session", "bniproxy_session"]),
        ("Citrix NetScaler", vec!["ns_af", "citrix_ns_id"]),
        ("Cloudfront", vec!["x-amz-cf-id", "x-amz-cf-pop"]),
        ("Fastly", vec!["x-fastly-request-id", "fastly-reassign"]),
        ("StackPath", vec!["x-sp-url", "x-sp-endpoint"]),
        ("FortiWeb", vec!["fortiwafsid"]),
        ("Radware AppWall", vec!["X-SL-CompContext"]),
        ("Microsoft Azure WAF", vec!["x-ms-request-id"]),
        ("Google Cloud WAF", vec!["x-goog-metageneration"]),
    ];

    for (name, sigs) in waf_signatures {
        for sig in sigs {
            for (header_name, _) in headers {
                if header_name.to_lowercase() == sig.to_lowercase() {
                    detected.push(name.to_string());
                    break;
                }
            }
            if detected.last().map(|s| s == name).unwrap_or(false) {
                break;
            }
        }
    }

    detected
}
