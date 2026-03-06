use std::collections::HashMap;

pub struct WAFInfo {
    pub name: String,
    pub detected: bool,
}

pub fn detect_waf_cdn(headers: &HashMap<String, String>) -> Vec<String> {
    let mut detected = Vec::new();
    
    let waf_signatures = vec![
        ("Cloudflare", vec!["cf-ray", "cf-cache-status", "__cfduid", "cf-connecting-ip"]),
        ("Akamai", vec!["x-akamai-transformed", "akamai-origin-hop", "x-akamai-session-info"]),
        ("AWS CloudFront", vec!["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-id"]),
        ("AWS WAF", vec!["x-amzn-requestid", "awselb/2.0"]),
        ("Imperva", vec!["x-iinfo", "incap_ses", "visid_incap"]),
        ("Sucuri", vec!["x-sucuri-id", "x-sucuri-cache"]),
        ("ModSecurity", vec!["x-mod-security"]),
        ("F5 BIG-IP", vec!["x-cbi-node", "ts01813138", "mr_session"]),
        ("Barracuda", vec!["barra_counter_session", "bniproxy_session"]),
        ("Citrix NetScaler", vec!["ns_af", "citrix_ns_id", "ns_session"]),
        ("Fastly", vec!["x-fastly-request-id", "fastly-reassign", "x-served-by"]),
        ("StackPath", vec!["x-sp-url", "x-sp-endpoint"]),
        ("FortiWeb", vec!["fortiwafsid"]),
        ("Radware AppWall", vec!["X-SL-CompContext"]),
        ("Microsoft Azure Front Door", vec!["x-azure-ref", "x-fd-intid"]),
        ("Google Cloud Load Balancer", vec!["x-goog-metageneration", "x-goog-generation"]),
        ("Incapula", vec!["incap_ses", "visid_incap"]),
        ("Varnish", vec!["x-varnish", "via"]),
        ("Squid", vec!["x-squid-error"]),
        ("Nginx Plus", vec!["x-ngx-conf-id"]),
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
