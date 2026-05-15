use std::collections::HashMap;

pub fn detect_waf(headers: &HashMap<String, String>) -> Vec<String> {
    let mut detected = Vec::new();
    
    let signatures = vec![
        ("Cloudflare", vec!["cf-ray", "cf-cache-status", "server:cloudflare"]),
        ("Akamai", vec!["x-akamai-transformed", "server:akamaighost"]),
        ("AWS WAF", vec!["x-amzn-requestid", "server:awselb/2.0"]),
        ("Imperva", vec!["x-iinfo", "incap_ses"]),
    ];

    for (name, sigs) in signatures {
        for sig in sigs {
            if sig.contains(':') {
                let parts: Vec<&str> = sig.split(':').collect();
                if let Some(val) = headers.get(parts[0]) {
                    if val.to_lowercase().contains(parts[1]) {
                        detected.push(name.to_string());
                        break;
                    }
                }
            } else {
                if headers.contains_key(sig) {
                    detected.push(name.to_string());
                    break;
                }
            }
        }
    }

    detected
}
