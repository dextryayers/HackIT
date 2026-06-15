use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct WAFResult {
    pub provider: String,
    pub waf_type: String,
    pub detected: bool,
    pub confidence: i32,
    pub signatures: Vec<String>,
}

struct WAFSignature {
    name: &'static str,
    headers: &'static [&'static str],
    type_name: &'static str,
    confidence: i32,
}

const WAF_SIGNATURES: &[WAFSignature] = &[
    WAFSignature { name: "Cloudflare",     headers: &["cf-ray", "cloudflare", "__cfduid", "cf-cache-status", "cf-request-id"], type_name: "Cloudflare WAF/CDN", confidence: 95 },
    WAFSignature { name: "Akamai",     headers: &["x-akamai", "akamai", "x-akamai-transformed", "akamai-", "x-akamai-request-id"], type_name: "Akamai Kona Site Defender", confidence: 90 },
    WAFSignature { name: "AWS WAF",     headers: &["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-trace-id", "x-amzn-requestid", "cloudfront"], type_name: "AWS WAF / CloudFront", confidence: 85 },
    WAFSignature { name: "Sucuri",     headers: &["x-sucuri", "x-sucuri-cache", "x-sucuri-id"], type_name: "Sucuri Firewall", confidence: 90 },
    WAFSignature { name: "Imperva",     headers: &["x-request-id", "x-cdn", "x-iinfo", "incapsula", "visid_incap"], type_name: "Imperva SecureSphere / Incapsula", confidence: 85 },
    WAFSignature { name: "F5 BIG-IP",     headers: &["x-application", "x-request-uri", "x-client-ip", "bigip", "big-ip", "x-forwarded-server"], type_name: "F5 BIG-IP ASM", confidence: 80 },
    WAFSignature { name: "Barracuda",     headers: &["x-barracuda", "barracuda"], type_name: "Barracuda WAF", confidence: 80 },
    WAFSignature { name: "ModSecurity",     headers: &["mod_security", "modsecurity", "NOYB"], type_name: "ModSecurity (OWASP CRS)", confidence: 75 },
    WAFSignature { name: "Comodo",     headers: &["comodo", "x-cwaf"], type_name: "Comodo cWatch WAF", confidence: 75 },
    WAFSignature { name: "Citrix",     headers: &["citrix", "ns-", "x-ns"], type_name: "Citrix NetScaler / ADC", confidence: 70 },
    WAFSignature { name: "Fortinet",     headers: &["fortinet", "fortiweb", "x-fortinet"], type_name: "Fortinet FortiWeb", confidence: 70 },
    WAFSignature { name: "Radware",     headers: &["radware", "x-radware", "x-cdn"], type_name: "Radware AppWall", confidence: 70 },
    WAFSignature { name: "StackPath",     headers: &["stackpath", "x-stackpath"], type_name: "StackPath WAF", confidence: 70 },
    WAFSignature { name: "Varnish",     headers: &["x-varnish", "via", "x-cache"], type_name: "Varnish Cache (+WAF)", confidence: 60 },
    WAFSignature { name: "Naxsi",     headers: &["naxsi", "x-naxsi"], type_name: "NAXSI WAF", confidence: 65 },
    WAFSignature { name: "WebKnight",     headers: &["webknight", "x-webknight"], type_name: "WebKnight (AQTRONIX)", confidence: 70 },
    WAFSignature { name: "Armor",     headers: &["armor", "x-armor"], type_name: "Armor Defense WAF", confidence: 60 },
    WAFSignature { name: "Wordfence",     headers: &["wordfence", "x-wordfence"], type_name: "Wordfence (WordPress WAF)", confidence: 70 },
    WAFSignature { name: "Reblaze",     headers: &["reblaze", "x-reblaze"], type_name: "Reblaze WAF", confidence: 60 },
    WAFSignature { name: "Qrator",     headers: &["qrator", "x-qrator"], type_name: "Qrator WAF/CDN", confidence: 60 },
    WAFSignature { name: "CrawlProtect",     headers: &["crawlprotect", "x-crawlprotect"], type_name: "CrawlProtect", confidence: 50 },
    WAFSignature { name: "SafeLine",     headers: &["safeline", "x-safeline"], type_name: "SafeLine WAF", confidence: 50 },
    WAFSignature { name: "Greywizard",     headers: &["greywizard", "x-greywizard"], type_name: "Greywizard WAF", confidence: 50 },
    WAFSignature { name: "Profense",     headers: &["profense", "x-profense"], type_name: "Profense WAF", confidence: 60 },
    WAFSignature { name: "Alert Logic",     headers: &["alert-logic", "x-alertlogic"], type_name: "Alert Logic WAF", confidence: 55 },
    WAFSignature { name: "Approach",     headers: &["approach", "x-approach"], type_name: "Approach WAF", confidence: 50 },
    WAFSignature { name: "DenyALL",     headers: &["denyall", "x-denyall"], type_name: "DenyALL WAF (Robezilla)", confidence: 55 },
    WAFSignature { name: "XLabs",     headers: &["xlabs", "x-xlabs"], type_name: "XLabs Security WAF", confidence: 50 },
    WAFSignature { name: "LiteSpeed",     headers: &["litespeed", "x-litespeed"], type_name: "LiteSpeed Web Server + WAF", confidence: 65 },
    WAFSignature { name: "BlockDoS",     headers: &["blockdos", "x-blockdos"], type_name: "BlockDoS WAF", confidence: 50 },
];

pub fn get_waf_json(headers_raw: &str) -> String {
    let headers_lower = headers_raw.to_lowercase();
    let mut best_match: Option<&WAFSignature> = None;
    let mut best_score = 0i32;
    let mut matched_signatures: Vec<String> = Vec::new();

    for sig in WAF_SIGNATURES {
        let mut score = 0i32;
        let mut found_headers: Vec<String> = Vec::new();
        for h in sig.headers {
            if headers_lower.contains(h) {
                score += 100 / sig.headers.len() as i32;
                found_headers.push(h.to_string());
            }
        }
        if score > 0 && !found_headers.is_empty() {
            matched_signatures.push(format!("{} ({} hits)", sig.name, found_headers.len()));
        }
        if score > best_score {
            best_score = score;
            best_match = Some(sig);
        }
    }

    let (provider, waf_type, detected, confidence) = match best_match {
        Some(sig) => {
            let conf = sig.confidence.min(95);
            (sig.name.to_string(), sig.type_name.to_string(), true, conf as i32)
        },
        None => ("Direct / Unknown".to_string(), "None".to_string(), false, 0),
    };

    let result = WAFResult {
        provider, waf_type, detected, confidence,
        signatures: matched_signatures,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
