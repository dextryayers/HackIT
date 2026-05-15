use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct WAFResult {
    pub provider: String,
    pub waf_type: String,
    pub detected: bool,
}

pub fn get_waf_json(headers_raw: &str) -> String {
    let mut provider = "Direct / Unknown".to_string();
    let mut waf_type = "None".to_string();
    let mut detected = false;

    if headers_raw.contains("cf-ray") || headers_raw.contains("cloudflare") {
        provider = "Cloudflare".to_string();
        waf_type = "Cloudflare WAF".to_string();
        detected = true;
    } else if headers_raw.contains("x-akamai") || headers_raw.contains("akamai") {
        provider = "Akamai".to_string();
        waf_type = "Kona Site Defender".to_string();
        detected = true;
    } else if headers_raw.contains("x-amz-cf-id") {
        provider = "AWS CloudFront".to_string();
        waf_type = "AWS WAF".to_string();
        detected = true;
    } else if headers_raw.contains("x-sucuri") {
        provider = "Sucuri".to_string();
        waf_type = "Sucuri Firewall".to_string();
        detected = true;
    }

    let result = WAFResult { provider, waf_type, detected };
    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
