use crate::common::{WafResult, build_client};

pub async fn detect(url: &str) -> WafResult {
    let full_url = if url.starts_with("http") { url.to_string() } else { format!("https://{}", url) };
    let mut indicators = Vec::new();
    let mut waf: Option<String> = None;
    let mut cdn: Option<String> = None;
    let client = match build_client(10) { Some(c) => c, None => return WafResult { url: full_url, waf: None, cdn: None, detected: false, indicators } };
    if let Ok(resp) = client.get(&full_url).send().await {
        for (name, value) in resp.headers().iter() {
            let n = name.as_str(); let v = value.to_str().unwrap_or("");
            match n {
                "server" => {
                    if v.contains("cloudflare") { cdn = Some("Cloudflare".into()); waf = Some("Cloudflare".into()); }
                    else if v.contains("Akamai") { cdn = Some("Akamai".into()); waf = Some("Akamai".into()); }
                    else if v.contains("CloudFront") { cdn = Some("AWS CloudFront".into()); }
                }
                "cf-ray" => { cdn = Some("Cloudflare".into()); indicators.push("cf-ray header".into()); }
                "x-sucuri-id" | "x-sucuri-cache" => { waf = Some("Sucuri".into()); indicators.push("Sucuri headers".into()); }
                "x-cdn" => { cdn = Some(v.to_string()); }
                "x-amz-cf-id" => { cdn = Some("AWS CloudFront".into()); }
                "x-akamai-transformed" => { cdn = Some("Akamai".into()); indicators.push("Akamai transformed header".into()); }
                "x-fastly-request-id" => { cdn = Some("Fastly".into()); }
                "x-powered-by" => { if v.contains("AWS Lambda") { cdn = Some("AWS Lambda".into()); } }
                "x-frame-options" => { if v == "DENY" || v == "SAMEORIGIN" { indicators.push(format!("X-Frame-Options: {}", v)); }}
                "strict-transport-security" => { indicators.push("HSTS enabled".into()); }
                _ => {}
            }
        }
    }
    let malicious_url = format!("{}/?id=1' OR '1'='1", full_url.trim_end_matches('/'));
    if let Ok(resp) = client.get(&malicious_url).send().await {
        if resp.headers().get("cf-ray").is_some() { waf.get_or_insert("Cloudflare".into()); indicators.push("Cloudflare WAF responded to malicious request".into()); }
        if resp.status().as_u16() == 406 || resp.status().as_u16() == 403 || resp.status().as_u16() == 999 {
            indicators.push(format!("WAF blocked request (HTTP {})", resp.status()));
            if waf.is_none() { waf = Some("Generic WAF".into()); }
        }
    }
    let detected = waf.is_some() || cdn.is_some() || !indicators.is_empty();
    if waf.is_none() && cdn.is_some() { waf = cdn.clone(); }
    WafResult { url: full_url, waf, cdn, detected, indicators }
}
