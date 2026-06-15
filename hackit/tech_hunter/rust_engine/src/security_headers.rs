use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderAudit {
    pub score: i32,
    pub grade: String,
    pub hsts: HeaderCheck,
    pub csp: HeaderCheck,
    pub xfo: HeaderCheck,
    pub xcto: HeaderCheck,
    pub rp: HeaderCheck,
    pub permissions_policy: HeaderCheck,
    pub cache_control: HeaderCheck,
    pub expect_ct: HeaderCheck,
    pub xss_protection: HeaderCheck,
    pub cross_origin: CrossOriginCheck,
    pub cookie_checks: CookieChecks,
    pub recommendations: Vec<String>,
    pub raw_headers: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HeaderCheck {
    pub present: bool,
    pub value: String,
    pub valid: bool,
    pub notes: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CrossOriginCheck {
    pub cors_enabled: bool,
    pub allow_origin_wildcard: bool,
    pub allow_credentials: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CookieChecks {
    pub http_only: bool,
    pub secure: bool,
    pub same_site: String,
}

fn parse_headers(headers_raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in headers_raw.lines() {
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_lowercase();
            let value = line[pos + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    map
}

fn check_header(headers: &HashMap<String, String>, name: &str) -> HeaderCheck {
    let name_lower = name.to_lowercase();
    let present = headers.contains_key(&name_lower);
    let value = headers.get(&name_lower).cloned().unwrap_or_default();
    let valid = !value.is_empty();

    let notes = match name_lower.as_str() {
        "strict-transport-security" => {
            if !present { "Missing - users vulnerable to SSL stripping".into() }
            else if value.contains("max-age=0") { "Present but max-age=0 (disabled)".into() }
            else if value.contains("max-age=") {
                let mut note = "Configured".to_string();
                if value.contains("includeSubDomains") { note += ", includes subdomains"; }
                if value.contains("preload") { note += ", preload ready"; }
                note
            } else { "Present but missing max-age".into() }
        },
        "content-security-policy" => {
            if !present { "Missing - XSS mitigation reduced".into() }
            else if value.contains("unsafe-inline") { "Present but uses unsafe-inline".into() }
            else if value.contains("unsafe-eval") { "Present but allows eval()".into() }
            else { "Configured".into() }
        },
        "x-frame-options" => {
            if !present { "Missing - clickjacking risk".into() }
            else if value.to_uppercase() == "DENY" { "DENY - prevents all framing".into() }
            else if value.to_uppercase() == "SAMEORIGIN" { "SAMEORIGIN - allows same-origin framing".into() }
            else if value.starts_with("ALLOW-FROM") { "ALLOW-FROM - limited protection".into() }
            else { "Present but unusual value".into() }
        },
        "x-content-type-options" => {
            if !present { "Missing - MIME sniffing risk".into() }
            else if value.to_lowercase() == "nosniff" { "nosniff - prevents MIME sniffing".into() }
            else { "Present but unusual value".into() }
        },
        "referrer-policy" => {
            if !present { "Missing - referrer info leakage possible".into() }
            else { format!("Configured: {}", value) }
        },
        "permissions-policy" | "feature-policy" => {
            if !present { "Missing - no feature control".into() }
            else { "Configured".into() }
        },
        "cache-control" => {
            if !present { "Missing - caching behavior undefined".into() }
            else if value.contains("no-store") { "no-store - sensitive data not cached".into() }
            else { format!("Set to: {}", value) }
        },
        "expect-ct" => {
            if !present { "Not configured".into() }
            else { "Configured".into() }
        },
        "x-xss-protection" => {
            if !present { "Not present (modern browsers ignore this)".into() }
            else if value.contains("1; mode=block") { "1; mode=block".into() }
            else { "Present".into() }
        },
        _ => {
            if present { "Present".into() } else { "Not present".into() }
        }
    };

    HeaderCheck { present, value, valid, notes }
}

pub fn get_audit_json(headers_raw: &str) -> String {
    let headers = parse_headers(headers_raw);

    let hsts = check_header(&headers, "Strict-Transport-Security");
    let csp = check_header(&headers, "Content-Security-Policy");
    let xfo = check_header(&headers, "X-Frame-Options");
    let xcto = check_header(&headers, "X-Content-Type-Options");
    let rp = check_header(&headers, "Referrer-Policy");
    let permissions_policy = check_header(&headers, "Permissions-Policy");
    let cache_control = check_header(&headers, "Cache-Control");
    let expect_ct = check_header(&headers, "Expect-CT");
    let xss_protection = check_header(&headers, "X-XSS-Protection");

    let cors_enabled = headers.contains_key("access-control-allow-origin");
    let allow_origin_wildcard = headers.get("access-control-allow-origin")
        .map(|v| v.trim() == "*").unwrap_or(false);
    let allow_credentials = headers.contains_key("access-control-allow-credentials");

    let cookie_str = headers.values()
        .find(|v| v.to_lowercase().contains("set-cookie"))
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let cookie_checks = CookieChecks {
        http_only: cookie_str.contains("httponly"),
        secure: cookie_str.contains("secure"),
        same_site: {
            if cookie_str.contains("samesite=strict") { "Strict".into() }
            else if cookie_str.contains("samesite=lax") { "Lax".into() }
            else if cookie_str.contains("samesite=none") { "None".into() }
            else { "Not Set".into() }
        },
    };

    let mut score = 0i32;
    if hsts.present && hsts.value.contains("max-age=") { score += 20; }
    if csp.present { score += 25; }
    if xfo.present && (xfo.value.to_uppercase() == "DENY" || xfo.value.to_uppercase() == "SAMEORIGIN") { score += 15; }
    if xcto.present && xcto.value.to_lowercase() == "nosniff" { score += 10; }
    if rp.present { score += 10; }
    if permissions_policy.present { score += 5; }
    if cache_control.present && cache_control.value.contains("no-store") { score += 5; }
    if cookie_checks.http_only { score += 5; }
    if cookie_checks.secure { score += 5; }

    let grade = match score {
        90..=100 => "A+",
        75..=89 => "A",
        60..=74 => "B",
        45..=59 => "C",
        30..=44 => "D",
        _ => "F",
    }.to_string();

    let mut recommendations: Vec<String> = Vec::new();
    if !hsts.present { recommendations.push("Enable Strict-Transport-Security with max-age >= 31536000".into()); }
    if !csp.present { recommendations.push("Add Content-Security-Policy header to prevent XSS".into()); }
    if !xfo.present { recommendations.push("Add X-Frame-Options: DENY to prevent clickjacking".into()); }
    if !xcto.present { recommendations.push("Add X-Content-Type-Options: nosniff".into()); }
    if !rp.present { recommendations.push("Add Referrer-Policy: strict-origin-when-cross-origin".into()); }
    if allow_origin_wildcard && allow_credentials {
        recommendations.push("CRITICAL: CORS with wildcard origin AND credentials enabled!".into());
    }

    let result = HeaderAudit {
        score, grade, hsts, csp, xfo, xcto, rp,
        permissions_policy, cache_control, expect_ct, xss_protection,
        cross_origin: CrossOriginCheck { cors_enabled, allow_origin_wildcard, allow_credentials },
        cookie_checks,
        recommendations,
        raw_headers: headers,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
