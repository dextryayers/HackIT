use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use ureq::{Agent, AgentBuilder};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <url>", args[0]);
        std::process::exit(1);
    }

    let target = normalize_url(&args[1]);
    let agent = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
        .redirects(0)
        .build();

    let resp = match agent.get(&target)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .set("Accept", "text/html,*/*")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            emit_json("error", json!({"message": format!("Request failed: {}", e)}));
            return;
        }
    };

    let status = resp.status();
    let mut findings: Vec<Value> = Vec::new();
    let mut policy_report: Vec<Value> = Vec::new();
    let mut csp_directives: Vec<Value> = Vec::new();
    let mut cors_details: Value = json!(null);
    let mut cookie_details: Vec<Value> = Vec::new();

    // Collect all headers
    let mut headers: HashMap<String, String> = HashMap::new();
    for name in resp.headers_names() {
        if let Some(val) = resp.header(&name) {
            headers.insert(name.to_lowercase(), val.to_string());
        }
    }

    // === CSP ANALYSIS ===
    if let Some(csp) = headers.get("content-security-policy") {
        csp_directives = parse_csp(csp);
        analyze_csp(&csp_directives, &mut findings);

        // CSP-Tested endpoints via report-uri/report-to
        for d in &csp_directives {
            if let Some(name) = d.get("directive").and_then(|v| v.as_str()) {
                if name == "report-uri" || name == "report-to" {
                    policy_report.push(json!({
                        "type": "csp_reporting",
                        "directive": name,
                        "value": d.get("value"),
                    }));
                }
            }
        }
    } else {
        findings.push(policy_finding("missing", "CSP",
            "Content-Security-Policy header is missing",
            "Add CSP to prevent XSS and injection attacks", "High"));
    }

    // === CORS ANALYSIS ===
    cors_details = analyze_cors(&headers, &agent, &target, &mut findings);

    // === COOP / COEP ANALYSIS ===
    analyze_cross_origin_isolation(&headers, &mut findings);

    // === COOKIE ANALYSIS ===
    if let Some(cookies) = headers.get("set-cookie") {
        // Set-Cookie may have multiple values joined with commas
        let cookie_strs = split_cookies(cookies);
        for c in &cookie_strs {
            let detail = analyze_cookie(c, &mut findings);
            cookie_details.push(detail);
        }
    }

    // === CACHE ANALYSIS ===
    analyze_cache(&headers, &mut findings);

    // === PERMISSIONS-POLICY ANALYSIS ===
    if let Some(pp) = headers.get("permissions-policy") {
        analyze_permissions_policy(pp, &mut findings);
    } else {
        findings.push(policy_finding("info", "Permissions-Policy",
            "Permissions-Policy header is missing",
            "Add Permissions-Policy to restrict browser feature access", "Info"));
    }

    // Summary
    emit_json("summary", json!({
        "target": target, "status": status,
        "csp_directives": csp_directives.len(),
        "cookies": cookie_details.len(),
        "findings": findings.len(),
        "cors_configured": cors_details != json!(null),
    }));

    if !csp_directives.is_empty() {
        for d in &csp_directives { emit_json("csp_directive", d.clone()); }
    }
    if cors_details != json!(null) {
        emit_json("cors_detail", cors_details);
    }
    for c in &cookie_details { emit_json("cookie_detail", c.clone()); }
    for f in &findings { emit_json("finding", f.clone()); }
    if !policy_report.is_empty() {
        for p in &policy_report { emit_json("policy_report", p.clone()); }
    }
    emit_json("policy_done", json!({"status": "ok"}));
}

// === CSP PARSER ===
fn parse_csp(csp: &str) -> Vec<Value> {
    let mut directives = Vec::new();
    for part in csp.split(';') {
        let part = part.trim();
        if part.is_empty() { continue; }
        let mut words = part.split_whitespace();
        let name = words.next().unwrap_or("").to_lowercase();
        let sources: Vec<String> = words.map(|s| s.to_string()).collect();
        directives.push(json!({
            "directive": name, "sources": sources,
            "source_count": sources.len()
        }));
    }
    directives
}

fn analyze_csp(directives: &[Value], findings: &mut Vec<Value>) {
    let mut has_default_src = false;
    let mut has_object_src = false;
    let mut has_frame_ancestors = false;
    let mut has_base_uri = false;

    for d in directives {
        let name = d.get("directive").and_then(|v| v.as_str()).unwrap_or("");
        let sources: Vec<String> = d.get("sources")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();

        let sources_str = sources.join(" ");

        if name == "default-src" { has_default_src = true; }
        if name == "object-src" { has_object_src = true; }
        if name == "frame-ancestors" { has_frame_ancestors = true; }
        if name == "base-uri" { has_base_uri = true; }

        if sources_str.contains("'unsafe-inline'") {
            findings.push(policy_finding("weak", "CSP: unsafe-inline",
                &format!("'unsafe-inline' in {} weakens XSS protection", name),
                "Use nonces or hashes instead of 'unsafe-inline'", "High"));
        }
        if sources_str.contains("'unsafe-eval'") {
            findings.push(policy_finding("weak", "CSP: unsafe-eval",
                &format!("'unsafe-eval' in {} permits eval() execution", name),
                "Remove 'unsafe-eval' from CSP", "Medium"));
        }
        if name == "script-src" && sources_str.contains("'strict-dynamic'") {
            // strict-dynamic is good - modern CSP approach
        }
    }

    if !has_default_src {
        findings.push(policy_finding("weak", "CSP: no default-src",
            "Missing default-src directive - no fallback policy",
            "Add default-src 'self' or a restrictive default policy", "Medium"));
    }
    if !has_object_src {
        findings.push(policy_finding("weak", "CSP: no object-src",
            "Missing object-src directive - plugins may be unrestricted",
            "Add object-src 'none' to block plugin content", "Medium"));
    }
    if !has_frame_ancestors {
        findings.push(policy_finding("info", "CSP: no frame-ancestors",
            "Missing frame-ancestors directive (alternative to X-Frame-Options)",
            "Add frame-ancestors 'self' or 'none' for clickjacking protection", "Info"));
    }
    if !has_base_uri {
        findings.push(policy_finding("info", "CSP: no base-uri",
            "Missing base-uri directive - allows <base> tag injection attacks",
            "Add base-uri 'self' to restrict <base> tag", "Low"));
    }
}

// === CORS ANALYZER ===
fn analyze_cors(headers: &HashMap<String, String>, agent: &Agent, target: &str, findings: &mut Vec<Value>) -> Value {
    let allow_origin = headers.get("access-control-allow-origin").cloned().unwrap_or_default();
    let allow_methods = headers.get("access-control-allow-methods").cloned().unwrap_or_default();
    let allow_credentials = headers.get("access-control-allow-credentials").cloned().unwrap_or_default();
    let allow_headers = headers.get("access-control-allow-headers").cloned().unwrap_or_default();
    let expose_headers = headers.get("access-control-expose-headers").cloned().unwrap_or_default();
    let max_age = headers.get("access-control-max-age").cloned().unwrap_or_default();

    if allow_origin.is_empty() {
        return json!(null);
    }

    let mut details = json!({
        "allow_origin": allow_origin, "allow_methods": allow_methods,
        "allow_credentials": allow_credentials, "allow_headers": allow_headers,
        "expose_headers": expose_headers, "max_age": max_age,
    });

    // Check for wildcard
    if allow_origin == "*" {
        if allow_credentials.to_lowercase() == "true" {
            findings.push(policy_finding("critical", "CORS: wildcard + credentials",
                "Wildcard origin (*) with credentials=true - CORS spec violation",
                "Use specific origin instead of * when credentials=true", "Critical"));
        } else {
            findings.push(policy_finding("high", "CORS: wildcard origin",
                "Wildcard CORS origin (*) allows any site to read responses",
                "Specify exact allowed origins", "High"));
        }
    }

    // Check dangerous methods
    for m in &["PUT", "DELETE", "PATCH"] {
        if allow_methods.to_uppercase().contains(m) {
            findings.push(policy_finding("medium", "CORS: dangerous method",
                &format!("CORS allows {} - modify/delete via XSS", m),
                "Restrict CORS methods to GET/POST only", "Medium"));
        }
    }

    // Check for sensitive headers
    for h in &["authorization", "x-api-key", "api-key", "token"] {
        if allow_headers.to_lowercase().contains(h) {
            findings.push(policy_finding("medium", "CORS: sensitive headers exposed",
                &format!("CORS exposes headers containing '{}'", h),
                "Ensure sensitive headers only go to trusted origins", "Medium"));
        }
    }

    // Test origin reflection
    let test_origins = vec!["https://evil.com", "https://attacker.com", "null"];
    let mut reflected = Vec::new();
    for origin in &test_origins {
        let req = agent.get(target)
            .set("Origin", origin)
            .set("User-Agent", "Mozilla/5.0")
            .call();
        if let Ok(r) = req {
            if let Some(returned_origin) = r.header("access-control-allow-origin") {
                if returned_origin == *origin || returned_origin.contains(origin.trim_start_matches("https://")) {
                    reflected.push(origin.to_string());
                }
            }
        }
    }
    if !reflected.is_empty() {
        findings.push(policy_finding("high", "CORS: origin reflection",
            &format!("Server reflects {} origins back", reflected.len()),
            "Implement strict origin whitelist instead of reflection", "High"));
        details["origin_reflection"] = json!(reflected);
    }

    // Test preflight
    for origin in &["https://evil.com"] {
        let preq = agent.request("OPTIONS", target)
            .set("Origin", origin)
            .set("Access-Control-Request-Method", "GET")
            .set("User-Agent", "Mozilla/5.0")
            .call();
        if let Ok(r) = preq {
            let pre_origin = r.header("Access-Control-Allow-Origin").unwrap_or("");
            if pre_origin == *origin {
                findings.push(policy_finding("high", "CORS: preflight origin reflection",
                    "Preflight response reflects Origin header",
                    "Fix origin whitelist for preflight", "High"));
            }
            if r.header("Access-Control-Allow-Credentials") == Some("true") &&
               r.header("Access-Control-Allow-Origin") == Some("*") {
                findings.push(policy_finding("critical", "CORS: preflight credentials + wildcard",
                    "Preflight allows credentials with wildcard origin",
                    "This is a CORS specification violation", "Critical"));
            }
        }
    }

    details
}

// === COOP / COEP ANALYSIS ===
fn analyze_cross_origin_isolation(headers: &HashMap<String, String>, findings: &mut Vec<Value>) {
    let coop = headers.get("cross-origin-opener-policy").cloned().unwrap_or_default();
    let coep = headers.get("cross-origin-embedder-policy").cloned().unwrap_or_default();
    let corp = headers.get("cross-origin-resource-policy").cloned().unwrap_or_default();

    if !coop.is_empty() {
        let v = coop.to_lowercase();
        if v == "unsafe-none" || v == "same-origin-allow-popups" {
            // Weak but acceptable
        } else if v == "same-origin" {
            findings.push(policy_finding("info", "COOP: same-origin",
                "Cross-Origin-Opener-Policy: same-origin (strong isolation)",
                "", "Info"));
        }
    }

    if !coep.is_empty() {
        let v = coep.to_lowercase();
        if v == "require-corp" || v == "credentialless" {
            findings.push(policy_finding("info", "COEP configured",
                &format!("Cross-Origin-Embedder-Policy: {} (Spectre mitigation)", v),
                "Ensure all cross-origin resources have CORP headers", "Info"));
        }
    } else {
        findings.push(policy_finding("info", "COEP missing",
            "Cross-Origin-Embedder-Policy is missing (Spectre mitigation)",
            "Consider adding COEP: require-corp or credentialless", "Info"));
    }

    if coep.to_lowercase() == "require-corp" && corp.is_empty() {
        findings.push(policy_finding("info", "CORP missing",
            "COEP=require-corp but no Cross-Origin-Resource-Policy set",
            "Add CORP headers to all cross-origin resources", "Medium"));
    }
}

// === COOKIE ANALYZER ===
fn split_cookies(cookies: &str) -> Vec<String> {
    // RFC 6265: multiple Set-Cookie headers should be separate,
    // but sometimes they're joined with commas
    let mut result = Vec::new();
    let mut depth = 0;
    let mut current = String::new();
    for ch in cookies.chars() {
        match ch {
            ',' if depth == 0 => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() { result.push(trimmed); }
                current.clear();
            }
            '=' if !current.contains('=') => { current.push(ch); }
            '"' => { depth ^= 1; current.push(ch); }
            _ => { current.push(ch); }
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() { result.push(trimmed); }
    result
}

fn analyze_cookie(cookie: &str, findings: &mut Vec<Value>) -> Value {
    let parts: Vec<&str> = cookie.split(';').collect();
    let name = parts[0].split('=').next().unwrap_or("?").trim().to_string();
    let value = parts[0].splitn(2, '=').nth(1).unwrap_or("").to_string();

    let has_secure = cookie.to_lowercase().contains("secure");
    let has_httponly = cookie.to_lowercase().contains("httponly");
    let has_samesite = cookie.to_lowercase().contains("samesite");
    let samesite_val = extract_attr_value(cookie, "samesite");
    let domain = extract_attr_value(cookie, "domain");
    let path = extract_attr_value(cookie, "path");
    let max_age = extract_attr_value(cookie, "max-age");
    let expires = extract_attr_value(cookie, "expires");

    let mut issues: Vec<String> = Vec::new();

    if !has_secure { issues.push("Missing Secure flag".into()); }
    if !has_httponly { issues.push("Missing HttpOnly flag".into()); }
    if !has_samesite {
        issues.push("Missing SameSite attribute (CSRF risk)".into());
    } else {
        match samesite_val.to_lowercase().as_str() {
            "none" if !has_secure => issues.push("SameSite=None requires Secure".into()),
            "lax" => issues.push("SameSite=Lax allows top-level GET CSRF".into()),
            "strict" => {} // OK
            _ => issues.push(format!("Unknown SameSite value: {}", samesite_val)),
        }
    }

    if domain.starts_with('.') {
        issues.push("Domain starts with '.' - sent to all subdomains".into());
    }
    if path != "/" && !path.is_empty() {
        issues.push("Cookie scoped to non-root path".into());
    }
    if name.starts_with("__Host-") {
        if !has_secure || !path.is_empty() && path != "/" || !domain.is_empty() {
            issues.push("__Host- prefix requires Secure, Path=/, and no Domain".into());
        }
    }
    if name.starts_with("__Secure-") && !has_secure {
        issues.push("__Secure- prefix requires Secure flag".into());
    }

    if !issues.is_empty() {
        let sev = if has_secure && has_httponly { "Low" } else { "Medium" };
        for issue in &issues {
            findings.push(policy_finding("cookie", &name,
                &format!("{}: {}", name, issue),
                &fix_cookie_issue(issue), sev));
        }
    }

    json!({
        "name": name, "value": mask_value(&value),
        "domain": domain, "path": path,
        "secure": has_secure, "httponly": has_httponly,
        "samesite": samesite_val, "max_age": max_age,
        "expires": expires, "issues": issues,
    })
}

fn extract_attr_value(cookie: &str, attr: &str) -> String {
    let re = Regex::new(&format!(r#"(?i){}=(?:"([^"]+)"|([^;\s]+))"#, regex::escape(attr))).unwrap();
    re.captures(cookie)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

fn mask_value(val: &str) -> String {
    if val.len() > 8 {
        format!("{}...{}", &val[..4], &val[val.len()-4..])
    } else {
        val.to_string()
    }
}

fn fix_cookie_issue(issue: &str) -> String {
    if issue.contains("Secure") { "Add Secure flag to cookie".into() }
    else if issue.contains("HttpOnly") { "Add HttpOnly flag to cookie".into() }
    else if issue.contains("SameSite") { "Add SameSite=Strict or Lax".into() }
    else if issue.contains("__Host-") { "Ensure __Host- cookie has Secure, Path=/, and no Domain".into() }
    else if issue.contains("domain") { "Use specific domain without leading dot".into() }
    else { "Review cookie configuration".into() }
}

// === CACHE ANALYSIS ===
fn analyze_cache(headers: &HashMap<String, String>, findings: &mut Vec<Value>) {
    let cc = headers.get("cache-control").cloned().unwrap_or_default();
    let pragma = headers.get("pragma").cloned().unwrap_or_default();
    let expires = headers.get("expires").cloned().unwrap_or_default();

    if cc.is_empty() && pragma.is_empty() && expires.is_empty() {
        findings.push(policy_finding("medium", "Cache: no policy",
            "No Cache-Control, Pragma, or Expires headers",
            "Set Cache-Control with appropriate caching policy", "Medium"));
        return;
    }

    let cc_lower = cc.to_lowercase();
    if cc_lower.contains("public") && !cc_lower.contains("no-store") {
        findings.push(policy_finding("medium", "Cache: public without no-store",
            "Cache-Control has 'public' without 'no-store' - sensitive data may be cached",
            "Add 'no-store' for sensitive responses", "Medium"));
    }
    if cc_lower.contains("no-store") {
        // Sensitive content - OK
    }

    let max_age_re = Regex::new(r"max-age=(\d+)").unwrap();
    if let Some(cap) = max_age_re.captures(&cc_lower) {
        if let Ok(age) = cap[1].parse::<u64>() {
            if age > 86400 {
                findings.push(policy_finding("low", "Cache: long max-age",
                    &format!("max-age={}s is very long (>24h)", age),
                    "Use shorter max-age or versioned URLs", "Low"));
            }
            if age == 0 {
                findings.push(policy_finding("info", "Cache: max-age=0",
                    "Response set to not cache (max-age=0)",
                    "Consider using no-cache or no-store instead", "Info"));
            }
        }
    }
}

// === PERMISSIONS-POLICY ANALYSIS ===
fn analyze_permissions_policy(pp: &str, findings: &mut Vec<Value>) {
    let features = parse_permissions_policy(pp);
    for (feature, allows) in &features {
        if allows == "*" {
            findings.push(policy_finding("medium", "Permissions-Policy: wildcard",
                &format!("Feature '{}' allowed for all origins", feature),
                &format!("Restrict '{}' to 'self' or specific origins", feature), "Medium"));
        }
    }
}

fn parse_permissions_policy(pp: &str) -> Vec<(String, String)> {
    let mut features = Vec::new();
    for part in pp.split(',') {
        let part = part.trim();
        if part.is_empty() { continue; }
        // Format: feature=(allowlist)
        if let Some(eq_pos) = part.find('=') {
            let name = part[..eq_pos].trim().to_string();
            let value = part[eq_pos+1..].trim().trim_matches('"').to_string();
            features.push((name, value));
        } else {
            features.push((part.to_string(), String::new()));
        }
    }
    features
}

fn normalize_url(s: &str) -> String {
    let s = s.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{}", s)
    }
}

fn emit_json(t: &str, v: Value) {
    let mut obj = v.as_object().cloned().unwrap_or_default();
    obj.insert("type".to_string(), Value::String(t.to_string()));
    println!("{}", serde_json::to_string(&obj).unwrap_or_default());
}

fn policy_finding(ftype: &str, category: &str, desc: &str, rec: &str, severity: &str) -> Value {
    json!({
        "finding_type": ftype, "category": category,
        "description": desc, "recommendation": rec,
        "severity": severity, "source": "policy_checker",
    })
}
