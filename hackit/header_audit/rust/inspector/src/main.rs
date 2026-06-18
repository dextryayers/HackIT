use serde_json::{json, Value};
use std::env;
use std::time::Instant;
use regex::Regex;
use ureq::{Agent, AgentBuilder};
use std::time::Duration;

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
        .timeout_write(Duration::from_secs(10))
        .redirects(5)
        .build();

    // Paths to scan
    let paths = vec!["/", "/api", "/admin", "/graphql", "/robots.txt", "/.well-known/security.txt"];

    let mut all_findings: Vec<Value> = Vec::new();
    let mut all_headers: Vec<Value> = Vec::new();
    let mut tech_stack: Vec<Value> = Vec::new();
    let mut methods_allowed: Vec<String> = Vec::new();

    for path in &paths {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        scan_path(&agent, &url, path, &mut all_headers, &mut all_findings, &mut tech_stack);
    }

    // Method discovery
    for method in &["GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"] {
        let start = Instant::now();
        match agent.request(method, &target).call() {
            Ok(resp) => {
                if resp.status() < 400 {
                    methods_allowed.push(method.to_string());
                }
                let elapsed = start.elapsed().as_millis() as u64;
                if *method == "OPTIONS" {
                    if let Some(allow) = resp.header("Allow") {
                        emit_json("methods", json!({
                            "source": "OPTIONS", "allow_header": allow,
                            "elapsed_ms": elapsed
                        }));
                    }
                }
            }
            Err(_) => {}
        }
    }

    // Summary
    emit_json("summary", json!({
        "target": target,
        "paths_scanned": paths.len(),
        "total_headers": all_headers.len(),
        "total_findings": all_findings.len(),
        "technologies": tech_stack.len(),
        "methods": methods_allowed,
    }));

    for h in &all_headers { emit_json("header", h.clone()); }
    for f in &all_findings { emit_json("finding", f.clone()); }
    for t in &tech_stack { emit_json("tech", t.clone()); }

    emit_json("inspector_done", json!({"status": "ok"}));
}

fn scan_path(
    agent: &Agent, url: &str, path: &str,
    all_headers: &mut Vec<Value>,
    all_findings: &mut Vec<Value>,
    tech_stack: &mut Vec<Value>,
) {
    let start = Instant::now();
    let resp = match agent.get(url)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
        .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .set("Accept-Language", "en-US,en;q=0.9")
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            emit_json("scan_error", json!({"path": path, "error": format!("{}", e)}));
            return;
        }
    };
    let status = resp.status();
    let elapsed = start.elapsed().as_millis() as u64;
    let server = resp.header("Server").unwrap_or("").to_string();
    let ct = resp.header("Content-Type").unwrap_or("").to_string();

    emit_json("scan_path", json!({
        "path": path, "url": url, "status": status,
        "server": server, "content_type": ct, "elapsed_ms": elapsed
    }));

    let header_names: Vec<String> = resp.headers_names();

    for hname in &header_names {
        if let Some(hval) = resp.header(hname) {
            let (desc, cat, is_sec) = classify_header(hname);
            all_headers.push(json!({
                "key": hname, "value": hval, "path": path,
                "description": desc, "category": cat, "is_security": is_sec
            }));

            // Validate header values
            validate_header(hname, hval, path, all_findings);
        }
    }

    // Technology fingerprinting
    let all_vals: String = header_names.iter().filter_map(|h| {
        resp.header(h).map(|v| format!("{}={}", h, v))
    }).collect::<Vec<_>>().join("; ");

    fingerprint_techs(&all_vals, tech_stack);

    // Security header presence check
    check_security_headers(&header_names, &resp, path, all_findings);
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

fn classify_header(key: &str) -> (String, String, bool) {
    let k = key.to_lowercase();
    match k.as_str() {
        "strict-transport-security" => ("Enforces HTTPS connections".into(), "Security".into(), true),
        "content-security-policy" => ("Controls allowed resources (XSS protection)".into(), "Security".into(), true),
        "x-frame-options" => ("Prevents clickjacking".into(), "Security".into(), true),
        "x-content-type-options" => ("Prevents MIME-sniffing".into(), "Security".into(), true),
        "referrer-policy" => ("Controls referrer information leakage".into(), "Security".into(), true),
        "permissions-policy" => ("Controls browser feature access".into(), "Security".into(), true),
        "cross-origin-embedder-policy" => ("Requires CORP for cross-origin resources".into(), "Security".into(), true),
        "cross-origin-opener-policy" => ("Controls cross-origin window isolation".into(), "Security".into(), true),
        "cross-origin-resource-policy" => ("Controls cross-origin resource loading".into(), "Security".into(), true),
        "access-control-allow-origin" => ("CORS allowed origin".into(), "CORS".into(), true),
        "access-control-allow-methods" => ("CORS allowed methods".into(), "CORS".into(), true),
        "access-control-allow-credentials" => ("CORS credentials policy".into(), "CORS".into(), true),
        "access-control-expose-headers" => ("CORS exposed headers".into(), "CORS".into(), true),
        "access-control-max-age" => ("CORS preflight cache duration".into(), "CORS".into(), true),
        "cache-control" => ("Caching directives".into(), "Caching".into(), false),
        "expires" => ("Response expiry time".into(), "Caching".into(), false),
        "pragma" => ("Legacy cache control".into(), "Caching".into(), false),
        "age" => ("Proxy cache age".into(), "Caching".into(), false),
        "set-cookie" => ("HTTP cookie".into(), "Session".into(), true),
        "server" => ("Server software".into(), "Info".into(), false),
        "x-powered-by" => ("Technology stack info".into(), "Info".into(), false),
        "x-aspnet-version" => ("ASP.NET version (info leak)".into(), "Info Leak".into(), true),
        "x-aspnetmvc-version" => ("ASP.NET MVC version (info leak)".into(), "Info Leak".into(), true),
        "x-generator" => ("CMS generator (info leak)".into(), "Info Leak".into(), true),
        "x-debug-token" => ("Debug token (dev mode leak)".into(), "Info Leak".into(), true),
        "x-served-by" => ("Internal hostname (info leak)".into(), "Info Leak".into(), true),
        "x-runtime" => ("Execution time (info leak)".into(), "Info Leak".into(), true),
        "via" => ("Proxy info (info leak)".into(), "Info Leak".into(), true),
        "content-type" => ("Media type of response".into(), "Content".into(), false),
        "content-length" => ("Response body size".into(), "Content".into(), false),
        "content-encoding" => ("Compression algorithm".into(), "Content".into(), false),
        "date" => ("Response timestamp".into(), "Network".into(), false),
        "connection" => ("Connection control".into(), "Network".into(), false),
        "location" => ("Redirect target".into(), "Network".into(), false),
        "www-authenticate" => ("Auth scheme (401)".into(), "Security".into(), true),
        "nel" => ("Network Error Logging policy".into(), "Security".into(), true),
        "report-to" => ("Reporting endpoint".into(), "Security".into(), true),
        "clear-site-data" => ("Clear browsing data directive".into(), "Security".into(), true),
        "expect-ct" => ("CT enforcement (deprecated)".into(), "Security".into(), true),
        "x-dns-prefetch-control" => ("DNS prefetch control".into(), "Security".into(), true),
        "x-xss-protection" => ("Legacy XSS filter".into(), "Security".into(), true),
        _ => ("General response header".into(), "General".into(), false),
    }
}

fn validate_header(key: &str, value: &str, path: &str, findings: &mut Vec<Value>) {
    let k = key.to_lowercase();
    match k.as_str() {
        "strict-transport-security" => validate_hsts(value, path, findings),
        "content-security-policy" => validate_csp(value, path, findings),
        "x-frame-options" => validate_xfo(value, path, findings),
        "x-content-type-options" => {
            if value.to_lowercase() != "nosniff" {
                findings.push(finding(
                    "weak", key, value, path, "Low",
                    "X-Content-Type-Options should be 'nosniff'",
                    "Set X-Content-Type-Options: nosniff",
                ));
            }
        }
        "referrer-policy" => validate_referrer(value, path, findings),
        "set-cookie" => validate_cookie(value, path, findings),
        "server" => {
            findings.push(finding(
                "leak", key, value, path, "Medium",
                &format!("Server header exposes: {}", value),
                "Remove or obscure the Server header",
            ));
        }
        "x-powered-by" => {
            findings.push(finding(
                "leak", key, value, path, "Low",
                &format!("Technology stack exposed: {}", value),
                "Remove X-Powered-By header",
            ));
        }
        "access-control-allow-origin" => validate_cors_origin(key, value, path, findings),
        "access-control-allow-credentials" => {
            if value.to_lowercase() == "true" {
                findings.push(finding(
                    "cors", key, value, path, "Medium",
                    "CORS credentials enabled - cookies/auth headers exposed cross-origin",
                    "Use specific origins with caution",
                ));
            }
        }
        _ => {}
    }
}

fn finding(ftype: &str, header: &str, value: &str, path: &str, severity: &str, desc: &str, rec: &str) -> Value {
    json!({
        "finding_type": ftype, "header": header, "value": value,
        "path": path, "severity": severity, "description": desc,
        "recommendation": rec
    })
}

fn validate_hsts(value: &str, path: &str, findings: &mut Vec<Value>) {
    let v = value.to_lowercase();
    if !v.contains("max-age=") {
        findings.push(finding("missing", "Strict-Transport-Security", value, path, "High",
            "HSTS missing max-age directive", "Set max-age=31536000; includeSubDomains"));
        return;
    }
    let re = Regex::new(r"max-age=(\d+)").unwrap();
    if let Some(cap) = re.captures(&v) {
        let max_age: u64 = cap[1].parse().unwrap_or(0);
        if max_age < 31536000 {
            findings.push(finding("weak", "Strict-Transport-Security", value, path, "Medium",
                &format!("HSTS max-age too short: {}s (min 31536000)", max_age),
                "Increase max-age to at least 31536000 (1 year)"));
        }
    }
    if !v.contains("includesubdomains") {
        findings.push(finding("weak", "Strict-Transport-Security", value, path, "Low",
            "HSTS missing includeSubDomains", "Add includeSubDomains directive"));
    }
    if v.contains("includesubdomains") && !v.contains("preload") {
        findings.push(finding("info", "Strict-Transport-Security", value, path, "Info",
            "HSTS preload not requested", "Consider submitting to HSTS preload list"));
    }
}

fn validate_csp(value: &str, path: &str, findings: &mut Vec<Value>) {
    let v = value.to_lowercase();
    if v.contains("unsafe-inline") {
        findings.push(finding("weak", "Content-Security-Policy", value, path, "High",
            "CSP allows 'unsafe-inline' - weakens XSS protection",
            "Use nonces or hashes instead of unsafe-inline"));
    }
    if v.contains("unsafe-eval") {
        findings.push(finding("weak", "Content-Security-Policy", value, path, "Medium",
            "CSP allows 'unsafe-eval' - permits eval() execution",
            "Remove unsafe-eval from CSP"));
    }
    if !v.contains("default-src") {
        findings.push(finding("weak", "Content-Security-Policy", value, path, "Medium",
            "CSP missing default-src directive",
            "Add default-src 'self' or a restrictive policy"));
    }
    if v.contains("http:") {
        findings.push(finding("weak", "Content-Security-Policy", value, path, "Medium",
            "CSP allows http: scheme - mixed content risk",
            "Use https: instead of http: in CSP directives"));
    }
    if v.contains("https:") && v.contains("http:") {
        // Both http: and https: means http: is redundant (https implies http)
    }
    // Check for missing frame-ancestors when X-Frame-Options is absent
    if !v.contains("frame-ancestors") {
        findings.push(finding("info", "Content-Security-Policy", value, path, "Info",
            "CSP missing frame-ancestors directive (alternative to X-Frame-Options)",
            "Add frame-ancestors 'self' or 'none' for clickjacking protection"));
    }
}

fn validate_xfo(value: &str, path: &str, findings: &mut Vec<Value>) {
    let v = value.to_uppercase();
    if v != "DENY" && v != "SAMEORIGIN" {
        findings.push(finding("weak", "X-Frame-Options", value, path, "Medium",
            &format!("Weak X-Frame-Options: {} (should be DENY or SAMEORIGIN)", value),
            "Set X-Frame-Options: DENY or SAMEORIGIN"));
    }
}

fn validate_referrer(value: &str, path: &str, findings: &mut Vec<Value>) {
    let safe = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin",
                 "no-referrer-when-downgrade"];
    let v = value.to_lowercase();
    if v == "unsafe-url" {
        findings.push(finding("weak", "Referrer-Policy", value, path, "High",
            "unsafe-url leaks full URL to all origins",
            "Use strict-origin-when-cross-origin"));
    } else if !safe.contains(&v.as_str()) {
        findings.push(finding("info", "Referrer-Policy", value, path, "Info",
            "Non-standard Referrer-Policy value", "Use strict-origin-when-cross-origin"));
    }
}

fn validate_cookie(value: &str, path: &str, findings: &mut Vec<Value>) {
    let parts: Vec<&str> = value.split(';').collect();
    let name = parts[0].split('=').next().unwrap_or("?").trim();
    let has_secure = value.to_lowercase().contains("secure");
    let has_httponly = value.to_lowercase().contains("httponly");
    let has_samesite = value.to_lowercase().contains("samesite");
    let has_samesite_none = value.to_lowercase().contains("samesite=none");

    if !has_secure {
        findings.push(finding("cookie", name, value, path, "Medium",
            "Cookie missing Secure flag - sent over unencrypted HTTP",
            "Add Secure flag to the cookie"));
    }
    if !has_httponly {
        findings.push(finding("cookie", name, value, path, "Medium",
            "Cookie missing HttpOnly flag - accessible via JavaScript (XSS risk)",
            "Add HttpOnly flag"));
    }
    if !has_samesite {
        findings.push(finding("cookie", name, value, path, "Low",
            "Cookie missing SameSite attribute - CSRF risk",
            "Add SameSite=Lax or SameSite=Strict"));
    }
    if has_samesite_none && !has_secure {
        findings.push(finding("cookie", name, value, path, "High",
            "SameSite=None requires Secure flag - browsers reject without it",
            "Add Secure flag when using SameSite=None"));
    }
    if name.starts_with("__Host-") {
        if !has_secure || path != "/" || value.to_lowercase().contains("domain=") {
            findings.push(finding("cookie", name, value, path, "Medium",
                "__Host- prefix requires Secure, Path=/, and no Domain",
                "Ensure __Host- cookie meets all requirements"));
        }
    }
    if name.starts_with("__Secure-") && !has_secure {
        findings.push(finding("cookie", name, value, path, "Medium",
            "__Secure- prefix requires Secure flag",
            "Add Secure flag to __Secure- cookie"));
    }
}

fn validate_cors_origin(key: &str, value: &str, path: &str, findings: &mut Vec<Value>) {
    if value == "*" {
        findings.push(finding("cors", key, value, path, "High",
            "Wildcard CORS origin (*) allows any website to read responses",
            "Specify exact allowed origins instead of *"));
    }
    if value == "null" {
        findings.push(finding("cors", key, value, path, "High",
            "CORS origin is 'null' - sandboxed documents can access",
            "Remove null origin from CORS policy"));
    }
}

fn check_security_headers(
    _header_names: &[String], resp: &ureq::Response, path: &str,
    findings: &mut Vec<Value>,
) {
    let required = [
        ("Strict-Transport-Security", "High", "Enforces HTTPS connections"),
        ("Content-Security-Policy", "High", "Prevents XSS and injection attacks"),
        ("X-Frame-Options", "Medium", "Prevents clickjacking"),
        ("X-Content-Type-Options", "Low", "Prevents MIME-sniffing"),
        ("Referrer-Policy", "Low", "Controls referrer leakage"),
        ("Permissions-Policy", "Medium", "Controls browser feature access"),
        ("Cross-Origin-Embedder-Policy", "Medium", "Spectre mitigation (COEP)"),
        ("Cross-Origin-Opener-Policy", "Medium", "Spectre mitigation (COOP)"),
        ("Cross-Origin-Resource-Policy", "Medium", "Resource isolation (CORP)"),
    ];
    for (name, sev, desc) in &required {
        if resp.header(name).is_none() {
            findings.push(finding("missing", name, "", path, sev,
                &format!("Missing: {}", desc),
                &format!("Add {} header", name)));
        }
    }
}

fn fingerprint_techs(all_vals: &str, techs: &mut Vec<Value>) {
    let rules: Vec<(&str, &str, &str, &str)> = vec![
        ("Cloudflare", r"(?i)cloudflare|__cfduid|cf-ray", "Server/Cookie", "High"),
        ("CloudFront", r"(?i)cloudfront|x-amz-", "Header", "High"),
        ("Akamai", r"(?i)akamai|akamaized", "Header", "High"),
        ("Fastly", r"(?i)fastly|x-fastly|squid", "Header", "High"),
        ("Varnish", r"(?i)varnish|x-varnish", "Header", "High"),
        ("Nginx", r"(?i)nginx", "Server", "High"),
        ("Apache", r"(?i)apache", "Server", "High"),
        ("IIS", r"(?i)iis|microsoft-iis|x-aspnet", "Server/Headers", "High"),
        ("OpenResty", r"(?i)openresty", "Server", "High"),
        ("PHP", r"(?i)(?:\b|/)php(?:/|\b)", "X-Powered-By", "High"),
        ("ASP.NET", r"(?i)asp\.net|x-aspnet", "X-Powered-By", "High"),
        ("Express", r"(?i)express", "X-Powered-By", "Medium"),
        ("Python", r"(?i)python|wsgi", "Server", "Medium"),
        ("Ruby/Rails", r"(?i)phusion|passenger|rails|ruby", "Server/Headers", "Medium"),
        ("Java/Tomcat", r"(?i)java|tomcat|jboss|jetty|servlet", "Server/Headers", "Medium"),
        ("WordPress", r"(?i)wordpress", "X-Powered-By", "Medium"),
        ("Drupal", r"(?i)drupal", "X-Generator", "Medium"),
        ("Joomla", r"(?i)joomla", "X-Generator", "Medium"),
        ("Laravel", r"(?i)laravel", "X-Powered-By", "Medium"),
        ("Symfony", r"(?i)symfony|x-debug-token", "Header", "Medium"),
        ("Netlify", r"(?i)netlify", "Server", "High"),
        ("Vercel", r"(?i)vercel", "Server/Headers", "High"),
        ("Heroku", r"(?i)heroku", "Server", "High"),
        ("GitHub Pages", r"(?i)github\.com", "Server", "Medium"),
        ("AWS S3", r"(?i)amazons3|aws-s3|x-amz-", "Server/Headers", "High"),
        ("AWS ELB", r"(?i)elb|elasticloadbalancing", "Server", "Medium"),
        ("Google Cloud", r"(?i)gcloud|google-cloud|gcp|appspot", "Server", "Medium"),
    ];

    for (name, pattern, source, certainty) in &rules {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(all_vals) {
            techs.push(json!({
                "name": name, "certainty": certainty, "source": source
            }));
        }
    }
}
