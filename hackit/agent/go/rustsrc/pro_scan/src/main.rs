//! pro_scan — high-precision header / CORS / JS / path / cookie scanner.
//!
//! Transport is `curl` (bytes) + this engine does the intelligent parsing,
//! differential verification and finding assembly.  Output is one JSON
//! object on stdout so the Go orchestrator and Python bridge can merge it.

use std::env;
use std::process::Command;
use std::str;

const UA: &str = "HackIt-Pentest/2.3 (+authorised assessment)";

fn curl(url: &str, extra: &[&str], timeout_secs: u64, method: &str) -> (u16, String) {
    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("-L").arg("--max-time").arg(timeout_secs.to_string())
        .arg("-i").arg("-X").arg(method)
        .arg("-A").arg(UA)
        .arg("-H").arg("Accept: */*");
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.arg(url);
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => return (0, format!("curl error: {}", e)),
    };
    let raw = String::from_utf8_lossy(&output.stdout).into_owned();
    let status = raw.split("\r\n").next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn headers_of(url: &str, timeout_secs: u64) -> (u16, std::collections::HashMap<String, String>) {
    let (status, body) = curl(url, &["-I"], timeout_secs, "HEAD");
    let mut map = std::collections::HashMap::new();
    for line in body.split("\r\n") {
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_ascii_lowercase();
            let value = line[idx + 1..].trim().to_string();
            if !name.is_empty() {
                map.entry(name).or_insert(value);
            }
        }
    }
    (status, map)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn finding(ftype: &str, target: &str, title: &str, evidence: &str, severity: &str, cvss: &str,
           remediation: &str, reproduction: &str) -> String {
    format!(
        "{{\"id\":\"{}-{:x}\",\"type\":\"{}\",\"severity\":\"{}\",\"cvss\":{},\"target\":\"{}\",\"description\":\"{}\",\"evidence\":\"{}\",\"remediation\":\"{}\",\"reproduction\":\"{}\"}}",
        ftype.to_ascii_uppercase(),
        uuid_hex(),
        json_escape(ftype),
        json_escape(severity),
        cvss,
        json_escape(target),
        json_escape(title),
        json_escape(evidence),
        json_escape(remediation),
        json_escape(reproduction),
    )
}

fn uuid_hex() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    // Time-based entropy is sufficient for ids inside a single run.
    nanos ^ (nanos.rotate_left(13))
}

fn print_findings(findings: &[String], extra: &str) {
    let joined = findings.join(",");
    if extra.is_empty() {
        println!("{{\"findings\":[{}]}}", joined);
    } else {
        println!("{{\"findings\":[{}],{}}}", joined, extra);
    }
}

fn mode_headers(url: &str) {
    let (status, headers) = headers_of(url, 10);
    let mut findings: Vec<String> = Vec::new();
    let required: [(&str, &str, &str, f64); 6] = [
        ("strict-transport-security", "Missing HSTS Strict-Transport-Security", "low", 3.1),
        ("content-security-policy", "Missing Content-Security-Policy", "medium", 4.3),
        ("x-frame-options", "Missing X-Frame-Options (clickjacking)", "low", 2.4),
        ("x-content-type-options", "Missing X-Content-Type-Options (MIME sniffing)", "low", 1.6),
        ("referrer-policy", "Missing Referrer-Policy", "low", 1.3),
        ("permissions-policy", "Missing Permissions-Policy", "info", 0.5),
    ];
    for (header, title, severity, cvss) in &required {
        if !headers.contains_key(*header) || headers.get(*header).map(|v| v.trim().is_empty()).unwrap_or(true) {
            findings.push(finding(
                "security_header_missing", url, title,
                &format!("Header {:?} absent (HTTP {})", header, status),
                severity, format!("{}", cvss).as_str(),
                &format!("Add the {} response header", header),
                &format!("curl -sI {} | grep -i {}", url, header),
            ));
        }
    }
    if let Some(hsts) = headers.get("strict-transport-security") {
        if let Some(arg) = hsts.split('=').nth(1) {
            if let Some(num) = arg.trim().split(';').next() {
                if let Ok(age) = num.trim().parse::<u64>() {
                    if age < 31536000 {
                        findings.push(finding(
                            "weak_hsts", url, "HSTS max-age below 1 year",
                            &format!("Strict-Transport-Security: {}", hsts),
                            "low", "2.0",
                            "Use max-age of at least 31536000 and includeSubDomains",
                            &format!("curl -sI {} | grep -i strict-transport-security", url),
                        ));
                    }
                }
            }
        }
    }
    if let Some(csp) = headers.get("content-security-policy") {
        let lowered = csp.to_ascii_lowercase();
        for directive in ["unsafe-inline", "unsafe-eval"] {
            if lowered.contains(directive) {
                findings.push(finding(
                    "weak_csp", url, &format!("Weak CSP directive: {}", directive),
                    &format!("Content-Security-Policy: {}", csp),
                    "medium", "4.1",
                    "Remove unsafe directives and narrow source lists",
                    &format!("curl -sI {} | grep -i content-security-policy", url),
                ));
                break;
            }
        }
    }
    if let Some(server) = headers.get("server") {
        if server.chars().any(|c| c.is_ascii_digit()) {
            findings.push(finding(
                "info_disclosure", url, "Server version disclosed",
                &format!("Server: {}", server),
                "info", "2.0",
                "Suppress or genericise Server and X-Powered-By headers",
                &format!("curl -sI {} | grep -i '^server:'", url),
            ));
        }
    }
    if let Some(powered) = headers.get("x-powered-by") {
        findings.push(finding(
            "info_disclosure", url, "X-Powered-By stack disclosure",
            &format!("X-Powered-By: {}", powered),
            "info", "2.1",
            "Remove the X-Powered-By response header",
            &format!("curl -sI {} | grep -i x-powered-by", url),
        ));
    }
    let headers_json: Vec<String> = headers.iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
        .collect();
    print_findings(&findings, &format!("\"headers\":{{{}}}", headers_json.join(",")));
}

fn mode_cors(url: &str) {
    let (_, body) = curl(url, &[], 10, "GET");
    let mut findings: Vec<String> = Vec::new();
    let (status, headers) = headers_of(url, 10);
    if let Some(acao) = headers.get("access-control-allow-origin") {
        if acao.trim() == "*" {
            let cred = headers.get("access-control-allow-credentials").map(|v| v.as_str()).unwrap_or("false");
            findings.push(finding(
                "cors", url, "CORS allows any origin (*)",
                &format!("Access-Control-Allow-Origin: * (credentials={})", cred),
                "medium", "5.3",
                "Restrict to explicit trusted origins; never combine wildcard with credentials",
                &format!("curl -s -H 'Origin: https://evil.example' -D- -o /dev/null {} | grep -i access-control", url),
            ));
        }
    }
    let _ = body; // static evaluation preferred; the Python layer adds reflection probes.
    let _ = status;
    print_findings(&findings, &format!("\"base\":{{\"acao\":\"{}\"}}",
        headers_of(url, 10).1.get("access-control-allow-origin").cloned().unwrap_or_default()));
}

fn mode_js(url: &str) {
    let (_, body) = curl(url, &[], 20, "GET");
    let mut findings: Vec<String> = Vec::new();
    let endpoints = extract_endpoints(&body);
    for sk in secret_hits(&body) {
        findings.push(finding(
            "js_secret", url, "Secret leak in page source",
            &format!("hardcoded_secret: {}", &sk[..sk.len().min(120)]),
            "high", "7.0",
            "Rotate and remove the embedded secret; use vault/proxy",
            &format!("grep the page source for {}", &sk[..sk.len().min(24)]),
        ));
    }
    if body.contains("sourceMappingURL") {
        findings.push(finding(
            "js_sourcemap", url, "JavaScript source map published",
            "sourceMappingURL marker present in served JS",
            "medium", "5.4",
            "Build without sourcemaps; do not serve .map in production",
            &format!("curl -s {} | grep -i sourceMappingURL", url),
        ));
    }
    let ep_json: Vec<String> = endpoints.iter().map(|e| format!("\"{}\"", json_escape(e))).collect();
    print_findings(&findings, &format!("\"endpoints\":[{}]", ep_json.join(",")));
}

fn extract_endpoints(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for token in body.split(|c: char| c == '"' || c == '\'' || c == '`' || c.is_whitespace()) {
        let t = token.trim_matches(|c: char| c == '(' || c == ')' || c == ',' || c == ';');
        if t.starts_with("https://") || t.starts_with("http://") || t.starts_with('/') {
            if t.len() >= 8 && t.len() <= 300
                && !t.contains("<")
                && (t.contains('/') || t.contains('.')) {
                out.push(t.to_string());
            }
        }
    }
    out.truncate(120);
    out
}

fn secret_hits(body: &str) -> Vec<String> {
    let prefixes = [
        ("AKIA", 20), ("ASIA", 20), ("AIza", 24), ("ghp_", 24), ("gho_", 24),
        ("ghu_", 24), ("ghs_", 24), ("ghr_", 24), ("xoxb-", 12), ("xoxa-", 12),
        ("sk-", 16),
    ];
    let mut hits = Vec::new();
    for (prefix, min) in prefixes {
        let mut i = 0;
        while i < body.len() {
            if let Some(rel) = body[i..].find(prefix) {
                let start = i + rel;
                let end = (start + 60).min(body.len());
                let mut cand = String::from_utf8_lossy(&body.as_bytes()[start..end]).into_owned();
                cand = cand.split(|c: char| c == '"' || c == '\'').next().unwrap_or("").to_string();
                if cand.len() >= min {
                    hits.push(cand);
                }
                i = start + prefix.len() + 1;
            } else {
                break;
            }
        }
    }
    hits.truncate(12);
    hits
}

fn mode_paths(base_url: &str) {
    let candidates = [
        (".env", "env", ".env file exposed", "critical", "9.0"),
        (".git/HEAD", "git", "git headfile exposed", "high", "7.5"),
        ("phpinfo.php", "phpinfo", "phpinfo() exposed", "medium", "5.3"),
        ("swagger.json", "json", "OpenAPI spec exposed", "medium", "4.1"),
        ("openapi.json", "json", "OpenAPI spec exposed", "medium", "4.1"),
        ("actuator", "spring", "Spring actuator exposed", "high", "6.5"),
        ("actuator/env", "spring", "Spring actuator/env exposed", "high", "7.0"),
        ("dump.sql", "text", "SQL dump exposed", "high", "8.0"),
        ("backup.zip", "binary", "backup archive exposed", "medium", "5.5"),
    ];
    let base = base_url.trim_end_matches('/');
    // Baseline for soft-404 differential.
    let (baseline_status, baseline_body) = curl(&format!("{}/hackit-not-exist-{}", base, uuid_hex()), &[], 8, "GET");

    let mut findings: Vec<String> = Vec::new();
    for (path, kind, title, severity, cvss) in candidates {
        let url = format!("{}/{}", base, path);
        let (status, body) = curl(&url, &[], 8, "GET");
        if status != 200 {
            continue;
        }
        if baseline_status == 200 && body.trim() == baseline_body.trim() {
            continue; // same catch-all body
        }
        let ok = match kind {
            "env" => body.starts_with("APP_") || body.contains("APP_KEY") || body.contains("DB_PASSWORD"),
            "git" => body.contains("ref:") || body.contains("[core]"),
            "phpinfo" => body.to_ascii_lowercase().contains("php version"),
            "json" => body.trim_start().starts_with('{') || body.trim_start().starts_with('['),
            "spring" => body.contains("\"_links\"") || body.contains("\"propertySources\"") || body.contains("\"status\""),
            "binary" => body.len() > 64 && !body.to_ascii_lowercase().contains("<html"),
            _ => !body.to_ascii_lowercase().contains("404")
                && !body.to_ascii_lowercase().contains("not found"),
        };
        if !ok {
            continue;
        }
        findings.push(finding(
            "exposed_file", &url, title,
            &format!("GET {} -> HTTP 200 ({} bytes)", path, body.len()),
            severity, cvss,
            "Remove the file and block access at the web server layer",
            &format!("curl -i {}", url),
        ));
    }
    print_findings(&findings, &format!("\"baseline_status\":{}", baseline_status));
}

fn mode_cookies(url: &str) {
    let (_, out) = curl(url, &["-I"], 10, "GET");
    let mut findings: Vec<String> = Vec::new();
    for line in out.split("\r\n") {
        if !line.to_ascii_lowercase().starts_with("set-cookie:") {
            continue;
        }
        let cookie = line.split(':').nth(1).unwrap_or("").trim().to_string();
        let low = cookie.to_ascii_lowercase();
        let name = cookie.split('=').next().unwrap_or("").trim().to_ascii_lowercase();
        if !name.contains("session") && !name.contains("sid") && !name.contains("token") && !name.contains("auth") {
            continue;
        }
        let mut missing: Vec<&str> = Vec::new();
        if !low.contains("httponly") { missing.push("HttpOnly"); }
        if !low.contains("secure") { missing.push("Secure"); }
        if !low.contains("samesite") { missing.push("SameSite"); }
        if missing.is_empty() { continue; }
        findings.push(finding(
            "weak_cookie", url, &format!("Session cookie missing {}", missing.join(", ")),
            &format!("Set-Cookie: {}", cookie),
            "low", "2.7",
            "Add the missing flags to session cookies",
            &format!("curl -sI {} | grep -i set-cookie", url),
        ));
    }
    print_findings(&findings, "");
}

fn mode_all(url: &str) {
    let (status, _headers) = headers_of(url, 10);
    println!("{{\"all_in_one\":{{\"url\":\"{}\",\"status\":{}}}}}", json_escape(url), status);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.iter().position(|a| a == "--mode").map(|i| args.get(i + 1).cloned().unwrap_or_default())
        .unwrap_or_default();
    let url_flag = args.iter().position(|a| a == "--url").map(|i| args.get(i + 1).cloned().unwrap_or_default());
    let url = match url_flag { Some(u) if !u.is_empty() => u, _ => args.last().cloned().unwrap_or_default() };
    if url.is_empty() {
        eprintln!("pro_scan --mode <headers|cors|js|paths|cookies> --url <base>");
        std::process::exit(2);
    }
    match mode.as_str() {
        "headers" => mode_headers(&url),
        "cors" => mode_cors(&url),
        "js" => mode_js(&url),
        "paths" => mode_paths(&url),
        "cookies" => mode_cookies(&url),
        "all" => mode_all(&url),
        _ => { eprintln!("unknown mode {}", mode); std::process::exit(2); }
    }
}
