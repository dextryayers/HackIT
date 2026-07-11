use crate::common::{VulnResult, Vulnerability, build_client, normalize_url};

pub async fn scan(target: &str) -> VulnResult {
    let url = normalize_url(target);
    let client = build_client(15);
    let mut vulns = Vec::new();
    let target_host = url.replace("https://", "").replace("http://", "").split('/').next().unwrap_or("").to_string();

    if let Some(client) = client {
        check_directory_traversal(&client, &url, &mut vulns).await;
        check_ssrf(&client, &url, &mut vulns).await;
        check_open_redirect(&client, &url, &mut vulns).await;
        check_cors_misconfig(&client, &url, &mut vulns).await;
        check_xss_reflected(&client, &url, &mut vulns).await;
        check_sql_error(&client, &url, &mut vulns).await;
        check_ssti(&client, &url, &mut vulns).await;
        check_xxe(&client, &url, &mut vulns).await;
        check_debug_endpoints(&client, &url, &mut vulns).await;
        check_clickjacking(&client, &url, &mut vulns).await;
        check_insecure_cookies(&client, &url, &mut vulns).await;
        check_hsts(&client, &url, &mut vulns).await;
        check_csp(&client, &url, &mut vulns).await;
        check_open_ports_common(&target_host, &mut vulns);
    }

    check_weak_tls(&target_host, &mut vulns).await;
    check_http_vs_https(&url, &mut vulns).await;

    VulnResult { target: target.to_string(), vulnerabilities: vulns }
}

fn make_vuln(cve_id: Option<&str>, name: &str, severity: &str, description: &str, remediation: Option<&str>) -> Vulnerability {
    Vulnerability { cve_id: cve_id.map(|s| s.into()), name: name.into(), severity: severity.into(), description: description.into(), remediation: remediation.map(|s| s.into()) }
}

async fn check_directory_traversal(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let payloads = ["../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "..%252f..%252f..%252fetc/passwd", "....//....//....//etc/passwd",
        "../../Windows/win.ini", "..\\..\\..\\Windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini", "..\\..\\..\\etc\\passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"];
    for payload in payloads {
        let test_url = format!("{}/{}", url.trim_end_matches('/'), payload);
        if let Ok(resp) = client.get(&test_url).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains("root:") || body.contains("nobody:") || body.contains("[extensions]")
                    || body.contains("[fonts]") || body.contains("root:x:0:") || body.contains("daemon:x:1:") {
                    vulns.push(make_vuln(Some("CVE-DIR-TRAVERSAL"), "Directory Traversal", "High",
                        &format!("Path traversal vulnerability at {}", test_url), Some("Validate and sanitize all file path inputs; use allowlist")));
                    break;
                }
            }
        }
    }
}

async fn check_ssrf(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let targets = [
        format!("{}?url=http://169.254.169.254/latest/meta-data/", url.trim_end_matches('/')),
        format!("{}?url=http://169.254.169.254/latest/user-data/", url.trim_end_matches('/')),
        format!("{}?url=http://metadata.google.internal/", url.trim_end_matches('/')),
        format!("{}?url=http://100.100.100.200/latest/meta-data/", url.trim_end_matches('/')),
    ];
    for test_url in &targets {
        if let Ok(resp) = client.get(test_url).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains("ami-id") || body.contains("instance-id") || body.contains("iam/")
                    || body.contains("project-id") || body.contains("zone") {
                    vulns.push(make_vuln(Some("CVE-SSRF-META"), "Server-Side Request Forgery", "Critical",
                        &format!("SSRF vulnerability detected via cloud metadata at {}", test_url),
                        Some("Restrict outbound requests; validate URLs; use allowlist")));
                    break;
                }
            }
        }
    }
}

async fn check_open_redirect(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let params = ["redirect=", "url=", "next=", "return=", "returnUrl=", "return_url=", "r=", "u=", "to=", "target=", "view=", "dir=", "dest="];
    for param in &params {
        let test_url = format!("{}?{}https://evil.com{}", url.trim_end_matches('/'), param, if param.ends_with('=') { "" } else { "" });
        if let Ok(resp) = client.get(&test_url).send().await {
            if resp.status().is_redirection() {
                if let Some(loc) = resp.headers().get("location") {
                    if let Ok(loc_str) = loc.to_str() {
                        if loc_str.contains("evil.com") || loc_str.starts_with("//evil") {
                            vulns.push(make_vuln(Some("CVE-OPEN-REDIRECT"), "Open Redirect", "Medium",
                                &format!("Open redirect via {} to {}", param, loc_str),
                                Some("Validate redirect URLs against an allowlist")));
                        }
                    }
                }
            }
        }
    }
}

async fn check_cors_misconfig(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    if let Ok(resp) = client.get(url).header("Origin", "https://evil.com").send().await {
        if let Some(ac) = resp.headers().get("access-control-allow-origin") {
            if let Ok(ac_str) = ac.to_str() {
                if ac_str == "*" || ac_str == "https://evil.com" {
                    vulns.push(make_vuln(Some("CVE-CORS-MISCONFIG"), "CORS Misconfiguration", "Medium",
                        &format!("Access-Control-Allow-Origin: {}", ac_str), Some("Restrict CORS to specific trusted origins")));
                }
                if let Some(ac) = resp.headers().get("access-control-allow-credentials") {
                    if ac.to_str().unwrap_or("") == "true" && ac_str != "" {
                        vulns.push(make_vuln(Some("CVE-CORS-CRED"), "CORS with Credentials", "High",
                            "CORS allows credentials with wildcard/mirrored origin", Some("Do not use Access-Control-Allow-Credentials: true with wildcard origins")));
                    }
                }
            }
        }
    }
}

async fn check_xss_reflected(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let payloads = [
        ("q", "<script>alert(1)</script>"),
        ("search", "<img src=x onerror=alert(1)>"),
        ("s", "\"><script>alert(1)</script>"),
        ("query", "'-alert(1)-'"),
        ("page", "1<svg/onload=alert(1)>"),
    ];
    for (param, payload) in &payloads {
        let sep = if url.contains('?') { "&" } else { "?" };
        let test_url = format!("{}{}{}={}", url.trim_end_matches('/'), sep, param, urlencoding(payload));
        if let Ok(resp) = client.get(&test_url).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains(payload) && !body.contains(&encode_html_entities(payload)) {
                    vulns.push(make_vuln(Some("CVE-XSS-REFLECTED"), "Reflected XSS", "High",
                        &format!("Reflected XSS via parameter '{}': {}", param, payload),
                        Some("Encode output; use Content-Security-Policy; validate input")));
                    break;
                }
            }
        }
    }
}

async fn check_sql_error(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let payloads = ["'", "\"", "1=1--", "' OR '1'='1", "') OR ('1'='1", "' UNION SELECT NULL--", "\" OR 1=1--"];
    for payload in &payloads {
        let test_url = format!("{}?id={}", url.trim_end_matches('/'), urlencoding(payload));
        if let Ok(resp) = client.get(&test_url).send().await {
            if let Ok(body) = resp.text().await {
                let b = body.to_lowercase();
                if (b.contains("sql") || b.contains("mysql") || b.contains("ora-") || b.contains("postgresql"))
                    && (b.contains("syntax") || b.contains("unclosed quotation") || b.contains("warning") || b.contains("error") || b.contains("driver") || b.contains("sqlite")) {
                    vulns.push(make_vuln(Some("CVE-SQLI"), "SQL Injection", "Critical",
                        &format!("SQL error leak with payload: {}", payload), Some("Use prepared statements; validate and sanitize all inputs")));
                    break;
                }
            }
        }
    }
}

async fn check_ssti(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let payloads = [
        ("template", "{{7*7}}"),
        ("name", "${{7*7}}"),
        ("user", "#{7*7}"),
        ("page", "${7*7}"),
    ];
    for (param, payload) in &payloads {
        let test_url = format!("{}?{}={}", url.trim_end_matches('/'), param, payload);
        if let Ok(resp) = client.get(&test_url).send().await {
            if let Ok(body) = resp.text().await {
                if body.contains("49") || body.contains("7*7") {
                    vulns.push(make_vuln(Some("CVE-SSTI"), "Server-Side Template Injection", "Critical",
                        &format!("SSTI detected via parameter '{}' with payload '{}'", param, payload),
                        Some("Do not render user input in template engines; sandbox template rendering")));
                    break;
                }
            }
        }
    }
}

async fn check_xxe(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let xxe_payload = r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"#;
    if let Ok(resp) = client.post(url).header("Content-Type", "application/xml").body(xxe_payload).send().await {
        if let Ok(body) = resp.text().await {
            if body.contains("root:") || body.contains("nobody:") {
                vulns.push(make_vuln(Some("CVE-XXE"), "XML External Entity (XXE) Injection", "Critical",
                    "XXE detected via XML POST body reading /etc/passwd", Some("Disable external entity parsing; use JSON instead of XML")));
            }
        }
    }
}

async fn check_csp(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    if let Ok(resp) = client.get(url).send().await {
        let has_csp = resp.headers().get("content-security-policy").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        match has_csp {
            Some(csp) => {
                let lower = csp.to_lowercase();
                if lower.contains("unsafe-inline") {
                    vulns.push(make_vuln(None, "Weak CSP: unsafe-inline", "Low",
                        "CSP allows 'unsafe-inline' which can enable XSS", Some("Use nonces or hashes instead of 'unsafe-inline'")));
                }
                if !lower.contains("frame-ancestors") {
                    vulns.push(make_vuln(None, "CSP Missing frame-ancestors", "Low",
                        "CSP does not restrict framing; page may be clickjackable", Some("Add frame-ancestors directive to CSP")));
                }
            }
            None => {
                vulns.push(make_vuln(None, "Missing CSP Header", "Info",
                    "No Content-Security-Policy header set", Some("Implement a CSP to mitigate XSS and data injection")));
            }
        }
    }
}

async fn check_debug_endpoints(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let endpoints = ["/actuator/health", "/actuator/env", "/actuator/heapdump",
        "/actuator/threaddump", "/debug", "/api/debug", "/console", "/status",
        "/.env", "/info.php", "/phpinfo.php", "/server-status", "/server-info",
        "/actuator/prometheus", "/actuator/metrics", "/actuator/beans",
        "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
        "/.git/config", "/.svn/entries", "/DS_Store"];
    for ep in &endpoints {
        let test_url = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(resp) = client.get(&test_url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if !body.is_empty() && body.len() < 200000 {
                    vulns.push(make_vuln(None, &format!("Exposed Endpoint: {}", ep), "Medium",
                        &format!("Debug/Info endpoint accessible at {}", test_url), Some("Disable debug endpoints in production; restrict access")));
                }
            }
        }
    }
}

async fn check_clickjacking(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    if let Ok(resp) = client.get(url).send().await {
        let has_xfo = resp.headers().get("x-frame-options").is_some();
        let has_csp = resp.headers().get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("frame-ancestors"))
            .unwrap_or(false);
        if !has_xfo && !has_csp {
            vulns.push(make_vuln(Some("CVE-CLICKJACK"), "Clickjacking (Missing X-Frame-Options)", "Medium",
                "Page can be embedded in an iframe", Some("Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'")));
        }
    }
}

async fn check_insecure_cookies(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    if let Ok(resp) = client.get(url).send().await {
        let cookies = resp.headers().get_all("set-cookie");
        for cookie in cookies {
            if let Ok(c) = cookie.to_str() {
                let lower = c.to_lowercase();
                if !lower.contains("secure") {
                    vulns.push(make_vuln(None, "Insecure Cookie (Missing Secure Flag)", "Low",
                        &format!("Cookie missing Secure flag: {}", c.split(';').next().unwrap_or("")), Some("Add Secure; HttpOnly; SameSite flags to all cookies")));
                }
                if !lower.contains("httponly") {
                    vulns.push(make_vuln(None, "Cookie Missing HttpOnly Flag", "Low",
                        &format!("Cookie missing HttpOnly flag: {}", c.split(';').next().unwrap_or("")), Some("Add HttpOnly flag to prevent JavaScript access")));
                }
            }
        }
    }
}

async fn check_hsts(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    if let Ok(resp) = client.get(url).send().await {
        let has_hsts = resp.headers().get("strict-transport-security").is_some();
        if !has_hsts {
            vulns.push(make_vuln(None, "Missing HSTS Header", "Low",
                "HTTP Strict-Transport-Security not set", Some("Add Strict-Transport-Security header with a long max-age")));
        }
    }
}

async fn check_http_vs_https(url: &str, vulns: &mut Vec<Vulnerability>) {
    if url.starts_with("https://") {
        let http_url = url.replacen("https://", "http://", 1);
        if let Some(client) = build_client(5) {
            if let Ok(resp) = client.get(&http_url).send().await {
                if resp.status().is_success() {
                    vulns.push(make_vuln(None, "HTTP Site Also Available", "Info",
                        &format!("Site also responds on HTTP at {}", http_url), Some("Redirect all HTTP traffic to HTTPS via 301")));
                }
            }
        }
    }
}

fn check_open_ports_common(host: &str, vulns: &mut Vec<Vulnerability>) {
    let common_dangerous = vec![21u16, 23, 25, 110, 143, 445, 3389, 5900, 6379, 27017, 135, 139, 1433, 1521, 2049, 3306, 5432, 8080, 8443, 9200, 11211, 27017];
    for port in common_dangerous {
        let addr: std::net::SocketAddr = match format!("{}:{}", host, port).parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1500)).is_ok() {
            vulns.push(make_vuln(None, &format!("Open Service Port {}/{}", port, service_name(port)), "Info",
                &format!("Port {} is open on {}", port, host), Some("Restrict access; use firewall rules")));
        }
    }
}

async fn check_weak_tls(host: &str, vulns: &mut Vec<Vulnerability>) {
    let url = format!("https://{}:443/", host);
    if let Ok(client) = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        if let Err(_) = client.get(&url).send().await {
            vulns.push(make_vuln(None, "TLS Connection Issue", "Low",
                &format!("Failed to establish HTTPS connection to {}", host),
                Some("Ensure TLS certificate is valid and properly configured")));
        }
    }
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 111 => "RPC", 135 => "EPMAP", 137 => "NetBIOS",
        139 => "SMB", 143 => "IMAP", 161 => "SNMP", 389 => "LDAP", 443 => "HTTPS",
        445 => "SMB", 465 => "SMTPS", 500 => "ISAKMP", 587 => "Submission",
        636 => "LDAPS", 993 => "IMAPS", 995 => "POP3S", 1080 => "SOCKS",
        1433 => "MSSQL", 1521 => "Oracle", 2049 => "NFS", 2375 => "Docker",
        2376 => "Docker-TLS", 3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL",
        5900 => "VNC", 5985 => "WinRM-HTTP", 5986 => "WinRM-HTTPS",
        6379 => "Redis", 8080 => "HTTP-Proxy", 8443 => "HTTPS-Alt",
        9200 => "Elasticsearch", 11211 => "Memcached", 27017 => "MongoDB",
        50070 => "Hadoop", 50075 => "Hadoop-Data", _ => "Unknown"
    }
}

fn urlencoding(s: &str) -> String {
    s.chars().map(|c| match c { 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(), _ => format!("%{:02X}", c as u8) }).collect()
}

fn encode_html_entities(s: &str) -> String {
    s.chars().map(|c| match c { '<' => "&lt;".into(), '>' => "&gt;".into(), '&' => "&amp;".into(), '"' => "&quot;".into(), '\'' => "&#x27;".into(), _ => c.to_string() }).collect()
}
