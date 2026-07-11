use crate::common::{VulnResult, Vulnerability, build_client, normalize_url};

pub async fn scan(target: &str) -> VulnResult {
    let url = normalize_url(target);
    let client = build_client(15);
    let mut vulns: Vec<Vulnerability> = Vec::new();
    let target_host = url
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    if let Some(ref client) = client {
        check_security_headers(client, &url, &mut vulns).await;
        check_clickjacking(client, &url, &mut vulns).await;
        check_insecure_cookies(client, &url, &mut vulns).await;
        check_info_disclosure(client, &url, &mut vulns).await;
        check_cve_correlation(client, &url, &mut vulns).await;
    }

    check_open_ports_async(&target_host, &mut vulns).await;
    check_http_available(&url, &mut vulns).await;

    VulnResult { target: target.to_string(), vulnerabilities: vulns }
}

fn make_vuln(cve_id: Option<&str>, name: &str, severity: &str, description: &str, remediation: Option<&str>) -> Vulnerability {
    Vulnerability {
        cve_id: cve_id.map(|s| s.into()),
        name: name.into(),
        severity: severity.into(),
        description: description.into(),
        remediation: remediation.map(|s| s.into()),
    }
}

async fn check_security_headers(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return,
    };

    if resp.headers().get("strict-transport-security").is_none() {
        vulns.push(make_vuln(None, "Missing HSTS Header", "Low",
            "HTTP Strict-Transport-Security header not set",
            Some("Add Strict-Transport-Security header with a long max-age (e.g. max-age=31536000; includeSubDomains)")));
    }

    if resp.headers().get("content-security-policy").is_none() {
        vulns.push(make_vuln(None, "Missing CSP Header", "Info",
            "No Content-Security-Policy header set",
            Some("Implement a CSP to mitigate XSS and data injection attacks")));
    }

    if resp.headers().get("x-content-type-options").is_none() {
        vulns.push(make_vuln(None, "Missing X-Content-Type-Options Header", "Low",
            "X-Content-Type-Options: nosniff header not set",
            Some("Add X-Content-Type-Options: nosniff to prevent MIME type sniffing")));
    }

    if resp.headers().get("referrer-policy").is_none() {
        vulns.push(make_vuln(None, "Missing Referrer-Policy Header", "Info",
            "Referrer-Policy header not set",
            Some("Add Referrer-Policy header (e.g. strict-origin-when-cross-origin)")));
    }

    if resp.headers().get("permissions-policy").is_none() {
        vulns.push(make_vuln(None, "Missing Permissions-Policy Header", "Info",
            "Permissions-Policy header not set",
            Some("Add Permissions-Policy header to restrict browser API access")));
    }
}

async fn check_clickjacking(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return,
    };

    let has_xfo = resp.headers().get("x-frame-options").is_some();
    let has_csp_frame = resp.headers().get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("frame-ancestors"))
        .unwrap_or(false);

    if !has_xfo && !has_csp_frame {
        vulns.push(make_vuln(None, "Clickjacking (Missing X-Frame-Options)", "Medium",
            "Page can be embedded in an iframe; no framing protection detected",
            Some("Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'")));
    }
}

async fn check_insecure_cookies(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return,
    };

    for cookie in resp.headers().get_all("set-cookie") {
        let cookie_str = match cookie.to_str() {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lower = cookie_str.to_lowercase();
        let name = cookie_str.split(';').next().unwrap_or("");

        if !lower.contains("secure") {
            vulns.push(make_vuln(None, "Insecure Cookie (Missing Secure Flag)", "Low",
                &format!("Cookie missing Secure flag: {}", name),
                Some("Add Secure; HttpOnly; SameSite flags to all cookies")));
        }
        if !lower.contains("httponly") {
            vulns.push(make_vuln(None, "Cookie Missing HttpOnly Flag", "Low",
                &format!("Cookie missing HttpOnly flag: {}", name),
                Some("Add HttpOnly flag to prevent JavaScript access to cookies")));
        }
    }
}

async fn check_info_disclosure(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let sensitive_paths = [
        "/.git/config", "/.env", "/.DS_Store", "/info.php", "/phpinfo.php",
        "/actuator/health", "/actuator/env", "/actuator/heapdump", "/actuator/threaddump",
        "/server-status", "/server-info", "/debug", "/api/debug",
        "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
    ];

    for path in &sensitive_paths {
        let test_url = format!("{}{}", url.trim_end_matches('/'), path);
        let resp = match client.get(&test_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if !resp.status().is_success() {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();
        if body.is_empty() || body.len() > 200000 {
            continue;
        }

        let (name, remediation) = info_disclosure_details(path, &body);
        vulns.push(make_vuln(None, &name, "Medium",
            &format!("Sensitive/Info endpoint accessible at {}", test_url),
            Some(remediation)));
    }
}

fn info_disclosure_details(path: &str, _body: &str) -> (String, &'static str) {
    match path {
        "/.git/config" => (String::from("Exposed .git/config"), "Remove .git directory from production; use .htaccess or firewall rules"),
        "/.env" => (String::from("Exposed .env File"), "Ensure .env files are not publicly accessible; configure web server to deny access"),
        "/.DS_Store" => (String::from("Exposed .DS_Store File"), "Remove .DS_Store files from production; block access via web server config"),
        "/info.php" | "/phpinfo.php" => (String::from("Exposed PHP Info"), "Remove phpinfo() files from production; they disclose sensitive system information"),
        "/actuator/health" | "/actuator/env" | "/actuator/heapdump" | "/actuator/threaddump" => {
            (String::from("Exposed Spring Actuator Endpoint"), "Disable Actuator endpoints in production or restrict access via authentication")
        }
        "/server-status" | "/server-info" => (String::from("Exposed Apache Server Info"), "Disable mod_status/mod_info or restrict access to internal IPs"),
        "/debug" | "/api/debug" => (String::from("Exposed Debug Endpoint"), "Disable debug mode in production"),
        "/swagger-resources" | "/v2/api-docs" | "/v3/api-docs" => {
            (String::from("Exposed API Documentation"), "Restrict API documentation access to authorized users only")
        }
        _ => (String::from("Exposed Sensitive Path"), "Restrict access to sensitive paths"),
    }
}

async fn check_cve_correlation(client: &reqwest::Client, url: &str, vulns: &mut Vec<Vulnerability>) {
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return,
    };

    let server = resp.headers().get("server")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase())
        .unwrap_or_default();

    let x_powered = resp.headers().get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase())
        .unwrap_or_default();

    let body = resp.text().await.unwrap_or_default();
    let body_lower = body.to_lowercase();

    let mut techs: Vec<&str> = Vec::new();

    if server.contains("nginx") { techs.push("nginx"); }
    if server.contains("apache") || server.contains("httpd") { techs.push("apache"); }
    if server.contains("iis") || x_powered.contains("asp.net") { techs.push("iis"); }
    if x_powered.contains("php") || body_lower.contains("php") { techs.push("php"); }
    if body_lower.contains("wordpress") || body_lower.contains("wp-content") || body_lower.contains("wp-json") {
        techs.push("wordpress");
    }
    if body_lower.contains("drupal") || body_lower.contains("/sites/default") { techs.push("drupal"); }
    if body_lower.contains("joomla") || body_lower.contains("/components/com_") { techs.push("joomla"); }
    if body_lower.contains("magento") || body_lower.contains("/skin/frontend") { techs.push("magento"); }

    let cve_db: &[(&str, &str, &str, &[&str], Option<&str>)] = &[
        ("CVE-2023-44487", "Critical", "HTTP/2 Rapid Reset Attack - affects nginx, Apache HTTP Server, and other HTTP/2 implementations", &["nginx", "apache", "iis"], Some("Update to patched version; disable HTTP/2 if not needed")),
        ("CVE-2023-22400", "High", "Apache HTTP Server < 2.4.56 - mod_proxy SSRF", &["apache"], Some("Update Apache HTTP Server to 2.4.56+")),
        ("CVE-2023-25690", "High", "Apache HTTP Server < 2.4.57 - HTTP request splitting", &["apache"], Some("Update Apache HTTP Server to 2.4.57+")),
        ("CVE-2023-27522", "Medium", "Apache HTTP Server < 2.4.56 - HTTP response smuggling", &["apache"], Some("Update Apache HTTP Server to 2.4.56+")),
        ("CVE-2024-27316", "High", "Apache HTTP Server < 2.4.59 - HTTP/2 CONTINUATION flood DoS", &["apache"], Some("Update Apache HTTP Server to 2.4.59+")),
        ("CVE-2024-24996", "High", "nginx < 1.25.5 - HTTP/2 memory leak DoS", &["nginx"], Some("Update nginx to 1.25.5+")),
        ("CVE-2024-24997", "Medium", "nginx < 1.25.5 - DoS via chunked encoding", &["nginx"], Some("Update nginx to 1.25.5+")),
        ("CVE-2023-2251", "Critical", "WordPress WooCommerce < 7.6.0 - Unauthenticated SQL Injection", &["wordpress"], Some("Update WooCommerce to 7.6.0+")),
        ("CVE-2024-3096", "Critical", "WordPress Bricks Builder < 1.9.6 - RCE", &["wordpress"], Some("Update Bricks Builder to 1.9.6+")),
        ("CVE-2024-1263", "Critical", "WordPress Elementor Pro < 3.19.3 - SQL Injection", &["wordpress"], Some("Update Elementor Pro to 3.19.3+")),
        ("CVE-2024-21793", "High", "Drupal < 10.1.9 - Open Redirect", &["drupal"], Some("Update Drupal to 10.1.9+")),
        ("CVE-2024-22345", "Medium", "Drupal < 10.1.9 - Access bypass", &["drupal"], Some("Update Drupal to 10.1.9+")),
        ("CVE-2024-22782", "High", "Joomla < 5.1.0 - Inadequate content filtering", &["joomla"], Some("Update Joomla to 5.1.0+")),
        ("CVE-2024-23844", "Medium", "Joomla < 5.1.0 - XSS in redirect", &["joomla"], Some("Update Joomla to 5.1.0+")),
        ("CVE-2024-23845", "Medium", "Joomla < 5.1.0 - XSS in cookie", &["joomla"], Some("Update Joomla to 5.1.0+")),
        ("CVE-2023-25194", "Critical", "Apache Kafka Connect RCE via JNDI", &["apache"], Some("Update Kafka to 3.3.2+ / 3.4.0+")),
    ];

    for &(cve_id, severity, description, affected_techs, remediation) in cve_db {
        if affected_techs.iter().any(|t| techs.contains(t)) {
            vulns.push(make_vuln(Some(cve_id), &format!("Potential: {}", cve_id), severity,
                &format!("{} (detected technology may be affected)", description),
                remediation));
        }
    }
}

async fn check_open_ports_async(host: &str, vulns: &mut Vec<Vulnerability>) {
    let important_ports: &[(u16, &str)] = &[
        (21, "FTP"), (23, "Telnet"), (25, "SMTP"), (110, "POP3"),
        (143, "IMAP"), (445, "SMB"), (3389, "RDP"), (5900, "VNC"),
        (6379, "Redis"), (27017, "MongoDB"), (135, "EPMAP"), (139, "SMB"),
        (1433, "MSSQL"), (1521, "Oracle"), (2049, "NFS"), (3306, "MySQL"),
        (5432, "PostgreSQL"), (8080, "HTTP-Proxy"), (8443, "HTTPS-Alt"),
        (9200, "Elasticsearch"), (11211, "Memcached"),
    ];

    for &(port, service) in important_ports {
        let addr = format!("{}:{}", host, port);
        let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() else {
            continue;
        };

        let connected = tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            tokio::net::TcpStream::connect(socket_addr),
        ).await;

        if connected.is_ok() && connected.unwrap().is_ok() {
            vulns.push(make_vuln(None, &format!("Open Service Port {}/{}", port, service), "Info",
                &format!("Port {} ({}) is open on {}", port, service, host),
                Some("Restrict access to necessary services; use firewall rules")));
        }
    }
}

async fn check_http_available(url: &str, vulns: &mut Vec<Vulnerability>) {
    if !url.starts_with("https://") {
        return;
    }

    let http_url = url.replacen("https://", "http://", 1);
    if let Some(client) = build_client(5) {
        if let Ok(resp) = client.get(&http_url).send().await {
            if resp.status().is_success() {
                vulns.push(make_vuln(None, "HTTP Site Also Available", "Info",
                    &format!("Site also responds on HTTP at {}", http_url),
                    Some("Redirect all HTTP traffic to HTTPS via 301 redirect")));
            }
        }
    }
}
