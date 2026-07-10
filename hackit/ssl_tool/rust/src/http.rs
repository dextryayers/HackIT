use crate::types::*;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

pub async fn http_check(host: &str, port: u16, tmo: Duration) -> HTTPReport {
    let mut r = HTTPReport::default();
    let addr = format!("{}:{}", host, port);

    let mut stream = match timeout(tmo, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => {
            r.issues.push("TCP connection failed".to_string());
            return r;
        }
    };

    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: HackIT-Scanner/3.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host
    );

    if timeout(tmo, stream.write_all(req.as_bytes())).await.is_err() {
        r.issues.push("Failed to send HTTP request".to_string());
        return r;
    }

    let mut buf = vec![0u8; 16384];
    let n = match timeout(tmo, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => {
            r.issues.push("No HTTP response".to_string());
            return r;
        }
    };

    let response = String::from_utf8_lossy(&buf[..n]).to_string();
    let mut lines = response.lines();
    let mut headers = Vec::new();

    if let Some(status_line) = lines.next() {
        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            r.status = parts[1].parse().unwrap_or(0);
        }
    }

    for line in lines.by_ref() {
        if line.is_empty() { break; }
        if let Some(pos) = line.find(':') {
            let name = line[..pos].trim().to_string();
            let value = line[pos+1..].trim().to_string();
            headers.push(HeaderInfo { name: name.clone(), value: value.clone() });

            let lower = name.to_lowercase();
            match lower.as_str() {
                "server" => r.server = value,
                "location" => r.location = value,
                "content-type" => r.content_type = value,
                "content-length" => r.content_length = value.parse().unwrap_or(0),
                "last-modified" => r.last_modified = value,
                "strict-transport-security" => {
                    r.hsts = value.clone();
                    r.hsts_valid = true;
                    if let Some(ma) = value.to_lowercase().find("max-age=") {
                        let rest = &value[ma + 8..];
                        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                        r.strict_transport_security_max_age = num_str.parse().unwrap_or(0);
                    }
                    r.strict_transport_security_include_subdomains = value.to_lowercase().contains("includesubdomains");
                    r.strict_transport_security_preload = value.to_lowercase().contains("preload");
                }
                "content-security-policy" => {
                    r.csp = value.clone();
                    r.content_security_policy_directives = value.split(';').map(|s| s.trim().to_string()).collect();
                }
                "x-frame-options" => r.x_frame_options = value,
                "x-content-type-options" => r.x_content_type = value,
                "x-xss-protection" => r.x_xss_protection = value,
                "referrer-policy" => r.referrer_policy = value,
                "permissions-policy" => r.permissions_policy = value,
                "x-permitted-cross-domain-policies" => r.x_permitted_cross_domain_policies = value,
                "cross-origin-embedder-policy" => r.cross_origin_embedder_policy = value,
                "cross-origin-opener-policy" => r.cross_origin_opener_policy = value,
                "cross-origin-resource-policy" => r.cross_origin_resource_policy = value,
                "access-control-allow-origin" => r.access_control_allow_origin = value,
                "access-control-allow-methods" => r.access_control_allow_methods = value,
                "set-cookie" => {
                    let cookie = CookieInfo {
                        name: value.split('=').next().unwrap_or("").to_string(),
                        value: value.clone(),
                        secure: value.to_lowercase().contains("secure"),
                        httponly: value.to_lowercase().contains("httponly"),
                        samesite: if value.to_lowercase().contains("samesite=lax") { "Lax".to_string() }
                                  else if value.to_lowercase().contains("samesite=strict") { "Strict".to_string() }
                                  else if value.to_lowercase().contains("samesite=none") { "None".to_string() }
                                  else { "Not Set".to_string() },
                        domain: String::new(),
                        path: String::new(),
                        max_age: 0,
                    };
                    if cookie.secure { r.cookies_secure = true; }
                    if cookie.httponly { r.cookies_httponly = true; }
                    r.set_cookie.push(cookie);
                }
                _ => {}
            }
        }
    }

    r.headers_raw = headers;

    r.issues = build_http_issues(&r);
    let mut sc = 100i32;
    if r.hsts.is_empty() { sc -= 20; }
    if r.csp.is_empty() { sc -= 15; }
    if r.x_frame_options.is_empty() { sc -= 10; }
    if r.x_content_type.is_empty() { sc -= 5; }
    if r.referrer_policy.is_empty() { sc -= 5; }
    if !r.cookies_secure { sc -= 10; }
    if !r.cookies_httponly { sc -= 5; }
    r.score = sc.max(0) as u32;
    r
}

fn build_http_issues(r: &HTTPReport) -> Vec<String> {
    let mut issues = Vec::new();
    if r.hsts.is_empty() { issues.push("HTTP Strict-Transport-Security (HSTS) header missing".to_string()); }
    if r.csp.is_empty() { issues.push("Content-Security-Policy (CSP) header missing".to_string()); }
    if r.x_frame_options.is_empty() { issues.push("X-Frame-Options header missing - clickjacking risk".to_string()); }
    if r.x_content_type.is_empty() { issues.push("X-Content-Type-Options header missing".to_string()); }
    if r.referrer_policy.is_empty() { issues.push("Referrer-Policy header missing".to_string()); }
    if !r.cookies_secure { issues.push("Cookies missing Secure flag".to_string()); }
    if !r.cookies_httponly { issues.push("Cookies missing HttpOnly flag".to_string()); }
    issues
}
