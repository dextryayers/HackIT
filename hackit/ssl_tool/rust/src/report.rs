use crate::types::*;

pub fn calculate_final_grade(r: &ScanResult) -> u32 {
    let mut score = 100i32;

    let cert = &r.certificate;
    if cert.expired { return 0; }
    if cert.self_signed { score -= 30; }
    if cert.key_strength == "Insecure" { score -= 25; }
    else if cert.key_strength == "Weak" { score -= 15; }
    let sig_lower = cert.sig_alg.to_lowercase();
    if sig_lower.contains("sha1") { score -= 15; }
    if cert.expires_soon { score -= 10; }
    if cert.wildcard { score -= 5; }
    if !cert.sct_present { score -= 5; }

    let cipher = &r.ciphers;
    for _ in &cipher.insecure { score -= 20; }
    for _ in &cipher.weak { score -= 10; }
    if !cipher.pfs_enabled { score -= 15; }

    for f in &r.vulnerabilities.findings {
        if f.status == "VULNERABLE" || f.status == "WEAK" {
            match f.severity.as_str() {
                "CRITICAL" => score -= 35,
                "HIGH" => score -= 25,
                "MEDIUM" => score -= 15,
                "LOW" => score -= 5,
                _ => {}
            }
        }
    }

    let tls = &r.tls_features;
    if !tls.tls_13_supported { score -= 10; }
    if !tls.ocsp_stapled { score -= 5; }
    if !tls.session_resumption { score -= 5; }

    score.max(0) as u32
}

pub fn calculate_grade(score: u32) -> String {
    match score {
        90..=100 => "A".to_string(),
        80..=89 => "A-".to_string(),
        70..=79 => "B+".to_string(),
        60..=69 => "B".to_string(),
        50..=59 => "C+".to_string(),
        40..=49 => "C".to_string(),
        30..=39 => "D+".to_string(),
        20..=29 => "D".to_string(),
        _ => "F".to_string(),
    }
}

pub fn collect_all_issues(r: &ScanResult) -> Vec<String> {
    let mut issues = Vec::new();
    issues.extend(r.certificate.issues.iter().cloned());
    for c in &r.ciphers.weak {
        issues.push(format!("Weak cipher: {}", c.name));
    }
    for c in &r.ciphers.insecure {
        issues.push(format!("Insecure cipher: {} ({})", c.name, c.reason));
    }
    for f in &r.vulnerabilities.findings {
        if f.status == "VULNERABLE" || f.status == "WEAK" {
            issues.push(format!("[{}] {}: {} (CVE: {})", f.severity, f.name, f.detail, f.cve));
        }
    }
    issues.extend(r.tls_features.issues.iter().cloned());
    issues.extend(r.dns.issues.iter().cloned());
    issues.extend(r.http.issues.iter().cloned());
    issues.extend(r.chain.issues.iter().cloned());
    issues.extend(r.crypto.issues.iter().cloned());
    issues.extend(r.port_scan.issues.iter().cloned());
    issues
}

pub fn generate_recommendations(r: &ScanResult) -> Vec<String> {
    let mut recs = Vec::new();

    if r.certificate.expired { recs.push("RENEW: Certificate has expired - renew immediately".to_string()); }
    if r.certificate.expires_soon { recs.push("RENEW: Certificate expires soon - schedule renewal".to_string()); }
    if r.certificate.self_signed { recs.push("REPLACE: Self-signed cert - use trusted CA certificate".to_string()); }
    if !r.certificate.sct_present { recs.push("ENHANCE: Add Certificate Transparency (SCT) logs".to_string()); }
    if r.certificate.key_strength == "Weak" || r.certificate.key_strength == "Insecure" {
        recs.push("UPGRADE: Weak key - generate stronger key (2048+ RSA or 256+ ECDSA)".to_string());
    }
    if r.certificate.sig_alg.to_lowercase().contains("sha1") {
        recs.push("UPDATE: Weak signature algorithm (SHA-1) - use SHA-256+".to_string());
    }

    if !r.ciphers.weak.is_empty() || !r.ciphers.insecure.is_empty() {
        recs.push("DISABLE: Remove weak/insecure ciphers from server config".to_string());
    }
    if !r.ciphers.pfs_enabled { recs.push("ENABLE: Configure PFS ciphers (ECDHE) for forward secrecy".to_string()); }

    for f in &r.vulnerabilities.findings {
        if f.status == "VULNERABLE" {
            recs.push(format!("PATCH: Fix {} ({})", f.name, f.cve));
        }
    }

    if !r.tls_features.tls_13_supported { recs.push("ENABLE: Enable TLS 1.3 for best security".to_string()); }
    if !r.tls_features.h2 { recs.push("ENABLE: Enable HTTP/2 (h2) for performance".to_string()); }
    if !r.tls_features.ocsp_stapled { recs.push("ENABLE: Configure OCSP stapling".to_string()); }
    for p in &r.tls_features.protocols {
        if p == "TLS 1.0" || p == "TLS 1.1" { recs.push(format!("DISABLE: Deprecated protocol {}", p)); }
    }

    if r.dns.spf.is_empty() { recs.push("CONFIGURE: Add SPF record to prevent email spoofing".to_string()); }
    if r.dns.dmarc.is_empty() { recs.push("CONFIGURE: Add DMARC record for email auth policy".to_string()); }

    if r.http.hsts.is_empty() { recs.push("ADD: HTTP Strict-Transport-Security (HSTS) header".to_string()); }
    if r.http.csp.is_empty() { recs.push("ADD: Content-Security-Policy (CSP) header".to_string()); }
    if r.http.x_frame_options.is_empty() { recs.push("ADD: X-Frame-Options header to prevent clickjacking".to_string()); }
    if !r.http.cookies_secure { recs.push("SECURE: Add Secure flag to cookies".to_string()); }
    if !r.http.cookies_httponly { recs.push("SECURE: Add HttpOnly flag to cookies".to_string()); }

    for p in &r.port_scan.open_ports {
        match p.port {
            21 => recs.push("REPLACE: FTP (21) with SFTP/SCP".to_string()),
            23 => recs.push("REPLACE: Telnet (23) with SSH".to_string()),
            3306 | 5432 => recs.push(format!("RESTRICT: Database port {} from public access", p.port)),
            _ => {}
        }
    }

    recs
}
