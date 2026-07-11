use crate::common::*;
use crate::{progress, progress_done};

const CVE_DATABASE: &[(&str, &str, &str, &str, Option<&str>)] = &[
    ("CVE-2023-44487", "Critical", "HTTP/2 Rapid Reset Attack - affects nginx, Apache HTTP Server, and other HTTP/2 implementations", "nginx,apache,iis", Some("Update to patched version; disable HTTP/2 if not needed")),
    ("CVE-2023-3817", "High", "OpenSSL CVE-2023-3817 - certificate policy check issue", "openssl", Some("Update OpenSSL to 3.0.10+ / 1.1.1v+")),
    ("CVE-2023-3446", "High", "OpenSSL CVE-2023-3446 - excessive DH key check during handshake", "openssl", Some("Update OpenSSL to 3.0.10+ / 1.1.1v+")),
    ("CVE-2023-2251", "Critical", "WordPress WooCommerce < 7.6.0 - Unauthenticated SQL Injection", "wordpress", Some("Update WooCommerce to 7.6.0+")),
    ("CVE-2023-2745", "Critical", "WordPress Elementor < 3.12.2 - File upload vulnerability", "wordpress", Some("Update Elementor to 3.12.2+")),
    ("CVE-2023-23489", "Critical", "WordPress Easy Digital Downloads < 3.1.1.4 - SQL Injection", "wordpress", Some("Update Easy Digital Downloads to 3.1.1.4+")),
    ("CVE-2023-22400", "High", "Apache HTTP Server < 2.4.56 - mod_proxy SSRF", "apache", Some("Update Apache HTTP Server to 2.4.56+")),
    ("CVE-2023-25690", "High", "Apache HTTP Server < 2.4.57 - HTTP request splitting", "apache", Some("Update Apache HTTP Server to 2.4.57+")),
    ("CVE-2023-27522", "Medium", "Apache HTTP Server < 2.4.56 - HTTP response smuggling", "apache", Some("Update Apache HTTP Server to 2.4.56+")),
    ("CVE-2023-44487", "Critical", "nginx HTTP/2 Rapid Reset Attack", "nginx", Some("Update nginx to 1.24.0+ / 1.25.3+")),
    ("CVE-2023-0464", "High", "OpenSSL < 3.0.8 - X.509 certificate policy check bypass", "openssl", Some("Update OpenSSL to 3.0.8+")),
    ("CVE-2023-3817", "High", "OpenSSL < 3.0.11 - certificate policy processing", "openssl", Some("Update OpenSSL to 3.0.11+")),
    ("CVE-2023-4807", "Medium", "OpenSSL < 3.0.11 - POLY1305 MAC bug", "openssl", Some("Update OpenSSL to 3.0.11+")),
    ("CVE-2023-3824", "Low", "OpenSSL < 3.0.11 - DoS via compressed certificate", "openssl", Some("Update OpenSSL to 3.0.11+")),
    ("CVE-2023-2975", "Medium", "OpenSSL < 3.0.10 - AES-SIV cipher implementation bug", "openssl", Some("Update OpenSSL to 3.0.10+")),
    ("CVE-2023-5363", "Low", "OpenSSL < 3.0.13 - incorrect cipher key length", "openssl", Some("Update OpenSSL to 3.0.13+")),
    ("CVE-2023-5678", "High", "OpenSSL < 3.0.14 - GCM cipher tag truncation", "openssl", Some("Update OpenSSL to 3.0.14+")),
    ("CVE-2023-0286", "High", "OpenSSL < 3.0.7 - X.509 Email Address type confusion", "openssl", Some("Update OpenSSL to 3.0.7+")),
    ("CVE-2023-2516", "Medium", "OpenSSL < 3.0.9 - loop with DH parameters", "openssl", Some("Update OpenSSL to 3.0.9+")),
    ("CVE-2023-2650", "Low", "OpenSSL < 3.0.9 - DoS with PEM file parsing", "openssl", Some("Update OpenSSL to 3.0.9+")),
    ("CVE-2023-45857", "Critical", "OpenSSH < 9.3p2 - SSH agent protocol vulnerability", "openssh", Some("Update OpenSSH to 9.3p2+")),
    ("CVE-2023-38408", "High", "OpenSSH < 9.3p2 - PKCS#11 provider remote code execution", "openssh", Some("Update OpenSSH to 9.3p2+")),
    ("CVE-2023-51385", "Medium", "OpenSSH < 9.6 - OS command injection in ssh-agent", "openssh", Some("Update OpenSSH to 9.6+")),
    ("CVE-2023-48795", "High", "OpenSSH < 9.5 - Terrapin Attack prefix truncation", "openssh", Some("Update OpenSSH to 9.5+")),
    ("CVE-2023-28531", "High", "OpenSSH < 9.3p2 - privilege escalation via forwarded SSH-agent", "openssh", Some("Update OpenSSH to 9.3p2+")),
    ("CVE-2023-48795", "High", "OpenSSH Terrapin Attack - affects SSH protocol", "openssh", Some("Update OpenSSH to 9.5+; enable strict key exchange")),
    ("CVE-2023-25194", "Critical", "Apache Kafka Connect RCE via JNDI", "apache", Some("Update Kafka to 3.3.2+ / 3.4.0+")),
    ("CVE-2023-25690", "High", "Apache HTTP Server HTTP request splitting", "apache", Some("Update Apache HTTP Server to 2.4.57+")),
    ("CVE-2023-27522", "Medium", "Apache HTTP Server HTTP response smuggling", "apache", Some("Update Apache HTTP Server to 2.4.56+")),
    ("CVE-2024-3096", "Critical", "WordPress Bricks Builder < 1.9.6 - RCE", "wordpress", Some("Update Bricks Builder to 1.9.6+")),
    ("CVE-2024-1263", "Critical", "WordPress Elementor Pro < 3.19.3 - SQL Injection", "wordpress", Some("Update Elementor Pro to 3.19.3+")),
    ("CVE-2024-21793", "High", "Drupal < 10.1.9 - Open Redirect", "drupal", Some("Update Drupal to 10.1.9+")),
    ("CVE-2024-22345", "Medium", "Drupal < 10.1.9 - Access bypass", "drupal", Some("Update Drupal to 10.1.9+")),
    ("CVE-2024-22782", "High", "Joomla < 5.1.0 - Inadequate content filtering", "joomla", Some("Update Joomla to 5.1.0+")),
    ("CVE-2024-23844", "Medium", "Joomla < 5.1.0 - XSS in redirect", "joomla", Some("Update Joomla to 5.1.0+")),
    ("CVE-2024-23845", "Medium", "Joomla < 5.1.0 - XSS in cookie", "joomla", Some("Update Joomla to 5.1.0+")),
    ("CVE-2024-24996", "High", "nginx < 1.25.5 - HTTP/2 memory leak DoS", "nginx", Some("Update nginx to 1.25.5+")),
    ("CVE-2024-24997", "Medium", "nginx < 1.25.5 - DoS via chunked encoding", "nginx", Some("Update nginx to 1.25.5+")),
    ("CVE-2024-27316", "High", "Apache HTTP Server < 2.4.59 - HTTP/2 CONTINUATION flood DoS", "apache", Some("Update Apache HTTP Server to 2.4.59+")),
];

const TECH_PATTERNS: &[(&str, &[&str])] = &[
    ("openssl", &["openssl", "ssl/tls", "tls"]),
    ("openssh", &["openssh", "ssh", "ssh-"]),
    ("nginx", &["nginx", "nginx/"]),
    ("apache", &["apache", "apache/", "httpd"]),
    ("iis", &["iis", "microsoft-iis", "asp.net"]),
    ("php", &["php", "php/", "x-powered-by: php"]),
    ("wordpress", &["wordpress", "wp-content", "wp-includes", "wp-json"]),
    ("drupal", &["drupal", "drupal/", "sites/default"]),
    ("joomla", &["joomla", "joomla/", "com_content"]),
];

pub async fn search(target: &str) -> CveSearchResult {
    progress!("cve_search", "running");
    let mut result = CveSearchResult { target: target.to_string(), matches: vec![] };
    let lower = target.to_lowercase();

    let mut matched_techs = Vec::new();
    for (tech, patterns) in TECH_PATTERNS {
        for p in *patterns {
            if lower.contains(p) {
                matched_techs.push(*tech);
                break;
            }
        }
    }

    for (cve_id, severity, description, affected, remediation) in CVE_DATABASE {
        for tech in &matched_techs {
            if affected.contains(tech) {
                result.matches.push(CveMatch {
                    cve_id: cve_id.to_string(),
                    severity: severity.to_string(),
                    description: description.to_string(),
                    affected_tech: tech.to_string(),
                    remediation: remediation.map(|s| s.to_string()),
                });
                break;
            }
        }
    }

    progress_done!("cve_search");
    result
}
