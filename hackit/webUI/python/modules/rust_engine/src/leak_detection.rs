use crate::common::{LeakDetectionResult, LeakFinding, build_client};

const LEAK_ENDPOINTS: &[&str] = &[
    "/.env", "/.git/config", "/.svn/entries", "/wp-config.php.bak",
    "/backup.sql", "/database.sql", "/dump.sql",
    "/config.json", "/config.php", "/settings.php",
    "/credentials.txt", "/passwords.txt", "/secret.txt",
    "/.aws/credentials", "/.azure/credentials",
    "/.gitlab-ci.yml", "/.travis.yml",
];

struct ContentCheck {
    leak_type: &'static str,
    severity: &'static str,
    search: &'static str,
    case_sensitive: bool,
}

const CONTENT_CHECKS: &[ContentCheck] = &[
    ContentCheck { leak_type: "RSA Private Key", severity: "critical", search: "BEGIN RSA PRIVATE KEY", case_sensitive: true },
    ContentCheck { leak_type: "OpenSSH Private Key", severity: "critical", search: "BEGIN OPENSSH PRIVATE KEY", case_sensitive: true },
    ContentCheck { leak_type: "Certificate", severity: "high", search: "-----BEGIN CERTIFICATE-----", case_sensitive: true },
    ContentCheck { leak_type: "Stripe Live Key", severity: "critical", search: "sk_live_", case_sensitive: true },
    ContentCheck { leak_type: "Stripe Test Key", severity: "medium", search: "sk_test_", case_sensitive: true },
    ContentCheck { leak_type: "GitHub Token", severity: "critical", search: "ghp_", case_sensitive: true },
    ContentCheck { leak_type: "GitHub OAuth Token", severity: "critical", search: "gho_", case_sensitive: true },
    ContentCheck { leak_type: "GitHub PAT", severity: "critical", search: "github_pat_", case_sensitive: true },
    ContentCheck { leak_type: "Password", severity: "high", search: "password", case_sensitive: false },
    ContentCheck { leak_type: "Passwd Entry", severity: "high", search: "passwd", case_sensitive: false },
    ContentCheck { leak_type: "Pwd Entry", severity: "high", search: "pwd", case_sensitive: false },
    ContentCheck { leak_type: "Secret", severity: "high", search: "secret", case_sensitive: false },
    ContentCheck { leak_type: "API Key", severity: "high", search: "api_key", case_sensitive: false },
    ContentCheck { leak_type: "API Key", severity: "high", search: "api-key", case_sensitive: false },
];

fn extract_preview(body: &str, pos: usize, context_len: usize) -> String {
    let start = if pos > context_len / 2 { pos - context_len / 2 } else { 0 };
    let end = std::cmp::min(pos + context_len / 2, body.len());
    let snippet = &body[start..end];
    format!("...{}...", snippet)
}

fn check_aws_key(body: &str) -> Option<(usize, String)> {
    let bytes = body.as_bytes();
    for i in 0..bytes.len().saturating_sub(19) {
        if bytes[i] == b'A' && bytes[i+1] == b'K' && bytes[i+2] == b'I' && bytes[i+3] == b'A' {
            let mut valid = true;
            for j in 4..20 {
                let c = bytes[i + j];
                if !(c.is_ascii_uppercase() || c.is_ascii_digit()) {
                    valid = false;
                    break;
                }
            }
            if valid {
                let key: String = body[i..i + 20].chars().collect();
                return Some((i, key));
            }
        }
    }
    None
}

pub async fn detect(target: &str) -> LeakDetectionResult {
    let base = if target.starts_with("http") {
        target.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", target.trim_end_matches('/'))
    };

    let client = match build_client(10) {
        Some(c) => c,
        None => return LeakDetectionResult {
            target: base,
            has_leaks: false,
            total_findings: 0,
            leaks: Vec::new(),
            error: Some("Failed to build HTTP client".to_string()),
        },
    };

    let mut leaks: Vec<LeakFinding> = Vec::new();

    for endpoint in LEAK_ENDPOINTS {
        if leaks.len() >= 50 {
            break;
        }

        let url = format!("{}{}", base, endpoint);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();
        if status == 404 || status == 0 {
            continue;
        }

        let body = resp.text().await.unwrap_or_default();

        let endpoint_preview = if body.len() > 200 {
            format!("...{}...", &body[..200])
        } else if !body.is_empty() {
            body.clone()
        } else {
            String::new()
        };

        leaks.push(LeakFinding {
            leak_type: "Exposed Endpoint".to_string(),
            severity: "high".to_string(),
            description: format!("{} is accessible (HTTP {})", endpoint, status),
            location: Some(url.clone()),
            value_preview: Some(endpoint_preview),
        });

        if leaks.len() >= 50 {
            break;
        }

        let body_lower = body.to_lowercase();

        for check in CONTENT_CHECKS {
            if leaks.len() >= 50 {
                break;
            }

            let search_lower = check.search.to_lowercase();
            let found = if check.case_sensitive {
                body.contains(check.search)
            } else {
                body_lower.contains(&search_lower)
            };

            if found {
                let body_ref = if check.case_sensitive { &body } else { &body_lower };
                let search_ref = if check.case_sensitive { check.search } else { &search_lower };
                let pos = match body_ref.find(search_ref) {
                    Some(p) => p,
                    None => continue,
                };

                leaks.push(LeakFinding {
                    leak_type: check.leak_type.to_string(),
                    severity: check.severity.to_string(),
                    description: format!("{} detected in {}", check.leak_type, endpoint),
                    location: Some(url.clone()),
                    value_preview: Some(extract_preview(&body, pos, 100)),
                });
            }
        }

        if leaks.len() >= 50 {
            break;
        }

        if let Some((pos, _)) = check_aws_key(&body) {
            leaks.push(LeakFinding {
                leak_type: "AWS Access Key".to_string(),
                severity: "critical".to_string(),
                description: format!("AWS access key detected in {}", endpoint),
                location: Some(url.clone()),
                value_preview: Some(extract_preview(&body, pos, 100)),
            });
        }
    }

    let total = leaks.len() as u32;
    LeakDetectionResult {
        target: base,
        has_leaks: total > 0,
        total_findings: total,
        leaks,
        error: None,
    }
}
