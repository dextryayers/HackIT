use crate::common::*;

pub async fn analyze(url: &str) -> CspAnalysisResult {
    let url = normalize_url(url);
    let mut result = CspAnalysisResult {
        url: url.clone(),
        has_csp: false,
        csp_header: None,
        csp_in_meta: None,
        directives: Vec::new(),
        issues: Vec::new(),
        security_score: 0,
        error: None,
    };

    if let Some(client) = build_client(15) {
        match client.get(&url).send().await {
            Ok(resp) => {
                let mut csp_policies: Vec<String> = Vec::new();

                if let Some(val) = resp.headers()
                    .get("content-security-policy")
                    .and_then(|v| v.to_str().ok())
                {
                    result.csp_header = Some(val.to_string());
                    csp_policies.push(val.to_string());
                }

                if let Some(val) = resp.headers()
                    .get("content-security-policy-report-only")
                    .and_then(|v| v.to_str().ok())
                {
                    if result.csp_header.is_none() {
                        result.csp_header = Some(val.to_string());
                    }
                    csp_policies.push(val.to_string());
                }

                if let Ok(body) = resp.text().await {
                    if let Some(meta_csp) = extract_meta_csp(&body) {
                        result.csp_in_meta = Some(meta_csp.clone());
                        csp_policies.push(meta_csp);
                    }
                }

                if !csp_policies.is_empty() {
                    result.has_csp = true;
                    for policy in &csp_policies {
                        parse_csp_policy(policy, &mut result);
                    }
                    analyze_csp_issues(&mut result);
                    compute_csp_score(&mut result);
                }
            }
            Err(e) => {
                result.error = Some(format!("{:.80}", e));
            }
        }
    }

    result
}

fn extract_meta_csp(body: &str) -> Option<String> {
    let patterns = [
        r#"<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*"([^"]*)"[^>]*>"#,
        r#"<meta[^>]*http-equiv\s*=\s*[']Content-Security-Policy['][^>]*content\s*=\s*'([^']*)'[^>]*>"#,
        r#"<meta[^>]*content\s*=\s*"([^"]*)"[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>"#,
        r#"<meta[^>]*content\s*=\s*'([^']*)'[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>"#,
    ];
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(body) {
                if let Some(val) = caps.get(1) {
                    return Some(val.as_str().to_string());
                }
            }
        }
    }
    None
}

fn parse_csp_policy(policy: &str, result: &mut CspAnalysisResult) {
    for directive_str in policy.split(';') {
        let trimmed = directive_str.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].to_lowercase();

        if result.directives.iter().any(|d| d.name == name) {
            continue;
        }

        let sources: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
        let is_unsafe = sources.iter().any(|s| {
            let lower = s.to_lowercase();
            lower == "'unsafe-inline'" || lower == "'unsafe-eval'" || lower == "*"
        });

        result.directives.push(CspDirective {
            name,
            sources,
            is_unsafe,
        });
    }
}

fn analyze_csp_issues(result: &mut CspAnalysisResult) {
    let has_default_src = result.directives.iter().any(|d| d.name == "default-src");
    let has_base_uri = result.directives.iter().any(|d| d.name == "base-uri");
    let has_form_action = result.directives.iter().any(|d| d.name == "form-action");

    let source_in = |name: &str, val: &str| -> bool {
        result.directives.iter().any(|d| d.name == name && d.sources.iter().any(|s| s == val))
    };

    if source_in("script-src", "'unsafe-inline'") || (!has_default_src && source_in("default-src", "'unsafe-inline'")) {
        result.issues.push(CspIssue {
            issue_type: "unsafe_inline_script".into(),
            severity: "high".into(),
            description: "script-src allows 'unsafe-inline', enabling XSS via inline scripts".into(),
        });
    }

    if source_in("style-src", "'unsafe-inline'") || (!has_default_src && source_in("default-src", "'unsafe-inline'")) {
        result.issues.push(CspIssue {
            issue_type: "unsafe_inline_style".into(),
            severity: "medium".into(),
            description: "style-src allows 'unsafe-inline', enabling style injection attacks".into(),
        });
    }

    if source_in("script-src", "'unsafe-eval'") || (!has_default_src && source_in("default-src", "'unsafe-eval'")) {
        result.issues.push(CspIssue {
            issue_type: "unsafe_eval".into(),
            severity: "medium".into(),
            description: "script-src allows 'unsafe-eval', enabling eval() execution".into(),
        });
    }

    if source_in("script-src", "*") || (!has_default_src && source_in("default-src", "*")) {
        result.issues.push(CspIssue {
            issue_type: "wildcard_script".into(),
            severity: "high".into(),
            description: "script-src allows wildcard (*), permitting scripts from any origin".into(),
        });
    }

    if source_in("object-src", "*") || (!has_default_src && source_in("default-src", "*")) {
        result.issues.push(CspIssue {
            issue_type: "wildcard_object".into(),
            severity: "high".into(),
            description: "object-src allows wildcard (*), permitting plugins from any origin".into(),
        });
    }

    if source_in("frame-ancestors", "*") {
        result.issues.push(CspIssue {
            issue_type: "wildcard_frame_ancestors".into(),
            severity: "medium".into(),
            description: "frame-ancestors allows wildcard (*), permitting embedding by any site".into(),
        });
    }

    let script_src_exists = result.directives.iter().any(|d| d.name == "script-src");
    if script_src_exists && source_in("script-src", "data:") {
        result.issues.push(CspIssue {
            issue_type: "data_in_script".into(),
            severity: "medium".into(),
            description: "script-src allows data: URIs, enabling script execution via data URIs".into(),
        });
    }

    if script_src_exists && source_in("script-src", "https:") {
        result.issues.push(CspIssue {
            issue_type: "https_scheme_script".into(),
            severity: "low".into(),
            description: "script-src allows the https: scheme broadly; consider using specific origins".into(),
        });
    }

    if !has_default_src {
        result.issues.push(CspIssue {
            issue_type: "missing_default_src".into(),
            severity: "medium".into(),
            description: "default-src is not set; directives fall back to no restriction".into(),
        });
    }

    if !has_base_uri {
        result.issues.push(CspIssue {
            issue_type: "missing_base_uri".into(),
            severity: "medium".into(),
            description: "base-uri is not set; attackers could inject <base> tags to hijack relative URLs".into(),
        });
    }

    if !has_form_action {
        result.issues.push(CspIssue {
            issue_type: "missing_form_action".into(),
            severity: "low".into(),
            description: "form-action is not set; form submissions are not restricted".into(),
        });
    }
}

fn compute_csp_score(result: &mut CspAnalysisResult) {
    if !result.has_csp {
        result.security_score = 0;
        return;
    }

    let mut score: i32 = 100;

    for issue in &result.issues {
        match issue.issue_type.as_str() {
            "unsafe_inline_script" | "wildcard_script" => score -= 20,
            "wildcard_object" => score -= 15,
            "unsafe_inline_style" | "unsafe_eval" | "wildcard_frame_ancestors"
            | "missing_default_src" | "missing_base_uri" | "data_in_script" => score -= 10,
            "missing_form_action" | "https_scheme_script" => score -= 5,
            _ => {}
        }
    }

    result.security_score = score.max(0) as u32;
}
