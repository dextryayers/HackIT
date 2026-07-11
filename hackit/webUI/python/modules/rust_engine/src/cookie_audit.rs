use crate::common::*;
use crate::{progress, progress_done};

pub async fn audit(url: &str) -> CookieAuditResult {
    progress!("cookie_audit", "running");
    let url = normalize_url(url);
    let mut result = CookieAuditResult { url: url.clone(), cookies: vec![], issues: vec![], score: Some(0u32) };
    if let Some(client) = build_client(10) {
        if let Ok(resp) = client.get(&url).send().await {
            for header in resp.headers().get_all("set-cookie") {
                if let Ok(raw) = header.to_str() {
                    let parts: Vec<&str> = raw.split(';').collect();
                    let name = parts.first().and_then(|p| p.split('=').next()).unwrap_or("unknown").to_string();
                    let secure = raw.to_lowercase().contains("secure");
                    let http_only = raw.to_lowercase().contains("httponly");
                    let same_site = parts.iter().find(|p| p.trim().to_lowercase().starts_with("samesite"))
                        .and_then(|p| p.split('=').nth(1))
                        .map(|s| s.trim().to_string());
                    result.cookies.push(CookieInfo { name: name.clone(), secure, http_only, same_site: same_site.clone() });
                    let mut score = result.score.unwrap_or(0);
                    if secure { score += 25; }
                    if http_only { score += 25; }
                    if let Some(ref ss) = same_site {
                        if ss.eq_ignore_ascii_case("lax") || ss.eq_ignore_ascii_case("strict") {
                            score += 25;
                        }
                    }
                    result.score = Some(score.min(100));
                    if !secure {
                        result.issues.push(format!("Cookie '{}' missing Secure flag", name));
                    }
                    if !http_only {
                        result.issues.push(format!("Cookie '{}' missing HttpOnly flag", name));
                    }
                    if same_site.is_none() {
                        result.issues.push(format!("Cookie '{}' missing SameSite attribute", name));
                    }
                }
            }
        }
    }
    progress_done!("cookie_audit");
    result
}
