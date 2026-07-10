use crate::common::EmailResult;

pub async fn discover(domain: &str) -> EmailResult {
    let prefixes = [
        "admin","info","support","sales","contact","webmaster","hostmaster","postmaster","abuse","noreply",
        "help","billing","marketing","press","jobs","hr","pr","feedback","hello","team","careers",
        "newsletter","register","subscribe","unsubscribe","blog","community","developer","dev","engineering",
        "tech","security","dmca","legal","copyright","partner","service","shop","store","investor",
    ];
    let mut patterns: Vec<String> = prefixes.iter().map(|p| format!("{}@{}", p, domain)).collect();
    patterns.sort(); patterns.dedup();
    if let Ok(resp) = reqwest::get(&format!("https://{}", domain)).await {
        if let Ok(body) = resp.text().await {
            let chars: Vec<char> = body.to_lowercase().chars().collect();
            for i in 0..chars.len().saturating_sub(3) {
                if chars[i] == '@' {
                    let mut start = i; let mut end = i + 1;
                    while start > 0 && (chars[start-1].is_alphanumeric() || ". _ % +".contains(chars[start-1])) { start -= 1; }
                    while end < chars.len() && (chars[end].is_alphanumeric() || " . - _".contains(chars[end])) { end += 1; }
                    let email: String = chars[start..end].iter().collect();
                    if email.len() > 5 && email.contains('.') && email.ends_with(domain) && !patterns.contains(&email) {
                        patterns.push(email);
                    }
                }
            }
        }
    }
    patterns.sort(); patterns.dedup();
    EmailResult { domain: domain.to_string(), count: patterns.len(), patterns }
}
