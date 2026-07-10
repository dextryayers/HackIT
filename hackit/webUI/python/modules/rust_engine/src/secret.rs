use crate::common::{SECRET_PATTERNS, SecretResult, SecretFinding, build_client};

pub async fn scan(url: &str) -> SecretResult {
    let full_url = if url.starts_with("http") { url.to_string() } else { format!("https://{}", url) };
    let mut secrets = Vec::new();
    let client = match build_client(10) { Some(c) => c, None => return SecretResult { url: full_url, secrets } };
    if let Ok(resp) = client.get(&full_url).send().await {
        if let Ok(body) = resp.text().await {
            let lower = body.to_lowercase();
            for (secret_type, _pattern) in SECRET_PATTERNS {
                let search_term = secret_type.to_lowercase();
                let keywords = match search_term.as_str() {
                    "aws access key" => vec!["AKIA"],
                    "google api key" => vec!["AIza"],
                    "jwt token" => vec!["eyJ"],
                    "private key" => vec!["-----BEGIN"],
                    "ssh key" => vec!["-----BEGIN OPENSSH"],
                    _ => continue,
                };
                for kw in keywords {
                    let mut pos = 0;
                    while let Some(idx) = lower[pos..].find(kw) {
                        let start = if pos + idx > 50 { pos + idx - 50 } else { 0 };
                        let end = std::cmp::min(pos + idx + 100, lower.len());
                        let context = &body[start..end];
                        let value = if context.len() > 100 { format!("...{}...", &context[..100]) } else { context.to_string() };
                        secrets.push(SecretFinding { secret_type: secret_type.to_string(), value, location: "page body".to_string() });
                        pos += idx + 1;
                    }
                }
            }
            let api_patterns = [
                ("AWS Key", &["AKIA"][..]),
                ("Google Key", &["AIza"][..]),
                ("JWT", &["eyJ"][..]),
                ("Private Key", &["-----BEGIN"]),
                ("Heroku", &["heroku"]),
                ("Slack", &["xoxb-", "xoxp-", "xoxa-"]),
                ("GitHub Token", &["ghp_"]),
                ("Discord Webhook", &["discord.com/api/webhooks"]),
                ("Slack Webhook", &["hooks.slack.com/services"]),
                ("MongoDB", &["mongodb+srv://"]),
                ("PostgreSQL", &["postgres://"]),
                ("MySQL", &["mysql://"]),
                ("Redis", &["redis://"]),
                ("Firebase", &[".firebaseio.com"]),
            ];
            for (name, patterns) in &api_patterns {
                for pattern in *patterns {
                    if lower.contains(pattern) {
                        if !secrets.iter().any(|s| s.secret_type == *name) {
                            let pos = lower.find(pattern).unwrap_or(0);
                            let start = if pos > 50 { pos - 50 } else { 0 };
                            let end = std::cmp::min(pos + 100, lower.len());
                            let value = format!("...{}...", &body[start..end]);
                            secrets.push(SecretFinding { secret_type: name.to_string(), value, location: "page body".to_string() });
                        }
                    }
                }
            }
        }
    }
    let js_paths = ["/main.js", "/app.js", "/bundle.js", "/index.js", "/vendor.js", "/api.js", "/config.js"];
    for js_path in &js_paths {
        let js_url = format!("{}{}", full_url.trim_end_matches('/'), js_path);
        if let Ok(resp) = client.get(&js_url).send().await {
            if let Ok(body) = resp.text().await {
                let lower = body.to_lowercase();
                for (secret_type, _) in SECRET_PATTERNS {
                    if lower.contains(&secret_type.to_lowercase()) && !secrets.iter().any(|s| s.secret_type == *secret_type) {
                        secrets.push(SecretFinding { secret_type: secret_type.to_string(), value: format!("Found in {}", js_path), location: js_path.to_string() });
                    }
                }
            }
        }
    }
    SecretResult { url: full_url, secrets }
}
