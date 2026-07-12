use crate::common::{ScanConfig, build_client, FormInfo};
use crate::common::WebFormDiscoveryResult;
use std::time::Duration;
use tokio::task;

const FORM_PATHS: &[&str] = &[
    "/", "/login", "/register", "/signup", "/contact", "/search",
    "/feedback", "/subscribe", "/newsletter", "/apply", "/order",
    "/checkout", "/payment", "/donate", "/survey", "/poll",
    "/comment", "/review", "/rate", "/upload", "/submit",
    "/booking", "/reservation", "/enquiry", "/quote", "/request",
];

pub async fn scan(target: &str, _config: &ScanConfig) -> WebFormDiscoveryResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_lowercase();
    let base_url = format!("https://{}", domain);
    let timeout = Duration::from_secs(8);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(15));
    let mut handles = Vec::new();

    for &path in FORM_PATHS {
        let url = format!("{}{}", base_url, path);
        let client = client.clone();
        let sem = sem.clone();

        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let body = resp.text().await.unwrap_or_default();
            let lower = body.to_lowercase();

            let in_form = lower.contains("<form") && lower.contains("</form>");
            if !in_form {
                return None;
            }

            let action = extract_attr(&body, "action");
            let method = extract_attr(&body, "method").to_uppercase();
            let method = if method.is_empty() { "GET".to_string() } else { method };

            let mut inputs = Vec::new();
            let mut sensitive_inputs = Vec::new();
            let has_csrf = body.to_lowercase().contains("csrf")
                || body.to_lowercase().contains("_token")
                || body.to_lowercase().contains("authenticity_token");

            let mut pos = 0;
            while let Some(start) = body[pos..].find("<input") {
                let end = body[pos + start..].find('>').map(|e| pos + start + e + 1).unwrap_or(body.len());
                let tag = &body[pos + start..end.min(pos + start + 300)];
                let input_type = get_attr_value(tag, "type").unwrap_or("text");
                let input_name = get_attr_value(tag, "name").unwrap_or("");
                inputs.push(format!("{}:{}", input_type, input_name));
                let tag_lower = tag.to_lowercase();
                if tag_lower.contains("password") || tag_lower.contains("secret")
                    || tag_lower.contains("credit") || tag_lower.contains("ssn")
                    || tag_lower.contains("token") || tag_lower.contains("key") {
                    sensitive_inputs.push(format!("{}:{}", input_type, input_name));
                }
                pos = end;
                if inputs.len() > 30 { break; }
            }

            Some((path.to_string(), vec![FormInfo {
                action, method, inputs, has_csrf, sensitive_inputs,
            }]))
        }));
    }

    let mut total_forms = 0;
    let mut paths_with_forms = Vec::new();
    let mut all_forms = Vec::new();

    for h in handles {
        if let Ok(Some((path, forms))) = h.await {
            paths_with_forms.push(path);
            total_forms += forms.len();
            all_forms.extend(forms);
        }
    }

    WebFormDiscoveryResult {
        domain,
        pages_checked: FORM_PATHS.len(),
        pages_with_forms: paths_with_forms.len(),
        total_forms,
        paths: paths_with_forms,
        forms: all_forms.into_iter().take(50).collect(),
    }
}

fn extract_attr(html: &str, attr: &str) -> String {
    let lower = html.to_lowercase();
    let needle = format!("{}=\"", attr);
    if let Some(start) = lower.find(&needle) {
        let val_start = start + needle.len();
        if let Some(end) = lower[val_start..].find('"') {
            return html[val_start..val_start + end].to_string();
        }
    }
    String::new()
}

fn get_attr_value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let needle = format!("{}=\"", attr);
    let lower = tag.to_lowercase();
    if let Some(start) = lower.find(&needle) {
        let val_start = start + needle.len();
        let end = lower[val_start..].find('"')?;
        Some(&tag[val_start..val_start + end])
    } else {
        None
    }
}
