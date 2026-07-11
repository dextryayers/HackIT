use crate::common::{CrawlResult, WebFormInfo, InputField, build_client, normalize_url};
use regex::Regex;

pub async fn analyze(url: &str) -> CrawlResult {
    let full_url = normalize_url(url);
    let client = build_client(15);
    let mut result = CrawlResult {
        url: full_url.clone(), title: None, links: Vec::new(), meta: Vec::new(),
        status: None, scripts: Vec::new(), forms: Vec::new(),
        api_endpoints: Vec::new(), spa_framework: None, js_files: Vec::new(),
    };
    let domain = full_url.replace("https://", "").replace("http://", "").split('/').next().unwrap_or("").to_string();

    if let Some(client) = client {
        if let Ok(resp) = client.get(&full_url).send().await {
            result.status = Some(resp.status().as_u16());
            if let Ok(body) = resp.text().await {
                let lower = body.to_lowercase();

                // Title
                if let Some(start) = lower.find("<title") {
                    if let Some(ts) = lower[start..].find('>') {
                        if let Some(te) = lower[start+ts+1..].find("</title") {
                            result.title = Some(body[start+ts+1..start+ts+1+te].trim().to_string());
                        }
                    }
                }

                // Meta tags
                let meta_re = Regex::new(r#"(?i)<meta\s[^>]*>"#).unwrap();
                for cap in meta_re.captures_iter(&body) {
                    let tag = cap[0].to_lowercase();
                    let name = extract_attr(&tag, "name").or_else(|| extract_attr(&tag, "property"));
                    let content = extract_attr(&tag, "content");
                    if let (Some(n), Some(c)) = (name, content) {
                        result.meta.push((n, c));
                    }
                }

                // Links
                let href_re = Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
                for cap in href_re.captures_iter(&body) {
                    let link = cap[1].to_string();
                    if (link.starts_with("http") || link.starts_with('/') || link.starts_with('.')) && link.len() > 3 && link.len() < 500 {
                        result.links.push(link);
                    }
                }

                // Scripts
                let script_re = Regex::new(r#"(?i)<script[^>]*src=["']([^"']+)["']"#).unwrap();
                for cap in script_re.captures_iter(&body) {
                    let src = cap[1].to_string();
                    let full = if src.starts_with("http") { src.clone() }
                        else if src.starts_with('/') { format!("{}://{}", if full_url.starts_with("https") {"https"} else {"http"}, domain) + &src }
                        else { format!("{}/{}", full_url.trim_end_matches('/'), src) };
                    result.js_files.push(full.clone());
                    result.scripts.push(full);
                }

                // Forms
                extract_forms(&body, &mut result.forms);

                // API endpoints from HTML
                extract_api_endpoints(&body, &mut result.api_endpoints);

                // SPA framework detection
                detect_spa_framework(&body, &mut result.spa_framework);

                // JS file content analysis
                for js_url in result.js_files.iter().take(5) {
                    if let Ok(js_resp) = client.get(js_url).send().await {
                        if let Ok(js_body) = js_resp.text().await {
                            extract_api_endpoints(&js_body, &mut result.api_endpoints);
                        }
                    }
                }
            }
        }

        // Check common API endpoints
        check_api_endpoints(&client, &full_url, &mut result.api_endpoints).await;
    }

    result.links.sort(); result.links.dedup(); result.links.truncate(200);
    result
}

fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"(?i){}\s*=\s*["']([^"']*)["']"#, regex::escape(attr))).ok()?;
    re.captures(tag).map(|c| c[1].to_string())
}

fn extract_forms(html: &str, forms: &mut Vec<WebFormInfo>) {
    let form_re = Regex::new(r#"(?i)<form[^>]*>"#).unwrap();
    let input_re = Regex::new(r#"(?i)<input[^>]*>"#).unwrap();
    let method_re = Regex::new(r#"(?i)method\s*=\s*["']([^"']*)["']"#).unwrap();

    for cap in form_re.captures_iter(html) {
        let form_tag = cap[0].to_string();
        let action = extract_attr(&form_tag, "action").unwrap_or_default();
        let method = method_re.captures(&form_tag).map(|m| m[1].to_string().to_uppercase()).unwrap_or_else(|| "GET".into());

        let mut inputs = Vec::new();
        let form_start = cap.get(0).unwrap().start();
        let rest = &html[form_start..];
        let end = rest.find("</form>").map(|e| e).unwrap_or(0);
        let form_html = &rest[..end];

        for inp in input_re.captures_iter(form_html) {
            let inp_str = inp[0].to_string();
            let name = extract_attr(&inp_str, "name").unwrap_or_default();
            let type_field = extract_attr(&inp_str, "type").unwrap_or_else(|| "text".into());
            let required = inp_str.to_lowercase().contains("required");
            inputs.push(InputField { name, type_field, required });
        }

        forms.push(WebFormInfo { action, method, inputs });
    }
}

fn extract_api_endpoints(html: &str, endpoints: &mut Vec<String>) {
    let patterns = [
        r#"(?i)["'](https?://[^"']*api[^"']*|/[a-z]+/api/[^"']*|/api/v[0-9]+[^"']*)["']"#,
        r#"(?i)(?:fetch|axios|ajax|getJSON)\s*\(\s*['"]([^'"]+)['"]"#,
        r#"(?i)(?:url|endpoint|baseURL)[:=]\s*['"]([^'"]+)['"]"#,
    ];
    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(html) {
                let ep = cap[1].to_string();
                if !endpoints.contains(&ep) && (ep.starts_with("http") || ep.starts_with('/')) {
                    endpoints.push(ep);
                }
            }
        }
    }
}

fn detect_spa_framework(body: &str, framework: &mut Option<String>) {
    let b = body.to_lowercase();
    if b.contains("__next") || b.contains("next.js") || b.contains("next/static") || b.contains("_next/") { *framework = Some("Next.js".into()); }
    else if b.contains("__nuxt") || b.contains("nuxt") || b.contains("_nuxt/") || b.contains("nuxt3") { *framework = Some("Nuxt.js".into()); }
    else if b.contains("__vue__") || b.contains("vue") && b.contains("v-bind") || b.contains("vue-router") || b.contains("vuex") { *framework = Some("Vue.js".into()); }
    else if b.contains("reactroot") || b.contains("react-dom") || b.contains("__react") || b.contains("react/cjs") { *framework = Some("React".into()); }
    else if b.contains("ng-version") || b.contains("angular") || b.contains("ng-app") || b.contains("ng-controller") { *framework = Some("Angular".into()); }
    else if b.contains("svelte") && b.contains("__svelte") || b.contains("sveltekit") { *framework = Some("Svelte".into()); }
    else if b.contains("gatsby") || b.contains("gatsby/") { *framework = Some("Gatsby".into()); }
    else if b.contains("remix") { *framework = Some("Remix".into()); }
    else if b.contains("astro") { *framework = Some("Astro".into()); }
}

async fn check_api_endpoints(client: &reqwest::Client, base_url: &str, endpoints: &mut Vec<String>) {
    let common = vec![
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/health", "/api/status",
        "/graphql", "/api/graphql", "/graphiql", "/playground",
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/api/docs",
        "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
        "/rest", "/rest/v1", "/rest/v2",
        "/api/users", "/api/login", "/api/auth", "/api/token", "/api/register",
        "/api/config", "/api/settings", "/api/admin",
    ];
    let base = base_url.trim_end_matches('/');
    for ep in &common {
        let url = format!("{}{}", base, ep);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status < 500 && status != 404 {
                if let Ok(body) = resp.text().await {
                    if !body.contains("404 Not Found") && !body.contains("resource not found") && !body.contains("Cannot GET") {
                        endpoints.push(format!("{} ({})", ep, status));
                    }
                }
            }
        }
    }
}
