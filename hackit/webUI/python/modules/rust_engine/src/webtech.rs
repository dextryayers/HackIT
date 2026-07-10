use crate::common::{WebtechResult, build_client};

pub async fn detect(url: &str) -> WebtechResult {
    let full_url = if url.starts_with("http") { url.to_string() } else { format!("https://{}", url) };
    let client = build_client(10);
    let mut result = WebtechResult { url: full_url.clone(), status: None, server: None, tech: vec![], headers: vec![] };
    if let Some(client) = client {
        if let Ok(resp) = client.get(&full_url).send().await {
            result.status = Some(resp.status().as_u16());
            for (name, value) in resp.headers().iter() {
                let n = name.as_str().to_string(); let v = value.to_str().unwrap_or("").to_string();
                result.headers.push((n.clone(), v.clone()));
                match n.as_str() {
                    "server" => { result.server = Some(v.clone()); if v.contains("nginx") { result.tech.push("Nginx".into()); } else if v.contains("Apache") { result.tech.push("Apache".into()); } else if v.contains("cloudflare") { result.tech.push("Cloudflare".into()); } else if v.contains("IIS") { result.tech.push("IIS".into()); } }
                    "x-powered-by" => { if v.contains("PHP") { result.tech.push("PHP".into()); } else if v.contains("ASP.NET") { result.tech.push("ASP.NET".into()); } else if v.contains("Express") { result.tech.push("Express".into()); } }
                    "x-generator" => { result.tech.push(format!("Generator:{}", v)); }
                    "cf-ray" => result.tech.push("Cloudflare".into()),
                    "x-amz-cf-id" => result.tech.push("AWS CloudFront".into()),
                    "x-akamai-transformed" => result.tech.push("Akamai".into()),
                    "x-fastly-request-id" => result.tech.push("Fastly".into()),
                    _ => {}
                }
            }
            if let Ok(body) = resp.text().await {
                let b = body.to_lowercase();
                if b.contains("wp-content") || b.contains("wp-includes") { result.tech.push("WordPress".into()); }
                if b.contains("joomla") { result.tech.push("Joomla".into()); }
                if b.contains("drupal") { result.tech.push("Drupal".into()); }
                if b.contains("laravel") || (b.contains("csrf-token") && b.contains("laravel_session")) { result.tech.push("Laravel".into()); }
                if b.contains("react") || b.contains("reactroot") { result.tech.push("React".into()); }
                if b.contains("vue") || b.contains("__vue__") { result.tech.push("Vue.js".into()); }
                if b.contains("angular") || b.contains("ng-version") { result.tech.push("Angular".into()); }
                if b.contains("next.js") || b.contains("__next") { result.tech.push("Next.js".into()); }
                if b.contains("nuxt") { result.tech.push("Nuxt.js".into()); }
                if b.contains("jquery") { result.tech.push("jQuery".into()); }
                if b.contains("bootstrap") { result.tech.push("Bootstrap".into()); }
                if b.contains("tailwind") { result.tech.push("Tailwind CSS".into()); }
                if b.contains("shopify") || b.contains("/cdn/shop/") { result.tech.push("Shopify".into()); }
                if b.contains("squarespace") { result.tech.push("Squarespace".into()); }
            }
        }
    }
    result.tech.sort(); result.tech.dedup();
    result
}
