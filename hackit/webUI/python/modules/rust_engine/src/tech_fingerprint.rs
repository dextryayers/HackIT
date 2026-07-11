use crate::common::*;
use crate::{progress, progress_done};
use regex::Regex;

pub async fn fingerprint(url: &str) -> TechFingerprintResult {
    progress!("tech_fingerprint", "running");
    let mut result = TechFingerprintResult { url: url.to_string(), ..Default::default() };
    let url = normalize_url(url);

    if let Some(client) = build_client(15) {
        match client.get(&url).send().await {
            Ok(resp) => {
                let headers = resp.headers().clone();
                let server = headers.get("server").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                let x_powered = headers.get("x-powered-by").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                let x_generator = headers.get("x-generator").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
                let x_aspnet = headers.get("x-aspnet-version").and_then(|v| v.to_str().ok()).map(|s| s.to_string());

                if let Some(ref v) = server {
                    result.webserver = Some(v.clone());
                    let lower = v.to_lowercase();
                    if lower.contains("cloudflare") { result.cdn = Some("Cloudflare".into()); }
                    else if lower.contains("cloudfront") { result.cdn = Some("AWS CloudFront".into()); }
                    else if lower.contains("fastly") { result.cdn = Some("Fastly".into()); }
                    else if lower.contains("akamai") { result.cdn = Some("Akamai".into()); }
                }
                if let Some(ref v) = x_powered {
                    let lower = v.to_lowercase();
                    if lower.contains("php") { result.languages.push("PHP".into()); }
                    if lower.contains("asp.net") { result.languages.push("ASP.NET".into()); }
                    if lower.contains("express") { result.frameworks.push("Express".into()); }
                }
                if let Some(v) = x_generator { result.cms = Some(v); }
                if let Some(v) = x_aspnet { result.languages.push(format!(".NET {}", v)); }

                if let Ok(body) = resp.text().await {
                    let lower_body = body.to_lowercase();
                    let body_slice = &lower_body;

                    if body_slice.contains("wordpress") || body_slice.contains("wp-content") || body_slice.contains("wp-includes") || body_slice.contains("wp-json") {
                        result.cms = Some("WordPress".into());
                    } else if body_slice.contains("drupal") || body_slice.contains("/sites/default") {
                        result.cms = Some("Drupal".into());
                    } else if body_slice.contains("joomla") || body_slice.contains("/components/com_") {
                        result.cms = Some("Joomla".into());
                    } else if body_slice.contains("magento") || body_slice.contains("/skin/frontend") {
                        result.cms = Some("Magento".into());
                    } else if body_slice.contains("ghost") || body_slice.contains("ghost/") {
                        result.cms = Some("Ghost".into());
                    } else if body_slice.contains("squarespace") || body_slice.contains("static.squarespace") {
                        result.cms = Some("Squarespace".into());
                    } else if body_slice.contains("wix") || body_slice.contains("wixstatic.com") {
                        result.cms = Some("Wix".into());
                    }

                    if let Ok(re) = Regex::new(r#"<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#) {
                        if let Some(cap) = re.captures(&body) {
                            if let Some(val) = cap.get(1) {
                                result.cms.get_or_insert(val.as_str().to_string());
                            }
                        }
                    }

                    let js_patterns: &[(&str, &str)] = &[
                        ("React", r#"(react\.js|react\.min\.js|react-dom|__NEXT_DATA__)"#),
                        ("Vue.js", r#"(vue\.js|vue\.min\.js|__VUE__|vue-router)"#),
                        ("Angular", r#"(angular\.js|angular\.min\.js|ng-app|ng-version)"#),
                        ("jQuery", r#"(jquery\.js|jquery\.min\.js|jquery-)"#),
                        ("Svelte", r#"(svelte\.js|__svelte)"#),
                        ("Bootstrap", r#"(bootstrap\.js|bootstrap\.min\.js|bootstrap\.css)"#),
                        ("Tailwind CSS", r#"(tailwindcss|tailwind\.css)"#),
                        ("Lodash", r#"(lodash\.js|lodash\.min\.js)"#),
                        ("Moment.js", r#"(moment\.js|moment\.min\.js)"#),
                        ("D3.js", r#"(d3\.js|d3\.min\.js)"#),
                        ("Next.js", r"(_next/static|__NEXT_DATA__)"),
                        ("Nuxt.js", r"(_nuxt/static|__NUXT__)"),
                        ("Gatsby", r"(gatsby\.js|gatsby-wrapper)"),
                    ];
                    for (name, pattern) in js_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&body) {
                                result.frameworks.push(name.to_string());
                            }
                        }
                    }
                    if result.frameworks.iter().any(|f| f == "Next.js") { result.cms.get_or_insert("Next.js".into()); }

                    let analytics_patterns: &[&str] = &[
                        "google-analytics", "gtag", "ga-", "google_analytics",
                        "facebook-pixel", "fbq", "facebook_pixel",
                        "hotjar", "hotjar/", "hotjar-",
                        "hubspot", "hubspot/",
                        "intercom", "intercom/",
                        "mixpanel", "mixpanel/",
                        "amplitude", "amplitude/",
                        "segment", "segment.io",
                        "fullstory", "fullstory/",
                        "heap", "heap.io",
                        "adroll", "adroll/",
                        "linkedin-insight", "linkedin_insight",
                        "twitter-pixel", "twitter_pixel",
                        "tiktok-pixel", "tiktok_pixel",
                        "pinterest-tag", "pinterest_tag",
                        "reddit-pixel", "reddit_pixel",
                        "snapchat-pixel", "snapchat_pixel",
                        "criteo", "criteo/",
                        "taboola", "taboola/",
                        "outbrain", "outbrain/",
                    ];
                    for a in analytics_patterns {
                        if body_slice.contains(a) {
                            result.analytics.push(a.to_string());
                        }
                    }

                    if body_slice.contains("cf-ray") || body_slice.contains("__cfduid") {
                        result.cdn.get_or_insert("Cloudflare".into());
                    }

                    if let Some(re) = Regex::new(r#"src=["']([^"']+\.(js|ts|jsx|tsx))["']"#).ok() {
                        for cap in re.captures_iter(&body) {
                            if let Some(src) = cap.get(1) {
                                let s = src.as_str();
                                if !result.js_libraries.iter().any(|x| x == s) {
                                    result.js_libraries.push(s.to_string());
                                }
                            }
                        }
                    }

                    let lang_patterns: &[(&str, &[&str])] = &[
                        ("PHP", &[".php", "x-powered-by: php"]),
                        ("Python", &["python", "django", "flask", "fastapi", "werkzeug", "uvicorn"]),
                        ("Ruby", &["ruby", "rails", "ruby/"]),
                        ("Java", &["java", "jsp", "servlet", "spring"]),
                        ("Go", &["golang", "go/"]),
                        (".NET", &["asp.net", "aspnet", ".net core", ".net"]),
                        ("Perl", &["perl/", "perl"]),
                        ("Rust", &["rust/", "actix-web", "rocket"]),
                    ];
                    for (name, patterns) in lang_patterns {
                        for p in *patterns {
                            if body_slice.contains(p) || headers.iter().any(|(_, v)| v.to_str().unwrap_or("").to_lowercase().contains(p)) {
                                if !result.languages.iter().any(|x| x == name) {
                                    result.languages.push(name.to_string());
                                }
                                break;
                            }
                        }
                    }

                    let hosting_patterns: &[(&str, &[&str])] = &[
                        ("AWS", &["ec2-", "amazonaws", "cloudfront"]),
                        ("Azure", &["azurewebsites", "azureedge", "azurefd"]),
                        ("GCP", &["appspot", "googleapis", "gcloud"]),
                        ("Heroku", &["herokuapp", "herokudns"]),
                        ("Vercel", &["vercel.app", "now.sh"]),
                        ("Netlify", &["netlify.app"]),
                        ("GitHub Pages", &["github.io"]),
                        ("DigitalOcean", &["digitalocean"]),
                        ("OVH", &["ovh.net"]),
                    ];
                    let lower_url = url.to_lowercase();
                    for (name, patterns) in hosting_patterns {
                        for p in *patterns {
                            if lower_url.contains(p) || body_slice.contains(p) {
                                result.hosting = Some(name.to_string());
                                break;
                            }
                        }
                        if result.hosting.is_some() { break; }
                    }

                    let os_from_server = result.webserver.as_deref().unwrap_or("").to_lowercase();
                    if os_from_server.contains("ubuntu") { result.os = Some("Ubuntu Linux".into()); }
                    else if os_from_server.contains("debian") { result.os = Some("Debian Linux".into()); }
                    else if os_from_server.contains("centos") { result.os = Some("CentOS Linux".into()); }
                    else if os_from_server.contains("red hat") || os_from_server.contains("rhel") { result.os = Some("Red Hat Linux".into()); }
                    else if os_from_server.contains("windows") || os_from_server.contains("win32") || os_from_server.contains("win64") { result.os = Some("Windows".into()); }
                    else if os_from_server.contains("freebsd") { result.os = Some("FreeBSD".into()); }
                    else if os_from_server.contains("alpine") { result.os = Some("Alpine Linux".into()); }
                }
            }
            Err(e) => {
                result.error = Some(format!("{:.80}", e));
            }
        }
    }

    progress_done!("tech_fingerprint");
    result
}
