use crate::common::*;
use crate::{progress, progress_done};
use regex::Regex;

fn extract_server_version(val: &str) -> Option<String> {
    Regex::new(r"^[a-zA-Z]+/([\d.]+)").ok()?.captures(val)
        .and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

fn extract_x_powered_version(val: &str) -> Option<String> {
    Regex::new(r"(?i)(?:php|asp\.net|express|python|ruby|java)/([\d.]+)").ok()?.captures(val)
        .and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

fn detect_js_lib_version(body: &str) -> Vec<String> {
    let mut libs: Vec<String> = Vec::new();
    let name_map: &[(&str, &str)] = &[
        ("jquery", "jQuery"), ("jquery-ui", "jQuery UI"), ("jquery-migrate", "jQuery Migrate"),
        ("bootstrap", "Bootstrap"), ("vue", "Vue.js"), ("react", "React"),
        ("angular", "Angular"), ("lodash", "Lodash"), ("moment", "Moment.js"),
        ("d3", "D3.js"), ("chart", "Chart.js"), ("handlebars", "Handlebars"),
        ("underscore", "Underscore"), ("backbone", "Backbone.js"), ("ember", "Ember.js"),
        ("knockout", "Knockout"), ("dojo", "Dojo"), ("ext", "Ext JS"),
        ("mootools", "MooTools"), ("prototype", "Prototype"), ("svelte", "Svelte"),
        ("solid", "Solid"), ("qwik", "Qwik"), ("preact", "Preact"),
        ("alpine", "Alpine.js"), ("htmx", "htmx"), ("hyperscript", "Hyperscript"),
        ("swiper", "Swiper"), ("select2", "Select2"), ("datatables", "DataTables"),
        ("fullcalendar", "FullCalendar"), ("quill", "Quill"), ("tinymce", "TinyMCE"),
        ("ckeditor", "CKEditor"), ("summernote", "Summernote"), ("dropzone", "Dropzone"),
        ("flatpickr", "Flatpickr"), ("choices", "Choices.js"), ("imask", "IMask"),
        ("cleave", "Cleave.js"), ("inputmask", "Inputmask"), ("parsley", "Parsley.js"),
        ("jquery-validation", "jQuery Validation"), ("axios", "Axios"),
        ("fetch", "Fetch"), ("superagent", "SuperAgent"),("gsap", "GSAP"),
        ("three", "Three.js"), ("p5", "p5.js"), ("fabric", "Fabric.js"),
        ("paper", "Paper.js"), ("raphael", "Raphaël"), ("snap", "Snap.svg"),
        ("velocity", "Velocity.js"), ("lottie", "Lottie"), ("anime", "Anime.js"),
        ("particles", "Particles.js"), ("typed", "Typed.js"), ("waypoints", "Waypoints"),
        ("isotope", "Isotope"), ("masonry", "Masonry"), ("packery", "Packery"),
        ("owlcarousel", "Owl Carousel"), ("slick", "Slick"), ("fancybox", "Fancybox"),
        ("lightbox", "Lightbox"), ("magnific-popup", "Magnific Popup"),
        ("tippy", "Tippy.js"), ("popper", "Popper"), ("tooltipster", "Tooltipster"),
        ("swal", "SweetAlert"), ("sweetalert", "SweetAlert"), ("toastr", "Toastr"),
        ("noty", "Noty"), ("pnotify", "PNotify"),
        ("chartist", "Chartist"), ("echarts", "ECharts"), ("highcharts", "Highcharts"),
        ("amcharts", "amCharts"), ("google-charts", "Google Charts"),
        ("leaflet", "Leaflet"), ("openlayers", "OpenLayers"), ("mapbox", "Mapbox"),
        ("gmaps", "Google Maps"), ("maplibre", "MapLibre"),
        ("markerclusterer", "MarkerClusterer"),
        ("socket.io", "Socket.IO"), ("socket", "Socket.IO"), ("engine.io", "Engine.IO"),
        ("pusher", "Pusher"), ("ably", "Ably"),("signalr", "SignalR"),
        ("monaco", "Monaco Editor"), ("ace", "Ace Editor"), ("codemirror", "CodeMirror"),
        ("prism", "Prism.js"), ("highlight", "Highlight.js"),
        ("mermaid", "Mermaid"), ("katex", "KaTeX"), ("mathjax", "MathJax"),
        ("pdf", "PDF.js"),("markdown", "Marked"),
        ("turbolinks", "Turbolinks"), ("turbo", "Turbo"), ("stimulus", "Stimulus"),
        ("hotwire", "Hotwire"), ("livewire", "Livewire"),
        ("alpinejs", "Alpine.js"),("sortable", "SortableJS"),
    ];

    if let Ok(re) = Regex::new(r#"src=["']([^"']*\b([a-zA-Z][a-zA-Z0-9]*(?:[-.][a-zA-Z][a-zA-Z0-9]*)*)[.-](\d+\.\d+\.\d+)[^"']*\.(?:js|ts|mjs|cjs))["']"#) {
        for cap in re.captures_iter(body) {
            let path = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let raw_name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            let version = cap.get(3).map(|m| m.as_str()).unwrap_or("");
            if !version.is_empty() && !libs.iter().any(|l| l.contains(version)) {
                let display = name_map.iter()
                    .find(|(key, _)| raw_name.to_lowercase().contains(key))
                    .map(|(_, name)| *name)
                    .unwrap_or(raw_name);
                let lib_entry = if display == raw_name {
                    format!("{} {}", raw_name, version)
                } else {
                    format!("{} {}", display, version)
                };
                if !libs.contains(&lib_entry) {
                    libs.push(lib_entry);
                }
            }
            if !libs.iter().any(|x| x == path) && !path.is_empty() {
                libs.push(path.to_string());
            }
        }
    }
    libs
}

fn detect_cookie_consent(body: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let patterns: &[(&str, &str)] = &[
        ("Cookiebot", r"cookiebot"),
        ("OneTrust", r"(onetrust|Optanon)"),
        ("Osano", r"osano"),
        ("CookieConsent", r"(cookieconsent|cookie-consent|cookie_law)"),
        ("CookieYes", r"cookieyes"),
        ("Complianz", r"complianz"),
        ("GDPR Cookie Compliance", r"gdpr-cookie"),
        ("Cookie Notice", r"cookie-notice"),
        ("Borlabs Cookie", r"borlabs"),
        ("Termly", r"termly"),
        ("Usercentrics", r"usercentrics"),
        ("CookieFirst", r"cookiefirst"),
        ("CookieInfo", r"cookieinfo"),
        ("Cookie Scanner", r"cookie-scanner"),
        ("Klaro", r"klaro"),
        ("Civic Cookie Control", r"civic-cookie"),
        ("CookieHub", r"cookiehub"),
        ("Fancy Cookie", r"fancy-cookie"),
        ("CookieBox", r"cookiebox"),
        ("GDPR Cookie Consent", r"(moove_gdpr|gdpr-cookie-consent)"),
    ];
    let lower = body.to_lowercase();
    for (name, pattern) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(&lower) && !found.contains(&name.to_string()) {
                found.push(name.to_string());
            }
        }
    }
    found
}

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
                    else if lower.contains("incapsula") { result.cdn = Some("Incapsula".into()); }
                    else if lower.contains("sucuri") { result.cdn = Some("Sucuri".into()); }
                    else if lower.contains("stackpath") { result.cdn = Some("StackPath".into()); }
                    else if lower.contains("keycdn") { result.cdn = Some("KeyCDN".into()); }
                    else if lower.contains("cachefly") { result.cdn = Some("CacheFly".into()); }
                    else if lower.contains("bunnycdn") || lower.contains("bunny") { result.cdn = Some("Bunny CDN".into()); }
                    else if lower.contains("section.io") { result.cdn = Some("Section.io".into()); }
                    else if lower.contains("belugacdn") { result.cdn = Some("BelugaCDN".into()); }
                    else if lower.contains("ovh") { result.cdn = Some("OVH CDN".into()); }

                    if let Some(ver) = extract_server_version(v) {
                        if !result.frameworks.contains(&format!("server/{}", ver)) {
                            let name = lower.split('/').next().unwrap_or("").to_string();
                            result.frameworks.push(format!("{} {}", name, ver));
                        }
                    }
                }
                if let Some(ref v) = x_powered {
                    let lower = v.to_lowercase();
                    if lower.contains("php") { result.languages.push("PHP".into()); }
                    if lower.contains("asp.net") { result.languages.push("ASP.NET".into()); }
                    if lower.contains("express") { result.frameworks.push("Express".into()); }
                    if lower.contains("python") { result.languages.push("Python".into()); }
                    if lower.contains("ruby") { result.languages.push("Ruby".into()); }
                    if lower.contains("java") || lower.contains("jsp") { result.languages.push("Java".into()); }
                    if let Some(ver) = extract_x_powered_version(v) {
                        if !result.frameworks.contains(&format!("x-powered/{}", ver)) {
                            result.cms_version = Some(ver);
                        }
                    }
                }
                if let Some(v) = x_generator {
                    let lower = v.to_lowercase();
                    if lower.contains("wordpress") || lower.contains("wp") {
                        result.cms = Some("WordPress".into());
                        if let Ok(re) = Regex::new(r"(?i)wordpress\s*([\d.]+)") {
                            if let Some(caps) = re.captures(&v) {
                                if let Some(ver) = caps.get(1) {
                                    result.cms_version = Some(ver.as_str().to_string());
                                }
                            }
                        }
                    } else if lower.contains("drupal") {
                        result.cms = Some("Drupal".into());
                        if let Ok(re) = Regex::new(r"(?i)drupal\s*([\d.]+)") {
                            if let Some(caps) = re.captures(&v) {
                                if let Some(ver) = caps.get(1) {
                                    result.cms_version = Some(ver.as_str().to_string());
                                }
                            }
                        }
                    } else if lower.contains("joomla") {
                        result.cms = Some("Joomla".into());
                    } else if lower.contains("magento") {
                        result.cms = Some("Magento".into());
                    } else if lower.contains("shopify") {
                        result.cms = Some("Shopify".into());
                    } else if lower.contains("squarespace") {
                        result.cms = Some("Squarespace".into());
                    } else if lower.contains("wix") {
                        result.cms = Some("Wix".into());
                    } else if lower.contains("strapi") {
                        result.cms = Some("Strapi".into());
                    } else if lower.contains("ghost") {
                        result.cms = Some("Ghost".into());
                    } else if lower.contains("contentful") {
                        result.cms = Some("Contentful".into());
                    } else {
                        result.cms = Some(v);
                    }
                }
                if let Some(v) = x_aspnet {
                    result.languages.push(format!(".NET {}", v));
                }

                if let Ok(body) = resp.text().await {
                    let lower_body = body.to_lowercase();
                    let body_slice = &lower_body;

                    if body_slice.contains("wordpress") || body_slice.contains("wp-content") || body_slice.contains("wp-includes") || body_slice.contains("wp-json") {
                        result.cms.get_or_insert("WordPress".into());
                        if let Ok(re) = Regex::new(r#"(?i)<meta\s+name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)["']"#) {
                            if let Some(caps) = re.captures(&body) {
                                if let Some(ver) = caps.get(1) {
                                    result.cms_version = Some(ver.as_str().to_string());
                                }
                            }
                        }
                    }
                    if result.cms.is_none() {
                        if body_slice.contains("drupal") || body_slice.contains("/sites/default") || body_slice.contains("drupal.js") {
                            result.cms = Some("Drupal".into());
                        } else if body_slice.contains("joomla") || body_slice.contains("/components/com_") || body_slice.contains("/modules/mod_") {
                            result.cms = Some("Joomla".into());
                        } else if body_slice.contains("magento") || body_slice.contains("/skin/frontend") || body_slice.contains("mage/") {
                            result.cms = Some("Magento".into());
                        } else if body_slice.contains("ghost") || body_slice.contains("ghost/") || body_slice.contains("ghost-framework") {
                            result.cms.get_or_insert("Ghost".into());
                        } else if body_slice.contains("squarespace") || body_slice.contains("static.squarespace") || body_slice.contains("squarespace.com") {
                            result.cms.get_or_insert("Squarespace".into());
                        } else if body_slice.contains("wix") || body_slice.contains("wixstatic.com") || body_slice.contains("wix.com") {
                            result.cms.get_or_insert("Wix".into());
                        } else if body_slice.contains("weebly") || body_slice.contains("weebly.com") || body_slice.contains("edit.weebly") {
                            result.cms = Some("Weebly".into());
                        } else if body_slice.contains("strapi") || body_slice.contains("strapi.io") || body_slice.contains("strapi-cms") {
                            result.cms = Some("Strapi".into());
                        } else if body_slice.contains("contentful") || body_slice.contains("contentful.com") || body_slice.contains("ctfassets.net") {
                            result.cms = Some("Contentful".into());
                        }
                    }

                    if let Ok(re) = Regex::new(r#"<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#) {
                        if let Some(cap) = re.captures(&body) {
                            if let Some(val) = cap.get(1) {
                                let gen = val.as_str();
                                result.cms.get_or_insert(gen.to_string());
                                if let Ok(ver_re) = Regex::new(r"([\d.]+)") {
                                    if let Some(ver_cap) = ver_re.captures(gen) {
                                        if let Some(ver) = ver_cap.get(1) {
                                            result.cms_version = Some(ver.as_str().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let js_patterns: &[(&str, &str)] = &[
                        ("React", r#"(react\.js|react\.min\.js|react-dom|__NEXT_DATA__|__REACT_DEVTOOLS)"#),
                        ("Vue.js", r#"(vue\.js|vue\.min\.js|__VUE__|vue-router|vuex|createApp)"#),
                        ("Angular", r#"(angular\.js|angular\.min\.js|ng-app|ng-version)"#),
                        ("jQuery", r#"(jquery\.js|jquery\.min\.js|jquery-)"#),
                        ("Svelte", r#"(svelte\.js|__svelte|svelte\.min\.js)"#),
                        ("Bootstrap", r#"(bootstrap\.js|bootstrap\.min\.js|bootstrap\.css|bootstrap\.min\.css)"#),
                        ("Tailwind CSS", r#"(tailwindcss|tailwind\.css|@tailwind)"#),
                        ("Bulma", r#"(bulma\.css|bulma\.min\.css|bulma\/)"#),
                        ("Foundation", r#"(foundation\.css|foundation\.min\.css|foundation\.js|foundation\.min\.js|foundation\/)"#),
                        ("Materialize", r#"(materialize\.css|materialize\.min\.css|materialize\.js|materialize\.min\.js|materializecss)"#),
                        ("Lodash", r#"(lodash\.js|lodash\.min\.js|_\.isEqual|_\.debounce)"#),
                        ("Moment.js", r#"(moment\.js|moment\.min\.js|moment\.tz)"#),
                        ("D3.js", r#"(d3\.js|d3\.min\.js|d3-scale|d3-selection)"#),
                        ("Next.js", r"(_next/static|__NEXT_DATA__)"),
                        ("Nuxt.js", r"(_nuxt/static|__NUXT__|useNuxtApp)"),
                        ("Gatsby", r"(gatsby\.js|gatsby-wrapper|gatsby-ssr)"),
                        ("Remix", r"(remix\.js|@remix-run|remix-request)"),
                        ("Solid.js", r"(solid\.js|solid\.min\.js|_$HY|solid-js)"),
                        ("Qwik", r"(qwik\.js|qwik\.min\.js|\$qwik|qwik-city)"),
                        ("Preact", r"(preact\.js|preact\.min\.js|preact\/)"),
                        ("Alpine.js", r"(alpine\.js|alpine\.min\.js|alpinejs|x-data)"),
                        ("htmx", r"(htmx\.js|htmx\.min\.js|hx-get|hx-post|hx-target)"),
                        ("Hyperscript", r"(_hyperscript|hyperscript\.js)"),
                        ("Stimulus", r"(stimulus\.js|stimulus\.min\.js|stimulus-)"),
                        ("Hotwire Turbo", r"(turbo\.js|turbo\.min\.js|@hotwired/turbo)"),
                        ("Livewire", r"(livewire\.js|livewire\.min\.js|@livewire)"),
                        ("Socket.IO", r"(socket\.io\.js|socket\.io\.min\.js|io\()"),
                        ("Axios", r"(axios\.js|axios\.min\.js|axios/)"),
                        ("Chart.js", r"(chart\.js|chart\.min\.js|chart\.umd)"),
                        ("GSAP", r"(gsap\.js|gsap\.min\.js|TweenMax|TimelineMax)"),
                        ("Three.js", r"(three\.js|three\.min\.js|three\.module)"),
                        ("Leaflet", r"(leaflet\.js|leaflet\.min\.js|L\.map|leaflet\.css)"),
                    ];
                    for (name, pattern) in js_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&body) {
                                if !result.frameworks.iter().any(|f| f == name) {
                                    result.frameworks.push(name.to_string());
                                }
                            }
                        }
                    }

                    if result.frameworks.iter().any(|f| f == "Next.js") { result.cms.get_or_insert("Next.js".into()); }
                    if result.frameworks.iter().any(|f| f == "Nuxt.js") { result.cms.get_or_insert("Nuxt.js".into()); }
                    if result.frameworks.iter().any(|f| f == "Gatsby") { result.cms.get_or_insert("Gatsby".into()); }
                    if result.frameworks.iter().any(|f| f == "Remix") { result.cms.get_or_insert("Remix".into()); }

                    if let Ok(re) = Regex::new(r#"ng-version=["']([\d.]+)["']"#) {
                        if let Some(caps) = re.captures(&body) {
                            if let Some(ver) = caps.get(1) {
                                let entry = format!("Angular {}", ver.as_str());
                                if !result.frameworks.contains(&entry) {
                                    result.frameworks.push(entry);
                                }
                            }
                        }
                    }

                    let analytics_patterns: &[&str] = &[
                        "google-analytics", "gtag", "ga-", "google_analytics", "ga4", "gtm-",
                        "facebook-pixel", "fbq", "facebook_pixel",
                        "hotjar", "hotjar/", "hotjar-",
                        "hubspot", "hubspot/",
                        "intercom", "intercom/",
                        "mixpanel", "mixpanel/",
                        "amplitude", "amplitude/",
                        "segment", "segment.io", "segment/",
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
                        "matomo", "matomo/", "piwik",
                        "plausible", "plausible.io",
                        "fathom", "fathom/", "usefathom",
                        "simpleanalytics", "simpleanalytics.com",
                        "counter.dev", "counter-dev",
                        "umami", "umami/",
                        "clarity", "clarity.ms", "microsoft clarity",
                        "yandex-metrica", "yandex_metrika", "mc.yandex",
                        "baidu-tongji", "baidu_analytics",
                        "alexa", "alexa.com",
                        "quantcast", "quantcast.",
                        "comscore", "comscore",
                        "chartbeat", "chartbeat",
                        "parsely", "parsely",
                        "permutive", "permutive",
                        "adobe-analytics", "adobe_analytics", "adobedtm",
                        "salesforce-dmp", "salesforce_dmp", "krxd",
                        "bluekai", "bluekai",
                        "lotame", "lotame",
                        "neustar", "neustar",
                        "the-trade-desk", "adsrvr",
                        "amazon-advertising", "amazon-adsystem",
                    ];
                    for a in analytics_patterns {
                        if body_slice.contains(a) {
                            if !result.analytics.iter().any(|x| x == a) {
                                result.analytics.push(a.to_string());
                            }
                        }
                    }

                    let cookie_platforms = detect_cookie_consent(&body);
                    for c in cookie_platforms {
                        if !result.frameworks.contains(&c) {
                            result.frameworks.push(c);
                        }
                    }

                    if body_slice.contains("cf-ray") || body_slice.contains("__cfduid") || body_slice.contains("cfduid") {
                        result.cdn.get_or_insert("Cloudflare".into());
                    }
                    if body_slice.contains("cloudfront") { result.cdn.get_or_insert("AWS CloudFront".into()); }
                    if body_slice.contains("fastly") { result.cdn.get_or_insert("Fastly".into()); }

                    let detected_libs = detect_js_lib_version(&body);
                    for lib in detected_libs {
                        if !result.js_libraries.contains(&lib) {
                            result.js_libraries.push(lib);
                        }
                    }

                    if let Some(re) = Regex::new(r#"src=["']([^"']+\.(js|ts|jsx|tsx|mjs|cjs))["']"#).ok() {
                        for cap in re.captures_iter(&body) {
                            if let Some(src) = cap.get(1) {
                                let s = src.as_str().to_string();
                                if !result.js_libraries.contains(&s) {
                                    result.js_libraries.push(s);
                                }
                            }
                        }
                    }

                    let lang_patterns: &[(&str, &[&str])] = &[
                        ("PHP", &[".php", "x-powered-by: php"]),
                        ("Python", &["python", "django", "flask", "fastapi", "werkzeug", "uvicorn"]),
                        ("Ruby", &["ruby", "rails", "ruby/", "sinatra"]),
                        ("Java", &["java", "jsp", "servlet", "spring", "jakarta", "tomcat"]),
                        ("Go", &["golang", "go/", "gin-"]),
                        (".NET", &["asp.net", "aspnet", ".net core", ".net", "blazor", "mvc"]),
                        ("Perl", &["perl/", "perl", "cgi"]),
                        ("Rust", &["rust/", "actix-web", "rocket", "axum", "warp", "tide"]),
                        ("Kotlin", &["kotlin", "ktor", "kotlin/"]),
                        ("Swift", &["swift", "vapor", "swift/"]),
                        ("Scala", &["scala", "play framework", "play/", "akka"]),
                        ("Elixir", &["elixir", "phoenix", "phoenix/"]),
                        ("Clojure", &["clojure", "ring", "luminus", "clj/"]),
                    ];
                    for (name, patterns) in lang_patterns {
                        for p in *patterns {
                            let in_body = body_slice.contains(p);
                            let in_header = headers.iter().any(|(_, v)| v.to_str().unwrap_or("").to_lowercase().contains(p));
                            if in_body || in_header {
                                if !result.languages.iter().any(|x| x == name) {
                                    result.languages.push(name.to_string());
                                }
                                break;
                            }
                        }
                    }

                    let hosting_patterns: &[(&str, &[&str])] = &[
                        ("AWS", &["ec2-", "amazonaws", "cloudfront", "aws-", "s3-website", "elasticbeanstalk", "amazonaws.com"]),
                        ("Azure", &["azurewebsites", "azureedge", "azurefd", "azure-api", "cloudapp.net", "trafficmanager"]),
                        ("GCP", &["appspot", "googleapis", "gcloud", "compute.amazonaws.com", "cloud.google"]),
                        ("Heroku", &["herokuapp", "herokudns", "heroku.com"]),
                        ("Vercel", &["vercel.app", "now.sh", "vercel.com"]),
                        ("Netlify", &["netlify.app", "netlify.com"]),
                        ("GitHub Pages", &["github.io"]),
                        ("DigitalOcean", &["digitalocean", "do-"]),
                        ("OVH", &["ovh.net", "ovh.com"]),
                        ("Linode", &["linode", "linode.com"]),
                        ("Vultr", &["vultr", "vultr.com"]),
                        ("Hetzner", &["hetzner", "hetzner.com"]),
                        ("Fly.io", &["fly.io", "fly.dev"]),
                        ("Railway", &["railway.app", "railway.com"]),
                        ("Render", &["render.com"]),
                        ("Cloudflare Pages", &["pages.dev", "cfpages"]),
                        ("Cloudflare Workers", &["workers.dev"]),
                        ("Firebase", &["firebaseapp", "web.app", "firebase.io"]),
                        ("Supabase", &["supabase.co"]),
                        ("Koyeb", &["koyeb.app", "koyeb.com"]),
                        ("Northflank", &["northflank"]),
                        ("Platform.sh", &["platform.sh"]),
                        ("Oracle Cloud", &["oraclecloud", "oci-"]),
                        ("IBM Cloud", &["ibm.cloud", "cloud.ibm"]),
                        ("Alibaba Cloud", &["aliyuncs", "alibaba"]),
                    ];
                    let lower_url = url.to_lowercase();
                    for (name, patterns) in hosting_patterns {
                        if result.hosting.is_some() { break; }
                        for p in *patterns {
                            if lower_url.contains(p) || body_slice.contains(p) {
                                result.hosting = Some(name.to_string());
                                break;
                            }
                        }
                    }

                    let os_from_server = result.webserver.as_deref().unwrap_or("").to_lowercase();
                    if os_from_server.contains("ubuntu") { result.os = Some("Ubuntu Linux".into()); }
                    else if os_from_server.contains("debian") { result.os = Some("Debian Linux".into()); }
                    else if os_from_server.contains("centos") { result.os = Some("CentOS Linux".into()); }
                    else if os_from_server.contains("red hat") || os_from_server.contains("rhel") { result.os = Some("Red Hat Linux".into()); }
                    else if os_from_server.contains("windows") || os_from_server.contains("win32") || os_from_server.contains("win64") { result.os = Some("Windows".into()); }
                    else if os_from_server.contains("freebsd") { result.os = Some("FreeBSD".into()); }
                    else if os_from_server.contains("alpine") { result.os = Some("Alpine Linux".into()); }
                    else if os_from_server.contains("amazon") || os_from_server.contains("amzn") { result.os = Some("Amazon Linux".into()); }
                    else if os_from_server.contains("suse") || os_from_server.contains("opensuse") { result.os = Some("SUSE Linux".into()); }
                    else if os_from_server.contains("fedora") { result.os = Some("Fedora Linux".into()); }
                    else if os_from_server.contains("arch") { result.os = Some("Arch Linux".into()); }
                    else if os_from_server.contains("mac") || os_from_server.contains("darwin") { result.os = Some("macOS".into()); }
                    else if os_from_server.contains("solaris") { result.os = Some("Solaris".into()); }
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
