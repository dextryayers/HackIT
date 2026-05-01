use std::collections::HashMap;
use regex::Regex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TechInfo {
    pub name: String,
    pub confidence: i32,
    pub category: String,
    pub version: Option<String>,
}

pub struct TechSignature {
    pub name: String,
    pub category: String,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<String>,
    pub html_patterns: Vec<String>,
    pub meta_tags: HashMap<String, String>,
    pub url_patterns: Vec<String>,
    pub script_patterns: Vec<String>,
}

impl TechSignature {
    pub fn new(name: &str, category: &str) -> Self {
        Self {
            name: name.to_string(),
            category: category.to_string(),
            headers: HashMap::new(),
            cookies: Vec::new(),
            html_patterns: Vec::new(),
            meta_tags: HashMap::new(),
            url_patterns: Vec::new(),
            script_patterns: Vec::new(),
        }
    }
}

lazy_static! {
    static ref SIGNATURE_DB: Vec<TechSignature> = {
        let mut db = Vec::new();

        // --- WEB SERVERS ---
        let mut nginx = TechSignature::new("Nginx", "Web Server");
        nginx.headers.insert("Server".to_string(), r"nginx/?([0-9.]*)?".to_string());
        db.push(nginx);

        let mut apache = TechSignature::new("Apache", "Web Server");
        apache.headers.insert("Server".to_string(), r"Apache/?([0-9.]*)?".to_string());
        db.push(apache);

        let mut iis = TechSignature::new("IIS", "Web Server");
        iis.headers.insert("Server".to_string(), r"Microsoft-IIS/?([0-9.]*)?".to_string());
        db.push(iis);

        let mut litespeed = TechSignature::new("LiteSpeed", "Web Server");
        litespeed.headers.insert("Server".to_string(), r"LiteSpeed".to_string());
        litespeed.headers.insert("X-LiteSpeed-Cache".to_string(), r".+".to_string());
        db.push(litespeed);

        let mut openresty = TechSignature::new("OpenResty", "Web Server");
        openresty.headers.insert("Server".to_string(), r"openresty/?([0-9.]*)?".to_string());
        db.push(openresty);

        let mut caddy = TechSignature::new("Caddy", "Web Server");
        caddy.headers.insert("Server".to_string(), r"Caddy".to_string());
        db.push(caddy);

        // --- CMS ---
        let mut wp = TechSignature::new("WordPress", "CMS");
        wp.meta_tags.insert("generator".to_string(), r"WordPress ?([0-9.]*)?".to_string());
        wp.html_patterns.push(r"wp-content/".to_string());
        wp.html_patterns.push(r"wp-includes/".to_string());
        wp.url_patterns.push(r"/wp-admin/".to_string());
        wp.script_patterns.push(r"wp-embed\.min\.js".to_string());
        wp.headers.insert("X-Pingback".to_string(), r".*xmlrpc\.php".to_string());
        db.push(wp);

        let mut joomla = TechSignature::new("Joomla", "CMS");
        joomla.meta_tags.insert("generator".to_string(), r"Joomla!".to_string());
        joomla.url_patterns.push(r"/administrator/".to_string());
        joomla.html_patterns.push(r"Joomla! - Open Source Content Management".to_string());
        db.push(joomla);

        let mut drupal = TechSignature::new("Drupal", "CMS");
        drupal.meta_tags.insert("generator".to_string(), r"Drupal".to_string());
        drupal.html_patterns.push(r"Drupal\.settings".to_string());
        drupal.headers.insert("X-Drupal-Cache".to_string(), r".+".to_string());
        db.push(drupal);

        let mut magento = TechSignature::new("Magento", "CMS/E-commerce");
        magento.html_patterns.push(r"Mage.Cookies".to_string());
        magento.url_patterns.push(r"skin/frontend/".to_string());
        db.push(magento);

        let mut shopify = TechSignature::new("Shopify", "E-commerce");
        shopify.headers.insert("X-Shopify-Stage".to_string(), r".+".to_string());
        shopify.html_patterns.push(r"cdn.shopify.com".to_string());
        db.push(shopify);

        // --- BACKEND FRAMEWORKS ---
        let mut laravel = TechSignature::new("Laravel", "Backend Framework");
        laravel.cookies.push(r"laravel_session".to_string());
        laravel.cookies.push(r"XSRF-TOKEN".to_string());
        laravel.headers.insert("X-Powered-By".to_string(), r"Laravel".to_string());
        db.push(laravel);

        let mut django = TechSignature::new("Django", "Backend Framework");
        django.cookies.push(r"csrftoken".to_string());
        django.html_patterns.push(r"csrfmiddlewaretoken".to_string());
        db.push(django);

        let mut php = TechSignature::new("PHP", "Language");
        php.headers.insert("X-Powered-By".to_string(), r"PHP/?([0-9.]*)?".to_string());
        php.cookies.push(r"PHPSESSID".to_string());
        db.push(php);

        let mut rails = TechSignature::new("Ruby on Rails", "Backend Framework");
        rails.cookies.push(r"_rails_session".to_string());
        rails.headers.insert("X-Rack-Cache".to_string(), r".+".to_string());
        db.push(rails);

        let mut express = TechSignature::new("Express", "Backend Framework");
        express.headers.insert("X-Powered-By".to_string(), r"Express".to_string());
        express.cookies.push(r"connect.sid".to_string());
        db.push(express);

        // --- FRONTEND FRAMEWORKS ---
        let mut react = TechSignature::new("React", "Frontend Framework");
        react.html_patterns.push(r"data-reactroot".to_string());
        react.script_patterns.push(r"react\.production\.min\.js".to_string());
        react.html_patterns.push(r"_reactListening".to_string());
        db.push(react);

        let mut vue = TechSignature::new("Vue.js", "Frontend Framework");
        vue.html_patterns.push(r"__vue__".to_string());
        vue.script_patterns.push(r"vue\.js".to_string());
        vue.html_patterns.push(r"data-v-".to_string());
        db.push(vue);

        let mut angular = TechSignature::new("Angular", "Frontend Framework");
        angular.html_patterns.push(r"ng-version=".to_string());
        angular.html_patterns.push(r"ng-app=".to_string());
        db.push(angular);

        let mut nextjs = TechSignature::new("Next.js", "Frontend Framework");
        nextjs.html_patterns.push(r"__NEXT_DATA__".to_string());
        nextjs.script_patterns.push(r"_next/static".to_string());
        nextjs.headers.insert("X-Nextjs-Cache".to_string(), r".+".to_string());
        db.push(nextjs);

        let mut svelte = TechSignature::new("Svelte", "Frontend Framework");
        svelte.html_patterns.push(r"svelte-".to_string());
        svelte.script_patterns.push(r"svelte".to_string());
        db.push(svelte);

        // --- CDN / WAF / SECURITY ---
        let mut cf = TechSignature::new("Cloudflare", "CDN/WAF");
        cf.headers.insert("CF-RAY".to_string(), r".+".to_string());
        cf.headers.insert("Server".to_string(), r"cloudflare".to_string());
        cf.headers.insert("cf-cache-status".to_string(), r".+".to_string());
        db.push(cf);

        let mut akamai = TechSignature::new("Akamai", "CDN/WAF");
        akamai.headers.insert("X-Akamai-Transformed".to_string(), r".+".to_string());
        akamai.headers.insert("Server".to_string(), r"AkamaiGHost".to_string());
        db.push(akamai);

        let mut fastly = TechSignature::new("Fastly", "CDN/WAF");
        fastly.headers.insert("X-Served-By".to_string(), r"cache-".to_string());
        fastly.headers.insert("X-Cache".to_string(), r"HIT, HIT".to_string());
        db.push(fastly);

        let mut cloudfront = TechSignature::new("Cloudfront", "CDN/WAF");
        cloudfront.headers.insert("X-Amz-Cf-Id".to_string(), r".+".to_string());
        cloudfront.headers.insert("Via".to_string(), r"CloudFront".to_string());
        db.push(cloudfront);

        // --- ANALYTICS & TOOLS ---
        let mut ga = TechSignature::new("Google Analytics", "Analytics");
        ga.script_patterns.push(r"google-analytics\.com/analytics\.js".to_string());
        ga.script_patterns.push(r"googletagmanager\.com/gtag/js".to_string());
        db.push(ga);

        let mut gtm = TechSignature::new("Google Tag Manager", "Analytics");
        gtm.html_patterns.push(r"googletagmanager\.com/ns\.html".to_string());
        db.push(gtm);

        // --- JS LIBRARIES ---
        let mut jquery = TechSignature::new("jQuery", "JS Library");
        jquery.script_patterns.push(r"jquery(?:\.min)?\.js".to_string());
        jquery.html_patterns.push(r"jQuery".to_string());
        db.push(jquery);

        let mut bootstrap = TechSignature::new("Bootstrap", "Frontend CSS Framework");
        bootstrap.html_patterns.push(r"bootstrap(?:\.min)?\.css".to_string());
        bootstrap.script_patterns.push(r"bootstrap(?:\.min)?\.js".to_string());
        db.push(bootstrap);

        let mut tailwind = TechSignature::new("Tailwind CSS", "Frontend CSS Framework");
        tailwind.html_patterns.push(r"tailwind".to_string());
        db.push(tailwind);

        let mut gsap = TechSignature::new("GSAP", "JS Library");
        gsap.script_patterns.push(r"gsap(?:\.min)?\.js".to_string());
        gsap.html_patterns.push(r"TweenMax|TweenLite|TimelineMax".to_string());
        db.push(gsap);

        let mut astro = TechSignature::new("Astro", "Frontend Framework");
        astro.html_patterns.push(r"astro-island".to_string());
        astro.html_patterns.push(r"astro-".to_string());
        db.push(astro);

        let mut alpine = TechSignature::new("Alpine.js", "JS Library");
        alpine.html_patterns.push(r"x-data=".to_string());
        alpine.script_patterns.push(r"alpine(?:\.min)?\.js".to_string());
        db.push(alpine);

        let mut solidjs = TechSignature::new("SolidJS", "Frontend Framework");
        solidjs.html_patterns.push(r"solid-js".to_string());
        db.push(solidjs);

        let mut blogger = TechSignature::new("Blogger", "CMS");
        blogger.meta_tags.insert("generator".to_string(), r"blogger".to_string());
        blogger.html_patterns.push(r"blogger\.com".to_string());
        db.push(blogger);

        let mut wix = TechSignature::new("Wix", "CMS");
        wix.meta_tags.insert("generator".to_string(), r"Wix\.com Website Builder".to_string());
        wix.html_patterns.push(r"static\.wixstatic\.com".to_string());
        db.push(wix);

        let mut ghost = TechSignature::new("Ghost", "CMS");
        ghost.meta_tags.insert("generator".to_string(), r"Ghost\s?([0-9.]*)?".to_string());
        ghost.html_patterns.push(r"ghost-content".to_string());
        db.push(ghost);

        let mut varnish = TechSignature::new("Varnish", "Cache/Proxy");
        varnish.headers.insert("X-Varnish".to_string(), r".+".to_string());
        varnish.headers.insert("Via".to_string(), r"Varnish".to_string());
        db.push(varnish);

        db
    };
}

pub fn detect_technologies(body: &str, headers: &HashMap<String, String>) -> HashMap<String, TechInfo> {
    let mut detected = HashMap::new();
    
    // Extract cookies for matching
    let mut cookies = Vec::new();
    for (k, v) in headers {
        if k.to_lowercase() == "set-cookie" {
            cookies.push(v.to_string());
        }
    }

    // Extract meta tags for matching
    let mut meta_tags = HashMap::new();
    let re_meta = Regex::new(r#"(?i)<meta\s+name=["'](.*?)["']\s+content=["'](.*?)["']"#).unwrap();
    for cap in re_meta.captures_iter(body) {
        meta_tags.insert(cap[1].to_lowercase(), cap[2].to_string());
    }

    for sig in SIGNATURE_DB.iter() {
        let mut signals = 0;
        let mut version = None;
        let mut current_confidence = 0;

        // 1. Check Meta Tags (High Weight)
        for (m_name, m_pattern) in &sig.meta_tags {
            if let Some(val) = meta_tags.get(&m_name.to_lowercase()) {
                let re = Regex::new(&format!("(?i){}", m_pattern)).unwrap();
                if let Some(caps) = re.captures(val) {
                    signals += 1;
                    current_confidence = current_confidence.max(90);
                    if caps.len() > 1 && version.is_none() {
                        version = Some(caps[1].to_string());
                    }
                }
            }
        }

        // 2. Check Headers (High Weight)
        for (h_key, h_pattern) in &sig.headers {
            if let Some(val) = headers.get(h_key) {
                let re = Regex::new(&format!("(?i){}", h_pattern)).unwrap();
                if let Some(caps) = re.captures(val) {
                    signals += 1;
                    current_confidence = current_confidence.max(85);
                    if caps.len() > 1 && version.is_none() {
                        version = Some(caps[1].to_string());
                    }
                }
            }
        }

        // 3. Check Script Patterns (Medium Weight)
        for p in &sig.script_patterns {
            let re = Regex::new(&format!("(?i){}", p)).unwrap();
            if re.is_match(body) {
                signals += 1;
                current_confidence = current_confidence.max(75);
            }
        }

        // 4. Check HTML Patterns (Medium/Low Weight)
        for p in &sig.html_patterns {
            let re = Regex::new(&format!("(?i){}", p)).unwrap();
            if re.is_match(body) {
                signals += 1;
                current_confidence = current_confidence.max(60);
            }
        }

        // 5. Check URL Patterns (Medium Weight)
        // (Body check for URL patterns like script src or link href)
        for p in &sig.url_patterns {
             let re = Regex::new(&format!("(?i){}", p)).unwrap();
             if re.is_match(body) {
                 signals += 1;
                 current_confidence = current_confidence.max(70);
             }
        }

        // 6. Check Cookies (Low Weight)
        for c_pattern in &sig.cookies {
            let re = Regex::new(&format!("(?i){}", c_pattern)).unwrap();
            for cookie in &cookies {
                if re.is_match(cookie) {
                    signals += 1;
                    current_confidence = current_confidence.max(50);
                }
            }
        }

        if signals > 0 {
            // Confidence boost for multiple signals
            let final_confidence = if signals > 1 {
                (current_confidence + (signals * 5)).min(100)
            } else {
                current_confidence
            };

            detected.insert(sig.name.clone(), TechInfo {
                name: sig.name.clone(),
                confidence: final_confidence,
                category: sig.category.clone(),
                version,
            });
        }
    }
    
    detected
}
