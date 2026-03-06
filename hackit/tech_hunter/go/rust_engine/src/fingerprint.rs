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

        // --- CMS ---
        let mut wp = TechSignature::new("WordPress", "CMS");
        wp.meta_tags.insert("generator".to_string(), r"WordPress ?([0-9.]*)?".to_string());
        wp.html_patterns.push(r"wp-content/".to_string());
        wp.html_patterns.push(r"wp-includes/".to_string());
        wp.url_patterns.push(r"/wp-admin/".to_string());
        wp.script_patterns.push(r"wp-embed\.min\.js".to_string());
        db.push(wp);

        let mut joomla = TechSignature::new("Joomla", "CMS");
        joomla.meta_tags.insert("generator".to_string(), r"Joomla!".to_string());
        joomla.url_patterns.push(r"/administrator/".to_string());
        db.push(joomla);

        let mut drupal = TechSignature::new("Drupal", "CMS");
        drupal.meta_tags.insert("generator".to_string(), r"Drupal".to_string());
        drupal.html_patterns.push(r"Drupal\.settings".to_string());
        db.push(drupal);

        // --- BACKEND FRAMEWORKS ---
        let mut laravel = TechSignature::new("Laravel", "Backend Framework");
        laravel.cookies.push(r"laravel_session".to_string());
        laravel.cookies.push(r"XSRF-TOKEN".to_string());
        db.push(laravel);

        let mut django = TechSignature::new("Django", "Backend Framework");
        django.cookies.push(r"csrftoken".to_string());
        db.push(django);

        let mut rails = TechSignature::new("Ruby on Rails", "Backend Framework");
        rails.cookies.push(r"_rails_session".to_string());
        db.push(rails);

        // --- FRONTEND FRAMEWORKS ---
        let mut react = TechSignature::new("React", "Frontend Framework");
        react.html_patterns.push(r"data-reactroot".to_string());
        react.script_patterns.push(r"react\.production\.min\.js".to_string());
        db.push(react);

        let mut vue = TechSignature::new("Vue.js", "Frontend Framework");
        vue.html_patterns.push(r"__vue__".to_string());
        vue.script_patterns.push(r"vue\.js".to_string());
        db.push(vue);

        let mut nextjs = TechSignature::new("Next.js", "Frontend Framework");
        nextjs.html_patterns.push(r"__NEXT_DATA__".to_string());
        nextjs.script_patterns.push(r"_next/static".to_string());
        db.push(nextjs);

        // --- CDN / WAF ---
        let mut cf = TechSignature::new("Cloudflare", "CDN/WAF");
        cf.headers.insert("CF-RAY".to_string(), r".+".to_string());
        cf.headers.insert("Server".to_string(), r"cloudflare".to_string());
        db.push(cf);

        let mut akamai = TechSignature::new("Akamai", "CDN/WAF");
        akamai.headers.insert("X-Akamai-Transformed".to_string(), r".+".to_string());
        db.push(akamai);

        // --- ANALYTICS ---
        let mut ga = TechSignature::new("Google Analytics", "Analytics");
        ga.script_patterns.push(r"google-analytics\.com/analytics\.js".to_string());
        ga.script_patterns.push(r"googletagmanager\.com/gtag/js".to_string());
        db.push(ga);

        // --- NEW JS LIBRARIES & FRAMEWORKS ---
        let mut gsap = TechSignature::new("GSAP", "JS Library");
        gsap.script_patterns.push(r"gsap(?:\.min)?\.js".to_string());
        gsap.html_patterns.push(r"TweenMax|TweenLite|TimelineMax".to_string());
        db.push(gsap);

        let mut astro = TechSignature::new("Astro", "Frontend Framework");
        astro.html_patterns.push(r"astro-island".to_string());
        astro.html_patterns.push(r"astro-".to_string());
        db.push(astro);

        let mut svelte = TechSignature::new("Svelte", "Frontend Framework");
        svelte.html_patterns.push(r"svelte-".to_string());
        svelte.script_patterns.push(r"svelte".to_string());
        db.push(svelte);

        let mut jquery = TechSignature::new("jQuery", "JS Library");
        jquery.script_patterns.push(r"jquery(?:\.min)?\.js".to_string());
        jquery.html_patterns.push(r"jQuery".to_string());
        db.push(jquery);

        let mut blogger = TechSignature::new("Blogger", "CMS");
        blogger.meta_tags.insert("generator".to_string(), r"blogger".to_string());
        blogger.html_patterns.push(r"blogger\.com".to_string());
        db.push(blogger);

        let mut wix = TechSignature::new("Wix", "CMS");
        wix.meta_tags.insert("generator".to_string(), r"Wix\.com Website Builder".to_string());
        wix.html_patterns.push(r"static\.wixstatic\.com".to_string());
        db.push(wix);

        let mut squarespace = TechSignature::new("Squarespace", "CMS");
        squarespace.headers.insert("X-Served-By".to_string(), r"Squarespace".to_string());
        squarespace.html_patterns.push(r"static1\.squarespace\.com".to_string());
        db.push(squarespace);

        let mut ghost = TechSignature::new("Ghost", "CMS");
        ghost.meta_tags.insert("generator".to_string(), r"Ghost\s?([0-9.]*)?".to_string());
        ghost.html_patterns.push(r"ghost-content".to_string());
        db.push(ghost);

        let mut typo3 = TechSignature::new("TYPO3", "CMS");
        typo3.meta_tags.insert("generator".to_string(), r"TYPO3 CMS".to_string());
        typo3.html_patterns.push(r"typo3temp/".to_string());
        db.push(typo3);

        let mut prestashop = TechSignature::new("PrestaShop", "CMS");
        prestashop.meta_tags.insert("generator".to_string(), r"PrestaShop".to_string());
        prestashop.html_patterns.push(r"prestashop".to_string());
        db.push(prestashop);

        // --- NEW FRONTEND & LIBRARIES ---
        let mut tailwind = TechSignature::new("Tailwind CSS", "Frontend Framework");
        tailwind.html_patterns.push(r"tailwind".to_string());
        db.push(tailwind);

        let mut bootstrap = TechSignature::new("Bootstrap", "Frontend Framework");
        bootstrap.html_patterns.push(r"bootstrap(?:\.min)?\.css".to_string());
        bootstrap.script_patterns.push(r"bootstrap(?:\.min)?\.js".to_string());
        db.push(bootstrap);

        let mut alpine = TechSignature::new("Alpine.js", "JS Library");
        alpine.html_patterns.push(r"x-data=".to_string());
        alpine.script_patterns.push(r"alpine(?:\.min)?\.js".to_string());
        db.push(alpine);

        let mut solidjs = TechSignature::new("SolidJS", "Frontend Framework");
        solidjs.html_patterns.push(r"solid-js".to_string());
        db.push(solidjs);

        // --- NEW SERVERS & INFRA ---
        let mut caddy = TechSignature::new("Caddy", "Web Server");
        caddy.headers.insert("Server".to_string(), r"Caddy".to_string());
        db.push(caddy);

        let mut openresty = TechSignature::new("OpenResty", "Web Server");
        openresty.headers.insert("Server".to_string(), r"openresty".to_string());
        db.push(openresty);

        let mut varnish = TechSignature::new("Varnish", "Web Server");
        varnish.headers.insert("X-Varnish".to_string(), r".+".to_string());
        varnish.headers.insert("Via".to_string(), r"Varnish".to_string());
        db.push(varnish);

        let mut litespeed = TechSignature::new("LiteSpeed", "Web Server");
        litespeed.headers.insert("Server".to_string(), r"LiteSpeed".to_string());
        litespeed.headers.insert("X-LiteSpeed-Cache".to_string(), r".+".to_string());
        db.push(litespeed);

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
        let mut max_confidence = 0;
        let mut version = None;

        // 1. Check Meta Tags (90%)
        for (m_name, m_pattern) in &sig.meta_tags {
            if let Some(val) = meta_tags.get(&m_name.to_lowercase()) {
                let re = Regex::new(&format!("(?i){}", m_pattern)).unwrap();
                if let Some(caps) = re.captures(val) {
                    max_confidence = max_confidence.max(90);
                    if caps.len() > 1 {
                        version = Some(caps[1].to_string());
                    }
                }
            }
        }

        // 2. Check Headers (80%)
        for (h_key, h_pattern) in &sig.headers {
            if let Some(val) = headers.get(h_key) {
                let re = Regex::new(&format!("(?i){}", h_pattern)).unwrap();
                if let Some(caps) = re.captures(val) {
                    max_confidence = max_confidence.max(80);
                    if caps.len() > 1 {
                        version = Some(caps[1].to_string());
                    }
                }
            }
        }

        // 3. Check Script Patterns (70%)
        for p in &sig.script_patterns {
            let re = Regex::new(&format!("(?i){}", p)).unwrap();
            if re.is_match(body) {
                max_confidence = max_confidence.max(70);
            }
        }

        // 4. Check HTML Patterns (60%)
        for p in &sig.html_patterns {
            let re = Regex::new(&format!("(?i){}", p)).unwrap();
            if re.is_match(body) {
                max_confidence = max_confidence.max(60);
            }
        }

        // 5. Check Cookies (50%)
        for c_pattern in &sig.cookies {
            let re = Regex::new(&format!("(?i){}", c_pattern)).unwrap();
            for cookie in &cookies {
                if re.is_match(cookie) {
                    max_confidence = max_confidence.max(50);
                }
            }
        }

        if max_confidence > 0 {
            // Bonus for multiple signals
            let mut final_confidence = max_confidence;
            let mut signals = 0;
            if max_confidence >= 50 { signals += 1; }
            // Check if there are other signals to boost confidence
            // (Simple boost logic)
            if signals > 1 {
                final_confidence = (final_confidence + 10).min(100);
            }

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
