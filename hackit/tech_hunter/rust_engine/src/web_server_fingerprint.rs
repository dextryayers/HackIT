use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerFingerprint {
    pub server_software: String,
    pub framework: String,
    pub cms: String,
    pub language: String,
    pub os_hint: String,
    pub confidence: i32,
    pub details: Vec<String>,
}

struct CMSFingerprint {
    patterns: &'static [&'static str],
    name: &'static str,
    confidence: i32,
    details: &'static [&'static str],
}

const CMS_FINGERPRINTS: &[CMSFingerprint] = &[
    CMSFingerprint {     patterns: &["wp-", "wordpress", "/wp-content/", "/wp-includes/", "/wp-admin/", "wp-login", "xmlrpc"], name: "WordPress", confidence: 85,     details: &["PHP/MySQL", "Plugin ecosystem"] },
    CMSFingerprint {     patterns: &["drupal", "drupal.js", "drupalSettings"], name: "Drupal", confidence: 85,     details: &["PHP", "Twig templating"] },
    CMSFingerprint {     patterns: &["joomla", "/components/", "/modules/", "/templates/"], name: "Joomla", confidence: 80,     details: &["PHP", "MVC framework"] },
    CMSFingerprint {     patterns: &["magento", "mage", "requirejs"], name: "Magento", confidence: 75,     details: &["PHP", "Zend/Laminas framework"] },
    CMSFingerprint {     patterns: &["shopify", "myshopify", "/cdn/shop/"], name: "Shopify", confidence: 85,     details: &["Ruby/Liquid", "Hosted e-commerce"] },
    CMSFingerprint {     patterns: &["squarespace", "static.squarespace"], name: "Squarespace", confidence: 80,     details: &["Hosted CMS"] },
    CMSFingerprint {     patterns: &["wix", "wixstatic", "wix.com"], name: "Wix", confidence: 80,     details: &["Hosted CMS"] },
    CMSFingerprint {     patterns: &["umbraco", "umbraco"], name: "Umbraco", confidence: 70,     details: &["ASP.NET CMS"] },
    CMSFingerprint {     patterns: &["sitecore", "sitecore"], name: "Sitecore", confidence: 70,     details: &["ASP.NET CMS", "Enterprise"] },
    CMSFingerprint {     patterns: &["typo3", "typo3"], name: "TYPO3", confidence: 75,     details: &["PHP CMS"] },
    CMSFingerprint {     patterns: &["django cms", "django.cms", "cms"], name: "Django CMS", confidence: 60,     details: &["Python/Django"] },
    CMSFingerprint {     patterns: &["ghost", "ghost.io"], name: "Ghost", confidence: 70,     details: &["Node.js", "Blogging platform"] },
    CMSFingerprint {     patterns: &["hubspot", "hs-analytics"], name: "HubSpot CMS", confidence: 65,     details: &["Hosted CMS/CRM"] },
    CMSFingerprint {     patterns: &["webflow", "webflow"], name: "Webflow", confidence: 65,     details: &["Hosted CMS"] },
    CMSFingerprint {     patterns: &["jekyll", "jekyll"], name: "Jekyll", confidence: 55,     details: &["Static site generator", "Ruby"] },
    CMSFingerprint {     patterns: &["hugo", "hugo"], name: "Hugo", confidence: 50,     details: &["Static site generator", "Go"] },
];

struct FrameworkFingerprint {
    patterns: &'static [&'static str],
    name: &'static str,
    language: &'static str,
    confidence: i32,
}

const FRAMEWORK_FINGERPRINTS: &[FrameworkFingerprint] = &[
    FrameworkFingerprint {     patterns: &["laravel", "xsrf-token", "laravel_session", "livewire"], name: "Laravel", language: "PHP", confidence: 80 },
    FrameworkFingerprint {     patterns: &["symfony", "_sf2_", "_sf_"], name: "Symfony", language: "PHP", confidence: 75 },
    FrameworkFingerprint {     patterns: &["cakephp", "cake_"], name: "CakePHP", language: "PHP", confidence: 70 },
    FrameworkFingerprint {     patterns: &["codeigniter", "ci_session"], name: "CodeIgniter", language: "PHP", confidence: 65 },
    FrameworkFingerprint {     patterns: &["yii", "yii_"], name: "Yii Framework", language: "PHP", confidence: 65 },
    FrameworkFingerprint {     patterns: &["django", "csrftoken", "sessionid", "django"], name: "Django", language: "Python", confidence: 80 },
    FrameworkFingerprint {     patterns: &["flask", "flask"], name: "Flask", language: "Python", confidence: 55 },
    FrameworkFingerprint {     patterns: &["fastapi", "fastapi"], name: "FastAPI", language: "Python", confidence: 55 },
    FrameworkFingerprint {     patterns: &["rails", "rails", "authenticity_token", "_csrf_token"], name: "Ruby on Rails", language: "Ruby", confidence: 80 },
    FrameworkFingerprint {     patterns: &["sinatra", "sinatra"], name: "Sinatra", language: "Ruby", confidence: 60 },
    FrameworkFingerprint {     patterns: &["express", "connect.sid"], name: "Express.js", language: "Node.js", confidence: 75 },
    FrameworkFingerprint {     patterns: &["koa", "koa"], name: "Koa.js", language: "Node.js", confidence: 55 },
    FrameworkFingerprint {     patterns: &["next-js", "next.js", "__next", "next"], name: "Next.js", language: "Node.js", confidence: 75 },
    FrameworkFingerprint {     patterns: &["nuxt", "_nuxt"], name: "Nuxt.js", language: "Node.js", confidence: 60 },
    FrameworkFingerprint {     patterns: &["gatsby", "gatsby"], name: "Gatsby", language: "Node.js", confidence: 55 },
    FrameworkFingerprint {     patterns: &["spring", "__spring"], name: "Spring Boot", language: "Java", confidence: 65 },
    FrameworkFingerprint {     patterns: &["play framework", "play"], name: "Play Framework", language: "Java/Scala", confidence: 55 },
    FrameworkFingerprint {     patterns: &["asp.net", "viewstate", "__viewstate", "asp.net_sessionid"], name: "ASP.NET", language: "C#", confidence: 75 },
    FrameworkFingerprint {     patterns: &["blazor", "blazor"], name: "Blazor", language: "C#/.NET", confidence: 55 },
    FrameworkFingerprint {     patterns: &["gin", "gin"], name: "Gin", language: "Go", confidence: 45 },
    FrameworkFingerprint {     patterns: &["echo", "echo"], name: "Echo", language: "Go", confidence: 40 },
];

fn extract_server_software(headers_lower: &str) -> (String, String, String) {
    if let Some(pos) = headers_lower.find("server:") {
        let start = pos + 7;
        let end = headers_lower[start..].find('\n').unwrap_or(headers_lower.len() - start);
        let server = headers_lower[start..start + end].trim().to_string();

        let os_hint = if server.contains("ubuntu") { "Ubuntu".into() }
            else if server.contains("debian") { "Debian".into() }
            else if server.contains("centos") { "CentOS".into() }
            else if server.contains("red hat") || server.contains("rhel") { "Red Hat".into() }
            else if server.contains("windows") || server.contains("win32") { "Windows Server".into() }
            else if server.contains("freebsd") { "FreeBSD".into() }
            else { "Unknown".into() };

        return (server, os_hint, "".into());
    }
    ("Unknown".into(), "Unknown".into(), "".into())
}

pub fn get_fingerprint_json(headers_raw: &str) -> String {
    let headers_lower = headers_raw.to_lowercase();
    let body_lower = headers_lower.clone(); // body included in headers_raw for this function

    let (server_software, os_hint, _) = extract_server_software(&headers_lower);

    let mut cms = "None".to_string();
    let mut cms_conf = 0;
    let mut cms_details: Vec<String> = Vec::new();

    for fp in CMS_FINGERPRINTS {
        for p in fp.patterns {
            if body_lower.contains(p) || headers_lower.contains(p) {
                if fp.confidence > cms_conf {
                    cms = fp.name.to_string();
                    cms_conf = fp.confidence;
                    cms_details = fp.details.iter().map(|s| s.to_string()).collect();
                }
                break;
            }
        }
    }

    let mut framework = "None".to_string();
    let mut framework_lang = "Unknown".to_string();
    let mut framework_conf = 0;

    for fp in FRAMEWORK_FINGERPRINTS {
        for p in fp.patterns {
            if body_lower.contains(p) || headers_lower.contains(p) {
                if fp.confidence > framework_conf {
                    framework = fp.name.to_string();
                    framework_lang = fp.language.to_string();
                    framework_conf = fp.confidence;
                }
                break;
            }
        }
    }

    let mut details = Vec::new();
    if cms_conf > 0 {
        details.push(format!("CMS: {} (confidence: {}%)", cms, cms_conf));
        for d in &cms_details {
            details.push(format!("  - {}", d));
        }
    }
    if framework_conf > 0 {
        details.push(format!("Framework: {} ({})", framework, framework_lang));
    }
    if server_software != "Unknown" {
        details.push(format!("Server: {}", server_software));
    }

    let result = ServerFingerprint {
        server_software,
        framework,
        cms,
        language: framework_lang,
        os_hint,
        confidence: cms_conf.max(framework_conf) as i32,
        details,
    };

    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
}
