use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use std::env;

lazy_static::lazy_static! {
    static ref CMS_PATTERNS: Vec<(Regex, &'static str, &'static str)> = vec![
        (Regex::new(r"(?i)wp-content|wp-includes|wordpress|wp-json").unwrap(), "WordPress", "CMS"),
        (Regex::new(r"(?i)drupal|sites/default|drupal.js").unwrap(), "Drupal", "CMS"),
        (Regex::new(r"(?i)joomla|com_content|com_user").unwrap(), "Joomla", "CMS"),
        (Regex::new(r"(?i)magento|skin/frontend|Mage\.").unwrap(), "Magento", "E-commerce"),
        (Regex::new(r"(?i)shopify|myshopify|cdn\.shopify").unwrap(), "Shopify", "E-commerce"),
        (Regex::new(r"(?i)woocommerce|wc-ajax|woocommerce").unwrap(), "WooCommerce", "E-commerce"),
        (Regex::new(r"(?i)prestashop|prestashop").unwrap(), "PrestaShop", "E-commerce"),
        (Regex::new(r"(?i)expressionengine|ee:").unwrap(), "ExpressionEngine", "CMS"),
        (Regex::new(r"(?i)concrete5|concrete/c5").unwrap(), "Concrete5", "CMS"),
        (Regex::new(r"(?i)umbraco|umbraco").unwrap(), "Umbraco", "CMS"),
        (Regex::new(r"(?i)sitecore|sitecore").unwrap(), "Sitecore", "CMS"),
        (Regex::new(r"(?i)django|csrftoken|__admin").unwrap(), "Django", "Framework"),
        (Regex::new(r"(?i)rails|ruby on rails|csrf-token").unwrap(), "Ruby on Rails", "Framework"),
        (Regex::new(r"(?i)laravel|livewire|laravel_session").unwrap(), "Laravel", "Framework"),
        (Regex::new(r"(?i)symfony|_sf2|symfony").unwrap(), "Symfony", "Framework"),
        (Regex::new(r"(?i)asp\.net|__viewstate|__eventvalidation").unwrap(), "ASP.NET", "Framework"),
        (Regex::new(r"(?i)next\.js|_next/static|__next").unwrap(), "Next.js", "Framework"),
        (Regex::new(r"(?i)nuxt|_nuxt").unwrap(), "Nuxt.js", "Framework"),
        (Regex::new(r"(?i)gatsby|___gatsby").unwrap(), "Gatsby", "Framework"),
        (Regex::new(r"(?i)vue\.js|vue-app|__vue__").unwrap(), "Vue.js", "JS Framework"),
        (Regex::new(r"(?i)react|reactjs|__react|reactroot").unwrap(), "React", "JS Framework"),
        (Regex::new(r"(?i)angular|ng-app|ng-version|angularjs").unwrap(), "Angular", "JS Framework"),
        (Regex::new(r"(?i)jquery|jquery\.min\.js|jquery-").unwrap(), "jQuery", "JS Library"),
        (Regex::new(r"(?i)bootstrap|bootstrap\.min\.css|col-md-").unwrap(), "Bootstrap", "CSS Framework"),
        (Regex::new(r"(?i)tailwind|dark:bg-gray|tw-").unwrap(), "Tailwind CSS", "CSS Framework"),
        (Regex::new(r"(?i)font-awesome|fa-|fontawesome").unwrap(), "Font Awesome", "Icon Library"),
        (Regex::new(r"(?i)cloudflare|cloudflare-nginx|__cf").unwrap(), "Cloudflare", "CDN"),
        (Regex::new(r"(?i)cloudfront|\.cloudfront\.net").unwrap(), "AWS CloudFront", "CDN"),
        (Regex::new(r"(?i)akamai|akamai|akamaiedge").unwrap(), "Akamai", "CDN"),
        (Regex::new(r"(?i)fastly|fastly|safebrowsing").unwrap(), "Fastly", "CDN"),
        (Regex::new(r"(?i)cdn\.|cdn-|\.cdn\.|netdna").unwrap(), "Generic CDN", "CDN"),
        (Regex::new(r"(?i)google-analytics|ga\('create|gtag").unwrap(), "Google Analytics", "Analytics"),
        (Regex::new(r"(?i)hotjar|hotjar").unwrap(), "Hotjar", "Analytics"),
        (Regex::new(r"(?i)facebook.*pixel|fbq\(|connect\.facebook").unwrap(), "Facebook Pixel", "Analytics"),
        (Regex::new(r"(?i)recaptcha|google\.com/recaptcha").unwrap(), "reCAPTCHA", "Security"),
        (Regex::new(r"(?i)hcaptcha|hcaptcha\.com").unwrap(), "hCaptcha", "Security"),
        (Regex::new(r"(?i)newrelic|NREUM").unwrap(), "New Relic", "Monitoring"),
    ];
    static ref SERVER_PATTERNS: Vec<(Regex, &'static str)> = vec![
        (Regex::new(r"(?i)server:\s*nginx/([0-9.]+)").unwrap(), "Nginx"),
        (Regex::new(r"(?i)server:\s*apache/([0-9.]+)").unwrap(), "Apache"),
        (Regex::new(r"(?i)server:\s*cloudflare").unwrap(), "Cloudflare"),
        (Regex::new(r"(?i)server:\s*microsoft-iis/([0-9.]+)").unwrap(), "IIS"),
        (Regex::new(r"(?i)server:\s*litespeed/([0-9.]+)").unwrap(), "LiteSpeed"),
        (Regex::new(r"(?i)server:\s*openresty/([0-9.]+)").unwrap(), "OpenResty"),
        (Regex::new(r"(?i)server:\s*caddy/([0-9.]+)").unwrap(), "Caddy"),
        (Regex::new(r"(?i)server:\s*lighttpd/([0-9.]+)").unwrap(), "Lighttpd"),
        (Regex::new(r"(?i)server:\s*gunicorn/([0-9.]+)").unwrap(), "Gunicorn"),
        (Regex::new(r"(?i)server:\s*uwsgi/([0-9.]+)").unwrap(), "uWSGI"),
        (Regex::new(r"(?i)server:\s*node\.js/([0-9.]+)").unwrap(), "Node.js"),
        (Regex::new(r"(?i)server:\s*tomcat/([0-9.]+)").unwrap(), "Tomcat"),
        (Regex::new(r"(?i)server:\s*jboss/([0-9.]+)").unwrap(), "JBoss"),
        (Regex::new(r"(?i)server:\s*jetty/([0-9.]+)").unwrap(), "Jetty"),
        (Regex::new(r"(?i)server:\s*webrick/([0-9.]+)").unwrap(), "WEBrick"),
        (Regex::new(r"(?i)server:\s*cherokee/([0-9.]+)").unwrap(), "Cherokee"),
        (Regex::new(r"(?i)server:\s*hiawatha/([0-9.]+)").unwrap(), "Hiawatha"),
        (Regex::new(r"(?i)server:\s*mono/([0-9.]+)").unwrap(), "Mono"),
        (Regex::new(r"(?i)server:\s*amazon-s3").unwrap(), "Amazon S3"),
        (Regex::new(r"(?i)server:\s*gse").unwrap(), "Google Search"),
    ];
    static ref HEADER_CHECKS: Vec<(&'static str, &'static str, &'static str)> = vec![
        ("x-powered-by", "x-powered-by", "Powered By"),
        ("x-generator", "x-generator", "Generator"),
        ("x-aspnet-version", "x-aspnet-version", "ASP.NET Version"),
        ("x-aspnetmvc-version", "x-aspnetmvc-version", "ASP.NET MVC Version"),
        ("x-drupal-cache", "x-drupal-cache", "Drupal Cache"),
        ("x-drupal-dynamic-cache", "x-drupal-dynamic-cache", "Drupal Dynamic Cache"),
        ("x-varnish", "x-varnish", "Varnish"),
        ("x-cache", "x-cache", "Cache"),
        ("cf-ray", "cf-ray", "Cloudflare Ray"),
        ("cf-cache-status", "cf-cache-status", "Cloudflare Cache"),
        ("x-served-by", "x-served-by", "Served By"),
        ("x-request-id", "x-request-id", "Request ID"),
    ];
}

#[derive(Debug, Serialize)]
struct WebFingerprint {
    url: String,
    status: u16,
    server: String,
    tech: Vec<String>,
    cms: Vec<String>,
    frameworks: Vec<String>,
    cdn: Vec<String>,
    analytics: Vec<String>,
    headers: HashMap<String, String>,
    cookies: Vec<String>,
    title: String,
    generator: String,
    elapsed_ms: u64,
}

struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    cookies: Vec<String>,
}

fn http_request(host: &str, port: u16, tls: bool, timeout_ms: u64) -> Option<Response> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(timeout_ms)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    let _scheme = if tls { "https" } else { "http" };
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: HackIT-RS/3.0 WebFingerprint\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: close\r\n\r\n",
        host
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut buf = vec![0u8; 65536];
    let mut resp = Vec::new();
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 { break; }
        resp.extend_from_slice(&buf[..n]);
        if resp.len() > 131072 { break; }
    }
    let s = String::from_utf8_lossy(&resp);
    let mut lines = s.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut headers = HashMap::new();
    let mut cookies = Vec::new();
    let body_start = s.find("\r\n\r\n").map(|p| p + 4).unwrap_or(s.len());
    for line in s.lines().take(100) {
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_lowercase();
            let val = line[pos + 1..].trim().to_string();
            if key == "set-cookie" { cookies.push(val.clone()); }
            headers.insert(key, val);
        }
    }
    let body = s[body_start..].to_string();
    Some(Response { status, headers, body, cookies })
}

fn extract_title(body: &str) -> String {
    if let Some(start) = body.find("<title>") {
        let rest = &body[start + 7..];
        if let Some(end) = rest.find("</title>") {
            return rest[..end].trim().to_string();
        }
    }
    String::new()
}

fn extract_generator(body: &str, headers: &HashMap<String, String>) -> String {
    if let Some(val) = headers.get("x-generator") { return val.clone(); }
    if let Some(caps) = Regex::new(r#"(?i)<meta\s+name="?generator"?\s+content="?([^">]+)"#).unwrap().captures(body) {
        return caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
    }
    String::new()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host> [port]", args[0]);
        eprintln!("  Analyzes web server technology, CMS, frameworks, CDN, analytics");
        std::process::exit(1);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(80);
    let start = Instant::now();
    let resp = http_request(host, port, port == 443, 5000);
    let elapsed = start.elapsed().as_millis() as u64;
    if let Some(resp) = resp {
        let mut tech = Vec::new();
        let mut cms = Vec::new();
        let mut frameworks = Vec::new();
        let mut cdns = Vec::new();
        let mut analytics = Vec::new();
        let server = resp.headers.get("server").cloned().unwrap_or_default();
        let check_body = format!("{}\n{}", resp.body, serde_json::to_string(&resp.headers).unwrap_or_default());
        for (re, name, category) in CMS_PATTERNS.iter() {
            if re.is_match(&check_body) {
                match *category {
                    "CMS" => cms.push(name.to_string()),
                    "Framework" | "JS Framework" | "JS Library" | "CSS Framework" | "Icon Library" => frameworks.push(name.to_string()),
                    "CDN" => cdns.push(name.to_string()),
                    "Analytics" | "Monitoring" | "Security" => analytics.push(name.to_string()),
                    "E-commerce" => cms.push(name.to_string()),
                    _ => tech.push(name.to_string()),
                }
                tech.push(format!("{} ({})", name, category));
            }
        }
        for (re, name) in SERVER_PATTERNS.iter() {
            if re.is_match(&check_body) && !tech.iter().any(|t| t.starts_with(name)) {
                tech.push(name.to_string());
            }
        }
        let mut extra_headers = HashMap::new();
        for (key, _, label) in HEADER_CHECKS.iter() {
            if let Some(val) = resp.headers.get(*key) {
                extra_headers.insert(label.to_string(), val.clone());
            }
        }
        let title = extract_title(&resp.body);
        let generator = extract_generator(&resp.body, &resp.headers);
        let result = WebFingerprint {
            url: format!("{}://{}:{}", if port == 443 { "https" } else { "http" }, host, port),
            status: resp.status,
            server,
            tech,
            cms,
            frameworks,
            cdn: cdns,
            analytics,
            headers: extra_headers,
            cookies: resp.cookies,
            title,
            generator,
            elapsed_ms: elapsed,
        };
        println!("RESULT:{}", serde_json::to_string(&result).unwrap());
    } else {
        let result = serde_json::json!({
            "url": format!("http://{}:{}", host, port),
            "error": "Connection failed or timeout",
            "elapsed_ms": elapsed,
        });
        println!("RESULT:{}", result);
    }
    let final_output = serde_json::json!({
        "host": host,
        "port": port,
        "elapsed_ms": elapsed,
    });
    println!("FINAL:{}", final_output);
}
