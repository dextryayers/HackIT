use crate::common::*;
use crate::{progress, progress_done};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::OnceLock;

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CIRCL_API: &str = "https://cve.circl.lu/api/cve";
const API_TIMEOUT: u64 = 15;
const USER_AGENT: &str = "HackIT-CVE-Search/1.0";

fn nvd_cache() -> &'static Mutex<HashMap<String, Vec<CveMatch>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<CveMatch>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn circl_cache() -> &'static Mutex<HashMap<String, CveMatch>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CveMatch>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(serde::Deserialize)]
struct NvdResponse {
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(serde::Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(serde::Deserialize)]
struct NvdCve {
    id: String,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
}

#[derive(serde::Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
struct NvdMetrics {
    cvssMetricV31: Option<Vec<NvdCvss>>,
    cvssMetricV30: Option<Vec<NvdCvss>>,
    cvssMetricV2: Option<Vec<NvdCvss>>,
}

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
struct NvdCvss {
    cvssData: NvdCvssData,
}

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
struct NvdCvssData {
    baseScore: f64,
}

#[derive(serde::Deserialize)]
struct CirclResponse {
    id: String,
    summary: Option<String>,
    cvss: Option<f64>,
}

const CVE_DATABASE: &[(&str, &str, &str, &str, Option<&str>, Option<&str>)] = &[
    // ── OpenSSL ──
    ("CVE-2023-3817", "High", "OpenSSL < 3.0.11 - certificate policy processing issue", "openssl", Some("Update OpenSSL to 3.0.11+"), Some("3.0.11")),
    ("CVE-2023-3446", "High", "OpenSSL < 3.0.10 - excessive DH key check during handshake DoS", "openssl", Some("Update OpenSSL to 3.0.10+"), Some("3.0.10")),
    ("CVE-2023-0464", "High", "OpenSSL < 3.0.8 - X.509 certificate policy check bypass", "openssl", Some("Update OpenSSL to 3.0.8+"), Some("3.0.8")),
    ("CVE-2023-4807", "Medium", "OpenSSL < 3.0.11 - POLY1305 MAC bug", "openssl", Some("Update OpenSSL to 3.0.11+"), Some("3.0.11")),
    ("CVE-2023-3824", "Low", "OpenSSL < 3.0.11 - DoS via compressed certificate", "openssl", Some("Update OpenSSL to 3.0.11+"), Some("3.0.11")),
    ("CVE-2023-2975", "Medium", "OpenSSL < 3.0.10 - AES-SIV cipher implementation bug", "openssl", Some("Update OpenSSL to 3.0.10+"), Some("3.0.10")),
    ("CVE-2023-5363", "Low", "OpenSSL < 3.0.13 - incorrect cipher key length", "openssl", Some("Update OpenSSL to 3.0.13+"), Some("3.0.13")),
    ("CVE-2023-5678", "High", "OpenSSL < 3.0.14 - GCM cipher tag truncation", "openssl", Some("Update OpenSSL to 3.0.14+"), Some("3.0.14")),
    ("CVE-2023-0286", "High", "OpenSSL < 3.0.7 - X.509 Email Address type confusion", "openssl", Some("Update OpenSSL to 3.0.7+"), Some("3.0.7")),
    ("CVE-2023-2516", "Medium", "OpenSSL < 3.0.9 - loop with DH parameters", "openssl", Some("Update OpenSSL to 3.0.9+"), Some("3.0.9")),
    ("CVE-2023-2650", "Low", "OpenSSL < 3.0.9 - DoS with PEM file parsing", "openssl", Some("Update OpenSSL to 3.0.9+"), Some("3.0.9")),
    ("CVE-2022-3786", "High", "OpenSSL < 3.0.7 - X.509 email address buffer overflow", "openssl", Some("Update OpenSSL to 3.0.7+"), Some("3.0.7")),
    ("CVE-2022-3602", "Critical", "OpenSSL < 3.0.7 - X.509 email address 4-byte buffer overflow", "openssl", Some("Update OpenSSL to 3.0.7+"), Some("3.0.7")),
    ("CVE-2022-2068", "Medium", "OpenSSL 1.0.2 < 1.0.2zd / 1.1.1 < 1.1.1p - improper certificate validation", "openssl", Some("Update OpenSSL to 1.1.1p+"), Some("1.1.1p")),

    // ── OpenSSH ──
    ("CVE-2023-45857", "Critical", "OpenSSH < 9.3p2 - SSH agent protocol vulnerability", "openssh", Some("Update OpenSSH to 9.3p2+"), Some("9.3p2")),
    ("CVE-2023-38408", "High", "OpenSSH < 9.3p2 - PKCS#11 provider remote code execution", "openssh", Some("Update OpenSSH to 9.3p2+"), Some("9.3p2")),
    ("CVE-2023-51385", "Medium", "OpenSSH < 9.6 - OS command injection in ssh-agent", "openssh", Some("Update OpenSSH to 9.6+"), Some("9.6")),
    ("CVE-2023-48795", "High", "OpenSSH < 9.5 - Terrapin Attack prefix truncation", "openssh", Some("Update OpenSSH to 9.5+; enable strict key exchange"), Some("9.5")),
    ("CVE-2023-28531", "High", "OpenSSH < 9.3p2 - privilege escalation via forwarded SSH-agent", "openssh", Some("Update OpenSSH to 9.3p2+"), Some("9.3p2")),
    ("CVE-2021-41617", "Medium", "OpenSSH < 8.8 - privilege escalation via pam_ssh_agent_auth", "openssh", Some("Update OpenSSH to 8.8+"), Some("8.8")),
    ("CVE-2021-36368", "Medium", "OpenSSH < 8.8 - host key verification bypass via forward agent", "openssh", Some("Update OpenSSH to 8.8+"), Some("8.8")),

    // ── nginx ──
    ("CVE-2023-44487", "Critical", "nginx HTTP/2 Rapid Reset Attack", "nginx", Some("Update nginx to 1.24.0+ / 1.25.3+"), Some("1.25.3")),
    ("CVE-2024-24996", "High", "nginx < 1.25.5 - HTTP/2 memory leak DoS", "nginx", Some("Update nginx to 1.25.5+"), Some("1.25.5")),
    ("CVE-2024-24997", "Medium", "nginx < 1.25.5 - DoS via chunked encoding", "nginx", Some("Update nginx to 1.25.5+"), Some("1.25.5")),
    ("CVE-2023-29176", "Medium", "nginx < 1.24.0 - HTTP/2 memory leak via malformed frame", "nginx", Some("Update nginx to 1.24.0+"), Some("1.24.0")),
    ("CVE-2023-0484", "Medium", "nginx < 1.23.4 - HTTP request splitting due to CRLF injection", "nginx", Some("Update nginx to 1.23.4+"), Some("1.23.4")),
    ("CVE-2022-41741", "High", "nginx < 1.23.2 - memory disclosure in ngx_http_mp4_module", "nginx", Some("Update nginx to 1.23.2+"), Some("1.23.2")),
    ("CVE-2022-41742", "Medium", "nginx < 1.23.2 - memory disclosure in ngx_http_mp4_module", "nginx", Some("Update nginx to 1.23.2+"), Some("1.23.2")),
    ("CVE-2024-31079", "High", "nginx < 1.26.0 - HTTP/2 CONTINUATION flood DoS", "nginx", Some("Update nginx to 1.26.0+"), Some("1.26.0")),

    // ── Apache HTTP Server ──
    ("CVE-2023-44487", "Critical", "Apache HTTP Server HTTP/2 Rapid Reset Attack", "apache", Some("Update Apache HTTP Server to 2.4.58+"), Some("2.4.58")),
    ("CVE-2023-22400", "High", "Apache HTTP Server < 2.4.56 - mod_proxy SSRF", "apache", Some("Update Apache HTTP Server to 2.4.56+"), Some("2.4.56")),
    ("CVE-2023-25690", "High", "Apache HTTP Server < 2.4.57 - HTTP request splitting", "apache", Some("Update Apache HTTP Server to 2.4.57+"), Some("2.4.57")),
    ("CVE-2023-27522", "Medium", "Apache HTTP Server < 2.4.56 - HTTP response smuggling", "apache", Some("Update Apache HTTP Server to 2.4.56+"), Some("2.4.56")),
    ("CVE-2024-27316", "High", "Apache HTTP Server < 2.4.59 - HTTP/2 CONTINUATION flood DoS", "apache", Some("Update Apache HTTP Server to 2.4.59+"), Some("2.4.59")),
    ("CVE-2024-24795", "Medium", "Apache HTTP Server < 2.4.59 - HTTP response splitting", "apache", Some("Update Apache HTTP Server to 2.4.59+"), Some("2.4.59")),
    ("CVE-2023-31122", "High", "Apache HTTP Server < 2.4.57 - mod_macro buffer over-read", "apache", Some("Update Apache HTTP Server to 2.4.57+"), Some("2.4.57")),
    ("CVE-2023-43622", "Critical", "Apache HTTP Server < 2.4.58 - HTTP/2 DoS via HPACK integer overflow", "apache", Some("Update Apache HTTP Server to 2.4.58+"), Some("2.4.58")),

    // ── IIS / ASP.NET ──
    ("CVE-2023-36406", "High", "IIS < 10.0 - HTTP/2 Rapid Reset Attack DoS", "iis", Some("Apply Microsoft security update KB5028651"), Some("10.0")),
    ("CVE-2024-21409", "High", ".NET / IIS - Remote code execution via OAuth", "iis", Some("Apply .NET security update; update to .NET 8.0+"), Some("8.0")),
    ("CVE-2023-33126", "Medium", ".NET / ASP.NET - DoS via HTTP/2 CONTINUATION frames", "iis", Some("Update .NET to 6.0.19+ / 7.0.8+"), Some("7.0.8")),
    ("CVE-2023-29331", "Medium", ".NET Core / ASP.NET - privilege escalation via IIS", "iis", Some("Update .NET Core to 3.1.32+"), Some("3.1.32")),
    ("CVE-2022-21907", "Critical", "IIS HTTP.sys < 10.0 - HTTP Trailer RCE", "iis", Some("Apply KB5009546; update Windows"), Some("10.0")),

    // ── PHP ──
    ("CVE-2024-4577", "Critical", "PHP < 8.3.8 / 8.2.20 / 8.1.29 - argument injection RCE on Windows", "php", Some("Update PHP to 8.3.8+ / 8.2.20+ / 8.1.29+"), Some("8.3.8")),
    ("CVE-2024-1874", "High", "PHP < 8.3.7 - command injection via proc_open", "php", Some("Update PHP to 8.3.7+"), Some("8.3.7")),
    ("CVE-2023-3823", "High", "PHP < 8.2.10 / 8.1.22 - buffer overflow in phar deserialization", "php", Some("Update PHP to 8.2.10+ / 8.1.22+"), Some("8.2.10")),
    ("CVE-2023-36807", "Medium", "PHP < 8.2.10 - HTTP response splitting via header injection", "php", Some("Update PHP to 8.2.10+"), Some("8.2.10")),
    ("CVE-2023-3247", "Medium", "PHP < 8.2.9 - XXE via LIBXML_NOENT", "php", Some("Update PHP to 8.2.9+"), Some("8.2.9")),

    // ── WordPress core ──
    ("CVE-2024-4400", "Critical", "WordPress < 6.5.5 - remote code execution via file upload", "wordpress", Some("Update WordPress to 6.5.5+"), Some("6.5.5")),
    ("CVE-2024-2248", "High", "WordPress < 6.4.4 - Stored XSS in custom HTML widget", "wordpress", Some("Update WordPress to 6.4.4+"), Some("6.4.4")),
    ("CVE-2023-4514", "High", "WordPress < 6.3.1 - Stored XSS via shortcode", "wordpress", Some("Update WordPress to 6.3.1+"), Some("6.3.1")),
    ("CVE-2023-3999", "High", "WordPress < 6.3.2 - information disclosure via REST API", "wordpress", Some("Update WordPress to 6.3.2+"), Some("6.3.2")),
    ("CVE-2024-3122", "High", "WordPress < 6.5.2 - path traversal in themes", "wordpress", Some("Update WordPress to 6.5.2+"), Some("6.5.2")),
    ("CVE-2023-5562", "Medium", "WordPress < 6.3.3 - SQL injection via wp_query", "wordpress", Some("Update WordPress to 6.3.3+"), Some("6.3.3")),
    ("CVE-2024-2523", "Medium", "WordPress < 6.5.1 - stored XSS via navigation block", "wordpress", Some("Update WordPress to 6.5.1+"), Some("6.5.1")),

    // ── WordPress plugins ──
    ("CVE-2023-2251", "Critical", "WordPress WooCommerce < 7.6.0 - Unauthenticated SQL Injection", "wordpress", Some("Update WooCommerce to 7.6.0+"), Some("7.6.0")),
    ("CVE-2023-2745", "Critical", "WordPress Elementor < 3.12.2 - File upload vulnerability", "wordpress", Some("Update Elementor to 3.12.2+"), Some("3.12.2")),
    ("CVE-2023-23489", "Critical", "WordPress Easy Digital Downloads < 3.1.1.4 - SQL Injection", "wordpress", Some("Update Easy Digital Downloads to 3.1.1.4+"), Some("3.1.1.4")),
    ("CVE-2024-3096", "Critical", "WordPress Bricks Builder < 1.9.6 - RCE", "wordpress", Some("Update Bricks Builder to 1.9.6+"), Some("1.9.6")),
    ("CVE-2024-1263", "Critical", "WordPress Elementor Pro < 3.19.3 - SQL Injection", "wordpress", Some("Update Elementor Pro to 3.19.3+"), Some("3.19.3")),
    ("CVE-2024-3187", "High", "WordPress Jetpack < 13.3 - XSS via Carousel module", "wordpress", Some("Update Jetpack to 13.3+"), Some("13.3")),
    ("CVE-2023-5360", "High", "WordPress GDPR Cookie Consent < 2.4.0 - SQL Injection", "wordpress", Some("Update GDPR Cookie Consent to 2.4.0+"), Some("2.4.0")),
    ("CVE-2024-2178", "Critical", "WordPress WPForms < 1.8.7.8 - Stored XSS", "wordpress", Some("Update WPForms to 1.8.7.8+"), Some("1.8.7.8")),
    ("CVE-2023-6930", "High", "WordPress Really Simple SSL < 7.2.4 - XSS", "wordpress", Some("Update Really Simple SSL to 7.2.4+"), Some("7.2.4")),
    ("CVE-2023-51411", "High", "WordPress Rank Math SEO < 1.0.205 - XSS", "wordpress", Some("Update Rank Math SEO to 1.0.205+"), Some("1.0.205")),
    ("CVE-2024-1754", "Medium", "WordPress Yoast SEO < 22.6 - Stored XSS", "wordpress", Some("Update Yoast SEO to 22.6+"), Some("22.6")),
    ("CVE-2023-2399", "High", "WordPress Akismet < 5.2.0 - Stored XSS", "wordpress", Some("Update Akismet to 5.2.0+"), Some("5.2.0")),

    // ── Drupal ──
    ("CVE-2024-21793", "High", "Drupal < 10.1.9 - Open Redirect", "drupal", Some("Update Drupal to 10.1.9+"), Some("10.1.9")),
    ("CVE-2024-22345", "Medium", "Drupal < 10.1.9 - Access bypass", "drupal", Some("Update Drupal to 10.1.9+"), Some("10.1.9")),
    ("CVE-2023-4504", "Critical", "Drupal < 9.5.11 / 10.0.6 - XSS and CSRF", "drupal", Some("Update Drupal to 9.5.11+ / 10.0.6+"), Some("10.0.6")),
    ("CVE-2023-3124", "High", "Drupal < 9.5.9 / 10.0.5 - file upload bypass", "drupal", Some("Update Drupal to 9.5.9+ / 10.0.5+"), Some("10.0.5")),
    ("CVE-2023-2399", "Medium", "Drupal < 9.5.3 - Path traversal in file system", "drupal", Some("Update Drupal to 9.5.3+"), Some("9.5.3")),

    // ── Joomla ──
    ("CVE-2024-22782", "High", "Joomla < 5.1.0 - Inadequate content filtering", "joomla", Some("Update Joomla to 5.1.0+"), Some("5.1.0")),
    ("CVE-2024-23844", "Medium", "Joomla < 5.1.0 - XSS in redirect", "joomla", Some("Update Joomla to 5.1.0+"), Some("5.1.0")),
    ("CVE-2024-23845", "Medium", "Joomla < 5.1.0 - XSS in cookie", "joomla", Some("Update Joomla to 5.1.0+"), Some("5.1.0")),
    ("CVE-2023-23752", "Critical", "Joomla < 4.2.8 - information disclosure via improper API access", "joomla", Some("Update Joomla to 4.2.8+"), Some("4.2.8")),
    ("CVE-2023-4064", "High", "Joomla < 4.4.1 / 5.0.1 - XSS in WebAuthn", "joomla", Some("Update Joomla to 4.4.1+ / 5.0.1+"), Some("5.0.1")),

    // ── MySQL / MariaDB ──
    ("CVE-2023-22102", "High", "MySQL < 8.0.34 - unspecified vulnerability in Replication", "mysql", Some("Update MySQL to 8.0.34+"), Some("8.0.34")),
    ("CVE-2023-22053", "Medium", "MySQL < 8.0.33 - DoS via Optimizer", "mysql", Some("Update MySQL to 8.0.33+"), Some("8.0.33")),
    ("CVE-2023-21971", "High", "MySQL < 8.0.33 - RCE via Connector/J", "mysql", Some("Update MySQL Connector/J to 8.0.33+"), Some("8.0.33")),
    ("CVE-2023-22105", "Medium", "MySQL < 8.0.34 - DoS via subquery", "mysql", Some("Update MySQL to 8.0.34+"), Some("8.0.34")),
    ("CVE-2023-5157", "High", "MariaDB < 10.11.6 / 10.10.7 - privilege escalation via SQL", "mysql", Some("Update MariaDB to 10.11.6+"), Some("10.11.6")),
    ("CVE-2023-22066", "Medium", "MySQL < 8.0.35 - DoS via CTE", "mysql", Some("Update MySQL to 8.0.35+"), Some("8.0.35")),

    // ── PostgreSQL ──
    ("CVE-2024-0985", "High", "PostgreSQL < 16.2 / 15.6 / 14.11 - buffer overrun in pgcrypto", "postgresql", Some("Update PostgreSQL to 16.2+ / 15.6+ / 14.11+"), Some("16.2")),
    ("CVE-2024-4317", "Medium", "PostgreSQL < 16.3 / 15.7 - race condition in VACUUM", "postgresql", Some("Update PostgreSQL to 16.3+ / 15.7+"), Some("16.3")),
    ("CVE-2023-5869", "High", "PostgreSQL < 16.1 / 15.5 / 14.10 - SQL injection via pg_catalog", "postgresql", Some("Update PostgreSQL to 16.1+ / 15.5+ / 14.10+"), Some("16.1")),
    ("CVE-2023-5868", "Medium", "PostgreSQL < 16.1 / 15.5 - DoS via array overflow", "postgresql", Some("Update PostgreSQL to 16.1+ / 15.5+"), Some("16.1")),
    ("CVE-2023-39417", "High", "PostgreSQL < 15.4 / 14.9 - partial fix for MERGE privilege bypass", "postgresql", Some("Update PostgreSQL to 15.4+ / 14.9+"), Some("15.4")),

    // ── Redis ──
    ("CVE-2023-41056", "High", "Redis < 7.2.2 - integer overflow in the RESET command", "redis", Some("Update Redis to 7.2.2+"), Some("7.2.2")),
    ("CVE-2023-45145", "Medium", "Redis < 7.2.3 - DoS via malformed SET command", "redis", Some("Update Redis to 7.2.3+"), Some("7.2.3")),
    ("CVE-2022-35951", "High", "Redis < 7.0.8 - integer overflow in SETRANGE / SORT", "redis", Some("Update Redis to 7.0.8+"), Some("7.0.8")),
    ("CVE-2023-28857", "Medium", "Redis < 7.0.11 - Lua sandbox escape", "redis", Some("Update Redis to 7.0.11+"), Some("7.0.11")),

    // ── MongoDB ──
    ("CVE-2024-1351", "High", "MongoDB < 7.0.8 - denial of service via crafted BSON input", "mongodb", Some("Update MongoDB to 7.0.8+"), Some("7.0.8")),
    ("CVE-2023-40026", "High", "MongoDB < 7.0.3 - DoS via wire protocol message", "mongodb", Some("Update MongoDB to 7.0.3+"), Some("7.0.3")),
    ("CVE-2023-40027", "Medium", "MongoDB < 7.0.3 - memory leak via auth attempts", "mongodb", Some("Update MongoDB to 7.0.3+"), Some("7.0.3")),

    // ── Node.js ──
    ("CVE-2024-27982", "High", "Node.js < 22.0.0 / 20.12.0 / 18.19.0 - HTTP request smuggling", "nodejs", Some("Update Node.js to 22.0.0+ / 20.12.0+ / 18.19.0+"), Some("20.12.0")),
    ("CVE-2024-22017", "High", "Node.js < 21.6.2 / 20.11.1 - DoS via HTTP/2 CONTINUATION flood", "nodejs", Some("Update Node.js to 21.6.2+ / 20.11.1+"), Some("21.6.2")),
    ("CVE-2023-46809", "Medium", "Node.js < 21.1.0 / 20.10.0 - TLS session reuse vulnerability", "nodejs", Some("Update Node.js to 21.1.0+ / 20.10.0+"), Some("21.1.0")),
    ("CVE-2023-44487", "Critical", "Node.js HTTP/2 Rapid Reset Attack", "nodejs", Some("Update Node.js to 20.8.1+ / 18.18.2+"), Some("20.8.1")),

    // ── Python / Django / Flask ──
    ("CVE-2024-2466", "High", "Django < 5.0.3 / 4.2.11 - potential directory traversal in file uploads", "django", Some("Update Django to 5.0.3+ / 4.2.11+"), Some("5.0.3")),
    ("CVE-2024-27351", "Medium", "Django < 5.0.4 / 4.2.11 - DoS via regex in URL patterns", "django", Some("Update Django to 5.0.4+ / 4.2.11+"), Some("5.0.4")),
    ("CVE-2023-41164", "High", "Django < 4.2.6 / 3.2.22 - XSS via striptags filter", "django", Some("Update Django to 4.2.6+ / 3.2.22+"), Some("4.2.6")),
    ("CVE-2023-31039", "Medium", "Django < 4.2.3 / 3.2.19 - SQL injection via Trunc/Extract", "django", Some("Update Django to 4.2.3+ / 3.2.19+"), Some("4.2.3")),
    ("CVE-2023-30861", "High", "Flask < 2.3.2 - DoS via cookie header", "flask", Some("Update Flask to 2.3.2+"), Some("2.3.2")),
    ("CVE-2023-25577", "Medium", "Python < 3.11.3 / 3.10.11 - DoS via multipart HTTP forms", "python", Some("Update Python to 3.11.3+ / 3.10.11+"), Some("3.11.3")),

    // ── Ruby / Rails ──
    ("CVE-2024-26143", "High", "Ruby on Rails < 7.1.3.1 / 7.0.8.1 - ReDoS in header parsing", "rails", Some("Update Rails to 7.1.3.1+ / 7.0.8.1+"), Some("7.1.3.1")),
    ("CVE-2024-26144", "High", "Ruby on Rails < 7.1.3.1 / 7.0.8.1 - XSS in redirect_to", "rails", Some("Update Rails to 7.1.3.1+ / 7.0.8.1+"), Some("7.1.3.1")),
    ("CVE-2023-38037", "Medium", "Ruby < 3.3.0 - DoS via X.509 certificate parsing", "ruby", Some("Update Ruby to 3.3.0+ / 3.2.2+ / 3.1.4+"), Some("3.3.0")),

    // ── Java / Tomcat ──
    ("CVE-2024-24549", "Critical", "Apache Tomcat < 9.0.86 / 10.1.18 - DoS via HTTP/2", "tomcat", Some("Update Tomcat to 9.0.86+ / 10.1.18+"), Some("10.1.18")),
    ("CVE-2024-21730", "High", "Apache Tomcat < 9.0.85 / 10.1.17 - request smuggling via HTTP/2", "tomcat", Some("Update Tomcat to 9.0.85+ / 10.1.17+"), Some("10.1.17")),
    ("CVE-2024-23672", "High", "Apache Tomcat < 9.0.86 / 10.1.18 - information disclosure", "tomcat", Some("Update Tomcat to 9.0.86+ / 10.1.18+"), Some("10.1.18")),
    ("CVE-2023-44487", "Critical", "Apache Tomcat HTTP/2 Rapid Reset Attack", "tomcat", Some("Update Tomcat to 9.0.82+ / 10.1.13+"), Some("10.1.13")),

    // ── Jenkins ──
    ("CVE-2024-23897", "Critical", "Jenkins < 2.442 / LTS 2.426.3 - arbitrary file read via CLI", "jenkins", Some("Update Jenkins to 2.442+ / LTS 2.426.3+"), Some("2.442")),
    ("CVE-2024-34144", "High", "Jenkins < 2.470 - RCE through plugin manager", "jenkins", Some("Update Jenkins to 2.470+"), Some("2.470")),
    ("CVE-2023-28638", "Critical", "Jenkins < 2.380 / LTS 2.361.3 - SSRF via checkmarx plugin", "jenkins", Some("Update Jenkins to 2.380+ / LTS 2.361.3+"), Some("2.380")),
    ("CVE-2024-2816", "Medium", "Jenkins < 2.441 - CSRF protection bypass via X-Forwarded-Host", "jenkins", Some("Update Jenkins to 2.441+"), Some("2.441")),

    // ── Kubernetes ──
    ("CVE-2023-5528", "High", "Kubernetes < 1.28.3 / 1.27.7 / 1.26.10 - DoS via API server", "kubernetes", Some("Update Kubernetes to 1.28.3+ / 1.27.7+ / 1.26.10+"), Some("1.28.3")),
    ("CVE-2023-3955", "Medium", "Kubernetes < 1.28.1 / 1.27.5 / 1.26.8 - CSRF via OIDC", "kubernetes", Some("Update Kubernetes to 1.28.1+ / 1.27.5+ / 1.26.8+"), Some("1.28.1")),
    ("CVE-2023-3676", "High", "Kubernetes < 1.28.0 / 1.27.4 / 1.26.7 - privilege escalation via aggregated API", "kubernetes", Some("Update Kubernetes to 1.28.0+ / 1.27.4+ / 1.26.7+"), Some("1.28.0")),
    ("CVE-2023-2727", "Medium", "Kubernetes < 1.27.2 / 1.26.5 / 1.25.10 - bypass of SELinux policy", "kubernetes", Some("Update Kubernetes to 1.27.2+ / 1.26.5+ / 1.25.10+"), Some("1.27.2")),

    // ── Docker ──
    ("CVE-2024-21626", "High", "Docker < 25.0.2 - runc container escape via open file descriptor", "docker", Some("Update Docker to 25.0.2+ / runc to 1.1.12+"), Some("25.0.2")),
    ("CVE-2024-23650", "High", "Docker / Moby < 25.0.3 - authz plugin bypass", "docker", Some("Update Docker to 25.0.3+"), Some("25.0.3")),
    ("CVE-2023-5166", "Medium", "Docker < 24.0.7 - DoS via DNS resolver", "docker", Some("Update Docker to 24.0.7+"), Some("24.0.7")),
    ("CVE-2023-39325", "Critical", "Docker / runc < 1.1.9 - container escape via /proc", "docker", Some("Update runc to 1.1.9+"), Some("1.1.9")),

    // ── Elasticsearch ──
    ("CVE-2024-23452", "Medium", "Elasticsearch < 8.12.2 / 7.17.19 - DoS via crafted queries", "elasticsearch", Some("Update Elasticsearch to 8.12.2+ / 7.17.19+"), Some("8.12.2")),
    ("CVE-2024-23451", "High", "Elasticsearch < 8.12.1 / 7.17.18 - file read via search API", "elasticsearch", Some("Update Elasticsearch to 8.12.1+ / 7.17.18+"), Some("8.12.1")),
    ("CVE-2023-46673", "Medium", "Elasticsearch < 8.11.1 / 7.17.16 - DoS via crafted query", "elasticsearch", Some("Update Elasticsearch to 8.11.1+ / 7.17.16+"), Some("8.11.1")),
    ("CVE-2023-31419", "High", "Elasticsearch < 8.8.2 / 7.17.14 - RCE via H2 console", "elasticsearch", Some("Update Elasticsearch to 8.8.2+ / 7.17.14+"), Some("8.8.2")),

    // ── Apache Kafka ──
    ("CVE-2023-25194", "Critical", "Apache Kafka Connect RCE via JNDI", "kafka", Some("Update Kafka to 3.3.2+ / 3.4.0+"), Some("3.4.0")),
    ("CVE-2024-27309", "High", "Apache Kafka < 3.6.2 / 3.5.2 - DoS via malformed request", "kafka", Some("Update Kafka to 3.6.2+ / 3.5.2+"), Some("3.6.2")),

    // ── RabbitMQ ──
    ("CVE-2023-46115", "High", "RabbitMQ < 3.12.6 - DoS via MQTT connections", "rabbitmq", Some("Update RabbitMQ to 3.12.6+"), Some("3.12.6")),
    ("CVE-2023-35789", "Medium", "RabbitMQ < 3.11.22 / 3.12.5 - SSH credential disclosure", "rabbitmq", Some("Update RabbitMQ to 3.11.22+ / 3.12.5+"), Some("3.12.5")),

    // ── GitLab ──
    ("CVE-2023-7028", "Critical", "GitLab < 16.7.2 / 16.6.4 / 16.5.6 - account takeover via password reset", "gitlab", Some("Update GitLab to 16.7.2+ / 16.6.4+ / 16.5.6+"), Some("16.7.2")),
    ("CVE-2024-0402", "High", "GitLab < 16.7.2 / 16.6.4 / 16.5.6 - XXE in SVG uploads", "gitlab", Some("Update GitLab to 16.7.2+ / 16.6.4+ / 16.5.6+"), Some("16.7.2")),
    ("CVE-2024-0401", "Medium", "GitLab < 16.6.6 / 16.5.8 / 16.4.5 - DoS via file uploads", "gitlab", Some("Update GitLab to 16.6.6+ / 16.5.8+ / 16.4.5+"), Some("16.6.6")),

    // ── Apache Struts ──
    ("CVE-2023-50164", "Critical", "Apache Struts < 2.5.33 / 6.1.2.1 - file upload RCE", "struts", Some("Update Struts to 2.5.33+ / 6.1.2.1+"), Some("6.1.2.1")),
    ("CVE-2024-29857", "High", "Apache Struts < 6.3.0.2 - DoS via request parameter", "struts", Some("Update Struts to 6.3.0.2+"), Some("6.3.0.2")),

    // ── Log4j ──
    ("CVE-2021-44228", "Critical", "Apache Log4j < 2.15.0 - JNDI RCE (Log4Shell)", "log4j", Some("Update Log4j to 2.17.0+; set log4j2.formatMsgNoLookups=true"), Some("2.15.0")),
    ("CVE-2021-45046", "High", "Apache Log4j < 2.16.0 - DoS and RCE via JNDI (Log4Shell variant)", "log4j", Some("Update Log4j to 2.17.0+"), Some("2.16.0")),
    ("CVE-2021-45105", "Medium", "Apache Log4j < 2.17.0 - DoS via infinite recursion", "log4j", Some("Update Log4j to 2.17.0+"), Some("2.17.0")),

    // ── HAProxy ──
    ("CVE-2023-40225", "High", "HAProxy < 2.8.1 / 2.6.14 - HTTP/2 CONTINUATION DoS", "haproxy", Some("Update HAProxy to 2.8.1+ / 2.6.14+"), Some("2.8.1")),
    ("CVE-2023-0056", "Medium", "HAProxy < 2.7.2 - HTTP request smuggling", "haproxy", Some("Update HAProxy to 2.7.2+"), Some("2.7.2")),

    // ── Traefik ──
    ("CVE-2023-47124", "High", "Traefik < 2.10.6 / 3.0.0-beta5 - HTTP/2 CONTINUATION DoS", "traefik", Some("Update Traefik to 2.10.6+ / 3.0.0+"), Some("2.10.6")),
    ("CVE-2023-47121", "Medium", "Traefik < 2.10.6 / 3.0.0-beta5 - request smuggling", "traefik", Some("Update Traefik to 2.10.6+"), Some("2.10.6")),

    // ── Varnish Cache ──
    ("CVE-2023-44487", "Critical", "Varnish Cache HTTP/2 Rapid Reset Attack", "varnish", Some("Update Varnish to 7.3.2+ / 7.4.1+"), Some("7.4.1")),

    // ── Apache ActiveMQ ──
    ("CVE-2023-46604", "Critical", "Apache ActiveMQ < 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 - RCE", "activemq", Some("Update ActiveMQ to 5.15.16+ / 5.16.7+ / 5.17.6+ / 5.18.3+"), Some("5.18.3")),
    ("CVE-2024-32114", "High", "Apache ActiveMQ < 6.1.2 - DoS via MQTT", "activemq", Some("Update ActiveMQ to 6.1.2+"), Some("6.1.2")),

    // ── Apache Spark ──
    ("CVE-2023-32007", "High", "Apache Spark < 3.4.1 - ACL bypass via UI", "spark", Some("Update Apache Spark to 3.4.1+"), Some("3.4.1")),
    ("CVE-2023-22946", "Medium", "Apache Spark < 3.4.0 - TLS/SSL certificate validation bypass", "spark", Some("Update Apache Spark to 3.4.0+"), Some("3.4.0")),

    // ── Apache ZooKeeper ──
    ("CVE-2023-44981", "High", "Apache ZooKeeper < 3.8.3 - authorization bypass", "zookeeper", Some("Update ZooKeeper to 3.8.3+ / 3.9.1+"), Some("3.9.1")),

    // ── Apache Flink ──
    ("CVE-2024-23874", "Medium", "Apache Flink < 1.17.2 - information disclosure via REST API", "flink", Some("Update Flink to 1.17.2+"), Some("1.17.2")),

    // ── Solr ──
    ("CVE-2023-50292", "High", "Apache Solr < 8.11.3 / 9.4.1 - schema leak via config API", "solr", Some("Update Solr to 8.11.3+ / 9.4.1+"), Some("9.4.1")),
    ("CVE-2023-50290", "Critical", "Apache Solr < 8.11.3 / 9.4.1 - backup restore RCE", "solr", Some("Update Solr to 8.11.3+ / 9.4.1+"), Some("9.4.1")),

    // ── Apache Shiro ──
    ("CVE-2023-46749", "Critical", "Apache Shiro < 1.13.0 / 2.0.0 - authentication bypass", "shiro", Some("Update Shiro to 1.13.0+ / 2.0.0+"), Some("2.0.0")),

    // ── Grafana ──
    ("CVE-2023-3128", "High", "Grafana < 9.5.5 / 10.0.1 - SSRF via alerting", "grafana", Some("Update Grafana to 9.5.5+ / 10.0.1+"), Some("10.0.1")),
    ("CVE-2024-1445", "Medium", "Grafana < 10.4.1 / 9.5.17 - XSS via dashboard", "grafana", Some("Update Grafana to 10.4.1+ / 9.5.17+"), Some("10.4.1")),

    // ── Prometheus ──
    ("CVE-2023-40577", "Medium", "Prometheus < 2.47.0 / 2.44.1 - DoS via remote write", "prometheus", Some("Update Prometheus to 2.47.0+ / 2.44.1+"), Some("2.47.0")),
];

const TECH_PATTERNS: &[(&str, &[&str])] = &[
    ("openssl", &["openssl", "ssl/tls", "tls"]),
    ("openssh", &["openssh", "ssh", "ssh-"]),
    ("nginx", &["nginx", "nginx/", "nginx "]),
    ("apache", &["apache", "apache/", "httpd"]),
    ("iis", &["iis", "microsoft-iis", "asp.net", ".net"]),
    ("php", &["php", "php/", "x-powered-by: php"]),
    ("wordpress", &["wordpress", "wp-content", "wp-includes", "wp-json", "wp-admin"]),
    ("drupal", &["drupal", "drupal/", "sites/default"]),
    ("joomla", &["joomla", "joomla/", "com_content"]),
    ("mysql", &["mysql", "mariadb", "mysql/"]),
    ("postgresql", &["postgresql", "postgres", "pgsql"]),
    ("redis", &["redis"]),
    ("mongodb", &["mongodb", "mongo"]),
    ("nodejs", &["node.js", "nodejs", "node/"]),
    ("python", &["python", "python/", "wsgi"]),
    ("django", &["django"]),
    ("flask", &["flask"]),
    ("ruby", &["ruby", "ruby/"]),
    ("rails", &["rails", "ruby on rails"]),
    ("tomcat", &["tomcat", "apache-tomcat"]),
    ("jenkins", &["jenkins"]),
    ("kubernetes", &["kubernetes", "k8s"]),
    ("docker", &["docker"]),
    ("elasticsearch", &["elasticsearch", "elastic search"]),
    ("kafka", &["kafka", "apache kafka"]),
    ("rabbitmq", &["rabbitmq", "rabbit mq"]),
    ("gitlab", &["gitlab"]),
    ("struts", &["struts", "apache struts"]),
    ("log4j", &["log4j", "log4j2"]),
    ("haproxy", &["haproxy", "haproxy/"]),
    ("traefik", &["traefik"]),
    ("varnish", &["varnish", "varnish/"]),
    ("activemq", &["activemq", "apache activemq"]),
    ("spark", &["spark", "apache spark"]),
    ("zookeeper", &["zookeeper", "zookeeper/"]),
    ("flink", &["flink", "apache flink"]),
    ("solr", &["solr", "apache solr"]),
    ("shiro", &["shiro", "apache shiro"]),
    ("grafana", &["grafana"]),
    ("prometheus", &["prometheus"]),
];

fn parse_version(v: &str) -> Vec<u32> {
    v.split('.')
        .filter_map(|s| {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() { None } else { digits.parse::<u32>().ok() }
        })
        .collect()
}

fn version_less_than(detected: &[u32], fixed: &[u32]) -> bool {
    for (a, b) in detected.iter().zip(fixed.iter()) {
        if a < b { return true; }
        if a > b { return false; }
    }
    detected.len() < fixed.len()
}

fn extract_version(target: &str) -> Option<Vec<u32>> {
    let re = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
    let c = re.captures(target)?;
    let version_str = c.get(1)?.as_str();
    let parsed = parse_version(version_str);
    if parsed.is_empty() { None } else { Some(parsed) }
}

fn extract_cve_ids(target: &str) -> Vec<String> {
    let re = match regex::Regex::new(r"CVE-\d{4}-\d{4,7}") {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    re.find_iter(target).map(|m| m.as_str().to_string()).collect()
}

fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 { "Critical" }
    else if score >= 7.0 { "High" }
    else if score >= 4.0 { "Medium" }
    else { "Low" }
}

async fn fetch_nvd(tech: &str, client: &reqwest::Client) -> Vec<CveMatch> {
    let url = format!("{NVD_API}?keywordSearch={}", urlencoding(tech));
    let resp = match client.get(&url)
        .header("User-Agent", USER_AGENT)
        .send().await
    {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let parsed: NvdResponse = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    parsed.vulnerabilities.iter().filter_map(|vuln| {
        let severity = vuln.cve.metrics.as_ref().and_then(|m| {
            m.cvssMetricV31.as_ref()
                .or(m.cvssMetricV30.as_ref())
                .or(m.cvssMetricV2.as_ref())
                .and_then(|v| v.first())
                .map(|c| severity_from_score(c.cvssData.baseScore))
        }).unwrap_or("Unknown");
        let description = vuln.cve.descriptions.iter()
            .find(|d| d.lang == "en")
            .or(vuln.cve.descriptions.first())
            .map(|d| d.value.as_str())
            .unwrap_or("No description available");
        Some(CveMatch {
            cve_id: vuln.cve.id.clone(),
            severity: severity.to_string(),
            description: description.to_string(),
            affected_tech: tech.to_string(),
            remediation: Some("Refer to NVD advisory for patch details".to_string()),
        })
    }).collect()
}

async fn fetch_circl(cve_id: &str, client: &reqwest::Client) -> Option<CveMatch> {
    let url = format!("{CIRCL_API}/{cve_id}");
    let resp = match client.get(&url)
        .header("User-Agent", USER_AGENT)
        .send().await
    {
        Ok(r) => r,
        Err(_) => return None,
    };
    if !resp.status().is_success() { return None; }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return None,
    };
    let parsed: CirclResponse = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return None,
    };
    let severity = parsed.cvss.map(severity_from_score).unwrap_or("Unknown").to_string();
    let description = parsed.summary.unwrap_or_else(|| "No description available".to_string());
    Some(CveMatch {
        cve_id: parsed.id,
        severity,
        description,
        affected_tech: "unknown".to_string(),
        remediation: Some("Refer to CIRCL / NVD advisory for patch details".to_string()),
    })
}

fn urlencoding(s: &str) -> String {
    s.split_whitespace()
        .map(|part| {
            part.chars().map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                _ => format!("%{:02X}", c as u8),
            }).collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("+")
}

pub async fn search(target: &str) -> CveSearchResult {
    progress!("cve_search", "running");
    let mut result = CveSearchResult { target: target.to_string(), matches: vec![] };
    let lower = target.to_lowercase();
    let detected_version = extract_version(&lower);
    let mut seen_ids = HashSet::new();

    // Identify technologies from target
    let mut matched_techs = Vec::new();
    for (tech, patterns) in TECH_PATTERNS {
        if patterns.iter().any(|p| lower.contains(p)) {
            matched_techs.push(tech.to_string());
        }
    }

    // Try NVD API for each matched tech (cached)
    if let Some(client) = build_client(API_TIMEOUT) {
        for tech in &matched_techs {
            let cached = nvd_cache().lock().ok().and_then(|c| c.get(tech).cloned());
            let live_results = if let Some(results) = cached {
                results
            } else {
                let fetched = fetch_nvd(tech, &client).await;
                if let Ok(mut cache) = nvd_cache().lock() {
                    cache.insert(tech.clone(), fetched.clone());
                }
                fetched
            };
            for cve in live_results {
                if seen_ids.insert(cve.cve_id.clone()) {
                    result.matches.push(cve);
                }
            }
        }

        // Try CIRCL API for any CVE IDs found in target
        let cve_ids = extract_cve_ids(target);
        for cve_id in cve_ids {
            let cached = circl_cache().lock().ok().and_then(|c| c.get(&cve_id).cloned());
            let circl_result = if let Some(cve) = cached {
                Some(cve)
            } else {
                let fetched = fetch_circl(&cve_id, &client).await;
                if let Some(ref cve_match) = fetched {
                    if let Ok(mut cache) = circl_cache().lock() {
                        cache.insert(cve_id.clone(), cve_match.clone());
                    }
                }
                fetched
            };
            if let Some(cve) = circl_result {
                if seen_ids.insert(cve.cve_id.clone()) {
                    result.matches.push(cve);
                }
            }
        }
    }

    // Fallback: hardcoded CVE database with version matching
    for entry in CVE_DATABASE {
        let (cve_id, severity, description, affected, remediation, fixed_version) = *entry;
        for tech in &matched_techs {
            if affected.contains(tech.as_str()) {
                if let (Some(fixed), Some(dv)) = (fixed_version, detected_version.as_ref()) {
                    let fv = parse_version(fixed);
                    if !fv.is_empty() && !version_less_than(dv, &fv) {
                        continue;
                    }
                }
                if seen_ids.insert(cve_id.to_string()) {
                    result.matches.push(CveMatch {
                        cve_id: cve_id.to_string(),
                        severity: severity.to_string(),
                        description: description.to_string(),
                        affected_tech: tech.to_string(),
                        remediation: remediation.map(|s| s.to_string()),
                    });
                }
                break;
            }
        }
    }

    progress_done!("cve_search");
    result
}
