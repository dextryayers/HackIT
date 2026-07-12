use crate::common::{ScanConfig, build_client, WebIntelResult, WebSensitiveFile, WebHeaderInfo};
use std::time::Duration;
use tokio::task;

const SENSITIVE_PATHS: &[(&str, &str, &str)] = &[
    ("/.env", "Environment File", "high"),
    ("/.git/config", "Git Configuration", "high"),
    ("/.git/HEAD", "Git HEAD", "high"),
    ("/robots.txt", "Robots.txt", "info"),
    ("/sitemap.xml", "Sitemap", "info"),
    ("/.htaccess", "Apache Config", "high"),
    ("/web.config", "IIS Config", "high"),
    ("/wp-config.php.bak", "WordPress Config Backup", "critical"),
    ("/.DS_Store", "macOS Directory Store", "medium"),
    ("/Thumbs.db", "Windows Thumbnail Cache", "low"),
    ("/backup.sql", "SQL Backup", "critical"),
    ("/database.sql", "SQL Database", "critical"),
    ("/dump.sql", "SQL Dump", "critical"),
    ("/admin/", "Admin Panel", "medium"),
    ("/administrator/", "Admin Panel", "medium"),
    ("/phpmyadmin/", "phpMyAdmin", "high"),
    ("/admin.php", "Admin Login", "medium"),
    ("/login", "Login Page", "info"),
    ("/debug", "Debug Endpoint", "high"),
    ("/trace", "Trace Endpoint", "high"),
    ("/server-status", "Apache Server Status", "high"),
    ("/server-info", "Apache Server Info", "high"),
    ("/.well-known/security.txt", "Security Contact", "info"),
    ("/favicon.ico", "Favicon", "info"),
    ("/crossdomain.xml", "Cross Domain Policy", "info"),
    ("/clientaccesspolicy.xml", "Silverlight Policy", "info"),
    ("/elmah.axd", "ELMAH Error Log", "critical"),
    ("/trace.axd", "ASP.NET Trace", "high"),
    ("/web.config.bak", "IIS Config Backup", "high"),
    ("/.svn/entries", "SVN Entries", "high"),
    ("/.hg/dirstate", "Mercurial Config", "high"),
    ("/composer.json", "PHP Dependencies", "info"),
    ("/package.json", "Node Dependencies", "info"),
    ("/Gemfile", "Ruby Dependencies", "info"),
    ("/requirements.txt", "Python Dependencies", "info"),
    ("/Cargo.toml", "Rust Dependencies", "info"),
    ("/go.mod", "Go Dependencies", "info"),
    ("/.aws/credentials", "AWS Credentials", "critical"),
    ("/config.json", "Configuration File", "high"),
    ("/config.yml", "Configuration File", "high"),
    ("/config.php", "PHP Configuration", "high"),
    ("/settings.json", "Settings File", "high"),
    ("/.ssh/id_rsa", "SSH Private Key", "critical"),
    ("/.ssh/authorized_keys", "SSH Authorized Keys", "high"),
    ("/api/swagger", "Swagger API Docs", "info"),
    ("/api/docs", "API Documentation", "info"),
    ("/graphql", "GraphQL Endpoint", "info"),
    ("/.well-known/openid-configuration", "OpenID Config", "info"),
];

const INTERESTING_HEADERS: &[(&str, &str)] = &[
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
    ("x-aspnet-version", "ASP.NET Version"),
    ("x-aspnetmvc-version", "MVC Version"),
    ("x-generator", "Generator"),
    ("x-drupal-cache", "Drupal Cache"),
    ("x-shopify-stage", "Shopify"),
    ("x-debug", "Debug"),
    ("x-request-id", "Request ID"),
    ("x-runtime", "Runtime"),
    ("x-version", "Version"),
    ("x-build", "Build"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> WebIntelResult {
    let client = build_client(15).unwrap_or_default();
    let domain = target.trim().to_string();
    let timeout = Duration::from_secs(8);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(30));
    let mut handles = Vec::new();

    for &(path, name, severity) in SENSITIVE_PATHS {
        let url = format!("https://{}{}", domain, path);
        let client = client.clone();
        let sem = sem.clone();
        let path = path.to_string();
        let name = name.to_string();
        let severity = severity.to_string();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let status = resp.status().as_u16();
            if status == 200 || status == 301 || status == 302 || status == 403 {
                let body = resp.text().await.unwrap_or_default();
                let size = body.len();
                let snippet = body.chars().take(200).collect();
                Some(WebSensitiveFile {
                    path,
                    name,
                    status,
                    severity,
                    size,
                    snippet,
                })
            } else {
                None
            }
        }));
    }

    let mut sensitive_files = Vec::new();
    for h in handles {
        if let Ok(Some(f)) = h.await {
            sensitive_files.push(f);
        }
    }

    let headers = check_headers(&client, &domain).await;

    let technologies = detect_technologies(&headers, &sensitive_files);

    WebIntelResult {
        domain,
        sensitive_files,
        headers,
        technologies,
    }
}

async fn check_headers(client: &reqwest::Client, domain: &str) -> Vec<WebHeaderInfo> {
    let url = format!("https://{}", domain);
    let mut results = Vec::new();

    if let Ok(Ok(resp)) = tokio::time::timeout(Duration::from_secs(8), client.get(&url).send()).await {
        for (key, value) in resp.headers() {
            let key_lower = key.as_str().to_lowercase();
            for &(header, label) in INTERESTING_HEADERS {
                if key_lower == header {
                    if let Ok(v) = value.to_str() {
                        results.push(WebHeaderInfo {
                            name: label.to_string(),
                            value: v.to_string(),
                        });
                    }
                }
            }
        }
    }
    results
}

fn detect_technologies(headers: &[WebHeaderInfo], files: &[WebSensitiveFile]) -> Vec<String> {
    let mut techs = Vec::new();
    let all = format!("{} {}", 
        headers.iter().map(|h| format!("{}: {}", h.name, h.value)).collect::<Vec<_>>().join(" "),
        files.iter().map(|f| f.path.clone()).collect::<Vec<_>>().join(" ")
    );
    let lower = all.to_lowercase();

    let tech_patterns = vec![
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("cloudflare", "Cloudflare"),
        ("iis", "IIS"),
        ("php", "PHP"),
        ("asp.net", "ASP.NET"),
        ("express", "Express.js"),
        ("node", "Node.js"),
        ("python", "Python"),
        ("ruby", "Ruby"),
        ("java", "Java"),
        ("tomcat", "Tomcat"),
        ("jetty", "Jetty"),
        ("lighttpd", "Lighttpd"),
        ("caddy", "Caddy"),
        ("openresty", "OpenResty"),
        ("gunicorn", "Gunicorn"),
        ("uvicorn", "Uvicorn"),
        ("drupal", "Drupal"),
        ("wordpress", "WordPress"),
        ("joomla", "Joomla"),
        ("magento", "Magento"),
        ("shopify", "Shopify"),
        ("laravel", "Laravel"),
        ("django", "Django"),
        ("rails", "Rails"),
        ("flask", "Flask"),
        ("spring", "Spring"),
        ("graphql", "GraphQL"),
        ("swagger", "Swagger"),
        ("phpmyadmin", "phpMyAdmin"),
    ];

    for (pattern, tech) in tech_patterns {
        if lower.contains(pattern) {
            techs.push(tech.to_string());
        }
    }
    techs
}
