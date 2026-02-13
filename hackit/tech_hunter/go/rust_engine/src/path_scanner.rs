use serde::{Serialize, Deserialize};
use reqwest::Client;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PathDiscovery {
    pub path: String,
    pub status: u16,
    pub content_length: u64,
    pub title: String,
    pub risk: String, // Low, Medium, High
}

pub async fn scan_sensitive_paths(base_url: &str) -> Vec<PathDiscovery> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    let paths = vec![
        (".env", "High"),
        (".git/config", "High"),
        (".svn/entries", "Medium"),
        ("phpinfo.php", "Medium"),
        ("info.php", "Medium"),
        ("config.php.bak", "High"),
        ("web.config", "Medium"),
        ("robots.txt", "Low"),
        ("sitemap.xml", "Low"),
        (".htaccess", "Medium"),
        (".ssh/id_rsa", "High"),
        ("backup.sql", "High"),
        ("dump.sql", "High"),
        ("db.sql", "High"),
        ("wp-config.php.bak", "High"),
        ("admin/", "Low"),
        ("login/", "Low"),
        (".well-known/security.txt", "Low"),
    ];

    let mut discoveries = Vec::new();
    let base = base_url.trim_end_matches('/');

    for (path, risk) in paths {
        let url = format!("{}/{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 403 {
                let content_length = resp.content_length().unwrap_or(0);
                let body = resp.text().await.unwrap_or_default();
                
                let mut title = String::new();
                if let Some(start) = body.find("<title>") {
                    if let Some(end) = body[start..].find("</title>") {
                        title = body[start + 7..start + end].trim().to_string();
                    }
                }

                discoveries.push(PathDiscovery {
                    path: path.to_string(),
                    status,
                    content_length,
                    title,
                    risk: risk.to_string(),
                });
            }
        }
    }

    discoveries
}
