use crate::common::*;
use crate::{progress, progress_done};

pub async fn enumerate(url: &str) -> DirEnumResult {
    progress!("dir_enum", "running");
    let url = normalize_url(url);
    let base = url.trim_end_matches('/');
    let mut result = DirEnumResult { url: url.clone(), directories: vec![] };
    if let Some(client) = build_client(8) {
        let extra_paths = ["/admin", "/wp-admin", "/administrator", "/backup", "/config", "/.git", "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/phpinfo.php", "/info.php", "/.env", "/Dockerfile", "/docker-compose.yml", "/package.json", "/composer.json", "/Gemfile", "/Procfile", "/.htaccess", "/web.config", "/README.md", "/CHANGELOG.md", "/VERSION", "/status", "/health", "/metrics", "/debug", "/test", "/dev", "/staging", "/api", "/v1", "/v2", "/swagger.json", "/api-docs", "/graphql", "/console", "/manage", "/management", "/panel", "/cpanel", "/whm", "/pma", "/phpmyadmin", "/phpMyAdmin", "/mysql", "/adminer.php"];
        let all_paths: Vec<&str> = COMMON_PREFIXES.iter().chain(extra_paths.iter()).take(100).map(|s| *s).collect();
        let total = all_paths.len() as u64;
        for (i, path) in all_paths.iter().enumerate() {
            if i % 10 == 0 {
                println!("{}", serde_json::to_string(&ProgressEvent::with_progress("dir_enum", "scanning", i as u64, total)).unwrap());
            }
            let target_url = format!("{}/{}", base, path.trim_start_matches('/'));
            if let Ok(resp) = client.head(&target_url).send().await {
                let status = resp.status().as_u16();
                if status == 200 || status == 301 || status == 302 || status == 403 || status == 401 {
                    let size = resp.content_length();
                    result.directories.push(DirEntry {
                        path: format!("/{}", path.trim_start_matches('/')),
                        status,
                        size,
                    });
                }
            }
        }
    }
    progress_done!("dir_enum");
    result
}
