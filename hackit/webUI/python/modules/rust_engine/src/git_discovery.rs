use crate::common::*;
use crate::{progress, progress_done};

pub async fn discover(url: &str) -> GitDiscoveryResult {
    progress!("git_discovery", "running");
    let url = normalize_url(url);
    let base = url.trim_end_matches('/');
    let mut result = GitDiscoveryResult { url: url.clone(), git_exposed: false, files: vec![], has_config: false, has_head: false };
    let paths = [
        "/.git/HEAD", "/.git/config", "/.git/index", "/.git/refs/heads/master",
        "/.svn/entries", "/.env", "/.env.example",
    ];
    if let Some(client) = build_client(10) {
        for path in &paths {
            let target_url = format!("{}{}", base, path);
            if let Ok(resp) = client.get(&target_url).send().await {
                if resp.status().as_u16() == 200 {
                    result.files.push(path.to_string());
                    if *path == "/.git/HEAD" { result.has_head = true; }
                    if *path == "/.git/config" { result.has_config = true; }
                }
            }
        }
    }
    result.git_exposed = result.has_head || result.has_config;
    progress_done!("git_discovery");
    result
}
