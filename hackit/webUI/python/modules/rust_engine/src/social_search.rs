use crate::common::*;
use crate::{progress, progress_done};

pub async fn search(username: &str) -> SocialSearchResult {
    progress!("social_search", "running");
    let mut result = SocialSearchResult { username: username.into(), profiles: vec![] };

    if let Some(client) = build_client(5) {
        for (platform, url_tmpl) in PLATFORMS.iter().take(50) {
            let url = url_tmpl.replace("{}", username);
            match client.get(&url).send().await {
                Ok(resp) => {
                    if resp.status().as_u16() == 200 {
                        result.profiles.push(SocialProfileInfo {
                            platform: platform.to_string(),
                            url,
                            exists: true,
                        });
                    }
                }
                Err(_) => {}
            }
        }
    }

    progress_done!("social_search");
    result
}
