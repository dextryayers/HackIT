use crate::common::{PLATFORMS, SocialResult, SocialProfile, build_client};

pub async fn check(username: &str) -> SocialResult {
    let mut profiles = Vec::new();
    let client = match build_client(5) { Some(c) => c, None => return SocialResult { username: username.to_string(), profiles } };
    let mut handles = Vec::new();
    for (platform, url_template) in PLATFORMS {
        let profile_url = url_template.replace("{}", username);
        let c = client.clone();
        let p = platform.to_string();
        handles.push(tokio::spawn(async move {
            if let Ok(resp) = c.get(&profile_url).send().await {
                let status = resp.status().as_u16();
                if status == 200 { return Some(SocialProfile { platform: p.clone(), url: profile_url, exists: true, status: Some(status) }); }
            }
            None
        }));
    }
    for h in handles { if let Ok(Some(s)) = h.await { profiles.push(s); } }
    SocialResult { username: username.to_string(), profiles }
}
