use crate::common::{ScanConfig, build_client};
use crate::common::SocialMediaCheckResult;
use std::time::Duration;
use tokio::task;

const PLATFORMS: &[(&str, &str, &str)] = &[
    ("Twitter/X", "https://x.com/{u}", "social"),
    ("Instagram", "https://www.instagram.com/{u}/", "social"),
    ("Facebook", "https://www.facebook.com/{u}", "social"),
    ("TikTok", "https://www.tiktok.com/@{u}", "social"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "social"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "professional"),
    ("GitHub", "https://github.com/{u}", "dev"),
    ("GitLab", "https://gitlab.com/{u}", "dev"),
    ("Bitbucket", "https://bitbucket.org/{u}", "dev"),
    ("Reddit", "https://www.reddit.com/user/{u}/", "social"),
    ("YouTube", "https://www.youtube.com/@{u}", "video"),
    ("Twitch", "https://www.twitch.tv/{u}", "gaming"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "social"),
    ("Tumblr", "https://{u}.tumblr.com", "blogging"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "photo"),
    ("Medium", "https://medium.com/@{u}", "blogging"),
    ("DevTo", "https://dev.to/{u}", "dev"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "dev"),
    ("ProductHunt", "https://www.producthunt.com/@{u}", "product"),
    ("Keybase", "https://keybase.io/{u}", "security"),
    ("Gravatar", "https://en.gravatar.com/{u}", "identity"),
    ("About.me", "https://about.me/{u}", "identity"),
    ("Linktree", "https://linktr.ee/{u}", "link-in-bio"),
    ("Bitwarden", "https://bitwarden.com/{u}", "security"),
    ("npm", "https://www.npmjs.com/~{u}", "dev"),
    ("PyPI", "https://pypi.org/user/{u}/", "dev"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "dev"),
    ("Spotify", "https://open.spotify.com/user/{u}", "music"),
    ("SoundCloud", "https://soundcloud.com/{u}", "music"),
    ("ReverbNation", "https://www.reverbnation.com/{u}", "music"),
    ("Behance", "https://www.behance.net/{u}", "creative"),
    ("Dribbble", "https://dribbble.com/{u}", "creative"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "creative"),
    ("Fiverr", "https://www.fiverr.com/{u}", "freelance"),
    ("Upwork", "https://www.upwork.com/freelancers/{u}", "freelance"),
    ("Patreon", "https://www.patreon.com/{u}", "supporter"),
    ("Substack", "https://{u}.substack.com", "blogging"),
    ("Letterboxd", "https://letterboxd.com/{u}", "movie"),
    ("Goodreads", "https://www.goodreads.com/{u}", "book"),
    ("Steam", "https://steamcommunity.com/id/{u}", "gaming"),
    ("Xbox", "https://www.xbox.com/en-US/play/user/{u}", "gaming"),
    ("PSNProfiles", "https://psnprofiles.com/{u}", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{u}", "gaming"),
    ("Duolingo", "https://www.duolingo.com/profile/{u}", "education"),
    ("Kaggle", "https://www.kaggle.com/{u}", "data"),
    ("CodePen", "https://codepen.io/{u}", "dev"),
    ("LeetCode", "https://leetcode.com/{u}/", "dev"),
    ("HackerRank", "https://www.hackerrank.com/{u}", "dev"),
    ("Replit", "https://replit.com/@{u}", "dev"),
    ("Gratipay", "https://gratipay.com/~{u}", "supporter"),
    ("CashApp", "https://cash.app/${u}", "finance"),
    ("BuyMeACoffee", "https://buymeacoffee.com/{u}", "supporter"),
    ("Ko-fi", "https://ko-fi.com/{u}", "supporter"),
];

pub async fn scan(target: &str, _config: &ScanConfig) -> Vec<SocialMediaCheckResult> {
    let client = build_client(15).unwrap_or_default();
    let username = target.trim().trim_start_matches('@').to_string();
    let timeout = Duration::from_secs(8);
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(30));
    let mut handles = Vec::new();

    for &(name, url_tpl, category) in PLATFORMS {
        let url = url_tpl.replace("{u}", &username);
        let client = client.clone();
        let sem = sem.clone();
        let username = username.clone();
        handles.push(task::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let resp = client.get(&url).timeout(timeout).send().await.ok()?;
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let is_match = match status {
                200..=299 => {
                    let lower = final_url.to_lowercase();
                    let lower_body = resp.text().await.unwrap_or_default().to_lowercase();
                    !(lower.contains("/login") || lower.contains("/signup")
                        || lower.contains("not-found") || lower.contains("page-not-found")
                        || lower_body.contains("page you were looking for")
                        || lower_body.contains("this page isn't available")
                        || lower_body.contains("sorry, this page"))
                }
                301 | 302 | 303 | 307 | 308 => {
                    let lower = final_url.to_lowercase();
                    !lower.contains("login") && !lower.contains("signup")
                }
                _ => false,
            };
            Some(SocialMediaCheckResult {
                platform: name.to_string(),
                url,
                username: username.clone(),
                exists: is_match,
                status,
                category: category.to_string(),
                http_status: status,
                final_url,
            })
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(Some(r)) = h.await {
            results.push(r);
        }
    }
    results
}
