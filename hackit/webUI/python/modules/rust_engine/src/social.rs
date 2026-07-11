use crate::common::{build_client, PLATFORMS, SocialResult, SocialProfile};
use std::sync::Arc;
use tokio::sync::Semaphore;

const MAX_CONCURRENT: usize = 20;

fn platform_category(platform: &str) -> &'static str {
    match platform {
        "Discord" | "Telegram" | "Signal" | "WhatsApp" | "Snapchat" | "WeChat" | "Line"
        | "Viber" | "Slack" | "Matrix" | "Element" | "Keybase" | "Session" | "Wire"
        | "Threema" | "Google Meet" | "Microsoft Teams" | "Zoom" => "messaging",

        "Facebook" | "Twitter" | "LinkedIn" | "Instagram" | "TikTok" | "Reddit"
        | "Pinterest" | "Tumblr" | "VSCO" | "Flickr" => "social_network",

        "GitHub" | "GitLab" | "GitHub Gist" | "GitLab Snippets" | "StackOverflow"
        | "Replit" | "CodePen" | "JSFiddle" | "CodeSandbox" | "StackBlitz" | "NPM"
        | "PyPI" | "RubyGems" | "Crates.io" | "Docker Hub" | "Homebrew" | "Scoop"
        | "Chocolatey" => "developer",

        "YouTube" | "YouTube Channel" | "Vimeo" | "Twitch" | "Dribbble" | "Behance"
        | "500px" | "SoundCloud" | "Bandcamp" | "Mixcloud" | "Spotify" | "DeviantArt"
        | "ArtStation" | "Furaffinity" | "Imgur" => "media",

        "Medium" | "Dev.to" | "HackerNews" | "Substack" | "Medium Publication"
        | "Blogger" | "WordPress" | "Ghost" | "Wix" | "Squarespace" | "Carrd"
        | "Linktree" | "Bio.link" => "blogging",

        "HackerOne" | "Bugcrowd" | "TryHackMe" | "HackTheBox" | "RootMe"
        | "CTFtime" => "security",

        "AngelList" | "Crunchbase" | "ProductHunt" | "Calendly" | "Zendesk"
        | "Intercom" | "Trello" | "Asana" | "Jira" | "Notion" | "Miro"
        | "Figma" | "Figma Community" => "business",

        "Wikipedia" | "Google Scholar" | "ResearchGate" | "Academia" | "ORCID"
        | "PubMed" | "arXiv" => "academic",

        "Steam" | "Epic Games" | "Xbox" | "PlayStation" | "Nintendo" | "Battle.net"
        | "Riot Games" | "Chess.com" | "Lichess" | "Speedrun.com" => "gaming",

        "Strava" | "Fitbit" | "MyFitnessPal" | "Runkeeper" | "Komoot"
        | "AllTrails" => "fitness",

        "Etsy" | "Shopify" | "Buy Me a Coffee" | "Ko-fi" | "Patreon"
        | "Open Collective" | "GoFundMe" | "Kickstarter" | "Indiegogo" => "funding",

        "IMDb" | "Letterboxd" | "Trakt" | "Goodreads" | "LibraryThing"
        | "MyAnimeList" | "AniList" => "entertainment",

        "Google Play" | "App Store" => "app_store",

        _ => "other",
    }
}

async fn check_platform(
    client: &reqwest::Client,
    semaphore: Arc<Semaphore>,
    platform: String,
    url: String,
) -> Option<SocialProfile> {
    let _permit = semaphore.acquire().await.ok()?;

    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().as_str().to_string();
    let body = resp.text().await.unwrap_or_default();

    let category = platform_category(&platform).to_string();
    let body_lower = body.to_lowercase();

    if body_lower.contains("rate limit")
        || body_lower.contains("rate_limit")
        || body_lower.contains("too many requests")
        || body_lower.contains("try again later")
    {
        return Some(SocialProfile {
            platform,
            url,
            exists: false,
            status: Some(status),
            category,
            rate_limited: true,
        });
    }

    if status >= 300 && status < 400 {
        return None;
    }

    if status == 200 {
        let original_host = url
            .parse::<reqwest::Url>()
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        let final_host = final_url
            .parse::<reqwest::Url>()
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        let different_domain = match (original_host, final_host) {
            (Some(oh), Some(fh)) => oh != fh,
            _ => false,
        };
        if different_domain {
            return None;
        }
        Some(SocialProfile {
            platform,
            url: final_url,
            exists: true,
            status: Some(status),
            category,
            rate_limited: false,
        })
    } else {
        None
    }
}

pub async fn check(username: &str) -> SocialResult {
    let client = match build_client(10) {
        Some(c) => c,
        None => {
            return SocialResult {
                username: username.to_string(),
                profiles: Vec::new(),
            }
        }
    };

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let mut handles = Vec::with_capacity(PLATFORMS.len());

    for (platform, url_template) in PLATFORMS {
        let profile_url = url_template.replace("{}", username);
        let c = client.clone();
        let sem = Arc::clone(&semaphore);
        let p = platform.to_string();

        handles.push(tokio::spawn(async move {
            check_platform(&c, sem, p, profile_url).await
        }));
    }

    let mut profiles = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(Some(p)) = h.await {
            profiles.push(p);
        }
    }

    SocialResult {
        username: username.to_string(),
        profiles,
    }
}
