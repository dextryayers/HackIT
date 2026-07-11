use crate::common::{build_client, PLATFORMS, SocialSearchResult, SocialProfileInfo};
use crate::{progress, progress_done};

const LITE_LIMIT: usize = 50;

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

pub async fn search(username: &str) -> SocialSearchResult {
    progress!("social_search", "running");

    let client = match build_client(10) {
        Some(c) => c,
        None => {
            progress_done!("social_search");
            return SocialSearchResult {
                username: username.into(),
                profiles: vec![],
            };
        }
    };

    let mut result = SocialSearchResult {
        username: username.into(),
        profiles: vec![],
    };

    for (platform, url_tmpl) in PLATFORMS.iter().take(LITE_LIMIT) {
        let url = url_tmpl.replace("{}", username);
        let category = platform_category(platform).to_string();

        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();

                if body_lower.contains("rate limit")
                    || body_lower.contains("rate_limit")
                    || body_lower.contains("too many requests")
                    || body_lower.contains("try again later")
                {
                    continue;
                }

                if status >= 300 && status < 400 {
                    continue;
                }

                if status == 200 {
                    result.profiles.push(SocialProfileInfo {
                        platform: platform.to_string(),
                        url,
                        exists: true,
                        category,
                    });
                }
            }
            Err(_) => {}
        }
    }

    progress_done!("social_search");
    result
}
