use std::env;
use std::fs;

use std::time::{Duration, Instant};
use regex::Regex;
use serde::{Deserialize, Serialize};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, ACCEPT, ACCEPT_LANGUAGE};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Site {
    name: String,
    url: String,
    category: String,
    #[serde(default = "default_method")]
    method: String,
    hit_code: Option<u16>,
    hit_body: Option<String>,
    #[serde(default)]
    miss_body: Vec<String>,
    #[serde(default)]
    miss_code: Vec<u16>,
    title_check: Option<String>,
    json_path: Option<String>,
    json_hit: Option<String>,
}

fn default_method() -> String { "status_code".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    platform: String,
    category: String,
    url: String,
    status: String,
    http_status: u16,
    title: String,
    description: String,
    confidence: u8,
    note: String,
    response_time: f64,
}

fn load_sites() -> Vec<Site> {
    // Try loading from embedded JSON, then fall back to built-in
    let paths = vec![
        "sites.json",
        "../sites.json",
        "/home/aniipid/HackIT/hackit/osint/sites.json",
        "/home/aniipid/HackIT/hackit/osint/go/sites.json",
    ];
    for p in &paths {
        if let Ok(data) = fs::read_to_string(p) {
            if let Ok(sites) = serde_json::from_str::<Vec<Site>>(&data) {
                eprintln!("[osint] Loaded {} sites from {}", sites.len(), p);
                return sites;
            }
        }
    }
    eprintln!("[osint] No sites.json found, using built-in sites");
    builtin_sites()
}

fn builtin_sites() -> Vec<Site> {
    let mut sites = Vec::new();

    // ===== SOCIAL MEDIA =====
    sites.push(site("Twitter / X", "https://twitter.com/{username}", "Social", "status_code", Some(200), None,
        vec!["this account doesn't exist", "page doesn't exist"], vec![404], None));
    sites.push(site("Instagram", "https://www.instagram.com/{username}/", "Social", "status_code", Some(200), None,
        vec!["page isn't available", "this page isn't available"], vec![404], None));
    sites.push(site("Facebook", "https://www.facebook.com/{username}", "Social", "status_code", Some(200), None,
        vec!["this content isn't available", "page not found"], vec![404], None));
    sites.push(site("TikTok", "https://www.tiktok.com/@{username}", "Social", "title", None, None,
        vec!["couldn't find this account"], vec![404], Some("(@{username})")));
    sites.push(site("Reddit", "https://www.reddit.com/user/{username}/", "Social", "title", None, None,
        vec!["page not found", "sorry, nobody on reddit"], vec![404], Some("{username}")));
    sites.push(site("LinkedIn", "https://www.linkedin.com/in/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("YouTube", "https://www.youtube.com/@{username}", "Social", "status_code", Some(200), None,
        vec!["this channel doesn't exist", "not found"], vec![404], None));
    sites.push(site("Pinterest", "https://www.pinterest.com/{username}/", "Social", "status_code", Some(200), None,
        vec!["doesn't exist", "page not found"], vec![404], None));
    sites.push(site("Tumblr", "https://{username}.tumblr.com", "Social", "status_code", Some(200), None,
        vec!["there's nothing here", "page not found"], vec![404], None));
    sites.push(site("Snapchat", "https://www.snapchat.com/add/{username}", "Social", "status_code", Some(200), None,
        vec!["couldn't find", "page not found"], vec![404], None));
    sites.push(site("Telegram", "https://t.me/{username}", "Social", "body_text", None, Some("{username}"),
        vec!["if you have telegram", "sorry, this page"], vec![404], None));
    sites.push(site("Discord", "https://discord.com/users/{username}", "Social", "status_code", Some(200), None,
        vec!["not found", "doesn't exist"], vec![404], None));
    sites.push(site("Medium", "https://medium.com/@{username}", "Blogging", "status_code", Some(200), None,
        vec!["page not found", "not found"], vec![404], None));
    sites.push(site("Threads", "https://www.threads.net/@{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bluesky", "https://bsky.app/profile/{username}", "Social", "status_code", Some(200), None,
        vec!["profile not found", "does not exist"], vec![404], None));
    sites.push(site("Mastodon.social", "https://mastodon.social/@{username}", "Social", "status_code", Some(200), None,
        vec!["page not found", "doesn't exist"], vec![404], None));
    sites.push(site("VK", "https://vk.com/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found", "user not found"], vec![404], None));
    sites.push(site("OK.ru", "https://ok.ru/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Weibo", "https://weibo.com/u/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found", "user doesn't exist"], vec![404], None));
    sites.push(site("Vero", "https://vero.co/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Parler", "https://parler.com/profile/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found", "user not found"], vec![404], None));
    sites.push(site("Gab", "https://gab.com/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Gettr", "https://gettr.com/user/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("MeWe", "https://mewe.com/i/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Minds", "https://www.minds.com/{username}/", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Steemit", "https://steemit.com/@{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Badoo", "https://badoo.com/en/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Taringa", "https://www.taringa.net/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Ello", "https://ello.co/{username}", "Social", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== DEVELOPER =====
    sites.push(site("GitHub", "https://github.com/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found", "not found"], vec![404], None));
    sites.push(site("GitLab", "https://gitlab.com/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bitbucket", "https://bitbucket.org/{username}/", "Developer", "status_code", Some(200), None,
        vec!["page not found", "could not be found"], vec![404], None));
    sites.push(site("Stack Overflow", "https://stackoverflow.com/users/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Keybase", "https://keybase.io/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Replit", "https://replit.com/@{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("CodePen", "https://codepen.io/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("npm", "https://www.npmjs.com/~{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("PyPI", "https://pypi.org/user/{username}/", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Docker Hub", "https://hub.docker.com/u/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found", "not found"], vec![404], None));
    sites.push(site("Hugging Face", "https://huggingface.co/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("LeetCode", "https://leetcode.com/u/{username}/", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Kaggle", "https://www.kaggle.com/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Dev.to", "https://dev.to/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Hashnode", "https://hashnode.com/@{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Product Hunt", "https://www.producthunt.com/@{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Codeforces", "https://codeforces.com/profile/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found", "not found"], vec![404], None));
    sites.push(site("HackerRank", "https://www.hackerrank.com/profile/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("CodeChef", "https://www.codechef.com/users/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Codewars", "https://www.codewars.com/users/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("GitHub Gist", "https://gist.github.com/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Pastebin", "https://pastebin.com/u/{username}", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("SourceForge", "https://sourceforge.net/u/{username}/", "Developer", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== SECURITY =====
    sites.push(site("HackerOne", "https://hackerone.com/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bugcrowd", "https://bugcrowd.com/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("TryHackMe", "https://tryhackme.com/p/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Hack The Box", "https://app.hackthebox.com/profile/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Root Me", "https://www.root-me.org/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("CTFtime", "https://ctftime.org/user/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Intigriti", "https://app.intigriti.com/profile/{username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Exploit-DB", "https://www.exploit-db.com/author/?a={username}", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("OpenBugBounty", "https://www.openbugbounty.org/researchers/{username}/", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("PacketStorm", "https://packetstormsecurity.com/user/{username}/", "Security", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== FORUMS & BLOGGING =====
    sites.push(site("Quora", "https://www.quora.com/profile/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Hacker News", "https://news.ycombinator.com/user?id={username}", "Forums", "status_code", Some(200), None,
        vec!["no such user", "user not found"], vec![404], None));
    sites.push(site("Lobsters", "https://lobste.rs/u/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Slashdot", "https://slashdot.org/~{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Substack", "https://substack.com/@{username}", "Blogging", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("WordPress.com", "https://{username}.wordpress.com", "Blogging", "status_code", Some(200), None,
        vec!["page not found", "doesn't exist"], vec![404], None));
    sites.push(site("Blogger", "https://{username}.blogspot.com", "Blogging", "status_code", Some(200), None,
        vec!["page not found", "not found"], vec![404], None));
    sites.push(site("Speaker Deck", "https://speakerdeck.com/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Issuu", "https://issuu.com/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("SlideShare", "https://www.slideshare.net/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Disqus", "https://disqus.com/by/{username}/", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Scribd", "https://www.scribd.com/user/{username}", "Forums", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Notion", "https://{username}.notion.site", "Productivity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== GAMING =====
    sites.push(site("Steam", "https://steamcommunity.com/id/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found", "the specified profile could not be found"], vec![404], None));
    sites.push(site("Twitch", "https://www.twitch.tv/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found", "doesn't exist"], vec![404], None));
    sites.push(site("Roblox", "https://www.roblox.com/user.aspx?username={username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Chess.com", "https://www.chess.com/member/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found", "doesn't exist"], vec![404], None));
    sites.push(site("Lichess", "https://lichess.org/@/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found", "user not found"], vec![404], None));
    sites.push(site("Epic Games", "https://www.epicgames.com/id/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("MyAnimeList", "https://myanimelist.net/profile/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("AniList", "https://anilist.co/user/{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Itch.io", "https://{username}.itch.io", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Nexus Mods", "https://next.nexusmods.com/profile/{username}/", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Newgrounds", "https://{username}.newgrounds.com", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Game Jolt", "https://gamejolt.com/@{username}", "Gaming", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== CREATIVE =====
    sites.push(site("DeviantArt", "https://www.deviantart.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found", "doesn't exist"], vec![404], None));
    sites.push(site("ArtStation", "https://www.artstation.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Behance", "https://www.behance.net/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Dribbble", "https://dribbble.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Flickr", "https://www.flickr.com/people/{username}/", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("500px", "https://500px.com/p/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Unsplash", "https://unsplash.com/@{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Imgur", "https://imgur.com/user/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("VSCO", "https://vsco.co/{username}/gallery", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bandcamp", "https://bandcamp.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("SoundCloud", "https://soundcloud.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Spotify", "https://open.spotify.com/user/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Mixcloud", "https://www.mixcloud.com/{username}/", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Dailymotion", "https://www.dailymotion.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Vimeo", "https://vimeo.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Genius", "https://genius.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Discogs", "https://www.discogs.com/user/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Sketchfab", "https://sketchfab.com/{username}", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Thingiverse", "https://www.thingiverse.com/{username}/designs", "Creative", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== PROFESSIONAL =====
    sites.push(site("Upwork", "https://www.upwork.com/freelancers/~{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Fiverr", "https://www.fiverr.com/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Freelancer", "https://www.freelancer.com/u/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("AngelList", "https://angel.co/u/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("ResearchGate", "https://www.researchgate.net/profile/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Academia.edu", "https://independent.academia.edu/{username}", "Professional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Coursera", "https://www.coursera.org/user/{username}", "Education", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Udemy", "https://www.udemy.com/user/{username}/", "Education", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Skillshare", "https://www.skillshare.com/en/profile/{username}", "Education", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Duolingo", "https://www.duolingo.com/profile/{username}", "Education", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Codecademy", "https://www.codecademy.com/profiles/{username}", "Education", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Trello", "https://trello.com/u/{username}", "Productivity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Calendly", "https://calendly.com/{username}", "Productivity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== IDENTITY / LINK-IN-BIO =====
    sites.push(site("About.me", "https://about.me/{username}", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Linktree", "https://linktr.ee/{username}", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Carrd", "https://{username}.carrd.co", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Beacons", "https://beacons.ai/{username}", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bento.me", "https://bento.me/{username}", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Solo.to", "https://solo.to/{username}", "Identity", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== REGIONAL =====
    sites.push(site("Zhihu", "https://www.zhihu.com/people/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Bilibili", "https://space.bilibili.com/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Naver", "https://blog.naver.com/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("LiveJournal", "https://{username}.livejournal.com", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Douban", "https://www.douban.com/people/{username}/", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Pixiv", "https://www.pixiv.net/en/users/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Hatena Blog", "https://{username}.hatenablog.com", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Note.com", "https://note.com/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("TwitCasting", "https://twitcasting.tv/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Yandex Zen", "https://zen.yandex.ru/{username}", "Regional", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== CREATOR / SHOPPING =====
    sites.push(site("Patreon", "https://www.patreon.com/{username}", "Creator", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Ko-fi", "https://ko-fi.com/{username}", "Creator", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Buy Me a Coffee", "https://www.buymeacoffee.com/{username}", "Creator", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("OnlyFans", "https://onlyfans.com/{username}", "Creator", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("OpenSea", "https://opensea.io/{username}", "Crypto", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Etsy", "https://www.etsy.com/shop/{username}", "Shopping", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("eBay", "https://www.ebay.com/usr/{username}", "Shopping", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("TripAdvisor", "https://www.tripadvisor.com/members/{username}", "Travel", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Strava", "https://www.strava.com/athletes/{username}", "Fitness", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Goodreads", "https://www.goodreads.com/{username}", "Books", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));
    sites.push(site("Letterboxd", "https://letterboxd.com/{username}/", "Entertainment", "status_code", Some(200), None,
        vec!["page not found"], vec![404], None));

    // ===== ARCHIVE/LEGACY =====
    sites.push(site("Twitter Archive", "https://web.archive.org/web/*/https://twitter.com/{username}", "Social", "status_code", Some(200), None,
        vec!["not archived"], vec![404], None));
    sites.push(site("GitHub Archive", "https://web.archive.org/web/*/https://github.com/{username}", "Developer", "status_code", Some(200), None,
        vec!["not archived"], vec![404], None));
    sites.push(site("Reddit Archive", "https://web.archive.org/web/*/https://reddit.com/user/{username}", "Social", "status_code", Some(200), None,
        vec!["not archived"], vec![404], None));
    sites.push(site("LinkedIn Archive", "https://web.archive.org/web/*/https://www.linkedin.com/in/{username}", "Professional", "status_code", Some(200), None,
        vec!["not archived"], vec![404], None));

    sites
}

fn site(name: &str, url: &str, cat: &str, method: &str, hit_code: Option<u16>, hit_body: Option<&str>,
        miss_body: Vec<&str>, miss_code: Vec<u16>, title_check: Option<&str>) -> Site {
    Site {
        name: name.to_string(),
        url: url.to_string(),
        category: cat.to_string(),
        method: method.to_string(),
        hit_code,
        hit_body: hit_body.map(|s| s.to_string()),
        miss_body: miss_body.into_iter().map(|s| s.to_string()).collect(),
        miss_code,
        title_check: title_check.map(|s| s.to_string()),
        json_path: None,
        json_hit: None,
    }
}

struct Detection {
    status: String,
    title: String,
    description: String,
    confidence: u8,
}

fn detect(site: &Site, http_status: u16, body: &str, headers: &HeaderMap) -> Detection {
    let body_lower = body.to_lowercase();
    let missing = &site.miss_body;

    if site.miss_code.contains(&http_status) {
        return Detection { status: "miss".into(), title: String::new(), description: "Not found (status code)".into(), confidence: 95 };
    }

    for m in missing {
        if body_lower.contains(&m.to_lowercase()) {
            return Detection { status: "miss".into(), title: String::new(), description: format!("Not found (body: {})", m), confidence: 90 };
        }
    }

    if http_status >= 300 && http_status < 400 {
        let redirect_url = headers.get("location").and_then(|v| v.to_str().ok()).unwrap_or("");
        if redirect_url.contains("login") || redirect_url.contains("signin") || redirect_url.contains("auth") {
            return Detection { status: "miss".into(), title: String::new(), description: format!("Redirected to login"), confidence: 85 };
        }
        if redirect_url.contains("search") || redirect_url.contains("404") {
            return Detection { status: "miss".into(), title: String::new(), description: format!("Redirected to 404"), confidence: 90 };
        }
        return Detection { status: "possible".into(), title: String::new(), description: format!("Redirect: {}", &redirect_url[..redirect_url.len().min(60)]), confidence: 60 };
    }

    if http_status == 401 || http_status == 403 {
        return Detection { status: "unknown".into(), title: String::new(), description: "Blocked or private profile".into(), confidence: 50 };
    }
    if http_status == 429 {
        return Detection { status: "unknown".into(), title: String::new(), description: "Rate limited".into(), confidence: 30 };
    }

    match site.method.as_str() {
        "status_code" => {
            if let Some(c) = site.hit_code {
                if http_status == c {
                    return Detection { status: "hit".into(), title: extract_title(body), description: "Profile found".into(), confidence: 95 };
                }
            }
            if http_status == 200 {
                return Detection { status: "hit".into(), title: extract_title(body), description: "Profile found".into(), confidence: 80 };
            }
        }
        "body_text" => {
            if let Some(hit) = &site.hit_body {
                if body_lower.contains(&hit.to_lowercase()) {
                    return Detection { status: "hit".into(), title: extract_title(body), description: "Hit text found".into(), confidence: 95 };
                }
            }
            if http_status == 200 {
                return Detection { status: "possible".into(), title: extract_title(body), description: "200 OK".into(), confidence: 50 };
            }
        }
        "title" => {
            let title = extract_title(body);
            if let Some(check) = &site.title_check {
                if title.to_lowercase().contains(&check.to_lowercase()) {
                    return Detection { status: "hit".into(), title, description: "Title matched".into(), confidence: 90 };
                }
            }
            if !title.is_empty() && http_status == 200 {
                return Detection { status: "possible".into(), title, description: "Title found".into(), confidence: 40 };
            }
        }
        _ => {}
    }

    if http_status == 200 {
        let title = extract_title(body);
        if !title.is_empty() {
            Detection { status: "hit".into(), title, description: "Profile found".into(), confidence: 75 }
        } else {
            Detection { status: "possible".into(), title: String::new(), description: "200 OK, no title".into(), confidence: 40 }
        }
    } else if http_status == 0 {
        Detection { status: "unknown".into(), title: String::new(), description: "Connection failed".into(), confidence: 0 }
    } else {
        Detection { status: "unknown".into(), title: String::new(), description: format!("Status: {}", http_status), confidence: 10 }
    }
}

fn extract_title(body: &str) -> String {
    let re = Regex::new(r"(?i)<title[^>]*>(.*?)</title>").unwrap();
    re.captures(body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default()
}

fn build_client(proxy: &Option<String>, timeout: u64) -> Result<Client, String> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip, deflate, br"));
    headers.insert("DNT", HeaderValue::from_static("1"));
    headers.insert("Connection", HeaderValue::from_static("keep-alive"));
    headers.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));

    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .danger_accept_invalid_certs(true)
        .default_headers(headers)
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .tcp_keepalive(Duration::from_secs(30));

    if let Some(p) = proxy {
        let proxy_url = if p.starts_with("socks5") || p.starts_with("http") { p.clone() } else { format!("http://{}", p) };
        match reqwest::Proxy::all(&proxy_url) {
            Ok(pr) => { builder = builder.proxy(pr); }
            Err(e) => return Err(format!("Invalid proxy {}: {}", proxy_url, e)),
        }
    }

    builder.build().map_err(|e| e.to_string())
}

fn check_site(site: &Site, username: &str, client: &Client, retries: u8) -> CheckResult {
    let url_str = site.url.replace("{username}", username);
    let mut result = CheckResult {
        platform: site.name.clone(),
        category: site.category.clone(),
        url: url_str.clone(),
        status: "unknown".into(),
        http_status: 0,
        title: String::new(),
        description: String::new(),
        confidence: 0,
        note: String::new(),
        response_time: 0.0,
    };

    for attempt in 0..=retries {
        let start = Instant::now();
        match client.get(&url_str).send() {
            Ok(resp) => {
                let http_status = resp.status().as_u16();
                let elapsed = start.elapsed().as_secs_f64();
                let headers = resp.headers().clone();
                let body = resp.text().unwrap_or_default();
                let det = detect(site, http_status, &body, &headers);

                result.status = det.status.clone();
                result.http_status = http_status;
                result.title = det.title;
                result.description = det.description;
                result.confidence = det.confidence;
                result.response_time = elapsed;
                result.note = if attempt > 0 { format!("(retry {})", attempt) } else { String::new() };

                if det.status != "unknown" { break; }
            }
            Err(e) => {
                result.response_time = start.elapsed().as_secs_f64();
                result.description = format!("Error: {}", e.to_string().chars().take(80).collect::<String>());
                if attempt < retries {
                    std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
                    continue;
                }
            }
        }
    }

    result
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: osint_checker <username> [--proxy <proxy>] [--retry <n>] [--timeout <secs>] [--workers <n>]");
        std::process::exit(1);
    }

    let username = args[1].trim().to_lowercase();
    let mut proxy = None;
    let mut retries: u8 = 1;
    let mut timeout: u64 = 15;
    let mut workers: usize = 50;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--proxy" if i + 1 < args.len() => { proxy = Some(args[i + 1].clone()); i += 2; }
            "--retry" if i + 1 < args.len() => { retries = args[i + 1].parse().unwrap_or(1); i += 2; }
            "--timeout" if i + 1 < args.len() => { timeout = args[i + 1].parse().unwrap_or(15); i += 2; }
            "--workers" if i + 1 < args.len() => { workers = args[i + 1].parse().unwrap_or(50); i += 2; }
            _ => { i += 1; }
        }
    }

    let sites = load_sites();
    eprintln!("[osint] Loaded {} sites", sites.len());

    let client = match build_client(&proxy, timeout) {
        Ok(c) => c,
        Err(e) => { eprintln!("[osint] Client error: {}", e); std::process::exit(1); }
    };

    let results: Vec<CheckResult> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in sites.chunks(workers) {
            for site in chunk {
                let c = scope.spawn(|| {
                    check_site(site, &username, &client, retries)
                });
                handles.push(c);
            }
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut final_results = results;
    final_results.sort_by(|a, b| {
        let order = |s: &str| -> u8 { match s { "hit" => 0, "possible" => 1, "unknown" => 2, _ => 3 } };
        order(&a.status).cmp(&order(&b.status))
    });

    for r in &final_results {
        println!("RESULT:{}", serde_json::to_string(r).unwrap());
    }

    let hits = final_results.iter().filter(|r| r.status == "hit").count();
    let poss = final_results.iter().filter(|r| r.status == "possible").count();
    let unk = final_results.iter().filter(|r| r.status == "unknown").count();
    println!("FINAL:{}", serde_json::json!({"username": username, "total": final_results.len(), "hits": hits, "possible": poss, "unknown": unk}));
}
