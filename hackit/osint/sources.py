"""
Curated public OSINT sources for username/profile discovery.

Each source is a public profile endpoint. The scanner only checks public pages and
does not log in, bypass access controls, or query private APIs.
"""

SOCIAL_SOURCES = [
    {"name": "GitHub", "category": "Developer", "url": "https://github.com/{username}"},
    {"name": "GitLab", "category": "Developer", "url": "https://gitlab.com/{username}"},
    {"name": "Bitbucket", "category": "Developer", "url": "https://bitbucket.org/{username}"},
    {"name": "Stack Overflow", "category": "Developer", "url": "https://stackoverflow.com/users/{username}"},
    {"name": "HackerOne", "category": "Security", "url": "https://hackerone.com/{username}"},
    {"name": "Bugcrowd", "category": "Security", "url": "https://bugcrowd.com/{username}"},
    {"name": "Keybase", "category": "Identity", "url": "https://keybase.io/{username}"},
    {"name": "Twitter/X", "category": "Social", "url": "https://x.com/{username}"},
    {"name": "Instagram", "category": "Social", "url": "https://www.instagram.com/{username}/"},
    {"name": "TikTok", "category": "Social", "url": "https://www.tiktok.com/@{username}"},
    {"name": "Facebook", "category": "Social", "url": "https://www.facebook.com/{username}"},
    {"name": "Threads", "category": "Social", "url": "https://www.threads.net/@{username}"},
    {"name": "Reddit", "category": "Forum", "url": "https://www.reddit.com/user/{username}"},
    {"name": "Pinterest", "category": "Social", "url": "https://www.pinterest.com/{username}/"},
    {"name": "Tumblr", "category": "Blog", "url": "https://{username}.tumblr.com/"},
    {"name": "Medium", "category": "Blog", "url": "https://medium.com/@{username}"},
    {"name": "Dev.to", "category": "Developer", "url": "https://dev.to/{username}"},
    {"name": "Hashnode", "category": "Developer", "url": "https://hashnode.com/@{username}"},
    {"name": "Product Hunt", "category": "Startup", "url": "https://www.producthunt.com/@{username}"},
    {"name": "Kaggle", "category": "Data", "url": "https://www.kaggle.com/{username}"},
    {"name": "Replit", "category": "Developer", "url": "https://replit.com/@{username}"},
    {"name": "CodePen", "category": "Developer", "url": "https://codepen.io/{username}"},
    {"name": "npm", "category": "Developer", "url": "https://www.npmjs.com/~{username}"},
    {"name": "PyPI", "category": "Developer", "url": "https://pypi.org/user/{username}/"},
    {"name": "Docker Hub", "category": "Developer", "url": "https://hub.docker.com/u/{username}"},
    {"name": "TryHackMe", "category": "Security", "url": "https://tryhackme.com/p/{username}"},
    {"name": "Hack The Box", "category": "Security", "url": "https://app.hackthebox.com/profile/{username}"},
    {"name": "Root Me", "category": "Security", "url": "https://www.root-me.org/{username}"},
    {"name": "CTFtime", "category": "Security", "url": "https://ctftime.org/user/{username}"},
    {"name": "YouTube", "category": "Media", "url": "https://www.youtube.com/@{username}"},
    {"name": "Twitch", "category": "Media", "url": "https://www.twitch.tv/{username}"},
    {"name": "SoundCloud", "category": "Media", "url": "https://soundcloud.com/{username}"},
    {"name": "Spotify", "category": "Media", "url": "https://open.spotify.com/user/{username}"},
    {"name": "Steam", "category": "Gaming", "url": "https://steamcommunity.com/id/{username}"},
    {"name": "Roblox", "category": "Gaming", "url": "https://www.roblox.com/user.aspx?username={username}"},
    {"name": "Chess.com", "category": "Gaming", "url": "https://www.chess.com/member/{username}"},
    {"name": "Lichess", "category": "Gaming", "url": "https://lichess.org/@/{username}"},
    {"name": "Dribbble", "category": "Design", "url": "https://dribbble.com/{username}"},
    {"name": "Behance", "category": "Design", "url": "https://www.behance.net/{username}"},
    {"name": "Flickr", "category": "Media", "url": "https://www.flickr.com/people/{username}/"},
    {"name": "About.me", "category": "Identity", "url": "https://about.me/{username}"},
    {"name": "LinkedIn", "category": "Professional", "url": "https://www.linkedin.com/in/{username}/"},
    {"name": "Mastodon.social", "category": "Social", "url": "https://mastodon.social/@{username}"},
    {"name": "Mastodon.online", "category": "Social", "url": "https://mastodon.online/@{username}"},
    {"name": "Bluesky", "category": "Social", "url": "https://bsky.app/profile/{username}.bsky.social"},
    {"name": "VK", "category": "Social", "url": "https://vk.com/{username}"},
    {"name": "OK.ru", "category": "Social", "url": "https://ok.ru/{username}"},
    {"name": "Weibo", "category": "Social", "url": "https://weibo.com/{username}"},
    {"name": "Telegram", "category": "Messaging", "url": "https://t.me/{username}"},
    {"name": "Snapchat", "category": "Social", "url": "https://www.snapchat.com/add/{username}"},
    {"name": "Blogger", "category": "Blog", "url": "https://{username}.blogspot.com/"},
    {"name": "WordPress", "category": "Blog", "url": "https://{username}.wordpress.com/"},
    {"name": "Wattpad", "category": "Writing", "url": "https://www.wattpad.com/user/{username}"},
    {"name": "Goodreads", "category": "Books", "url": "https://www.goodreads.com/{username}"},
    {"name": "Letterboxd", "category": "Media", "url": "https://letterboxd.com/{username}/"},
    {"name": "Unsplash", "category": "Media", "url": "https://unsplash.com/@{username}"},
    {"name": "500px", "category": "Media", "url": "https://500px.com/p/{username}"},
    {"name": "Bandcamp", "category": "Media", "url": "https://bandcamp.com/{username}"},
    {"name": "BuyMeACoffee", "category": "Creator", "url": "https://www.buymeacoffee.com/{username}"},
    {"name": "Patreon", "category": "Creator", "url": "https://www.patreon.com/{username}"},
    {"name": "Ko-fi", "category": "Creator", "url": "https://ko-fi.com/{username}"},
    {"name": "Linktree", "category": "Identity", "url": "https://linktr.ee/{username}"},
    {"name": "Carrd", "category": "Identity", "url": "https://{username}.carrd.co/"},
    {"name": "OnlyFans", "category": "Creator", "url": "https://onlyfans.com/{username}"},
    {"name": "Fiverr", "category": "Freelance", "url": "https://www.fiverr.com/{username}"},
    {"name": "Freelancer", "category": "Freelance", "url": "https://www.freelancer.com/u/{username}"},
    {"name": "Upwork", "category": "Freelance", "url": "https://www.upwork.com/freelancers/~{username}"},
    {"name": "Cracked.io", "category": "Forum", "url": "https://cracked.io/{username}"},
    {"name": "HackForums", "category": "Forum", "url": "https://hackforums.net/member.php?action=profile&uid={username}"},
    {"name": "MyAnimeList", "category": "Media", "url": "https://myanimelist.net/profile/{username}"},
    {"name": "AniList", "category": "Media", "url": "https://anilist.co/user/{username}/"},
    {"name": "Duolingo", "category": "Education", "url": "https://www.duolingo.com/profile/{username}"},
    {"name": "Codecademy", "category": "Education", "url": "https://www.codecademy.com/profiles/{username}"},
    {"name": "LeetCode", "category": "Developer", "url": "https://leetcode.com/{username}/"},
    {"name": "Codeforces", "category": "Developer", "url": "https://codeforces.com/profile/{username}"},
    {"name": "Topcoder", "category": "Developer", "url": "https://www.topcoder.com/members/{username}"},
    {"name": "Hugging Face", "category": "AI", "url": "https://huggingface.co/{username}"},
    {"name": "OpenSea", "category": "Crypto", "url": "https://opensea.io/{username}"},
    {"name": "Foundation", "category": "Crypto", "url": "https://foundation.app/@{username}"},
    {"name": "TripAdvisor", "category": "Travel", "url": "https://www.tripadvisor.com/Profile/{username}"},
    {"name": "Strava", "category": "Fitness", "url": "https://www.strava.com/athletes/{username}"},
]

PROFILE_PACKS = [
    ("Social", "https://www.{domain}/{username}", [
        "ask.fm", "last.fm/user", "mixcloud.com", "slideshare.net", "scribd.com",
        "dailykos.com/user", "disqus.com/by", "forum.xda-developers.com/m",
        "producthunt.com/@", "indiedb.com/members", "moddb.com/members",
        "houzz.com/user", "instructables.com/member", "kongregate.com/accounts",
        "newgrounds.com", "sketchfab.com", "pastebin.com/u", "gumroad.com",
        "itch.io/profile", "sourceforge.net/u", "launchpad.net/~",
    ]),
]


def get_social_sources():
    """Return an expanded, de-duplicated source list.

    The large probe volume comes from sources multiplied by generated handle
    variants. This keeps the registry maintainable while still producing
    1000+ public checks for normal full-name inputs.
    """
    from .additional_sources import ADDITIONAL_SOURCES
    from .validators import normalize_source

    expanded = list(SOCIAL_SOURCES) + list(ADDITIONAL_SOURCES)
    for category, template, domains in PROFILE_PACKS:
        for domain in domains:
            if domain.endswith("/") or "/" in domain:
                url = "https://" + domain + "/{username}"
            else:
                url = template.format(domain=domain, username="{username}")
            name = domain.replace("www.", "").split("/")[0]
            expanded.append({"name": name, "category": category, "url": url})

    seen = set()
    clean = []
    for source in expanded:
        source = normalize_source(source)
        if not source:
            continue
        key = source["url"]
        if key not in seen:
            seen.add(key)
            clean.append(source)
    return clean

SEARCH_LEADS = [
    {"name": "Google exact name", "url": "https://www.google.com/search?q=%22{query}%22"},
    {"name": "Google social", "url": "https://www.google.com/search?q=%22{query}%22+%28instagram+OR+github+OR+linkedin+OR+twitter%29"},
    {"name": "Bing exact name", "url": "https://www.bing.com/search?q=%22{query}%22"},
    {"name": "DuckDuckGo exact name", "url": "https://duckduckgo.com/?q=%22{query}%22"},
    {"name": "GitHub code/users", "url": "https://github.com/search?q=%22{query}%22&type=users"},
    {"name": "Reddit mentions", "url": "https://www.reddit.com/search/?q=%22{query}%22"},
    {"name": "LinkedIn public search", "url": "https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{query}%22"},
    {"name": "Instagram public search", "url": "https://www.google.com/search?q=site%3Ainstagram.com+%22{query}%22"},
    {"name": "TikTok public search", "url": "https://www.google.com/search?q=site%3Atiktok.com+%22{query}%22"},
    {"name": "GitHub commits/issues", "url": "https://www.google.com/search?q=site%3Agithub.com+%22{query}%22"},
    {"name": "Paste public traces", "url": "https://www.google.com/search?q=%22{query}%22+%28pastebin+OR+gist+OR+paste%29"},
    {"name": "Documents", "url": "https://www.google.com/search?q=%22{query}%22+filetype%3Apdf+OR+filetype%3Adocx"},
]
