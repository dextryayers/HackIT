import httpx
import re
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

PLATFORMS = [
    # Social Media
    ("Twitter/X", "https://twitter.com/{username}", "social-media"),
    ("Instagram", "https://www.instagram.com/{username}", "social-media"),
    ("Facebook", "https://www.facebook.com/{username}", "social-media"),
    ("TikTok", "https://www.tiktok.com/@{username}", "social-media"),
    ("Snapchat", "https://www.snapchat.com/add/{username}", "social-media"),
    ("Threads", "https://www.threads.net/@{username}", "social-media"),
    ("Bluesky", "https://bsky.app/profile/{username}", "social-media"),
    ("Mastodon", "https://mastodon.social/@{username}", "social-media"),
    ("Pinterest", "https://www.pinterest.com/{username}", "social-media"),
    ("Tumblr", "https://{username}.tumblr.com", "blogging"),
    ("Reddit", "https://www.reddit.com/user/{username}", "social-media"),
    ("HackerNews", "https://news.ycombinator.com/user?id={username}", "social-media"),
    ("ProductHunt", "https://www.producthunt.com/@{username}", "product"),

    # Messaging & Communication
    ("WhatsApp", "https://wa.me/{username}", "messaging"),
    ("Telegram", "https://t.me/{username}", "messaging"),
    ("Signal", "https://signal.me/#p/{username}", "messaging"),
    ("Keybase", "https://keybase.io/{username}", "security"),
    ("Discord", "https://discord.com/users/{username}", "gaming"),

    # Gaming
    ("Twitch", "https://www.twitch.tv/{username}", "gaming"),
    ("Steam", "https://steamcommunity.com/id/{username}", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{username}", "gaming"),
    ("Lichess", "https://lichess.org/@/{username}", "gaming"),
    ("Epic Games", "https://www.epicgames.com/id/{username}", "gaming"),

    # Cybersecurity & CTF
    ("HackerOne", "https://hackerone.com/{username}", "security"),
    ("Bugcrowd", "https://bugcrowd.com/{username}", "security"),
    ("TryHackMe", "https://tryhackme.com/p/{username}", "security"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{username}", "security"),
    ("CTFtime", "https://ctftime.org/user/{username}", "security"),
    ("RootMe", "https://www.root-me.org/{username}", "security"),

    # Development & Code Hosting
    ("GitHub", "https://github.com/{username}", "development"),
    ("GitLab", "https://gitlab.com/{username}", "development"),
    ("Bitbucket", "https://bitbucket.org/{username}", "development"),
    ("CodePen", "https://codepen.io/{username}", "development"),
    ("Replit", "https://replit.com/@{username}", "development"),
    ("StackOverflow", "https://stackoverflow.com/users/{username}", "development"),
    ("Dev.to", "https://dev.to/{username}", "development"),
    ("Medium", "https://medium.com/@{username}", "blogging"),
    ("Hashnode", "https://hashnode.com/@{username}", "blogging"),

    # Package Registries
    ("Docker Hub", "https://hub.docker.com/u/{username}", "development"),
    ("NPM", "https://www.npmjs.com/~{username}", "development"),
    ("PyPI", "https://pypi.org/user/{username}", "development"),
    ("RubyGems", "https://rubygems.org/profiles/{username}", "development"),
    ("Crates.io", "https://crates.io/users/{username}", "development"),
    ("NuGet", "https://www.nuget.org/profiles/{username}", "development"),
    ("Packagist", "https://packagist.org/packages/{username}", "development"),

    # Professional / Business
    ("LinkedIn", "https://www.linkedin.com/in/{username}", "professional"),
    ("AngelList", "https://angel.co/u/{username}", "professional"),
    ("Fiverr", "https://www.fiverr.com/{username}", "professional"),
    ("Upwork", "https://www.upwork.com/freelancers/~{username}", "professional"),
    ("Freelancer", "https://www.freelancer.com/u/{username}", "professional"),
    ("SlideShare", "https://www.slideshare.net/{username}", "professional"),

    # Crowdfunding & Support
    ("Patreon", "https://www.patreon.com/{username}", "funding"),
    ("Ko-fi", "https://ko-fi.com/{username}", "funding"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", "funding"),
    ("Substack", "https://{username}.substack.com", "blogging"),
    ("IndieHackers", "https://www.indiehackers.com/{username}", "product"),

    # Design & Creative
    ("Behance", "https://www.behance.net/{username}", "design"),
    ("Dribbble", "https://dribbble.com/{username}", "design"),
    ("ArtStation", "https://www.artstation.com/{username}", "design"),
    ("DeviantArt", "https://www.deviantart.com/{username}", "design"),
    ("Figma", "https://www.figma.com/@{username}", "design"),
    ("Flickr", "https://www.flickr.com/people/{username}", "photography"),

    # Music & Audio
    ("Bandcamp", "https://{username}.bandcamp.com", "music"),
    ("SoundCloud", "https://soundcloud.com/{username}", "music"),
    ("Spotify", "https://open.spotify.com/user/{username}", "music"),

    # Video & Streaming
    ("YouTube", "https://www.youtube.com/@{username}", "video"),
    ("Vimeo", "https://vimeo.com/{username}", "video"),

    # Marketplace & Shopping
    ("Etsy", "https://www.etsy.com/shop/{username}", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{username}", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{username}", "shopping"),

    # Developer Tools
    ("Sentry", "https://sentry.io/{username}", "development"),
    ("Pagespeed", "https://pagespeed.web.dev/analysis?url={username}", "development"),

    # Reference
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "reference"),
    ("About.me", "https://about.me/{username}", "social-media"),
    ("Calendly", "https://calendly.com/{username}", "professional"),

    # Social Media (extended)
    ("VK", "https://vk.com/{username}", "social-media"),
    ("Ok.ru", "https://ok.ru/{username}", "social-media"),
    ("Weibo", "https://www.weibo.com/{username}", "social-media"),
    ("QQ", "https://user.qzone.qq.com/{username}", "social-media"),
    ("Douban", "https://www.douban.com/people/{username}/", "social-media"),
    ("Zhihu", "https://www.zhihu.com/people/{username}", "social-media"),
    ("Bilibili", "https://space.bilibili.com/{username}", "social-media"),
    ("Xiaohongshu", "https://www.xiaohongshu.com/user/{username}", "social-media"),
    ("Gettr", "https://gettr.com/user/{username}", "social-media"),
    ("Minds", "https://www.minds.com/{username}", "social-media"),
    ("Gab", "https://gab.com/{username}", "social-media"),
    ("Parler", "https://parler.com/profile/{username}", "social-media"),
    ("MeWe", "https://mewe.com/i/{username}", "social-media"),
    ("Plurk", "https://www.plurk.com/{username}", "social-media"),

    # Video & Streaming (extended)
    ("Dailymotion", "https://www.dailymotion.com/{username}", "video"),
    ("Rumble", "https://rumble.com/user/{username}", "video"),
    ("Odysee", "https://odysee.com/@{username}", "video"),
    ("Bitchute", "https://www.bitchute.com/channel/{username}", "video"),
    ("DTube", "https://d.tube/#!/c/{username}", "video"),
    ("Youku", "https://youku.com/{username}", "video"),

    # Gaming (extended)
    ("Kongregate", "https://www.kongregate.com/accounts/{username}", "gaming"),
    ("Newgrounds", "https://{username}.newgrounds.com", "gaming"),
    ("Speedrun.com", "https://www.speedrun.com/users/{username}", "gaming"),
    ("Battle.net", "https://battle.net/{username}", "gaming"),
    ("Xbox Live", "https://xbox.com/@{username}", "gaming"),
    ("PlayStation", "https://psnprofiles.com/{username}", "gaming"),
    ("Nintendo", "https://en-americas-support.nintendo.com/user/{username}", "gaming"),
    ("GOG", "https://www.gog.com/u/{username}", "gaming"),
    ("Itch.io", "https://{username}.itch.io", "gaming"),
    ("GameJolt", "https://gamejolt.com/@{username}", "gaming"),

    # Music & Audio (extended)
    ("Last.fm", "https://www.last.fm/user/{username}", "music"),
    ("Shazam", "https://www.shazam.com/profile/{username}", "music"),
    ("Mixcloud", "https://www.mixcloud.com/{username}/", "music"),
    ("Beatport", "https://www.beatport.com/artist/{username}", "music"),
    ("Tidal", "https://tidal.com/{username}", "music"),
    ("Deezer", "https://www.deezer.com/profile/{username}", "music"),
    ("Apple Music", "https://music.apple.com/profile/{username}", "music"),
    ("Audiomack", "https://audiomack.com/{username}", "music"),

    # Design & Creative (extended)
    ("Unsplash", "https://unsplash.com/@{username}", "photography"),
    ("500px", "https://500px.com/{username}", "photography"),
    ("Pexels", "https://www.pexels.com/@{username}", "photography"),
    ("Pixabay", "https://pixabay.com/users/{username}/", "photography"),
    ("Freepik", "https://www.freepik.com/author/{username}", "design"),
    ("Shutterstock", "https://www.shutterstock.com/g/{username}", "design"),
    ("Adobe Stock", "https://stock.adobe.com/contributor/{username}", "design"),
    ("Behance", "https://www.behance.net/{username}", "design"),
    ("Dribbble", "https://dribbble.com/{username}", "design"),
    ("ArtStation", "https://www.artstation.com/{username}", "design"),
    ("DeviantArt", "https://www.deviantart.com/{username}", "design"),
    ("Figma Community", "https://www.figma.com/@{username}", "design"),
    ("Sketch", "https://sketch.com/{username}", "design"),

    # Books & Literature
    ("Goodreads", "https://www.goodreads.com/{username}", "reference"),
    ("LibraryThing", "https://www.librarything.com/profile/{username}", "reference"),
    ("IMDb", "https://www.imdb.com/user/ur{username}", "reference"),
    ("Letterboxd", "https://letterboxd.com/{username}/", "reference"),
    ("Trakt", "https://trakt.tv/users/{username}", "reference"),
    ("MyAnimeList", "https://myanimelist.net/profile/{username}", "reference"),
    ("AniList", "https://anilist.co/user/{username}", "reference"),
    ("Kitsu", "https://kitsu.io/users/{username}", "reference"),
    ("Wattpad", "https://www.wattpad.com/user/{username}", "reference"),
    ("Archive of Our Own", "https://archiveofourown.org/users/{username}", "reference"),
    ("FanFiction", "https://www.fanfiction.net/u/{username}", "reference"),
    ("Quote.com", "https://www.quote.com/{username}", "reference"),

    # Development & Code Hosting (extended)
    ("GitLab", "https://gitlab.com/{username}", "development"),
    ("Bitbucket", "https://bitbucket.org/{username}", "development"),
    ("CodePen", "https://codepen.io/{username}", "development"),
    ("Replit", "https://replit.com/@{username}", "development"),
    ("StackOverflow", "https://stackoverflow.com/users/{username}", "development"),
    ("Dev.to", "https://dev.to/{username}", "development"),
    ("Medium", "https://medium.com/@{username}", "blogging"),
    ("Hashnode", "https://hashnode.com/@{username}", "blogging"),
    ("Observable", "https://observablehq.com/@{username}", "development"),
    ("Deepnote", "https://deepnote.com/@{username}", "development"),
    ("Kaggle", "https://www.kaggle.com/{username}", "development"),
    ("Codecademy", "https://www.codecademy.com/profiles/{username}", "development"),
    ("FreeCodeCamp", "https://www.freecodecamp.org/{username}", "development"),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{username}", "development"),
    ("LeetCode", "https://leetcode.com/{username}/", "development"),
    ("HackerRank", "https://www.hackerrank.com/{username}", "development"),
    ("Codewars", "https://www.codewars.com/users/{username}", "development"),
    ("TopCoder", "https://www.topcoder.com/members/{username}", "development"),
    ("CodinGame", "https://www.codingame.com/profile/{username}", "development"),
    ("Exercism", "https://exercism.org/profiles/{username}", "development"),
    ("Frontend Mentor", "https://www.frontendmentor.io/profile/{username}", "development"),
    ("Codementor", "https://www.codementor.io/@{username}", "development"),
    ("Hackaday", "https://hackaday.io/{username}", "development"),
    ("Instructables", "https://www.instructables.com/member/{username}", "development"),
    ("Thingiverse", "https://www.thingiverse.com/{username}", "development"),
    ("Printables", "https://www.printables.com/@{username}", "development"),

    # Pastebins & Code Snippets
    ("Pastebin", "https://pastebin.com/u/{username}", "development"),
    ("Rentry.co", "https://rentry.co/{username}", "development"),
    ("JSFiddle", "https://jsfiddle.net/user/{username}/", "development"),
    ("CodeSandbox", "https://codesandbox.io/u/{username}", "development"),
    ("Glitch", "https://glitch.com/@{username}", "development"),
    ("StackBlitz", "https://stackblitz.com/@{username}", "development"),
    ("Gitpod", "https://gitpod.io/{username}", "development"),

    # CI/CD & Quality
    ("Travis CI", "https://travis-ci.com/{username}", "development"),
    ("CircleCI", "https://circleci.com/{username}", "development"),
    ("SonarCloud", "https://sonarcloud.io/user/{username}", "development"),
    ("CodeClimate", "https://codeclimate.com/github/{username}", "development"),
    ("Coveralls", "https://coveralls.io/{username}", "development"),

    # Documentation
    ("Read the Docs", "https://readthedocs.org/profiles/{username}/", "development"),
    ("GitBook", "https://app.gitbook.com/@{username}", "development"),

    # Professional (extended)
    ("LinkedIn", "https://www.linkedin.com/in/{username}", "professional"),
    ("AngelList", "https://angel.co/u/{username}", "professional"),
    ("Fiverr", "https://www.fiverr.com/{username}", "professional"),
    ("Upwork", "https://www.upwork.com/freelancers/~{username}", "professional"),
    ("Freelancer", "https://www.freelancer.com/u/{username}", "professional"),
    ("SlideShare", "https://www.slideshare.net/{username}", "professional"),
    ("Crunchbase", "https://www.crunchbase.com/person/{username}", "professional"),
    ("Glassdoor", "https://www.glassdoor.com/Profile/{username}", "professional"),
    ("Trustpilot", "https://www.trustpilot.com/review/{username}", "professional"),
    ("G2", "https://www.g2.com/profile/{username}", "professional"),
    ("Capterra", "https://www.capterra.com/p/{username}", "professional"),
    ("Yelp", "https://www.yelp.com/user_details?userid={username}", "professional"),
    ("Meetup", "https://www.meetup.com/members/{username}/", "professional"),
    ("Eventbrite", "https://www.eventbrite.com/o/{username}", "professional"),
    ("ResearchGate", "https://www.researchgate.net/profile/{username}", "professional"),
    ("Academia.edu", "https://academia.edu/{username}", "professional"),
    ("Google Scholar", "https://scholar.google.com/citations?user={username}", "professional"),
    ("ORCID", "https://orcid.org/{username}", "professional"),
    ("Scopus", "https://www.scopus.com/authid/detail.uri?authorId={username}", "professional"),

    # Crowdfunding (extended)
    ("Patreon", "https://www.patreon.com/{username}", "funding"),
    ("Ko-fi", "https://ko-fi.com/{username}", "funding"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", "funding"),
    ("Substack", "https://{username}.substack.com", "blogging"),
    ("IndieHackers", "https://www.indiehackers.com/{username}", "product"),
    ("Open Collective", "https://opencollective.com/{username}", "funding"),
    ("Liberapay", "https://liberapay.com/{username}", "funding"),
    ("Kickstarter", "https://www.kickstarter.com/profile/{username}", "funding"),
    ("Indiegogo", "https://www.indiegogo.com/individuals/{username}", "funding"),
    ("GoFundMe", "https://www.gofundme.com/{username}", "funding"),

    # Shopping & Marketplaces (extended)
    ("Etsy", "https://www.etsy.com/shop/{username}", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{username}", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{username}", "shopping"),
    ("Amazon", "https://www.amazon.com/gp/profile/{username}", "shopping"),
    ("Wish", "https://www.wish.com/{username}", "shopping"),
    ("Mercari", "https://www.mercari.com/u/{username}", "shopping"),
    ("Poshmark", "https://poshmark.com/closet/{username}", "shopping"),
    ("Depop", "https://www.depop.com/{username}/", "shopping"),
    ("Vinted", "https://www.vinted.com/member/{username}", "shopping"),
    ("Grailed", "https://www.grailed.com/{username}", "shopping"),
    ("StockX", "https://stockx.com/{username}", "shopping"),

    # Sports & Fitness
    ("Strava", "https://www.strava.com/athletes/{username}", "reference"),
    ("Runkeeper", "https://runkeeper.com/user/{username}", "reference"),
    ("Fitbit", "https://www.fitbit.com/user/{username}", "reference"),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{username}", "reference"),
    ("AllTrails", "https://www.alltrails.com/members/{username}", "reference"),
    ("TrainerRoad", "https://trainerroad.com/user/{username}", "reference"),
    ("Zwift", "https://zwift.com/profile/{username}", "reference"),
    ("Peloton", "https://www.onepeloton.com/profile/{username}", "reference"),

    # Education & Learning
    ("Coursera", "https://www.coursera.org/user/{username}", "reference"),
    ("edX", "https://www.edx.org/user/{username}", "reference"),
    ("Udemy", "https://www.udemy.com/user/{username}", "reference"),
    ("Skillshare", "https://www.skillshare.com/profile/{username}", "reference"),
    ("Pluralsight", "https://app.pluralsight.com/profile/{username}", "reference"),
    ("DataCamp", "https://www.datacamp.com/portfolio/{username}", "reference"),
    ("Brilliant", "https://brilliant.org/profile/{username}", "reference"),
    ("Khan Academy", "https://www.khanacademy.org/profile/{username}", "reference"),
    ("Duolingo", "https://www.duolingo.com/profile/{username}", "reference"),
    ("Memrise", "https://www.memrise.com/user/{username}", "reference"),

    # Blogging & Writing
    ("WordPress", "https://{username}.wordpress.com", "blogging"),
    ("Blogger", "https://{username}.blogspot.com", "blogging"),
    ("Ghost", "https://{username}.ghost.io", "blogging"),
    ("Telegraph", "https://telegra.ph/{username}", "blogging"),
    ("Write.as", "https://write.as/{username}", "blogging"),
    ("BearBlog", "https://{username}.bearblog.dev", "blogging"),
    ("Micro.blog", "https://micro.blog/{username}", "blogging"),

    # Security & CTF
    ("HackerOne", "https://hackerone.com/{username}", "security"),
    ("Bugcrowd", "https://bugcrowd.com/{username}", "security"),
    ("TryHackMe", "https://tryhackme.com/p/{username}", "security"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{username}", "security"),
    ("CTFtime", "https://ctftime.org/user/{username}", "security"),
    ("RootMe", "https://www.root-me.org/{username}", "security"),
    ("PentesterLab", "https://pentesterlab.com/profile/{username}", "security"),
    ("Intigriti", "https://www.intigriti.com/researcher/profile/{username}", "security"),
    ("YesWeHack", "https://www.yeswehack.com/hunter/{username}", "security"),
    ("Open Bug Bounty", "https://www.openbugbounty.org/researchers/{username}/", "security"),
    ("VulDB", "https://vuldb.com/?user.{username}", "security"),
    ("Exploit-DB", "https://www.exploit-db.com/author/{username}", "security"),

    # Forums & Communities
    ("StackExchange", "https://stackexchange.com/users/{username}", "reference"),
    ("Quora", "https://www.quora.com/profile/{username}", "reference"),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{username}", "reference"),
    ("About.me", "https://about.me/{username}", "social-media"),
    ("Calendly", "https://calendly.com/{username}", "professional"),
    ("Linktree", "https://linktr.ee/{username}", "social-media"),
    ("Bio.link", "https://bio.link/{username}", "social-media"),
    ("Carrd", "https://{username}.carrd.co", "social-media"),
    ("Beacons", "https://beacons.ai/{username}", "social-media"),

    # Messaging (extended)
    ("WhatsApp", "https://wa.me/{username}", "messaging"),
    ("Telegram", "https://t.me/{username}", "messaging"),
    ("Signal", "https://signal.me/#p/{username}", "messaging"),
    ("Keybase", "https://keybase.io/{username}", "security"),
    ("Discord", "https://discord.com/users/{username}", "gaming"),
    ("Slack", "https://{username}.slack.com", "messaging"),
    ("Matrix", "https://matrix.to/#/@{username}", "messaging"),
    ("IRC", "https://irc.libera.chat/{username}", "messaging"),
    ("Wire", "https://wire.com/{username}", "messaging"),
    ("Session", "https://getsession.org/{username}", "messaging"),
    ("Element", "https://app.element.io/#/user/@{username}", "messaging"),
]


PLATFORM_DETAIL_EXTRACTORS = {
    "Twitch": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "bio": r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
    },
    "Instagram": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "bio": r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
    },
    "TikTok": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "bio": r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
    },
    "Reddit": {
        "karma": r'(\d[\d,]*)\s*(?:karma|Karma)',
        "age": r'(?:account\s+created|member\s+since)[:\s]*([^<]+)',
    },
    "GitHub": {
        "repos": r'(\d[\d,]*)\s*(?:repositories?|Repositories?)',
        "stars": r'(\d[\d,]*)\s*(?:stars?|Stars?)',
        "bio": r'<div\s+class=["\']user-profile-bio["\'][^>]*>\s*<div[^>]*>([^<]+)',
    },
    "YouTube": {
        "subscribers": r'(\d[\d,]*)\s*(?:subscriber|Subscriber|Subscribers)',
    },
    "VK": {
        "friends": r'(\d[\d,]*)\s*(?:friends?|Friends?)',
        "bio": r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
    },
    "Bilibili": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "views": r'(\d[\d,]*)\s*(?:views?|Views?)',
    },
    "SoundCloud": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "tracks": r'(\d[\d,]*)\s*(?:tracks?|Tracks?)',
    },
    "Spotify": {
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
        "playlists": r'(\d[\d,]*)\s*(?:playlists?|Playlists?)',
    },
    "DeviantArt": {
        "deviations": r'(\d[\d,]*)\s*(?:deviations?|Deviations?)',
        "watching": r'(\d[\d,]*)\s*(?:watching|Watching)',
    },
    "Strava": {
        "activities": r'(\d[\d,]*)\s*(?:activities?|Activities?)',
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
    },
    "Patreon": {
        "patrons": r'(\d[\d,]*)\s*(?:patrons?|Patrons?)',
        "bio": r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
    },
    "Etsy": {
        "sales": r'(\d[\d,]*)\s*(?:sales?|Sales?)',
        "reviews": r'(\d[\d,]*)\s*(?:reviews?|Reviews?)',
    },
    "HackerOne": {
        "reputation": r'(\d[\d,]*)\s*(?:reputation|Reputation)',
        "rank": r'#(\d+)',
    },
    "HackTheBox": {
        "points": r'(\d[\d,]*)\s*(?:points?|Points?)',
        "rank": r'(\w+)\s*(?:rank|Rank)',
    },
    "Steam": {
        "level": r'(\d+)\s*(?:level|Level)',
        "games": r'(\d[\d,]*)\s*(?:games?|Games?)',
    },
    "Chess.com": {
        "rating": r'(\d{3,4})\s*(?:rating|Rating)',
        "games_played": r'(\d[\d,]*)\s*(?:games?|Games?)',
    },
    "Goodreads": {
        "books": r'(\d[\d,]*)\s*(?:books?|Books?)',
        "reviews": r'(\d[\d,]*)\s*(?:reviews?|Reviews?)',
    },
    "Letterboxd": {
        "films": r'(\d[\d,]*)\s*(?:films?|Films?)',
        "reviews": r'(\d[\d,]*)\s*(?:reviews?|Reviews?)',
    },
    "Last.fm": {
        "scrobbles": r'(\d[\d,]*)\s*(?:scrobbles?|Scrobbles?)',
    },
    "TryHackMe": {
        "rank": r'(\w+)\s*(?:rank|Rank)',
        "rooms": r'(\d[\d,]*)\s*(?:rooms?|Rooms?)',
    },
    "Dribbble": {
        "shots": r'(\d[\d,]*)\s*(?:shots?|Shots?)',
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
    },
    "ProductHunt": {
        "upvotes": r'(\d[\d,]*)\s*(?:upvotes?|Upvotes?)',
        "products": r'(\d[\d,]*)\s*(?:products?|Products?)',
    },
    "Flickr": {
        "photos": r'(\d[\d,]*)\s*(?:photos?|Photos?)',
        "views": r'(\d[\d,]*)\s*(?:views?|Views?)',
    },
    "Behance": {
        "projects": r'(\d[\d,]*)\s*(?:projects?|Projects?)',
        "followers": r'(\d[\d,]*)\s*(?:follower|Follower|Followers)',
    },
    "ResearchGate": {
        "publications": r'(\d[\d,]*)\s*(?:publications?|Publications?)',
        "reads": r'(\d[\d,]*)\s*(?:reads?|Reads?)',
    },
}

USERNAME_PREFIXES = ["my", "the", "get", "go", "real", "official", "just", "i", "its"]


async def check_platform(username: str, platform_name: str, url_template: str,
                         category: str, client: httpx.AsyncClient) -> list:
    findings = []
    url = url_template.replace("{username}", username)
    try:
        resp = await client.get(url, timeout=10.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            },
            follow_redirects=True
        )
        page_text = resp.text.lower() if hasattr(resp, 'text') else ""

        not_found_indicators = [
            "page not found", "doesn't exist", "no user found",
            "could not find", "this page doesn't exist", "sorry",
            "not found", "we couldn't find", "no one uses this",
            "user not found", "profile not found", "this account doesn",
            "404", "this page isn't available", "this profile doesn",
            "page doesn't exist", "couldn't find", "no results",
            "the page you requested was not found",
        ]
        is_not_found = any(ind in page_text for ind in not_found_indicators) and resp.status_code == 404
        is_not_found = is_not_found or resp.status_code == 404

        if resp.status_code == 200 and not any(
            ind in page_text for ind in ["page not found", "doesn't exist", "not found", "could not find",
                                          "page doesn't exist", "couldn't find"]
        ):
            profile_name = ""
            title_match = re.search(r'<title>([^<]+)</title>', resp.text or "", re.IGNORECASE)
            if title_match:
                profile_name = title_match.group(1).strip()[:100]

            findings.append(IntelligenceFinding(
                entity=f"{platform_name}: {profile_name or username}",
                type=f"Social Profile: {platform_name}",
                source="SocialSearch",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Profile found",
                resolution=url,
                raw_data=f"URL: {url}, Title: {profile_name}",
                tags=["social-profile", category, platform_name.lower().replace("/", "-").replace(" ", "-")]
            ))

            extractors = PLATFORM_DETAIL_EXTRACTORS.get(platform_name, {})
            for detail_type, pattern in extractors.items():
                match = re.search(pattern, resp.text or "")
                if match:
                    extract_name = f"{platform_name}: {detail_type.capitalize()}"
                    findings.append(IntelligenceFinding(
                        entity=match.group(1).strip()[:200],
                        type=extract_name,
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=[platform_name.lower().replace(" ", "-"), detail_type]
                    ))

            if platform_name == "Twitter/X":
                followers_match = re.search(r'(\d[\d,]*)\s*(?:follower|Follower)', resp.text or "")
                if followers_match:
                    findings.append(IntelligenceFinding(
                        entity=f"Followers: {followers_match.group(1)}",
                        type="Twitter/X: Followers",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["twitter", "followers"]
                    ))
            elif platform_name == "LinkedIn":
                headline_match = re.search(r'<title>([^|]+)', resp.text or "")
                if headline_match:
                    findings.append(IntelligenceFinding(
                        entity=headline_match.group(1).strip()[:150],
                        type="LinkedIn Headline",
                        source="SocialSearch",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["linkedin", "headline"]
                    ))
            elif platform_name == "GitHub":
                if "bio" not in extractors:
                    bio_match = re.search(r'<div\s+class=["\']user-profile-bio["\'][^>]*>\s*<div[^>]*>([^<]+)',
                                          resp.text or "", re.DOTALL)
                    if not bio_match:
                        bio_match = re.search(r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)',
                                              resp.text or "")
                    if bio_match:
                        findings.append(IntelligenceFinding(
                            entity=bio_match.group(1).strip()[:200],
                            type="GitHub Bio",
                            source="SocialSearch",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            tags=["github", "bio"]
                        ))

            wayback_url = f"https://web.archive.org/web/2025/{url}"
            gcache_url = f"https://webcache.googleusercontent.com/search?q=cache:{url}"
            findings.append(IntelligenceFinding(
                entity=f"Profile Snapshot: {platform_name}",
                type="Profile Snapshot Links",
                source="SocialSearch",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                resolution=url,
                raw_data=f"Wayback: {wayback_url}\nGoogle Cache: {gcache_url}",
                tags=["snapshot", "wayback", "google-cache", platform_name.lower().replace(" ", "-")]
            ))

        elif resp.status_code < 500:
            pass
    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass
    return findings


async def check_username_across_platforms(username: str, client: httpx.AsyncClient) -> list:
    findings = []
    tasks = []
    for platform_name, url_template, category in PLATFORMS:
        tasks.append(
            check_platform(username, platform_name, url_template, category, client)
        )

    results = await asyncio.gather(*tasks, return_exceptions=True)
    found_profile_types = set()
    for result in results:
        if isinstance(result, list):
            findings.extend(result)
            for f in result:
                if f.type.startswith("Social Profile:"):
                    found_profile_types.add(f.type)

    found_count = len(found_profile_types)
    if found_count > 0:
        platforms_found = ", ".join(sorted(found_profile_types))
        platforms_lower = [p.lower() for p in found_profile_types]
        confidence = compute_username_confidence(found_count, platforms_lower)

        findings.append(IntelligenceFinding(
            entity=f"Username '{username}' found on {found_count} platform(s): {platforms_found[:200]}",
            type="Social Search: Profile Summary",
            source="SocialSearch",
            confidence=confidence,
            color="purple" if found_count > 3 else "slate",
            threat_level="Informational",
            status=f"{found_count} profiles found",
            tags=["social-search", "username-summary", username]
        ))

        cross_refs = find_cross_references(username, [f for f in findings if f.type.startswith("Social Profile:")])
        if cross_refs:
            findings.extend(cross_refs)

        availability_score = compute_availability_score(found_count, len(PLATFORMS))
        findings.append(IntelligenceFinding(
            entity=f"Username Availability: {availability_score}/100 (found on {found_count}/{len(PLATFORMS)} platforms)",
            type="Username Availability Score",
            source="SocialSearch",
            confidence="Medium",
            color="green" if availability_score > 70 else "orange" if availability_score > 40 else "red",
            threat_level="Informational",
            status=f"Score: {availability_score}/100",
            tags=["social-search", "availability-score", "username-analysis"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"Username '{username}' not found on checked platforms",
            type="Social Search: No Results",
            source="SocialSearch",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="No profiles found",
            tags=["social-search", "no-results"]
        ))

    return findings


def compute_username_confidence(found_count: int, platforms: list) -> str:
    if found_count >= 10:
        return "Very High"
    elif found_count >= 5:
        return "High"
    elif found_count >= 3:
        return "Medium"
    elif found_count >= 1:
        return "Low"
    return "None"


def compute_availability_score(found_count: int, total_platforms: int) -> int:
    if total_platforms == 0:
        return 0
    ratio = found_count / total_platforms
    if ratio >= 0.5:
        return max(0, int(100 - (ratio * 100)))
    elif ratio >= 0.2:
        return max(0, int(80 - (ratio * 100)))
    elif ratio >= 0.05:
        return int(90 - (ratio * 200))
    else:
        return 95


def find_cross_references(username: str, profile_findings: list) -> list:
    cross_findings = []
    profile_types = {}
    for f in profile_findings:
        raw_type = f.type.replace("Social Profile: ", "")
        profile_types[raw_type.lower()] = f

    identity_platforms = {"github", "stackoverflow", "linkedin"}
    matched = identity_platforms & set(profile_types.keys())
    if len(matched) >= 2:
        matched_list = sorted(matched)
        platforms_str = ", ".join(matched_list)
        entity_str = f"Verified Identity: {username} on {platforms_str}"
        cross_findings.append(IntelligenceFinding(
            entity=entity_str,
            type="Cross-Reference: Verified Identity",
            source="SocialSearch",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status=f"Verified across {len(matched_list)} platforms",
            raw_data=f"Platforms: {', '.join(profile_types[p].resolution for p in matched_list if p in profile_types)}",
            tags=["cross-reference", "verified-identity", username] + [f"xref-{p}" for p in matched_list]
        ))

    dev_platforms = {"github", "gitlab", "bitbucket", "stackoverflow", "codepen", "replit", "dev.to", "npm", "pypi", "docker hub"}
    dev_matched = dev_platforms & set(profile_types.keys())
    if len(dev_matched) >= 3:
        dev_list = sorted(dev_matched)
        cross_findings.append(IntelligenceFinding(
            entity=f"Developer Footprint: {username} on {len(dev_list)} dev platforms",
            type="Cross-Reference: Developer Footprint",
            source="SocialSearch",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status=f"{len(dev_list)} dev platforms",
            tags=["cross-reference", "developer-footprint", username] + [f"xref-{p}" for p in dev_list]
        ))

    social_platforms = {"instagram", "facebook", "twitter/x", "tiktok", "threads", "reddit", "bluesky"}
    social_matched = social_platforms & set(profile_types.keys())
    if len(social_matched) >= 3:
        social_list = sorted(social_matched)
        cross_findings.append(IntelligenceFinding(
            entity=f"Social Footprint: {username} on {len(social_matched)} social platforms",
            type="Cross-Reference: Social Footprint",
            source="SocialSearch",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status=f"{len(social_matched)} social platforms",
            tags=["cross-reference", "social-footprint", username] + [f"xref-{p}" for p in social_list]
        ))

    return cross_findings


def extract_potential_usernames(target: str) -> list:
    candidates = set()
    original_target = target.strip().lower()
    domain = original_target

    is_url = domain.startswith("http")
    if is_url:
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path.strip("/")
        if path and "/" not in path:
            candidates.add(path)
        elif path:
            for seg in path.split("/"):
                if seg and not seg.startswith("_") and len(seg) >= 2:
                    candidates.add(seg)

    # Domain parts as username
    parts = domain.split(".")
    if len(parts) >= 2:
        candidates.add(parts[0])
    if len(parts) >= 3:
        candidates.add(parts[1])
    if len(parts) >= 4:
        candidates.add(parts[2])

    # Handle subdomains: "shop.example.com" -> "shop"
    if len(parts) >= 3 and parts[-1] in ("com", "org", "net", "io", "co", "app", "dev", "me"):
        for i in range(len(parts) - 2):
            candidates.add(parts[i])

    # Hyphen handling
    for p in parts:
        if "-" in p:
            candidates.add(p.replace("-", ""))
            candidates.add(p.replace("-", "_"))
            for sub in p.split("-"):
                if len(sub) >= 2:
                    candidates.add(sub)

    # Strip "blog" suffix
    if parts[0].endswith("blog") and len(parts[0]) > 4:
        candidates.add(parts[0][:-4])

    # Common prefixes
    for prefix in USERNAME_PREFIXES:
        prefix_pattern = f"{prefix}."
        if domain.startswith(prefix_pattern):
            stripped = domain[len(prefix_pattern):]
            if stripped and "." in stripped:
                core = stripped.split(".")[0]
                candidates.add(core)
        if parts[0].startswith(prefix) and len(parts[0]) > len(prefix):
            candidates.add(parts[0][len(prefix):])

    # Add the full TLD-stripped name and variations
    main_part = parts[0]
    candidates.add(main_part)
    candidates.add(main_part.capitalize())
    candidates.add(main_part.upper())

    # Company name from domain
    company_variations = [
        main_part,
        main_part + "hq",
        main_part + "labs",
        main_part + "app",
        main_part + "io",
        main_part + "corp",
        main_part + "inc",
        main_part.capitalize(),
        main_part + "team",
        main_part + "dev",
    ]
    for var in company_variations:
        candidates.add(var)

    # Sort by relevance: shorter, more common patterns first
    def relevance(c):
        score = 0
        if c == main_part:
            score += 100
        if c.islower():
            score += 10
        if "_" in c:
            score -= 5
        if len(c) < 4:
            score -= 3
        if c in company_variations:
            score += 5
        if c.startswith(tuple(USERNAME_PREFIXES)):
            score -= 2
        return -score

    sorted_candidates = sorted(candidates, key=relevance)

    return [c for c in sorted_candidates if 3 <= len(c) <= 30][:10]


async def check_domain_on_profiles(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    company_username = domain.split(".")[0] if "." in domain else domain

    soc_tasks = []
    for platform_name, url_template, category in [
        ("LinkedIn", "https://www.linkedin.com/company/{username}", "professional"),
        ("Facebook", "https://www.facebook.com/{username}", "social-media"),
        ("Twitter/X", "https://twitter.com/{username}", "social-media"),
        ("GitHub", "https://github.com/{username}", "development"),
        ("Instagram", "https://www.instagram.com/{username}", "social-media"),
        ("YouTube", "https://www.youtube.com/@{username}", "video"),
        ("Crunchbase", "https://www.crunchbase.com/organization/{username}", "business"),
        ("AngelList", "https://angel.co/company/{username}", "business"),
        ("PitchBook", "https://pitchbook.com/profiles/{username}", "business"),
        ("Glassdoor", "https://www.glassdoor.com/Overview/Working-at-{username}-EI_IE{username}.htm", "business"),
        ("ProductHunt", "https://www.producthunt.com/@{username}", "product"),
        ("GitLab", "https://gitlab.com/{username}", "development"),
        ("Bitbucket", "https://bitbucket.org/{username}", "development"),
        ("Docker Hub", "https://hub.docker.com/u/{username}", "development"),
        ("NPM", "https://www.npmjs.com/~{username}", "development"),
        ("PyPI", "https://pypi.org/user/{username}", "development"),
    ]:
        soc_tasks.append(
            check_platform(company_username, f"{platform_name} (Company/Org)",
                          url_template, category, client)
        )

    results = await asyncio.gather(*soc_tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    potential_usernames = extract_potential_usernames(domain)

    tasks = []
    # Search top usernames
    for username in potential_usernames[:5]:
        tasks.append(check_username_across_platforms(username, client))

    # Also check domain as company profile
    tasks.append(check_domain_on_profiles(domain, client))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    profile_count = sum(1 for f in findings if f.type.startswith("Social Profile:"))
    username_count = sum(1 for f in findings if "Username" in f.entity and "platform" in f.entity)

    findings.append(IntelligenceFinding(
        entity=f"Social Search: {profile_count} profiles across social platforms",
        type="Social Search Summary",
        source="SocialSearch",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{profile_count} profiles, {username_count} username matches, {len(potential_usernames)} usernames tried",
        raw_data=f"Usernames checked: {', '.join(potential_usernames)}",
        tags=["social-search", "summary"]
    ))

    return findings
