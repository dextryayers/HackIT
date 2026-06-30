import httpx
import re
import asyncio
import json
import math
from models import IntelligenceFinding
from datetime import datetime, timezone
from urllib.parse import urlparse

SOCIAL_PLATFORMS = [
    ("Twitter/X", "https://x.com/{u}", "profile", "social"),
    ("Instagram", "https://www.instagram.com/{u}/", "profile", "social"),
    ("Facebook", "https://www.facebook.com/{u}", "profile", "social"),
    ("TikTok", "https://www.tiktok.com/@{u}", "profile", "social"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "profile", "social"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "profile", "social"),
    ("LinkedIn", "https://www.linkedin.com/in/{u}", "profile", "professional"),
    ("YouTube", "https://www.youtube.com/@{u}", "channel", "social"),
    ("Twitch", "https://www.twitch.tv/{u}", "channel", "gaming"),
    ("Reddit", "https://www.reddit.com/user/{u}/", "profile", "social"),
    ("Tumblr", "https://{u}.tumblr.com", "blog", "social"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "profile", "social"),
    ("Mastodon.social", "https://mastodon.social/@{u}", "profile", "social"),
    ("Bluesky", "https://bsky.app/profile/{u}", "profile", "social"),
    ("Threads", "https://www.threads.net/@{u}", "profile", "social"),
    ("WhatsApp", "https://wa.me/{u}", "contact", "social"),
    ("Telegram", "https://t.me/{u}", "profile", "social"),
    ("Discord", "https://discord.com/users/{u}", "profile", "gaming"),
    ("Signal", "https://signal.me/#p/{u}", "contact", "social"),
    ("WeChat", "https://web.wechat.com/{u}", "profile", "social"),
    ("Clubhouse", "https://www.clubhouse.com/@{u}", "profile", "social"),
    ("Parler", "https://parler.com/profile/{u}", "profile", "social"),
    ("Gab", "https://gab.com/{u}", "profile", "social"),
    ("TruthSocial", "https://truthsocial.com/@{u}", "profile", "social"),
    ("Weibo", "https://www.weibo.com/{u}", "profile", "social"),
    ("QQ", "https://user.qzone.qq.com/{u}", "profile", "social"),
    ("VK", "https://vk.com/{u}", "profile", "social"),
    ("Odnoklassniki", "https://ok.ru/{u}", "profile", "social"),
    ("GitHub", "https://github.com/{u}", "profile", "dev"),
    ("GitLab", "https://gitlab.com/{u}", "profile", "dev"),
    ("Bitbucket", "https://bitbucket.org/{u}", "profile", "dev"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "profile", "dev"),
    ("NPM", "https://www.npmjs.com/~{u}", "profile", "dev"),
    ("PyPI", "https://pypi.org/user/{u}/", "profile", "dev"),
    ("RubyGems", "https://rubygems.org/profiles/{u}", "profile", "dev"),
    ("NuGet", "https://www.nuget.org/profiles/{u}", "profile", "dev"),
    ("Crates.io", "https://crates.io/users/{u}", "profile", "dev"),
    ("Packagist", "https://packagist.org/packages/{u}/", "profile", "dev"),
    ("Dev.to", "https://dev.to/{u}", "blog", "dev"),
    ("Medium", "https://medium.com/@{u}", "blog", "dev"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "profile", "dev"),
    ("Stack Overflow", "https://stackoverflow.com/users/{u}", "profile", "dev"),
    ("CodePen", "https://codepen.io/{u}", "profile", "dev"),
    ("Replit", "https://replit.com/@{u}", "profile", "dev"),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{u}", "profile", "dev"),
    ("SourceForge", "https://sourceforge.net/u/{u}", "profile", "dev"),
    ("HackerOne", "https://hackerone.com/{u}", "profile", "dev"),
    ("Bugcrowd", "https://bugcrowd.com/{u}", "profile", "dev"),
    ("HackerRank", "https://www.hackerrank.com/{u}", "profile", "dev"),
    ("LeetCode", "https://leetcode.com/{u}/", "profile", "dev"),
    ("Codeforces", "https://codeforces.com/profile/{u}", "profile", "dev"),
    ("TopCoder", "https://www.topcoder.com/members/{u}", "profile", "dev"),
    ("CTFtime", "https://ctftime.org/user/{u}", "profile", "dev"),
    ("TryHackMe", "https://tryhackme.com/p/{u}", "profile", "dev"),
    ("HackTheBox", "https://app.hackthebox.com/profile/{u}", "profile", "dev"),
    ("Glitch", "https://glitch.com/@{u}", "profile", "dev"),
    ("Codewars", "https://www.codewars.com/users/{u}", "profile", "dev"),
    ("Exercism", "https://exercism.org/profiles/{u}", "profile", "dev"),
    ("Kaggle", "https://www.kaggle.com/{u}", "profile", "dev"),
    ("Hugging Face", "https://huggingface.co/{u}", "profile", "dev"),
    ("Google Developer", "https://developers.google.com/profile/u/{u}", "profile", "dev"),
    ("Microsoft Learn", "https://learn.microsoft.com/en-us/users/{u}", "profile", "dev"),
    ("Keybase", "https://keybase.io/{u}", "profile", "dev"),
    ("Behance", "https://www.behance.net/{u}", "portfolio", "creative"),
    ("Dribbble", "https://dribbble.com/{u}", "portfolio", "creative"),
    ("ArtStation", "https://www.artstation.com/{u}", "portfolio", "creative"),
    ("DeviantArt", "https://www.deviantart.com/{u}", "portfolio", "creative"),
    ("Figma", "https://www.figma.com/@{u}", "profile", "creative"),
    ("SoundCloud", "https://soundcloud.com/{u}", "profile", "creative"),
    ("Bandcamp", "https://bandcamp.com/{u}", "profile", "creative"),
    ("Mixcloud", "https://www.mixcloud.com/{u}/", "profile", "creative"),
    ("Spotify", "https://open.spotify.com/user/{u}", "profile", "creative"),
    ("Imgur", "https://imgur.com/user/{u}", "profile", "creative"),
    ("GIPHY", "https://giphy.com/{u}", "profile", "creative"),
    ("VSCO", "https://vsco.co/{u}", "profile", "creative"),
    ("Adobe Portfolio", "https://{u}.myportfolio.com", "portfolio", "creative"),
    ("Carbonmade", "https://{u}.carbonmade.com", "portfolio", "creative"),
    ("Wix", "https://{u}.wixsite.com/website", "site", "creative"),
    ("Squarespace", "https://{u}.squarespace.com", "site", "creative"),
    ("AngelList", "https://angel.co/u/{u}", "profile", "professional"),
    ("Crunchbase", "https://www.crunchbase.com/person/{u}", "profile", "professional"),
    ("About.me", "https://about.me/{u}", "profile", "professional"),
    ("Linktree", "https://linktr.ee/{u}", "profile", "professional"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{u}", "profile", "professional"),
    ("Patreon", "https://www.patreon.com/{u}", "profile", "professional"),
    ("Ko-fi", "https://ko-fi.com/{u}", "profile", "professional"),
    ("ProductHunt", "https://www.producthunt.com/@{u}", "profile", "professional"),
    ("IndieHackers", "https://www.indiehackers.com/{u}", "profile", "professional"),
    ("Calendly", "https://calendly.com/{u}", "profile", "professional"),
    ("Indeed", "https://www.indeed.com/r/{u}", "profile", "professional"),
    ("Glassdoor", "https://www.glassdoor.com/Overview/working-at-{u}-EI_IE{u}.htm", "profile", "professional"),
    ("Google Scholar", "https://scholar.google.com/citations?user={u}", "profile", "professional"),
    ("ResearchGate", "https://www.researchgate.net/profile/{u}", "profile", "professional"),
    ("Academia.edu", "https://independent.academia.edu/{u}", "profile", "professional"),
    ("ORCID", "https://orcid.org/{u}", "profile", "professional"),
    ("Loop", "https://loop.frontiersin.org/people/{u}", "profile", "professional"),
    ("Hashnode", "https://hashnode.com/@{u}", "blog", "dev"),
    ("Steam", "https://steamcommunity.com/id/{u}", "profile", "gaming"),
    ("Epic Games", "https://www.epicgames.com/id/{u}", "profile", "gaming"),
    ("Xbox Live", "https://www.xboxgamertag.com/search/{u}", "profile", "gaming"),
    ("PlayStation", "https://psnprofiles.com/{u}", "profile", "gaming"),
    ("Nintendo", "https://en-americas-support.nintendo.com/user/{u}", "profile", "gaming"),
    ("Chess.com", "https://www.chess.com/member/{u}", "profile", "gaming"),
    ("Lichess", "https://lichess.org/@/{u}", "profile", "gaming"),
    ("Speedrun.com", "https://www.speedrun.com/users/{u}", "profile", "gaming"),
    ("CurseForge", "https://www.curseforge.com/members/{u}", "profile", "gaming"),
    ("Riot Games", "https://www.riotgames.com/en/user/{u}", "profile", "gaming"),
    ("Battle.net", "https://battle.net/{u}", "profile", "gaming"),
    ("Origin", "https://www.origin.com/{u}", "profile", "gaming"),
    ("Uplay", "https://club.ubisoft.com/en-US/profile/{u}", "profile", "gaming"),
    ("Minecraft", "https://namemc.com/profile/{u}", "profile", "gaming"),
    ("Roblox", "https://www.roblox.com/user.aspx?username={u}", "profile", "gaming"),
    ("Kongregate", "https://www.kongregate.com/accounts/{u}", "profile", "gaming"),
    ("Etsy", "https://www.etsy.com/shop/{u}", "shop", "shopping"),
    ("eBay", "https://www.ebay.com/usr/{u}", "profile", "shopping"),
    ("Amazon Wishlist", "https://www.amazon.com/gp/profile/{u}", "profile", "shopping"),
    ("Redbubble", "https://www.redbubble.com/people/{u}", "shop", "shopping"),
    ("Mercari", "https://www.mercadolibre.com.ar/perfil/{u}", "profile", "shopping"),
    ("Poshmark", "https://poshmark.com/closet/{u}", "shop", "shopping"),
    ("Depop", "https://www.depop.com/{u}", "shop", "shopping"),
    ("Vinted", "https://www.vinted.com/member/{u}", "profile", "shopping"),
    ("Grailed", "https://www.grailed.com/{u}", "profile", "shopping"),
    ("StockX", "https://stockx.com/{u}", "profile", "shopping"),
    ("Fiverr", "https://www.fiverr.com/{u}", "profile", "professional"),
    ("Upwork", "https://www.upwork.com/freelancers/~{u}", "profile", "professional"),
    ("Freelancer", "https://www.freelancer.com/u/{u}", "profile", "professional"),
    ("Shazam", "https://www.shazam.com/artist/{u}", "profile", "creative"),
    ("Genius", "https://genius.com/{u}", "profile", "creative"),
    ("Last.fm", "https://www.last.fm/user/{u}", "profile", "creative"),
    ("RateYourMusic", "https://rateyourmusic.com/~{u}", "profile", "creative"),
    ("Discogs", "https://www.discogs.com/user/{u}", "profile", "creative"),
    ("BitcoinTalk", "https://bitcointalk.org/index.php?action=profile;u={u}", "forum", "crypto"),
    ("Gitcoin", "https://gitcoin.co/{u}", "profile", "crypto"),
    ("Etherscan", "https://etherscan.io/address/{u}", "address", "crypto"),
    ("Keybase (crypto)", "https://keybase.io/{u}/sigchain", "profile", "crypto"),
    ("Solscan", "https://solscan.io/account/{u}", "address", "crypto"),
    ("BscScan", "https://bscscan.com/address/{u}", "address", "crypto"),
    ("DeBank", "https://debank.com/profile/{u}", "profile", "crypto"),
    ("Zapper", "https://zapper.xyz/account/{u}", "profile", "crypto"),
    ("Zerion", "https://zerion.io/{u}", "profile", "crypto"),
    ("Rainbow Wallet", "https://rainbow.me/{u}", "profile", "crypto"),
    ("Tinder", "https://tinder.com/@/{u}", "profile", "dating"),
    ("Bumble", "https://bumble.com/profile/{u}", "profile", "dating"),
    ("OkCupid", "https://www.okcupid.com/profile/{u}", "profile", "dating"),
    ("Hinge", "https://hinge.co/profile/{u}", "profile", "dating"),
    ("Grindr", "https://grindr.com/profile/{u}", "profile", "dating"),
    ("Badoo", "https://badoo.com/{u}", "profile", "dating"),
    ("Line", "https://line.me/{u}", "profile", "social"),
    ("KakaoTalk", "https://open.kakao.com/o/{u}", "profile", "social"),
    ("Slack", "https://{u}.slack.com", "workspace", "social"),
    ("VK", "https://vk.com/{u}", "profile", "social"),
    ("Ok.ru", "https://ok.ru/{u}", "profile", "social"),
    ("Weibo", "https://www.weibo.com/{u}", "profile", "social"),
    ("QQ", "https://user.qzone.qq.com/{u}", "profile", "social"),
    ("Douban", "https://www.douban.com/people/{u}/", "profile", "social"),
    ("Zhihu", "https://www.zhihu.com/people/{u}", "profile", "social"),
    ("Bilibili", "https://space.bilibili.com/{u}", "channel", "social"),
    ("Xiaohongshu", "https://www.xiaohongshu.com/user/{u}", "profile", "social"),
    ("Douyin", "https://www.douyin.com/user/{u}", "profile", "social"),
    ("Kuaishou", "https://www.kuaishou.com/profile/{u}", "profile", "social"),
    ("Vimeo", "https://vimeo.com/{u}", "profile", "creative"),
    ("Dailymotion", "https://www.dailymotion.com/{u}", "profile", "creative"),
    ("Youku", "https://youku.com/{u}", "profile", "creative"),
    ("Twitlonger", "https://www.twitlonger.com/user/{u}", "profile", "social"),
    ("Gettr", "https://gettr.com/user/{u}", "profile", "social"),
    ("Minds", "https://www.minds.com/{u}", "profile", "social"),
    ("Gab", "https://gab.com/{u}", "profile", "social"),
    ("Parler", "https://parler.com/profile/{u}", "profile", "social"),
    ("MeWe", "https://mewe.com/i/{u}", "profile", "social"),
    ("Rumble", "https://rumble.com/user/{u}", "profile", "social"),
    ("Odysee", "https://odysee.com/@{u}", "profile", "social"),
    ("Bitchute", "https://www.bitchute.com/channel/{u}", "channel", "social"),
    ("DTube", "https://d.tube/#!/c/{u}", "channel", "social"),
    ("Peertube", "https://peertube.tv/accounts/{u}", "profile", "social"),
    ("Write.as", "https://write.as/{u}", "blog", "social"),
    ("BearBlog", "https://{u}.bearblog.dev", "blog", "social"),
    ("Micro.blog", "https://micro.blog/{u}", "blog", "social"),
    ("Plurk", "https://www.plurk.com/{u}", "profile", "social"),
    ("Mastodon.social", "https://mastodon.social/@{u}", "profile", "social"),
    ("Hometown", "https://hometown.{u}", "profile", "social"),
    ("Pixelfed", "https://pixelfed.social/{u}", "profile", "social"),
    ("Friendica", "https://friendica.{u}", "profile", "social"),
    ("Diaspora", "https://diasp.org/u/{u}", "profile", "social"),
    ("Hubzilla", "https://hubzilla.{u}", "profile", "social"),
    ("Mobilizon", "https://mobilizon.{u}", "profile", "social"),
    ("WordPress", "https://{u}.wordpress.com", "blog", "creative"),
    ("Blogger", "https://{u}.blogspot.com", "blog", "creative"),
    ("Ghost", "https://{u}.ghost.io", "blog", "creative"),
    ("Substack", "https://{u}.substack.com", "blog", "creative"),
    ("Medium", "https://medium.com/@{u}", "blog", "creative"),
    ("Telegraph", "https://telegra.ph/{u}", "blog", "creative"),
    ("LinkedIn Company", "https://www.linkedin.com/company/{u}", "company", "professional"),
    ("Crunchbase", "https://www.crunchbase.com/organization/{u}", "organization", "professional"),
    ("Glassdoor", "https://www.glassdoor.com/Overview/Working-at-{u}-EI_IE{u}.htm", "company", "professional"),
    ("PitchBook", "https://pitchbook.com/profiles/{u}", "company", "professional"),
    ("Owler", "https://www.owler.com/company/{u}", "company", "professional"),
    ("Trustpilot", "https://www.trustpilot.com/review/{u}", "review", "professional"),
    ("G2", "https://www.g2.com/products/{u}", "review", "professional"),
    ("Capterra", "https://www.capterra.com/p/{u}", "review", "professional"),
    ("Yelp", "https://www.yelp.com/biz/{u}", "review", "professional"),
    ("Google Maps", "https://maps.google.com/?cid={u}", "location", "professional"),
    ("Foursquare", "https://foursquare.com/v/{u}", "location", "professional"),
    ("Goodreads", "https://www.goodreads.com/{u}", "profile", "creative"),
    ("LibraryThing", "https://www.librarything.com/profile/{u}", "profile", "creative"),
    ("IMDb", "https://www.imdb.com/user/ur{u}", "profile", "creative"),
    ("Letterboxd", "https://letterboxd.com/{u}/", "profile", "creative"),
    ("Trakt", "https://trakt.tv/users/{u}", "profile", "creative"),
    ("MyAnimeList", "https://myanimelist.net/profile/{u}", "profile", "creative"),
    ("AniList", "https://anilist.co/user/{u}", "profile", "creative"),
    ("Kitsu", "https://kitsu.io/users/{u}", "profile", "creative"),
    ("TV Time", "https://www.tvtime.com/en/user/{u}", "profile", "creative"),
    ("DriveTribe", "https://drivetribe.com/u/{u}", "profile", "creative"),
    ("Meetup", "https://www.meetup.com/members/{u}/", "profile", "professional"),
    ("Eventbrite", "https://www.eventbrite.com/o/{u}", "organization", "professional"),
    ("ZoomInfo", "https://www.zoominfo.com/p/{u}", "profile", "professional"),
    ("Apollo.io", "https://www.apollo.io/{u}", "profile", "professional"),
    ("Lusha", "https://www.lusha.com/profile/{u}", "profile", "professional"),
    ("ProtonMail", "https://proton.me/{u}", "profile", "dev"),
    ("Tutanota", "https://tutanota.com/{u}", "profile", "dev"),
    ("Startpage", "https://www.startpage.com/{u}", "profile", "dev"),
    ("DuckDuckGo", "https://duckduckgo.com/{u}", "profile", "dev"),
    ("Brave", "https://brave.com/{u}", "profile", "dev"),
    ("Observable", "https://observablehq.com/@{u}", "profile", "dev"),
    ("Deepnote", "https://deepnote.com/@{u}", "profile", "dev"),
    ("Colab", "https://colab.research.google.com/github/{u}", "profile", "dev"),
    ("Kaggle", "https://www.kaggle.com/{u}", "profile", "dev"),
    ("DataCamp", "https://www.datacamp.com/portfolio/{u}", "profile", "dev"),
    ("Data.world", "https://data.world/{u}", "profile", "dev"),
    ("Tableau Public", "https://public.tableau.com/profile/{u}", "profile", "dev"),
    ("Power BI", "https://community.powerbi.com/t5/user/viewprofilepage/user-id/{u}", "profile", "dev"),
    ("Grafana", "https://grafana.com/orgs/{u}", "organization", "dev"),
    ("Prometheus", "https://prometheus.io/community/{u}", "profile", "dev"),
    ("Open Collective", "https://opencollective.com/{u}", "organization", "dev"),
    ("GitHub Sponsors", "https://github.com/sponsors/{u}", "profile", "dev"),
    ("Liberapay", "https://liberapay.com/{u}", "profile", "dev"),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{u}", "profile", "dev"),
    ("Waze", "https://www.waze.com/user/{u}", "profile", "dev"),
    ("Strava", "https://www.strava.com/athletes/{u}", "profile", "creative"),
    ("Runkeeper", "https://runkeeper.com/user/{u}", "profile", "creative"),
    ("Fitbit", "https://www.fitbit.com/user/{u}", "profile", "creative"),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{u}", "profile", "creative"),
    ("AllTrails", "https://www.alltrails.com/members/{u}", "profile", "creative"),
    ("TrainerRoad", "https://trainerroad.com/user/{u}", "profile", "creative"),
    ("Zwift", "https://zwift.com/profile/{u}", "profile", "creative"),
    ("Peloton", "https://www.onepeloton.com/profile/{u}", "profile", "creative"),
    ("Coursera", "https://www.coursera.org/user/{u}", "profile", "professional"),
    ("edX", "https://www.edx.org/user/{u}", "profile", "professional"),
    ("Udemy", "https://www.udemy.com/user/{u}", "profile", "professional"),
    ("Skillshare", "https://www.skillshare.com/profile/{u}", "profile", "professional"),
    ("Pluralsight", "https://app.pluralsight.com/profile/{u}", "profile", "professional"),
    ("Codecademy", "https://www.codecademy.com/profiles/{u}", "profile", "dev"),
    ("FreeCodeCamp", "https://www.freecodecamp.org/{u}", "profile", "dev"),
    ("The Odin Project", "https://www.theodinproject.com/users/{u}", "profile", "dev"),
    ("Frontend Mentor", "https://www.frontendmentor.io/profile/{u}", "profile", "dev"),
    ("CSS-Tricks", "https://css-tricks.com/author/{u}", "profile", "dev"),
    ("Codementor", "https://www.codementor.io/@{u}", "profile", "dev"),
    ("Hackaday", "https://hackaday.io/{u}", "profile", "dev"),
    ("Instructables", "https://www.instructables.com/member/{u}", "profile", "dev"),
    ("Thingiverse", "https://www.thingiverse.com/{u}", "profile", "dev"),
    ("Printables", "https://www.printables.com/@{u}", "profile", "dev"),
    ("MyMiniFactory", "https://www.myminifactory.com/users/{u}", "profile", "dev"),
    ("Pastebin", "https://pastebin.com/u/{u}", "profile", "dev"),
    ("Hastebin", "https://hastebin.skyra.pw/{u}", "profile", "dev"),
    ("Rentry.co", "https://rentry.co/{u}", "profile", "dev"),
    ("Carbon.now.sh", "https://carbon.now.sh/{u}", "profile", "dev"),
    ("JSFiddle", "https://jsfiddle.net/user/{u}/", "profile", "dev"),
    ("CodeSandbox", "https://codesandbox.io/u/{u}", "profile", "dev"),
    ("Glitch", "https://glitch.com/@{u}", "profile", "dev"),
    ("StackBlitz", "https://stackblitz.com/@{u}", "profile", "dev"),
    ("Gitpod", "https://gitpod.io/{u}", "profile", "dev"),
    ("Codiga", "https://codiga.io/hub/user/{u}", "profile", "dev"),
    ("SonarCloud", "https://sonarcloud.io/user/{u}", "profile", "dev"),
    ("CodeClimate", "https://codeclimate.com/github/{u}", "profile", "dev"),
    ("Coveralls", "https://coveralls.io/{u}", "profile", "dev"),
    ("Travis CI", "https://travis-ci.com/{u}", "profile", "dev"),
    ("CircleCI", "https://circleci.com/{u}", "profile", "dev"),
    ("GitHub Actions", "https://github.com/{u}/{u}/actions", "repo", "dev"),
    ("Read the Docs", "https://readthedocs.org/profiles/{u}/", "profile", "dev"),
    ("GitBook", "https://app.gitbook.com/@{u}", "profile", "dev"),
    ("Notion", "https://notion.so/{u}", "profile", "dev"),
    ("ClickUp", "https://app.clickup.com/{u}", "profile", "dev"),
    ("Monday.com", "https://monday.com/profile/{u}", "profile", "dev"),
    ("Asana", "https://app.asana.com/0/profile/{u}", "profile", "dev"),
    ("Trello", "https://trello.com/{u}", "profile", "dev"),
    ("Jira", "https://{u}.atlassian.net", "workspace", "dev"),
    ("Confluence", "https://{u}.atlassian.net/wiki", "workspace", "dev"),
    ("Basecamp", "https://basecamp.com/{u}", "project", "dev"),
    ("Notion", "https://{u}.notion.site", "site", "dev"),
    ("Linear", "https://linear.app/{u}", "profile", "dev"),
    ("Canny", "https://{u}.canny.io", "company", "dev"),
    ("Figma Community", "https://www.figma.com/community/file/{u}", "file", "creative"),
    ("Sketch", "https://sketch.com/{u}", "profile", "creative"),
    ("XD", "https://xd.adobe.com/{u}", "profile", "creative"),
    ("Photopea", "https://photopea.com/{u}", "profile", "creative"),
    ("Unsplash", "https://unsplash.com/@{u}", "profile", "creative"),
    ("500px", "https://500px.com/{u}", "profile", "creative"),
    ("Pexels", "https://www.pexels.com/@{u}", "profile", "creative"),
    ("Pixabay", "https://pixabay.com/users/{u}/", "profile", "creative"),
    ("Freepik", "https://www.freepik.com/author/{u}", "profile", "creative"),
    ("Shutterstock", "https://www.shutterstock.com/g/{u}", "profile", "creative"),
    ("Adobe Stock", "https://stock.adobe.com/contributor/{u}", "profile", "creative"),
]

LEETSPEAK_MAP = {
    'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5',
    't': '7', 'b': '8', 'g': '9', 'z': '2',
}

PREFIXES = ['mr_', 'ms_', 'dr_', 'the', 'real', 'official', 'its', 'im_', 'i_am_', 'x_', 'its_']
SUFFIXES = ['_', '_1', '_123', '_io', '_app', '_hq', '_labs', '_dev', '_pro', '_xyz']
YEARS = ['2020', '2021', '2022', '2023', '2024', '2025', '2026']

RATE_LIMIT_PATTERNS = [
    (r'429', "HTTP 429"),
    (r'rate.?limit', "Rate Limit Text"),
    (r'too many requests', "Too Many Requests"),
    (r'retry.?after', "Retry-After"),
    (r'captcha', "CAPTCHA"),
    (r'blocked', "Blocked"),
    (r'access.?denied', "Access Denied"),
    (r'please.?wait', "Please Wait"),
    (r'slow.?down', "Slow Down"),
    (r'try again later', "Try Again Later"),
    (r'error.?429', "Error 429"),
]

CATEGORY_NAMES = {
    "social": "Social Media",
    "dev": "Developer Platforms",
    "professional": "Professional/Work",
    "creative": "Creative/Media",
    "gaming": "Gaming",
    "shopping": "Marketplaces",
    "crypto": "Cryptocurrency",
    "dating": "Dating",
    "forum": "Forums",
    "blog": "Blogs",
}

_rate_limit_state: dict[str, dict] = {}
_cross_platform_names: dict[str, list[dict]] = {}


def normalize_username(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r'[^a-z0-9._-]', '', raw)
    return raw[:30]


def leetspeak_variants(base: str) -> set:
    variants = set()
    indices = [i for i, ch in enumerate(base) if ch in LEETSPEAK_MAP]
    for idx in indices:
        variant = base[:idx] + LEETSPEAK_MAP[base[idx]] + base[idx+1:]
        variants.add(variant)
    for i in range(len(indices)):
        for j in range(i+1, len(indices)):
            vi = list(base)
            vi[indices[i]] = LEETSPEAK_MAP[base[indices[i]]]
            vi[indices[j]] = LEETSPEAK_MAP[base[indices[j]]]
            variants.add(''.join(vi))
    for i in range(len(indices)):
        for j in range(i+1, len(indices)):
            for k in range(j+1, len(indices)):
                vi = list(base)
                vi[indices[i]] = LEETSPEAK_MAP[base[indices[i]]]
                vi[indices[j]] = LEETSPEAK_MAP[base[indices[j]]]
                vi[indices[k]] = LEETSPEAK_MAP[base[indices[k]]]
                variants.add(''.join(vi))
    return variants


def generate_permutations(base: str) -> list:
    perms = set()
    perms.add(base)
    base_clean = base

    perms.update(leetspeak_variants(base))

    for v in list(perms):
        for year in YEARS:
            perms.add(f"{v}{year}")
            perms.add(f"{v}_{year}")

    for v in list(perms):
        for prefix in PREFIXES:
            perms.add(f"{prefix}{v}")

    for v in list(perms):
        for suffix in SUFFIXES:
            perms.add(f"{v}{suffix}")

    if base.isalpha():
        perms.add(base.capitalize())
        perms.add(base.upper())

    for joiner in ['_', '.', '-']:
        if joiner in base:
            for repl in ['', '_', '.', '-']:
                if repl != joiner:
                    perms.add(base.replace(joiner, repl))

    tag_variants = set()
    for v in list(perms):
        tag_variants.add(f"@{v}")
        tag_variants.add(f"/u/{v}")
        tag_variants.add(f"user/{v}")
    perms.update(tag_variants)

    return sorted(perms)


def _get_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


async def _apply_adaptive_delay(url: str):
    domain = _get_domain(url)
    if not domain:
        return
    state = _rate_limit_state.get(domain)
    if state and state['current_delay'] > 0:
        await asyncio.sleep(state['current_delay'])


def _record_rate_limit(url: str, status_code: int):
    domain = _get_domain(url)
    if not domain:
        return
    if domain not in _rate_limit_state:
        _rate_limit_state[domain] = {'current_delay': 0.0, 'consecutive': 0, 'last_429': None}
    state = _rate_limit_state[domain]
    if status_code == 429:
        state['consecutive'] += 1
        state['last_429'] = datetime.now(timezone.utc).isoformat()
        delay = min(30.0, 1.0 * (2 ** (state['consecutive'] - 1)))
        state['current_delay'] = delay
    elif status_code in (403, 401):
        state['consecutive'] += 0.5
        state['current_delay'] = min(10.0, state['current_delay'] + 0.5)
    else:
        if state['consecutive'] > 0:
            state['consecutive'] = max(0, state['consecutive'] - 0.5)
        if state['consecutive'] == 0:
            state['current_delay'] = 0.0


async def check_platform(client: httpx.AsyncClient, name: str, url: str, ptype: str, category: str, username: str) -> IntelligenceFinding | None:
    try:
        await _apply_adaptive_delay(url)
        resp = await client.get(url, timeout=8.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        _record_rate_limit(url, resp.status_code)

        if resp.status_code == 200:
            ext = extract_profile_details(resp.text, name)
            extra_findings = []
            raw = f"URL: {url} | Status: {resp.status_code}"
            if ext:
                raw += " | " + ext

            structured = extract_structured_details(resp.text)
            person_name = structured.get('display_name', '') or structured.get('title', '')
            if person_name and person_name != username:
                normalized_name = person_name.strip().lower()[:50]
                if normalized_name not in _cross_platform_names:
                    _cross_platform_names[normalized_name] = []
                _cross_platform_names[normalized_name].append({
                    'platform': name,
                    'url': url,
                    'username': username,
                })

            age_str, age_days = estimate_account_age(resp.text)
            if age_str:
                raw += f" | age={age_str}"

            activity = detect_activity_level(resp.text)
            if activity:
                raw += f" | activity={activity}"

            if structured.get('followers'):
                raw += f" | followers={structured['followers']}"
            if structured.get('following'):
                raw += f" | following={structured['following']}"
            if structured.get('bio'):
                raw += f" | bio={structured['bio'][:80]}"
            if structured.get('website'):
                raw += f" | site={structured['website'][:60]}"
            if structured.get('location'):
                raw += f" | location={structured['location'][:40]}"
            if structured.get('email'):
                raw += f" | email={structured['email']}"

            return IntelligenceFinding(
                entity=f"@{username} on {name} ({url})",
                type=f"Social Alias: {name}",
                source="SocialAliasHunter",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Found",
                resolution=f"Category: {category}, Type: {ptype}",
                raw_data=raw,
                tags=[category, ptype, "social-alias", "found"],
            )
        if resp.status_code == 403 or resp.status_code == 401:
            return IntelligenceFinding(
                entity=f"@{username} on {name} ({url})",
                type=f"Social Alias: {name}",
                source="SocialAliasHunter",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Restricted",
                resolution=f"HTTP {resp.status_code} - account may exist but is private/restricted",
                raw_data=f"URL: {url} | Status: {resp.status_code}",
                tags=[category, ptype, "social-alias", "restricted"],
            )
        for rl_pat, rl_name in RATE_LIMIT_PATTERNS:
            if re.search(rl_pat, resp.text, re.IGNORECASE) or re.search(rl_pat, str(resp.status_code)):
                return IntelligenceFinding(
                    entity=f"Rate limiting detected on {name} for {username}",
                    type="Rate Limit Detection",
                    source="SocialAliasHunter",
                    confidence="Medium",
                    color="red",
                    threat_level="Informational",
                    status="Rate Limited",
                    resolution=rl_name,
                    raw_data=f"URL: {url} | Pattern: {rl_pat}",
                    tags=["rate-limit", name.lower().replace("/", "-")],
                )
    except httpx.TimeoutException:
        return IntelligenceFinding(
            entity=f"Timeout checking {name} for {username}",
            type="Social Alias Timeout",
            source="SocialAliasHunter",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Timeout",
            resolution=f"URL: {url}",
            tags=["timeout"],
        )
    except Exception:
        pass
    return None


def extract_profile_details(html: str, platform: str) -> str:
    details = []
    name_patterns = [
        (r'<title>([^<]+)</title>', 'title'),
        (r'"name"\s*:\s*"([^"]+)"', 'json-name'),
        (r'"full_name"\s*:\s*"([^"]+)"', 'json-fullname'),
        (r'<meta[^>]+name="description"[^>]+content="([^"]+)"', 'meta-desc'),
        (r'<meta[^>]+property="og:title"[^>]+content="([^"]+)"', 'og-title'),
        (r'"displayName"\s*:\s*"([^"]+)"', 'display-name'),
        (r'"username"\s*:\s*"([^"]+)"', 'json-username'),
        (r'"screen_name"\s*:\s*"([^"]+)"', 'screen-name'),
        (r'<meta[^>]+name="twitter:title"[^>]+content="([^"]+)"', 'tw-title'),
        (r'"realName"\s*:\s*"([^"]+)"', 'real-name'),
        (r'"display_name"\s*:\s*"([^"]+)"', 'display-name-json'),
        (r'"nickname"\s*:\s*"([^"]+)"', 'nickname'),
    ]
    for pat, label in name_patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            val = m.group(1)[:100]
            details.append(f"{label}={val}")
            break
    return " | ".join(details) if details else ""


def extract_structured_details(html: str) -> dict:
    result = {
        'title': '',
        'display_name': '',
        'bio': '',
        'followers': '',
        'following': '',
        'joined': '',
        'website': '',
        'email': '',
        'location': '',
        'posts_count': '',
        'likes_count': '',
    }
    title_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    if title_m:
        result['title'] = title_m.group(1).strip()[:100]
    for key, pat in [
        ('display_name', r'"display_name"\s*:\s*"([^"]+)"'),
        ('display_name', r'"displayName"\s*:\s*"([^"]+)"'),
        ('display_name', r'"full_name"\s*:\s*"([^"]+)"'),
        ('display_name', r'"realName"\s*:\s*"([^"]+)"'),
        ('display_name', r'"name"\s*:\s*"([^"]+)"'),
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            result['display_name'] = m.group(1)[:80]
            break
    bio_m = re.search(r'<meta[^>]+name="description"[^>]+content="([^"]{20,300})"', html, re.IGNORECASE)
    if bio_m:
        result['bio'] = bio_m.group(1)[:200]
    for key, pat in [
        ('followers', r'["\']followers["\'][^:]*:\s*["\']?(\d[\d,.KkMmBb]*)'),
        ('followers', r'(?:followers?|subscribers?|fans?)\s*:?\s*([\d,.KkMmBb]+)'),
        ('followers', r'"follower_count"\s*:\s*(\d+)'),
        ('followers', r'"followersCount"\s*:\s*(\d+)'),
        ('followers', r'"followers"\s*:\s*(\d+)'),
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            result['followers'] = m.group(1)
            break
    for key, pat in [
        ('following', r'["\']following["\'][^:]*:\s*["\']?(\d[\d,.KkMmBb]*)'),
        ('following', r'(?:following)\s*:?\s*([\d,.KkMmBb]+)'),
        ('following', r'"following_count"\s*:\s*(\d+)'),
        ('following', r'"friendsCount"\s*:\s*(\d+)'),
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            result['following'] = m.group(1)
            break
    join_pats = [
        (r'(?:joined|member since|registered|created_at|createdAt)\s*:?\s*["\']?(\w+\s+\d{4})'),
        (r'(?:joined|member since|registered)\s*:?\s*["\']?(\d{4}-\d{2}-\d{2})'),
        (r'"createdAt"\s*:\s*"(\d{4}-\d{2}-\d{2})'),
        (r'"join_date"\s*:\s*"([^"]+)"'),
        (r'"registered"\s*:\s*"([^"]+)"'),
    ]
    for pat in join_pats:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            result['joined'] = m.group(1)
            break
    for key, pat in [
        ('website', r'(?:website|url|link|site)\s*:?\s*"?((?:https?://)[^"\s<]+)'),
        ('website', r'"website"\s*:\s*"([^"]+)"'),
        ('website', r'"url"\s*:\s*"([^"]+)"'),
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            val = m.group(1)
            if not val.startswith('http'):
                continue
            result['website'] = val[:80]
            break
    email_pats = [
        (r'[\w.+-]+@[\w-]+\.[\w.-]+'),
        (r'"email"\s*:\s*"([^"]+)"'),
        (r'"email_address"\s*:\s*"([^"]+)"'),
    ]
    for pat in email_pats:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            val = m.group(0) if not m.lastindex else m.group(1)
            if '@' in val and not val.startswith('"'):
                result['email'] = val[:60]
                break
    loc_pats = [
        (r'(?:location|city|country)\s*:?\s*["\']?([A-Z][a-z]+(?:\s*,\s*[A-Z][a-z]+)?)'),
        (r'"location"\s*:\s*"([^"]+)"'),
        (r'"locality"\s*:\s*"([^"]+)"'),
    ]
    for pat in loc_pats:
        m = re.search(pat, html)
        if m:
            val = m.group(1).strip()
            if 2 < len(val) < 60:
                result['location'] = val
                break
    for key, pat in [
        ('posts_count', r'["\'](?:posts|tweets| statuses)["\'][^:]*:\s*(\d+)'),
        ('posts_count', r'"statuses_count"\s*:\s*(\d+)'),
        ('likes_count', r'"favourites_count"\s*:\s*(\d+)'),
        ('likes_count', r'"likes_count"\s*:\s*(\d+)'),
    ]:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            result[key] = m.group(1)
            break
    return result


def estimate_account_age(html: str) -> tuple:
    patterns = [
        r'(?:joined|member since|registered|created_at|createdAt)\s*:?\s*["\']?(\w+\s+\d{4})',
        r'(?:joined|member since|registered)\s*:?\s*["\']?(\d{4})',
        r'"createdAt"\s*:\s*"(\d{4}-\d{2}-\d{2})',
        r'"join_date"\s*:\s*"(\d{4}-\d{2}-\d{2})',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            date_str = m.group(1)
            try:
                for fmt in ['%Y-%m-%d', '%Y', '%B %Y', '%b %Y']:
                    try:
                        dt = datetime.strptime(date_str[:len(fmt.replace('%B', '1234567890').replace('%b', '123')) if '%B' in fmt or '%b' in fmt else len(date_str)], fmt)
                        now = datetime.now()
                        days = (now - dt).days
                        if days > 0:
                            years = days // 365
                            if years > 0:
                                return f"{years}y {days % 365}d", days
                            return f"{days}d", days
                    except ValueError:
                        continue
            except Exception:
                pass
    return "", 0


def detect_activity_level(html: str) -> str:
    inactive_patterns = [
        r'last active.*?(?:years?|months? ago)',
        r'last seen.*?(?:years?|months? ago)',
        r'joined.*?20(?:1[0-9]|20)',
        r'no (?:recent|new) (?:activity|posts|content)',
        r'inactive',
        r'this account has been (?:deactivated|suspended|deleted)',
    ]
    active_patterns = [
        r'last active.*?(?:just now|minutes? ago|hours? ago|days? ago)',
        r'last seen.*?(?:just now|minutes? ago|hours? ago|days? ago)',
        r'online now',
        r'active now',
        r'seen recently',
        r'(?:posts|tweets)\s*:?\s*[\d,]+',
        r'"statuses_count"\s*:\s*[1-9]\d*',
    ]
    for pat in inactive_patterns:
        if re.search(pat, html, re.IGNORECASE):
            return "inactive"
    for pat in active_patterns:
        if re.search(pat, html, re.IGNORECASE):
            return "active"
    return ""


def calculate_privacy_risk_score(findings: list) -> int:
    found = [f for f in findings if f.status == "Found" and f.type.startswith("Social Alias:")]
    score = 0
    score += len(found) * 4
    categories = {}
    for f in found:
        for tag in f.tags:
            if tag in CATEGORY_NAMES:
                categories[tag] = categories.get(tag, 0) + 1
    category_weights = {
        "social": 3, "dev": 2, "professional": 5,
        "creative": 2, "gaming": 1, "shopping": 3,
        "crypto": 4, "dating": 8, "forum": 2, "blog": 1,
    }
    for cat, count in categories.items():
        score += category_weights.get(cat, 1) * min(count, 5)
    if len(categories) >= 3:
        score += 10
    if len(categories) >= 5:
        score += 15
    restricted = [f for f in findings if f.status == "Restricted"]
    score += len(restricted) * 2
    return min(100, score)


def generate_category_coverage(findings: list) -> dict:
    found = [f for f in findings if f.status == "Found" and f.type.startswith("Social Alias:")]
    coverage = {}
    platform_details = {}
    for f in found:
        for tag in f.tags:
            if tag in CATEGORY_NAMES and tag not in ("social-alias", "found"):
                coverage[tag] = coverage.get(tag, 0) + 1
                if tag not in platform_details:
                    platform_details[tag] = []
                platform_name = f.type.replace("Social Alias: ", "")
                if platform_name not in platform_details[tag]:
                    platform_details[tag].append(platform_name)
    result = {}
    for cat, count in coverage.items():
        result[cat] = {
            "count": count,
            "label": CATEGORY_NAMES.get(cat, cat.title()),
            "platforms": platform_details.get(cat, []),
        }
    return result


def correlate_cross_platform(findings: list) -> list:
    correlation_findings = []
    for name, platforms in _cross_platform_names.items():
        if len(platforms) >= 2:
            platform_list = ", ".join(p['platform'] for p in platforms)
            urls_list = ", ".join(p['url'] for p in platforms)
            correlation_findings.append(IntelligenceFinding(
                entity=f"Cross-platform identity: '{name}'",
                type="Social Alias Cross-Platform Correlation",
                source="SocialAliasHunter",
                confidence="High",
                color="gold",
                threat_level="Informational",
                status="Linked",
                resolution=f"Same name found on {len(platforms)} platforms: {platform_list}",
                raw_data=f"Name: {name} | Platforms: {urls_list}",
                tags=["correlation", "cross-platform", "identity-link"],
            ))
    return correlation_findings


async def crawl(target: str, client: httpx.AsyncClient):
    global _cross_platform_names
    _cross_platform_names = {}
    findings = []
    domain = target.strip().lower()

    email_username = ""
    if '@' in domain and re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', domain):
        email_username = domain.split('@')[0]
        findings.append(IntelligenceFinding(
            entity=f"Email detected: {domain}",
            type="Social Alias Email Detection",
            source="SocialAliasHunter",
            confidence="High",
            color="cyan",
            threat_level="Informational",
            status="Email Input",
            resolution=f"Extracted username '{email_username}' from email address",
            raw_data=f"Email: {domain}, Username: {email_username}",
            tags=["email", "username-extraction"],
        ))

    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        base_name = normalize_username(domain.split(".")[0] if not email_username else email_username)
        if not base_name:
            return findings

        permutations = generate_permutations(base_name)
        findings.append(IntelligenceFinding(
            entity=f"Username: {base_name} | {len(permutations)} permutations generated",
            type="Social Alias Username Normalization",
            source="SocialAliasHunter",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Analyzed",
            resolution=f"{len(permutations)} username variants",
            raw_data=f"Base: {base_name}, Permutations: {', '.join(permutations[:20])}",
            tags=["username", "permutations"],
        ))

        tasks = []
        for platform_name, url_tpl, ptype, category in SOCIAL_PLATFORMS:
            url = url_tpl.format(u=base_name)
            tasks.append(check_platform(client, platform_name, url, ptype, category, base_name))

        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i+chunk_size]
            results = await asyncio.gather(*chunk, return_exceptions=True)
            for r in results:
                if isinstance(r, IntelligenceFinding):
                    findings.append(r)

        found_count = sum(1 for f in findings if f.status == "Found" and f.type.startswith("Social Alias:"))
        restricted_count = sum(1 for f in findings if f.status == "Restricted")
        rate_limited = sum(1 for f in findings if f.status == "Rate Limited")

        categories_found = {}
        for f in findings:
            for tag in f.tags:
                if tag in CATEGORY_NAMES:
                    categories_found[tag] = categories_found.get(tag, 0) + 1

        correlation_results = correlate_cross_platform(findings)
        findings.extend(correlation_results)

        category_coverage = generate_category_coverage(findings)
        if category_coverage:
            cov_parts = []
            for cat, info in sorted(category_coverage.items()):
                cov_parts.append(f"{info['label']}: {info['count']}")
            findings.append(IntelligenceFinding(
                entity=f"Category coverage: {', '.join(cov_parts)}",
                type="Social Alias Category Coverage",
                source="SocialAliasHunter",
                confidence="Medium",
                color="teal",
                threat_level="Informational",
                status="Analyzed",
                resolution=f"{len(category_coverage)} categories with hits",
                raw_data=json.dumps(category_coverage, indent=2),
                tags=["coverage", "categories"] + list(category_coverage.keys()),
            ))

        risk_score = calculate_privacy_risk_score(findings)
        risk_level = "Low"
        if risk_score >= 70:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        findings.append(IntelligenceFinding(
            entity=f"Privacy risk score: {risk_score}/100 ({risk_level})",
            type="Social Alias Privacy Risk Score",
            source="SocialAliasHunter",
            confidence="Medium",
            color="red" if risk_score >= 50 else "orange" if risk_score >= 30 else "green",
            threat_level=risk_level,
            status="Scored",
            resolution=f"{risk_score}/100 - {risk_level} exposure",
            raw_data=f"Score: {risk_score}/100 | Found: {found_count} platforms | Restricted: {restricted_count} | Categories: {len(category_coverage)}",
            tags=["privacy-risk", "scoring", risk_level.lower()],
        ))

        summary_parts = [f"Found on {found_count} platforms"]
        if restricted_count:
            summary_parts.append(f"{restricted_count} restricted")
        if rate_limited:
            summary_parts.append(f"{rate_limited} rate-limited")
        if categories_found:
            cats = ", ".join(f"{k}: {v}" for k, v in sorted(categories_found.items()))
            summary_parts.append(f"[{cats}]")
        if _cross_platform_names:
            linked = sum(1 for v in _cross_platform_names.values() if len(v) >= 2)
            if linked:
                summary_parts.append(f"{linked} identity links")

        findings.append(IntelligenceFinding(
            entity=f"Alias '{base_name}' checked on {len(SOCIAL_PLATFORMS)} platforms: {', '.join(summary_parts)}",
            type="Social Alias Summary",
            source="SocialAliasHunter",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{found_count} found, {restricted_count} restricted, {rate_limited} rate-limited",
            raw_data=f"Total platforms: {len(SOCIAL_PLATFORMS)}, Found: {found_count}, Restricted: {restricted_count}",
            tags=["summary"],
        ))

        if found_count == 0 and rate_limited == 0:
            for perm in permutations[1:11]:
                perm_tasks = []
                for platform_name, url_tpl, ptype, category in SOCIAL_PLATFORMS[:20]:
                    url = url_tpl.format(u=perm)
                    perm_tasks.append(check_platform(client, platform_name, url, ptype, category, perm))
                perm_results = await asyncio.gather(*perm_tasks, return_exceptions=True)
                for r in perm_results:
                    if isinstance(r, IntelligenceFinding) and r.status == "Found":
                        findings.append(r)
                        break
    except Exception:
        pass
    return findings
