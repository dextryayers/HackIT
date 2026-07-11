import httpx
import re
import asyncio
import socket
import xml.etree.ElementTree as ET
import math
from urllib.parse import urlparse, urldefrag, urljoin
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

COMMON_MAILBOXES = [
    "admin", "info", "contact", "support", "sales", "marketing", "billing",
    "abuse", "postmaster", "webmaster", "noreply", "no-reply", "help",
    "hello", "hi", "team", "careers", "jobs", "hr", "recruitment",
    "press", "media", "pr", "partner", "partners", "business",
    "enquiries", "enquiry", "inquiry", "inquiries", "general",
    "feedback", "complaints", "customerservice", "cs", "service",
    "newsletter", "subscribe", "unsubscribe", "announce",
    "security", "privacy", "legal", "dmca", "copyright",
    "dev", "developer", "developers", "engineering", "tech",
    "it", "it-support", "sysadmin", "operations",
    "ceo", "founder", "director", "manager",
    "test", "testing", "mail", "email", "office",
    "accounts", "accounting", "finance", "payments",
    "shipping", "logistics", "orders", "order",
    "return", "returns", "refund", "refunds",
]

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
MAILTO_REGEX = re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
PHONE_REGEX = re.compile(
    r'(?:(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})'  # NANP + international
    r'|(?:\+\d{1,3}[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,9})'  # generic international
    r'|(?:(?:00)\d{1,3}[\s.-]?\d{1,4}[\s.-]?\d{1,4}[\s.-]?\d{1,9})'  # 00 prefix intl
)
SOCIAL_PATTERNS = [
    (r"(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in|school)/[a-zA-Z0-9_-]+", "LinkedIn"),
    (r"(?:https?://)?(?:www\.)?twitter\.com/[a-zA-Z0-9_]+", "Twitter / X"),
    (r"(?:https?://)?(?:www\.)?github\.com/[a-zA-Z0-9_-]+", "GitHub"),
    (r"(?:https?://)?(?:www\.)?facebook\.com/[a-zA-Z0-9.]+", "Facebook"),
    (r"(?:https?://)?(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+", "Instagram"),
    (r"(?:https?://)?(?:www\.)?youtube\.com/@?[a-zA-Z0-9_-]+", "YouTube"),
    (r"(?:https?://)?(?:www\.)?crunchbase\.com/organization/[a-zA-Z0-9_-]+", "Crunchbase"),
    (r"(?:https?://)?(?:www\.)?angel\.co/[a-zA-Z0-9_-]+", "AngelList"),
    (r"(?:https?://)?(?:www\.)?glassdoor\.com/(?:Overview|Reviews)/[a-zA-Z0-9_-]+", "Glassdoor"),
    (r"(?:https?://)?(?:www\.)?producthunt\.com/@?[a-zA-Z0-9_-]+", "Product Hunt"),
    (r"(?:https?://)?(?:www\.)?tiktok\.com/@?[a-zA-Z0-9_.]+", "TikTok"),
    (r"(?:https?://)?(?:www\.)?reddit\.com/(?:r|u)/[a-zA-Z0-9_]+", "Reddit"),
    (r"(?:https?://)?(?:www\.)?pinterest\.[a-z]+/[a-zA-Z0-9_/]+", "Pinterest"),
    (r"(?:https?://)?(?:www\.)?snapchat\.com/add/[a-zA-Z0-9_]+", "Snapchat"),
    (r"(?:https?://)?(?:www\.)?discord\.[a-z]+/invite/[a-zA-Z0-9_]+", "Discord"),
    (r"(?:https?://)?(?:www\.)?t\.me/[a-zA-Z0-9_]+", "Telegram"),
    (r"(?:https?://)?(?:www\.)?medium\.com/@?[a-zA-Z0-9_.]+", "Medium"),
    (r"(?:https?://)?(?:www\.)?dev\.to/[a-zA-Z0-9_]+", "Dev.to"),
    (r"(?:https?://)?(?:www\.)?hashnode\.com/@?[a-zA-Z0-9_-]+", "Hashnode"),
    (r"(?:https?://)?(?:stackoverflow\.com/users/\d+/[a-zA-Z0-9_-]+)", "StackOverflow"),
    (r"(?:https?://)?(?:[a-z]+\.)?stackexchange\.com/users/\d+/[a-zA-Z0-9_-]+", "StackExchange"),
    (r"(?:https?://)?(?:www\.)?gitlab\.[a-z]+/[a-zA-Z0-9_.-]+", "GitLab"),
    (r"(?:https?://)?(?:www\.)?bitbucket\.org/[a-zA-Z0-9_-]+", "Bitbucket"),
    (r"(?:https?://)?(?:www\.)?keybase\.io/[a-zA-Z0-9_]+", "Keybase"),
    (r"(?:https?://)?(?:www\.)?hackerone\.com/[a-zA-Z0-9_]+", "HackerOne"),
    (r"(?:https?://)?(?:www\.)?bugcrowd\.com/[a-zA-Z0-9_]+", "Bugcrowd"),
    (r"(?:https?://)?(?:www\.)?tryhackme\.com/p/[a-zA-Z0-9_]+", "TryHackMe"),
    (r"(?:https?://)?(?:www\.)?hackthebox\.com/profile/\d+", "HackTheBox"),
    (r"(?:https?://)?(?:www\.)?root-me\.org/[a-zA-Z0-9_/]+", "RootMe"),
    (r"(?:https?://)?(?:www\.)?codewars\.com/users/[a-zA-Z0-9_-]+", "Codewars"),
    (r"(?:https?://)?(?:www\.)?leetcode\.[a-z]+/[a-zA-Z0-9_]+", "LeetCode"),
    (r"(?:https?://)?(?:www\.)?hackerrank\.com/[a-zA-Z0-9_/]+", "HackerRank"),
    (r"(?:https?://)?(?:www\.)?upwork\.com/freelancers/[a-zA-Z0-9_]+", "Upwork"),
    (r"(?:https?://)?(?:www\.)?fiverr\.com/[a-zA-Z0-9_]+", "Fiverr"),
    (r"(?:https?://)?(?:www\.)?freelancer\.[a-z]+/[a-zA-Z0-9_]+", "Freelancer"),
    (r"(?:https?://)?(?:www\.)?behance\.net/[a-zA-Z0-9_]+", "Behance"),
    (r"(?:https?://)?(?:www\.)?dribbble\.com/[a-zA-Z0-9_]+", "Dribbble"),
    (r"(?:https?://)?(?:www\.)?deviantart\.com/[a-zA-Z0-9_-]+", "DeviantArt"),
    (r"(?:https?://)?(?:www\.)?flickr\.com/people/[a-zA-Z0-9_@]+", "Flickr"),
    (r"(?:https?://)?(?:www\.)?500px\.com/[a-zA-Z0-9_]+", "500px"),
    (r"(?:https?://)?(?:www\.)?vimeo\.com/[a-zA-Z0-9_]+", "Vimeo"),
    (r"(?:https?://)?(?:www\.)?twitch\.tv/[a-zA-Z0-9_]+", "Twitch"),
    (r"(?:https?://)?(?:www\.)?patreon\.com/[a-zA-Z0-9_]+", "Patreon"),
    (r"(?:https?://)?(?:www\.)?ko-fi\.com/[a-zA-Z0-9_]+", "Ko-fi"),
    (r"(?:https?://)?(?:www\.)?buymeacoffee\.com/[a-zA-Z0-9_]+", "BuyMeACoffee"),
    (r"(?:https?://)?(?:www\.)?substack\.com/@?[a-zA-Z0-9_]+", "Substack"),
    (r"(?:https?://)?(?:www\.)?threads\.net/@?[a-zA-Z0-9_]+", "Threads"),
    (r"(?:https?://)?(?:www\.)?mastodon\.social/@?[a-zA-Z0-9_]+", "Mastodon"),
    (r"(?:https?://)?(?:[a-z]+\.)?mastodon\.[a-z]+/@?[a-zA-Z0-9_]+", "Mastodon (Fediverse)"),
    (r"(?:https?://)?(?:www\.)?bluesky\.social/profile/[a-zA-Z0-9.]+", "Bluesky"),
    (r"(?:https?://)?(?:www\.)?signal\.org/[a-zA-Z0-9_]+", "Signal"),
    (r"(?:https?://)?(?:www\.)?whatsapp\.com/[a-zA-Z0-9_/]+", "WhatsApp"),
    (r"(?:https?://)?(?:www\.)?messenger\.com/[a-zA-Z0-9_]+", "Facebook Messenger"),
    (r"(?:https?://)?(?:www\.)?wechat\.com/[a-zA-Z0-9_]+", "WeChat"),
    (r"(?:https?://)?(?:www\.)?line\.me/[a-zA-Z0-9_]+", "LINE"),
    (r"(?:https?://)?(?:www\.)?telegram\.org/[a-zA-Z0-9_]+", "Telegram"),
    (r"(?:https?://)?(?:www\.)?vk\.com/[a-zA-Z0-9_.]+", "VKontakte"),
    (r"(?:https?://)?(?:www\.)?ok\.ru/[a-zA-Z0-9_]+", "Odnoklassniki"),
    (r"(?:https?://)?(?:www\.)?weibo\.com/[a-zA-Z0-9_]+", "Weibo"),
    (r"(?:https?://)?(?:www\.)?xiaohongshu\.com/[a-zA-Z0-9_]+", "Xiaohongshu"),
    (r"(?:https?://)?(?:www\.)?bilibili\.com/[a-zA-Z0-9_/]+", "Bilibili"),
    (r"(?:https?://)?(?:www\.)?zhihu\.com/people/[a-zA-Z0-9_]+", "Zhihu"),
    (r"(?:https?://)?(?:www\.)?douyin\.com/[a-zA-Z0-9_]+", "Douyin"),
    (r"(?:https?://)?(?:www\.)?kuaishou\.com/[a-zA-Z0-9_]+", "Kuaishou"),
    (r"(?:https?://)?(?:www\.)?quora\.com/profile/[a-zA-Z0-9_-]+", "Quora"),
    (r"(?:https?://)?(?:www\.)?slideshare\.net/[a-zA-Z0-9_]+", "SlideShare"),
    (r"(?:https?://)?(?:www\.)?scribd\.com/[a-zA-Z0-9_]+", "Scribd"),
    (r"(?:https?://)?(?:www\.)?issuu\.com/[a-zA-Z0-9_]+", "Issuu"),
    (r"(?:https?://)?(?:www\.)?calendly\.com/[a-zA-Z0-9_]+", "Calendly"),
    (r"(?:https?://)?(?:www\.)?canva\.com/[a-zA-Z0-9_]+", "Canva"),
    (r"(?:https?://)?(?:www\.)?figma\.com/@?[a-zA-Z0-9_]+", "Figma"),
    (r"(?:https?://)?(?:www\.)?notion\.so/[a-zA-Z0-9_-]+", "Notion"),
    (r"(?:https?://)?(?:www\.)?miro\.com/[a-zA-Z0-9_]+", "Miro"),
    (r"(?:https?://)?(?:www\.)?trello\.com/[a-zA-Z0-9_]+", "Trello"),
    (r"(?:https?://)?(?:www\.)?asana\.com/[a-zA-Z0-9_]+", "Asana"),
    (r"(?:https?://)?(?:www\.)?atlassian\.net/[a-zA-Z0-9_]+", "Atlassian"),
    (r"(?:https?://)?(?:www\.)?jira\.[a-z]+/[a-zA-Z0-9_]+", "Jira"),
    (r"(?:https?://)?(?:www\.)?confluence\.[a-z]+/[a-zA-Z0-9_]+", "Confluence"),
    (r"(?:https?://)?(?:www\.)?datadog\.com/[a-zA-Z0-9_]+", "Datadog"),
    (r"(?:https?://)?(?:www\.)?docker\.com/u/[a-zA-Z0-9_]+", "Docker Hub"),
    (r"(?:https?://)?(?:www\.)?npmjs\.com/~[a-zA-Z0-9_]+", "npm"),
    (r"(?:https?://)?(?:www\.)?pypi\.org/user/[a-zA-Z0-9_-]+", "PyPI"),
    (r"(?:https?://)?(?:www\.)?rubygems\.org/profiles/[a-zA-Z0-9_]+", "RubyGems"),
    (r"(?:https?://)?(?:www\.)?hub\.docker\.com/u/[a-zA-Z0-9_]+", "Docker Hub"),
    (r"(?:https?://)?(?:www\.)?nuget\.org/profiles/[a-zA-Z0-9_]+", "NuGet"),
    (r"(?:https?://)?(?:www\.)?crates\.io/users/[a-zA-Z0-9_]+", "crates.io"),
    (r"(?:https?://)?(?:www\.)?packagist\.org/users/[a-zA-Z0-9_-]+", "Packagist"),
    (r"(?:https?://)?(?:www\.)?gitter\.im/[a-zA-Z0-9_/]+", "Gitter"),
    (r"(?:https?://)?(?:www\.)?hubspot\.com/[a-zA-Z0-9_]+", "HubSpot"),
    (r"(?:https?://)?(?:www\.)?salesforce\.com/[a-zA-Z0-9_]+", "Salesforce"),
    (r"(?:https?://)?(?:www\.)?zendesk\.com/[a-zA-Z0-9_]+", "Zendesk"),
    (r"(?:https?://)?(?:www\.)?intercom\.com/[a-zA-Z0-9_]+", "Intercom"),
    (r"(?:https?://)?(?:www\.)?mixpanel\.com/[a-zA-Z0-9_]+", "Mixpanel"),
    (r"(?:https?://)?(?:www\.)?amplitude\.com/[a-zA-Z0-9_]+", "Amplitude"),
    (r"(?:https?://)?(?:www\.)?segment\.com/[a-zA-Z0-9_]+", "Segment"),
    (r"(?:https?://)?(?:www\.)?stripe\.com/[a-zA-Z0-9_]+", "Stripe"),
    (r"(?:https?://)?(?:www\.)?paypal\.com/[a-zA-Z0-9_]+", "PayPal"),
    (r"(?:https?://)?(?:www\.)?gumroad\.com/[a-zA-Z0-9_]+", "Gumroad"),
    (r"(?:https?://)?(?:www\.)?shopify\.com/[a-zA-Z0-9_]+", "Shopify"),
    (r"(?:https?://)?(?:www\.)?etsy\.com/shop/[a-zA-Z0-9_]+", "Etsy"),
    (r"(?:https?://)?(?:www\.)?amazon\.com/sp/[a-zA-Z0-9_]+", "Amazon Seller"),
    (r"(?:https?://)?(?:www\.)?ebay\.com/usr/[a-zA-Z0-9_]+", "eBay"),
    (r"(?:https?://)?(?:www\.)?wikipedia\.org/wiki/[a-zA-Z0-9_%]+", "Wikipedia"),
    (r"(?:https?://)?(?:www\.)?wikidata\.org/[a-zA-Z0-9_]+", "Wikidata"),
    (r"(?:https?://)?(?:www\.)?imdb\.com/name/[a-zA-Z0-9_]+", "IMDb"),
    (r"(?:https?://)?(?:www\.)?soundcloud\.com/[a-zA-Z0-9_-]+", "SoundCloud"),
    (r"(?:https?://)?(?:www\.)?spotify\.com/(?:user|artist)/[a-zA-Z0-9_]+", "Spotify"),
    (r"(?:https?://)?(?:www\.)?bandcamp\.com/[a-zA-Z0-9_]+", "Bandcamp"),
    (r"(?:https?://)?(?:www\.)?last\.fm/user/[a-zA-Z0-9_-]+", "Last.fm"),
    (r"(?:https?://)?(?:www\.)?mixcloud\.com/[a-zA-Z0-9_-]+", "Mixcloud"),
]

EMAIL_PATTERN_ANALYSIS = [
    (r"^[a-z]+\.[a-z]+@", "firstname.lastname"),
    (r"^[a-z][a-z]+[a-z]@", "firstinitiallastname"),
    (r"^[a-z]+@", "firstname"),
    (r"^[a-z]{1}\.[a-z]+@", "firstinitial.lastname"),
    (r"^[a-z]+\.[a-z]{1}@", "firstname.lastinitial"),
    (r"^[a-z]{1}[a-z]+@", "firstinitial+lastname"),
    (r"^[a-z]+[0-9]+@", "name+number"),
    (r"^[a-z]+\_[a-z]+@", "firstname_lastname"),
    (r"^[a-z]+\-[a-z]+@", "firstname-lastname"),
]

EMAIL_FORMAT_PATTERNS = {
    "firstname.lastname": lambda f, l: f"{f}.{l}",
    "firstinitial.lastname": lambda f, l: f"{f[0]}.{l}",
    "firstname.lastinitial": lambda f, l: f"{f}.{l[0]}",
    "firstinitiallastname": lambda f, l: f"{f[0]}{l}",
    "firstname": lambda f, l: f"{f}",
    "firstname_lastname": lambda f, l: f"{f}_{l}",
    "firstname-lastname": lambda f, l: f"{f}-{l}",
    "firstinitial+lastname": lambda f, l: f"{f[0]}{l}",
    "name+number": lambda f, l: f"{f}{l}",
}

CONTACT_KEYWORDS = ["contact", "contact-us", "contactus", "get-in-touch", "reach-us", "contactanos", "kontakt"]
ABOUT_KEYWORDS = ["about", "about-us", "aboutus", "our-team", "team", "who-we-are"]
PAGE_PROBABILITY_BOOST = {
    "contact": 0.15,
    "about": 0.10,
    "team": 0.15,
    "careers": 0.10,
    "support": 0.10,
    "default": 0.0,
}

SMTP_TIMEOUT = 5


async def check_smtp(host: str, email: str) -> dict:
    try:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: socket.create_connection(
            (host, 25), timeout=SMTP_TIMEOUT
        ))
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await loop.create_connection(
            lambda: protocol, host=host, port=25
        )

        def recv_line():
            fut = loop.create_future()
            reader.readuntil(b'\n').add_done_callback(lambda f: fut.set_result(f.result()))
            return fut

        async def send_line(line: bytes):
            transport.write(line + b'\r\n')
            await asyncio.sleep(0.1)

        banner = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        banner_str = banner.decode("utf-8", errors="ignore").strip()

        await send_line(b'EHLO hunterhow.local')
        ehlo_resp = b""
        try:
            while True:
                line = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
                ehlo_resp += line
                if b'250 ' in line:
                    break
        except Exception:
            pass

        await send_line(f'MAIL FROM:<verify@{email.split("@")[1]}>'.encode())
        mailfrom_resp = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        mailfrom_str = mailfrom_resp.decode("utf-8", errors="ignore")

        await send_line(f'RCPT TO:<{email}>'.encode())
        rcpt_resp = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        rcpt_str = rcpt_resp.decode("utf-8", errors="ignore")

        await send_line(b'QUIT')
        transport.close()

        is_valid = rcpt_str.startswith("250") or rcpt_str.startswith("251")
        return {"valid": is_valid, "banner": banner_str[:100], "response": rcpt_str.strip()[:100]}
    except Exception as e:
        return {"valid": None, "banner": "", "response": str(e)[:100]}


async def fetch_url(client: httpx.AsyncClient, url: str, timeout: float = 15.0) -> str:
    try:
        resp = await safe_fetch(client, url, timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            return resp.text if hasattr(resp, "text") else ""
    except Exception:
        pass
    return ""


def detect_page_type(url: str, html: str) -> str:
    url_lower = url.lower()
    for keyword in CONTACT_KEYWORDS:
        if keyword in url_lower:
            return "contact"
    for keyword in ABOUT_KEYWORDS:
        if keyword in url_lower:
            return "about"
    if "team" in url_lower:
        return "team"
    if "career" in url_lower or "job" in url_lower:
        return "careers"
    if "support" in url_lower or "help" in url_lower:
        return "support"
    html_lower = html.lower()
    contact_score = sum(1 for k in CONTACT_KEYWORDS if k in html_lower.replace("-", "").replace(" ", ""))
    about_score = sum(1 for k in ABOUT_KEYWORDS if k in html_lower.replace("-", "").replace(" ", ""))
    if contact_score > about_score and contact_score > 1:
        return "contact"
    if about_score > contact_score and about_score > 1:
        return "about"
    return "default"


def compute_email_probability(mailbox: str, page_type: str, found_in_page: bool = False) -> float:
    base = 0.5
    if page_type in PAGE_PROBABILITY_BOOST:
        base += PAGE_PROBABILITY_BOOST[page_type]
    if page_type == "contact" and mailbox in ("contact", "info", "support", "help"):
        base += 0.20
    if page_type == "about" and mailbox in ("team", "info", "hello", "hi"):
        base += 0.15
    if page_type == "team" and mailbox in ("team", "hello", "hi"):
        base += 0.20
    if page_type == "careers" and mailbox in ("careers", "jobs", "hr", "recruitment"):
        base += 0.15
    if page_type == "support" and mailbox in ("support", "help", "info"):
        base += 0.20
    if mailbox in ("abuse", "security", "postmaster", "webmaster"):
        base += 0.05
    if found_in_page:
        base += 0.15
    return min(base, 0.99)


async def crawl_robots_txt(client: httpx.AsyncClient, base_url: str) -> list:
    paths = []
    robots_url = f"{base_url.rstrip('/')}/robots.txt"
    robots_text = await fetch_url(client, robots_url)
    if not robots_text:
        return paths
    for line in robots_text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:") or line.startswith("Disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                paths.append(path)
    return paths


async def crawl_sitemap_xml(client: httpx.AsyncClient, base_url: str) -> list:
    urls = []
    sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
    sitemap_text = await fetch_url(client, sitemap_url)
    if not sitemap_text:
        return urls
    try:
        root = ET.fromstring(sitemap_text)
        ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        for loc in root.findall(".//ns:loc", ns):
            loc_text = loc.text.strip()
            if loc_text:
                urls.append(loc_text)
        if not urls:
            for loc in root.findall(".//loc"):
                loc_text = loc.text.strip()
                if loc_text:
                    urls.append(loc_text)
    except ET.ParseError:
        url_matches = re.findall(r'<loc>(.*?)</loc>', sitemap_text)
        for m in url_matches:
            m = m.strip()
            if m:
                urls.append(m)
    return urls


async def pgp_keyserver_lookup(client: httpx.AsyncClient, domain: str) -> list:
    emails = []
    try:
        search_url = f"https://keyserver.ubuntu.com/pks/lookup?op=index&search={domain}"
        resp = await safe_fetch(client, search_url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            text = resp.text if hasattr(resp, "text") else ""
            found = set(EMAIL_REGEX.findall(text))
            for email in found:
                email = email.lower()
                if email.endswith("." + domain) or email.endswith(domain):
                    emails.append(email)
    except Exception:
        pass
    return emails


def predict_email_service(mx_hosts: list) -> str:
    for _, mx in mx_hosts:
        mx_lower = mx.lower()
        if any(d in mx_lower for d in ["google", "googlemail", "gmail"]):
            return "Google Workspace"
        if any(d in mx_lower for d in ["outlook", "microsoft", "office365", "protection.outlook"]):
            return "Microsoft 365"
        if any(d in mx_lower for d in ["protonmail", "proton"]):
            return "ProtonMail"
        if any(d in mx_lower for d in ["zoho"]):
            return "Zoho"
        if any(d in mx_lower for d in ["fastmail", "messagingengine"]):
            return "Fastmail"
        if any(d in mx_lower for d in ["yandex"]):
            return "Yandex"
        if any(d in mx_lower for d in ["mailgun"]):
            return "Mailgun"
        if any(d in mx_lower for d in ["sendgrid"]):
            return "SendGrid"
        if any(d in mx_lower for d in ["mailchimp", "mandrill"]):
            return "Mailchimp"
        if any(d in mx_lower for d in ["rackspace"]):
            return "Rackspace"
        if any(d in mx_lower for d in ["exchange", "cpanel", "exim"]):
            return "Self-Hosted (Exchange/cPanel/Exim)"
        if any(d in mx_lower for d in ["postfix"]):
            return "Self-Hosted (Postfix)"
        if any(d in mx_lower for d in ["sendmail"]):
            return "Self-Hosted (Sendmail)"
        if any(d in mx_lower for d in ["cloudflare"]):
            return "Cloudflare Email Routing"
    return "Self-Hosted / Unknown"


def detect_email_format_pattern(local_parts: list) -> str:
    if len(local_parts) < 2:
        return "unknown"
    dot_patterns = 0
    underscore_patterns = 0
    dash_patterns = 0
    single_name_patterns = 0
    for part in local_parts:
        if "." in part and len(part.split(".")) == 2:
            a, b = part.split(".")
            if len(a) >= 2 and len(b) >= 2:
                dot_patterns += 1
            elif len(a) == 1 and len(b) >= 2:
                dot_patterns += 1
            elif len(a) >= 2 and len(b) == 1:
                dot_patterns += 1
        elif "_" in part:
            underscore_patterns += 1
        elif "-" in part:
            dash_patterns += 1
        else:
            single_name_patterns += 1
    total = len(local_parts)
    if dot_patterns / total >= 0.5:
        return "firstname.lastname"
    if underscore_patterns / total >= 0.5:
        return "firstname_lastname"
    if dash_patterns / total >= 0.5:
        return "firstname-lastname"
    if single_name_patterns / total >= 0.5:
        return "single_name"
    return "mixed"


def suggest_email_variations(detected_pattern: str, local_parts: list, domain: str) -> list:
    suggestions = []
    if detected_pattern == "unknown" or not local_parts:
        return suggestions
    sample = local_parts[0]
    parts = re.split(r'[._\-]', sample)
    first_name = parts[0] if parts else sample
    last_name = parts[-1] if len(parts) > 1 else ""
    if len(parts) == 2 and len(parts[0]) >= 2 and len(parts[1]) >= 2:
        first_name = parts[0]
        last_name = parts[1]
    elif len(parts) == 1:
        first_name = sample
        last_name = ""
    elif len(parts) >= 3:
        first_name = parts[0]
        last_name = parts[-1]

    if not first_name or len(first_name) < 2:
        first_name = "john"
    if not last_name or len(last_name) < 2:
        last_name = "doe"

    if detected_pattern == "single_name":
        return suggestions

    for pattern_name, generator in EMAIL_FORMAT_PATTERNS.items():
        if pattern_name == detected_pattern:
            continue
        suggested_local = generator(first_name, last_name)
        suggested_email = f"{suggested_local}@{domain}"
        if suggested_email not in suggestions:
            suggestions.append(suggested_email)
    return suggestions[:6]


TYPO_DOMAINS = {
    "gmail.com": ["gmai.com", "gamil.com", "gmail.co", "gmail.cm", "gmial.com", "gnail.com", "gmale.com"],
    "yahoo.com": ["yahooo.com", "yahho.com", "yaho.com", "yahoo.co", "yahoo.cm", "yhaoo.com"],
    "hotmail.com": ["hotmail.co", "hotmail.cm", "hotmai.com", "htomail.com", "hotmil.com", "hotmial.com"],
    "outlook.com": ["outlok.com", "outloo.com", "outook.com", "outllok.com", "utlook.com"],
    "icloud.com": ["icloud.co", "icloud.cm", "icoud.com", "iloud.com", "iclod.com"],
    "aol.com": ["aol.co", "aol.cm", "aol.com", "oll.com"],
    "protonmail.com": ["protonail.com", "protonmal.com", "protonmil.com", "protonmai.com"],
    "zoho.com": ["zoho.co", "zoho.cm", "zohoo.com", "zohomail.com"],
    "mail.com": ["mail.co", "mail.cm", "maiil.com", "maill.com"],
    "yandex.com": ["yandex.co", "yandex.cm", "yandex.ru", "yandx.com"],
}


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    base_url = f"https://{domain}"
    html = ""
    js_content = ""
    secondary_pages_html = []

    try:
        resp = await safe_fetch(client, base_url, timeout=15.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            html = resp.text if hasattr(resp, "text") else ""
    except Exception:
        try:
            resp = await safe_fetch(client, f"http://{domain}", timeout=15.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp.status_code == 200:
                html = resp.text if hasattr(resp, "text") else ""
        except Exception:
            pass

    if not html:
        return findings

    # robots.txt crawling
    robots_paths = await crawl_robots_txt(client, base_url)
    if robots_paths:
        findings.append(make_finding(
            entity=f"Robots.txt paths: {len(robots_paths)}",
            type="HunterHOW - Robots.txt Crawl",
            source="HunterHOW",
            confidence="High",
            color="slate",
            raw_data=f"Disallowed paths: {', '.join(robots_paths[:15])}",
            tags=["crawl", "robots.txt"]
        ))
        for path in robots_paths[:5]:
            page_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            page_text = await fetch_url(client, page_url, timeout=10.0)
            if page_text:
                secondary_pages_html.append((page_url, page_text))

    # sitemap.xml crawling
    sitemap_urls = await crawl_sitemap_xml(client, base_url)
    if sitemap_urls:
        findings.append(make_finding(
            entity=f"Sitemap URLs: {len(sitemap_urls)}",
            type="HunterHOW - Sitemap Crawl",
            source="HunterHOW",
            confidence="High",
            color="slate",
            raw_data=f"Total URLs in sitemap: {len(sitemap_urls)}",
            tags=["crawl", "sitemap.xml"]
        ))
        sample_size = min(8, len(sitemap_urls))
        step = max(1, len(sitemap_urls) // sample_size)
        sampled_urls = [sitemap_urls[i] for i in range(0, len(sitemap_urls), step)][:sample_size]
        for surl in sampled_urls:
            page_text = await fetch_url(client, surl, timeout=10.0)
            if page_text:
                secondary_pages_html.append((surl, page_text))

    # discover more pages via internal links from main page
    internal_links = set()
    for m in re.finditer(r'href=["\'](https?://[^"\']+)["\']', html):
        link = m.group(1)
        parsed = urlparse(link)
        if parsed.netloc == domain or (not parsed.netloc and not link.startswith("#") and not link.startswith("javascript")):
            if not parsed.netloc:
                link = urljoin(base_url, link)
            internal_links.add(link.rstrip("/"))
    for link in list(internal_links)[:5]:
        page_text = await fetch_url(client, link, timeout=10.0)
        if page_text:
            secondary_pages_html.append((link, page_text))

    # PGP keyserver lookup
    pgp_emails = await pgp_keyserver_lookup(client, domain)
    for email in pgp_emails:
        if not any(f.entity == email and "PGP" in f.type for f in findings):
            findings.append(make_finding(
                entity=email,
                ftype="HunterHOW - Email (PGP Keyserver)",
                source="HunterHOW",
                confidence="High",
                color="emerald",
                status="PGP Key Found",
                raw_data=f"Email from PGP keyserver: {email}",
                tags=["email", "pgp"]
            ))

    mailto_emails = set()
    for m in MAILTO_REGEX.finditer(html):
        mailto_emails.add(m.group(1).lower())
    for url, page_text in secondary_pages_html:
        for m in MAILTO_REGEX.finditer(page_text):
            mailto_emails.add(m.group(1).lower())

    for email in mailto_emails:
        if email.endswith("." + domain) or email.endswith(domain):
            findings.append(make_finding(
                entity=email,
                ftype="HunterHOW - Email (mailto: link)",
                source="HunterHOW",
                confidence="High",
                color="emerald",
                status="Found in HTML",
                raw_data=f"Email in mailto: {email}",
                tags=["email", "mailto"]
            ))

    text_emails = set()
    all_page_text = html + " " + " ".join(pt for _, pt in secondary_pages_html)
    for m in EMAIL_REGEX.finditer(all_page_text):
        email = m.group(0).lower()
        if email.endswith("." + domain) or email.endswith(domain):
            text_emails.add(email)

    non_mailto = text_emails - mailto_emails
    for email in list(non_mailto)[:15]:
        findings.append(make_finding(
            entity=email,
            ftype="HunterHOW - Email (in page text)",
            source="HunterHOW",
            confidence="Medium",
            color="cyan",
            status="Found in content",
            raw_data=f"Email in page content: {email}",
            tags=["email", "text"]
        ))

    js_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html)
    all_js_srcs = set(js_scripts)
    for _, page_text in secondary_pages_html:
        all_js_srcs.update(re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', page_text))
    for js_src in list(all_js_srcs)[:10]:
        try:
            js_url = js_src if js_src.startswith("http") else f"{base_url.rstrip('/')}/{js_src.lstrip('/')}"
            js_resp = await safe_fetch(client, js_url, timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if js_resp.status_code == 200:
                js_content += (js_resp.text or "")
        except Exception:
            pass

    if js_content:
        js_emails = set()
        for m in EMAIL_REGEX.finditer(js_content):
            email = m.group(0).lower()
            if email.endswith("." + domain) or email.endswith(domain):
                js_emails.add(email)
        for email in list(js_emails)[:10]:
            findings.append(make_finding(
                entity=email,
                ftype="HunterHOW - Email (in JavaScript)",
                source="HunterHOW",
                confidence="Medium",
                color="cyan",
                status="Found in JS",
                raw_data=f"Email in JavaScript: {email}",
                tags=["email", "javascript"]
            ))

    all_found_emails = set()
    for f in findings:
        if f.entity and "@" in f.entity:
            all_found_emails.add(f.entity)
    all_found_emails.update(pgp_emails)

    # Page context probability scoring for mailbox guesses
    main_page_type = detect_page_type(base_url, html)
    page_types = {
        base_url: main_page_type,
    }
    for url, page_text in secondary_pages_html:
        page_types[url] = detect_page_type(url, page_text)

    found_mailboxes = set()
    for mailbox in COMMON_MAILBOXES:
        test_email = f"{mailbox}@{domain}"
        if test_email in all_found_emails:
            found_mailboxes.add(mailbox)

    verified_mailboxes = {}
    for mailbox in COMMON_MAILBOXES[:20]:
        test_email = f"{mailbox}@{domain}"
        if test_email in all_found_emails:
            verified_mailboxes[mailbox] = compute_email_probability(mailbox, "default", found_in_page=True)
            continue
        check_html_lower = html.lower()
        if mailbox in check_html_lower:
            best_prob = 0.0
            for page_type in page_types.values():
                prob = compute_email_probability(mailbox, page_type, found_in_page=False)
                if prob > best_prob:
                    best_prob = prob
            verified_mailboxes[mailbox] = best_prob

    for mailbox, prob in sorted(verified_mailboxes.items(), key=lambda x: -x[1]):
        test_email = f"{mailbox}@{domain}"
        if test_email not in all_found_emails:
            prob_pct = f"{prob*100:.0f}%"
            findings.append(make_finding(
                entity=test_email,
                ftype="HunterHOW - Common Mailbox (likely)",
                source="HunterHOW",
                confidence="High" if prob >= 0.7 else "Medium" if prob >= 0.4 else "Low",
                color="emerald" if prob >= 0.7 else "blue" if prob >= 0.4 else "slate",
                status=f"Probability: {prob_pct}",
                raw_data=f"Common mailbox pattern: {mailbox}@{domain} | Page context confidence: {prob_pct}",
                tags=["email", "common-mailbox"]
            ))

    if not verified_mailboxes and not all_found_emails:
        for mailbox in ["info", "contact", "admin", "support"]:
            test_email = f"{mailbox}@{domain}"
            findings.append(make_finding(
                entity=test_email,
                ftype="HunterHOW - Common Mailbox (suggested)",
                source="HunterHOW",
                confidence="Low",
                color="slate",
                status="Suggested",
                raw_data=f"Suggested common mailbox: {test_email}",
                tags=["email", "common-mailbox"]
            ))

    all_emails = list(all_found_emails)
    if all_emails:
        for email in all_emails[:3]:
            local_part = email.split("@")[0]
            for pattern, pattern_name in EMAIL_PATTERN_ANALYSIS:
                if re.match(pattern, local_part):
                    findings.append(make_finding(
                        entity=f"Email format: {pattern_name} (from {email})",
                        type="HunterHOW - Email Naming Pattern",
                        source="HunterHOW",
                        confidence="High",
                        color="purple",
                        raw_data=f"Pattern: {pattern_name} | Example: {local_part}@{domain}",
                        tags=["email", "pattern"]
                    ))
                    break

        local_parts = [e.split("@")[0] for e in all_emails]
        if len(set(local_parts)) >= 2:
            findings.append(make_finding(
                entity=f"{len(set(local_parts))} different local parts found",
                type="HunterHOW - Email Diversity",
                source="HunterHOW",
                confidence="Medium",
                color="slate",
                raw_data=f"Local parts: {', '.join(sorted(set(local_parts))[:10])}",
                tags=["email", "diversity"]
            ))

        # Email format consistency check
        detected_format = detect_email_format_pattern(local_parts)
        if detected_format != "unknown":
            findings.append(make_finding(
                entity=f"Detected email format: {detected_format}",
                ftype="HunterHOW - Email Format Consistency",
                source="HunterHOW",
                confidence="Medium",
                color="indigo",
                raw_data=f"Format: {detected_format} | Based on {len(local_parts)} local parts: {', '.join(local_parts[:8])}",
                tags=["email", "format"]
            ))
            variations = suggest_email_variations(detected_format, local_parts, domain)
            if variations:
                findings.append(make_finding(
                    entity=f"Suggested variations: {', '.join(variations)}",
                    type="HunterHOW - Email Format Variations",
                    source="HunterHOW",
                    confidence="Low",
                    color="purple",
                    raw_data=f"Detected: {detected_format} | Try also: {', '.join(variations)}",
                    tags=["email", "format", "variations"]
                ))

    smtp_host = None
    import dns.resolver
    loop = asyncio.get_event_loop()
    mx_hosts = []
    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        mx_hosts = [(r.preference, str(r.exchange).rstrip('.')) for r in mx_records]
        if mx_hosts:
            mx_hosts.sort()
            smtp_host = mx_hosts[0][1]
            for prio, mx in mx_hosts:
                findings.append(make_finding(
                    entity=f"{mx} (priority {prio})",
                    type="HunterHOW - Mail Server (MX)",
                    source="HunterHOW",
                    confidence="High",
                    color="slate",
                    raw_data=f"MX: {mx} | Priority: {prio}",
                    tags=["email", "mx"]
                ))

            # Email source prediction from MX
            email_service = predict_email_service(mx_hosts)
            if email_service != "Self-Hosted / Unknown":
                findings.append(make_finding(
                    entity=f"Email service: {email_service}",
                    ftype="HunterHOW - Email Service Prediction",
                    source="HunterHOW",
                    confidence="High",
                    color="blue",
                    raw_data=f"Predicted provider: {email_service} | MX hosts: {', '.join(m[1] for m in mx_hosts)}",
                    tags=["email", "provider", "mx"]
                ))
            else:
                findings.append(make_finding(
                    entity="Self-Hosted / Unknown email service",
                    ftype="HunterHOW - Email Service Prediction",
                    source="HunterHOW",
                    confidence="Medium",
                    color="slate",
                    raw_data=f"Self-hosted or unknown MX provider | MX hosts: {', '.join(m[1] for m in mx_hosts)}",
                    tags=["email", "provider", "mx"]
                ))
    except Exception:
        pass

    # Domain variation / typosquatting analysis
    domain_variations = []
    domain_name = domain.split(".")[0] if "." in domain else domain
    domain_tld = "." + domain.split(".", 1)[1] if "." in domain else ""
    for known_domain, typos in TYPO_DOMAINS.items():
        known_name = known_domain.split(".")[0]
        if known_name in domain_name.lower() or domain_name.lower() in known_name:
            for typo in typos:
                domain_variations.append(typo)
                if len(domain_variations) >= 5:
                    break
    if not domain_variations:
        common_tld_swaps = [".com", ".org", ".net", ".io", ".co", ".app", ".dev", ".ai"]
        for tld in common_tld_swaps:
            if tld != domain_tld:
                variant = f"{domain_name}{tld}"
                if variant != domain:
                    domain_variations.append(variant)
    if domain_variations:
        findings.append(make_finding(
            entity=f"Possible domain variations: {', '.join(domain_variations[:8])}",
            type="HunterHOW - Domain Variation Analysis",
            source="HunterHOW",
            confidence="Low",
            color="yellow",
            raw_data=f"Suggested typo/variation checks for {domain}: {', '.join(domain_variations)}",
            tags=["domain", "typosquatting", "variations"]
        ))

    # Phone number extraction from all crawled pages
    all_crawled_text = html
    for _, pt in secondary_pages_html:
        all_crawled_text += " " + pt
    phone_numbers = set()
    for m in PHONE_REGEX.finditer(all_crawled_text):
        phone = m.group(0).strip()
        if len(phone) >= 7 and len(phone) <= 20:
            phone_numbers.add(phone)
    for phone in list(phone_numbers)[:8]:
        findings.append(make_finding(
            entity=phone,
            ftype="HunterHOW - Phone Number",
            source="HunterHOW",
            confidence="Medium",
            color="cyan",
            status="Extracted from page",
            raw_data=f"Phone: {phone}",
            tags=["phone", "contact"]
        ))

    if all_emails and smtp_host:
        verify_email = list(all_emails)[0]
        smtp_result = await check_smtp(smtp_host, verify_email)

        if smtp_result.get("valid") is True:
            findings.append(make_finding(
                entity=f"{verify_email} is VERIFIED (SMTP confirmed)",
                type="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="High",
                color="emerald",
                status="Verified",
                raw_data=f"SMTP verification passed for {verify_email} via {smtp_host}",
                tags=["email", "verified", "smtp"]
            ))
        elif smtp_result.get("valid") is False:
            findings.append(make_finding(
                entity=f"{verify_email} REJECTED by mail server",
                ftype="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="Medium",
                color="red",
                status="Invalid",
                raw_data=f"SMTP rejection for {verify_email}: {smtp_result.get('response', '')}",
                tags=["email", "invalid", "smtp"]
            ))
        else:
            findings.append(make_finding(
                entity=f"SMTP check inconclusive for {verify_email}",
                ftype="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="Low",
                color="orange",
                status="Unknown",
                raw_data=f"SMTP result: {smtp_result.get('response', '')}",
                tags=["email", "smtp"]
            ))

        banner = smtp_result.get("banner", "")
        if banner:
            banner_lower = banner.lower()
            if "catch" in banner_lower or "catch-all" in banner_lower:
                findings.append(make_finding(
                    entity=f"Catch-all detected: {banner[:100]}",
                    ftype="HunterHOW - Catch-All Detection",
                    source="HunterHOW",
                    confidence="Medium",
                    color="orange",
                    raw_data=f"Banner suggests catch-all: {banner[:200]}",
                    tags=["email", "catch-all"]
                ))

            banner_provider = "Unknown"
            for name, patterns in [
                ("Google Workspace", ["google", "gmail"]),
                ("Microsoft 365", ["outlook", "microsoft", "office365"]),
                ("ProtonMail", ["protonmail"]),
                ("Zoho", ["zoho"]),
                ("Fastmail", ["fastmail", "messagingengine"]),
                ("Yandex", ["yandex"]),
                ("Mailgun", ["mailgun"]),
                ("Cpanel/Exim", ["exim", "cpanel"]),
                ("Postfix", ["postfix"]),
                ("Sendmail", ["sendmail"]),
            ]:
                if any(p in banner_lower for p in patterns):
                    banner_provider = name
                    break

            if banner_provider != "Unknown":
                findings.append(make_finding(
                    entity=f"Mail server: {banner_provider}",
                    ftype="HunterHOW - Mail Server Provider",
                    source="HunterHOW",
                    confidence="High",
                    color="blue",
                    raw_data=f"SMTP banner: {banner[:200]}",
                    tags=["email", "provider"]
                ))
    elif smtp_host and not all_emails:
        catch_all_test = f"catchalltest{abs(hash(domain)) % 10000}@{domain}"
        smtp_result = await check_smtp(smtp_host, catch_all_test)
        if smtp_result.get("valid") is True:
            findings.append(make_finding(
                entity=f"Server accepts ALL email at {domain} (Catch-All)",
                type="HunterHOW - Catch-All Detected",
                source="HunterHOW",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                raw_data=f"Catch-all confirmed via SMTP test",
                tags=["email", "catch-all"]
            ))

    for pattern, platform in SOCIAL_PATTERNS:
        social_matches = re.findall(pattern, html, re.IGNORECASE)
        for url, page_text in secondary_pages_html:
            social_matches.extend(re.findall(pattern, page_text, re.IGNORECASE))
        for sm in list(dict.fromkeys(social_matches))[:3]:
            findings.append(make_finding(
                entity=sm[:200],
                ftype=f"HOW - {platform} Profile",
                source="HunterHOW",
                confidence="High",
                color="purple" if "linkedin" in platform.lower() else "slate",
                raw_data=sm[:500],
                tags=["social", platform.lower().replace(" ", "-").replace("/", "")]
            ))

    email_confidence = 0
    if all_found_emails:
        total = len(all_found_emails)
        sources = 0
        if mailto_emails: sources += 1
        if pgp_emails: sources += 1
        if text_emails: sources += 1
        if js_emails: sources += 1
        if verified_mailboxes: sources += 1
        email_confidence = min(100, (total * 5) + (sources * 10))
        if total >= 10: email_confidence += 10
        if total >= 25: email_confidence += 10
        conf_label = "Low" if email_confidence < 40 else "Medium" if email_confidence < 70 else "High"
        findings.append(make_finding(
            entity=f"Email data confidence: {email_confidence}/100 ({conf_label})",
            type="HunterHOW - Email Confidence Score",
            source="HunterHOW",
            confidence="Medium",
            color="emerald" if email_confidence >= 70 else "orange" if email_confidence >= 40 else "slate",
            raw_data=f"Confidence: {email_confidence}/100 | {total} emails from {sources} sources",
            tags=["email", "confidence"]
        ))

    import dns.resolver as dns_res
    dns_loop = asyncio.get_event_loop()
    try:
        spf_txt = await dns_loop.run_in_executor(None, lambda: dns_res.resolve(domain, 'TXT'))
        for r in spf_txt:
            txt = str(r)
            if txt.startswith("v=spf1"):
                findings.append(make_finding(
                    entity=txt[:200],
                    ftype="HunterHOW - SPF Record Discovery",
                    source="HunterHOW",
                    confidence="High",
                    color="emerald",
                    raw_data=txt[:1000],
                    tags=["email", "spf"]
                ))
                break
    except:
        pass

    try:
        dmarc_txt = await dns_loop.run_in_executor(None, lambda: dns_res.resolve(f"_dmarc.{domain}", 'TXT'))
        for r in dmarc_txt:
            txt = str(r)
            if "v=DMARC" in txt:
                findings.append(make_finding(
                    entity=txt[:200],
                    ftype="HunterHOW - DMARC Record Discovery",
                    source="HunterHOW",
                    confidence="High",
                    color="emerald",
                    raw_data=txt[:1000],
                    tags=["email", "dmarc"]
                ))
                break
    except:
        pass

    for sel in ["default", "google", "mail", "dkim", "selector1", "k1"]:
        try:
            dkim_txt = await dns_loop.run_in_executor(None, lambda: dns_res.resolve(f"{sel}._domainkey.{domain}", 'TXT'))
            for r in dkim_txt:
                findings.append(make_finding(
                    entity=f"DKIM selector '{sel}' found",
                    ftype="HunterHOW - DKIM Discovery",
                    source="HunterHOW",
                    confidence="High",
                    color="emerald",
                    raw_data=str(r)[:500],
                    tags=["email", "dkim"]
                ))
                break
        except:
            pass

    if all_found_emails:
        try:
            paste1 = await safe_fetch(client, f"https://psbdmp.ws/api/search/{domain}", timeout=10.0)
            if paste1.status_code == 200 and paste1.text.strip():
                findings.append(make_finding(
                    entity=f"Paste site results for {domain}",
                    ftype="HunterHOW - Breach/Paste Mention",
                    source="HunterHOW",
                    confidence="Medium",
                    color="orange",
                    raw_data=f"psbdmp.ws returned data for {domain}",
                    tags=["email", "breach", "paste"]
                ))
        except:
            pass

    findings.append(make_finding(
        entity=f"Total emails found: {len(all_found_emails)}",
        type="HunterHOW - Summary",
        source="HunterHOW",
        confidence="High" if all_found_emails else "Medium",
        color="emerald" if all_found_emails else "slate",
        threat_level="Informational",
        raw_data=f"Emails discovered: {len(all_found_emails)} | From mailto: {len(mailto_emails)} | From text: {len(text_emails)} | From JS: {len(js_emails) if js_content else 0} | From PGP: {len(pgp_emails)} | Mailboxes suggested: {len(verified_mailboxes)} | Secondary pages: {len(secondary_pages_html)}",
        tags=["email", "summary"]
    ))

    async def check_security_headers_how():
        for proto in ["https", "http"]:
            try:
                resp = await safe_fetch(client, f"{proto}://{domain}", timeout=8.0, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}
                for hdr in ["strict-transport-security", "x-content-type-options", "x-frame-options", "content-security-policy", "referrer-policy"]:
                    if hdr in hdrs:
                        findings.append(make_finding(
                            entity=f"{hdr}: {hdrs[hdr][:100]}", ftype="HOW - HTTP Security Header",
                            source="HunterHOW", confidence="High", color="emerald", threat_level="Informational",
                            tags=["http", "security"]))
                if "server" in hdrs:
                    findings.append(make_finding(
                        entity=f"Server: {hdrs['server'][:80]}", ftype="HOW - HTTP Server Header",
                        source="HunterHOW", confidence="Medium", color="slate", threat_level="Informational",
                        tags=["http", "server"]))
                break
            except: pass

    async def check_common_discovery_how():
        headers = {"User-Agent": "Mozilla/5.0"}
        paths = [f"https://{domain}/.well-known/security.txt", f"https://{domain}/.well-known/change-password",
                 f"https://{domain}/robots.txt", f"https://{domain}/sitemap.xml",
                 f"https://{domain}/humans.txt", f"https://{domain}/security.txt",
                 f"https://{domain}/ads.txt", f"https://{domain}/crossdomain.xml"]
        async def check_path(path):
            try:
                resp = await safe_fetch(client, path, timeout=8.0, follow_redirects=True, headers=headers)
                if resp.status_code == 200:
                    pname = path.split("/")[-1]
                    findings.append(make_finding(
                        entity=f"{pname} accessible ({len(resp.text)} bytes)",
                        type="HOW - File Discovery", source="HunterHOW",
                        confidence="High", color="slate", threat_level="Informational",
                        tags=["discovery", "file"]))
                    if "security.txt" in path and "Contact" in resp.text:
                        findings.append(make_finding(
                            entity=f"Security contact info found", ftype="HOW - Security.txt",
                            source="HunterHOW", confidence="High", color="emerald",
                            raw_data=resp.text[:2000], tags=["security", "disclosure"]))
                        for m in EMAIL_REGEX.finditer(resp.text):
                            findings.append(make_finding(
                                entity=m.group(0).lower(), ftype="HOW - Security.txt Email",
                                source="HunterHOW", confidence="High", color="blue",
                                tags=["email", "security"]))
            except: pass
        await asyncio.gather(*[check_path(p) for p in paths])

    async def check_name_extraction():
        all_text = html[:30000]
        for _, pt in secondary_pages_html:
            all_text += " " + pt[:5000]
        people = set()
        for m in re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', all_text):
            full = m.group(1).strip()
            if 3 <= len(full) <= 40 and not any(x in full.lower() for x in ["the ", "this ", "that ", "with ", "from "]):
                people.add(full)
        for name in list(people)[:5]:
            findings.append(make_finding(
                entity=name, ftype="HOW - Person Name",
                source="HunterHOW", confidence="Low", color="slate", threat_level="Informational",
                tags=["people", "name"]))

    async def check_cookie_analysis():
        try:
            resp = await safe_fetch(client, f"https://{domain}", timeout=8.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
            cookies = resp.cookies
            if cookies:
                for name in list(cookies.keys())[:5]:
                    findings.append(make_finding(
                        entity=f"Cookie: {name}", ftype="HOW - Cookie Discovery",
                        source="HunterHOW", confidence="Medium", color="slate", threat_level="Informational",
                        tags=["http", "cookie"]))
                trackers = [c for c in cookies if c.lower().startswith(("__cf","__utm","_ga","_gid","_fbp","_hjid"))]
                if trackers:
                    findings.append(make_finding(
                        entity=f"Tracking cookies: {', '.join(trackers)[:100]}",
                        type="HOW - Tracking Cookie", source="HunterHOW",
                        confidence="Medium", color="orange", threat_level="Informational",
                        tags=["privacy", "tracking"]))
        except: pass

    async def check_page_metadata():
        title = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title:
            findings.append(make_finding(
                entity=f"Title: {title.group(1).strip()[:100]}",
                type="HOW - Page Title", source="HunterHOW",
                confidence="High", color="slate", threat_level="Informational",
                tags=["page", "metadata"]))
        for m in list(re.finditer(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE))[:5]:
            findings.append(make_finding(
                entity=f"Meta {m.group(1)}: {m.group(2)[:80]}",
                type="HOW - Meta Tag", source="HunterHOW",
                confidence="High", color="slate", threat_level="Informational",
                tags=["page", "metadata"]))

    async def check_tech_stack():
        indicators = {"WordPress":["/wp-content/","/wp-admin/"],"Drupal":["drupal"],"Shopify":["shopify","myshopify"],
            "Cloudflare":["cloudflare","__cfduid"],"jQuery":["jquery"],"Bootstrap":["bootstrap"],
            "React":["react"],"Vue.js":["vuejs"],"Angular":["angular"],
            "nginx":["nginx"],"Apache":["apache"],"PHP":[".php"],
            "GA/GTM":["google-analytics","gtag","gtm.js"]}
        detected = [tech for tech, pats in indicators.items() if any(p in html.lower() for p in pats)]
        if detected:
            findings.append(make_finding(
                entity=f"Tech: {', '.join(detected[:8])}", ftype="HOW - Technology Stack",
                source="HunterHOW", confidence="Medium", color="purple",
                tags=["tech", "stack"]))
        ga = re.search(r'UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,12}', html)
        if ga:
            findings.append(make_finding(
                entity=f"Analytics: {ga.group(0)}", ftype="HOW - Analytics ID",
                source="HunterHOW", confidence="High", color="slate",
                tags=["analytics", "tracking"]))

    await asyncio.gather(
        check_security_headers_how(),
        check_common_discovery_how(),
        check_name_extraction(),
        check_cookie_analysis(),
        check_page_metadata(),
        check_tech_stack(),
    )

    return findings
