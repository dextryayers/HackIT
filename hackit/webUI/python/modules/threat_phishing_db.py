import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

PHISHING_FEEDS = [
    ("OpenPhish", "https://openphish.com/feed.txt"),
    ("PhishTank", "http://data.phishtank.com/data/online-valid.csv"),
    ("PhishStats", "https://phishstats.info/phish_stats.csv"),
    ("URLScan", "https://urlscan.io/phish/"),
    ("APWG", "https://apwg.org/threat-feed/"),
    ("Cisco Talos", "https://talosintelligence.com/feeds/ip-filter.blf"),
    ("Spamhaus", "https://www.spamhaus.org/drop/drop.txt"),
    ("Sucuri", "https://labs.sucuri.net/?s=phishing"),
]

PHISHING_CATEGORIES = {
    "banking": ["bank", "chase", "wells fargo", "bank of america", "hsbc", "barclays", "credit union", "online banking"],
    "social_media": ["facebook", "instagram", "twitter", "linkedin", "tiktok", "snapchat", "reddit"],
    "ecommerce": ["amazon", "ebay", "walmart", "target", "bestbuy", "shopify", "etsy", "alibaba", "aliexpress"],
    "government": ["irs", "gov", ".gov", "social security", "tax", "medicare", "dmv", "passport"],
    "crypto": ["coinbase", "binance", "metamask", "ledger", "trezor", "crypto", "bitcoin", "ethereum", "nft", "wallet"],
    "login_portal": ["login", "signin", "account", "verify", "secure", "authentication", "2fa", "mfa"],
    "document_sharing": ["google docs", "dropbox", "onedrive", "sharepoint", "docusign", "adobe", "pdf", "document"],
    "tech_support": ["microsoft", "apple", "google", "netflix", "paypal", "adobe", "amazon support", "tech support"],
    "shipping": ["fedex", "ups", "usps", "dhl", "tracking", "delivery", "shipment", "package"],
    "healthcare": ["cigna", "aetna", "blue cross", "unitedhealth", "medicare", "health", "covid", "vaccine"],
}

PHISHING_KIT_FINGERPRINTS = [
    "phishing kit", "phish kit", "fake login", "credential harvester",
    "rez0 phishing", "modlishka", "evilginx", "muraena",
    "socialfish", "shellphish", "zphisher", "nexphisher",
    "blackeye", "advphishing", "hackphisher", "hidden eye",
    "sneaky phisher", "go-phish", "gophish", "lure",
    "phisher kit", "fraud page", "spoof page",
]

PHISHING_TLDS = [".xyz", ".top", ".club", ".work", ".life", ".live", ".online",
                  ".site", ".space", ".store", ".shop", ".click", ".link", ".download",
                  ".review", ".country", ".science", ".party", ".gq", ".ml", ".cf", ".ga", ".tk"]

async def fetch_openphish(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://openphish.com/feed.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line:
                    results.append({"url": line, "source": "OpenPhish"})
    except:
        pass
    return results

async def fetch_phishtank(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"http://data.phishtank.com/data/online-valid.csv", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines[1:51]:
                parts = line.split(",")
                if len(parts) >= 5:
                    results.append({
                        "url": parts[1].strip('"') if len(parts) > 1 else "",
                        "phish_id": parts[0].strip('"') if len(parts) > 0 else "",
                        "verified": parts[4].strip('"') if len(parts) > 4 else "",
                        "source": "PhishTank"
                    })
    except:
        pass
    return results

async def fetch_phishstats(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client,"https://phishstats.info/phish_stats.csv", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            for line in lines[1:51]:
                parts = line.split(",")
                if len(parts) >= 3:
                    results.append({
                        "url": parts[1].strip('"') if len(parts) > 1 else "",
                        "ip": parts[2].strip('"') if len(parts) > 2 else "",
                        "source": "PhishStats"
                    })
    except:
        pass
    return results

async def check_phishing_feeds(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for feed_name, feed_url in PHISHING_FEEDS:
            try:
                resp = await safe_fetch(client,feed_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        results.append({"feed": feed_name, "url": feed_url, "found": True})
            except:
                pass
    except:
        pass
    return results

async def classify_phishing_category(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for category, keywords in PHISHING_CATEGORIES.items():
            for kw in keywords:
                if kw in target_lower:
                    results.append({"category": category, "matched_keyword": kw})
                    break
    except:
        pass
    return results

async def detect_phishing_tld(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        parsed = urlparse(target_lower)
        domain = parsed.netloc or target_lower
        for tld in PHISHING_TLDS:
            if domain.endswith(tld):
                results.append({"tld": tld, "domain": domain})
    except:
        pass
    return results

async def detect_phishing_kit_fingerprints(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for fingerprint in PHISHING_KIT_FINGERPRINTS:
            if fingerprint in target_lower:
                results.append({"fingerprint": fingerprint})
    except:
        pass
    return results

async def analyze_phishing_url_patterns(target: str) -> list:
    results = []
    try:
        patterns = {
            "IP-based URL": re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
            "Excessive subdomains": re.compile(r'(?:[a-zA-Z0-9-]+\.){4,}[a-zA-Z]{2,}'),
            "URL shortener": re.compile(r'bit\.ly|tinyurl|goo\.gl|ow\.ly|is\.gd|buff\.ly|shorturl|shorte\.st'),
            "Typosquatting": re.compile(r'(g00gle|googie|go0gle|rnicrosoft|app1e|arnazon|faceboook|instagrarn|twltter)'),
            "Base64 encoded": re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
            "Hex encoded": re.compile(r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}'),
            "@ symbol": re.compile(r'https?://[^@]+@'),
            "Multiple paths": re.compile(r'(/[a-zA-Z0-9_-]+){5,}'),
            "Suspicious keywords": re.compile(r'(login|signin|verify|update|confirm|secure|account|alert|unusual|suspicious)'),
        }
        for name, pattern in patterns.items():
            if pattern.search(target):
                results.append({"pattern": name})
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    openphish_data = await fetch_openphish(client)
    target_in_openphish = [u for u in openphish_data if query in u["url"].lower()]
    for r in target_in_openphish[:10]:
        findings.append(make_finding(
            entity=f"OpenPhish: {r['url']}",
            ftype="Phishing URL Detection",
            source="OpenPhish",
            confidence="High",
            color="red",
            category="Phishing Intelligence",
            threat_level="Critical",
            status="Phishing URL Found",
            resolution=query,
            tags=["phishing", "openphish", "phishing-url"]
        ))

    phishtank_data = await fetch_phishtank(client)
    target_in_phishtank = [u for u in phishtank_data if query in u["url"].lower()] if phishtank_data else []
    for r in target_in_phishtank[:10]:
        findings.append(make_finding(
            entity=f"PhishTank: {r['url']} (ID: {r['phish_id']}, verified: {r['verified']})",
            ftype="Phishing URL Detection",
            source="PhishTank",
            confidence="High",
            color="red",
            category="Phishing Intelligence",
            threat_level="Critical",
            status="Confirmed Phishing",
            resolution=query,
            tags=["phishing", "phishtank", "verified-phish"]
        ))

    phishstats_data = await fetch_phishstats(client)
    target_in_phishstats = [u for u in phishstats_data if query in u["url"].lower()] if phishstats_data else []
    for r in target_in_phishstats[:10]:
        findings.append(make_finding(
            entity=f"PhishStats: {r['url']} (IP: {r.get('ip', 'N/A')})",
            ftype="Phishing URL Detection",
            source="PhishStats",
            confidence="Medium",
            color="orange",
            category="Phishing Intelligence",
            threat_level="High Risk",
            status="Suspicious URL",
            resolution=query,
            tags=["phishing", "phishstats", "suspicious-url"]
        ))

    feed_results = await check_phishing_feeds(client, query)
    for r in feed_results:
        findings.append(make_finding(
            entity=f"Phishing feed match: {r['feed']}",
            ftype="Phishing Feed Detection",
            source=r['feed'],
            confidence="Medium",
            color="orange",
            category="Phishing Intelligence",
            threat_level="High Risk",
            status="Feed Hit",
            resolution=query,
            tags=["phishing", "feed", r['feed'].lower().replace(" ", "-")]
        ))

    category_results = await classify_phishing_category(query)
    for r in category_results:
        findings.append(make_finding(
            entity=f"Phishing category: {r['category']} (keyword: {r['matched_keyword']})",
            ftype="Phishing Category Classification",
            source="Phishing DB",
            confidence="Medium",
            color="yellow",
            category="Phishing Intelligence",
            threat_level="Elevated Risk",
            status="Categorized",
            resolution=query,
            tags=["phishing", "category", r['category'].lower()]
        ))

    tld_results = await detect_phishing_tld(query)
    for r in tld_results:
        findings.append(make_finding(
            entity=f"Phishing TLD detected: {r['tld']} for domain {r['domain']}",
            ftype="Phishing TLD Detection",
            source="Phishing DB",
            confidence="Medium",
            color="yellow",
            category="Phishing Intelligence",
            threat_level="Elevated Risk",
            status="Suspicious TLD",
            resolution=query,
            tags=["phishing", "tld", r['tld'].replace(".", "")]
        ))

    kit_results = await detect_phishing_kit_fingerprints(query)
    for r in kit_results:
        findings.append(make_finding(
            entity=f"Phishing kit fingerprint: {r['fingerprint']}",
            ftype="Phishing Kit Detection",
            source="Phishing DB",
            confidence="High",
            color="red",
            category="Phishing Intelligence",
            threat_level="High Risk",
            status="Kit Fingerprinted",
            resolution=query,
            tags=["phishing", "phishing-kit", r['fingerprint'].replace(" ", "-")]
        ))

    url_pattern_results = await analyze_phishing_url_patterns(query)
    for r in url_pattern_results:
        findings.append(make_finding(
            entity=f"Phishing URL pattern: {r['pattern']}",
            ftype="Phishing URL Analysis",
            source="Phishing DB",
            confidence="Low",
            color="yellow",
            category="Phishing Intelligence",
            threat_level="Elevated Risk",
            status="Pattern Matched",
            resolution=query,
            tags=["phishing", "url-pattern", r['pattern'].lower().replace(" ", "-")]
        ))

    if not target_in_openphish and not target_in_phishtank and not target_in_phishstats:
        findings.append(make_finding(
            entity=f"No phishing database hits for {query}",
            ftype="Phishing Database Check",
            source="Phishing DB",
            confidence="Low",
            color="emerald",
            category="Phishing Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["phishing", "clean", "no-hits"]
        ))

    findings.append(make_finding(
        entity=f"Phishing intelligence complete for {query}: checked {len(PHISHING_FEEDS)} feeds, {len(PHISHING_CATEGORIES)} categories, {len(PHISHING_KIT_FINGERPRINTS)} kit fingerprints",
        ftype="Phishing Intelligence Summary",
        source="Phishing DB",
        confidence="Medium",
        color="slate",
        category="Phishing Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["phishing", "summary", "intelligence"]
    ))

    return findings
