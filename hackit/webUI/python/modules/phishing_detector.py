import httpx
import asyncio
import re
import json
import idna
import ssl
import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict
from module_common import safe_fetch, safe_fetch_json, make_finding
from models import IntelligenceFinding

LOOKALIKE_DOMAINS = [
    "go0gle", "g00gle", "googie", "goog1e", "go0gle.com", "gogle",
    "facebo0k", "faceb00k", "facebok", "faceboook", "facebo0k.com",
    "paypa1", "paypai", "paypall", "paypa1.com",
    "amaz0n", "amazn", "amazonn", "amaz0n.com",
    "micr0soft", "micros0ft", "micr0s0ft", "micr0soft.com",
    "app1e", "appple", "ap ple", "app1e.com",
    "netf1ix", "netfIix", "netflx", "netfl1x",
    "instagr4m", "instagrm", "instaggram", "instagr4m.com",
    "tw1tter", "twltter", "twitt3r", "tw1tter.com",
    "whatsapp", "whatsap", "whatsappp", "whatsapp.com",
    "te1egram", "telegr4m", "teIegram", "te1egram.com",
    "1inkedin", "linkedln", "Iinkedin", "1inkedin.com",
    "y0utube", "youtub3", "y0utube.com", "youtubee",
    "ad0be", "adob3", "ad0be.com",
    "d0xbin", "d0xbin.com",
]

EXTRA_LOOKALIKES = [
    "goog1e", "g00gle", "g0ogle", "go0gle", "gogle", "googIe", "goog1e.com",
    "faceb00k", "facebo0k", "facebok", "faceboook", "faceb0ok", "f4cebook",
    "paypa1", "payp4l", "paypaI", "p4ypal", "paypa1.com",
    "amaz0n", "amazn", "am4zon", "amaz0n.com", "am4z0n",
    "micr0s0ft", "micr0s0ft", "micros0ft", "micr0soft", "m1cr0s0ft",
    "app1e", "appIe", "ap ple", "app1e.com", "4pple",
    "netf1ix", "netfIix", "netfl1x", "n3tf1ix", "n3tfl1x",
    "inst4gr4m", "inst4gram", "instagr4m", "1nstagram",
    "tw1tt3r", "twitt3r", "tw1tter", "twltter", "tw1ttr",
    "wh4ts4pp", "wh4tsapp", "whats4pp", "wh4tsapp",
    "t3l3gram", "t3l3gr4m", "telegr4m", "t3lgram",
    "l1nked1n", "l1nkedin", "linked1n", "linkedln",
    "y0utub3", "y0utube", "youtub3", "y0utu83",
    "cr0wdstr1ke", "crowdstrike", "cr0wdstrike",
    "d0ck3r", "dock3r", "d0cker", "d0cker.com",
    "g1thub", "g1thub", "g1tlab", "g1tlab",
    "b1tc01n", "b1tco1n", "b1tcoin", "b1tc0in",
    "3th3r3um", "eth3r3um", "3thereum", "eth3reum",
    "b1n4nc3", "b1nance", "b1nanse", "b1n4nce",
    "c01nb4s3", "co1nbase", "co1nbase", "c01nbase",
]

TYPO_DOMAINS = [
    "googel", "gooogle", "googl", "goolge", "goole", "goog",
    "facebok", "fcebook", "facbook", "acebook", "fasebook",
    "paypl", "payal", "paipal", "pypal", "payapl",
    "amzon", "amazn", "amzon", "amzaon", "amanzon",
]

EXTRA_TYPOS = [
    "goggle", "goolge", "googel", "gooogle", "googlee",
    "facbook", "facebok", "fcebook", "fasebook",
    "paypall", "paypal", "paypl", "pypal",
    "amzonn", "amazoon", "amazn", "amzon",
    "microsft", "microsoft", "micosoft", "micrsoft",
    "appple", "aple", "appl", "apppe",
    "netflx", "netfix", "netflic", "netfllix",
    "instgram", "instagrm", "instagrram", "instragm",
    "twiter", "twtter", "twittr", "twiiter",
    "whatsap", "whatspp", "watsapp", "whatapp",
    "telegam", "telegrm", "telegramm", "teIegram",
    "linkein", "linkedn", "linkedin", "Iinkedin",
    "youtbe", "youtub", "yutube", "youtubee",
    "adobe", "adobee", "adbe",
]

SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "click", "work", "date",
    "racing", "review", "stream", "download", "loan", "men",
    "bid", "trade", "webcam", "science", "party", "gdn",
    "win", "mom", "uno", "icu", "xyz", "top", "club",
    "online", "site", "live", "shop", "store", "help",
]

EXTRA_SUSPICIOUS_TLDS = [
    "cfd", "faith", "LOL", "work", "bond", "repl", "ovh",
    "host", "press", "rest", "moe", "cfd", "banzai",
    "рус", "укр", "wang", "xin", "vip", "pro", "cc",
    "fun", "life", "blog", "sbs", "digital", "loan",
    "kim", "news", "today", "list", "cool", "global",
    "group", "agency", "center", "world", "tech",
    "info", "email", "cloud", "systems", "solutions",
]

HOMOGRAPH_CHARS = {
    "a": ["а", "à", "á", "â", "ã", "ä", "å", "ɑ", "α", "а", "Ꭺ", "Ⲁ"],
    "c": ["с", "ç", "ć", "ĉ", "ċ", "č", "ↄ", "ⅽ", "ϲ"],
    "e": ["е", "è", "é", "ê", "ë", "ē", "ĕ", "ė", "ę", "ě", "ё", "ӛ"],
    "i": ["і", "ì", "í", "î", "ï", "ĩ", "ī", "ĭ", "į", "ı", "ΐ", "ί"],
    "o": ["о", "ò", "ó", "ô", "õ", "ö", "ø", "ō", "ŏ", "ő", "ο", "σ", "〇", "ⲟ"],
    "p": ["р", "þ", "ρ", "ⲣ"],
    "s": ["ѕ", "ş", "š", "ŝ", "ș", "ѕ", "ꜱ"],
    "u": ["υ", "ù", "ú", "û", "ü", "ũ", "ū", "ŭ", "ů", "µ"],
    "x": ["х", "×", "✕", "✖", "ⅹ", "ⲭ"],
    "y": ["у", "ý", "ÿ", "ŷ", "ӯ", "ӱ"],
    "b": ["ь", "ъ", "Ь", "Ъ"],
    "m": ["м", "м"],
    "h": ["н", "һ", "Н"],
    "k": ["к", "κ"],
    "t": ["т", "τ"],
}

PHISHING_KEYWORDS = [
    "verify", "login", "sign-in", "signin", "account", "secure",
    "update", "confirm", "reset", "password", "credential",
    "banking", "payment", "suspend", "alert", "security",
    "authenticate", "validate", "unlock", "restrict", "limited",
    "blocked", "unauthorized", "recent activity", "unusual",
    "invoice", "refund", "deposit", "withdrawal", "transaction",
    "2fa", "mfa", "two-factor", "two factor", "multi-factor",
    "verification code", "security code", "one-time", "otp",
]

EXTRA_PHISHING_KEYWORDS = [
    "unusual sign-in", "suspicious activity", "account recovery",
    "identity confirmation", "document verification", "kyc",
    "compliance", "regulatory", "account review", "temporary hold",
    "limited access", "restricted access", "action required",
    "urgent notification", "security alert", "account alert",
    "payment confirmation", "billing update", "subscription",
    "reactivate", "re-activate", "termination", "deactivation",
    "charge", "overdue", "payment failed", "transaction failed",
    "confirmed", "shipment", "tracking", "delivery", "shipping",
    "prize", "winner", "lottery", "inheritance", "bequest",
    "grant", "fund", "compensation", "settlement",
    "tax refund", "rebate", "stimulus", "relief",
]

def check_suspicious_tld(domain: str) -> list:
    findings = []
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in SUSPICIOUS_TLDS or tld in EXTRA_SUSPICIOUS_TLDS:
            findings.append(tld)
    return findings

def detect_lookalike(domain: str) -> list:
    findings = []
    domain_lower = domain.lower()
    for lookalike in LOOKALIKE_DOMAINS + EXTRA_LOOKALIKES:
        if lookalike.lower() in domain_lower:
            findings.append(lookalike)
    for typo in TYPO_DOMAINS + EXTRA_TYPOS:
        if typo.lower() in domain_lower:
            findings.append(typo)
    return findings

def detect_homograph(domain: str) -> list:
    findings = []
    for char, homoglyphs in HOMOGRAPH_CHARS.items():
        for h in homoglyphs:
            if h in domain:
                findings.append({"original": char, "homoglyph": h, "char_code": hex(ord(h))})
    return findings

def check_url_structure(url: str) -> list:
    findings = []
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http", ""):
            findings.append(f"Unusual scheme: {parsed.scheme}")
        if "@" in parsed.netloc:
            findings.append("URL contains @ symbol (credential smuggling)")
        if re.search(r'\d{3,}', parsed.netloc):
            findings.append("IP-based URL instead of domain")
        dash_count = parsed.netloc.count("-")
        if dash_count > 2:
            findings.append(f"Multiple hyphens in domain ({dash_count})")
        subdomain_count = len(parsed.netloc.split(".")) - 1
        if subdomain_count > 3:
            findings.append(f"Excessive subdomains ({subdomain_count})")
        if parsed.netloc.count(".") > 4:
            findings.append(f"Excessive dots in hostname ({parsed.netloc.count('.')})")
        if len(parsed.netloc) > 50:
            findings.append(f"Very long hostname ({len(parsed.netloc)} chars)")
        if parsed.path and len(parsed.path) > 100:
            findings.append(f"Very long path ({len(parsed.path)} chars)")
        numeric_subdomains = sum(1 for part in parsed.netloc.split(".") if part.isdigit())
        if numeric_subdomains > 2:
            findings.append(f"Multiple numeric subdomains ({numeric_subdomains})")
    except:
        pass
    return findings

def extract_html_indicators(html: str) -> list:
    indicators = []
    try:
        form_count = len(re.findall(r'<form', html, re.IGNORECASE))
        input_count = len(re.findall(r'<input', html, re.IGNORECASE))
        password_count = len(re.findall(r'type=["\']password["\']', html, re.IGNORECASE))
        submit_count = len(re.findall(r'type=["\']submit["\']', html, re.IGNORECASE))
        hidden_count = len(re.findall(r'type=["\']hidden["\']', html, re.IGNORECASE))
        text_count = len(re.findall(r'type=["\']text["\']', html, re.IGNORECASE))

        if password_count > 0:
            indicators.append(f"{password_count} password field(s)")
        if submit_count > 0:
            indicators.append(f"{submit_count} submit button(s)")
        if form_count > 0:
            indicators.append(f"{form_count} form(s)")
        if hidden_count > 0:
            indicators.append(f"{hidden_count} hidden field(s)")

        obfuscated = re.findall(r'(?:eval|atob|btoa|unescape|decodeURIComponent|fromCharCode)\s*\(', html, re.IGNORECASE)
        if obfuscated:
            indicators.append(f"{len(obfuscated)} obfuscation function(s)")

        iframes = re.findall(r'<iframe', html, re.IGNORECASE)
        if iframes:
            indicators.append(f"{len(iframes)} iframe(s)")

        meta_refresh = re.findall(r'<meta[^>]+http-equiv=["\']refresh["\']', html, re.IGNORECASE)
        if meta_refresh:
            indicators.append(f"{len(meta_refresh)} meta refresh tag(s)")

        javascript_uri = re.findall(r'href=["\']javascript:', html, re.IGNORECASE)
        if javascript_uri:
            indicators.append(f"{len(javascript_uri)} javascript: URI(s)")

        data_uri = re.findall(r'src=["\']data:', html, re.IGNORECASE)
        if data_uri:
            indicators.append(f"{len(data_uri)} data: URI(s)")

        base64_inline = re.findall(r'base64,', html, re.IGNORECASE)
        if base64_inline:
            indicators.append(f"{len(base64_inline)} base64 encoded content(s)")

        external_forms = re.findall(r'<form[^>]+action=["\']https?://(?!' + re.escape(re.search(r'<base[^>]+href=["\']([^"\']+)', html, re.IGNORECASE).group(1) if re.search(r'<base[^>]+href=["\']([^"\']+)', html, re.IGNORECASE) else "samedomainonly") + r')[^"\']+', html, re.IGNORECASE)
        if external_forms:
            indicators.append(f"{len(external_forms)} external form action(s)")

        short_url_patterns = re.findall(r'(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|short\.link|t\.co|rb\.gy|shorturl\.at|v\.gd)', html, re.IGNORECASE)
        if short_url_patterns:
            indicators.append(f"{len(short_url_patterns)} URL shortener(s)")
    except:
        pass
    return indicators

async def check_openphish(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, "https://openphish.com/feed.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            urls = resp.text.strip().splitlines()
            results = [u.strip() for u in urls if u.strip()][:200]
    except:
        pass
    return results

async def check_phishstats(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, "https://phishstats.info/phish_stats.csv", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            lines = resp.text.strip().splitlines()
            for line in lines[1:51]:
                parts = line.split(",")
                if len(parts) >= 3:
                    results.append(parts[-1].strip('" '))
    except:
        pass
    return results

async def check_urlscan_recent(client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, "https://urlscan.io/api/v1/result/", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("results", [])[:30]:
                results.append(item.get("page", {}).get("url", ""))
    except:
        pass
    return results

async def check_ssl_cert_age(domain: str) -> dict:
    result = {"days_remaining": None, "days_since_creation": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                if not_before:
                    created = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    result["days_since_creation"] = (datetime.now() - created).days
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result["days_remaining"] = (expiry - datetime.now()).days
    except:
        result["error"] = "Could not retrieve SSL cert"
    return result

async def check_target_in_phish_feeds(target: str, openphish_urls: list, phishstats_urls: list, urlscan_urls: list) -> list:
    matches = []
    target_lower = target.lower()
    for url_list, source in [(openphish_urls, "OpenPhish"), (phishstats_urls, "PhishStats"), (urlscan_urls, "URLScan.io")]:
        for url in url_list:
            if target_lower in url.lower():
                matches.append({"source": source, "url": url})
    return matches[:10]

async def calculate_risk_score(lookalikes: list, homographs: list, url_issues: list,
                                suspicious_tlds: list, html_indicators: list,
                                keyword_matches: list) -> dict:
    score = 0
    breakdown = {}

    score += min(len(lookalikes) * 15, 30)
    breakdown["lookalike"] = {"count": len(lookalikes), "score": min(len(lookalikes) * 15, 30), "max": 30}

    score += min(len(homographs) * 5, 20)
    breakdown["homograph"] = {"count": len(homographs), "score": min(len(homographs) * 5, 20), "max": 20}

    score += min(len(url_issues) * 10, 25)
    breakdown["url_issues"] = {"count": len(url_issues), "score": min(len(url_issues) * 10, 25), "max": 25}

    score += min(len(suspicious_tlds) * 15, 15)
    breakdown["tld"] = {"count": len(suspicious_tlds), "score": min(len(suspicious_tlds) * 15, 15), "max": 15}

    score += min(len(html_indicators) * 5, 20)
    breakdown["html"] = {"count": len(html_indicators), "score": min(len(html_indicators) * 5, 20), "max": 20}

    score += min(len(keyword_matches) * 2, 20)
    breakdown["keywords"] = {"count": len(keyword_matches), "score": min(len(keyword_matches) * 2, 20), "max": 20}

    score = min(score, 100)
    severity = "Critical" if score >= 75 else ("High Risk" if score >= 50 else ("Elevated Risk" if score >= 25 else "Low Risk"))

    return {"score": score, "severity": severity, "breakdown": breakdown}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    url = target.strip()
    
    parsed = urlparse(url)
    domain = parsed.netloc or url

    lookalikes = detect_lookalike(domain)
    homographs = detect_homograph(domain)
    url_issues = check_url_structure(url)
    suspicious_tlds = check_suspicious_tld(domain)

    for lookalike in lookalikes:
        findings.append(make_finding(
            entity=f"Lookalike domain detected: {lookalike} in {domain}",
            type="Phishing: Lookalike Domain",
            source="PhishingDetector",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Suspicious",
            resolution=domain,
            raw_data=f"Lookalike: {lookalike}",
            tags=["phishing", "lookalike", "brand-abuse", lookalike]
        ))

    for hg in homographs[:10]:
        findings.append(make_finding(
            entity=f"Homograph detected: '{hg['original']}' replaced with '{hg['homoglyph']}' (U+{hg['char_code'][2:]})",
            type="Phishing: Homograph Attack",
            source="PhishingDetector",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Suspicious",
            resolution=domain,
            tags=["phishing", "homograph", "unicode", "idn"]
        ))

    for issue in url_issues:
        findings.append(make_finding(
            entity=f"URL structural issue: {issue}",
            type="Phishing: URL Anomaly",
            source="PhishingDetector",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Suspicious",
            resolution=domain,
            tags=["phishing", "url-anomaly"]
        ))

    for tld in suspicious_tlds:
        findings.append(make_finding(
            entity=f"Suspicious TLD: .{tld}",
            type="Phishing: Suspicious TLD",
            source="PhishingDetector",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Warning",
            resolution=domain,
            tags=["phishing", "tld", f"dot-{tld}"]
        ))

    openphish_urls = await check_openphish(client)
    if openphish_urls:
        findings.append(make_finding(
            entity=f"OpenPhish feed: {len(openphish_urls)} live phishing URLs",
            type="Phishing: OpenPhish Feed",
            source="PhishingDetector",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Feed Available",
            resolution=domain,
            tags=["phishing", "openphish", "feed"]
        ))

    phishstats_urls = await check_phishstats(client)
    if phishstats_urls:
        findings.append(make_finding(
            entity=f"PhishStats feed: {len(phishstats_urls)} live phishing URLs",
            type="Phishing: PhishStats Feed",
            source="PhishingDetector",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Feed Available",
            resolution=domain,
            tags=["phishing", "phishstats", "feed"]
        ))

    urlscan_results = await check_urlscan_recent(client)
    if urlscan_results:
        findings.append(make_finding(
            entity=f"URLScan.io: {len(urlscan_results)} recent scans",
            type="Phishing: URLScan Recent",
            source="PhishingDetector",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Data Available",
            resolution=domain,
            tags=["phishing", "urlscan", "recent"]
        ))

    feed_matches = await check_target_in_phish_feeds(domain, openphish_urls, phishstats_urls, urlscan_results)
    for match in feed_matches:
        findings.append(make_finding(
            entity=f"Target found in {match['source']}: {match['url'][:200]}",
            type="Phishing: Target in Phish Feed",
            source=match['source'],
            confidence="High",
            color="red",
            threat_level="Critical",
            status="Confirmed Phishing",
            resolution=domain,
            tags=["phishing", "confirmed", match['source'].lower()]
        ))

    ssl_info = await check_ssl_cert_age(domain)
    if ssl_info.get("days_since_creation") is not None:
        if ssl_info["days_since_creation"] < 30:
            findings.append(make_finding(
                entity=f"SSL cert created only {ssl_info['days_since_creation']} days ago (very recent)",
                type="Phishing: Recent SSL Certificate",
                source="PhishingDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Recent",
                resolution=domain,
                tags=["phishing", "ssl", "recent-cert"]
            ))
        else:
            findings.append(make_finding(
                entity=f"SSL cert age: {ssl_info['days_since_creation']} days since creation",
                type="Phishing: SSL Certificate Age",
                source="PhishingDetector",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Established",
                resolution=domain,
                tags=["ssl", "cert-age"]
            ))
        if ssl_info.get("days_remaining") is not None and ssl_info["days_remaining"] < 30:
            findings.append(make_finding(
                entity=f"SSL cert expires in {ssl_info['days_remaining']} days (expiring soon)",
                type="Phishing: Expiring SSL Certificate",
                source="PhishingDetector",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Expiring",
                resolution=domain,
                tags=["phishing", "ssl", "expiring"]
            ))

    try:
        resp = await safe_fetch(client, url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            html = resp.text
            html_indicators = extract_html_indicators(html)
            for indicator in html_indicators:
                findings.append(make_finding(
                    entity=f"HTML indicator: {indicator}",
                    type="Phishing: HTML Analysis",
                    source="PhishingDetector",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Detected",
                    resolution=domain,
                    tags=["phishing", "html-analysis"]
                ))

            html_lower = html.lower()
            all_keywords = PHISHING_KEYWORDS + EXTRA_PHISHING_KEYWORDS
            keyword_matches = [kw for kw in all_keywords if kw in html_lower]
            for kw in keyword_matches[:10]:
                findings.append(make_finding(
                    entity=f"Phishing keyword detected: {kw}",
                    type="Phishing: Keyword Match",
                    source="PhishingDetector",
                    confidence="Low",
                    color="yellow",
                    threat_level="Informational",
                    status="Keyword Found",
                    resolution=domain,
                    tags=["phishing", "keyword", kw.replace(" ", "-")]
                ))

            brand_names = ["paypal", "google", "facebook", "amazon", "microsoft", "apple",
                          "netflix", "instagram", "twitter", "whatsapp", "telegram",
                          "linkedin", "youtube", "adobe", "dropbox", "wordpress",
                          "cloudflare", "github", "gitlab", "bitbucket", "slack",
                          "discord", "reddit", "tiktok", "snapchat", "pinterest",
                          "uber", "airbnb", "spotify", "twitch", "onlyfans",
                          "coinbase", "binance", "kraken", "metamask", "opensea"]
            brand_mentions = [b for b in brand_names if b in html_lower]
            if brand_mentions:
                findings.append(make_finding(
                    entity=f"Brand names in page: {', '.join(brand_mentions[:5])}",
                    type="Phishing: Brand Reference",
                    source="PhishingDetector",
                    confidence="Low",
                    color="yellow",
                    threat_level="Informational",
                    status="Referenced",
                    resolution=domain,
                    tags=["phishing", "brand"] + brand_mentions[:3]
                ))

            redirect_chain = []
            if resp.history:
                for h in resp.history:
                    redirect_chain.append(str(h.url))
                findings.append(make_finding(
                    entity=f"Redirect chain: {' -> '.join(redirect_chain)}",
                    type="Phishing: Redirect Analysis",
                    source="PhishingDetector",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Redirects Detected",
                    resolution=domain,
                    tags=["phishing", "redirect"]
                ))
    except:
        pass

    risk = await calculate_risk_score(lookalikes, homographs, url_issues,
                                       suspicious_tlds, 
                                       [f for f in findings if "HTML" in f.type],
                                       [f for f in findings if "Keyword" in f.type])
    findings.append(make_finding(
        entity=f"Phishing Risk Score: {risk['score']}/100 ({risk['severity']})",
        type="Phishing: Risk Score",
        source="PhishingDetector",
        confidence="Medium",
        color="red" if risk['score'] >= 50 else "orange",
        threat_level=risk["severity"],
        status=f"Score: {risk['score']}",
        resolution=domain,
        raw_data=json.dumps(risk["breakdown"]),
        tags=["phishing", "risk-score", risk["severity"].lower().replace(" ", "-")]
    ))

    if not findings:
        findings.append(make_finding(
            entity="No phishing indicators detected",
            type="Phishing: Analysis Complete",
            source="PhishingDetector",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=domain,
            tags=["phishing", "clean"]
        ))

    return findings
