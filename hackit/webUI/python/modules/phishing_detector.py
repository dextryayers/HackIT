import httpx
import asyncio
import re
import json
import idna
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import List, Optional
from collections import defaultdict
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
TYPO_DOMAINS = [
    "googel", "gooogle", "googl", "goolge", "goole", "goog",
    "facebok", "fcebook", "facbook", "acebook", "fasebook",
    "paypl", "payal", "paipal", "pypal", "payapl",
    "amzon", "amazn", "amzon", "amzaon", "amanzon",
]
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "click", "work", "date",
    "racing", "review", "stream", "download", "loan", "men",
    "bid", "trade", "webcam", "science", "party", "gdn",
    "win", "mom", "uno", "icu", "xyz", "top", "club",
    "online", "site", "live", "shop", "store", "help",
]
HOMOGRAPH_CHARS = {
    "a": ["а", "à", "á", "â", "ã", "ä", "å", "ɑ", "α"],
    "c": ["с", "ç", "ć", "ĉ", "ċ", "č", "ↄ"],
    "e": ["е", "è", "é", "ê", "ë", "ē", "ĕ", "ė", "ę", "ě"],
    "i": ["і", "ì", "í", "î", "ï", "ĩ", "ī", "ĭ", "į", "ı"],
    "o": ["о", "ò", "ó", "ô", "õ", "ö", "ø", "ō", "ŏ", "ő", "ο"],
    "p": ["р", "þ"],
    "s": ["ѕ", "ş", "š", "ŝ", "ș"],
    "u": ["υ", "ù", "ú", "û", "ü", "ũ", "ū", "ŭ", "ů"],
    "x": ["х", "×", "✕", "✖"],
    "y": ["у", "ý", "ÿ", "ŷ"],
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

def check_suspicious_tld(domain: str) -> list:
    findings = []
    parts = domain.split(".")
    if len(parts) >= 2:
        tld = parts[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            findings.append(tld)
    return findings

def detect_lookalike(domain: str) -> list:
    findings = []
    domain_lower = domain.lower()
    for lookalike in LOOKALIKE_DOMAINS:
        if lookalike.lower() in domain_lower:
            findings.append(lookalike)
    for typo in TYPO_DOMAINS:
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
        path = parsed.path
        if re.search(r'\d{3,}', parsed.netloc):
            findings.append("IP-based URL instead of domain")
        dash_count = parsed.netloc.count("-")
        if dash_count > 2:
            findings.append(f"Multiple hyphens in domain ({dash_count})")
        subdomain_count = len(parsed.netloc.split(".")) - 1
        if subdomain_count > 3:
            findings.append(f"Excessive subdomains ({subdomain_count})")
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

        if password_count > 0:
            indicators.append(f"{password_count} password field(s)")
        if submit_count > 0:
            indicators.append(f"{submit_count} submit button(s)")
        if form_count > 0:
            indicators.append(f"{form_count} form(s)")

        external_links = re.findall(r'href=["\']https?://(?!' + re.escape(re.search(r'<base[^>]+href=["\']([^"\']+)', html, re.IGNORECASE).group(1) if re.search(r'<base[^>]+href=["\']([^"\']+)', html, re.IGNORECASE) else "samedomainonly") + r')[^"\']+', html, re.IGNORECASE)
        if external_links:
            indicators.append(f"{len(external_links)} external link(s)")

        obfuscated = re.findall(r'(?:eval|atob|btoa|unescape|decodeURIComponent|fromCharCode)\s*\(', html, re.IGNORECASE)
        if obfuscated:
            indicators.append(f"{len(obfuscated)} obfuscation function(s)")

        iframes = re.findall(r'<iframe', html, re.IGNORECASE)
        if iframes:
            indicators.append(f"{len(iframes)} iframe(s)")
    except:
        pass
    return indicators

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
        findings.append(IntelligenceFinding(
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
        findings.append(IntelligenceFinding(
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
        findings.append(IntelligenceFinding(
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
        findings.append(IntelligenceFinding(
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

    try:
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            html = resp.text
            html_indicators = extract_html_indicators(html)
            for indicator in html_indicators:
                findings.append(IntelligenceFinding(
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
            keyword_matches = [kw for kw in PHISHING_KEYWORDS if kw in html_lower]
            for kw in keyword_matches[:10]:
                findings.append(IntelligenceFinding(
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
                          "linkedin", "youtube", "adobe", "dropbox", "wordpress"]
            brand_mentions = [b for b in brand_names if b in html_lower]
            if brand_mentions:
                findings.append(IntelligenceFinding(
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
    except:
        pass

    risk = await calculate_risk_score(lookalikes, homographs, url_issues,
                                       suspicious_tlds, 
                                       [f for f in findings if "HTML" in f.type],
                                       [f for f in findings if "Keyword" in f.type])
    findings.append(IntelligenceFinding(
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
        findings.append(IntelligenceFinding(
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
