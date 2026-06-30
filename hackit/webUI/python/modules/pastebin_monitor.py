import httpx
import asyncio
import re
import json
from datetime import datetime
from collections import defaultdict
from typing import List
from urllib.parse import quote
from models import IntelligenceFinding

PASTE_SITES = [
    ("Pastebin", "https://pastebin.com/search?q={}"),
    ("Ghostbin", "https://ghostbin.com/search?q={}"),
    ("Rentry", "https://rentry.org/search?q={}"),
    ("PasteCode", "https://pastecode.io/s/search?q={}"),
    ("ControlC", "https://controlc.com/search.php?q={}"),
    ("Codepad", "https://codepad.co/search?q={}"),
    ("SlickPaste", "https://slickpaste.com/search?q={}"),
    ("PSBDMP", "https://psbdmp.ws/api/search/{}"),
    ("LeakIX", "https://leakix.net/search?scope=leak&q={}"),
    ("PastebinPL", "https://pastebin.pl/search?q={}"),
    ("Dpaste", "https://dpaste.org/search?q={}"),
    ("CentOS Paste", "https://paste.centos.org/search?q={}"),
    ("Ubuntu Paste", "https://paste.ubuntu.com/search?q={}"),
    ("Debian Paste", "https://paste.debian.net/search?q={}"),
    ("KDE Paste", "https://paste.kde.org/search?q={}"),
    ("GitHub Gist", "https://gist.github.com/search?q={}"),
    ("GitLab Snippet", "https://gitlab.com/search?search={}"),
    ("BitBucket Snippet", "https://bitbucket.org/search?q={}"),
    ("Hastebin", "https://hastebin.skyra.pw/search?q={}"),
    ("Rentry Raw", "https://rentry.org/{}/raw"),
]

CREDENTIAL_PATTERN = re.compile(
    r'(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(?P<password>\S+)'
)
API_KEY_PATTERN = re.compile(
    r'(?:sk_live|sk_test|pk_live|pk_test)_[0-9a-zA-Z]{24,}|'
    r'AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|'
    r'xox[baprs]-[0-9a-zA-Z\-]{24,}|'
    r'AIza[0-9A-Za-z\-_]{35}|'
    r'-----BEGIN\s?(RSA\s)?PRIVATE KEY-----'
)
EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
PHONE_PATTERN = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
CC_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

SECRET_PATTERNS = {
    "password": r'\bpassword\s*[:=]\s*\S+',
    "api_key": r'\b(?:api[_-]?key|apikey)\s*[:=]\s*\S+',
    "secret": r'\bsecret\s*[:=]\s*\S+',
    "token": r'\btoken\s*[:=]\s*\S+',
    "access_key": r'\b(?:access[_-]?key|accesskey)\s*[:=]\s*\S+',
    "database_url": r'\b(?:database[_-]?url|db[_-]?url|mongodb|postgresql|mysql)\s*[:=]\s*\S+',
}

CONTENT_CATEGORIES = {
    "credential_dump": ["password", "login", "email:password", "username:password", "combo"],
    "source_code": ["source code", "repository", "git", "github", "gitlab", "bitbucket"],
    "config_file": ["config", "configuration", "settings", ".env", "environment"],
    "financial": ["credit card", "cvv", "bank", "paypal", "stripe", "bitcoin", "wire"],
    "personal_data": ["ssn", "social security", "address", "phone", "passport", "driver license"],
    "hacking_tools": ["exploit", "payload", "shell", "backdoor", "rat", "malware"],
    "database_dump": ["sql dump", "database", "insert into", "create table", "mysql"],
}

async def check_paste_site(client: httpx.AsyncClient, site_name: str, url_template: str, target: str) -> list:
    results = []
    try:
        url = url_template.format(quote(target))
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and len(resp.text) > 200:
            results.append({"site": site_name, "url": url, "content_snippet": resp.text[:1000], "status": "accessible"})
    except:
        pass
    return results

async def categorize_content(text: str) -> list:
    categories = []
    text_lower = text.lower()
    for cat, keywords in CONTENT_CATEGORIES.items():
        for kw in keywords:
            if kw in text_lower:
                categories.append(cat)
                break
    return categories

async def detect_secrets(text: str) -> list:
    secrets = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            secrets.append({"type": name, "count": len(matches)})
    return secrets

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    all_text = ""

    for site_name, url_template in PASTE_SITES:
        results = await check_paste_site(client, site_name, url_template, query)
        for r in results:
            findings.append(IntelligenceFinding(
                entity=f"Mention on {site_name}",
                type="Paste Site Mention",
                source=site_name,
                confidence="Low",
                color="orange",
                threat_level="Elevated Risk",
                status="Found",
                resolution=query,
                raw_data=f"URL: {r['url']}",
                tags=["paste", "monitor", site_name.lower()]
            ))
            all_text += r.get("content_snippet", "") + "\n"

    if all_text:
        emails = EMAIL_PATTERN.findall(all_text)
        if emails:
            findings.append(IntelligenceFinding(
                entity=f"{len(set(emails))} unique emails exposed",
                type="Email Exposure",
                source="PastebinMonitor",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Exposed",
                resolution=query,
                tags=["email", "exposure", "paste"]
            ))

        ips = IP_PATTERN.findall(all_text)
        if ips:
            findings.append(IntelligenceFinding(
                entity=f"{len(set(ips))} IP addresses exposed",
                type="IP Exposure",
                source="PastebinMonitor",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Exposed",
                resolution=query,
                tags=["ip", "exposure", "paste"]
            ))

        api_keys = API_KEY_PATTERN.findall(all_text)
        if api_keys:
            findings.append(IntelligenceFinding(
                entity=f"{len(set(api_keys))} API keys exposed",
                type="API Key Exposure",
                source="PastebinMonitor",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Secret Exposed",
                resolution=query,
                tags=["api-key", "secret", "critical"]
            ))

        secrets = await detect_secrets(all_text)
        for secret in secrets:
            findings.append(IntelligenceFinding(
                entity=f"{secret['count']} {secret['type']} pattern(s) found",
                type=f"Secret Detection: {secret['type'].title()}",
                source="PastebinMonitor",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Detected",
                resolution=query,
                tags=["secret", secret["type"]]
            ))

        categories = await categorize_content(all_text)
        if categories:
            cat_str = ", ".join(set(categories))
            findings.append(IntelligenceFinding(
                entity=f"Content categories: {cat_str}",
                type="Paste Content Categorization",
                source="PastebinMonitor",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Categorized",
                resolution=query,
                tags=["content", "category"] + list(set(categories))
            ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No paste mentions found",
            type="Paste Monitor Complete",
            source="PastebinMonitor",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["paste", "clean"]
        ))

    return findings
