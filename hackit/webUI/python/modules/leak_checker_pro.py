import httpx
import asyncio
import re
import json
import hashlib
from datetime import datetime
from typing import List
from collections import defaultdict
from models import IntelligenceFinding

LEAK_SOURCES = [
    ("LeakIX", lambda t: f"https://leakix.net/search?scope=leak&q={t}"),
    ("PSBDMP", lambda t: f"https://psbdmp.ws/api/search/{t}"),
    ("HaveIBeenPwned", lambda t: f"https://haveibeenpwned.com/api/v3/breaches?domain={t}"),
    ("BreachDirectory", lambda t: f"https://breachdirectory.org/api/v1/search?query={t}"),
    ("DeHashed", lambda t: f"https://dehashed.com/search?q={t}"),
    ("LeakCheck", lambda t: f"https://leakcheck.io/search?q={t}"),
    ("IntelX", lambda t: f"https://intelx.io/?s={t}"),
    ("Snusbase", lambda t: f"https://snusbase.com/search?term={t}"),
    ("ScatteredSecrets", lambda t: f"https://scatteredsecrets.com/search?q={t}"),
    ("Scylla", lambda t: f"https://scylla.so/search?q={t}"),
    ("WeLeakInfo", lambda t: f"https://weleakinfo.com/search?query={t}"),
    ("LeakBase", lambda t: f"https://leakbase.io/search?q={t}"),
    ("LeakPeak", lambda t: f"https://leakpeak.io/search?q={t}"),
    ("Ghostbin", lambda t: f"https://ghostbin.com/search?q={t}"),
    ("Rentry", lambda t: f"https://rentry.org/search?q={t}"),
    ("PasteCode", lambda t: f"https://pastecode.io/s/search?q={t}"),
    ("SlickPaste", lambda t: f"https://slickpaste.com/search?q={t}"),
    ("ControlC", lambda t: f"https://controlc.com/search.php?q={t}"),
    ("Codepad", lambda t: f"https://codepad.co/search?q={t}"),
    ("Pastebin", lambda t: f"https://pastebin.com/search?q={t}"),
]

CREDENTIAL_PATTERN = re.compile(
    r'(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(?P<password>\S+)'
)
EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
PHONE_PATTERN = re.compile(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}')
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
CC_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
API_KEY_PATTERN = re.compile(
    r'(?:sk_live|sk_test|pk_live|pk_test)_[0-9a-zA-Z]{24,}|'
    r'AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|'
    r'xox[baprs]-[0-9a-zA-Z\-]{24,}|'
    r'AIza[0-9A-Za-z\-_]{35}|'
    r'-----BEGIN\s?(RSA\s)?PRIVATE KEY-----'
)

DATA_CLASSIFICATION = {
    "credential": ["password", "login", "credential", "email:password", "combo"],
    "financial": ["credit card", "cvv", "bank", "paypal", "stripe", "bitcoin"],
    "personal": ["ssn", "social security", "address", "phone", "passport", "driver"],
    "medical": ["medical", "health", "patient", "hipaa", "prescription"],
    "config": ["config", ".env", "database", "settings", "api key"],
    "source_code": ["source code", "github", "gitlab", "repository", "gist"],
}

async def check_source(client: httpx.AsyncClient, name: str, url_builder, target: str) -> list:
    results = []
    try:
        url = url_builder(target)
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and len(resp.text) > 100:
            results.append({"source": name, "url": url, "content": resp.text[:2000]})
    except:
        pass
    return results

async def classify_data(text: str) -> list:
    categories = []
    text_lower = text.lower()
    for cat, keywords in DATA_CLASSIFICATION.items():
        for kw in keywords:
            if kw in text_lower:
                categories.append(cat)
                break
    return categories

async def extract_all_pii(text: str) -> dict:
    pii = {}
    emails = EMAIL_PATTERN.findall(text)
    if emails:
        pii["emails"] = list(set(emails))[:10]
    phones = PHONE_PATTERN.findall(text)
    if phones:
        pii["phones"] = list(set(phones))[:10]
    ssns = SSN_PATTERN.findall(text)
    if ssns:
        pii["ssns"] = list(set(ssns))[:5]
    ccs = CC_PATTERN.findall(text)
    if ccs:
        pii["credit_cards"] = list(set(ccs))[:5]
    ips = IP_PATTERN.findall(text)
    if ips:
        pii["ips"] = list(set(ips))[:10]
    api_keys = API_KEY_PATTERN.findall(text)
    if api_keys:
        pii["api_keys"] = list(set(api_keys))[:5]
    return pii

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    all_text = ""

    for name, url_builder in LEAK_SOURCES:
        results = await check_source(client, name, url_builder, t)
        for r in results:
            findings.append(IntelligenceFinding(
                entity=f"Leak source: {name} returned data",
                type="Leak Source Access",
                source=name,
                confidence="Low",
                color="orange",
                threat_level="Elevated Risk",
                status="Data Available",
                resolution=t,
                raw_data=f"URL: {r['url']}",
                tags=["leak", "source", name.lower()]
            ))
            all_text += r.get("content", "") + "\n"

    if all_text:
        pii = await extract_all_pii(all_text)
        for pii_type, values in pii.items():
            if values:
                findings.append(IntelligenceFinding(
                    entity=f"{len(values)} {pii_type} exposed across leak sources",
                    type=f"PII Exposure: {pii_type.replace('_', ' ').title()}",
                    source="LeakCheckerPro",
                    confidence="High",
                    color="red" if pii_type in ("ssns", "credit_cards", "api_keys") else "orange",
                    threat_level="Critical" if pii_type in ("ssns", "credit_cards", "api_keys") else "High Risk",
                    status="Exposed",
                    resolution=t,
                    tags=["pii", pii_type, "exposure"]
                ))

        creds = CREDENTIAL_PATTERN.findall(all_text)
        if creds:
            findings.append(IntelligenceFinding(
                entity=f"{len(creds)} email:password credentials leaked",
                type="Credential Leak Detected",
                source="LeakCheckerPro",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Credentials Leaked",
                resolution=t,
                tags=["credential", "leak", "critical"]
            ))

        categories = await classify_data(all_text)
        if categories:
            cat_counts = defaultdict(int)
            for cat in categories:
                cat_counts[cat] += 1
            for cat, count in cat_counts.items():
                findings.append(IntelligenceFinding(
                    entity=f"Data classification: {cat.title()} ({count} indicators)",
                    type=f"Data Classification: {cat.title()}",
                    source="LeakCheckerPro",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Classified",
                    resolution=t,
                    tags=["classification", cat]
                ))

    source_count = len([f for f in findings if f.type == "Leak Source Access"])
    if source_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"Leak check complete: {source_count} sources returned data",
            type="Leak Check Summary",
            source="LeakCheckerPro",
            confidence="Medium",
            color="red" if source_count > 3 else "orange",
            threat_level="High Risk" if source_count > 3 else "Elevated Risk",
            status=f"{source_count} sources",
            resolution=t,
            tags=["summary", "leak-check"]
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No leaks found across any sources",
            type="Leak Check Complete",
            source="LeakCheckerPro",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["leak", "clean"]
        ))

    return findings
