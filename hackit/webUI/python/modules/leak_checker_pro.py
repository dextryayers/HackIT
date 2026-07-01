import httpx
import asyncio
import re
import json
import hashlib
import math
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

EXTRA_LEAK_SOURCES = [
    ("FirefoxMonitor", lambda t: f"https://monitor.firefox.com/breaches?q={t}"),
    ("CheckLeaked", lambda t: f"https://checkleaked.cc/search?q={t}"),
    ("BreachCheck", lambda t: f"https://breachcheck.com/search?q={t}"),
    ("DataBreach", lambda t: f"https://databreach.com/search?q={t}"),
    ("VulnerabilityDB", lambda t: f"https://vulnerabilitydb.com/search?q={t}"),
    ("CredentialCheck", lambda t: f"https://credentialcheck.com/search?q={t}"),
    ("DarkWebLeaks", lambda t: f"https://darkwebleaks.com/search?q={t}"),
    ("HackCheck", lambda t: f"https://hackcheck.io/search?q={t}"),
    ("BreachAlarm", lambda t: f"https://breachalarm.com/search?q={t}"),
    ("PwnedCheck", lambda t: f"https://pwnedcheck.com/search?q={t}"),
]

CREDENTIAL_PATTERN = re.compile(
    r'(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(?P<password>\S+)'
)
USERNAME_PASS_PATTERN = re.compile(
    r'(?:username|user|login)\s*[:;=]\s*(\S+)\s*(?:password|pass|pwd)\s*[:;=]\s*(\S+)',
    re.IGNORECASE
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
JWT_PATTERN = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
BTC_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
ETH_PATTERN = re.compile(r'0x[a-fA-F0-9]{40}\b')

DATA_CLASSIFICATION = {
    "credential": ["password", "login", "credential", "email:password", "combo"],
    "financial": ["credit card", "cvv", "bank", "paypal", "stripe", "bitcoin"],
    "personal": ["ssn", "social security", "address", "phone", "passport", "driver"],
    "medical": ["medical", "health", "patient", "hipaa", "prescription"],
    "config": ["config", ".env", "database", "settings", "api key"],
    "source_code": ["source code", "github", "gitlab", "repository", "gist"],
}

SEVERITY_CLASSIFICATION = {
    "credential": {"level": "Critical", "color": "red"},
    "financial": {"level": "Critical", "color": "red"},
    "personal": {"level": "High Risk", "color": "red"},
    "medical": {"level": "High Risk", "color": "orange"},
    "config": {"level": "Elevated Risk", "color": "orange"},
    "source_code": {"level": "Elevated Risk", "color": "orange"},
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
    jwts = JWT_PATTERN.findall(text)
    if jwts:
        pii["jwts"] = list(set(jwts))[:5]
    btc = BTC_PATTERN.findall(text)
    if btc:
        pii["btc_wallets"] = list(set(btc))[:5]
    eth = ETH_PATTERN.findall(text)
    if eth:
        pii["eth_wallets"] = list(set(eth))[:5]
    return pii

async def analyze_password_strength(password: str) -> dict:
    if not password:
        return {"score": 0, "strength": "Unknown", "length": 0}
    length = len(password)
    entropy = 0
    if re.search(r'[a-z]', password): entropy += 26
    if re.search(r'[A-Z]', password): entropy += 26
    if re.search(r'[0-9]', password): entropy += 10
    if re.search(r'[^a-zA-Z0-9]', password): entropy += 33
    if entropy == 0: return {"score": 0, "strength": "Empty", "length": 0}
    actual_entropy = length * math.log2(entropy) if entropy > 0 else 0
    common_patterns = re.search(r'(123|password|qwerty|abc|admin|test|123456|iloveyou)', password, re.IGNORECASE)
    
    score = min(actual_entropy * 2, 100)
    if length < 8: score *= 0.5
    if common_patterns: score *= 0.5
    
    if score >= 80: strength = "Strong"
    elif score >= 50: strength = "Medium"
    else: strength = "Weak"
    
    return {"score": round(score), "strength": strength, "length": length, "entropy": round(actual_entropy, 2)}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    all_text = ""

    all_sources = LEAK_SOURCES + EXTRA_LEAK_SOURCES
    for name, url_builder in all_sources:
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
            severity_info = SEVERITY_CLASSIFICATION.get(pii_type.replace("_", " ").strip().split()[0], {"level": "High Risk", "color": "red"})
            if values:
                findings.append(IntelligenceFinding(
                    entity=f"{len(values)} {pii_type} exposed across leak sources",
                    type=f"PII Exposure: {pii_type.replace('_', ' ').title()}",
                    source="LeakCheckerPro",
                    confidence="High",
                    color=severity_info["color"],
                    threat_level=severity_info["level"],
                    status="Exposed",
                    resolution=t,
                    tags=["pii", pii_type, "exposure"]
                ))

        creds = CREDENTIAL_PATTERN.findall(all_text)
        if creds:
            weak_passwords = 0
            for email, passwd in creds[:20]:
                pwd_analysis = await analyze_password_strength(passwd)
                if pwd_analysis["strength"] == "Weak":
                    weak_passwords += 1
            findings.append(IntelligenceFinding(
                entity=f"{len(creds)} email:password credentials leaked ({weak_passwords} weak passwords)",
                type="Credential Leak Detected",
                source="LeakCheckerPro",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Credentials Leaked",
                resolution=t,
                raw_data=f"Total: {len(creds)}, Weak: {weak_passwords}",
                tags=["credential", "leak", "critical"]
            ))

        username_creds = USERNAME_PASS_PATTERN.findall(all_text)
        if username_creds:
            findings.append(IntelligenceFinding(
                entity=f"{len(username_creds)} username:password credentials leaked",
                type="Credential Leak: Username:Password",
                source="LeakCheckerPro",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Credentials Leaked",
                resolution=t,
                tags=["credential", "leak", "username-pass"]
            ))

        categories = await classify_data(all_text)
        if categories:
            cat_counts = defaultdict(int)
            for cat in categories:
                cat_counts[cat] += 1
            for cat, count in cat_counts.items():
                severity = SEVERITY_CLASSIFICATION.get(cat, {"level": "Elevated Risk", "color": "orange"})
                findings.append(IntelligenceFinding(
                    entity=f"Data classification: {cat.title()} ({count} indicators) - {severity['level']}",
                    type=f"Data Classification: {cat.title()}",
                    source="LeakCheckerPro",
                    confidence="Medium",
                    color=severity["color"],
                    threat_level=severity["level"],
                    status="Classified",
                    resolution=t,
                    tags=["classification", cat]
                ))

        total_pii_types = len(pii)
        if total_pii_types >= 3:
            findings.append(IntelligenceFinding(
                entity=f"{total_pii_types} distinct PII data types exposed - MULTIPLE DATA TYPES AT RISK",
                type="Data Breach Severity: Multiple PII Types",
                source="LeakCheckerPro",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Multi-Type Exposure",
                resolution=t,
                tags=["breach", "multi-pii", "critical"]
            ))

    source_count = len([f for f in findings if f.type == "Leak Source Access"])
    extra_source_count = len([f for f in findings if f.source in dict(EXTRA_LEAK_SOURCES)])
    if source_count > 0:
        total_sources = len(all_sources)
        findings.append(IntelligenceFinding(
            entity=f"Leak check complete: {source_count}/{total_sources} sources returned data ({extra_source_count} additional)",
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
