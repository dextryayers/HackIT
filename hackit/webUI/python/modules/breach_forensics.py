import httpx
import asyncio
import re
import json
from datetime import datetime
from collections import defaultdict
from urllib.parse import quote
from models import IntelligenceFinding

CREDENTIAL_PATTERN = re.compile(
    r"(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(?P<password>\S+)"
)
USERNAME_PASS_PATTERN = re.compile(
    r"(?:username|user|login)\s*[:;=]\s*(\S+)\s*(?:password|pass|pwd)\s*[:;=]\s*(\S+)",
    re.IGNORECASE
)
API_KEY_PATTERN = re.compile(
    r"(?:sk_live|sk_test|pk_live|pk_test)_[0-9a-zA-Z]{24,}|"
    r"AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|"
    r"xox[baprs]-[0-9a-zA-Z\-]{24,}|"
    r"AIza[0-9A-Za-z\-_]{35}|"
    r"-----BEGIN\s?(RSA\s)?PRIVATE KEY-----"
)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

LEAK_TYPES = {
    "credential": ["credential", "login", "password", "account", "hack", "breach"],
    "config": ["config", "configuration", "env", ".env", "settings", "database"],
    "financial": ["credit card", "cvv", "bank", "paypal", "stripe", "bitcoin"],
    "medical": ["medical", "health", "patient", "doctor", "prescription", "hipaa"],
    "personal": ["ssn", "social security", "address", "phone", "passport", "driver"],
    "source_code": ["source code", "repository", "github", "gitlab", "bitbucket"],
}

PASTE_SITES = [
    ("LeakIX", lambda t: f"https://leakix.net/search?scope=leak&q={t}", True),
    ("PSBDMP", lambda t: f"https://psbdmp.ws/api/search/{t}", False),
    ("SlickPaste", lambda t: f"https://slickpaste.com/search?q={t}", False),
    ("PasteCode", lambda t: f"https://pastecode.io/s/search?q={t}", False),
    ("ControlC", lambda t: f"https://controlc.com/search.php?q={t}", False),
    ("Codepad", lambda t: f"https://codepad.co/search?q={t}", False),
]

async def classify_leak(text: str) -> str:
    lower = text.lower()
    scores = defaultdict(int)
    for leak_type, keywords in LEAK_TYPES.items():
        for kw in keywords:
            if kw in lower:
                scores[leak_type] += 1
    if scores:
        return max(scores, key=scores.get)
    return "unknown"

async def extract_credentials(text: str):
    creds = []
    for match in CREDENTIAL_PATTERN.finditer(text):
        creds.append({
            "type": "email:password",
            "email": match.group("email"),
            "secret": match.group("password")
        })
    for match in USERNAME_PASS_PATTERN.finditer(text):
        creds.append({
            "type": "username:password",
            "email": match.group(1),
            "secret": match.group(2)
        })
    return creds

async def fetch_paste_content(client, url):
    try:
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return None

async def check_leakix(client, target):
    findings = []
    try:
        headers = {"Accept": "application/json"}
        resp = await client.get(
            f"https://leakix.net/search?scope=leak&q={target}",
            headers=headers, timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            leak_dates = []
            leak_sources = set()
            for leak in data:
                event = leak.get("event_source", "Unknown")
                leak_date = leak.get("time", "")
                summary = leak.get("summary", "")
                leak_sources.add(event)
                if leak_date:
                    leak_dates.append(leak_date)

                findings.append(IntelligenceFinding(
                    entity=target,
                    type="Data Breach / Leak",
                    source="LeakIX Forensics",
                    confidence="High",
                    color="red",
                    category="Leak / Breach Analysis",
                    threat_level="High Risk",
                    status="Breached",
                    raw_data=f"Date: {leak_date} | Source: {event} | Summary: {summary}",
                    tags=["breach", "leakix"]
                ))

                if summary:
                    classified = await classify_leak(summary)
                    if classified != "unknown":
                        findings.append(IntelligenceFinding(
                            entity=target,
                            type=f"Leak Classification: {classified.title()}",
                            source="LeakIX Forensics",
                            confidence="Medium",
                            color="orange",
                            category="Leak / Breach Analysis",
                            threat_level="Medium",
                            status="Classified",
                            tags=["classification", classified]
                        ))

            if leak_dates:
                try:
                    dates_parsed = []
                    for d in leak_dates:
                        try:
                            dates_parsed.append(datetime.fromisoformat(d.replace("Z", "")))
                        except:
                            pass
                    if dates_parsed:
                        earliest = min(dates_parsed).isoformat()[:10]
                        latest = max(dates_parsed).isoformat()[:10]
                        findings.append(IntelligenceFinding(
                            entity=target,
                            type="Leak Timeline",
                            source="LeakIX Forensics",
                            confidence="Medium",
                            color="slate",
                            category="Leak / Breach Analysis",
                            threat_level="Informational",
                            status="Timeline",
                            raw_data=f"First leak: {earliest}, Latest: {latest}",
                            tags=["timeline"]
                        ))
                except:
                    pass
    except:
        pass
    return findings

async def check_psbdmp(client, target):
    findings = []
    try:
        resp = await client.get(
            f"https://psbdmp.ws/api/search/{target}",
            timeout=12.0
        )
        if resp.status_code == 200:
            pastes = resp.json()
            if isinstance(pastes, list):
                all_text = ""
                for p in pastes[:10]:
                    paste_id = p.get("id", "?")
                    section = p.get("section", "")
                    tags = p.get("tags", [])
                    raw = p.get("raw", "")

                    findings.append(IntelligenceFinding(
                        entity=target,
                        type="Paste Mention",
                        source="PSBDMP.ws",
                        confidence="Medium",
                        color="orange",
                        category="Leak / Breach Analysis",
                        threat_level="Medium",
                        status="Exposed",
                        resolution=f"ID: {paste_id}",
                        raw_data=f"Paste: https://pastebin.com/{paste_id} | Section: {section} | Tags: {tags}",
                        tags=["paste", "psbdmp"]
                    ))

                    if raw:
                        all_text += raw + "\n"
                        creds = await extract_credentials(raw)
                        for cred in creds[:3]:
                            findings.append(IntelligenceFinding(
                                entity=cred["email"][:200],
                                type="Credential Exposure",
                                source="PSBDMP.ws",
                                confidence="High",
                                color="red",
                                category="Leak / Breach Analysis",
                                threat_level="Critical",
                                status="Credential Leaked",
                                resolution=cred["type"],
                                raw_data=f"Credential: {cred['email']}:{cred['secret']}",
                                tags=["credential", "exposed"]
                            ))

                if all_text:
                    api_keys = API_KEY_PATTERN.findall(all_text)
                    for ak in api_keys[:3]:
                        findings.append(IntelligenceFinding(
                            entity=f"API Key: {ak[:30]}...",
                            type="API Key Exposure",
                            source="PSBDMP.ws",
                            confidence="High",
                            color="red",
                            category="Leak / Breach Analysis",
                            threat_level="Critical",
                            status="Secret Leaked",
                            tags=["secret", "api-key"]
                        ))

                    emails = EMAIL_PATTERN.findall(all_text)
                    unique_emails = list(set(emails))
                    if unique_emails:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(unique_emails)} unique emails found in pastes",
                            type="Email Exposure Count",
                            source="PSBDMP.ws",
                            confidence="High",
                            color="orange",
                            category="Leak / Breach Analysis",
                            threat_level="Medium",
                            status="Exposed Emails",
                            tags=["email", "exposure"]
                        ))
    except:
        pass
    return findings

async def check_pastebinpro(client, target):
    findings = []
    for site_name, url_builder, is_json in [
        ("PastebinPro", lambda t: f"https://pastebin.com/search?q={t}", False),
        ("SlickPaste", lambda t: f"https://slickpaste.com/search?q={t}", False),
        ("ControlC", lambda t: f"https://controlc.com/search.php?q={t}", False),
    ]:
        try:
            url = url_builder(target)
            resp = await client.get(url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                text = resp.text.lower()
                if "found" in text or "result" in text or target.lower() in text:
                    findings.append(IntelligenceFinding(
                        entity=target,
                        type="Paste Site Mention",
                        source=site_name,
                        confidence="Low",
                        color="yellow",
                        category="Leak / Breach Analysis",
                        threat_level="Informational",
                        status="Possible Mention",
                        raw_data=f"Mention found on {site_name}",
                        tags=["paste", site_name.lower()]
                    ))
        except:
            pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    search_target = quote(target.strip().lower())

    leakix_results = await check_leakix(client, search_target)
    findings.extend(leakix_results)

    psbdmp_results = await check_psbdmp(client, search_target)
    findings.extend(psbdmp_results)

    paste_results = await check_pastebinpro(client, target.strip().lower())
    findings.extend(paste_results)

    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={target.strip().lower()}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "hibp-api-key": ""}
        )
        if resp.status_code == 200:
            breaches = resp.json()
            if isinstance(breaches, list):
                for br in breaches[:10]:
                    findings.append(IntelligenceFinding(
                        entity=br.get("Title", target),
                        type="Known Breach (HIBP)",
                        source="HaveIBeenPwned",
                        confidence="High",
                        color="red",
                        category="Leak / Breach Analysis",
                        threat_level="High Risk",
                        status="Breached",
                        resolution=br.get("Domain", ""),
                        raw_data=f"Date: {br.get('BreachDate')} | "
                                f"Records: {br.get('PwnCount', '?')} | "
                                f"Data: {', '.join(br.get('DataClasses', []))}",
                        tags=["hibp", "breach"]
                    ))
    except:
        pass

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No breaches/leaks found for {target}",
            type="Breach Check Complete",
            source="Breach Forensics",
            confidence="Low",
            color="emerald",
            category="Leak / Breach Analysis",
            threat_level="Informational",
            status="Clean",
            tags=["clean"]
        ))

    return findings
