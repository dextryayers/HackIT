import httpx
import asyncio
import re
import json
import hashlib
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
PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

DATA_CLASSIFICATION = {
    "credential": ["credential", "login", "password", "account", "hack", "breach"],
    "config": ["config", "configuration", "env", ".env", "settings", "database"],
    "financial": ["credit card", "cvv", "bank", "paypal", "stripe", "bitcoin"],
    "medical": ["medical", "health", "patient", "doctor", "prescription", "hipaa"],
    "personal": ["ssn", "social security", "address", "phone", "passport", "driver"],
    "source_code": ["source code", "repository", "github", "gitlab", "bitbucket"],
}

HASH_PATTERNS = {
    "MD5": re.compile(r"\b[a-f0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-f0-9]{40}\b"),
    "SHA256": re.compile(r"\b[a-f0-9]{64}\b"),
    "SHA512": re.compile(r"\b[a-f0-9]{128}\b"),
    "bcrypt": re.compile(r"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}"),
}

BREACH_SOURCES = [
    ("LeakIX", lambda t: f"https://leakix.net/search?scope=leak&q={t}", True),
    ("PSBDMP", lambda t: f"https://psbdmp.ws/api/search/{t}", False),
    ("SlickPaste", lambda t: f"https://slickpaste.com/search?q={t}", False),
    ("PasteCode", lambda t: f"https://pastecode.io/s/search?q={t}", False),
    ("ControlC", lambda t: f"https://controlc.com/search.php?q={t}", False),
    ("Codepad", lambda t: f"https://codepad.co/search?q={t}", False),
    ("HIBP", lambda t: f"https://haveibeenpwned.com/api/v3/breaches?domain={t}", True),
    ("DeHashed", lambda t: f"https://dehashed.com/api/v1/search?query={t}", False),
    ("ScatteredSecrets", lambda t: f"https://scatteredsecrets.com/api/search?q={t}", False),
    ("Snusbase", lambda t: f"https://snusbase.com/api/v1/search?term={t}", False),
    ("LeakCheck", lambda t: f"https://leakcheck.io/api/v2/check?query={t}", False),
    ("LeakPeak", lambda t: f"https://leakpeak.io/api/search?q={t}", False),
    ("BreachDirectory", lambda t: f"https://breachdirectory.org/api/v1/search?query={t}", False),
    ("IntelX", lambda t: f"https://intelx.io/api/v1/search?q={t}", False),
    ("Scylla", lambda t: f"https://scylla.so/search?q={t}", False),
    ("WeLeakInfo", lambda t: f"https://weleakinfo.com/api/v2/search?query={t}", False),
    ("LeakBase", lambda t: f"https://leakbase.io/api/search?q={t}", False),
    ("Ghostbin", lambda t: f"https://ghostbin.com/search?q={t}", False),
    ("Rentry", lambda t: f"https://rentry.org/search?q={t}", False),
]

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
    for leak_type, keywords in DATA_CLASSIFICATION.items():
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

async def identify_hash_type(hash_str: str) -> list:
    types = []
    for name, pattern in HASH_PATTERNS.items():
        if pattern.match(hash_str.strip()):
            types.append(name)
    return types

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

                    phones = PHONE_PATTERN.findall(all_text)
                    if phones:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(set(phones))} unique phone numbers found",
                            type="Phone Exposure",
                            source="PSBDMP.ws",
                            confidence="High",
                            color="red",
                            category="Leak / Breach Analysis",
                            threat_level="High Risk",
                            status="Exposed",
                            tags=["pii", "phone", "exposure"]
                        ))

                    ssns = SSN_PATTERN.findall(all_text)
                    if ssns:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(set(ssns))} SSNs found in pastes",
                            type="SSN Exposure",
                            source="PSBDMP.ws",
                            confidence="High",
                            color="red",
                            category="Leak / Breach Analysis",
                            threat_level="Critical",
                            status="Exposed",
                            tags=["pii", "ssn", "critical"]
                        ))

                    ccs = CC_PATTERN.findall(all_text)
                    if ccs:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(set(ccs))} credit card numbers found",
                            type="Financial Data Exposure",
                            source="PSBDMP.ws",
                            confidence="High",
                            color="red",
                            category="Leak / Breach Analysis",
                            threat_level="Critical",
                            status="Exposed",
                            tags=["financial", "credit-card", "critical"]
                        ))

                    ips = IP_PATTERN.findall(all_text)
                    if ips:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(set(ips))} IP addresses found in pastes",
                            type="IP Address Exposure",
                            source="PSBDMP.ws",
                            confidence="Medium",
                            color="orange",
                            category="Leak / Breach Analysis",
                            threat_level="Medium",
                            status="Exposed",
                            tags=["network", "ip", "exposure"]
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
        ("Ghostbin", lambda t: f"https://ghostbin.com/search?q={t}", False),
        ("Rentry", lambda t: f"https://rentry.org/search?q={t}", False),
        ("PasteCode", lambda t: f"https://pastecode.io/s/search?q={t}", False),
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

async def check_hibp_breaches(client, target):
    findings = []
    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={target}",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "hibp-api-key": ""}
        )
        if resp.status_code == 200:
            breaches = resp.json()
            if isinstance(breaches, list):
                total_records = 0
                for br in breaches[:15]:
                    pwn_count = br.get("PwnCount", 0) or 0
                    total_records += pwn_count
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
                                f"Records: {pwn_count} | "
                                f"Data: {', '.join(br.get('DataClasses', []))}",
                        tags=["hibp", "breach"]
                    ))
                if total_records:
                    findings.append(IntelligenceFinding(
                        entity=f"{total_records:,} total records exposed across {len(breaches)} breaches",
                        type="Total Exposure Volume",
                        source="HaveIBeenPwned",
                        confidence="High",
                        color="red",
                        category="Leak / Breach Analysis",
                        threat_level="High Risk",
                        status="Aggregated",
                        tags=["hibp", "volume", "aggregate"]
                    ))
    except:
        pass
    return findings

async def check_breach_directory(client, target):
    findings = []
    try:
        resp = await client.post(
            "https://breachdirectory.org/api/v1/search",
            json={"query": target},
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            breaches = data.get("breaches", data.get("results", []))
            for breach in breaches[:10]:
                if isinstance(breach, dict):
                    findings.append(IntelligenceFinding(
                        entity=breach.get("name", breach.get("title", target)),
                        type="Breach Directory Entry",
                        source="BreachDirectory",
                        confidence="Medium",
                        color="red",
                        category="Leak / Breach Analysis",
                        threat_level="High Risk",
                        status="Exposed",
                        raw_data=json.dumps(breach),
                        tags=["breach-directory", "breach"]
                    ))
    except:
        pass
    return findings

async def analyze_credential_hashes(text: str) -> list:
    findings = []
    for name, pattern in HASH_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings.append(IntelligenceFinding(
                entity=f"{len(set(matches))} potential {name} hashes found",
                type=f"Hash Identification: {name}",
                source="Breach Forensics",
                confidence="Medium",
                color="orange",
                category="Leak / Breach Analysis",
                threat_level="Medium",
                status="Detected",
                tags=["hash", name.lower(), "crypto"]
            ))
    return findings

async def check_clear_web_breach_sources(client, target):
    findings = []
    sources = [
        ("DeHashed", f"https://dehashed.com/search?q={target}"),
        ("LeakCheck", f"https://leakcheck.io/search?q={target}"),
        ("IntelX", f"https://intelx.io/?s={target}"),
    ]
    for name, url in sources:
        try:
            resp = await client.get(url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and len(resp.text) > 500:
                findings.append(IntelligenceFinding(
                    entity=f"Source: {name} returned results",
                    type="Breach Source Accessible",
                    source=name,
                    confidence="Low",
                    color="yellow",
                    category="Leak / Breach Analysis",
                    threat_level="Informational",
                    status="Accessible",
                    tags=["breach-source", name.lower()]
                ))
        except:
            pass
    return findings

async def analyze_data_impact_level(text: str) -> list:
    findings = []
    data_types_found = set()
    if EMAIL_PATTERN.search(text):
        data_types_found.add("email")
    if PHONE_PATTERN.search(text):
        data_types_found.add("phone")
    if SSN_PATTERN.search(text):
        data_types_found.add("ssn")
    if CC_PATTERN.search(text):
        data_types_found.add("credit_card")
    if IP_PATTERN.search(text):
        data_types_found.add("ip")
    if re.search(r"\bpassword\b", text, re.IGNORECASE):
        data_types_found.add("password")
    if re.search(r"\b(?:address|street|city|zip|postal)\b", text, re.IGNORECASE):
        data_types_found.add("address")

    if data_types_found:
        impact_score = len(data_types_found)
        impact = "Critical" if impact_score >= 4 else ("High Risk" if impact_score >= 3 else "Medium")
        findings.append(IntelligenceFinding(
            entity=f"Data types exposed: {', '.join(sorted(data_types_found))}",
            type="Data Impact Assessment",
            source="Breach Forensics",
            confidence="High",
            color="red" if impact_score >= 3 else "orange",
            category="Leak / Breach Analysis",
            threat_level=impact,
            status=f"Impact Level: {impact}",
            tags=["impact", "data-classification"] + list(data_types_found)
        ))
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

    hibp_results = await check_hibp_breaches(client, target.strip().lower())
    findings.extend(hibp_results)

    breach_dir_results = await check_breach_directory(client, target.strip().lower())
    findings.extend(breach_dir_results)

    clear_web_results = await check_clear_web_breach_sources(client, target.strip().lower())
    findings.extend(clear_web_results)

    all_text = ""
    for f in findings:
        if f.raw_data:
            all_text += str(f.raw_data) + "\n"

    hash_results = await analyze_credential_hashes(all_text)
    findings.extend(hash_results)

    impact_results = await analyze_data_impact_level(all_text)
    findings.extend(impact_results)

    breach_count = len([f for f in findings if "breach" in f.type.lower() or "credential" in f.type.lower() or "exposure" in f.type.lower()])
    if breach_count:
        risk = "Critical" if breach_count >= 10 else ("High Risk" if breach_count >= 5 else "Elevated Risk")
        findings.append(IntelligenceFinding(
            entity=target,
            type="Breach Risk Summary",
            source="Breach Forensics",
            confidence="High",
            color="red" if breach_count >= 5 else "orange",
            category="Leak / Breach Analysis",
            threat_level=risk,
            status="Analyzed",
            raw_data=f"Total breach indicators: {breach_count}",
            tags=["summary", "risk", risk.lower().replace(" ", "-")]
        ))

    source_dist = defaultdict(int)
    for f in findings:
        source_dist[f.source] += 1
    if source_dist:
        source_summary = ", ".join(f"{k}: {v}" for k, v in sorted(source_dist.items(), key=lambda x: -x[1]))
        findings.append(IntelligenceFinding(
            entity=source_summary,
            type="Breach Source Distribution",
            source="Breach Forensics",
            confidence="Medium",
            color="slate",
            category="Leak / Breach Analysis",
            threat_level="Informational",
            status="Analyzed",
            tags=["source-distribution", "summary"]
        ))

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
