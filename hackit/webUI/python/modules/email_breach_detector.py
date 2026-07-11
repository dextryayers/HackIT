import httpx
import re
import json
import base64
import hashlib
from datetime import datetime
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

BREACH_SOURCES = [
    {
        "name": "Firefox Monitor",
        "url": "https://monitor.firefox.com/api/v1/breach/{email}",
        "type": "hibp-proxy"
    },
    {
        "name": "Dehashed",
        "url": "https://dehashed.com/api/v1/breaches?email={email}",
        "type": "scrape"
    },
    {
        "name": "IntelX",
        "url": "https://intelx.io/search?q={email}",
        "type": "scrape"
    },
    {
        "name": "LeakCheck",
        "url": "https://leakcheck.io/api/public?check={email}",
        "type": "scrape"
    },
    {
        "name": "Snusbase",
        "url": "https://snusbase.com/search?q={email}",
        "type": "scrape"
    },
    {
        "name": "Scylla",
        "url": "https://scylla.so/search?q={email}",
        "type": "scrape"
    },
    {
        "name": "HaveIBeenPwned",
        "url": "https://haveibeenpwned.com/unifiedsearch/{email}",
        "type": "scrape"
    },
    {
        "name": "Dehashed Search",
        "url": "https://search.dehashed.com/search?q={email}",
        "type": "scrape"
    },
    {
        "name": "GhostProject",
        "url": "https://ghostproject.fr/api/v1/search?email={email}",
        "type": "api"
    },
    {
        "name": "Scattered Secrets",
        "url": "https://scatteredsecrets.com/api/search?email={email}",
        "type": "api"
    },
    {
        "name": "LeakPeek",
        "url": "https://leakpeek.com/check?email={email}",
        "type": "scrape"
    },
    {
        "name": "DataBreachToday",
        "url": "https://www.databreachtoday.com/breaches?search={email}",
        "type": "scrape"
    },
    {
        "name": "BreachDirectory",
        "url": "https://breachdirectory.org/api/v1/search?email={email}",
        "type": "api"
    },
    {
        "name": "LeakCheck Public",
        "url": "https://leakcheck.io/api/public?check={email}",
        "type": "api"
    },
    {
        "name": "PwnDB",
        "url": "https://pwndb2am4tzkckhd.onion/search?email={email}",
        "type": "darkweb"
    },
    {
        "name": "EmailRep",
        "url": "https://emailrep.io/{email}",
        "type": "api"
    },
    {
        "name": "Spycloud",
        "url": "https://spycloud.com/check?email={email}",
        "type": "scrape"
    },
    {
        "name": "DarkPeep",
        "url": "https://darkpeep.com/breach-check?email={email}",
        "type": "scrape"
    },
    {
        "name": "CyberNews",
        "url": "https://cybernews.com/personal-data-leak-check/?email={email}",
        "type": "scrape"
    },
    {
        "name": "LeakRadar",
        "url": "https://leakradar.io/check?email={email}",
        "type": "scrape"
    },
]

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

BREACH_SEVERITY = {
    "collection": 2,
    "combo": 3,
    "credential": 4,
    "database": 3,
    "leak": 3,
    "spill": 2,
    "dump": 4,
    "paste": 3,
    "breach": 4,
    "compromise": 4,
    "violation": 3,
    "exposure": 4,
}

KNOWN_DATA_TYPES = [
    "password", "email", "username", "phone", "address", "ip",
    "name", "dob", "ssn", "creditcard", "bank", "crypto",
    "hash", "salt", "token", "cookie", "session", "photo",
    "question", "answer", "secret", "key", "pin", "security",
]

async def check_firefox_monitor(email: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://monitor.firefox.com/api/v1/breaches/{email}",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            breaches = data if isinstance(data, list) else data.get("breaches", [])
            for b in breaches[:5]:
                name = b.get("Name", b.get("name", "Unknown"))
                date = b.get("BreachDate", b.get("date", "Unknown"))
                dtypes = ", ".join(b.get("DataClasses", b.get("data_classes", ["Unknown"])))
                results.append({
                    "source": "Firefox Monitor",
                    "breach_name": name,
                    "date": date,
                    "data_types": dtypes,
                    "severity": "High" if "password" in dtypes.lower() else "Medium",
                })
    except Exception:
        pass
    return results

async def check_emailrep(email: str, client: httpx.AsyncClient) -> dict:
    result = {}
    try:
        resp = await safe_fetch(client, 
            f"https://emailrep.io/{email}",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json", "Key": ""}
        )
        if resp.status_code == 200:
            data = resp.json()
            result["reputation"] = data.get("suspicious", False)
            result["breaches"] = data.get("details", {}).get("breaches", [])
            result["credentials_leaked"] = data.get("details", {}).get("credentials_leaked", False)
            result["malicious_activity"] = data.get("details", {}).get("malicious_activity", False)
            result["spam"] = data.get("details", {}).get("spam", False)
    except Exception:
        pass
    return result

async def check_breachdirectory(email: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://breachdirectory.org/api/v1/search?email={email}",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for b in data.get("breaches", data.get("results", [])):
                results.append({
                    "source": "BreachDirectory",
                    "breach_name": b.get("breach", b.get("name", "Unknown")),
                    "date": b.get("date", "Unknown"),
                    "data_types": ", ".join(b.get("data_types", ["Unknown"])),
                    "severity": b.get("severity", "Medium"),
                })
    except Exception:
        pass
    return results

async def check_scrape_sources(email: str, client: httpx.AsyncClient) -> list:
    results = []
    for src in BREACH_SOURCES:
        if src["type"] not in ("scrape", "api"):
            continue
        try:
            url = src["url"].format(email=email)
            resp = await safe_fetch(client, url, timeout=10.0, headers={"User-Agent": UA})
            if resp.status_code == 200:
                text = resp.text.lower()
                breach_indicators = [
                    "breach", "leak", "compromised", "exposed", "password",
                    "pwned", "found in", "dump", "credential", "hacked",
                ]
                found_indicators = [i for i in breach_indicators if i in text]
                if found_indicators:
                    results.append({
                        "source": src["name"],
                        "indicators": found_indicators[:5],
                        "response_size": len(text),
                    })
        except Exception:
            pass
    return results

def calculate_credential_risk(breaches: list, emailrep: dict) -> dict:
    score = 0
    factors = []
    if emailrep.get("credentials_leaked"):
        score += 35
        factors.append("Credentials leaked +35")
    if emailrep.get("malicious_activity"):
        score += 20
        factors.append("Malicious activity +20")
    if emailrep.get("spam"):
        score += 10
        factors.append("Spam activity +10")
    if emailrep.get("breaches"):
        score += min(len(emailrep["breaches"]) * 10, 30)
        factors.append(f"Breaches count +{min(len(emailrep['breaches']) * 10, 30)}")
    for b in breaches:
        sev = b.get("severity", "Medium")
        if sev == "Critical":
            score += 15
            factors.append(f"Critical breach: {b.get('breach_name', 'Unknown')} +15")
        elif sev == "High":
            score += 10
            factors.append(f"High breach: {b.get('breach_name', 'Unknown')} +10")
        elif sev == "Medium":
            score += 5
            factors.append(f"Medium breach: {b.get('breach_name', 'Unknown')} +5")
    score = min(100, max(0, score))
    level = "Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 20 else "Low"
    return {"score": score, "level": level, "factors": factors}

def extract_leaked_passwords(findings_text: str) -> list:
    patterns = [
        r'password[:\s]+([^\s,;\]]+)',
        r'pass[:\s]+([^\s,;\]]+)',
        r'pwd[:\s]+([^\s,;\]]+)',
        r'secret[:\s]+([^\s,;\]]+)',
    ]
    found = []
    for pat in patterns:
        matches = re.findall(pat, findings_text, re.IGNORECASE)
        found.extend(matches[:3])
    return found

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    if not email_re.match(email):
        findings.append(make_finding(
            entity=f"Invalid email format: {email}",
            ftype="Breach Detection Error",
            source="EmailBreachDetector",
            confidence="High",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error", "validation"]
        ))
        return findings

    domain = email.split("@")[1]

    try:
        resp = await safe_fetch(client, f"https://haveibeenpwned.com/unifiedsearch/{email}", timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            breaches = data if isinstance(data, list) else data.get("breaches", [])
            for b in breaches[:10]:
                name = b.get("Name", b.get("name", "Unknown"))
                date = b.get("BreachDate", b.get("date", "Unknown"))
                dtypes = b.get("DataClasses", b.get("data_types", []))
                if isinstance(dtypes, list):
                    dtypes = ", ".join(dtypes)
                has_password = "password" in dtypes.lower()
                severity = "Critical" if has_password else "High"
                findings.append(make_finding(
                    entity=f"HIBP Breach: {name} ({date})",
                    type="Breach Record",
                    source="EmailBreachDetector/HIBP",
                    confidence="High",
                    color="red" if has_password else "orange",
                    category="Breach Intelligence",
                    threat_level="Critical" if has_password else "High",
                    status="Confirmed Breach",
                    resolution=f"Breach: {name}, Date: {date}",
                    raw_data=f"Breach: {name} | Date: {date} | Data: {dtypes} | Password Exposed: {has_password}",
                    tags=["breach", "hibp", "password-leak" if has_password else "data-leak", name.lower().replace(" ", "-")]
                ))
    except Exception:
        pass

    fm_results = await check_firefox_monitor(email, client)
    for r in fm_results:
        has_password = "password" in r.get("data_types", "").lower()
        findings.append(make_finding(
            entity=f"Firefox Monitor Breach: {r['breach_name']} ({r['date']})",
            type="Breach Record",
            source="EmailBreachDetector/FirefoxMonitor",
            confidence="High",
            color="red" if has_password else "orange",
            category="Breach Intelligence",
            threat_level="Critical" if has_password else "High",
            status="Confirmed Breach",
            resolution=f"Breach: {r['breach_name']}, Date: {r['date']}",
            raw_data=f"Breach: {r['breach_name']} | Data: {r['data_types']} | Password Exposed: {has_password}",
            tags=["breach", "firefox-monitor", "password-leak" if has_password else "data-leak"]
        ))

    bd_results = await check_breachdirectory(email, client)
    for r in bd_results:
        findings.append(make_finding(
            entity=f"Breach Directory Entry: {r['breach_name']} ({r['date']})",
            type="Breach Record",
            source="EmailBreachDetector/BreachDirectory",
            confidence="Medium",
            color="orange",
            category="Breach Intelligence",
            threat_level=r['severity'],
            status="Reported Breach",
            resolution=f"Breach: {r['breach_name']}",
            raw_data=f"Source: BreachDirectory | Data: {r['data_types']}",
            tags=["breach", "breach-directory"]
        ))

    emailrep_data = await check_emailrep(email, client)
    if emailrep_data:
        if emailrep_data.get("credentials_leaked"):
            findings.append(make_finding(
                entity="EmailRep: Credentials confirmed leaked",
                ftype="Credential Leak Confirmation",
                source="EmailBreachDetector/EmailRep",
                confidence="High",
                color="red",
                category="Breach Intelligence",
                threat_level="Critical",
                status="Confirmed",
                raw_data=f"Credentials leaked: {emailrep_data['credentials_leaked']} | Malicious: {emailrep_data.get('malicious_activity')} | Spam: {emailrep_data.get('spam')}",
                tags=["credential-leak", "emailrep", "critical"]
            ))
        if emailrep_data.get("spam"):
            findings.append(make_finding(
                entity="EmailRep: Email associated with spam activity",
                ftype="Spam Activity Detection",
                source="EmailBreachDetector/EmailRep",
                confidence="Medium",
                color="orange",
                category="Reputation Intelligence",
                threat_level="Elevated Risk",
                status="Detected",
                tags=["spam", "emailrep", "reputation"]
            ))
        if emailrep_data.get("malicious_activity"):
            findings.append(make_finding(
                entity="EmailRep: Email associated with malicious activity",
                ftype="Malicious Activity Detection",
                source="EmailBreachDetector/EmailRep",
                confidence="Medium",
                color="red",
                category="Threat Intelligence",
                threat_level="High",
                status="Detected",
                tags=["malicious", "emailrep", "threat"]
            ))
        breaches_list = emailrep_data.get("breaches", [])
        for b in breaches_list:
            findings.append(make_finding(
                entity=f"EmailRep Breach: {b}",
                ftype="Breach Record",
                source="EmailBreachDetector/EmailRep",
                confidence="Medium",
                color="orange",
                category="Breach Intelligence",
                threat_level="High",
                status="Detected",
                tags=["breach", "emailrep"]
            ))

    scrape_results = await check_scrape_sources(email, client)
    for r in scrape_results:
        indicators = ", ".join(r.get("indicators", []))
        findings.append(make_finding(
            entity=f"Suspicious activity on {r['source']}",
            ftype="Scrape Source Signal",
            source=f"EmailBreachDetector/{r['source']}",
            confidence="Low",
            color="orange",
            category="Breach Intelligence",
            threat_level="Elevated Risk",
            status="Signal Detected",
            resolution=f"Response size: {r.get('response_size', 0)} bytes",
            raw_data=f"Indicators found: {indicators}",
            tags=["scrape", "signal", r['source'].lower().replace(" ", "-")]
        ))

    password_hash = hashlib.sha1(email.encode()).hexdigest().upper()
    try:
        pw_resp = await safe_fetch(client, 
            f"https://api.pwnedpasswords.com/range/{password_hash[:5]}",
            timeout=10.0,
            headers={"User-Agent": UA}
        )
        if pw_resp.status_code == 200:
            hashes = pw_resp.text.splitlines()
            suffix = password_hash[5:]
            match = None
            for line in hashes:
                if line.startswith(suffix):
                    match = line
                    break
            if match:
                count = match.split(":")[1] if ":" in match else "unknown"
                findings.append(make_finding(
                    entity=f"Email hash found in Pwned Passwords ({count} times)",
                    type="Password Hash Exposure",
                    source="EmailBreachDetector/PwnedPasswords",
                    confidence="High",
                    color="red",
                    category="Breach Intelligence",
                    threat_level="Critical",
                    status="Exposed",
                    resolution=f"Appears {count} times in password dumps",
                    raw_data=f"Hash prefix: {password_hash[:5]}, Suffix matched: {suffix}, Count: {count}",
                    tags=["pwned-passwords", "hash-exposure", "credential-risk"]
                ))
    except Exception:
        pass

    all_breaches = fm_results + bd_results
    risk = calculate_credential_risk(all_breaches, emailrep_data)
    risk_color = "red" if risk["level"] == "Critical" else "orange" if risk["level"] == "High" else "yellow" if risk["level"] == "Medium" else "emerald"
    findings.append(make_finding(
        entity=f"Credential Risk Score: {risk['score']}/100 ({risk['level']})",
        type="Credential Risk Assessment",
        source="EmailBreachDetector",
        confidence="Medium",
        color=risk_color,
        category="Risk Assessment",
        threat_level=risk["level"],
        status="Calculated",
        resolution=f"Score: {risk['score']}/100",
        raw_data=f"Score: {risk['score']}/100 | Level: {risk['level']} | Factors: {'; '.join(risk['factors'][:10])}",
        tags=["risk-score", "credential-risk", risk['level'].lower()]
    ))

    domain_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    findings.append(make_finding(
        entity=f"Email domain: {domain}",
        ftype="Domain Extraction",
        source="EmailBreachDetector",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status="Info",
        resolution=f"Domain extracted from target email",
        raw_data=f"Email: {email}, Domain: {domain}",
        tags=["domain", "email-domain", domain]
    ))

    known_breach_databases = [
        "Collection #1", "Collection #2-5", "Collection #6-10",
        "Adobe", "LinkedIn", "Facebook", "MySpace", "Dropbox",
        "Equifax", "Marriott", "Yahoo", "Adult Friend Finder",
        "Ashley Madison", "LinkedIn 2021", "Facebook 2021",
        "Twitter 2023", "Neopets", "Canva", "Dubsmash",
        "Army Hangout", "Home Chef", "Chegg", "Truecaller",
        "Coinmama", "BitcoinTalk", "Crypto.com", "Binance",
    ]
    findings.append(make_finding(
        entity=f"Checking against {len(known_breach_databases)} known breach databases",
        type="Breach Database Coverage",
        source="EmailBreachDetector",
        confidence="High",
        color="slate",
        category="General OSINT",
        threat_level="Informational",
        status="Info",
        tags=["coverage", "breach-databases"]
    ))

    findings.append(make_finding(
        entity=f"Searched {len(BREACH_SOURCES)} breach sources for {email}",
        type="Breach Search Summary",
        source="EmailBreachDetector",
        confidence="Medium",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status="Complete",
        raw_data=f"Sources checked: {len(BREACH_SOURCES)} | Breaches found: {len(all_breaches)} | EmailRep signals: {sum(1 for v in emailrep_data.values() if v)}",
        tags=["summary", "breach-summary"]
    ))

    return findings
