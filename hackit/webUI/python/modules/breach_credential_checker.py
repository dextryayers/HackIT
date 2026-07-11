import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

BREACH_SOURCES = [
    ("HaveIBeenPwned", "https://haveibeenpwned.com/api/v3/breachedaccount/{}"),
    ("Firefox Monitor", "https://monitor.firefox.com/breaches"),
    ("DeHashed", "https://dehashed.com/search?query={}"),
    ("LeakCheck", "https://leakcheck.io/api/public?check={}"),
    ("Snusbase", "https://snusbase.com/search?q={}"),
    ("LeakBase", "https://leakbase.io/search?q={}"),
    ("Scylla.so", "https://scylla.so/search?q={}"),
    ("IntelX", "https://intelx.io/search?q={}"),
    ("ScatteredSecrets", "https://scatteredsecrets.com/search?q={}"),
    ("WeLeakInfo", "https://weleakinfo.com/search?q={}"),
    ("LeakSource", "https://leaksource.info/search?q={}"),
    ("BreachDirectory", "https://breachdirectory.org/search?q={}"),
    ("BreachCheck", "https://breachcheck.com/search?q={}"),
    ("DataBreachToday", "https://databreachtoday.com/search?q={}"),
    ("BreachAware", "https://breachaware.com/search?q={}"),
    ("PrivacyWatch", "https://privacywatch.com/search?q={}"),
    ("CyberNews", "https://cybernews.com/search/?q={}"),
    ("TroyHunt", "https://www.troyhunt.com/search?q={}"),
    ("GHDB", "https://exploit-db.com/search?q={}"),
    ("PwnDB", "https://pwndb2am4tzkvold.onion/search?q={}"),
    ("LeakedDB", "https://leakedsource.ru/search?q={}"),
    ("COMB", "https://combolist.org/search?q={}"),
    ("AntiPublic", "https://antipublic.com/search?q={}"),
    ("Collection1", "https://collection1.com/search?q={}"),
    ("ExploitIN", "https://exploit.in/search?q={}"),
    ("Cracked", "https://cracked.to/search?q={}"),
    ("Nulled", "https://nulled.to/search?q={}"),
    ("BreachForums", "https://breachforums.is/search?q={}"),
    ("RaidForums", "https://raidforums.com/search?q={}"),
    ("XSS", "https://xss.is/search?q={}"),
]

BREACH_DATABASES = [
    "Collection #1", "Collection #2-5", "Collection 2024",
    "COMB (Combination of Many Breaches)", "AntiPublic",
    "LinkedIn 2021", "Facebook 2021", "Facebook 2019",
    "Adobe 2013", "Dropbox 2016", "MySpace 2016",
    "Tumblr 2013", "Twitter 2022", "Neopets 2016",
    "Clubhouse 2021", "Gravatar 2020", "Truecaller 2024",
    "AT&T 2024", "Ticketmaster 2024", "Santander 2024",
    "Medibank 2022", "Optus 2022", "Marriott 2018",
    "Equifax 2017", "Yahoo 2014", "Yahoo 2013",
    "AdultFriendFinder 2016", "AshleyMadison 2015",
    "LinkedIn 2012", "Canva 2019", "Evite 2019",
    "ArmorGames 2019", "Houzz 2019", "ShareThis 2018",
    "Dubsmash 2018", "MyHeritage 2018", "Quora 2018",
    "Google+ 2018", "UnderArmour 2018", "Panera 2018",
    "SberBank 2024", "Wildberries 2024", "Telegram 2024",
]

PASSWORD_STRONG_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>/?]).{12,}$')
PASSWORD_MEDIUM_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$')
NUMBERS_ONLY_PATTERN = re.compile(r'^\d+$')
ALPHA_ONLY_PATTERN = re.compile(r'^[A-Za-z]+$')
COMMON_PASSWORDS = {"123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123", "password1", "123123", "admin", "letmein", "welcome", "monkey", "dragon", "master", "login", "princess", "football", "shadow", "sunshine"}

async def check_hibp(target: str, client: httpx.AsyncClient) -> list:
    results = []
    data = await safe_fetch_json(client,
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}",
        headers={"hibp-api-key": ""})
    if data:
        for breach in data:
            results.append({
                "source": "HaveIBeenPwned",
                "name": breach.get("Name", ""),
                "domain": breach.get("Domain", ""),
                "date": breach.get("BreachDate", ""),
                "data_classes": breach.get("DataClasses", []),
                "description": breach.get("Description", "")[:200],
            })
    return results

async def check_dehashed(target: str, client: httpx.AsyncClient) -> list:
    results = []
    resp = await safe_fetch(client,
        f"https://dehashed.com/search?query={quote(target)}")
    if resp and resp.status_code == 200:
        text = resp.text
        result_count = len(re.findall(r'class=["\']result["\']', text))
        if result_count > 0:
            results.append({"source": "DeHashed", "count": result_count})
    return results

async def check_leakcheck(target: str, client: httpx.AsyncClient) -> list:
    results = []
    data = await safe_fetch_json(client,
        f"https://leakcheck.io/api/public?check={quote(target)}")
    if data and data.get("success"):
        results.append({
            "source": "LeakCheck",
            "found": data.get("found", False),
            "count": data.get("count", 0),
        })
    return results

async def classify_password_strength(password: str) -> str:
    if not password or len(password) < 4:
        return "Very Weak"
    if password in COMMON_PASSWORDS:
        return "Very Weak (Common)"
    if NUMBERS_ONLY_PATTERN.match(password):
        return "Weak"
    if ALPHA_ONLY_PATTERN.match(password):
        return "Weak"
    if PASSWORD_STRONG_PATTERN.match(password):
        return "Strong"
    if PASSWORD_MEDIUM_PATTERN.match(password):
        return "Medium"
    if len(password) >= 8:
        return "Medium"
    return "Weak"

CRED_PAIR_PATTERN = re.compile(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(\S+)')
HASH_PATTERN = re.compile(r'\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b')

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    hibp_results = await check_hibp(t, client)
    for breach in hibp_results:
        data_classes = ", ".join(breach.get("data_classes", []))
        findings.append(make_finding(
            entity=f"Breach: {breach['name']} ({breach['domain']}) - {breach['date']}",
            ftype="Breach: Known Breach",
            source="BreachCredChecker",
            confidence="Very High",
            color="red",
            category="Breach Intelligence",
            threat_level="Critical",
            status="Compromised",
            resolution=t,
            raw_data=f"Data exposed: {data_classes}",
            tags=["breach", "hibp", breach['name'].lower().replace(" ", "-")],
        ))
        findings.append(make_finding(
            entity=f"Data types exposed in {breach['name']}: {data_classes}",
            ftype="Breach: Exposed Data Types",
            source="BreachCredChecker",
            confidence="High",
            color="orange",
            category="Breach Intelligence",
            threat_level="High Risk",
            status="Data Identified",
            resolution=t,
            tags=["breach", "data-types", breach['name'].lower().replace(" ", "-")],
        ))

    dehashed_results = await check_dehashed(t, client)
    for result in dehashed_results:
        findings.append(make_finding(
            entity=f"DeHashed: {result['count']} results for {t}",
            ftype="Breach: DeHashed Results",
            source="BreachCredChecker",
            confidence="Medium",
            color="red",
            category="Breach Intelligence",
            threat_level="Critical",
            status="Found",
            resolution=t,
            tags=["breach", "dehashed"],
        ))

    leakcheck_results = await check_leakcheck(t, client)
    for result in leakcheck_results:
        if result.get("found"):
            findings.append(make_finding(
                entity=f"LeakCheck: {result['count']} entries found for {t}",
                ftype="Breach: LeakCheck Results",
                source="BreachCredChecker",
                confidence="High",
                color="red",
                category="Breach Intelligence",
                threat_level="Critical",
                status="Compromised",
                resolution=t,
                tags=["breach", "leakcheck"],
            ))

    public_breaches_containing = [b for b in BREACH_DATABASES if any(term in b.lower() for term in t.split(".") if len(term) > 3)]
    if public_breaches_containing:
        findings.append(make_finding(
            entity=f"Target may be in {len(public_breaches_containing)} public breach databases",
            ftype="Breach: Database Match Estimate",
            source="BreachCredChecker",
            confidence="Low",
            color="yellow",
            category="Breach Intelligence",
            threat_level="Medium Risk",
            status="Potential",
            resolution=t,
            tags=["breach", "database", "estimate"],
        ))

    findings.append(make_finding(
        entity=f"Credential risk assessment for {t}",
        ftype="Breach: Credential Risk",
        source="BreachCredChecker",
        confidence="Medium",
        color="orange" if hibp_results else "emerald",
        category="Breach Intelligence",
        threat_level="High Risk" if hibp_results else "Informational",
        status="Breached" if hibp_results else "Clean",
        resolution=t,
        tags=["breach", "credential", "risk"],
    ))

    total_breaches = len(hibp_results) + len(dehashed_results) + len(leakcheck_results)
    data_types_seen = set()
    for b in hibp_results:
        for dt in b.get("data_classes", []):
            data_types_seen.add(dt)

    if data_types_seen:
        findings.append(make_finding(
            entity=f"Exposed data types: {', '.join(sorted(data_types_seen))}",
            ftype="Breach: Data Type Inventory",
            source="BreachCredChecker",
            confidence="High",
            color="orange",
            category="Breach Intelligence",
            threat_level="High Risk",
            status="Exposed",
            resolution=t,
            tags=["breach", "data-type-inventory"],
        ))

    breach_timeline = sorted([b["date"] for b in hibp_results if b.get("date")])
    if breach_timeline:
        findings.append(make_finding(
            entity=f"Breach timeline: {breach_timeline[0]} to {breach_timeline[-1]} ({len(breach_timeline)} breaches)",
            ftype="Breach: Timeline Analysis",
            source="BreachCredChecker",
            confidence="High",
            color="orange",
            category="Breach Intelligence",
            threat_level="High Risk",
            status="Timeline Built",
            resolution=t,
            tags=["breach", "timeline", "analysis"],
        ))

    if not hibp_results and not dehashed_results and not leakcheck_results:
        findings.append(make_finding(
            entity="No breaches found for target in checked databases",
            ftype="Breach: Scan Complete",
            source="BreachCredChecker",
            confidence="Low",
            color="emerald",
            category="Breach Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["breach", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Breach scan complete: {total_breaches} breach records found",
        ftype="Breach: Scan Summary",
        source="BreachCredChecker",
        confidence="High",
        color="slate",
        category="Breach Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["breach", "summary"],
    ))

    return findings
