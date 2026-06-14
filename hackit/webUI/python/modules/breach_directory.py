import httpx
import asyncio
import json
import re
from datetime import datetime
from collections import defaultdict
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

DATA_CLASSES = {
    "email": "Email Address",
    "password": "Password",
    "username": "Username",
    "name": "Full Name",
    "phone": "Phone Number",
    "address": "Physical Address",
    "ip": "IP Address",
    "dob": "Date of Birth",
    "ssn": "Social Security Number",
    "credit": "Credit Card",
    "cvv": "CVV",
    "bank": "Bank Account",
    "crypto": "Cryptocurrency",
    "passport": "Passport Number",
    "license": "Driver License",
    "security_question": "Security Question",
    "cookie": "Session Cookie",
}

BREACH_SEVERITY = {
    "haveibeenpwned": "High",
    "dehashed": "High",
    "firefox_monitor": "High",
    "leakcheck": "High",
    "scylla": "Critical",
    "collection1": "High",
    "antipublic": "Critical",
    "exploitin": "High",
    "verification": "Medium",
    "unknown": "Medium",
}

DEHASHED_API = "https://dehashed.com/api/v1"

BREACH_DATABASES = [
    ("Collection #1", "collection1"),
    ("Antipublic", "antipublic"),
    ("Exploit.in", "exploit.in"),
    ("Verification", "verification"),
    ("Scylla", "scylla"),
]

async def query_dehashed(query: str, client: httpx.AsyncClient, page: int = 1) -> dict:
    try:
        resp = await client.get(
            f"{DEHASHED_API}/search",
            params={"query": query, "size": 30, "page": page},
            headers={"User-Agent": UA, "Accept": "application/json", "Authorization": ""},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def query_haveibeenpwned(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            headers={"User-Agent": UA, "hibp-api-key": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return []

async def query_firefox_monitor(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://monitor.firefox.com/api/v1/breaches",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            relevant = []
            for br in breaches:
                domains = br.get("Domains", [])
                if domain.lower() in [d.lower() for d in domains]:
                    relevant.append(br)
            return relevant
    except:
        pass
    return []

async def query_leakcheck(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://leakcheck.io/api/v2/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

PASSWORD_WEAK_RE = re.compile(r'^(123\d*|password|qwerty|letmein|admin|welcome|monkey|dragon|master|login|abc123|passw0rd|iloveyou|sunshine|princess|football)$', re.IGNORECASE)

def analyze_password(password: str) -> tuple:
    if not password:
        return None, None
    pw = str(password)
    if PASSWORD_WEAK_RE.match(pw):
        return "Weak", "Common/Top 100 password"
    if len(pw) < 8:
        return "Weak", "Too short (< 8 chars)"
    has_upper = bool(re.search(r'[A-Z]', pw))
    has_lower = bool(re.search(r'[a-z]', pw))
    has_digit = bool(re.search(r'\d', pw))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', pw))
    strength = sum([has_upper, has_lower, has_digit, has_special])
    if strength >= 4:
        return "Strong", "Complex (upper+lower+digit+special)"
    if strength >= 3:
        return "Medium", "Moderate complexity"
    return "Weak", f"Low complexity ({strength}/4 checks)"

def severity_for_breach(breach_name: str) -> str:
    for key, sev in BREACH_SEVERITY.items():
        if key.lower() in breach_name.lower():
            return sev
    return "Medium"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    seen_emails = set()
    password_hashes = []
    breach_timeline = []

    dehashed_data = await query_dehashed(f"domain:{t}", client)
    if dehashed_data:
        entries = dehashed_data.get("entries", dehashed_data.get("data", []))
        if entries:
            findings.append(IntelligenceFinding(
                entity=f"{len(entries)} record(s) found for {t}",
                type="Breach: Total Records",
                source="Dehashed",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                tags=["breach", "summary"],
            ))

            data_class_counts = defaultdict(int)
            for entry in entries[:50]:
                email = (entry.get("email") or "").strip().lower()
                username = (entry.get("username") or "").strip()
                password = (entry.get("password") or "").strip()
                breach_name = (entry.get("breach") or entry.get("database_name", "Unknown Breach")).strip()
                ip_addr = (entry.get("ip_address") or entry.get("ip", "")).strip()
                name = (entry.get("name") or entry.get("full_name", "")).strip()
                phone = (entry.get("phone") or entry.get("phone_number", "")).strip()
                address = (entry.get("address") or "").strip()
                hashed = (entry.get("hashed_password") or "").strip()

                if email and email not in seen_emails:
                    seen_emails.add(email)
                    pw_analysis, pw_note = analyze_password(password)

                    raw_parts = []
                    if breach_name:
                        raw_parts.append(f"Breach: {breach_name}")
                    if pw_note:
                        raw_parts.append(f"Password: {pw_note}")
                    raw_data = " | ".join(raw_parts) if raw_parts else None

                    sev = severity_for_breach(breach_name)
                    sev_color = "red" if sev in ("High", "Critical") else "orange"

                    findings.append(IntelligenceFinding(
                        entity=email,
                        type="Breach: Leaked Email",
                        source="Dehashed",
                        confidence="High",
                        color=sev_color,
                        threat_level="High Risk",
                        status="Confirmed",
                        resolution=f"via {breach_name}" if breach_name else None,
                        raw_data=raw_data,
                        tags=["breach", "email", "credential"],
                    ))

                    if password:
                        data_class_counts["password"] += 1
                        pw_strength_tag = pw_analysis.lower() if pw_analysis else "unknown"
                        findings.append(IntelligenceFinding(
                            entity=f"{email[:30]}... | {pw_analysis}: {pw_note}" if pw_analysis else "Password found",
                            type="Breach: Password Analysis",
                            source="Dehashed",
                            confidence="High",
                            color="red" if pw_analysis == "Weak" else ("orange" if pw_analysis == "Medium" else "slate"),
                            threat_level="High Risk" if pw_analysis == "Weak" else "Elevated Risk",
                            status="Confirmed",
                            raw_data=password[:100],
                            tags=["breach", "password", pw_strength_tag],
                        ))

                    if username:
                        data_class_counts["username"] += 1
                    if name:
                        data_class_counts["name"] += 1
                    if ip_addr:
                        data_class_counts["ip"] += 1
                    if phone:
                        data_class_counts["phone"] += 1
                    if address:
                        data_class_counts["address"] += 1
                    if hashed:
                        password_hashes.append(hashed)

                    if breach_name:
                        breach_timeline.append((breach_name, email))

            if breach_timeline:
                breach_names_seen = set()
                for bname, bemail in breach_timeline[:10]:
                    if bname not in breach_names_seen:
                        breach_names_seen.add(bname)
                        findings.append(IntelligenceFinding(
                            entity=f"{bname}",
                            type="Breach: Source Database",
                            source="Dehashed",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Confirmed",
                            tags=["breach", "source"],
                        ))

            for dc, cnt in sorted(data_class_counts.items(), key=lambda x: -x[1])[:8]:
                dc_label = DATA_CLASSES.get(dc, dc.title())
                findings.append(IntelligenceFinding(
                    entity=f"{dc_label}: {cnt} instance(s)",
                    type="Breach: Data Class Distribution",
                    source="Dehashed",
                    confidence="Medium",
                    color="slate",
                    status="Analyzed",
                    tags=["breach", "data-class", dc],
                ))

    hibp_breaches = await query_haveibeenpwned(t, client)
    if hibp_breaches:
        for br in hibp_breaches[:8]:
            br_name = br.get("Name", "")
            br_date = br.get("BreachDate", "")
            br_classes = br.get("DataClasses", [])
            br_desc = br.get("Description", "")[:200]
            findings.append(IntelligenceFinding(
                entity=f"{br_name} ({br_date})",
                type="Breach: HIBP Entry",
                source="HaveIBeenPwned",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                raw_data=f"Classes: {', '.join(br_classes)} | {br_desc}" if br_classes else br_desc,
                tags=["breach", "hibp"],
            ))

    ff_breaches = await query_firefox_monitor(t, client)
    if ff_breaches:
        for br in ff_breaches[:5]:
            br_name = br.get("Name", "")
            br_date = br.get("Date", br.get("BreachDate", ""))
            findings.append(IntelligenceFinding(
                entity=f"{br_name} ({br_date})",
                type="Breach: Firefox Monitor",
                source="Firefox Monitor",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Confirmed",
                tags=["breach", "firefox-monitor"],
            ))

    leakcheck_data = await query_leakcheck(t, client)
    if leakcheck_data and leakcheck_data.get("success"):
        lc_count = leakcheck_data.get("count", 0)
        if lc_count:
            findings.append(IntelligenceFinding(
                entity=f"{lc_count} leaked credential(s)",
                type="Breach: LeakCheck",
                source="LeakCheck",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                tags=["breach", "leakcheck"],
            ))

    if password_hashes:
        findings.append(IntelligenceFinding(
            entity=f"{len(password_hashes)} password hash(es) recovered",
            type="Breach: Password Hash Count",
            source="Dehashed",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Confirmed",
            tags=["breach", "password", "hashes"],
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No breach records for {t}",
            type="Breach: No Results",
            source="BreachDirectory",
            confidence="Low",
            color="emerald",
            status="Clean",
            tags=["breach", "clean"],
        ))

    return findings
