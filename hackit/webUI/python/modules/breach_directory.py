import httpx
import asyncio
import json
import re
import hashlib
import math
from datetime import datetime
from collections import defaultdict
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

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
    "snusbase": "High",
    "intelx": "Medium",
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

SELENIUM_BREACH_DBS = [
    "Collection #1",
    "Antipublic",
    "Exploit.in",
    "Verification",
    "Scylla",
    "COMB",
    "BreachCompilation",
    "Fake",
    "LinkedIn (2021)",
    "Facebook (2021)",
    "Adobe (2013)",
    "Ashley Madison (2015)",
]

HASH_PATTERNS = [
    (re.compile(r'^\$2[ayb]\$.{56}$'), "bcrypt"),
    (re.compile(r'^\$2[ayb]\$.{53}$'), "bcrypt"),
    (re.compile(r'^\$5\$.{43}$'), "SHA256-Crypt"),
    (re.compile(r'^\$6\$.{75}$'), "SHA512-Crypt"),
    (re.compile(r'^[0-9a-f]{32}$', re.I), "MD5"),
    (re.compile(r'^[0-9a-f]{40}$', re.I), "SHA1"),
    (re.compile(r'^[0-9a-f]{56}$', re.I), "SHA224"),
    (re.compile(r'^[0-9a-f]{64}$', re.I), "SHA256"),
    (re.compile(r'^[0-9a-f]{96}$', re.I), "SHA384"),
    (re.compile(r'^[0-9a-f]{128}$', re.I), "SHA512"),
    (re.compile(r'^[0-9a-f]{16}$', re.I), "MySQL3"),
    (re.compile(r'^\*[0-9a-f]{40}$', re.I), "MySQL5"),
    (re.compile(r'^[0-9a-f]{40}:[0-9a-f]{16}$', re.I), "Drupal7"),
    (re.compile(r'^\$P\$.{31}$'), "phpBB3"),
    (re.compile(r'^\$H\$.{31}$'), "phpBB3"),
    (re.compile(r'^[0-9a-f]{40}:[^:]+$', re.I), "Joomla"),
    (re.compile(r'^[0-9a-f]{32}:[^:]+$', re.I), "Joomla"),
    (re.compile(r'^\{SSHA}[0-9a-zA-Z+/=]+$'), "SSHA"),
    (re.compile(r'^\{SSHA256}[0-9a-zA-Z+/=]+$'), "SSHA256"),
    (re.compile(r'^\{SSHA512}[0-9a-zA-Z+/=]+$'), "SSHA512"),
    (re.compile(r'^\{SHA}[0-9a-zA-Z+/=]+$'), "SHA"),
    (re.compile(r'^sha1:[0-9a-f]{40}$', re.I), "SHA1"),
    (re.compile(r'^sha256:[0-9a-f]{64}$', re.I), "SHA256"),
    (re.compile(r'^sha512:[0-9a-f]{128}$', re.I), "SHA512"),
    (re.compile(r'^md5:[0-9a-f]{32}$', re.I), "MD5"),
    (re.compile(r'^ssha:[0-9a-zA-Z+/=]+$'), "SSHA"),
    (re.compile(r'^\$pbkdf2-sha256\$.+$'), "PBKDF2-SHA256"),
]

COMMON_PASSWORD_HASHES = set()

def _build_common_hash_lookup():
    common_pws = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
        "111111", "1234567", "sunshine", "qwerty123", "iloveyou", "princess",
        "admin", "welcome", "666666", "abc123", "football", "123123", "monkey",
        "654321", "!@#$%^&*", "charlie", "aa123456", "donald", "password1",
        "qwerty12345", "1234567890", "letmein", "password123", "dragon", "master",
    ]
    for pw in common_pws:
        for enc in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
            COMMON_PASSWORD_HASHES.add(enc(pw.encode()).hexdigest())

_build_common_hash_lookup()

async def query_dehashed(query: str, client: httpx.AsyncClient, page: int = 1) -> dict:
    try:
        resp = await safe_fetch(client, 
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
        resp = await safe_fetch(client, 
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
        resp = await safe_fetch(client, 
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
        resp = await safe_fetch(client, 
            f"https://leakcheck.io/api/v2/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_snusbase(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        payload = {"search": domain, "type": "domain"}
        resp = await safe_fetch(client, "https://snusbase.com/api/search/query",
            json=payload,
            headers={"User-Agent": UA, "Content-Type": "application/json", "Authorization": ""},
            timeout=15.0, method="POST")
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def query_scylla(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await safe_fetch(client, 
            f"https://scylla.so/api/search/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            if isinstance(data, dict) and "data" in data:
                return data["data"]
    except:
        pass
    return []

async def query_intelx(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client, 
            f"https://intelx.io/api/intelligent/search?term={domain}&maxresults=50&buckets=leaks,breaches,credentials",
            headers={"User-Agent": UA, "Accept": "application/json", "x-key": ""},
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

def identify_hash_type(hash_str: str) -> str:
    if not hash_str:
        return "Unknown"
    h = hash_str.strip()
    for pattern, label in HASH_PATTERNS:
        if pattern.match(h):
            return label
    if len(h) == 32:
        return "Likely MD5"
    if len(h) == 40:
        return "Likely SHA1"
    if len(h) == 64:
        return "Likely SHA256"
    return "Unknown"

def is_common_hash(hash_str: str) -> bool:
    return hash_str.strip().lower() in COMMON_PASSWORD_HASHES

def severity_for_breach(breach_name: str) -> str:
    for key, sev in BREACH_SEVERITY.items():
        if key.lower() in breach_name.lower():
            return sev
    return "Medium"

def compute_risk_score(total_emails: int, total_passwords: int, total_breaches: int,
                       weak_passwords: int, has_hibp: bool, data_class_count: int) -> dict:
    score = 0.0
    reasons = []
    if total_emails > 0:
        score += min(total_emails * 5, 25)
        reasons.append(f"{total_emails} email(s) exposed")
    if total_passwords > 0:
        score += min(total_passwords * 10, 30)
        reasons.append(f"{total_passwords} password(s) leaked")
    if total_breaches > 1:
        score += min(total_breaches * 5, 15)
        reasons.append(f"{total_breaches} breach source(s)")
    if weak_passwords > 0:
        score += min(weak_passwords * 15, 20)
        reasons.append(f"{weak_passwords} weak password(s)")
    if has_hibp:
        score += 10
        reasons.append("confirmed in HIBP")
    if data_class_count >= 3:
        score += min(data_class_count * 3, 10)
        reasons.append(f"{data_class_count} data class(es) exposed")
    score = min(score, 100)
    if score >= 70:
        level = "Critical"
    elif score >= 45:
        level = "High"
    elif score >= 20:
        level = "Medium"
    else:
        level = "Low"
    return {"score": round(score, 1), "level": level, "reasons": reasons}

def estimate_exposure_risk(email: str, found_passwords: bool, found_pii: bool,
                           breach_count: int) -> int:
    risk = 0
    if email:
        risk += 1
    if found_passwords:
        risk += 3
    if found_pii:
        risk += 2
    if breach_count >= 3:
        risk += 2
    elif breach_count >= 1:
        risk += 1
    return risk

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    seen_emails = set()
    password_hashes = []
    breach_timeline = []
    email_exposures = {}
    data_class_correlation = {"email_only": 0, "email_password": 0, "password_only": 0, "email_pii": 0}
    total_passwords = 0
    weak_password_count = 0
    total_breach_sources = set()
    exposed_data_classes = set()

    dehashed_data = await query_dehashed(f"domain:{t}", client)
    if dehashed_data:
        entries = dehashed_data.get("entries", dehashed_data.get("data", []))
        if entries:
            findings.append(make_finding(
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

                    findings.append(make_finding(
                        entity=email,
                        ftype="Breach: Leaked Email",
                        source="Dehashed",
                        confidence="High",
                        color=sev_color,
                        threat_level="High Risk",
                        status="Confirmed",
                        resolution=f"via {breach_name}" if breach_name else None,
                        raw_data=raw_data,
                        tags=["breach", "email", "credential"],
                    ))

                    has_pii = bool(name or phone or address or ip_addr)
                    has_password = bool(password or hashed)

                    if email and has_password:
                        data_class_correlation["email_password"] += 1
                    elif email and has_pii:
                        data_class_correlation["email_pii"] += 1
                    elif email:
                        data_class_correlation["email_only"] += 1
                    elif has_password:
                        data_class_correlation["password_only"] += 1

                    if password:
                        total_passwords += 1
                        data_class_counts["password"] += 1
                        if pw_analysis == "Weak":
                            weak_password_count += 1
                        pw_strength_tag = pw_analysis.lower() if pw_analysis else "unknown"
                        findings.append(make_finding(
                            entity=f"{email[:30]}... | {pw_analysis}: {pw_note}" if pw_analysis else "Password found",
                            ftype="Breach: Password Analysis",
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
                        exposed_data_classes.add("username")
                    if name:
                        data_class_counts["name"] += 1
                        exposed_data_classes.add("name")
                    if ip_addr:
                        data_class_counts["ip"] += 1
                        exposed_data_classes.add("ip")
                    if phone:
                        data_class_counts["phone"] += 1
                        exposed_data_classes.add("phone")
                    if address:
                        data_class_counts["address"] += 1
                        exposed_data_classes.add("address")
                    if hashed:
                        password_hashes.append(hashed)
                        htype = identify_hash_type(hashed)
                        findings.append(make_finding(
                            entity=f"Hash type: {htype}",
                            ftype="Breach: Hash Identification",
                            source="Dehashed",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            status="Confirmed",
                            raw_data=hashed[:60],
                            tags=["breach", "hash", "crypto"],
                        ))

                    if breach_name:
                        total_breach_sources.add(breach_name)
                        breach_timeline.append((breach_name, email))

                    if email not in email_exposures:
                        email_exposures[email] = {"breaches": set(), "has_password": False, "has_pii": False}
                    email_exposures[email]["breaches"].add(breach_name)
                    if has_password:
                        email_exposures[email]["has_password"] = True
                    if has_pii:
                        email_exposures[email]["has_pii"] = True

                if breach_name:
                    total_breach_sources.add(breach_name)
                    breach_timeline.append((breach_name, email or username or "unknown"))

            if breach_timeline:
                breach_names_seen = set()
                for bname, bemail in breach_timeline[:10]:
                    if bname not in breach_names_seen:
                        breach_names_seen.add(bname)
                        findings.append(make_finding(
                            entity=f"{bname}",
                            ftype="Breach: Source Database",
                            source="Dehashed",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Confirmed",
                            tags=["breach", "source"],
                        ))

            for dc, cnt in sorted(data_class_counts.items(), key=lambda x: -x[1])[:8]:
                dc_label = DATA_CLASSES.get(dc, dc.title())
                findings.append(make_finding(
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
            total_breach_sources.add(br_name)
            findings.append(make_finding(
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
            total_breach_sources.add(br_name)
            findings.append(make_finding(
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
            total_breach_sources.add("LeakCheck")
            findings.append(make_finding(
                entity=f"{lc_count} leaked credential(s)",
                type="Breach: LeakCheck",
                source="LeakCheck",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                tags=["breach", "leakcheck"],
            ))
        lc_entries = leakcheck_data.get("data", leakcheck_data.get("results", []))
        if lc_entries:
            for lc_entry in lc_entries[:25]:
                lc_email = (lc_entry.get("email") or lc_entry.get("login") or "").strip().lower()
                lc_pass = (lc_entry.get("password") or lc_entry.get("pass") or "").strip()
                lc_source = (lc_entry.get("source") or lc_entry.get("breach", "LeakCheck")).strip()
                lc_hash = (lc_entry.get("hash") or lc_entry.get("hash_password") or "").strip()

                if lc_email and lc_email not in seen_emails:
                    seen_emails.add(lc_email)
                    pw_analysis, pw_note = analyze_password(lc_pass)
                    total_breach_sources.add(lc_source)
                    findings.append(make_finding(
                        entity=lc_email,
                        ftype="Breach: Leaked Email",
                        source="LeakCheck",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        status="Confirmed",
                        resolution=f"via {lc_source}" if lc_source else None,
                        tags=["breach", "email", "leakcheck"],
                    ))
                    if lc_pass:
                        total_passwords += 1
                        if pw_analysis == "Weak":
                            weak_password_count += 1
                        findings.append(make_finding(
                            entity=f"Password: {pw_analysis}" if pw_analysis else "Password found",
                            ftype="Breach: LeakCheck Password",
                            source="LeakCheck",
                            confidence="Medium",
                            color="red" if pw_analysis == "Weak" else "orange",
                            threat_level="High Risk" if pw_analysis == "Weak" else "Elevated Risk",
                            status="Confirmed",
                            raw_data=lc_pass[:100],
                            tags=["breach", "password", "leakcheck"],
                        ))
                    if lc_hash:
                        password_hashes.append(lc_hash)
                        htype = identify_hash_type(lc_hash)
                        findings.append(make_finding(
                            entity=f"Hash type: {htype}",
                            ftype="Breach: Hash Identification",
                            source="LeakCheck",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            status="Confirmed",
                            raw_data=lc_hash[:60],
                            tags=["breach", "hash", "leakcheck"],
                        ))

    snusbase_data = await query_snusbase(t, client)
    if snusbase_data:
        sb_results = snusbase_data.get("results", snusbase_data.get("data", snusbase_data.get("records", [])))
        if sb_results:
            sb_count = len(sb_results) if isinstance(sb_results, list) else (snusbase_data.get("count", 0) or len(sb_results))
            total_breach_sources.add("SnusBase")
            findings.append(make_finding(
                entity=f"{sb_count} record(s) from SnusBase",
                type="Breach: SnusBase",
                source="SnusBase",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                tags=["breach", "snusbase"],
            ))
            if isinstance(sb_results, list):
                for sb_entry in sb_results[:20]:
                    sb_email = (sb_entry.get("email") or sb_entry.get("login", "")).strip().lower()
                    sb_pass = (sb_entry.get("password") or sb_entry.get("pass", "")).strip()
                    sb_hash = (sb_entry.get("hash") or sb_entry.get("hashed_password", "")).strip()
                    sb_source = (sb_entry.get("source") or sb_entry.get("breach", "SnusBase")).strip()
                    if sb_email and sb_email not in seen_emails:
                        seen_emails.add(sb_email)
                        total_breach_sources.add(sb_source)
                        findings.append(make_finding(
                            entity=sb_email,
                            ftype="Breach: Leaked Email",
                            source="SnusBase",
                            confidence="Medium",
                            color="red",
                            threat_level="High Risk",
                            status="Confirmed",
                            resolution=f"via {sb_source}" if sb_source else None,
                            tags=["breach", "email", "snusbase"],
                        ))
                        if sb_pass:
                            total_passwords += 1
                            pw_analysis, pw_note = analyze_password(sb_pass)
                            if pw_analysis == "Weak":
                                weak_password_count += 1
                            findings.append(make_finding(
                                entity=f"SnusBase Password: {pw_analysis}",
                                ftype="Breach: SnusBase Password",
                                source="SnusBase",
                                confidence="Medium",
                                color="red" if pw_analysis == "Weak" else "orange",
                                threat_level="High Risk" if pw_analysis == "Weak" else "Elevated Risk",
                                status="Confirmed",
                                raw_data=sb_pass[:100],
                                tags=["breach", "password", "snusbase"],
                            ))
                        if sb_hash:
                            password_hashes.append(sb_hash)

    scylla_data = await query_scylla(t, client)
    if scylla_data:
        scylla_count = len(scylla_data)
        total_breach_sources.add("Scylla")
        findings.append(make_finding(
            entity=f"{scylla_count} record(s) from Scylla.so",
            type="Breach: Scylla",
            source="Scylla.so",
            confidence="Medium",
            color="red",
            threat_level="Critical Risk",
            status="Confirmed",
            tags=["breach", "scylla"],
        ))
        for scylla_entry in scylla_data[:20]:
            sc_email = (scylla_entry.get("email") or scylla_entry.get("login", "")).strip().lower()
            sc_pass = (scylla_entry.get("password") or scylla_entry.get("pass", "")).strip()
            sc_hash = (scylla_entry.get("hash") or "").strip()
            sc_source = (scylla_entry.get("source") or scylla_entry.get("breach", "Scylla")).strip()
            if sc_email and sc_email not in seen_emails:
                seen_emails.add(sc_email)
                total_breach_sources.add(sc_source)
                findings.append(make_finding(
                    entity=sc_email,
                    ftype="Breach: Leaked Email",
                    source="Scylla.so",
                    confidence="Medium",
                    color="red",
                    threat_level="Critical Risk",
                    status="Confirmed",
                    resolution=f"via {sc_source}" if sc_source else None,
                    tags=["breach", "email", "scylla"],
                ))
                if sc_pass:
                    total_passwords += 1
                    pw_analysis, pw_note = analyze_password(sc_pass)
                    if pw_analysis == "Weak":
                        weak_password_count += 1
                    findings.append(make_finding(
                        entity=f"Scylla Password: {pw_analysis}",
                        ftype="Breach: Scylla Password",
                        source="Scylla.so",
                        confidence="Medium",
                        color="red" if pw_analysis == "Weak" else "orange",
                        threat_level="Critical Risk" if pw_analysis == "Weak" else "Elevated Risk",
                        status="Confirmed",
                        raw_data=sc_pass[:100],
                        tags=["breach", "password", "scylla"],
                    ))
                if sc_hash:
                    password_hashes.append(sc_hash)

    intelx_data = await query_intelx(t, client)
    if intelx_data:
        ix_records = intelx_data.get("records", intelx_data.get("results", intelx_data.get("data", [])))
        if ix_records:
            ix_count = len(ix_records)
            total_breach_sources.add("IntelX")
            findings.append(make_finding(
                entity=f"{ix_count} record(s) from IntelX.io",
                type="Breach: IntelX",
                source="IntelX.io",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Confirmed",
                tags=["breach", "intelx"],
            ))
            for ix_entry in ix_records[:15]:
                ix_email = (ix_entry.get("email") or ix_entry.get("login", ix_entry.get("value", ""))).strip().lower()
                ix_source = (ix_entry.get("source") or ix_entry.get("bucket", "IntelX")).strip()
                if ix_email and ix_email not in seen_emails:
                    seen_emails.add(ix_email)
                    total_breach_sources.add(ix_source)
                    findings.append(make_finding(
                        entity=ix_email,
                        ftype="Breach: Leaked Email",
                        source="IntelX.io",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Confirmed",
                        resolution=f"via {ix_source}" if ix_source else None,
                        tags=["breach", "email", "intelx"],
                    ))

    if password_hashes:
        findings.append(make_finding(
            entity=f"{len(password_hashes)} password hash(es) recovered",
            type="Breach: Password Hash Count",
            source="Dehashed",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Confirmed",
            tags=["breach", "password", "hashes"],
        ))
        common_hash_count = sum(1 for h in password_hashes if is_common_hash(h))
        if common_hash_count:
            findings.append(make_finding(
                entity=f"{common_hash_count} hash(es) match common/weak passwords",
                type="Breach: Credential Stuffing Risk",
                source="BreachDirectory",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Confirmed",
                raw_data="These hashes correspond to well-known weak passwords — high credential stuffing risk",
                tags=["breach", "credential-stuffing", "weak-hashes"],
            ))
        unique_types = set()
        for h in password_hashes:
            unique_types.add(identify_hash_type(h))
        if unique_types:
            findings.append(make_finding(
                entity=f"Hash types identified: {', '.join(sorted(unique_types))}",
                type="Breach: Hash Type Summary",
                source="BreachDirectory",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                tags=["breach", "hash", "crypto"],
            ))

    if email_exposures:
        high_risk_emails = 0
        for em, info in email_exposures.items():
            risk_score = estimate_exposure_risk(
                em, info["has_password"], info["has_pii"], len(info["breaches"])
            )
            if risk_score >= 5:
                high_risk_emails += 1
        if high_risk_emails:
            findings.append(make_finding(
                entity=f"{high_risk_emails} email(s) at high exposure risk",
                type="Breach: Email Exposure Scoring",
                source="BreachDirectory",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Analyzed",
                raw_data=f"Each scored on password-reuse + PII co-occurrence factors",
                tags=["breach", "email-exposure", "risk-scoring"],
            ))

    if breach_timeline:
        timeline_sorted = sorted(
            [(b, em) for b, em in breach_timeline if b],
            key=lambda x: x[0].lower()
        )
        timeline_entries = []
        seen_tl = set()
        for bname, bemail in timeline_sorted:
            if bname not in seen_tl:
                seen_tl.add(bname)
                sev = severity_for_breach(bname)
                timeline_entries.append(f"{bname} [{sev}]")
        if timeline_entries:
            findings.append(make_finding(
                entity=" | ".join(timeline_entries[:8]),
                type="Breach: Timeline (Chronological with Severity)",
                source="BreachDirectory",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Analyzed",
                tags=["breach", "timeline", "visualization"],
            ))

    if any(v > 0 for v in data_class_correlation.values()):
        parts = []
        for k, v in data_class_correlation.items():
            if v > 0:
                label = k.replace("_", " ").title()
                parts.append(f"{label}: {v}")
        findings.append(make_finding(
            entity=" | ".join(parts),
            type="Breach: Data Class Correlation",
            source="BreachDirectory",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Analyzed",
            tags=["breach", "correlation", "data-class"],
        ))

    risk_score = compute_risk_score(
        total_emails=len(seen_emails),
        total_passwords=total_passwords,
        total_breaches=len(total_breach_sources),
        weak_passwords=weak_password_count,
        has_hibp=bool(hibp_breaches),
        data_class_count=len(exposed_data_classes),
    )
    if risk_score["score"] > 0:
        findings.append(make_finding(
            entity=f"Risk Score: {risk_score['score']}/100 ({risk_score['level']})",
            type="Breach: Risk Score Summary",
            source="BreachDirectory",
            confidence="Medium",
            color="red" if risk_score["level"] in ("High", "Critical") else "orange",
            threat_level=f"{risk_score['level']} Risk",
            status="Analyzed",
            raw_data=" | ".join(risk_score["reasons"]),
            tags=["breach", "risk-score", risk_score["level"].lower()],
        ))

    if password_hashes:
        stuffing_risk_count = sum(1 for h in password_hashes if is_common_hash(h))
        if stuffing_risk_count > 0:
            findings.append(make_finding(
                entity=f"{stuffing_risk_count}/{len(password_hashes)} hashes are common — high credential stuffing risk",
                type="Breach: Credential Stuffing Assessment",
                source="BreachDirectory",
                confidence="High",
                color="red",
                threat_level="Critical Risk",
                status="Confirmed",
                tags=["breach", "credential-stuffing", "automated-attack"],
            ))

    selenium_refs = []
    for db_name in SELENIUM_BREACH_DBS:
        if any(db_name.lower() in bs.lower() for bs in total_breach_sources):
            selenium_refs.append(db_name)
    if selenium_refs:
        findings.append(make_finding(
            entity=f"References: {', '.join(selenium_refs[:6])}",
            type="Breach: Selenium Database References",
            source="BreachDirectory",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            status="Referenced",
            tags=["breach", "selenium", "database-reference"],
        ))

    breach_categories = set()
    category_map = {
        "linkedin": "Social", "facebook": "Social", "myspace": "Social", "twitter": "Social",
        "linkedin": "Social", "instagram": "Social", "snapchat": "Social",
        "adobe": "Entertainment", "canva": "Design", "pinterest": "Social",
        "dropbox": "Cloud", "last.fm": "Music", "spotify": "Music",
        "tumblr": "Social", "pornhub": "Adult", "ashley madison": "Adult",
        "adult friend": "Adult", "friendfinder": "Adult",
        "xbox": "Gaming", "playstation": "Gaming", "steam": "Gaming",
        "battle.net": "Gaming", "epic games": "Gaming", "minecraft": "Gaming",
        "twitch": "Gaming", "roblox": "Gaming", "nexus": "Gaming",
        "evony": "Gaming", "zynga": "Gaming",
        "bank": "Financial", "capital one": "Financial",
        "amazon": "E-Commerce", "ebay": "E-Commerce", "etsy": "E-Commerce",
        "shopify": "E-Commerce", "wish": "E-Commerce",
        "yahoo": "Tech", "google": "Tech", "microsoft": "Tech",
        "atlassian": "Tech", "github": "Tech", "gitlab": "Tech",
        "samsung": "Tech", "xiaomi": "Tech",
        "medibank": "Healthcare", "health": "Healthcare",
        "edmodo": "Education", "coursera": "Education", "udemy": "Education",
        "uber": "Transport", "lyft": "Transport",
    }
    for src in total_breach_sources:
        for kw, cat in category_map.items():
            if kw in src.lower():
                breach_categories.add(cat)
    if breach_categories:
        findings.append(make_finding(
            entity=f"Breach categories: {', '.join(sorted(breach_categories))}",
            type="Breach: Category Classification",
            source="BreachDirectory",
            confidence="Medium",
            color="slate",
            status="Analyzed",
            tags=["breach", "category"]
        ))

    reused_passwords = len([e for e in email_exposures.values() if e.get("has_password") and len(e.get("breaches", set())) > 1]) if email_exposures else 0
    if reused_passwords > 0:
        findings.append(make_finding(
            entity=f"~{reused_passwords} email(s) with password reuse across breaches",
            type="Breach: Password Reuse Detection",
            source="BreachDirectory",
            confidence="Medium",
            color="red",
            threat_level="High Risk",
            status="Analyzed",
            raw_data=f"Identical credentials exposed in multiple breaches = high account takeover risk",
            tags=["breach", "password-reuse", "account-takeover"]
        ))

    if seen_emails:
        email_risk_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for em, info in email_exposures.items():
            risk = estimate_exposure_risk(em, info["has_password"], info["has_pii"], len(info["breaches"]))
            if risk >= 6: email_risk_buckets["critical"] += 1
            elif risk >= 4: email_risk_buckets["high"] += 1
            elif risk >= 2: email_risk_buckets["medium"] += 1
            else: email_risk_buckets["low"] += 1
        findings.append(make_finding(
            entity=f"Exposure risk: C:{email_risk_buckets['critical']} H:{email_risk_buckets['high']} M:{email_risk_buckets['medium']} L:{email_risk_buckets['low']}",
            ftype="Breach: Email Risk Distribution",
            source="BreachDirectory",
            confidence="Medium",
            color="slate",
            status="Analyzed",
            raw_data=f"Critical: {email_risk_buckets['critical']} | High: {email_risk_buckets['high']} | Medium: {email_risk_buckets['medium']} | Low: {email_risk_buckets['low']}",
            tags=["breach", "risk-distribution"]
        ))

        findings.append(make_finding(
            entity=f"Total unique emails exposed: {len(seen_emails)} | Passwords leaked: {total_passwords} | Breach sources: {len(total_breach_sources)}",
            type="Breach: Exposure Landscape Summary",
            source="BreachDirectory",
            confidence="High",
            color="red" if total_passwords > 0 or len(total_breach_sources) > 2 else "orange",
            threat_level="Critical Risk" if total_passwords > 0 else "Elevated Risk",
            status="Analyzed",
            raw_data=f"Emails: {len(seen_emails)} | Passwords: {total_passwords} | Breaches: {len(total_breach_sources)} | Weak passwords: {weak_password_count} | Data classes: {len(exposed_data_classes)} | Risk score: {risk_score.get('score', 'N/A')}",
            tags=["breach", "landscape", "overview"]
        ))

    async def check_paste_sites():
        for url in [f"https://psbdmp.ws/api/search/{t}", f"https://pastebin.com/search?q={t}"]:
            try:
                resp = await safe_fetch(client, url, timeout=10.0, headers={"User-Agent": UA})
                if resp.status_code == 200 and len(resp.text.strip()) > 50:
                    findings.append(make_finding(
                        entity=f"Paste site data found for {t}", ftype="Breach: Paste Site Mention",
                        source="BreachDirectory", confidence="Low", color="orange", threat_level="Elevated Risk",
                        raw_data=f"{url.split('/')[2]} returned results", tags=["breach", "paste"]))
                    emails_in_paste = set(EMAIL_REGEX.findall(resp.text))
                    for pe in list(emails_in_paste)[:5]:
                        if pe not in seen_emails:
                            findings.append(make_finding(
                                entity=pe, ftype="Breach: Paste Email",
                                source="BreachDirectory", confidence="Low", color="orange",
                                threat_level="Elevated Risk", tags=["breach", "email", "paste"]))
            except: pass

    async def analyze_email_security_breach():
        import dns.resolver as dnsr
        loop = asyncio.get_event_loop()
        for record_type, label in [("SPF", "v=spf1"), ("DMARC", "v=DMARC1")]:
            try:
                domain = t.split("@")[-1] if "@" in t else t
                target_rec = domain if record_type == "SPF" else f"_dmarc.{domain}"
                txts = await loop.run_in_executor(None, lambda: dnsr.resolve(target_rec, 'TXT'))
                for r in txts:
                    txt = str(r)
                    if label in txt:
                        findings.append(make_finding(
                            entity=f"{record_type}: {'Present' if label in txt else 'Missing'}",
                            ftype=f"Breach: Email Security - {record_type}",
                            source="BreachDirectory", confidence="High", color="emerald",
                            threat_level="Informational", tags=["breach", "email-security", record_type.lower()]))
                        break
            except: pass

    async def analyze_email_reputation():
        domain = t.split("@")[-1] if "@" in t else t
        risk_factors = []
        disposable_domains = {"mailinator.com","guerrillamail.com","tempmail.com","10minutemail.com","yopmail.com","throwaway.email"}
        if domain in disposable_domains:
            risk_factors.append("Disposable email domain")
        free_domains = {"gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","mail.com","protonmail.com","yandex.com","gmx.com","icloud.com"}
        is_free = domain in free_domains
        if is_free:
            risk_factors.append("Free email provider")
        findings.append(make_finding(
            entity=f"Email domain: {domain} {'(Free/Consumer)' if is_free else '(Custom/Business)'}",
            type="Breach: Email Domain Classification",
            source="BreachDirectory", confidence="High", color="slate",
            threat_level="Informational" if not is_free else "Standard Target",
            tags=["breach", "domain"]))

    async def analyze_email_variations():
        if "@" not in t:
            return
        local, domain = t.split("@")
        variations = []
        for sep in [".", "_", "-", ""]:
            if len(local) >= 2:
                variations.append(f"{local}{sep}alt@{domain}")
                if len(local) >= 3:
                    variations.append(f"{local[:-1]}{sep}@{domain}")
        if variations:
            findings.append(make_finding(
                entity=f"Email variations: {', '.join(variations[:6])}",
                type="Breach: Email Variation Analysis",
                source="BreachDirectory", confidence="Low", color="slate",
                threat_level="Informational", tags=["breach", "email", "variation"]))

    async def analyze_password_breach_patterns():
        if not password_hashes:
            findings.append(make_finding(
                entity="No password data recovered from breach sources",
                ftype="Breach: Password Recovery Status",
                source="BreachDirectory", confidence="Medium", color="emerald",
                threat_level="Informational", tags=["breach", "password"]))
        else:
            htypes = defaultdict(int)
            for h in password_hashes:
                htypes[identify_hash_type(h)] += 1
            for ht, cnt in sorted(htypes.items(), key=lambda x: -x[1])[:5]:
                findings.append(make_finding(
                    entity=f"Hash type: {ht} ({cnt})", ftype="Breach: Hash Type Distribution",
                    source="BreachDirectory", confidence="High", color="slate",
                    threat_level="Informational", tags=["breach", "hash"]))

    async def scrape_common_breach_dbs():
        breach_pages = {
            "Firefox Monitor": f"https://monitor.firefox.com/breaches",
            "HIBP": f"https://haveibeenpwned.com/breaches",
        }
        for name, url in breach_pages.items():
            try:
                resp = await safe_fetch(client, url, timeout=10.0, headers={"User-Agent": UA})
                if resp.status_code == 200:
                    findings.append(make_finding(
                        entity=f"{name} accessible for breach research",
                        ftype="Breach: Breach Database Access",
                        source="BreachDirectory", confidence="Medium", color="slate",
                        threat_level="Informational", tags=["breach", "source"]))
                    break
            except: pass

    async def analyze_target_type():
        if "@" in t:
            findings.append(make_finding(
                entity=f"Target: Email address", ftype="Breach: Target Classification",
                source="BreachDirectory", confidence="High", color="slate",
                threat_level="Informational", tags=["breach", "target"]))
        else:
            findings.append(make_finding(
                entity=f"Target: Domain ({t})", ftype="Breach: Target Classification",
                source="BreachDirectory", confidence="High", color="slate",
                threat_level="Informational", tags=["breach", "target"]))

    async def generate_breach_recommendations():
        recs = []
        if total_passwords > 0: recs.append("Change all exposed passwords immediately")
        if weak_password_count > 0: recs.append("Use a password manager with strong random passwords")
        if len(total_breach_sources) > 0: recs.append("Enable 2FA on all accounts associated with this email")
        if len(seen_emails) > 0: recs.append("Monitor for phishing targeting this email")
        if any("password_reuse" in tag for f in findings for tag in f.tags): recs.append("Use unique passwords for every service")
        recs.append("Check https://haveibeenpwned.com for latest breach info")
        recs.append("Use Firefox Monitor for ongoing breach monitoring")
        if recs:
            for i, rec in enumerate(recs[:5]):
                findings.append(make_finding(
                    entity=f"Rec {i+1}: {rec[:100]}", ftype="Breach: Recommendation",
                    source="BreachDirectory", confidence="Medium", color="orange",
                    threat_level="Informational", tags=["breach", "recommendation"]))

    async def check_email_format_analysis():
        if "@" in t:
            local, domain = t.split("@")
            findings.append(make_finding(entity=f"Local part length: {len(local)}", ftype="Breach: Email Format",
                source="BreachDirectory", confidence="High", color="slate", threat_level="Informational", tags=["breach"]))
            findings.append(make_finding(entity=f"Domain: {domain}", ftype="Breach: Email Domain",
                source="BreachDirectory", confidence="High", color="slate", threat_level="Informational", tags=["breach"]))
            has_plus = "+" in local
            findings.append(make_finding(
                entity=f"Plus addressing: {'Enabled' if has_plus else 'Not used'}", ftype="Breach: Email Plus Addressing",
                source="BreachDirectory", confidence="High", color="emerald" if has_plus else "slate",
                threat_level="Informational", tags=["breach", "email"]))
            local_parts = re.split(r'[._\-]', local)
            if len(local_parts) >= 2:
                findings.append(make_finding(
                    entity=f"Local part has {len(local_parts)} segment(s)", ftype="Breach: Email Local Part Structure",
                    source="BreachDirectory", confidence="High", color="slate", threat_level="Informational", tags=["breach"]))
            has_number = bool(re.search(r'\d', local))
            findings.append(make_finding(
                entity=f"Numbers in email: {'Yes' if has_number else 'No'}", ftype="Breach: Email Numeric Pattern",
                source="BreachDirectory", confidence="High", color="slate", threat_level="Informational", tags=["breach"]))
        else:
            findings.append(make_finding(entity=f"Target domain: {t}", ftype="Breach: Domain Analysis",
                source="BreachDirectory", confidence="High", color="slate", threat_level="Informational", tags=["breach"]))

    async def check_domain_reputation():
        domain = t.split("@")[-1] if "@" in t else t
        mx_found = False
        try:
            import dns.resolver as dnsr
            mx = await asyncio.get_event_loop().run_in_executor(None, lambda: dnsr.resolve(domain, 'MX'))
            mx_found = len(list(mx)) > 0
        except: pass
        findings.append(make_finding(
            entity=f"Mail exchangers: {'Configured' if mx_found else 'None found'}", ftype="Breach: Domain Mail Status",
            source="BreachDirectory", confidence="High", color="emerald" if mx_found else "red",
            threat_level="Informational", tags=["breach", "dns"]))
        try:
            resp = await safe_fetch(client, f"https://{domain}", timeout=8.0, follow_redirects=True, headers={"User-Agent": UA})
            findings.append(make_finding(
                entity=f"Website: {'Accessible' if resp.status_code == 200 else f'HTTP {resp.status_code}'}",
                ftype="Breach: Domain Web Presence", source="BreachDirectory", confidence="High", color="slate",
                threat_level="Informational", tags=["breach", "web"]))
        except: pass

    async def check_common_leaks():
        leak_check_urls = [
            ("HaveIBeenPwned", f"https://haveibeenpwned.com/breaches"),
            ("Firefox Monitor", f"https://monitor.firefox.com/breaches"),
            ("Dehashed", f"https://dehashed.com/"),
        ]
        for name, url in leak_check_urls:
            try:
                resp = await safe_fetch(client, url, timeout=8.0, headers={"User-Agent": UA})
                if resp.status_code == 200:
                    findings.append(make_finding(
                        entity=f"{name} accessible ({len(resp.text)} bytes)", ftype="Breach: Breach Database Status",
                        source="BreachDirectory", confidence="Medium", color="slate", tags=["breach"]))
                    break
            except: pass

    async def analyze_breach_risk_factors():
        domain = t.split("@")[-1] if "@" in t else t
        factors = []
        if any(d in domain for d in ["mailinator","guerrillamail","tempmail","10minutemail","yopmail","throwaway"]):
            factors.append("Disposable email domain - high fraud risk")
        if domain in {"gmail.com","yahoo.com","hotmail.com","outlook.com"}:
            factors.append("Free email provider - common breach target")
        factors.append("Check if email appears in known breach collections")
        factors.append("Credential stuffing risk if password reused")
        for f_text in factors:
            findings.append(make_finding(
                entity=f_text, ftype="Breach: Risk Factor",
                source="BreachDirectory", confidence="Medium", color="orange",
                threat_level="Standard Target", tags=["breach", "risk"]))

    async def check_email_domain_age():
        domain = t.split("@")[-1] if "@" in t else t
        try:
            import whois
            w = await asyncio.get_event_loop().run_in_executor(None, lambda: whois.whois(domain))
            creation = str(w.creation_date) if w.creation_date else "Unknown"
            findings.append(make_finding(
                entity=f"Domain created: {creation[:30]}", ftype="Breach: Domain Age",
                source="BreachDirectory", confidence="Medium", color="slate", tags=["breach", "dns"]))
        except:
            findings.append(make_finding(
                entity=f"Domain age: Unknown", ftype="Breach: Domain Age Status",
                source="BreachDirectory", confidence="Low", color="slate", tags=["breach", "dns"]))

    async def analyze_breach_data_quality():
        if password_hashes:
            unique_hashes = len(set(password_hashes))
            findings.append(make_finding(
                entity=f"Unique hashes: {unique_hashes}/{len(password_hashes)}", ftype="Breach: Data Quality Analysis",
                source="BreachDirectory", confidence="Medium", color="slate", tags=["breach", "analysis"]))
        findings.append(make_finding(
            entity=f"Breach sources found: {len(total_breach_sources)}", ftype="Breach: Source Count",
            source="BreachDirectory", confidence="Medium", color="slate", tags=["breach", "source"]))
        findings.append(make_finding(
            entity=f"Unique emails exposed: {len(seen_emails)}", ftype="Breach: Exposure Count",
            source="BreachDirectory", confidence="Medium", color="red" if seen_emails else "emerald",
            threat_level="Informational", tags=["breach", "count"]))

    async def check_google_dork_breaches():
        dork = f"site:pastebin.com \"{t}\""
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q={dork.replace(' ', '+')}", timeout=8.0, headers={"User-Agent": UA})
            if resp.status_code == 200 and len(resp.text) > 200:
                findings.append(make_finding(
                    entity=f"Google dork results for pastebin mentions", ftype="Breach: Google Dork Analysis",
                    source="BreachDirectory", confidence="Low", color="orange", tags=["breach"]))
        except: pass

    async def check_social_mention_breaches():
        social_sites = ["github.com", "stackoverflow.com", "reddit.com", "twitter.com"]
        for site in social_sites:
            dork = f"site:{site} \"{t}\""
            try:
                resp = await safe_fetch(client, f"https://www.google.com/search?q={dork.replace(' ', '+')}", timeout=8.0, headers={"User-Agent": UA})
                if resp.status_code == 200 and len(resp.text) > 200:
                    findings.append(make_finding(
                        entity=f"Social mention: {site}", ftype="Breach: Social Media Mention",
                        source="BreachDirectory", confidence="Low", color="slate", tags=["breach", "social"]))
            except: pass

    async def check_security_headers_breach():
        domain = t.split("@")[-1] if "@" in t else t
        for proto in ["https", "http"]:
            try:
                resp = await safe_fetch(client, f"{proto}://{domain}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
                hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}
                for hdr, label in [("strict-transport-security","HSTS"),("x-frame-options","XFO"),("content-security-policy","CSP")]:
                    if hdr in hdrs:
                        findings.append(make_finding(
                            entity=f"{label}: Present", ftype="Breach: Security Header",
                            source="BreachDirectory", confidence="High", color="emerald", tags=["breach", "security"]))
                break
            except: pass

    await asyncio.gather(
        check_paste_sites(),
        analyze_email_security_breach(),
        analyze_email_reputation(),
        analyze_email_variations(),
        analyze_password_breach_patterns(),
        scrape_common_breach_dbs(),
        analyze_target_type(),
        generate_breach_recommendations(),
        check_email_format_analysis(),
        check_domain_reputation(),
        check_common_leaks(),
        analyze_breach_risk_factors(),
        check_email_domain_age(),
        analyze_breach_data_quality(),
        check_google_dork_breaches(),
        check_social_mention_breaches(),
        check_security_headers_breach(),
    )

    async def analyze_breach_impact_assessment():
        domain = t.split("@")[-1] if "@" in t else t
        total_exposed = len(seen_emails)
        findings.append(make_finding(
            entity=f"Breach impact: {total_exposed} email(s), {total_passwords} password(s), {len(total_breach_sources)} source(s)",
            type="Breach: Impact Assessment", source="BreachDirectory", confidence="Medium",
            color="red" if total_exposed > 0 else "emerald",
            threat_level="Critical Risk" if total_exposed > 0 else "Informational",
            tags=["breach", "impact"]))
        if total_exposed > 0:
            findings.append(make_finding(
                entity=f"Estimated account takeover risk: {'HIGH' if total_passwords > 0 else 'MEDIUM'}",
                ftype="Breach: Account Takeover Risk",
                source="BreachDirectory", confidence="Medium", color="red",
                threat_level="Elevated Risk", tags=["breach", "risk"]))

    async def check_technology_fingerprint():
        domain = t.split("@")[-1] if "@" in t else t
        try:
            resp = await safe_fetch(client, f"https://{domain}", timeout=8.0, follow_redirects=True, headers={"User-Agent": UA})
            html = resp.text[:50000] if hasattr(resp, 'text') else ""
            indicators = {
                "WordPress": ["/wp-content", "/wp-admin"], "Cloudflare": ["cloudflare", "__cfduid"],
                "Bootstrap": ["bootstrap"], "jQuery": ["jquery"], "React": ["react"],
                "Google Analytics": ["google-analytics", "gtag"], "PHP": [".php"],
            }
            for tech, pats in indicators.items():
                if any(p in html.lower() for p in pats):
                    findings.append(make_finding(
                        entity=f"Technology: {tech}", ftype="Breach: Tech Fingerprint",
                        source="BreachDirectory", confidence="Medium", color="slate",
                        tags=["breach", "tech"]))
        except: pass

    async def check_common_vulnerability_headers():
        domain = t.split("@")[-1] if "@" in t else t
        try:
            resp = await safe_fetch(client, f"https://{domain}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
            hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}
            server = hdrs.get("server", "")
            if server:
                findings.append(make_finding(
                    entity=f"Server: {server[:60]}", ftype="Breach: Server Fingerprint",
                    source="BreachDirectory", confidence="Medium", color="slate",
                    tags=["breach", "tech"]))
            x_powered = hdrs.get("x-powered-by", "")
            if x_powered:
                findings.append(make_finding(
                    entity=f"Powered by: {x_powered[:60]}", ftype="Breach: Technology Leak",
                    source="BreachDirectory", confidence="Medium", color="orange",
                    tags=["breach", "tech"]))
        except: pass

    async def analyze_dns_health():
        domain = t.split("@")[-1] if "@" in t else t
        loop2 = asyncio.get_event_loop()
        import dns.resolver as dnsr
        for rtype in ["A", "AAAA", "NS", "MX", "TXT"]:
            try:
                recs = await loop2.run_in_executor(None, lambda: dnsr.resolve(domain, rtype))
                count = sum(1 for _ in recs)
                findings.append(make_finding(
                    entity=f"DNS {rtype}: {count} record(s)", ftype="Breach: DNS Health",
                    source="BreachDirectory", confidence="High", color="slate",
                    tags=["breach", "dns"]))
            except: pass

    async def check_email_breach_prevention():
        recs = []
        recs.append("Enable 2FA on all accounts")
        recs.append("Use a password manager (Bitwarden, 1Password, KeePass)")
        recs.append("Regularly check HaveIBeenPwned for new breaches")
        recs.append("Use unique email addresses for different services")
        recs.append("Monitor for credential stuffing attacks")
        recs.append("Set up breach alerts via Firefox Monitor")
        for i, rec in enumerate(recs[:4]):
            findings.append(make_finding(
                entity=f"Prevention {i+1}: {rec}", ftype="Breach: Prevention Advice",
                source="BreachDirectory", confidence="Medium", color="blue",
                tags=["breach", "prevention"]))

    async def analyze_data_exposure_severity():
        if total_passwords > 0:
            pw_severity = "Critical" if total_passwords > 5 else "High"
            findings.append(make_finding(
                entity=f"Password exposure severity: {pw_severity} ({total_passwords} passwords)",
                type="Breach: Exposure Severity", source="BreachDirectory", confidence="High",
                color="red", threat_level=f"{pw_severity} Risk", tags=["breach", "severity"]))
        if len(exposed_data_classes) > 0:
            findings.append(make_finding(
                entity=f"Data classes exposed: {len(exposed_data_classes)} distinct type(s)",
                type="Breach: Data Class Exposure", source="BreachDirectory", confidence="High",
                color="red", tags=["breach", "data-class"]))
        if weak_password_count > 0:
            findings.append(make_finding(
                entity=f"Weak passwords detected: {weak_password_count}",
                ftype="Breach: Weak Password Alert", source="BreachDirectory", confidence="High",
                color="red", threat_level="Critical Risk", tags=["breach", "weak-password"]))

    await asyncio.gather(
        analyze_breach_impact_assessment(),
        check_technology_fingerprint(),
        check_common_vulnerability_headers(),
        analyze_dns_health(),
        check_email_breach_prevention(),
        analyze_data_exposure_severity(),
    )

    async def check_ssl_cert():
        domain = t.split("@")[-1] if "@" in t else t
        try:
            import ssl, socket
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                issuer = dict(cert.get("issuer", [[["", ""]]])[0]).get("commonName", "Unknown")
                findings.append(make_finding(
                    entity=f"SSL Issuer: {issuer}", ftype="Breach: SSL Certificate Info",
                    source="BreachDirectory", confidence="High", color="slate", tags=["breach", "ssl"]))
                sans = [v for _, v in cert.get("subjectAltName", [])]
                if sans:
                    findings.append(make_finding(
                        entity=f"SSL SANs: {len(sans)} domain(s)", ftype="Breach: SSL Subject Alt Names",
                        source="BreachDirectory", confidence="High", color="slate", tags=["breach", "ssl"]))
        except: pass

    async def check_http_redirects():
        domain = t.split("@")[-1] if "@" in t else t
        try:
            resp = await safe_fetch(client, f"https://{domain}", timeout=8.0, follow_redirects=False, headers={"User-Agent": UA})
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                findings.append(make_finding(
                    entity=f"Redirect: {resp.status_code} -> {location[:80]}",
                    ftype="Breach: HTTP Redirect", source="BreachDirectory",
                    confidence="High", color="slate", tags=["breach", "http"]))
        except: pass

    async def analyze_breach_remediation():
        recs = []
        if total_passwords > 0: recs.append("Immediately rotate all passwords for exposed accounts")
        if weak_password_count > 0: recs.append("Audit all accounts for weak password reuse")
        if len(total_breach_sources) > 0: recs.append("Review account recovery options (security questions, backup email)")
        recs.append("Check for exposed personal data (address, phone, SSN) in breach dumps")
        recs.append("Set up credit monitoring if financial data exposed")
        for i, rec in enumerate(recs[:3]):
            findings.append(make_finding(
                entity=f"Remediation {i+1}: {rec[:100]}", ftype="Breach: Remediation Step",
                source="BreachDirectory", confidence="Medium", color="orange",
                tags=["breach", "remediation"]))

    await asyncio.gather(
        check_ssl_cert(),
        check_http_redirects(),
        analyze_breach_remediation(),
    )

    if not findings:
        findings.append(make_finding(
            entity=f"No breach records for {t}",
            ftype="Breach: No Results",
            source="BreachDirectory",
            confidence="Low",
            color="emerald",
            status="Clean",
            tags=["breach", "clean"],
        ))

    return findings
