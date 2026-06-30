import httpx
import hashlib
import re
from datetime import datetime, timezone, timedelta
from models import IntelligenceFinding

DATA_CLASS_SEVERITY = {
    "Email addresses": "Medium",
    "Passwords": "Critical",
    "Password hashes": "Critical",
    "Credit cards": "Critical",
    "Bank account numbers": "Critical",
    "Phone numbers": "High",
    "Physical addresses": "High",
    "IP addresses": "Medium",
    "Dates of birth": "High",
    "Names": "Medium",
    "Usernames": "Medium",
    "Social security numbers": "Critical",
    "Security questions and answers": "Critical",
    "Government issued IDs": "Critical",
    "Job titles": "Low",
    "Employer": "Low",
    "Gender": "Low",
    "Ethnicity": "Medium",
    "Religion": "Medium",
    "Geographic locations": "Medium",
    "Browser user agent details": "Low",
    "Browser history": "Medium",
    "Device information": "Low",
}

BREACH_SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}

DATA_CLASS_EXPOSURE_WEIGHTS = {
    "Passwords": 10,
    "Password hashes": 9,
    "Credit cards": 10,
    "Bank account numbers": 10,
    "Social security numbers": 10,
    "Government issued IDs": 9,
    "Security questions and answers": 9,
    "Phone numbers": 7,
    "Physical addresses": 6,
    "Dates of birth": 6,
    "Email addresses": 3,
    "Usernames": 2,
    "Names": 2,
    "IP addresses": 3,
    "Geographic locations": 3,
    "Browser history": 2,
    "Device information": 1,
    "Job titles": 1,
    "Employer": 1,
    "Gender": 1,
    "Ethnicity": 1,
    "Religion": 1,
    "Browser user agent details": 1,
}

BREACH_TYPE_CLASSIFICATION = {
    "credential": ["credential", "login", "password", "account", "breach", "leak", "dump", "combo", "collection"],
    "data_scrape": ["scrape", "scraped", "data scrape", "crawler", "harvest", "aggregat"],
    "ransomware": ["ransomware", "ransom", "locker", "encrypt"],
    "insider_threat": ["insider", "employee leak", "whistleblow", "internal"],
    "phishing": ["phish", "phishing", "spoof", "fake page"],
    "malware": ["malware", "stealer", "infosteal", "trojan", "rat", "redline", "vidar"],
    "data_exposure": ["misconfig", "unsecured", "open bucket", "elasticsearch", "mongodb", "exposed"],
    "sql_injection": ["sql injection", "sqli", "injection"],
}

HIBP_API = "https://haveibeenpwned.com/api/v3"
UA = "HackIT-OSINT/1.0"

def extract_emails(text: str) -> list:
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))

def score_breach_severity(breach: dict) -> tuple:
    pwn_count = breach.get("PwnCount", 0) or 0
    data_classes = breach.get("DataClasses", [])
    is_verified = breach.get("IsVerified", True)
    is_fabricated = breach.get("IsFabricated", False)
    is_sensitive = breach.get("IsSensitive", False)
    is_retired = breach.get("IsRetired", False)
    is_spam_list = breach.get("IsSpamList", False)
    base_score = 0
    max_class_sev = 0
    for dc in data_classes:
        sev = DATA_CLASS_SEVERITY.get(dc, "Low")
        w = BREACH_SEVERITY_WEIGHTS.get(sev, 1)
        base_score += w
        max_class_sev = max(max_class_sev, w)
    if pwn_count > 100000000:
        base_score += 10
    elif pwn_count > 10000000:
        base_score += 7
    elif pwn_count > 1000000:
        base_score += 5
    elif pwn_count > 100000:
        base_score += 3
    elif pwn_count > 10000:
        base_score += 1
    if is_verified:
        base_score += 3
    if is_sensitive:
        base_score += 4
    if is_fabricated:
        base_score -= 5
    if is_retired:
        base_score -= 2
    if is_spam_list:
        base_score = max(1, base_score - 3)
    if base_score >= 20:
        return "Critical", base_score
    elif base_score >= 12:
        return "High Risk", base_score
    elif base_score >= 6:
        return "Elevated Risk", base_score
    else:
        return "Informational", base_score

def categorize_data_classes(data_classes: list) -> dict:
    categories = {
        "credentials": {"keywords": ["password", "username", "email", "login"], "items": []},
        "financial": {"keywords": ["credit card", "bank", "financial", "cvv", "paypal"], "items": []},
        "personal_id": {"keywords": ["ssn", "social security", "government", "passport", "driver", "national"], "items": []},
        "contact": {"keywords": ["phone", "address", "email address", "location"], "items": []},
        "demographic": {"keywords": ["gender", "ethnicity", "religion", "age", "dob", "birth"], "items": []},
        "technical": {"keywords": ["browser", "device", "ip address", "user agent", "cookie"], "items": []},
    }
    categorized = {}
    for dc in data_classes:
        dcl = dc.lower()
        placed = False
        for cat, info in categories.items():
            if any(kw in dcl for kw in info["keywords"]):
                info["items"].append(dc)
                categorized.setdefault(cat, []).append(dc)
                placed = True
                break
        if not placed:
            categorized.setdefault("other", []).append(dc)
    return categorized

def classify_breach_type(name: str, description: str = "") -> str:
    text = (name + " " + description).lower()
    for btype, keywords in BREACH_TYPE_CLASSIFICATION.items():
        if any(kw in text for kw in keywords):
            return btype
    if any(w in text for w in ["leak", "breach", "dump"]):
        return "credential"
    return "unknown"

def compute_data_exposure_score(data_classes: list) -> dict:
    score = 0
    max_possible = 0
    details = []
    for dc in data_classes:
        w = DATA_CLASS_EXPOSURE_WEIGHTS.get(dc, 1)
        score += w
        details.append({"class": dc, "weight": w})
    if score >= 50:
        level = "Critical"
    elif score >= 30:
        level = "High"
    elif score >= 15:
        level = "Medium"
    else:
        level = "Low"
    return {"score": score, "level": level, "details": details}

def is_recent_breach(breach_date_str: str, months: int = 6) -> bool:
    if not breach_date_str:
        return False
    try:
        bd = datetime.strptime(breach_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(days=30 * months)
        return bd >= cutoff
    except (ValueError, TypeError):
        return False

def estimate_credential_stuffing_services(email: str, clear_password: bool) -> int:
    if not email or not clear_password:
        return 0
    popular_services = 50
    return popular_services

def check_password_reuse(email_passwords: dict) -> list:
    flags = []
    for email, passwords in email_passwords.items():
        unique_pws = set(p for p in passwords if p)
        if len(unique_pws) > 1:
            flags.append({"email": email, "unique_passwords": len(unique_pws), "passwords": list(unique_pws)[:3]})
    return flags

async def check_pwned_password(password: str, client: httpx.AsyncClient) -> dict:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = await client.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10.0,
            headers={"User-Agent": UA},
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(":")[1])
                    return {"pwned": True, "count": count, "hash": sha1}
    except Exception:
        pass
    return {"pwned": False, "count": 0, "hash": sha1}

async def query_snusbase(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        payload = {"search": domain, "type": "domain"}
        resp = await client.post(
            "https://snusbase.com/api/search/query",
            json=payload,
            headers={"User-Agent": UA, "Content-Type": "application/json", "Authorization": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

async def query_leakcheck(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"https://leakcheck.io/api/v2/domain/{domain}",
            headers={"User-Agent": UA, "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

async def query_scylla(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
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
    except Exception:
        pass
    return []

async def query_dehashed(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            "https://dehashed.com/api/v1/search",
            params={"query": f"domain:{domain}", "size": 30, "page": 1},
            headers={"User-Agent": UA, "Accept": "application/json", "Authorization": ""},
            timeout=15.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

async def query_firefox_monitor(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            "https://monitor.firefox.com/api/v1/breaches",
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
    except Exception:
        pass
    return []

async def query_hibp_pastes(email: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            timeout=15.0,
            headers={"User-Agent": UA, "hibp-api-key": "", "Accept": "application/json"},
        )
        if resp.status_code == 200 and isinstance(resp.json(), list):
            return resp.json()
    except Exception:
        pass
    return []

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    emails_found = []
    email_password_map = {}
    all_breach_entries = []
    total_clear_passwords = 0
    total_emails_with_passwords = 0

    try:
        resp = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            timeout=15.0,
            headers={
                "User-Agent": UA,
                "hibp-api-key": "",
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200 and resp.text.startswith("["):
            breaches = resp.json()
            severity_scores = []
            timeline_events = []
            data_class_count = {}
            all_data_classes = []
            recent_breaches = []
            breach_type_counts = {}

            for breach in breaches:
                if not isinstance(breach, dict):
                    continue
                name = breach.get("Name", "")
                breach_domain = breach.get("Domain", "")
                date = breach.get("BreachDate", "")
                pwn_count = breach.get("PwnCount", 0) or 0
                data_classes = breach.get("DataClasses", [])
                description = breach.get("Description", breach.get("description", ""))
                logo_type = breach.get("LogoType", "")
                added_date = breach.get("AddedDate", "")
                modified_date = breach.get("ModifiedDate", "")
                is_verified = breach.get("IsVerified", True)
                is_sensitive = breach.get("IsSensitive", False)

                severity, score = score_breach_severity(breach)
                sev_color = "red" if severity in ("Critical", "High Risk") else ("orange" if severity == "Elevated Risk" else "emerald")
                severity_scores.append(score)

                if date:
                    timeline_events.append({"date": date, "name": name, "severity": severity})

                cat_data = categorize_data_classes(data_classes)
                for cat, items in cat_data.items():
                    data_class_count[cat] = data_class_count.get(cat, 0) + len(items)

                all_data_classes.extend(data_classes)

                breach_type = classify_breach_type(name, description)
                breach_type_counts[breach_type] = breach_type_counts.get(breach_type, 0) + 1

                if is_recent_breach(date):
                    recent_breaches.append({"name": name, "date": date, "severity": severity})

                entity_parts = [name]
                if date:
                    entity_parts.append(f"({date})")
                entity_parts.append(f"- {pwn_count:,} accounts")
                entity_str = " ".join(entity_parts)

                raw = f"Domain: {breach_domain}"
                if description:
                    raw += f" | Description: {description[:300]}"
                if data_classes:
                    raw += f" | Data Classes: {', '.join(data_classes)}"
                if added_date:
                    raw += f" | Added: {added_date}"
                if modified_date:
                    raw += f" | Modified: {modified_date}"

                tags = ["breach"]
                if is_verified:
                    tags.append("verified")
                if is_sensitive:
                    tags.append("sensitive")
                if data_classes:
                    tags.extend([dc.lower().replace(" ", "-") for dc in data_classes[:5]])
                tags.append(f"type-{breach_type}")

                findings.append(IntelligenceFinding(
                    entity=entity_str[:200],
                    type="Breach: Account Leak",
                    source="HaveIBeenPwned",
                    confidence="High",
                    color=sev_color,
                    threat_level=severity,
                    status="Confirmed" if is_verified else "Unverified",
                    raw_data=raw[:1000],
                    tags=tags,
                ))

                if logo_type:
                    findings.append(IntelligenceFinding(
                        entity=f"{name} logo type: {logo_type}",
                        type="Breach: Branding",
                        source="HaveIBeenPwned",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"LogoType: {logo_type}",
                    ))

                for dc in data_classes:
                    sev = DATA_CLASS_SEVERITY.get(dc, "Low")
                    dc_color = "red" if sev == "Critical" else ("orange" if sev in ("High", "Medium") else "slate")
                    findings.append(IntelligenceFinding(
                        entity=f"{name}: {dc}",
                        type=f"Data Class: {sev}",
                        source="HaveIBeenPwned",
                        confidence="High",
                        color=dc_color,
                        threat_level=sev if sev in ("Critical", "High") else "Informational",
                        raw_data=f"Breach: {name} | Data Class: {dc} | Severity: {sev}",
                        tags=["data-class", dc.lower().replace(" ", "-")],
                    ))

            if severity_scores:
                avg_score = sum(severity_scores) / len(severity_scores)
                overall_sev = "Critical" if avg_score >= 20 else ("High Risk" if avg_score >= 12 else ("Elevated Risk" if avg_score >= 6 else "Informational"))
                findings.append(IntelligenceFinding(
                    entity=f"{len(breaches)} known breaches (avg severity: {avg_score:.1f}) for {domain}",
                    type="HIBP Summary",
                    source="HaveIBeenPwned",
                    confidence="High",
                    color="red" if overall_sev in ("Critical", "High Risk") else "orange",
                    threat_level=overall_sev,
                    status="Analyzed",
                    raw_data=f"Total breaches: {len(breaches)}, Average severity score: {avg_score:.1f}, Data class distribution: {data_class_count}",
                    tags=["breach-summary"],
                ))

            if timeline_events:
                timeline_events.sort(key=lambda x: x["date"])
                for ev in timeline_events:
                    findings.append(IntelligenceFinding(
                        entity=f"{ev['date']}: {ev['name']} ({ev['severity']})",
                        type="Breach Timeline",
                        source="HaveIBeenPwned",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"{ev['date']} - {ev['name']} - Severity: {ev['severity']}",
                        tags=["timeline"],
                    ))

            for cat, count in sorted(data_class_count.items()):
                findings.append(IntelligenceFinding(
                    entity=f"{cat}: {count} occurrences across breaches",
                    type="Data Class Category",
                    source="HaveIBeenPwned",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Category: {cat}, Count: {count}",
                    tags=[f"category-{cat}"],
                ))

            if all_data_classes:
                exposure = compute_data_exposure_score(all_data_classes)
                exp_color = "red" if exposure["level"] in ("Critical", "High") else ("orange" if exposure["level"] == "Medium" else "slate")
                findings.append(IntelligenceFinding(
                    entity=f"Data Exposure Score: {exposure['score']} ({exposure['level']})",
                    type="Data Exposure Aggregation",
                    source="HaveIBeenPwned",
                    confidence="Medium",
                    color=exp_color,
                    threat_level=f"{exposure['level']} Risk",
                    status="Analyzed",
                    raw_data=f"Score: {exposure['score']} | Level: {exposure['level']} | Classes: {', '.join(all_data_classes)}",
                    tags=["data-exposure", exposure['level'].lower()],
                ))

            if recent_breaches:
                for rb in recent_breaches:
                    findings.append(IntelligenceFinding(
                        entity=f"Recent breach: {rb['name']} ({rb['date']}) - {rb['severity']}",
                        type="Breach Recency Alert",
                        source="HaveIBeenPwned",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Recent",
                        raw_data=f"Breach occurred within last 6 months - {rb['name']} on {rb['date']}",
                        tags=["recent-breach", "urgency"],
                    ))

            if breach_type_counts:
                type_summary = " | ".join(f"{bt}: {cnt}" for bt, cnt in sorted(breach_type_counts.items()))
                findings.append(IntelligenceFinding(
                    entity=f"Breach Type Classification: {type_summary}",
                    type="Breach Type Summary",
                    source="HaveIBeenPwned",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Analyzed",
                    raw_data=f"Types: {breach_type_counts}",
                    tags=["breach-type-classification"],
                ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"HIBP breach error: {str(e)[:100]}",
            type="HIBP Error",
            source="HaveIBeenPwned",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"],
        ))

    try:
        resp2 = await client.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            timeout=10.0,
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
        if resp2.status_code == 200 and resp2.text.startswith("["):
            all_breaches = resp2.json()
            breach_names = [b.get("Name", "") for b in all_breaches if isinstance(b, dict)]
            if breach_names:
                findings.append(IntelligenceFinding(
                    entity=f"Affected by: {', '.join(breach_names[:10])}",
                    type="Breach: Affected Services",
                    source="HaveIBeenPwned",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"All breach names: {breach_names}",
                    tags=["affected-services"],
                ))
    except Exception:
        pass

    try:
        from urllib.parse import urlparse, quote
        resp3 = await client.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            timeout=10.0,
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
        if resp3.status_code == 200:
            data3 = resp3.json()
            if isinstance(data3, list):
                for item in data3[:10]:
                    if isinstance(item, dict):
                        findings.append(IntelligenceFinding(
                            entity=item.get("Name", ""),
                            type="Breach: Domain Breach",
                            source="HaveIBeenPwned",
                            confidence="Medium",
                            color="orange",
                            threat_level="Elevated Risk",
                            raw_data=str(item)[:500],
                            tags=["domain-breach"],
                        ))
    except Exception:
        pass

    if emails_found:
        sample_email = emails_found[0]
        try:
            pastes = await query_hibp_pastes(sample_email, client)
            if pastes:
                findings.append(IntelligenceFinding(
                    entity=f"{len(pastes)} paste(s) found for {sample_email}",
                    type="HIBP Paste Search",
                    source="HaveIBeenPwned",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"Sample email: {sample_email} | Paste count: {len(pastes)}",
                    tags=["paste", "hibp-paste"],
                ))
                for paste in pastes[:5]:
                    paste_title = paste.get("Title", paste.get("Source", "Unknown"))
                    paste_date = paste.get("Date", "")
                    paste_source = paste.get("Source", "")
                    findings.append(IntelligenceFinding(
                        entity=f"Paste: {paste_title} ({paste_date})",
                        type="HIBP Paste Entry",
                        source="HaveIBeenPwned",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        raw_data=f"Title: {paste_title} | Source: {paste_source} | Date: {paste_date}",
                        tags=["paste", paste_source.lower() if paste_source else "paste"],
                    ))
        except Exception:
            pass

    try:
        snusbase_data = await query_snusbase(domain, client)
        if snusbase_data:
            sb_results = snusbase_data.get("results", snusbase_data.get("data", snusbase_data.get("records", [])))
            if sb_results:
                sb_count = len(sb_results) if isinstance(sb_results, list) else (snusbase_data.get("count", 0) or len(sb_results))
                findings.append(IntelligenceFinding(
                    entity=f"{sb_count} record(s) from SnusBase for {domain}",
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
                        sb_source = (sb_entry.get("source") or sb_entry.get("breach", "SnusBase")).strip()
                        if sb_email:
                            emails_found.append(sb_email)
                            if sb_pass:
                                total_clear_passwords += 1
                                total_emails_with_passwords += 1
                                email_password_map.setdefault(sb_email, []).append(sb_pass)
                                all_breach_entries.append({"source": sb_source, "email": sb_email, "password": True})
                            findings.append(IntelligenceFinding(
                                entity=sb_email,
                                type="Breach: Leaked Email",
                                source="SnusBase",
                                confidence="Medium",
                                color="red",
                                threat_level="High Risk",
                                status="Confirmed",
                                resolution=f"via {sb_source}" if sb_source else None,
                                tags=["breach", "email", "snusbase"],
                            ))
    except Exception:
        pass

    try:
        leakcheck_data = await query_leakcheck(domain, client)
        if leakcheck_data and leakcheck_data.get("success"):
            lc_count = leakcheck_data.get("count", 0)
            if lc_count:
                findings.append(IntelligenceFinding(
                    entity=f"{lc_count} leaked credential(s) from LeakCheck for {domain}",
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
                    if lc_email:
                        emails_found.append(lc_email)
                        if lc_pass:
                            total_clear_passwords += 1
                            total_emails_with_passwords += 1
                            email_password_map.setdefault(lc_email, []).append(lc_pass)
                            all_breach_entries.append({"source": lc_source, "email": lc_email, "password": True})
                        findings.append(IntelligenceFinding(
                            entity=lc_email,
                            type="Breach: Leaked Email",
                            source="LeakCheck",
                            confidence="Medium",
                            color="red",
                            threat_level="High Risk",
                            status="Confirmed",
                            resolution=f"via {lc_source}" if lc_source else None,
                            tags=["breach", "email", "leakcheck"],
                        ))
    except Exception:
        pass

    try:
        scylla_data = await query_scylla(domain, client)
        if scylla_data:
            scylla_count = len(scylla_data)
            findings.append(IntelligenceFinding(
                entity=f"{scylla_count} record(s) from Scylla.so for {domain}",
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
                sc_source = (scylla_entry.get("source") or scylla_entry.get("breach", "Scylla")).strip()
                if sc_email:
                    emails_found.append(sc_email)
                    if sc_pass:
                        total_clear_passwords += 1
                        total_emails_with_passwords += 1
                        email_password_map.setdefault(sc_email, []).append(sc_pass)
                        all_breach_entries.append({"source": sc_source, "email": sc_email, "password": True})
                    findings.append(IntelligenceFinding(
                        entity=sc_email,
                        type="Breach: Leaked Email",
                        source="Scylla.so",
                        confidence="Medium",
                        color="red",
                        threat_level="Critical Risk",
                        status="Confirmed",
                        resolution=f"via {sc_source}" if sc_source else None,
                        tags=["breach", "email", "scylla"],
                    ))
    except Exception:
        pass

    try:
        dehashed_data = await query_dehashed(domain, client)
        if dehashed_data:
            dehashed_entries = dehashed_data.get("entries", dehashed_data.get("data", []))
            if dehashed_entries:
                findings.append(IntelligenceFinding(
                    entity=f"{len(dehashed_entries)} record(s) from Dehashed for {domain}",
                    type="Breach: Dehashed",
                    source="Dehashed",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Confirmed",
                    tags=["breach", "dehashed"],
                ))
                for entry in dehashed_entries[:20]:
                    dh_email = (entry.get("email") or "").strip().lower()
                    dh_pass = (entry.get("password") or "").strip()
                    dh_breach = (entry.get("breach") or entry.get("database_name", "Dehashed")).strip()
                    if dh_email:
                        emails_found.append(dh_email)
                        if dh_pass:
                            total_clear_passwords += 1
                            total_emails_with_passwords += 1
                            email_password_map.setdefault(dh_email, []).append(dh_pass)
                            all_breach_entries.append({"source": dh_breach, "email": dh_email, "password": True})
                        findings.append(IntelligenceFinding(
                            entity=dh_email,
                            type="Breach: Leaked Email",
                            source="Dehashed",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Confirmed",
                            resolution=f"via {dh_breach}" if dh_breach else None,
                            tags=["breach", "email", "dehashed"],
                        ))
    except Exception:
        pass

    try:
        ff_breaches = await query_firefox_monitor(domain, client)
        if ff_breaches:
            findings.append(IntelligenceFinding(
                entity=f"{len(ff_breaches)} breach(es) from Firefox Monitor for {domain}",
                type="Breach: Firefox Monitor",
                source="Firefox Monitor",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Confirmed",
                tags=["breach", "firefox-monitor"],
            ))
            for br in ff_breaches[:5]:
                br_name = br.get("Name", "")
                br_date = br.get("Date", br.get("BreachDate", ""))
                findings.append(IntelligenceFinding(
                    entity=f"{br_name} ({br_date})",
                    type="Breach: Firefox Monitor Entry",
                    source="Firefox Monitor",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Confirmed",
                    tags=["breach", "firefox-monitor"],
                ))
    except Exception:
        pass

    if total_emails_with_passwords > 0:
        stuffing_risk_services = total_emails_with_passwords * 50
        findings.append(IntelligenceFinding(
            entity=f"Credential stuffing risk: {total_emails_with_passwords} email(s) with plain-text passwords could compromise up to ~{stuffing_risk_services} services",
            type="Credential Stuffing Risk Assessment",
            source="HackIT Analysis",
            confidence="Medium",
            color="red",
            threat_level="Critical Risk",
            status="Analyzed",
            raw_data=f"Emails with passwords: {total_emails_with_passwords} | Estimated services at risk: ~{stuffing_risk_services}",
            tags=["credential-stuffing", "risk-assessment"],
        ))

    if email_password_map:
        reuse_flags = check_password_reuse(email_password_map)
        if reuse_flags:
            for flag in reuse_flags:
                findings.append(IntelligenceFinding(
                    entity=f"Password reuse detected for {flag['email']}: {flag['unique_passwords']} unique passwords across breaches",
                    type="Password Reuse Analysis",
                    source="HackIT Analysis",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Confirmed",
                    raw_data=f"Email: {flag['email']} | Unique passwords: {flag['unique_passwords']} | Samples: {', '.join(flag['passwords'][:3])}",
                    tags=["password-reuse", "cross-breach"],
                ))

    if all_breach_entries:
        source_mapping = {}
        for entry in all_breach_entries:
            source_mapping.setdefault(entry["email"], set()).add(entry["source"])
        multi_source_emails = {e: s for e, s in source_mapping.items() if len(s) > 1}
        if multi_source_emails:
            findings.append(IntelligenceFinding(
                entity=f"{len(multi_source_emails)} email(s) appear in multiple breach sources",
                type="Cross-Source Breach Correlation",
                source="HackIT Analysis",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Analyzed",
                raw_data=f"Emails in multiple sources: {list(multi_source_emails.keys())[:5]}",
                tags=["cross-source", "correlation"],
            ))

    if total_emails_with_passwords > 0 or len(emails_found) > 0:
        pw_exposure_pct = round((total_emails_with_passwords / max(len(emails_found), 1)) * 100)
        findings.append(IntelligenceFinding(
            entity=f"Exposure Summary: {len(emails_found)} emails, {total_clear_passwords} passwords, {len(all_breach_entries)} total records",
            type="Comprehensive Breach Exposure Summary",
            source="HaveIBeenPwned",
            confidence="High",
            color="red" if total_emails_with_passwords > 0 else "orange",
            threat_level="Critical Risk" if total_emails_with_passwords > 0 else "Elevated Risk",
            status="Analyzed",
            raw_data=f"Total emails: {len(emails_found)} | Clear passwords: {total_clear_passwords} ({pw_exposure_pct}% of emails) | Breach records: {len(all_breach_entries)} | Password reuse cases: {len(email_password_map)}",
            tags=["breach", "summary", "comprehensive"]
        ))

    return findings
