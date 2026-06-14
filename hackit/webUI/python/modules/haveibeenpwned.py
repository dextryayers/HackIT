import httpx
import hashlib
import re
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

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    emails_found = []

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

    return findings
