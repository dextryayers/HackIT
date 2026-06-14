import httpx
import re
import hashlib
from datetime import datetime, timezone
from models import IntelligenceFinding

PASTE_SITES = [
    {
        "name": "Pastebin",
        "search_url": "https://pastebin.com/search?q={target}",
        "raw_pattern": r'/raw/([a-zA-Z0-9]{8})',
        "content_url": "https://pastebin.com/raw/{pid}",
    },
    {
        "name": "Ghostbin",
        "search_url": "https://ghostbin.com/search?q={target}",
        "raw_pattern": r'/paste/([a-zA-Z0-9]+)',
        "content_url": "https://ghostbin.com/paste/{pid}/raw",
    },
    {
        "name": "dpaste",
        "search_url": "https://dpaste.org/search?q={target}",
        "raw_pattern": r'/dpaste/([a-zA-Z0-9]+)',
        "content_url": "https://dpaste.org/{pid}/raw",
    },
    {
        "name": "Paste.ee",
        "search_url": "https://paste.ee/search?q={target}",
        "raw_pattern": r'/paste\.ee/p/([a-zA-Z0-9]+)',
        "content_url": "https://paste.ee/r/{pid}",
    },
]

SENSITIVE_PATTERNS = [
    (r'-----BEGIN\s*(RSA\s*)?PRIVATE\s*KEY-----', 'Private Key', 'Critical'),
    (r'-----BEGIN\s*CERTIFICATE-----', 'Certificate', 'Medium'),
    (r'[\'\"](?:API[_-]?KEY|api[_-]?key|apikey)[\'\"].*[\'\"][A-Za-z0-9_\-]{16,}[\'"]', 'API Key Leak', 'High'),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', 'GitHub Token', 'Critical'),
    (r'(?:xox[abrps]?|xapp|xoxb)-[A-Za-z0-9\-]{40,}', 'Slack Token', 'Critical'),
    (r'sk_live_[0-9a-z]{32}', 'Stripe Live Key', 'Critical'),
    (r'pk_live_[0-9a-z]{32}', 'Stripe Live Publishable', 'High'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'Critical'),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'\"]?\S{8,}[\'\"]?', 'Password Leak', 'Critical'),
    (r'(?i)(?:secret|token)\s*[=:]\s*[\'\"]?\S{8,}[\'\"]?', 'Secret Token', 'High'),
    (r'[\'\"](?:username|user|login)[\'\"].*[\'\"][A-Za-z0-9_@.\-]{4,}[\'"]', 'Credential Pair', 'High'),
    (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'Credit Card Number', 'Critical'),
    (r'\b(?:mongodb|postgresql|mysql|redis)://\S+:\S+@\S+\b', 'Database Connection String', 'Critical'),
    (r'(?i)Authorization:\s*Bearer\s+\S+', 'Bearer Token', 'Critical'),
    (r'(?i)connection.?string.*[=:].*', 'Connection String', 'High'),
    (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP Address', 'Low'),
    (r'(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', 'Email Address', 'Low'),
]

CATEGORY_KEYWORDS = {
    "Credential Leak": ["password", "login", "credentials", "username", "admin", "root", "hash"],
    "Configuration": ["config", "settings", "json", ".env", "database", "connection", "endpoint"],
    "Source Code": ["function", "class", "import", "def ", "var ", "int ", "void "],
    "Personal Data": ["ssn", "address", "phone", "dob", "birthday", "social security", "passport"],
    "Malware/IOC": ["malware", "trojan", "ransomware", "exploit", "c2 ", "botnet", "shellcode", "payload"],
    "Network Info": ["netstat", "ifconfig", "ip route", "traceroute", "dns ", "hostname"],
    "API Documentation": ["endpoint", "api/v", "/v1/", "/v2/", "rest api", "swagger"],
}

async def _fetch_paste_ids(target: str, site: dict, client: httpx.AsyncClient):
    results = []
    try:
        search_url = site["search_url"].format(target=target)
        search_resp = await client.get(search_url, timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if search_resp.status_code != 200:
            return results
        pids = set(re.findall(site["raw_pattern"], search_resp.text))
        for pid in pids:
            content_url = site["content_url"].format(pid=pid)
            results.append((site["name"], pid, content_url))
    except Exception:
        pass
    return results

async def _fetch_paste_content(content_url: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await client.get(content_url, timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            return resp.text[:50000]
    except Exception:
        pass
    return ""

def _score_sensitivity(matches: list) -> str:
    levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_score = 0
    for _, _, severity in matches:
        s = levels.get(severity, 0)
        if s > max_score:
            max_score = s
    if max_score >= 4:
        return "Critical"
    if max_score >= 3:
        return "High"
    if max_score >= 2:
        return "Medium"
    return "Low"

def _categorize_content(text: str) -> list:
    categories = []
    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in text.lower():
                categories.append(cat)
                break
    return categories if categories else ["Unknown"]

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    seen_hashes = set()
    seen_pids = set()

    for site in PASTE_SITES:
        entries = await _fetch_paste_ids(domain, site, client)
        for site_name, pid, content_url in entries:
            if pid in seen_pids:
                continue
            seen_pids.add(pid)
            content = await _fetch_paste_content(content_url, client)
            if not content:
                findings.append(IntelligenceFinding(
                    entity=f"{site_name} paste found: {content_url}",
                    type="Paste Hit",
                    source="PastebinMonitor",
                    confidence="Medium",
                    color="orange",
                    threat_level="Informational",
                    status="Unreviewed",
                    tags=["paste", site_name.lower(), domain.replace('.', '_')]
                ))
                continue

            content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)

            sensitive_matches = []
            for pattern, label, severity in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    match_text = matches[0][:80] if isinstance(matches[0], str) else str(matches[0])[:80]
                    sensitive_matches.append((match_text, label, severity))

            sensitivity = _score_sensitivity(sensitivity_matches)
            categories = _categorize_content(content)
            target_mentions = len(re.findall(re.escape(domain), content, re.IGNORECASE))

            color_map = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "slate"}
            threat_map = {"Critical": "Critical", "High": "High Risk", "Medium": "Elevated Risk", "Low": "Informational"}

            for cat in categories[:3]:
                cat_parts = cat.split("/")
                findings.append(IntelligenceFinding(
                    entity=f"{site_name} ({pid[:8]}...): Content categorized as {cat}",
                    type=f"Paste: {cat}",
                    source="PastebinMonitor",
                    confidence="High" if sensitivity in ("Critical", "High") else "Medium",
                    color=color_map.get(sensitivity, "slate"),
                    threat_level=threat_map.get(sensitivity, "Informational"),
                    status="Sensitive" if sensitivity in ("Critical", "High") else "Unreviewed",
                    resolution=content_url,
                    raw_data=f"Hash: {content_hash}, Sensitivity: {sensitivity}, Target mentions: {target_mentions}, Size: {len(content)} chars, Categories: {', '.join(categories)}",
                    tags=["paste", site_name.lower(), domain.replace('.', '_'), sensitivity.lower()]
                ))

            for match_text, label, severity in sensitive_matches[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"{label}: {match_text[:120]}",
                    type="Sensitive Data",
                    source="PastebinMonitor",
                    confidence="High",
                    color=color_map.get(severity, "orange"),
                    threat_level=threat_map.get(severity, "High Risk"),
                    status="Confirmed",
                    resolution=content_url,
                    raw_data=f"Pattern: {label}, Severity: {severity}, Match: {match_text[:300]}",
                    tags=["sensitive", label.lower().replace(' ', '_'), severity.lower(), "paste"]
                ))

            if target_mentions > 1:
                findings.append(IntelligenceFinding(
                    entity=f"Target mentioned {target_mentions}x in paste {pid[:8]}...",
                    type="Target Mention Count",
                    source="PastebinMonitor",
                    confidence="Medium",
                    color="slate",
                    threat_level="Elevated Risk" if target_mentions > 10 else "Informational",
                    status="Analyzed",
                    resolution=content_url,
                    raw_data=f"Target mentions in paste: {target_mentions}",
                    tags=["paste", "mention_count", domain.replace('.', '_')]
                ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No recent paste mentions found for {domain}",
            type="Paste Monitor Summary",
            source="PastebinMonitor",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            tags=["clean", domain.replace('.', '_')]
        ))
    else:
        sensitivity_levels = {}
        for f in findings:
            tl = f.threat_level or "Informational"
            sensitivity_levels[tl] = sensitivity_levels.get(tl, 0) + 1
        summary_parts = [f"{v} {k}" for k, v in sorted(sensitivity_levels.items())]
        findings.append(IntelligenceFinding(
            entity=f"Paste scan complete: {len(seen_pids)} unique pastes, {len(seen_hashes)} unique content blobs",
            type="Paste Monitor Summary",
            source="PastebinMonitor",
            confidence="High",
            color="red" if sensitivity_levels.get("Critical") or sensitivity_levels.get("High Risk") else "purple",
            threat_level="Informational",
            status="Complete",
            raw_data=" | ".join(summary_parts),
            tags=["summary", domain.replace('.', '_')]
        ))

    return findings
