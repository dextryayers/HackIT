import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

PASTE_SITES = [
    ("Pastebin", "https://pastebin.com/search?q={}"),
    ("Ghostbin", "https://ghostbin.com/search?q={}"),
    ("Rentry", "https://rentry.org/search?q={}"),
    ("DPaste", "https://dpaste.org/search?q={}"),
    ("Hastebin", "https://hastebin.skyra.pw/search?q={}"),
    ("Paste.ee", "https://paste.ee/search?q={}"),
    ("Paste.fo", "https://paste.fo/search?q={}"),
    ("Paste.kde.org", "https://paste.kde.org/search?q={}"),
    ("Paste.md", "https://paste.md/search?q={}"),
    ("Paste.rs", "https://paste.rs/search?q={}"),
    ("Ideone", "https://ideone.com/search?q={}"),
    ("Codepad", "https://codepad.co/search?q={}"),
    ("JSFiddle", "https://jsfiddle.net/search?q={}"),
    ("JSBin", "https://jsbin.com/?search={}"),
    ("Repl.it", "https://repl.it/search?q={}"),
    ("CodeShare", "https://codeshare.io/search?q={}"),
    ("Snippets.org", "https://snippets.org/search.php?q={}"),
    ("ControlC", "https://controlc.com/search.php?q={}"),
    ("Paste.centos", "https://paste.centos.org/search?q={}"),
    ("Paste.fedoraproject", "https://paste.fedoraproject.org/search?q={}"),
    ("Paste.debian", "https://paste.debian.net/search?q={}"),
    ("Paste.ubuntu", "https://paste.ubuntu.com/search?q={}"),
    ("Slexy", "https://slexy.org/search?q={}"),
    ("BitBin", "https://bitbin.it/search?q={}"),
    ("Clippin", "https://clippin.io/search?q={}"),
    ("IVPaste", "https://ivpaste.com/search?q={}"),
    ("Dumpz", "https://dumpz.org/search?q={}"),
    ("PasteBucket", "https://pastebucket.com/search?q={}"),
    ("PasteCode", "https://pastecode.io/s/search?q={}"),
    ("Paste2", "https://paste2.org/search?q={}"),
    ("PasteFR", "https://pastefr.com/search?q={}"),
    ("PasteCat", "https://pastecat.com/search?q={}"),
    ("PasteZone", "https://pastezone.com/search?q={}"),
    ("Pastie", "https://pastie.org/search?q={}"),
    ("Rentry Raw", "https://rentry.org/{}/raw"),
    ("GitHub Gist", "https://gist.github.com/search?q={}"),
    ("GitLab Snippet", "https://gitlab.com/search?search={}"),
    ("Bitbucket Snippet", "https://bitbucket.org/search?q={}"),
    ("Fedora Paste", "https://paste.fedoraproject.org/search?q={}"),
    ("Mageia Paste", "https://paste.mageia.org/search?q={}"),
    ("OpenSUSE Paste", "https://paste.opensuse.org/search?q={}"),
    ("Toptal Paste", "https://paste.toptal.com/search?q={}"),
    ("CatBin", "https://catbin.io/search?q={}"),
    ("SnipBin", "https://snipbin.com/search?q={}"),
    ("Krosk", "https://krosk.com/search?q={}"),
    ("PrivNote", "https://privnote.com/search?q={}"),
    ("SafeNote", "https://safenote.co/search?q={}"),
    ("CentOS Paste", "https://paste.centos.org/search?q={}"),
    ("Debian Paste", "https://paste.debian.net/search?q={}"),
    ("Ubuntu Paste", "https://paste.ubuntu.com/search?q={}"),
    ("KDE Paste", "https://paste.kde.org/search?q={}"),
    ("DGLog", "https://dglocker.de/search?q={}"),
]

CREDENTIAL_PATTERN = re.compile(r'(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(?P<password>\S+)')
API_KEY_PATTERN = re.compile(r'(?:sk_live|sk_test|pk_live|pk_test)_[0-9a-zA-Z]{24,}|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|xox[baprs]-[0-9a-zA-Z\-]{24,}|AIza[0-9A-Za-z\-_]{35}|-----BEGIN\s?(RSA\s)?PRIVATE KEY-----')
TOKEN_PATTERN = re.compile(r'(?:token|bearer|jwt|secret|apikey|api_key)\s*[:=]\s*["\']?([A-Za-z0-9\-_.]{16,})["\']?', re.IGNORECASE)
URL_PATTERN = re.compile(r'https?://[^\s\'\"<>]+')
EMAIL_PATTERN = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PASSWORD_PATTERN = re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s\'\"<>]+)["\']?', re.IGNORECASE)
CONFIG_PATTERN = re.compile(r'(?:DB_|DATABASE_|AWS_|AZURE_|GCP_|STRIPE_|TWILIO_)')

SEVERITY_KEYWORDS = {
    "critical": ["password", "secret", "private key", "credential", "token", "apikey", "aws_secret"],
    "high": ["ssh", "database", "connection string", "jwt", "bearer", "oauth"],
    "medium": ["email", "username", "api", "endpoint", "internal", "config"],
    "low": ["example", "test", "sample", "debug"],
}

async def search_paste_site(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await client.get(url, timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200 and len(resp.text) > 100:
            text = resp.text.lower()
            mentions = text.count(target.lower())
            return {"name": name, "url": url, "status": resp.status_code, "mentions": mentions, "text": resp.text}
    except:
        pass
    return None

async def classify_content_severity(text: str) -> str:
    text_lower = text.lower()
    for level, keywords in SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                return level
    return "low"

async def extract_findings_from_text(text: str, source: str, target: str) -> list:
    findings = []
    creds = CREDENTIAL_PATTERN.findall(text)
    for email, password in creds:
        findings.append({
            "type": "Credential Pair",
            "data": f"{email}:{password}",
            "severity": "critical",
        })

    api_keys = API_KEY_PATTERN.findall(text)
    for key in api_keys:
        findings.append({
            "type": "API Key",
            "data": key[:30] + "...",
            "severity": "critical",
        })

    tokens = TOKEN_PATTERN.findall(text)
    for token in tokens:
        findings.append({
            "type": "Token/Secret",
            "data": token[:30] + "...",
            "severity": "critical",
        })

    passwords = PASSWORD_PATTERN.findall(text)
    for pwd in passwords:
        findings.append({
            "type": "Password",
            "data": pwd[:20] + "...",
            "severity": "critical",
        })

    emails = EMAIL_PATTERN.findall(text)
    unique_emails = set(emails) - {target}
    for email in list(unique_emails)[:5]:
        findings.append({
            "type": "Email Address",
            "data": email,
            "severity": "high",
        })

    ips = IP_PATTERN.findall(text)
    private_ips = [ip for ip in ips if ip.startswith(("10.", "172.16.", "192.168."))]
    for ip in set(private_ips):
        findings.append({
            "type": "Internal IP",
            "data": ip,
            "severity": "high",
        })

    urls = URL_PATTERN.findall(text)
    for url in urls[:5]:
        if target in url:
            findings.append({
                "type": "Referenced URL",
                "data": url,
                "severity": "medium",
            })

    configs = CONFIG_PATTERN.findall(text)
    for cfg in configs:
        findings.append({
            "type": "Config Variable",
            "data": cfg,
            "severity": "high",
        })

    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_found_data = []
    sites_with_data = 0

    for name, url_template in PASTE_SITES:
        result = await search_paste_site(name, url_template, t, client)
        if result:
            all_found_data.append(result)
            sites_with_data += 1
            findings.append(IntelligenceFinding(
                entity=f"Paste site {name} returned results for {t}",
                type="Paste: Site Mention",
                source="PasteSitesScanner",
                confidence="Medium",
                color="sky",
                category="Paste Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["paste", name.lower().replace(" ", "-"), "mention"],
            ))

            extracted = await extract_findings_from_text(result["text"], name, t)
            for ext in extracted[:5]:
                severity = ext["severity"]
                findings.append(IntelligenceFinding(
                    entity=f"{ext['type']}: {ext['data'][:100]}",
                    type=f"Paste: {ext['type']}",
                    source="PasteSitesScanner",
                    confidence="High" if severity == "critical" else "Medium",
                    color="red" if severity == "critical" else "orange" if severity == "high" else "yellow",
                    category="Paste Intelligence",
                    threat_level="Critical" if severity == "critical" else "High Risk" if severity == "high" else "Medium Risk" if severity == "medium" else "Informational",
                    status="Exposed",
                    resolution=t,
                    tags=["paste", ext['type'].lower().replace(" ", "-"), severity],
                ))

    combined_text = " ".join(r["text"] for r in all_found_data)

    all_creds = CREDENTIAL_PATTERN.findall(combined_text)
    if all_creds:
        findings.append(IntelligenceFinding(
            entity=f"{len(all_creds)} credential pairs found across paste sites",
            type="Paste: Credential Summary",
            source="PasteSitesScanner",
            confidence="High",
            color="red",
            category="Paste Intelligence",
            threat_level="Critical",
            status="Credentials Exposed",
            resolution=t,
            tags=["paste", "credentials", "exposed"],
        ))

    all_keys = API_KEY_PATTERN.findall(combined_text)
    if all_keys:
        findings.append(IntelligenceFinding(
            entity=f"{len(all_keys)} API keys/tokens exposed in paste sites",
            type="Paste: API Key Summary",
            source="PasteSitesScanner",
            confidence="High",
            color="red",
            category="Paste Intelligence",
            threat_level="Critical",
            status="Keys Exposed",
            resolution=t,
            tags=["paste", "api-keys", "exposed"],
        ))

    all_emails = EMAIL_PATTERN.findall(combined_text)
    unique_emails = set(all_emails) - {t}
    if unique_emails:
        findings.append(IntelligenceFinding(
            entity=f"{len(unique_emails)} unique emails exposed: {', '.join(list(unique_emails)[:5])}",
            type="Paste: Email Exposure",
            source="PasteSitesScanner",
            confidence="Medium",
            color="orange",
            category="Paste Intelligence",
            threat_level="High Risk",
            status="Emails Exposed",
            resolution=t,
            tags=["paste", "emails", "exposure"],
        ))

    private_ips = [ip for ip in IP_PATTERN.findall(combined_text) if ip.startswith(("10.", "172.16.", "192.168."))]
    if private_ips:
        findings.append(IntelligenceFinding(
            entity=f"{len(set(private_ips))} internal IPs exposed on paste sites",
            type="Paste: Internal IP Leak",
            source="PasteSitesScanner",
            confidence="High",
            color="red",
            category="Paste Intelligence",
            threat_level="Critical",
            status="Exposed",
            resolution=t,
            tags=["paste", "internal-ip", "leak"],
        ))

    if not all_found_data:
        findings.append(IntelligenceFinding(
            entity="No paste site mentions found for target",
            type="Paste: Scan Complete",
            source="PasteSitesScanner",
            confidence="Low",
            color="emerald",
            category="Paste Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["paste", "clean"],
        ))

    findings.append(IntelligenceFinding(
        entity=f"Paste scan complete: {sites_with_data}/{len(PASTE_SITES)} sites had data",
        type="Paste: Coverage Summary",
        source="PasteSitesScanner",
        confidence="Medium",
        color="slate",
        category="Paste Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["paste", "coverage", "summary"],
    ))

    return findings
