import asyncio, httpx, json, re, socket, hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from urllib.parse import urlparse
from models import IntelligenceFinding
from settings_store import get_api_key

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

async def safe_fetch(client: httpx.AsyncClient, url: str, timeout: float = 15.0, follow_redirects: bool = True, headers: Optional[Dict] = None, params: Optional[Dict] = None, method: str = "GET", data: Optional[Any] = None, content: Optional[bytes] = None) -> Optional[httpx.Response]:
    try:
        hdrs = {**{"User-Agent": UA}, **(headers or {})}
        if method == "GET":
            resp = await client.get(url, timeout=timeout, follow_redirects=follow_redirects, headers=hdrs, params=params, data=data, content=content)
        elif method == "POST":
            resp = await client.post(url, timeout=timeout, follow_redirects=follow_redirects, headers=hdrs, data=data, content=content)
        else:
            resp = await client.get(url, timeout=timeout, follow_redirects=follow_redirects, headers=hdrs, params=params, data=data, content=content)
        return resp
    except (httpx.TimeoutException, httpx.ConnectError, httpx.TransportError, httpx.RemoteProtocolError):
        return None

async def safe_fetch_json(client: httpx.AsyncClient, url: str, timeout: float = 15.0, headers: Optional[Dict] = None, params: Optional[Dict] = None) -> Optional[Any]:
    resp = await safe_fetch(client, url, timeout=timeout, headers=headers, params=params)
    if resp and resp.status_code == 200 and resp.text:
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            pass
    return None

def make_finding(entity: str, ftype: str, source: str = "", confidence: str = "Medium", color: str = "blue", category: str = "General OSINT", threat_level: str = "Informational", status: str = "Discovered", resolution: str = "", raw_data: str = "", tags: Optional[List[str]] = None) -> IntelligenceFinding:
    return IntelligenceFinding(
        entity=entity, type=ftype, source=source, confidence=confidence, color=color, category=category,
        threat_level=threat_level, status=status, resolution=resolution, raw_data=raw_data, tags=tags or []
    )

def is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target.strip())
        return True
    except OSError:
        return False

def resolve_ip(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None

def classify_email(email: str) -> str:
    local = email.split("@")[0].lower()
    disposable_domains = {"tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com", "throwaway.email", "trashmail.com"}
    dom = email.split("@")[-1].lower() if "@" in email else ""
    if dom in disposable_domains:
        return "disposable"
    common_roles = {"info", "contact", "support", "sales", "admin", "help", "hello", "careers", "jobs",
                    "hr", "billing", "accounts", "finance", "marketing", "pr", "press", "media",
                    "partners", "business", "enquiries", "mail", "office", "team", "webmaster",
                    "postmaster", "hostmaster", "abuse", "noreply", "feedback", "newsletter",
                    "social", "community", "legal", "privacy", "security", "engineering",
                    "tech", "it", "devops", "system", "network", "recruitment", "compliance"}
    if local in common_roles:
        return "role-based"
    if re.match(r"^[a-z]+\.[a-z]+$", local):
        return "personal (first.last)"
    return "personal"

def extract_emails(text: str, domain_filter: str = "") -> List[str]:
    emails = set()
    for m in EMAIL_RE.finditer(text):
        e = m.group(0).lower()
        if domain_filter and not e.endswith(domain_filter.lower()):
            continue
        emails.add(e)
    return list(emails)

def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:16]
