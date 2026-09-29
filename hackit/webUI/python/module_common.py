"""Shared helpers for the HackIT webUI OSINT module library.

This module is imported by every module in ``modules/`` in two different
styles (``from module_common import ...`` and
``from ..module_common import ...``). Both styles resolve here through
``module_loader``, so keep the public surface backwards compatible.

Design goals
------------
1. Compatibility: accept every keyword the 200+ modules use, including the
   ``type`` / ``ftype`` split, so no module has to be patched.
2. Performance: one shared request budget, response caching inside a scan,
   and automatic category and color inference so findings stay specific.
3. Safety: empty or oversized findings are rejected instead of polluting the
   result set, and network errors are classified for the module logs.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from models import IntelligenceFinding

# ─────────────────────────── shared constants ───────────────────────────

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

# Global outbound budget. Every module funnels through safe_fetch, so one
# semaphore here protects every third party service at once.
MAX_CONCURRENT_REQUESTS = 24
_request_semaphore: Optional[asyncio.Semaphore] = None
_semaphore_loop: Optional[asyncio.AbstractEventLoop] = None

# Per scan response cache: many modules ask for the same homepage, robots.txt
# or certificate transparency data. One fetch, many consumers.
_CACHE_TTL = 300.0
_cache: Dict[Tuple[str, str, str], Tuple[float, Optional[httpx.Response]]] = {}


def _get_semaphore() -> Optional[asyncio.Semaphore]:
    """Return a semaphore bound to the running loop, recreated if the loop changed."""
    global _request_semaphore, _semaphore_loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return None
    if _request_semaphore is None or _semaphore_loop is not loop:
        _request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        _semaphore_loop = loop
    return _request_semaphore


def clear_cache() -> None:
    """Drop the shared response cache. Call once per scan."""
    _cache.clear()


# ─────────────────────────── target helpers ───────────────────────────

def normalize_target(value: str) -> str:
    """Strip scheme, path, credentials and trailing dots from a target."""
    if not value:
        return ""
    target = str(value).strip().lower()
    for scheme in ("http://", "https://"):
        if target.startswith(scheme):
            target = target[len(scheme):]
            break
    target = target.split("/", 1)[0].split("?", 1)[0].strip()
    if "@" in target:
        target = target.rsplit("@", 1)[1]
    if target.startswith("["):  # IPv6 literal
        return target
    if target.count(":") == 1:  # host:port
        host, _, port = target.partition(":")
        return f"{host}:{port}" if port.isdigit() else target
    return target.rstrip(".")


def target_host(target: str) -> str:
    """Hostname without any port suffix."""
    host = normalize_target(target)
    if host.startswith("["):
        return host.split("]")[0].lstrip("[")
    return host.split(":")[0] if host.count(":") == 1 else host


def target_port(target: str, default: int = 80) -> int:
    host = normalize_target(target)
    if not host.startswith("[") and host.count(":") == 1:
        _, _, port = host.partition(":")
        if port.isdigit():
            return int(port)
    return default


def target_kind(target: str) -> str:
    """Classify a target: ip, email, domain, url or host."""
    value = (target or "").strip()
    if "@" in value and EMAIL_RE.match(value.split()[0]):
        return "email"
    host = target_host(value)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return "ip"
    if DOMAIN_RE.match(host):
        return "domain"
    if "://" in value:
        return "url"
    return "host"


def is_ip(target: str) -> bool:
    host = target_host(target)
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def resolve_ip(hostname: str) -> Optional[str]:
    try:
        socket.gethostbyname(hostname)
    except (OSError, UnicodeError):
        return None
    return hostname and socket.gethostbyname(hostname)


def classify_email(email: str) -> str:
    """Classify an address as disposable, role-based or personal."""
    if "@" not in email:
        return "unknown"
    local, _, domain = email.lower().partition("@")
    disposable_domains = {
        "tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com",
        "throwaway.email", "trashmail.com", "yopmail.com", "temp-mail.org",
        "dispostable.com", "fakeinbox.com", "getnada.com", "sharklasers.com",
    }
    if domain in disposable_domains:
        return "disposable"
    common_roles = {
        "info", "contact", "support", "sales", "admin", "help", "hello", "careers", "jobs",
        "hr", "billing", "accounts", "finance", "marketing", "pr", "press", "media",
        "partners", "business", "enquiries", "mail", "office", "team", "webmaster",
        "postmaster", "hostmaster", "abuse", "noreply", "feedback", "newsletter",
        "social", "community", "legal", "privacy", "security", "engineering",
        "tech", "it", "devops", "system", "network", "recruitment", "compliance",
    }
    if local in common_roles:
        return "role-based"
    if re.match(r"^[a-z]+\.[a-z]+$", local):
        return "personal (first.last)"
    return "personal"


def extract_emails(text: str, domain_filter: str = "") -> List[str]:
    emails: set = set()
    for match in EMAIL_RE.finditer(text or ""):
        found = match.group(0).lower()
        if domain_filter and not found.endswith(domain_filter.lower()):
            continue
        emails.add(found)
    return sorted(emails)


def compute_hash(data: str) -> str:
    return hashlib.sha256((data or "").encode("utf-8", "ignore")).hexdigest()[:16]


def truncate(text: str, size: int) -> str:
    text = str(text)
    return text if len(text) <= size else text[: size - 1] + "…"


# ─────────────────────── finding taxonomy (specificity) ───────────────────────

CATEGORY_BY_TYPE: Dict[str, str] = {
    "subdomain": "1. DOMAIN RECON",
    "dns": "1. DOMAIN RECON",
    "dns record": "1. DOMAIN RECON",
    "domain": "1. DOMAIN RECON",
    "whois": "1. DOMAIN RECON",
    "registrar": "1. DOMAIN RECON",
    "nameserver": "1. DOMAIN RECON",
    "ip address": "2. IP / NETWORK RECON",
    "asn": "2. IP / NETWORK RECON",
    "open port": "2. IP / NETWORK RECON",
    "service": "2. IP / NETWORK RECON",
    "network": "2. IP / NETWORK RECON",
    "firewall": "2. IP / NETWORK RECON",
    "technology": "3. WEB APPLICATION ENUMERATION",
    "web technology": "3. WEB APPLICATION ENUMERATION",
    "cms": "3. WEB APPLICATION ENUMERATION",
    "web framework": "3. WEB APPLICATION ENUMERATION",
    "header": "3. WEB APPLICATION ENUMERATION",
    "security header": "3. WEB APPLICATION ENUMERATION",
    "web form": "3. WEB APPLICATION ENUMERATION",
    "api endpoint": "3. WEB APPLICATION ENUMERATION",
    "endpoint": "3. WEB APPLICATION ENUMERATION",
    "javascript": "3. WEB APPLICATION ENUMERATION",
    "library": "3. WEB APPLICATION ENUMERATION",
    "email address": "4. EMAIL OSINT",
    "email pattern": "4. EMAIL OSINT",
    "email security": "4. EMAIL OSINT",
    "mail server": "4. EMAIL OSINT",
    "social profile": "5. USERNAME / SOCIAL MEDIA OSINT",
    "username": "5. USERNAME / SOCIAL MEDIA OSINT",
    "social account": "5. USERNAME / SOCIAL MEDIA OSINT",
    "employee": "6. PERSON / ORGANIZATION OSINT",
    "person": "6. PERSON / ORGANIZATION OSINT",
    "organization": "6. PERSON / ORGANIZATION OSINT",
    "leak": "7. LEAK / BREACH ANALYSIS",
    "data breach": "7. LEAK / BREACH ANALYSIS",
    "secret": "10. SOURCE CODE / DEVOPS OSINT",
    "hardcoded secret": "10. SOURCE CODE / DEVOPS OSINT",
    "credential": "7. LEAK / BREACH ANALYSIS",
    "exposed vcs": "10. SOURCE CODE / DEVOPS OSINT",
    "source code": "10. SOURCE CODE / DEVOPS OSINT",
    "supply chain": "10. SOURCE CODE / DEVOPS OSINT",
    "cloud": "8. CLOUD / INFRASTRUCTURE OSINT",
    "cloud bucket": "8. CLOUD / INFRASTRUCTURE OSINT",
    "cloud provider": "8. CLOUD / INFRASTRUCTURE OSINT",
    "waf/cdn": "8. CLOUD / INFRASTRUCTURE OSINT",
    "document": "9. FILE / DOCUMENT ANALYSIS",
    "sensitive file": "9. FILE / DOCUMENT ANALYSIS",
    "backup file": "9. FILE / DOCUMENT ANALYSIS",
    "dork": "11. INTERNET SEARCH ENGINE OSINT",
    "search lead": "11. INTERNET SEARCH ENGINE OSINT",
    "intel": "11. INTERNET SEARCH ENGINE OSINT",
    "malware": "12. DARK WEB / THREAT INTEL",
    "threat": "12. DARK WEB / THREAT INTEL",
    "c2": "12. DARK WEB / THREAT INTEL",
    "botnet": "12. DARK WEB / THREAT INTEL",
    "ransomware": "12. DARK WEB / THREAT INTEL",
    "phishing": "12. DARK WEB / THREAT INTEL",
    "darknet": "12. DARK WEB / THREAT INTEL",
    "dark web": "12. DARK WEB / THREAT INTEL",
    "attribution": "12. DARK WEB / THREAT INTEL",
    "ssl certificate": "13. SSL / CERTIFICATE ANALYSIS",
    "ssl/tls": "13. SSL / CERTIFICATE ANALYSIS",
    "ssl": "13. SSL / CERTIFICATE ANALYSIS",
    "tls": "13. SSL / CERTIFICATE ANALYSIS",
    "archive": "14. HISTORICAL / ARCHIVE RECON",
    "wayback": "14. HISTORICAL / ARCHIVE RECON",
    "geolocation": "15. GEOLOCATION / PHYSICAL OSINT",
    "city": "15. GEOLOCATION / PHYSICAL OSINT",
    "infrastructure": "8. CLOUD / INFRASTRUCTURE OSINT",
    "mobile": "16. MOBILE / APP OSINT",
    "app": "16. MOBILE / APP OSINT",
    "vulnerability": "17. RISK / SECURITY ANALYSIS",
    "cve": "26. VULNERABILITY & CVE DATABASE",
    "config weakness": "17. RISK / SECURITY ANALYSIS",
    "cookie": "17. RISK / SECURITY ANALYSIS",
    "cors": "17. RISK / SECURITY ANALYSIS",
    "redirect": "17. RISK / SECURITY ANALYSIS",
    "relationship": "18. RELATIONSHIP MAPPING",
    "correlation": "20. AUTOMATED CORRELATION ENGINE",
    "financial": "21. FINANCIAL INTELLIGENCE",
    "crypto": "22. CRYPTO & BLOCKCHAIN ASSETS",
    "blockchain": "22. CRYPTO & BLOCKCHAIN ASSETS",
    "wallet": "22. CRYPTO & BLOCKCHAIN ASSETS",
    "tld": "11. INTERNET SEARCH ENGINE OSINT",
    "trademark": "6. PERSON / ORGANIZATION OSINT",
    "patent": "6. PERSON / ORGANIZATION OSINT",
    "research": "6. PERSON / ORGANIZATION OSINT",
}

COLOR_BY_THREAT = {
    "critical": "red",
    "high risk": "red",
    "elevated risk": "orange",
    "standard target": "blue",
    "informational": "slate",
}

THREAT_ORDER = {
    "critical": 5,
    "high risk": 4,
    "elevated risk": 3,
    "standard target": 2,
    "informational": 1,
}


def category_for(ftype: str) -> str:
    """Best effort category for a finding type, so the UI can group precisely."""
    key = (ftype or "").strip().lower()
    if key in CATEGORY_BY_TYPE:
        return CATEGORY_BY_TYPE[key]
    for needle, category in CATEGORY_BY_TYPE.items():
        if needle in key or key in needle:
            return category
    return "MISCELLANEOUS"


def threat_for(ftype: str) -> str:
    """Severity bucket implied by the finding type when a module did not set one."""
    key = (ftype or "").lower()
    if any(k in key for k in ("secret", "credential", "injection", "takeover", "breach", "vulnerability", "cve", "exposed")):
        return "Elevated Risk"
    if any(k in key for k in ("password", "leak", "c2", "malware", "ransomware", "backup file", "sensitive file")):
        return "High Risk"
    if any(k in key for k in ("subdomain", "technology", "email", "archive", "geolocation", "cloud")):
        return "Informational"
    return "Informational"


def rank_finding(finding: IntelligenceFinding) -> int:
    return THREAT_ORDER.get((getattr(finding, "threat_level", "") or "").lower(), 0)


# ─────────────────────────── finding factory ───────────────────────────

def make_finding(
    entity: str = "",
    ftype: str = "",
    source: str = "",
    confidence: str = "Medium",
    color: str = "",
    category: str = "",
    threat_level: str = "",
    status: str = "Discovered",
    resolution: str = "",
    raw_data: str = "",
    tags: Optional[List[str]] = None,
    type: Optional[str] = None,  # noqa: A002 - modules use this alias
    severity: Optional[str] = None,
    threat: Optional[str] = None,
    *extra_positional: Any,
    **extra: Any,
) -> Optional[IntelligenceFinding]:
    """Build an IntelligenceFinding from any of the calling conventions in use.

    The module library calls this helper in four shapes, all supported here:

        make_finding("a.example.com", "Subdomain", source="X")
        make_finding(entity=..., ftype=..., confidence=..., color=...)
        make_finding(entity=..., type=...)            # alias for ftype
        make_finding(..., severity="High Risk")       # alias for threat_level

    Returns None when there is nothing meaningful to report, which keeps
    noise out of the correlation engine.
    """
    ftype = ftype or type or ""
    # A third positional argument is the source in some older modules.
    if extra_positional and not source:
        source = str(extra_positional[0])
    for alias, value in (("severity", severity), ("threat", threat)):
        if value:
            threat_level = threat_level or str(value)
    if not threat_level:
        threat_level = extra.get("threat") or extra.get("severity") or ""
    if not entity:
        entity = extra.get("value") or extra.get("name") or ""
    if not ftype:
        ftype = extra.get("finding_type") or extra.get("kind") or "Intel"

    entity = truncate(str(entity).strip(), 500)
    if not entity or not ftype:
        return None

    if not category:
        category = extra.get("module_category") or ""
    if not category:
        category = category_for(ftype)
    if not threat_level:
        threat_level = threat_for(ftype)
    if not color:
        color = COLOR_BY_THREAT.get(str(threat_level).lower(), "blue")

    clean_tags: List[str] = []
    for tag in (tags or []):
        tag = str(tag).strip()
        if tag and tag not in clean_tags:
            clean_tags.append(tag)
    if source and source not in clean_tags:
        clean_tags.append(source.split(":", 1)[0].strip())

    return IntelligenceFinding(
        entity=entity,
        type=ftype,
        source=source or "Python",
        confidence=confidence or "Medium",
        color=color,
        category=category,
        threat_level=threat_level,
        status=status or "Discovered",
        resolution=resolution or None,
        raw_data=truncate(raw_data, 4000) if raw_data else None,
        tags=clean_tags,
    )


# ─────────────────────────── HTTP helpers ───────────────────────────

_NETWORK_ERRORS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.TransportError,
    httpx.RemoteProtocolError,
    httpx.LocalProtocolError,
    httpx.TooManyRedirects,
    httpx.UnsupportedProtocol,
    httpx.InvalidURL,
    httpx.ProxyError,
    socket.gaierror,
    socket.timeout,
    OSError,
)


async def safe_fetch(
    client: Optional[httpx.AsyncClient],
    url: str,
    timeout: float = 15.0,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    method: str = "GET",
    data: Any = None,
    content: Optional[bytes] = None,
    json: Any = None,
    retries: int = 1,
    **kwargs: Any,
) -> Optional[httpx.Response]:
    """Fetch a URL without ever raising, shared across all modules.

    Improvements over the previous helper:
      * uses ``client.request`` so params, data, json and content work for
        every method (httpx's get() rejects data= and content=)
      * one global concurrency budget instead of per module chaos
      * short in scan response cache to avoid duplicate third party hits
      * one retry with jitter for transient failures, no retry for 4xx
    """
    if client is None or not url:
        return None

    key = (method.upper(), url, repr(sorted((params or {}).items())))
    now = time.time()
    cached = _cache.get(key)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]

    merged = {"User-Agent": UA}
    merged.update(headers or {})
    send = {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        "headers": merged,
        "params": params,
        "data": data,
        "content": content,
        "json": json,
    }
    send.update(kwargs)

    semaphore = _get_semaphore()
    attempt = 0
    total = 1 + max(0, retries)
    last_exc: Optional[Exception] = None

    while attempt < total:
        try:
            if semaphore is not None:
                async with semaphore:
                    resp = await client.request(method.upper(), url, **send)
            else:
                resp = await client.request(method.upper(), url, **send)
        except _NETWORK_ERRORS as exc:
            last_exc = exc
            attempt += 1
            if attempt >= total:
                break
            await asyncio.sleep(0.25 * attempt)
            continue
        except Exception:
            return None

        if resp.status_code in (429, 500, 502, 503, 504) and attempt + 1 < total:
            attempt += 1
            await asyncio.sleep(0.4 * attempt)
            continue

        if key[1].startswith("http") or key[1].startswith("https"):
            _cache[key] = (now, resp)
        return resp

    del last_exc
    return None


async def safe_fetch_json(
    client: Optional[httpx.AsyncClient],
    url: str,
    timeout: float = 15.0,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Optional[Any]:
    resp = await safe_fetch(client, url, timeout=timeout, headers=headers, params=params, **kwargs)
    if resp is not None and resp.status_code == 200 and resp.content:
        try:
            return resp.json()
        except Exception:
            return None
    return None


async def safe_fetch_text(
    client: Optional[httpx.AsyncClient],
    url: str,
    timeout: float = 15.0,
    headers: Optional[Dict[str, str]] = None,
    **kwargs: Any,
) -> str:
    resp = await safe_fetch(client, url, timeout=timeout, headers=headers, **kwargs)
    if resp is None or resp.status_code >= 400:
        return ""
    try:
        return resp.text
    except Exception:
        return ""


def response_ok(resp: Optional[httpx.Response]) -> bool:
    return resp is not None and resp.status_code < 400


def require_api_keys(*services: str) -> List[str]:
    """Return the subset of services that have no API key configured.

    Modules that cannot work without a key call this first and return
    immediately when the list is non empty, instead of burning a full
    timeout on requests that are guaranteed to fail::

        if require_api_keys("shodan"):
            return findings
    """
    try:
        from settings_store import get_api_key
    except Exception:
        return list(services)
    return [s for s in services if not get_api_key(s)]


def guess_base_url(target: str, prefer_tls: bool = True) -> str:
    """Build a fetchable base URL from any target form."""
    host = target_host(target)
    if not host:
        return ""
    scheme = "https" if prefer_tls else "http"
    explicit_port = target_port(target, 0)
    if explicit_port and explicit_port not in (80, 443):
        return f"{scheme}://{host}:{explicit_port}"
    return f"{scheme}://{host}"


def base_url_candidates(target: str) -> List[str]:
    """Both schemes, https first, so a module can try the other one cheaply."""
    host = target_host(target)
    if not host:
        return []
    explicit_port = target_port(target, 0)
    if explicit_port and explicit_port not in (80, 443):
        return [f"http://{host}:{explicit_port}", f"https://{host}:{explicit_port}"]
    return [f"https://{host}", f"http://{host}"]


__all__ = [
    "UA", "EMAIL_RE", "DOMAIN_RE", "MAX_CONCURRENT_REQUESTS",
    "clear_cache", "normalize_target", "target_host", "target_port", "target_kind",
    "is_ip", "resolve_ip", "classify_email", "extract_emails", "compute_hash",
    "truncate", "category_for", "threat_for", "rank_finding", "make_finding",
    "require_api_keys",
    "safe_fetch", "safe_fetch_json", "safe_fetch_text", "response_ok",
    "guess_base_url", "base_url_candidates",
    "CATEGORY_BY_TYPE", "COLOR_BY_THREAT", "THREAT_ORDER",
]
