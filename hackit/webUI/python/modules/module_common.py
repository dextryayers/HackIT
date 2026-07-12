import socket
import re

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


async def safe_fetch(client, url, method="GET", **kwargs):
    """Safe HTTP request wrapper. Returns response or None on failure."""
    try:
        kwargs.setdefault("timeout", 10.0)
        kwargs.setdefault("follow_redirects", True)
        kwargs.setdefault("headers", {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        resp = await client.request(method, url, **kwargs)
        return resp
    except Exception:
        return None


async def safe_fetch_json(client, url, method="GET", **kwargs):
    """Safe HTTP request that returns parsed JSON dict, or empty dict on failure."""
    resp = await safe_fetch(client, url, method=method, **kwargs)
    if resp and resp.status_code == 200:
        try:
            return resp.json()
        except Exception:
            pass
    return {}


def make_finding(entity, ftype, source, confidence="Medium", color="slate",
                 threat_level="Informational", status=None, resolution=None,
                 raw_data=None, tags=None, **kwargs):
    """Convenience wrapper around IntelligenceFinding."""
    from models import IntelligenceFinding
    kw = dict(entity=entity, type=ftype, source=source, confidence=confidence,
              color=color, threat_level=threat_level)
    if status is not None:
        kw["status"] = status
    if resolution is not None:
        kw["resolution"] = resolution
    if raw_data is not None:
        kw["raw_data"] = raw_data
    if tags is not None:
        kw["tags"] = tags
    kw.update(kwargs)
    return IntelligenceFinding(**kw)


def is_ip(addr: str) -> bool:
    """Check if a string is an IPv4 address."""
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        return False


def resolve_ip(host: str) -> list:
    """Resolve hostname to list of IP addresses."""
    try:
        addrs = socket.getaddrinfo(host, 80, family=socket.AF_INET)
        return list(set(a[4][0] for a in addrs[:5]))
    except Exception:
        return []


def classify_email(email: str) -> str:
    """Classify an email address as disposable, corporate, or personal."""
    disposable = ["guerrillamail", "tempmail", "throwaway", "yopmail", "mailinator",
                  "guerrilla", "dispostable", "sharklasers", "guerrillamailblock",
                  "grr.la", "discard.email", "trashmail", "fakeinbox", "temp-mail"]
    corporate_indicators = [".gov", ".edu", ".mil"]
    local_indicators = ["localhost", "127.0.0.1", "0.0.0.0"]

    email_lower = email.lower()
    for d in disposable:
        if d in email_lower:
            return "disposable"
    for c in corporate_indicators:
        if c in email_lower:
            return "corporate"
    for l in local_indicators:
        if l in email_lower:
            return "local"
    return "personal"


def extract_emails(text: str) -> list:
    """Extract unique emails from text."""
    return list(set(EMAIL_RE.findall(text)))
