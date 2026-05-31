import hashlib
import re
from urllib.parse import urlparse, urljoin

from models import IntelligenceFinding


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def normalize_target(target: str) -> str:
    target = target.strip()
    if target.startswith(("http://", "https://")):
        host = urlparse(target).netloc
    else:
        host = target.split("/")[0]
    return host.strip().lower().strip(".")


def base_urls(target: str):
    host = normalize_target(target)
    return [f"https://{host}", f"http://{host}"]


def make_finding(entity, ftype, source, confidence="Medium", color="slate",
                 category=None, threat_level="Informational", status="Found",
                 resolution=None, raw_data=None, tags=None):
    return IntelligenceFinding(
        entity=str(entity)[:500],
        type=ftype,
        source=source,
        confidence=confidence,
        color=color,
        category=category,
        threat_level=threat_level,
        status=status,
        resolution=resolution,
        raw_data=raw_data[:4000] if isinstance(raw_data, str) else raw_data,
        tags=tags or [],
    )


def extract_emails(text: str, domain: str = ""):
    emails = sorted(set(m.group(0).strip(".,;:()[]{}<>").lower() for m in EMAIL_RE.finditer(text or "")))
    if domain:
        own = [e for e in emails if e.endswith("@" + domain) or e.split("@")[-1].endswith("." + domain)]
        return own + [e for e in emails if e not in own]
    return emails


def extract_urls(text: str):
    return sorted(set(m.group(0).rstrip(".,;)'\"") for m in URL_RE.finditer(text or "")))


def classify_url(url: str):
    lower = url.lower()
    if any(x in lower for x in ["/api/", "graphql", "swagger", "openapi", "rest/"]):
        return "API Endpoint"
    if "?" in url and "=" in url:
        return "URL Parameter"
    if any(lower.endswith(ext) for ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt"]):
        return "Document"
    if any(x in lower for x in [".env", ".git", "backup", "dump", "config", "secret", "credential"]):
        return "Sensitive URL"
    return "Historical URL"


def favicon_hash(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


def same_domain(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def absolute_url(base: str, value: str) -> str:
    return urljoin(base.rstrip("/") + "/", value)

