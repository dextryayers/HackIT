import hashlib
import re
import ssl
import socket
import asyncio
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import List, Optional, Dict, Any
import dns.resolver
from models import IntelligenceFinding


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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


def extract_ips(text: str):
    return sorted(set(m.group(0) for m in IP_RE.finditer(text or "")))


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


async def resolve_dns(target: str, record_type: str = 'A'):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, record_type))
        return [str(r) for r in answers]
    except:
        return []


async def get_all_dns_records(domain: str) -> Dict[str, List[str]]:
    results = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DS']:
        records = await resolve_dns(domain, rtype)
        if records:
            results[rtype] = records
    return results


async def get_ssl_cert_info(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    loop = asyncio.get_event_loop()
    def fetch():
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(10)
                s.connect((hostname, port))
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "protocol": version,
                }
        except:
            try:
                ctx = ssl._create_unverified_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(10)
                    s.connect((hostname, port))
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    version = s.version()
                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "protocol": version,
                    }
            except:
                return None
    return await loop.run_in_executor(None, fetch)


def parse_cert_to_dict(cert: Dict) -> Dict[str, Any]:
    if not cert:
        return {}
    issuer = {}
    for item in cert.get("issuer", []):
        for key, val in item:
            issuer[key] = val
    subject = {}
    for item in cert.get("subject", []):
        for key, val in item:
            subject[key] = val
    sans = [v for _, v in cert.get("subjectAltName", [])]
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    days_remaining = None
    is_expired = False
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (expiry - datetime.now()).days
            is_expired = days_remaining < 0
        except:
            pass
    return {
        "issuer": issuer,
        "subject": subject,
        "valid_from": not_before,
        "valid_to": not_after,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "subject_alt_names": sans,
        "serial_number": cert.get("serialNumber"),
        "fingerprint_sha256": cert.get("fingerprint") or cert.get("sha256"),
    }


async def check_email_security(domain: str) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    result = {"spf": None, "dkim": None, "dmarc": None, "mx": []}
    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        result["mx"] = [str(r.exchange).rstrip('.') for r in mx_records]
    except: pass
    try:
        txt_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        for r in txt_records:
            txt = str(r)
            if txt.startswith("v=spf1"):
                result["spf"] = txt
    except: pass
    try:
        dmarc_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'))
        for r in dmarc_records:
            result["dmarc"] = str(r)
    except: pass
    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx']:
        try:
            dkim_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT'))
            for r in dkim_records:
                result["dkim"] = f"{selector}: {str(r)}"
                break
        except: pass
    return result
