import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError


@dataclass
class BreachResult:
    email: str
    source: str
    data_class: str = ""
    date: str = ""
    confidence: int = 0


def check_haveibeenpwned(email: str) -> list[BreachResult]:
    """Check HaveIBeenPwned via the API (v3, no key needed for breaches)."""
    results = []
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        req = Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                      headers={"User-Agent": "HackIT-OSINT/1.0", "Add-Padding": "true"})
        with urlopen(req, timeout=15) as resp:
            data = resp.read().decode()
            for line in data.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(":")[1].strip())
                    results.append(BreachResult(
                        email=email, source="HaveIBeenPwned",
                        data_class=f"Password exposed ({count} times)", confidence=min(count * 10, 100)
                    ))
    except (URLError, OSError):
        pass
    return results


def check_emailrep(email: str) -> list[BreachResult]:
    """Check emailrep.io for reputation data."""
    results = []
    try:
        req = Request(f"https://emailrep.io/{email}",
                      headers={"User-Agent": "HackIT-OSINT/1.0", "Accept": "application/json"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("breaches"):
                for b in data["breaches"]:
                    results.append(BreachResult(
                        email=email, source="emailrep.io",
                        data_class=b.get("data_classes", ""), date=b.get("date", ""),
                        confidence=90
                    ))
            if data.get("details", {}).get("credentials_leaked"):
                results.append(BreachResult(
                    email=email, source="emailrep.io",
                    data_class="Credentials leaked (reported)", confidence=85
                ))
    except (URLError, OSError, json.JSONDecodeError):
        pass
    return results


def check_leakcheck(email: str) -> list[BreachResult]:
    """Check leakcheck.io (public API)."""
    results = []
    try:
        req = Request(f"https://leakcheck.io/api/public?check={email}",
                      headers={"User-Agent": "HackIT-OSINT/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("success") and data.get("found", 0) > 0:
                for line in data.get("result", [])[:5]:
                    results.append(BreachResult(
                        email=email, source="leakcheck.io",
                        data_class=f"Found in {line.get('sources', 'unknown')}",
                        confidence=80
                    ))
    except (URLError, OSError, json.JSONDecodeError):
        pass
    return results


def check_dehashed(email: str) -> list[BreachResult]:
    """Check dehashed.com via leaked database checks (simulated)."""
    results = []
    try:
        req = Request(f"https://dehashed.com/api/v1/search?email={email}",
                      headers={"User-Agent": "HackIT-OSINT/1.0", "Accept": "application/json"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("entries"):
                for entry in data["entries"][:5]:
                    results.append(BreachResult(
                        email=email, source="dehashed.com",
                        data_class=entry.get("type", ""), confidence=75
                    ))
    except (URLError, OSError, json.JSONDecodeError):
        pass
    return results


def check_firefox_monitor(email: str) -> list[BreachResult]:
    """Check Firefox Monitor (public)."""
    results = []
    try:
        req = Request(f"https://monitor.firefox.com/scan?email={email}",
                      headers={"User-Agent": "HackIT-OSINT/1.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("breaches"):
                for b in data["breaches"]:
                    results.append(BreachResult(
                        email=email, source="firefox-monitor",
                        data_class=b.get("Name", ""), confidence=85
                    ))
    except (URLError, OSError, json.JSONDecodeError):
        pass
    return results


def check_breaches(email: str) -> list[BreachResult]:
    results = []
    results.extend(check_haveibeenpwned(email))
    results.extend(check_emailrep(email))
    results.extend(check_firefox_monitor(email))
    return results
