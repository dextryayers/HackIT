import hashlib
import json
import re
from dataclasses import dataclass
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import quote_plus


@dataclass
class BreachResult:
    email: str
    source: str
    data_class: str = ""
    date: str = ""
    confidence: int = 0


def check_haveibeenpwned(email: str) -> list:
    results = []
    try:
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        req = Request(f"https://api.pwnedpasswords.com/range/{prefix}",
                      headers={"User-Agent": "HackIT-OSINT/2.0", "Add-Padding": "true"})
        with urlopen(req, timeout=15) as resp:
            data = resp.read().decode()
            for line in data.splitlines():
                if line.startswith(suffix):
                    count = int(line.split(":")[1].strip())
                    results.append(BreachResult(
                        email=email, source="HaveIBeenPwned",
                        data_class=f"Password exposed ({count:,} times)",
                        confidence=min(count * 5, 100)
                    ))
    except:
        pass
    return results


def check_emailrep(email: str) -> list:
    results = []
    try:
        req = Request(f"https://emailrep.io/{email}",
                      headers={"User-Agent": "HackIT-OSINT/2.0", "Accept": "application/json"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("breaches"):
                for b in data["breaches"]:
                    results.append(BreachResult(
                        email=email, source="emailrep.io",
                        data_class=b.get("data_classes", ""),
                        date=b.get("date", ""), confidence=90
                    ))
            if data.get("details", {}).get("credentials_leaked"):
                results.append(BreachResult(
                    email=email, source="emailrep.io",
                    data_class="Credentials leaked (reported)", confidence=85
                ))
            details = data.get("details", {})
            if details.get("malicious_activity"):
                results.append(BreachResult(
                    email=email, source="emailrep.io",
                    data_class="Malicious activity detected", confidence=80
                ))
            if details.get("spam"):
                results.append(BreachResult(
                    email=email, source="emailrep.io",
                    data_class="Reported spam activity", confidence=75
                ))
    except:
        pass
    return results


def check_leakcheck(email: str) -> list:
    results = []
    try:
        req = Request(f"https://leakcheck.io/api/public?check={email}",
                      headers={"User-Agent": "HackIT-OSINT/2.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("success") and data.get("found", 0) > 0:
                for line in data.get("result", [])[:8]:
                    results.append(BreachResult(
                        email=email, source="leakcheck.io",
                        data_class=f"Leaked via {line.get('sources', 'unknown')}",
                        confidence=80
                    ))
    except:
        pass
    return results


def check_firefox_monitor(email: str) -> list:
    results = []
    try:
        req = Request(f"https://monitor.firefox.com/scan?email={email}",
                      headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("breaches"):
                for b in data["breaches"]:
                    results.append(BreachResult(
                        email=email, source="Firefox Monitor",
                        data_class=b.get("Name", ""),
                        date=b.get("AddedDate", ""), confidence=85
                    ))
    except:
        pass
    return results


def check_dehashed_public(email: str) -> list:
    results = []
    try:
        url = f"https://dehashed.com/api/v1/search?email={email}"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if data.get("entries"):
                for entry in data["entries"][:5]:
                    results.append(BreachResult(
                        email=email, source="Dehashed",
                        data_class=f"{entry.get('type', 'data')}: {entry.get('value', '')[:50]}",
                        confidence=75
                    ))
    except:
        pass
    return results


def check_google_dork(email: str) -> list:
    results = []
    try:
        queries = [
            f'"{email}" breach',
            f'"{email}" leak',
            f'"{email}" pastebin',
            f'"{email}" dump',
        ]
        for q in queries:
            url = f"https://www.google.com/search?q={quote_plus(q)}"
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept-Language": "en-US,en;q=0.9",
            })
            with urlopen(req, timeout=10) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                count_match = re.search(r'About ([\d,]+) results', html)
                title_match = re.search(r'<title>(.*?)</title>', html)
                if count_match:
                    count = count_match.group(1)
                    if int(count.replace(',', '')) > 0:
                        results.append(BreachResult(
                            email=email, source=f"Google Dork: {q.split('"')[1]}",
                            data_class=f"~{count} public mentions",
                            confidence=65
                        ))
    except:
        pass
    return results


def check_pgp_key(email: str) -> list:
    results = []
    servers = [
        f"https://keyserver.ubuntu.com/pks/lookup?op=get&search={email}",
        f"https://pgp.mit.edu/pks/lookup?op=get&search={email}",
    ]
    for url in servers:
        try:
            req = Request(url, headers={"User-Agent": "HackIT-OSINT/2.0"})
            with urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                if "BEGIN PGP PUBLIC KEY BLOCK" in body:
                    results.append(BreachResult(
                        email=email, source="PGP Key Server",
                        data_class="PGP public key registered",
                        confidence=90
                    ))
        except:
            pass
    return results


def check_breaches(email: str) -> list:
    results = []
    results.extend(check_haveibeenpwned(email))
    results.extend(check_emailrep(email))
    results.extend(check_firefox_monitor(email))
    results.extend(check_leakcheck(email))
    results.extend(check_google_dork(email))
    results.extend(check_pgp_key(email))
    return results
