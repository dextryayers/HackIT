import httpx
import asyncio
import re
import hashlib
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from collections import defaultdict

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

PASTE_SOURCES = {
    "pastebin": {
        "url": "https://psbdmp.ws/api/v3/search?q={query}",
        "parser": "json",
    },
    "ghostbin": {
        "url": "https://ghostbin.com/paste/search?q={query}",
        "parser": "html",
    },
    "dpaste": {
        "url": "https://dpaste.org/search/?q={query}",
        "parser": "html",
    },
    "controlc": {
        "url": "https://controlc.com/search.php?search={query}",
        "parser": "html",
    },
}

BREACH_SOURCES = [
    {
        "name": "Dehashed",
        "url": "https://dehashed.com/search?query={query}",
        "type": "api",
    },
    {
        "name": "LeakCheck",
        "url": "https://leakcheck.io/api/public?check={query}",
        "type": "api",
    },
    {
        "name": "Scylla.so",
        "url": "https://scylla.so/search?q={query}",
        "type": "html",
    },
    {
        "name": "IntelX",
        "url": "https://intelx.io/search?q={query}",
        "type": "html",
    },
]

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
CRED_PATTERN = re.compile(
    r'(?P<email>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:;|,]\s*(?P<password>\S+)'
)
USERPASS_PATTERN = re.compile(
    r'(?P<username>[a-zA-Z0-9._-]+)\s*[:;|,]\s*(?P<password>\S+)'
)
IP_PORT_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b')
HASH_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')
PHONE_PATTERN = re.compile(r'\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b')
CREDIT_CARD_PATTERN = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')

LEAK_SEVERITY = {
    "email:password": 10,
    "credit_card": 10,
    "ssn": 10,
    "phone": 7,
    "email": 4,
    "username:password": 9,
    "hash": 6,
    "ip:port": 3,
}

BREACH_TIMELINE_KEYWORDS = [
    "2024", "2025", "2026", "2023", "2022", "2021", "2020",
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


def classify_leaked_data(text: str) -> List[Tuple[str, str]]:
    classified = []
    creds = CRED_PATTERN.findall(text)
    for email, password in creds:
        classified.append(("email:password", f"{email}:{password}"))
    userpass = USERPASS_PATTERN.findall(text)
    for username, password in userpass:
        classified.append(("username:password", f"{username}:{password}"))
    emails = EMAIL_REGEX.findall(text)
    for email in emails:
        classified.append(("email", email))
    phones = PHONE_PATTERN.findall(text)
    for phone in phones:
        classified.append(("phone", phone))
    cards = CREDIT_CARD_PATTERN.findall(text)
    for card in cards:
        classified.append(("credit_card", card))
    ips = IP_PORT_PATTERN.findall(text)
    for ip_port in ips:
        classified.append(("ip:port", ip_port))
    hashes = HASH_PATTERN.findall(text)
    for h in hashes:
        classified.append(("hash", h))
    return classified


def extract_breach_timeline(text: str) -> List[str]:
    dates = []
    for match in re.finditer(r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}[,a-z]*\s+\d{4}\b', text, re.I):
        dates.append(match.group())
    for match in re.finditer(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b', text):
        dates.append(match.group())
    for match in re.finditer(r'\b\d{1,2}[-/]\d{1,2}[-/]\d{4}\b', text):
        dates.append(match.group())
    return sorted(set(dates))


def extract_breach_names(text: str) -> List[str]:
    breach_keywords = [
        "breach", "leak", "dump", "compromised", "exposed", "hack",
        "data", "database", "collection", "combo", "crack", "wordlist"
    ]
    names = []
    lines = text.split('\n')
    for line in lines[:200]:
        line_lower = line.lower()
        if any(kw in line_lower for kw in breach_keywords) and len(line) < 200:
            names.append(line.strip()[:150])
    return names[:20]


def score_leak_severity(data_type: str) -> int:
    return LEAK_SEVERITY.get(data_type, 3)


def severity_to_threat(score: int) -> str:
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High Risk"
    elif score >= 4:
        return "Elevated Risk"
    return "Informational"


async def check_pastebin_dumps(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://psbdmp.ws/api/v3/search?q={quote(query)}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            dumps = data if isinstance(data, list) else data.get("data", [])
            for dump in dumps[:30]:
                dump_id = dump.get("id", "")
                content = dump.get("content", "")
                results.append({
                    "source": "PSBDMP",
                    "id": dump_id,
                    "content": content[:5000],
                    "url": f"https://pastebin.com/{dump_id}",
                })
    except Exception:
        pass
    return results


async def check_scylla(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://scylla.so/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            text = resp.text[:50000]
            entries = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL)
            for entry in entries[:20]:
                cells = re.findall(r'<td[^>]*>(.*?)</td>', entry, re.DOTALL)
                if cells:
                    row_data = " | ".join(re.sub(r'<[^>]+>', '', c).strip() for c in cells)
                    results.append({
                        "source": "Scylla.so",
                        "content": row_data[:1000],
                    })
    except Exception:
        pass
    return results


async def check_ghostbin(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://ghostbin.com/paste/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            paste_links = re.findall(r'href="(/paste/[^"]+)"', resp.text)
            for link in paste_links[:10]:
                paste_url = f"https://ghostbin.com{link}"
                paste_resp = await client.get(paste_url, headers=headers, timeout=15.0)
                if paste_resp.status_code == 200:
                    content = paste_resp.text[:5000]
                    results.append({
                        "source": "Ghostbin",
                        "url": paste_url,
                        "content": content,
                    })
    except Exception:
        pass
    return results


async def check_dpaste(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://dpaste.org/search/?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            paste_links = re.findall(r'href="(/\d+/[^"]+)"', resp.text)
            for link in paste_links[:10]:
                paste_url = f"https://dpaste.org{link}"
                paste_resp = await client.get(paste_url, headers=headers, timeout=15.0)
                if paste_resp.status_code == 200:
                    content = paste_resp.text[:5000]
                    results.append({
                        "source": "DPaste",
                        "url": paste_url,
                        "content": content,
                    })
    except Exception:
        pass
    return results


async def check_controlc(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://controlc.com/search.php?search={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            paste_links = re.findall(r'href="(/\d+)"', resp.text)
            for link in paste_links[:10]:
                paste_url = f"https://controlc.com{link}"
                paste_resp = await client.get(paste_url, headers=headers, timeout=15.0)
                if paste_resp.status_code == 200:
                    content = paste_resp.text[:5000]
                    results.append({
                        "source": "ControlC",
                        "url": paste_url,
                        "content": content,
                    })
    except Exception:
        pass
    return results


async def check_intelx(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://intelx.io/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            text = resp.text[:50000]
            records = re.findall(r'<div[^>]*class="[^"]*record[^"]*"[^>]*>(.*?)</div>', text, re.DOTALL)
            for record in records[:10]:
                content = re.sub(r'<[^>]+>', '', record).strip()[:500]
                if content:
                    results.append({
                        "source": "IntelX",
                        "content": content,
                    })
    except Exception:
        pass
    return results


async def check_leakcheck(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://leakcheck.io/api/public?check={quote(query)}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and data.get("success"):
                for entry in data.get("data", [])[:30]:
                    line = entry.get("line", "")
                    results.append({
                        "source": "LeakCheck",
                        "content": line[:1000],
                        "breach": entry.get("breach", ""),
                        "date": entry.get("date", ""),
                    })
    except Exception:
        pass
    return results


async def check_dehashed(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://dehashed.com/search?query={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            text = resp.text[:50000]
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL)
            for row in rows[:20]:
                cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
                if cells:
                    row_data = " | ".join(re.sub(r'<[^>]+>', '', c).strip() for c in cells)
                    results.append({
                        "source": "Dehashed",
                        "content": row_data[:1000],
                    })
    except Exception:
        pass
    return results


async def check_nfinite(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        url = f"https://nfinite.io/search/{quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            text = resp.text[:30000]
            snippets = re.findall(r'<div[^>]*class="[^"]*(?:result|entry|item)[^"]*"[^>]*>(.*?)</div>', text, re.DOTALL)
            for snippet in snippets[:10]:
                content = re.sub(r'<[^>]+>', '', snippet).strip()[:500]
                if content:
                    results.append({
                        "source": "Nfinite",
                        "content": content,
                    })
    except Exception:
        pass
    return results


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    queries = [domain]
    domain_without_tld = domain.split('.')[0] if len(domain.split('.')) > 1 else domain
    queries.append(domain_without_tld)

    all_raw_data = []

    for query in queries:
        tasks = [
            check_pastebin_dumps(client, query),
            check_scylla(client, query),
            check_ghostbin(client, query),
            check_dpaste(client, query),
            check_controlc(client, query),
            check_intelx(client, query),
            check_leakcheck(client, query),
            check_dehashed(client, query),
            check_nfinite(client, query),
        ]
        results_lists = await asyncio.gather(*tasks, return_exceptions=True)

        seen_creds = set()
        seen_emails = set()

        for results in results_lists:
            if not isinstance(results, list):
                continue
            for result in results:
                content = result.get("content", "")
                source_name = result.get("source", "Unknown")
                breach_name = result.get("breach", "")
                breach_date = result.get("date", "")

                if not content or len(content) < 5:
                    continue

                classified = classify_leaked_data(content)
                if not classified:
                    continue

                all_raw_data.append(content)

                breach_timeline = extract_breach_timeline(content)
                breach_names = extract_breach_names(content)

                domain_related = False
                for dt, val in classified:
                    if domain in val.lower() or domain in content.lower():
                        domain_related = True
                        break

                if not domain_related:
                    continue

                for data_type, value in classified:
                    if data_type in ("email:password",) and value in seen_creds:
                        continue
                    if data_type == "email" and value in seen_emails:
                        continue

                    if data_type in ("email:password",) and data_type == "email:password":
                        seen_creds.add(value)
                    elif data_type == "email":
                        seen_emails.add(value)

                    severity = score_leak_severity(data_type)
                    threat = severity_to_threat(severity)

                    tags = ["leak", data_type, source_name.lower()]
                    if breach_name:
                        tags.append(breach_name.lower().replace(" ", "_"))

                    entry = f"{data_type}: {value}"
                    color_map = {
                        "email:password": "red",
                        "credit_card": "red",
                        "ssn": "red",
                        "phone": "orange",
                        "username:password": "red",
                        "hash": "yellow",
                        "email": "orange",
                        "ip:port": "slate",
                    }
                    color = color_map.get(data_type, "slate")

                    resolution = f"Found in {source_name}"
                    if breach_name:
                        resolution += f" ({breach_name})"
                    if breach_timeline:
                        resolution += f" | Timeline: {', '.join(breach_timeline[:3])}"

                    findings.append(IntelligenceFinding(
                        entity=entry[:200],
                        type=f"Leak: {data_type}",
                        source=f"LeakChecker/{source_name}",
                        confidence="High" if data_type in ("email:password", "credit_card", "username:password") else "Medium",
                        color=color,
                        threat_level=threat,
                        status="Confirmed Leak" if data_type in ("email:password", "credit_card") else "Potential Leak",
                        resolution=resolution[:300] if resolution else None,
                        raw_data=f"Source: {source_name}\nValue: {value[:300]}\nContext: {content[:500]}",
                        tags=tags,
                    ))

                if breach_names:
                    for name in breach_names[:3]:
                        findings.append(IntelligenceFinding(
                            entity=name[:200],
                            type="Leak: Breach Name",
                            source=f"LeakChecker/{source_name}",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            status="Potential Breach",
                            raw_data=f"Mentioned in {source_name}: {name}",
                            tags=["breach-name", source_name.lower()]
                        ))

    if all_raw_data:
        combined = "\n".join(all_raw_data)
        all_dates = extract_breach_timeline(combined)
        all_breach_names = []
        for d in all_raw_data:
            all_breach_names.extend(extract_breach_names(d))

        breach_summary = f"Leak Check Summary: {len(findings)} findings"
        if all_dates:
            breach_summary += f" | Timeline events: {len(all_dates)}"
        if all_breach_names:
            breach_summary += f" | Potential breaches: {len(set(all_breach_names))}"

        findings.append(IntelligenceFinding(
            entity=breach_summary,
            type="Leak: Summary",
            source="LeakChecker",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data="\n".join([
                f"Total Findings: {len(findings)}",
                f"Sources Checked: PSBDMP, Scylla.so, Ghostbin, DPaste, ControlC, IntelX, LeakCheck, Dehashed, Nfinite",
                f"Breach Timeline Dates: {', '.join(all_dates[:10]) if all_dates else 'None found'}",
                f"Breach Names: {', '.join(set(all_breach_names[:10])) if all_breach_names else 'None identified'}",
            ]),
            tags=["summary", "leak-checker", "statistics"]
        ))

    return findings
