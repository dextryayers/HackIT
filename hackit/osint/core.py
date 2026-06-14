from __future__ import annotations

import hashlib
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Callable, List, Dict, Optional
from urllib.parse import quote_plus

import requests

from .analyzer import analyze_scan
from .identity import build_identity_target
from .mutations import build_email_candidates
from .sources import SEARCH_LEADS, get_social_sources


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class ProfileFinding:
    platform: str
    category: str
    handle: str
    url: str
    status: str
    confidence: str
    http_status: int | None = None
    note: str = ""
    title: str = ""
    description: str = ""


def _extract_between(text: str, pattern: str) -> str:
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    value = re.sub(r"\s+", " ", match.group(1)).strip()
    return value[:180]


def _extract_metadata(html: str) -> Dict[str, str]:
    return {
        "title": _extract_between(html, r"<title[^>]*>(.*?)</title>"),
        "description": _extract_between(
            html,
            r'<meta[^>]+(?:name|property)=["\'](?:description|og:description)["\'][^>]+content=["\'](.*?)["\']',
        ),
    }


def normalize_handles(query: str) -> List[str]:
    target = build_identity_target(query)
    return [target.canonical_handle] if target.canonical_handle else []


def _request_profile(session: requests.Session, source: Dict[str, str], handle: str, timeout: int) -> ProfileFinding:
    url = source["url"].format(username=handle)
    headers = {
        "User-Agent": "HackIt-OSINT/1.0 (+public-profile-check)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        code = response.status_code
        text = response.text[:5000].lower()

        if code == 200:
            not_found_markers = [
                "not found", "page not found", "user not found", "doesn't exist",
                "does not exist", "couldn't find", "isn't available",
            ]
            metadata = _extract_metadata(response.text[:20000])
            if any(marker in text for marker in not_found_markers):
                return ProfileFinding(source["name"], source["category"], handle, url, "miss", "low", code, "not-found marker", metadata["title"], metadata["description"])
            return ProfileFinding(source["name"], source["category"], handle, response.url, "hit", "medium", code, "", metadata["title"], metadata["description"])

        if code in (301, 302, 303, 307, 308):
            return ProfileFinding(source["name"], source["category"], handle, response.url, "possible", "low", code, "redirect")

        if code in (401, 403, 429):
            return ProfileFinding(source["name"], source["category"], handle, url, "unknown", "low", code, "blocked/rate-limited")

        return ProfileFinding(source["name"], source["category"], handle, url, "miss", "low", code)
    except requests.RequestException as exc:
        return ProfileFinding(source["name"], source["category"], handle, url, "unknown", "low", None, type(exc).__name__)


def scan_usernames_rust(
    query: str,
    proxy: Optional[str] = None,
    retry: int = 1,
    timeout: int = 15,
    workers: int = 50,
    on_result: Callable[[ProfileFinding], None] | None = None,
) -> List[ProfileFinding]:
    from .go_bridge import check_username

    data = check_username(query, proxy=proxy, retry=retry, timeout=timeout, workers=workers)
    results = data.get("results", [])
    findings = []

    for r in results:
        finding = ProfileFinding(
            platform=r.get("platform", ""),
            category=r.get("category", ""),
            handle=query,
            url=r.get("url", ""),
            status=r.get("status", "unknown"),
            confidence=str(r.get("confidence", 0)),
            http_status=r.get("http_status"),
            note=r.get("note", ""),
            title=r.get("title", ""),
            description=r.get("description", ""),
        )
        findings.append(finding)
        if on_result:
            on_result(finding)

    order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
    return sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))


def scan_usernames(
    query: str,
    timeout: int = 8,
    workers: int = 24,
    on_result: Callable[[ProfileFinding], None] | None = None,
    use_rust: bool = True,
    proxy: Optional[str] = None,
    retry: int = 1,
) -> List[ProfileFinding]:
    if use_rust:
        try:
            return scan_usernames_rust(query, proxy=proxy, retry=retry, timeout=max(timeout, 10), workers=workers, on_result=on_result)
        except Exception:
            pass

    handles = normalize_handles(query)
    sources = get_social_sources()
    findings: List[ProfileFinding] = []

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_request_profile, session, source, handle, timeout)
                for handle in handles
                for source in sources
            ]
            for future in as_completed(futures):
                finding = future.result()
                findings.append(finding)
                if on_result:
                    on_result(finding)

    order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
    return sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))


def inspect_email(query: str, timeout: int = 8) -> Dict[str, object]:
    email = query.strip().lower()
    result: Dict[str, object] = {
        "input": query,
        "is_email": bool(EMAIL_RE.match(email)),
        "domain": "",
        "mx_records": [],
        "gravatar": None,
        "candidates": build_email_candidates(query),
        "candidate_signals": [],
        "breaches": [],
    }

    if not result["is_email"]:
        result["candidate_signals"] = check_email_candidates(result["candidates"][:20], timeout=timeout)
        return result

    domain = email.split("@", 1)[1]
    result["domain"] = domain

    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception:
        try:
            socket.gethostbyname(domain)
            result["mx_records"] = ["domain-resolves-without-mx"]
        except Exception:
            result["mx_records"] = []

    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    try:
        response = requests.get(gravatar_url, timeout=timeout, allow_redirects=False)
        result["gravatar"] = {
            "url": f"https://www.gravatar.com/{digest}",
            "exists": response.status_code == 200,
            "http_status": response.status_code,
        }
    except requests.RequestException as exc:
        result["gravatar"] = {"url": f"https://www.gravatar.com/{digest}", "exists": None, "error": type(exc).__name__}

    try:
        from .breach import check_breaches
        result["breaches"] = [asdict(b) for b in check_breaches(email)]
    except Exception:
        pass

    return result


def check_email_candidates(candidates: List[str], timeout: int = 8) -> List[Dict[str, object]]:
    signals = []
    for email in candidates:
        digest = hashlib.md5(email.lower().encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{digest}?d=404"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            if response.status_code == 200:
                signals.append({
                    "email": email,
                    "source": "Gravatar",
                    "status": "possible",
                    "url": f"https://www.gravatar.com/{digest}",
                })
        except requests.RequestException:
            continue
    return signals


def build_trace_leads(query: str) -> List[Dict[str, str]]:
    target = build_identity_target(query)
    encoded = target.search_query
    leads = [{"name": item["name"], "url": item["url"].format(query=encoded)} for item in SEARCH_LEADS]
    for handle in normalize_handles(query)[:8]:
        h = quote_plus(handle)
        leads.extend([
            {"name": f"Exact handle: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22"},
            {"name": f"Code trace: {handle}", "url": f"https://github.com/search?q=%22{h}%22&type=code"},
            {"name": f"Paste trace: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+%28pastebin+OR+gist%29"},
        ])
    return leads


def run_full_scan(
    query: str,
    timeout: int = 8,
    workers: int = 24,
    on_result: Callable[[ProfileFinding], None] | None = None,
    use_rust: bool = True,
    proxy: Optional[str] = None,
    retry: int = 1,
    check_phone: bool = False,
    check_domain: bool = False,
    generate_html: bool = False,
    html_output: str = "",
) -> Dict[str, object]:
    profiles = scan_usernames(query, timeout=timeout, workers=workers, on_result=on_result, use_rust=use_rust, proxy=proxy, retry=retry)
    data = {
        "query": query,
        "handles": normalize_handles(query),
        "profiles": [asdict(item) for item in profiles],
        "email": inspect_email(query, timeout=timeout),
        "trace_leads": build_trace_leads(query),
        "summary": {
            "hits": sum(1 for item in profiles if item.status == "hit"),
            "possible": sum(1 for item in profiles if item.status == "possible"),
            "unknown": sum(1 for item in profiles if item.status == "unknown"),
            "checked": len(profiles),
        },
    }

    if check_phone and any(c.isdigit() for c in query):
        try:
            from .phone import analyze_phone
            data["phone"] = analyze_phone(query)
        except Exception:
            pass

    if check_domain and "." in query and not query.startswith("@"):
        try:
            from .domain_intel import analyze_domain
            data["domain"] = analyze_domain(query.split("@")[-1])
        except Exception:
            pass

    data["analysis"] = analyze_scan(data)

    if generate_html or html_output:
        try:
            from .reporter import generate_html_report
            path = html_output or f"osint_report_{query.replace('@','').replace('.','_')}.html"
            generate_html_report(data, path)
            data["html_report"] = path
        except Exception as e:
            data["html_report_error"] = str(e)

    return data
