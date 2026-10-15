from __future__ import annotations

import hashlib
import re
import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Callable, List, Dict, Optional
from urllib.parse import quote_plus

import requests

from .analyzer import analyze_scan
from .identity import build_identity_target
from .mutations import build_email_candidates, split_identity, build_username_variants
from .sources import SEARCH_LEADS, get_social_sources
from .progress import StepLogger, make_step_callback


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Mirrors the Rust engine verdict tables (osint_checker.rs).
NOT_FOUND_MARKERS = [
    "not found", "page not found", "user not found", "doesn't exist",
    "does not exist", "couldn't find", "couldn't be found", "isn't available",
    "no user found", "profile not found", "account not found",
    "this page doesn't exist", "cannot find", "we couldn't find",
    "no results", "sorry, this page", "this account doesn't exist",
    "couldn't find this account", "content is not available",
    "this profile may have been removed", "the link you followed may be broken",
    "no user with this username",
]

BLOCKED_WALL_MARKERS = [
    "checking your browser before accessing", "please verify you are a human",
    "verify you are human", "complete the security check",
    "are you a robot", "captcha", "recaptcha", "just a moment",
    "client challenge", "making sure you're not a bot",
    "verifying your browser", "perimeterx", "datadome", "arkose",
    "human verification",
]

GENERIC_LANDING_MARKERS = [
    "log in", "sign in", "sign up", "join conversation", "join group chat",
    "share on whatsapp", "contact on signal", "dashboard", "official site",
    "search results", "search result", "results for",
]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


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


def normalize_handles(query: str, deep: bool = False) -> List[str]:
    if not query or not str(query).strip():
        return []
    target = build_identity_target(query)
    handles = [target.canonical_handle] if target.canonical_handle else []
    handles.extend(target.aliases)
    if deep and target.canonical_handle:
        handles.extend(build_username_variants(target.canonical_handle, deep=True))
    seen = set()
    unique = []
    for h in handles:
        if h and h not in seen:
            seen.add(h)
            unique.append(h)
    return unique[:16]


def _request_profile(session: requests.Session, source: Dict[str, str], handle: str, timeout: int) -> ProfileFinding:
    url = source["url"].format(username=handle)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        code = response.status_code
        text = response.text[:8000].lower()
        metadata = _extract_metadata(response.text[:20000])
        title = metadata["title"]
        norm_title = _norm(title)
        norm_handle = _norm(handle)

        if any(marker in text for marker in NOT_FOUND_MARKERS):
            return ProfileFinding(source["name"], source["category"], handle, url, "miss", "low", code, "not-found marker", title, metadata["description"])

        if any(marker in text for marker in BLOCKED_WALL_MARKERS):
            return ProfileFinding(source["name"], source["category"], handle, url, "unknown", "low", code, "blocked/WAF wall", title, metadata["description"])

        if code == 200:
            # Smart verdict: search/landing pages mention the handle but
            # are not profiles — demote before the handle check.
            if title and any(marker in title.lower() for marker in GENERIC_LANDING_MARKERS):
                return ProfileFinding(source["name"], source["category"], handle, response.url, "possible", "low", code, "landing/search page", title, metadata["description"])
            # The title must mention the handle, else only a candidate.
            if norm_handle and norm_title and norm_handle in norm_title:
                return ProfileFinding(source["name"], source["category"], handle, response.url, "hit", "high", code, "title matched (handle)", title, metadata["description"])
            # Canonical-slug check: redirected to a different slug = miss.
            slug = _norm(response.url.rstrip("/").split("/")[-1].split("?")[0].split("#")[0])
            if norm_handle and slug and len(slug) >= 3 and norm_handle not in slug and slug not in norm_handle:
                if any(marker in text for marker in ("login", "sign in", "sign up", "join")):
                    return ProfileFinding(source["name"], source["category"], handle, response.url, "miss", "low", code, "redirected to login wall", title, metadata["description"])
            if title:
                return ProfileFinding(source["name"], source["category"], handle, response.url, "possible", "low", code, "title found (handle absent)", title, metadata["description"])
            return ProfileFinding(source["name"], source["category"], handle, response.url, "possible", "low", code, "200 OK, no title", title, metadata["description"])

        if code in (301, 302, 303, 307, 308):
            return ProfileFinding(source["name"], source["category"], handle, response.url, "possible", "low", code, "redirect")

        if code in (401, 403, 429):
            return ProfileFinding(source["name"], source["category"], handle, url, "unknown", "low", code, "blocked/rate-limited")

        return ProfileFinding(source["name"], source["category"], handle, url, "miss", "low", code)
    except requests.RequestException as exc:
        return ProfileFinding(source["name"], source["category"], handle, url, "unknown", "low", None, type(exc).__name__)


def scan_usernames_rust(
    query: str, proxy: Optional[str] = None, retry: int = 1, timeout: int = 15,
    workers: int = 50, on_result: Callable[[ProfileFinding], None] | None = None,
    on_step: Callable[[str, str], None] | None = None,
) -> List[ProfileFinding]:
    from .go_bridge import check_username
    data = check_username(query, proxy=proxy, retry=retry, timeout=timeout, workers=workers)
    results = data.get("results") or []
    if data.get("error") or not results:
        # Smart fallback: broken native sweep -> built-in sweep.
        if on_step:
            on_step("warn", "Sweep engine unavailable, using built-in sweep")
        raise RuntimeError(f"sweep engine unavailable: {data.get('error') or 'empty results'}")
    findings = []
    for r in results:
        finding = ProfileFinding(
            platform=r.get("platform", ""), category=r.get("category", ""),
            handle=query, url=r.get("url", ""), status=r.get("status", "unknown"),
            confidence=str(r.get("confidence", 0)), http_status=r.get("http_status"),
            note=r.get("note", ""), title=r.get("title", ""),
            description=r.get("description", ""),
        )
        findings.append(finding)
        if on_result:
            on_result(finding)
        if on_step:
            on_step("tick", f"{finding.platform} [{finding.status}]")
    order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
    return sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))


def scan_usernames(
    query: str, timeout: int = 8, workers: int = 24,
    on_result: Callable[[ProfileFinding], None] | None = None,
    use_rust: bool = True, proxy: Optional[str] = None, retry: int = 1,
    deep: bool = False, on_step: Callable[[str, str], None] | None = None,
) -> List[ProfileFinding]:
    if use_rust:
        # Sweep the canonical handle (no spaces) so the engine starts
        # immediately; deep mode adds the top alias variants.
        handles = normalize_handles(query, deep=deep)
        if not handles:
            handles = [re.sub(r"\s+", "", (query or "").strip().lower())]
        sweep_handles = handles[:4] if deep else handles[:1]
        try:
            merged: List[ProfileFinding] = []
            for h in sweep_handles:
                if on_step and len(sweep_handles) > 1:
                    on_step("note", f"Sweeping variant: {h}")
                merged.extend(scan_usernames_rust(h, proxy=proxy, retry=retry, timeout=max(timeout, 10), workers=workers, on_result=on_result, on_step=on_step))
            seen_urls, deduped = set(), []
            for f in merged:
                if f.url not in seen_urls:
                    seen_urls.add(f.url)
                    deduped.append(f)
            order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
            return sorted(deduped, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))
        except Exception:
            pass

    handles = normalize_handles(query, deep=deep)
    if not handles:
        handles = [re.sub(r"\s+", "", (query or "").strip().lower())]
    # Cap the built-in sweep so deep mode stays interactive.
    handles = handles[:6]
    sources = get_social_sources()
    findings: List[ProfileFinding] = []
    total = len(handles) * len(sources)
    if on_step:
        on_step("note", f"Built-in sweep: {len(handles)} handle(s) x {len(sources)} sources = {total} probes")

    with requests.Session() as session:
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_request_profile, session, source, handle, timeout)
                for handle in handles for source in sources
            ]
            # Overall deadline so one stalled connection cannot hang the scan.
            deadline = timeout * 4 + 60
            done, pending = concurrent.futures.wait(futures, timeout=deadline)
            for f in pending:
                f.cancel()
            checked = 0
            for future in done:
                try:
                    finding = future.result(timeout=5)
                except Exception:
                    continue
                findings.append(finding)
                checked += 1
                if on_result:
                    on_result(finding)
                if on_step and (checked == 1 or checked % 25 == 0 or checked >= len(done)):
                    on_step("tick", f"{finding.platform} [{finding.status}]|{checked}|{len(done)}")

    order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
    return sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))


def inspect_email(query: str, timeout: int = 8) -> Dict[str, object]:
    email = query.strip().lower()
    result: Dict[str, object] = {
        "input": query, "is_email": bool(EMAIL_RE.match(email)),
        "domain": "", "mx_records": [], "gravatar": None,
        "candidates": build_email_candidates(query),
        "candidate_signals": [], "breaches": [], "pgp_key": None,
        "google_traces": [], "social_by_email": [], "mx_secure": False,
    }

    if not result["is_email"]:
        result["candidate_signals"] = check_email_candidates(result["candidates"][:30], timeout=timeout)
        return result

    domain = email.split("@", 1)[1]
    result["domain"] = domain

    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = sorted([str(r.exchange).rstrip(".") for r in answers])
        result["mx_records"] = mx_list
        secure_providers = ["google.com", "outlook.com", "protonmail", "microsoft.com", "zoho.com"]
        for mx in mx_list:
            if any(sp in mx.lower() for sp in secure_providers):
                result["mx_secure"] = True
                break
    except Exception:
        try:
            socket.gethostbyname(domain)
            result["mx_records"] = ["domain-resolves-without-mx"]
        except Exception:
            result["mx_records"] = []

    digest = hashlib.md5(email.encode("utf-8")).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404&s=200"
    try:
        resp = requests.get(gravatar_url, timeout=timeout, allow_redirects=False)
        gravatar_exists = resp.status_code == 200
        result["gravatar"] = {
            "url": f"https://www.gravatar.com/{digest}",
            "image": f"https://www.gravatar.com/avatar/{digest}?s=200",
            "exists": gravatar_exists,
            "http_status": resp.status_code,
        }
        if gravatar_exists and resp.headers.get("X-Gravatar-Profile"):
            result["gravatar"]["profile"] = resp.headers["X-Gravatar-Profile"]
    except:
        result["gravatar"] = {"url": f"https://www.gravatar.com/{digest}", "exists": None}

    try:
        from .breach import check_breaches
        result["breaches"] = [asdict(b) for b in check_breaches(email)]
    except:
        pass

    try:
        servers = ["https://keyserver.ubuntu.com", "https://pgp.mit.edu"]
        for server in servers:
            pgp_url = f"{server}/pks/lookup?op=get&search={email}"
            resp = requests.get(pgp_url, timeout=timeout)
            if resp.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in resp.text:
                result["pgp_key"] = f"PGP key found on {server}"
                break
    except:
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
                    "email": email, "source": "Gravatar",
                    "status": "possible", "url": f"https://www.gravatar.com/{digest}",
                })
        except:
            continue
    return signals


def build_trace_leads(query: str) -> List[Dict[str, str]]:
    target = build_identity_target(query)
    encoded = target.search_query
    leads = [{"name": item["name"], "url": item["url"].format(query=encoded)} for item in SEARCH_LEADS]
    for handle in normalize_handles(query)[:5]:
        h = quote_plus(handle)
        leads.extend([
            {"name": f"🔍 Exact handle: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22"},
            {"name": f"🔍 Bing handle: {handle}", "url": f"https://www.bing.com/search?q=%22{h}%22"},
            {"name": f"🔍 Yandex handle: {handle}", "url": f"https://yandex.com/search/?text=%22{h}%22"},
            {"name": f"💻 GitHub code: {handle}", "url": f"https://github.com/search?q=%22{h}%22&type=code"},
            {"name": f"💻 GitLab code: {handle}", "url": f"https://gitlab.com/search?search=%22{h}%22"},
            {"name": f"📋 Pastebin: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+site%3Apastebin.com"},
            {"name": f"📋 Rentry: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+site%3Arentry.co"},
            {"name": f"📧 Email leak: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+%40+leak+breach"},
            {"name": f"📱 Phone: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+phone+number+whatsapp"},
            {"name": f"📍 Address: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+address+street+home"},
            {"name": f"🌐 All social: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+instagram+twitter+facebook+tiktok+linkedin"},
            {"name": f"💼 Job: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+resume+CV+linkedin+career"},
            {"name": f"🎓 Edu: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+school+university+college+student"},
            {"name": f"📰 News: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+news+article+report"},
            {"name": f"🔒 Breach: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+breach+leak+dump+password"},
            {"name": f"🕸️ Deep web: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+darknet+onion+darkweb"},
            {"name": f"📄 Documents: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+filetype%3Apdf+OR+filetype%3Adoc+OR+filetype%3Atxt"},
            {"name": f"💬 Forums: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+forum+thread+member+profile"},
            {"name": f"🏛️ Public records: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+bio+about+profile+public+record"},
            {"name": f"🔗 Site: {handle}", "url": f"https://www.google.com/search?q=%22{h}%22+site+\"com\"+OR+site+\"org\"+OR+site+\"io\""},
        ])
    return leads


def correlate_profiles(profiles: List[Dict[str, object]]) -> Dict[str, object]:
    """Cross-signal correlation: same title/persona across platforms.

    Hits sharing an identical normalized title are almost certainly the
    same person — this is the strongest signal and boosts confidence.
    """
    from collections import Counter
    hits = [p for p in profiles if p.get("status") == "hit"]
    title_groups: Dict[str, List[str]] = {}
    for p in hits:
        t = _norm(str(p.get("title", ""))[:80])
        if len(t) >= 4:
            title_groups.setdefault(t, []).append(str(p.get("platform", "?")))
    shared = {t: plats for t, plats in title_groups.items() if len(plats) >= 2}
    personae = sorted(shared.items(), key=lambda kv: -len(kv[1]))[:5]
    cats = Counter(p.get("category", "Unknown") for p in hits)
    return {
        "shared_title_clusters": [
            {"title_key": t, "count": len(plats), "platforms": plats[:8]}
            for t, plats in personae
        ],
        "cross_platform_personae": len(shared),
        "strongest_persona": (
            {"title_key": personae[0][0], "platforms": personae[0][1][:8]}
            if personae else None
        ),
        "category_breadth": len(cats),
    }


def run_full_scan(
    query: str, timeout: int = 8, workers: int = 24,
    on_result: Callable[[ProfileFinding], None] | None = None,
    use_rust: bool = True, proxy: Optional[str] = None, retry: int = 1,
    check_phone: bool = False, check_domain: bool = False,
    generate_html: bool = False, html_output: str = "",
    verbose: bool = True, deep: bool = False,
    on_step: Callable[[str, str], None] | None = None,
) -> Dict[str, object]:
    query = (query or "").strip()
    log = StepLogger(verbose=verbose)
    if on_step is None:
        on_step = make_step_callback(log)
    target = build_identity_target(query)
    sources = get_social_sources()
    handles = normalize_handles(query, deep=deep)

    log.phase(1, 8, "Identity parsing",
              f"canonical={handles[0] if handles else 'N/A'} (+{len(handles) - 1} variants)" if handles else "no handle")
    sweep_n = min(len(handles), 4) if deep else min(len(handles), 1)
    log.phase(2, 8, "Username sweep", f"{sweep_n} handle(s) x {len(sources)} sources")
    profiles = scan_usernames(query, timeout=timeout, workers=workers, on_result=on_result,
                              use_rust=use_rust, proxy=proxy, retry=retry,
                              deep=deep, on_step=on_step)
    n_hit = sum(1 for p in profiles if p.status == "hit")
    log.done(f"{n_hit} hits / {len(profiles)} checked")

    data = {
        "query": query, "handles": handles,
        "display_name": target.display_name, "first_name": target.first_name,
        "last_name": target.last_name, "middle_name": target.middle_name,
        "name_parts": target.name_parts, "initials": target.initials,
        "reversed_name": target.reversed_name, "aliases": target.aliases,
        "title": target.title, "suffix": target.suffix, "name_format": target.name_format,
        "profiles": [asdict(item) for item in profiles],
        "email": {},
        "trace_leads": [],
        "source_count": len(sources),
        "summary": {
            "hits": sum(1 for item in profiles if item.status == "hit"),
            "possible": sum(1 for item in profiles if item.status == "possible"),
            "unknown": sum(1 for item in profiles if item.status == "unknown"),
            "checked": len(profiles),
        },
    }

    log.phase(3, 8, "Email intelligence", "MX + Gravatar + breach + PGP")
    data["email"] = inspect_email(query, timeout=timeout)
    _email = data["email"]
    log.done(f"breaches={len(_email.get('breaches', []) or [])} gravatar={(_email.get('gravatar') or {}).get('exists')}")

    log.phase(4, 8, "Trace leads", "search-engine dork matrix")
    data["trace_leads"] = build_trace_leads(query)
    log.done(f"{len(data['trace_leads'])} leads")

    if check_phone and any(c.isdigit() for c in query):
        log.phase(5, 8, "Phone intelligence", "carrier + social + web mentions")
        try:
            from .phone import analyze_phone
            data["phone"] = analyze_phone(query)
            log.done(f"{data['phone'].get('country', '?')} / {data['phone'].get('carrier', '?')}")
        except Exception as exc:
            log.done(f"skipped ({exc})")
    else:
        log.phase(5, 8, "Phone intelligence", "skipped — no digits in query")

    if check_domain and "." in query and not query.startswith("@"):
        log.phase(6, 8, "Domain intelligence", "WHOIS + DNS + robtex")
        try:
            from .domain_intel import analyze_domain
            data["domain"] = analyze_domain(query.split("@")[-1])
            log.done(f"registrar={data['domain'].get('registrar', '?')}")
        except Exception as exc:
            log.done(f"skipped ({exc})")
    else:
        log.phase(6, 8, "Domain intelligence", "skipped — use --domain for FQDN targets")

    log.phase(7, 8, "Metadata & history", "wayback + cache + pastebin + github")
    try:
        from .metadata import extract_all
        data["metadata"] = extract_all(query)
        wb = (data["metadata"].get("wayback") or {}).get("total_archived", 0)
        log.done(f"wayback={wb} snapshots")
    except Exception as exc:
        log.done(f"skipped ({exc})")

    log.phase(8, 8, "Correlation & scoring", "cross-platform personae + confidence")
    data["correlation"] = correlate_profiles(data["profiles"])
    data["analysis"] = analyze_scan(data)
    log.done(f"confidence={data['analysis'].get('confidence')} ({data['analysis'].get('confidence_score')}/100)")
    log.report()

    if generate_html or html_output:
        try:
            from .reporter import generate_html_report
            safe = re.sub(r'[^\w]', '_', query)[:50]
            path = html_output or f"osint_report_{safe}.html"
            generate_html_report(data, path)
            data["html_report"] = path
        except Exception as e:
            data["html_report_error"] = str(e)

    return data
