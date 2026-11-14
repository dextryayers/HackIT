from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import concurrent.futures
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Callable, List, Dict, Optional
from urllib.parse import quote_plus

import random
import requests
from urllib.parse import urlparse

from .analyzer import analyze_scan
from .identity import build_identity_target
from .mutations import build_email_candidates, split_identity, build_username_variants
from .sources import SEARCH_LEADS, get_social_sources, is_profile_source
from .progress import StepLogger, make_step_callback


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SITES_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "go", "sites.json")
_SITE_RULES: Dict[str, dict] | None = None


def _site_rules() -> Dict[str, dict]:
    """Per-site verdict rules from sites.json, keyed by URL template."""
    global _SITE_RULES
    if _SITE_RULES is None:
        try:
            with open(SITES_JSON, encoding="utf-8") as fh:
                _SITE_RULES = {item["url"]: item for item in json.load(fh)}
        except Exception:
            _SITE_RULES = {}
    return _SITE_RULES


# Mirrors the Rust engine verdict tables (osint_checker.rs).
NOT_FOUND_MARKERS = [
    "not found", "page not found", "user not found", "doesn't exist",
    "does not exist", "couldn't find", "couldn't be found", "isn't available",
    "no user found", "profile not found", "account not found",
    "this page doesn't exist", "cannot find", "we couldn't find",
    "no results", "sorry, this page", "this account doesn't exist",
    "couldn't find this account", "content is not available",
    "this profile may have been removed", "the link you followed may be broken",
    "no user with this username", "nothing here", "no such user",
    "no profile", "user does not exist", "account suspended",
    "this user has been suspended", "page isn't available",
    "we can't find that page", "the page you requested could not be found",
    "does not use", "doesn't use", "has not joined", "is not a member",
    "no account with", "this username is available", "username is available",
    "not registered", "unclaimed", "no longer active",
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
    "search results", "search result", "results for", "browse fonts",
    "browse the web", "create your account", "get started", "download the app",
    "welcome to", "client challenge", "access denied",
]

# Platform shells that render 200 OK for every handle. A probe whose title is
# one of these carries no identity evidence and must not be reported as a hit.
SHELL_TITLES = {
    "", "home", "sign in", "sign up", "log in", "login", "register",
    "search", "explore", "discover", "welcome", "loading", "error",
    "page not found", "not found", "client challenge", "access denied",
    "just a moment", "attention required! | cloudflare",
}

# Titles that are pure platform branding — matched against the platform name.
BRAND_SUFFIXES = (
    " | facebook", " - facebook", " | instagram", " • instagram",
    " / x", " | twitter", " | linkedin", " - youtube", " | pinterest",
    " | tiktok", " - twitch", " | soundcloud", " | spotify",
)


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
    response_time: float = 0.0
    verified: bool = False


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


PHONE_RE = re.compile(r"^\+?[\d][\d\s().-]{6,}$")


def is_phone_query(query: str) -> bool:
    """True for a bare dialable number, not a handle that happens to be digits."""
    clean = (query or "").strip()
    if not PHONE_RE.match(clean):
        return False
    digits = re.sub(r"\D", "", clean)
    if len(digits) < 7 or len(digits) > 15:
        return False
    return clean.startswith("+") or len(digits) >= 9


DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.IGNORECASE)


def is_domain_query(query: str) -> bool:
    """True for a bare FQDN. ``torvalds.dev`` is a domain, not a handle."""
    clean = (query or "").strip().rstrip("/")
    return bool(DOMAIN_RE.match(clean))


def handle_seed(query: str) -> str:
    """The part of a target that actually behaves like a username.

    An email's local part is the handle; the domain is the footprint.
    """
    clean = (query or "").strip()
    if EMAIL_RE.match(clean):
        return clean.split("@", 1)[0]
    return clean


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


def _title_is_shell(title: str) -> bool:
    """True when a 200-OK page is a platform shell, not a profile."""
    clean = re.sub(r"\s+", " ", (title or "")).strip().lower()
    if clean in SHELL_TITLES:
        return True
    if any(clean.endswith(suffix) for suffix in BRAND_SUFFIXES):
        return True
    return any(marker in clean for marker in GENERIC_LANDING_MARKERS)


def _content_evidence(html: str, handle: str, display_name: str = "") -> list[str]:
    """Collect identity evidence from a profile page body.

    Only strong signals count: the handle in the title, og:url, canonical URL,
    an ``@handle`` mention, or the target's real name. A page that merely
    answers 200 OK proves nothing.
    """
    evidence: list[str] = []
    head = html[:60000]
    norm_handle = _norm(handle)
    title = _extract_between(head, r"<title[^>]*>(.*?)</title>")
    if norm_handle and norm_handle in _norm(title):
        evidence.append("title")
    for pattern, label in (
        (r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', "canonical"),
        (r'<meta[^>]+property=["\']og:url["\'][^>]+content=["\']([^"\']+)', "og:url"),
    ):
        match = re.search(pattern, head, re.IGNORECASE)
        if match and norm_handle and norm_handle in _norm(match.group(1)):
            evidence.append(label)
    if re.search(r"@" + re.escape(handle) + r"\b", head, re.IGNORECASE):
        evidence.append("handle mention")
    if display_name:
        norm_name = _norm(display_name)
        if len(norm_name) >= 5:
            og_title = _extract_between(
                head, r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']')
            if norm_name in _norm(og_title) or norm_name in _norm(title):
                evidence.append("real name")
    return evidence


def _verdict_by_title(title: str, handle: str) -> tuple[str, str, str]:
    """Fallback verdict when a site has no per-site rule.

    Order matters: shell pages are dead ends, handle evidence is a hit,
    and a 200 with no evidence is at best a weak ``possible``.
    """
    title_lower = (title or "").lower()
    if _title_is_shell(title):
        return "miss", "medium", "platform shell page"
    norm_title, norm_handle = _norm(title), _norm(handle)
    if norm_handle and norm_title and norm_handle in norm_title:
        return "hit", "high", "title matched (handle)"
    if not title:
        return "miss", "low", "200 OK, no title"
    return "possible", "low", "200 OK, no handle evidence"


def _apply_site_rules(rule: dict, code: int, text_lower: str, title: str,
                      handle: str, final_url: str, redirect_url: str) -> tuple[str, str, str] | None:
    """Apply the per-site rule set (sites.json) using the Rust detect() order.

    Returns (status, confidence, note) or None when the rules are indecisive.
    """
    miss_code = rule.get("miss_code") or []
    if code in miss_code:
        return "miss", "high", "not found (status code)"

    for marker in rule.get("miss_body") or []:
        if marker.lower() in text_lower:
            return "miss", "high", f"not found (body: {marker[:40]})"

    if any(marker in text_lower for marker in BLOCKED_WALL_MARKERS):
        return "unknown", "low", "blocked/WAF wall"

    if 300 <= code < 400:
        loc = (redirect_url or "").lower()
        if any(k in loc for k in ("login", "signin", "auth")):
            return "miss", "high", "redirected to login"
        if any(k in loc for k in ("search", "404")):
            return "miss", "high", "redirected to 404"
        return "possible", "medium", f"redirect: {final_url[:60]}"

    if code in (401, 403):
        return "unknown", "low", "blocked or private profile"
    if code == 429:
        return "unknown", "low", "rate limited"

    method = rule.get("method") or "status_code"
    if method == "title":
        check = (rule.get("title_check") or "").replace("{username}", handle)
        if check and check.lower() in title.lower():
            return "hit", "high", "title matched (handle)"
        if title and code == 200:
            return "possible", "low", "title found (handle absent)"
        return None
    if method == "body_text":
        hit_body = rule.get("hit_body")
        if hit_body and hit_body.lower() in text_lower:
            return "hit", "high", "hit text found"
        if code == 200:
            return "possible", "medium", "200 OK"
        return None

    hit_code = rule.get("hit_code") or 200
    if code == hit_code or code == 200:
        return _verdict_by_title(title, handle)
    return None


def _retry_delay(attempt: int, response: "requests.Response | None" = None) -> float:
    """Backoff with jitter; honours Retry-After when the platform sends one."""
    base = min(0.5 * (2 ** attempt), 8.0) + random.uniform(0, 0.35)
    ra = response.headers.get("Retry-After") if response is not None else None
    if ra:
        try:
            return max(base, min(float(ra), 30.0))
        except ValueError:
            pass
    return base


def _same_site(host_a: str, host_b: str) -> bool:
    """True when both hosts share the same registered domain (www-stripped)."""
    def reg(h: str) -> str:
        parts = (h or "").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (h or "").lower()
    return reg(host_a) == reg(host_b) and bool(reg(host_a))


def _request_profile(session: requests.Session, source: Dict[str, str], handle: str,
                     timeout: int, retry: int = 0,
                     display_name: str = "") -> ProfileFinding:
    url = source["url"].format(username=handle)
    norm_handle = _norm(handle)
    rule = _site_rules().get(source["url"], {})
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    last_error = "unknown"
    for attempt in range(max(retry, 0) + 1):
        start = time.time()
        try:
            response = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            code = response.status_code
            # Transient trouble: back off and try again instead of recording noise.
            if (code == 429 or code >= 500) and attempt < retry:
                time.sleep(_retry_delay(attempt, response))
                continue
            text_lower = response.text[:8000].lower()
            metadata = _extract_metadata(response.text[:20000])
            title = metadata["title"]

            body = response.text[:120000]
            evidence = _content_evidence(body, handle, display_name)
            verdict = _apply_site_rules(
                rule, code, text_lower, title, handle,
                response.url, response.headers.get("Location", ""),
            )
            if verdict is None:
                # Rules indecisive: content-first heuristics.
                if any(marker in text_lower for marker in NOT_FOUND_MARKERS):
                    verdict = ("miss", "high", "not-found marker")
                elif any(marker in text_lower for marker in BLOCKED_WALL_MARKERS):
                    verdict = ("unknown", "low", "blocked/WAF wall")
                elif code == 429:
                    verdict = ("unknown", "low", "rate-limited (429)")
                elif _title_is_shell(title):
                    verdict = ("miss", "medium", "platform shell page")
                elif evidence:
                    verdict = ("hit", "high", "content evidence: " + ", ".join(evidence[:3]))
                elif code == 200:
                    # A real page still has to prove it belongs to the handle.
                    norm_body = _norm(body[:4000])
                    if norm_handle and norm_handle in norm_body:
                        verdict = ("hit", "medium", "handle in body")
                    elif len(body) > 4000:
                        verdict = ("possible", "low", "200 OK, no handle evidence")
                    else:
                        verdict = ("miss", "medium", "empty shell page")
                elif code in (301, 302, 303, 307, 308):
                    verdict = ("possible", "low", "redirect")
                else:
                    verdict = ("miss", "low", "status code")

            # A "hit" resting on generic evidence (title/body handle match) that
            # landed on a *different domain* than the source template is almost
            # always a redirect to an auth/landing page — not the profile.
            if verdict[0] == "hit":
                note_l = verdict[2].lower()
                generic_hit = (note_l.startswith("title matched")
                               or note_l.startswith("handle in body")
                               or note_l.startswith("200 ok")
                               or note_l.startswith("content evidence"))
                if generic_hit:
                    src_host = urlparse(source["url"]).hostname or ""
                    fin_host = urlparse(response.url).hostname or ""
                    if src_host and fin_host and not _same_site(src_host, fin_host):
                        verdict = ("possible", "low", f"cross-domain redirect ({fin_host})")

            status, confidence, note = verdict
            if attempt > 0:
                note = f"{note} (retry {attempt})"
            verified = status == "hit" and confidence == "high"
            finding = ProfileFinding(
                source["name"], source["category"], handle,
                response.url, status, confidence, code, note, title,
                metadata["description"], round(elapsed, 3), verified=verified,
            )
            return _veto_finding(finding)
        except requests.RequestException as exc:
            last_error = type(exc).__name__
            if attempt < retry:
                time.sleep(_retry_delay(attempt))
                continue
    return ProfileFinding(source["name"], source["category"], handle, url,
                          "unknown", "low", None, last_error)


NON_PROFILE_URL_PATTERNS = (
    "google.com/search", "bing.com/search", "search.yahoo.com", "yandex.com/search",
    "baidu.com/s", "sogou.com/web", "duckduckgo.com/?q", "searx.", "mojeek.com/search",
    "startpage.com", "search.brave.com", "socialmention.com",
    "fonts.google.com", "groups.google.com", "patents.google.com",
    "scholar.google.com", "meet.google.com", "docs.google.com",
    "archive.org/details", "archive.org/search", "web.archive.org/web/*",
    "mail-archive.com", "censys.io", "shodan.io", "onyphe.io", "dnslytics.com",
    "domaintools.com", "who.is", "whois.com", "whoisxmlapi.com", "robtex.com",
    "brand24.com", "talkwalker.com", "trendsmap.com", "tweetbinder.com",
    "crt.sh", "hackertarget.com", "rapiddns.io", "subdomain.center",
)


def _veto_finding(finding: "ProfileFinding") -> "ProfileFinding":
    """Downgrade engine hits that are really shells, aggregators or 404 pages.

    Both engines can return ``hit`` for a page that merely echoed the handle in
    a search box or a "does not use this service" notice. This is the single
    gate every finding passes through before it reaches the report.
    """
    url_low = (finding.url or "").lower()
    if any(pattern in url_low for pattern in NON_PROFILE_URL_PATTERNS):
        finding.status = "miss"
        finding.confidence = "high"
        finding.note = "aggregator/search endpoint, not a profile"
        finding.verified = False
        return finding

    if finding.status != "hit":
        finding.verified = False

    title = (finding.title or "").lower()
    if title:
        if any(marker in title for marker in NOT_FOUND_MARKERS):
            finding.status = "miss"
            finding.confidence = "high"
            finding.note = "not-found notice in title"
            finding.verified = False
            return finding
        if _title_is_shell(finding.title):
            finding.status = "miss"
            finding.confidence = "medium"
            finding.note = "platform shell page"
            finding.verified = False
            return finding
    return finding


def _confidence_label(value) -> str:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return "low"
    return "high" if score >= 85 else "medium" if score >= 50 else "low"


def scan_usernames_rust(
    query: str, proxy: Optional[str] = None, retry: int = 1, timeout: int = 15,
    workers: int = 50, on_result: Callable[[ProfileFinding], None] | None = None,
    on_step: Callable[[str, str], None] | None = None,
) -> List[ProfileFinding]:
    from .go_bridge import check_username
    findings: List[ProfileFinding] = []

    def _stream(item: dict) -> None:
        finding = ProfileFinding(
            platform=item.get("platform", ""), category=item.get("category", ""),
            handle=query, url=item.get("url", ""), status=item.get("status", "unknown"),
            confidence=_confidence_label(item.get("confidence")),
            http_status=item.get("http_status"), note=item.get("note", ""),
            title=item.get("title", ""), description=item.get("description", ""),
            response_time=float(item.get("response_time") or 0.0),
        )
        finding = _veto_finding(finding)
        findings.append(finding)
        if on_result:
            on_result(finding)
        if on_step:
            on_step("tick", f"{finding.platform} [{finding.status}]")

    data = check_username(query, proxy=proxy, retry=retry, timeout=timeout,
                          workers=workers, on_result=_stream)
    if data.get("error") or not findings:
        # Smart fallback: broken native sweep -> built-in sweep.
        if on_step:
            on_step("warn", "Sweep engine unavailable, using built-in sweep")
        raise RuntimeError(f"sweep engine unavailable: {data.get('error') or 'empty results'}")
    order = {"hit": 0, "possible": 1, "unknown": 2, "miss": 3}
    ranked = sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))
    seen, unique = set(), []
    for finding in ranked:
        key = (_norm(finding.platform), _norm(finding.handle))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def scan_usernames(
    query: str, timeout: int = 8, workers: int = 24,
    on_result: Callable[[ProfileFinding], None] | None = None,
    use_rust: bool = True, proxy: Optional[str] = None, retry: int = 1,
    deep: bool = False, on_step: Callable[[str, str], None] | None = None,
    category: str = "",
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
            # The native engine carries its own site table; drop aggregators here
            # so both engines honour the same source policy.
            merged = [f for f in merged if is_profile_source(f.url, f.platform)]
            if category:
                merged = [f for f in merged if f.category.lower() == category.lower()]
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
    if category:
        sources = [s for s in sources if s["category"].lower() == category.lower()]
    findings: List[ProfileFinding] = []
    display_name = build_identity_target(query).display_name
    total = len(handles) * len(sources)
    if on_step:
        on_step("note", f"Built-in sweep: {len(handles)} handle(s) x {len(sources)} sources = {total} probes")

    with requests.Session() as session:
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(_request_profile, session, source, handle, timeout,
                                retry, display_name)
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
    ranked = sorted(findings, key=lambda f: (order.get(f.status, 9), f.platform, f.handle))
    seen, unique = set(), []
    for finding in ranked:
        key = (_norm(finding.platform), _norm(finding.handle))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


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
    """Gravatar probe for guessed addresses.

    Candidates are independent, so they fan out concurrently — serially this
    was up to len(candidates) * timeout seconds of dead air (30 x 8s = 4min).
    """
    if not candidates:
        return []

    per_request = max(2.0, min(float(timeout), 6.0))

    def _probe(email: str) -> Dict[str, object] | None:
        digest = hashlib.md5(email.lower().encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{digest}?d=404"
        try:
            response = requests.get(url, timeout=per_request, allow_redirects=False)
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        return {
            "email": email, "source": "Gravatar",
            "status": "possible", "url": f"https://www.gravatar.com/{digest}",
        }

    signals: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as pool:
        for hit in pool.map(_probe, candidates):
            if hit:
                signals.append(hit)
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
    category: str = "",
) -> Dict[str, object]:
    query = (query or "").strip()
    log = StepLogger(verbose=verbose)
    if on_step is None:
        on_step = make_step_callback(log)
    target = build_identity_target(query)
    sources = get_social_sources()
    if category:
        sources = [s for s in sources if s["category"].lower() == category.lower()]
    phone_target = is_phone_query(query)
    domain_target = is_domain_query(query)
    no_sweep = phone_target or domain_target
    seed = handle_seed(query)
    handles = [] if no_sweep else normalize_handles(seed, deep=deep)

    log.phase(1, 9, "Identity parsing",
              f"canonical={handles[0] if handles else 'N/A'} (+{len(handles) - 1} variants)" if handles else "no handle")
    sweep_n = min(len(handles), 4) if deep else min(len(handles), 1)
    if no_sweep:
        # 790 username templates against a phone number or an FQDN only
        # produce noise; those targets have their own intelligence phase.
        reason = "phone target" if phone_target else "domain target"
        log.phase(2, 9, "Username sweep", f"skipped — {reason}")
        profiles = []
        log.done(f"skipped ({reason})")
    else:
        log.phase(2, 9, "Username sweep", f"{sweep_n} handle(s) x {len(sources)} sources")
        profiles = scan_usernames(seed, timeout=timeout, workers=workers, on_result=on_result,
                                  use_rust=use_rust, proxy=proxy, retry=retry,
                                  deep=deep, on_step=on_step, category=category)
        n_hit = sum(1 for p in profiles if p.status == "hit")
        log.done(f"{n_hit} hits / {len(profiles)} checked")

    data = {
        "schema": "hackit.osint.v4",
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
            "miss": sum(1 for item in profiles if item.status == "miss"),
            "verified": sum(1 for item in profiles if item.verified),
            "checked": len(profiles),
        },
    }

    if no_sweep:
        log.phase(3, 9, "Email intelligence", "skipped — no personal target")
        data["email"] = {}
    else:
        log.phase(3, 9, "Email intelligence", "MX + Gravatar + breach + PGP")
        data["email"] = inspect_email(query, timeout=timeout)
    _email = data["email"]
    log.done(f"breaches={len(_email.get('breaches', []) or [])} gravatar={(_email.get('gravatar') or {}).get('exists')}")

    # Upstream metadata/wayback phase keeps its own budget; the live-intel
    # phase above replaced the old step-4 slot, so run it before correlation.
    log.phase(4, 9, "Metadata & history", "wayback + pastebin + github")
    try:
        from .metadata import extract_all
        data["metadata"] = extract_all(query)
        wb = (data["metadata"].get("wayback") or {}).get("total_archived", 0)
        log.done(f"wayback={wb} snapshots")
    except Exception as exc:
        log.done(f"skipped ({exc})")

    log.phase(5, 9, "Live public intel", "keyless profile, domain and email collectors")
    try:
        from .live_sources import collect_live_intel, verified_sources

        domain = ""
        if EMAIL_RE.match(query):
            domain = query.split("@", 1)[1]
        elif "." in query and not query.startswith("@"):
            domain = query.split("/")[0].split("@")[-1]
        email = query if EMAIL_RE.match(query) else ""

        live = collect_live_intel(handles, domain=domain, email=email,
                                  workers=workers, timeout=timeout,
                                  handle_limit=2 if deep else 1)
        verified = verified_sources(live)
        verified_norm = {_norm(v) for v in verified}
        for profile in profiles:
            if _norm(profile.platform) in verified_norm and profile.status in ("hit", "possible"):
                profile.verified = True
                profile.status = "hit"
                profile.confidence = "high"
        data["live_intel"] = live
        data["profiles"] = [asdict(item) for item in profiles]
        data["summary"] = {
            "hits": sum(1 for item in profiles if item.status == "hit"),
            "possible": sum(1 for item in profiles if item.status == "possible"),
            "unknown": sum(1 for item in profiles if item.status == "unknown"),
            "miss": sum(1 for item in profiles if item.status == "miss"),
            "verified": sum(1 for item in profiles if item.verified),
            "checked": len(profiles),
        }
        log.done(f"{len(live.get('profiles', []))} verified profiles, "
                 f"{len(live.get('subdomains', []))} subdomains, "
                 f"{len(live.get('errors', []))} blocked")
    except Exception as exc:
        data["live_intel"] = {"profiles": [], "subdomains": [], "dns": {}, "geo": {},
                              "errors": [{"source": "live", "error": str(exc)}]}
        log.done(f"skipped ({exc})")

    log.phase(6, 9, "Trace leads", "search-engine dork matrix")
    data["trace_leads"] = build_trace_leads(query)
    log.done(f"{len(data['trace_leads'])} leads")

    if (check_phone or phone_target) and any(c.isdigit() for c in query):
        log.phase(7, 9, "Phone intelligence", "carrier + social + web mentions")
        try:
            from .phone import analyze_phone
            data["phone"] = analyze_phone(query)
            log.done(f"{data['phone'].get('country', '?')} / {data['phone'].get('carrier', '?')}")
        except Exception as exc:
            log.done(f"skipped ({exc})")
    else:
        log.phase(7, 9, "Phone intelligence", "skipped — no digits in query")

    if check_domain and "." in query and not query.startswith("@"):
        log.phase(8, 9, "Domain intelligence", "WHOIS + DNS + robtex")
        try:
            from .domain_intel import analyze_domain
            data["domain"] = analyze_domain(query.split("@")[-1])
            log.done(f"registrar={data['domain'].get('registrar', '?')}")
        except Exception as exc:
            log.done(f"skipped ({exc})")
    else:
        log.phase(8, 9, "Domain intelligence", "skipped — use --domain for FQDN targets")

    log.phase(9, 9, "Correlation & scoring", "cross-platform personae + confidence")
    data["correlation"] = correlate_profiles(data["profiles"])
    data["analysis"] = analyze_scan(data)
    # The JSON contract keeps the headline numbers in one place.
    summary = data.setdefault("summary", {})
    summary["sources"] = len(sources)
    summary["confidence"] = data["analysis"].get("confidence")
    summary["score"] = data["analysis"].get("confidence_score")
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
