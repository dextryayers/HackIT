"""Live public-intelligence collectors — no API keys, public endpoints only.

Each collector is best-effort: a failure or timeout yields an empty result and
never aborts the scan. Everything here is data a platform serves publicly.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA, "Accept": "application/json, text/plain, */*"}
TIMEOUT = 10


def _get_json(url: str, timeout: int = TIMEOUT, headers: Optional[dict] = None):
    resp = requests.get(url, headers=headers or HEADERS, timeout=timeout,
                        allow_redirects=True)
    if resp.status_code != 200:
        return None
    ctype = resp.headers.get("Content-Type", "")
    if "json" not in ctype and not resp.text.lstrip().startswith(("{", "[")):
        return None
    try:
        return resp.json()
    except Exception:
        return None


def collect_github(handle: str) -> dict | None:
    user = _get_json(f"https://api.github.com/users/{handle}")
    if not user or not user.get("login"):
        return None
    repos = _get_json(f"https://api.github.com/users/{handle}/repos?sort=updated&per_page=5") or []
    return {
        "source": "GitHub", "url": user.get("html_url", ""),
        "name": user.get("name") or user.get("login"),
        "bio": user.get("bio") or "", "company": user.get("company") or "",
        "location": user.get("location") or "", "blog": user.get("blog") or "",
        "email": user.get("email") or "", "avatar": user.get("avatar_url", ""),
        "followers": user.get("followers", 0), "public_repos": user.get("public_repos", 0),
        "created_at": (user.get("created_at") or "")[:10],
        "recent_repos": [r.get("name") for r in repos if r.get("name")][:5],
    }


def collect_gitlab(handle: str) -> dict | None:
    users = _get_json(f"https://gitlab.com/api/v4/users?username={handle}")
    if not users or not isinstance(users, list):
        return None
    user = users[0]
    return {
        "source": "GitLab", "url": user.get("web_url", ""),
        "name": user.get("name") or user.get("username"),
        "bio": user.get("bio") or "", "location": user.get("location") or "",
        "created_at": (user.get("created_at") or "")[:10],
    }


def collect_reddit(handle: str) -> dict | None:
    data = _get_json(f"https://www.reddit.com/user/{handle}/about.json",
                     headers={**HEADERS, "User-Agent": "hackit-osint/3.0"})
    if not data:
        return None
    info = (data.get("data") or {})
    if not info.get("name") or info.get("is_suspended"):
        return None
    return {
        "source": "Reddit", "url": f"https://www.reddit.com/user/{info['name']}",
        "name": info.get("name"), "bio": info.get("subreddit", {}).get("public_description", "") or "",
        "karma": info.get("total_karma", 0), "created_at": time.strftime(
            "%Y-%m-%d", time.gmtime(info.get("created_utc", 0))) if info.get("created_utc") else "",
        "avatar": (info.get("snoovatar_img") or ""),
    }


def collect_keybase(handle: str) -> dict | None:
    data = _get_json(f"https://keybase.io/_/api/1.0/user/lookup.json?username={handle}")
    if not data or not data.get("them"):
        return None
    them = data["them"][0]
    proofs = [p.get("nametag") or p.get("username") for p in
              ((them.get("proofs_summary") or {}).get("all") or [])]
    profile = them.get("profile") or {}
    return {
        "source": "Keybase", "url": f"https://keybase.io/{handle}",
        "name": profile.get("full_name") or handle,
        "bio": profile.get("bio") or "", "location": profile.get("location") or "",
        "proofs": [p for p in proofs if p][:10],
    }


def collect_gravatar(handle: str) -> dict | None:
    for candidate in (handle, f"{handle}@gmail.com"):
        digest = hashlib.md5(candidate.lower().encode()).hexdigest()
        data = _get_json(f"https://www.gravatar.com/{digest}.json")
        if not data or not data.get("entry"):
            continue
        entry = data["entry"][0]
        return {
            "source": "Gravatar", "url": entry.get("profileUrl", ""),
            "name": (entry.get("name") or {}).get("formatted", "") or entry.get("displayName", ""),
            "bio": entry.get("aboutMe", "")[:300], "location": entry.get("currentLocation", ""),
            "avatar": entry.get("thumbnailUrl", ""),
            "accounts": [a.get("shortname") for a in entry.get("accounts", []) if a.get("shortname")][:10],
        }
    return None


def collect_mastodon(handle: str) -> dict | None:
    data = _get_json(f"https://mastodon.social/api/v1/accounts/lookup?acct={handle}")
    if not data or not data.get("username"):
        return None
    return {
        "source": "Mastodon", "url": data.get("url", ""),
        "name": data.get("display_name") or data.get("username"),
        "bio": data.get("note", "")[:300], "followers": data.get("followers_count", 0),
        "created_at": (data.get("created_at") or "")[:10],
        "avatar": data.get("avatar", ""),
    }


def collect_crtsh(domain: str) -> List[dict]:
    data = _get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
    if not data or not isinstance(data, list):
        return []
    seen, subdomains = set(), []
    host_re = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if (name.endswith(domain) and name not in seen
                    and host_re.match(name) and " " not in name):
                seen.add(name)
                subdomains.append({"host": name,
                                   "first_seen": (row.get("not_before") or "")[:10]})
    subdomains.sort(key=lambda s: s["host"])
    return subdomains[:60]


def collect_dns(domain: str) -> dict:
    result = {"A": [], "MX": [], "TXT": [], "NS": []}
    for rtype in result:
        data = _get_json(f"https://dns.google/resolve?name={domain}&type={rtype}")
        if not data:
            continue
        for answer in data.get("Answer") or []:
            value = str(answer.get("data", "")).strip().strip('"')
            if value and value not in result[rtype]:
                result[rtype].append(value)
    return result


def collect_ip_geo(domain: str) -> dict | None:
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return None
    data = _get_json(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as")
    if not data or data.get("status") != "success":
        return None
    return {"ip": ip, "country": data.get("country", ""),
            "region": data.get("regionName", ""), "city": data.get("city", ""),
            "isp": data.get("isp", ""), "org": data.get("org", ""),
            "asn": data.get("as", "")}


_PROFILE_COLLECTORS = {
    "github": collect_github,
    "gitlab": collect_gitlab,
    "reddit": collect_reddit,
    "keybase": collect_keybase,
    "gravatar": collect_gravatar,
    "mastodon": collect_mastodon,
}


def collect_live_intel(
    handles: List[str],
    domain: str = "",
    on_found: Callable[[dict], None] | None = None,
    workers: int = 6,
    enabled: bool = True,
) -> Dict[str, object]:
    """Run all keyless collectors for the primary handles (and domain)."""
    out: Dict[str, object] = {
        "profiles": [], "subdomains": [], "dns": {}, "geo": {},
        "sources_checked": 0,
    }
    if not enabled:
        return out

    primary = [h for h in handles[:2] if h]
    tasks = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for handle in primary:
            for key, fn in _PROFILE_COLLECTORS.items():
                tasks[pool.submit(fn, handle)] = (key, handle)
            out["sources_checked"] += len(_PROFILE_COLLECTORS)
        if domain:
            tasks[pool.submit(collect_crtsh, domain)] = ("crtsh", domain)
            tasks[pool.submit(collect_dns, domain)] = ("dns", domain)
            tasks[pool.submit(collect_ip_geo, domain)] = ("geo", domain)
            out["sources_checked"] += 3

        for future in as_completed(tasks):
            key, handle = tasks[future]
            try:
                result = future.result()
            except Exception:
                continue
            if not result:
                continue
            if key == "crtsh":
                out["subdomains"] = result
            elif key == "dns":
                out["dns"] = result
            elif key == "geo":
                out["geo"] = result
            else:
                out["profiles"].append(result)
                if on_found:
                    try:
                        on_found(result)
                    except Exception:
                        pass

    order = {"GitHub": 0, "GitLab": 1, "Keybase": 2, "Reddit": 3,
             "Mastodon": 4, "Gravatar": 5}
    out["profiles"].sort(key=lambda p: order.get(p.get("source", ""), 9))
    return out


def verified_sources(live_intel: Dict[str, object]) -> set[str]:
    """Lower-cased source names confirmed by an API response."""
    return {str(p.get("source", "")).lower() for p in live_intel.get("profiles", [])}