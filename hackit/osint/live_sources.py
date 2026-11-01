"""HackIT OSINT v4 — keyless live-intelligence collectors.

Everything here reads a public endpoint that answers **without an API key**.
Each collector is best-effort and isolated: a failure, a timeout or a block
yields ``None`` and is recorded as an error, never as a finding.

Output contract
---------------
Every profile collector returns a dict shaped like::

    {
      "source": "GitHub",          # human label
      "kind": "profile",           # profile|social|code|gaming|media|messaging
      "url": "https://...",        # canonical public URL
      "name": "Linus Torvalds",
      "bio": "...",
      "location": "...",
      "created": "2011-09-03",
      "followers": 200000,
      "facts": {"company": "Linux Foundation", ...},   # free-form extras
      "evidence": ["bio", "location"],                 # why it matched
    }

Domain collectors fill ``domain`` buckets, email collectors fill ``email``.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional
from urllib.parse import quote

import requests

try:  # bs4 is already a project dependency for the web modules
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover - graceful degradation
    BeautifulSoup = None


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
JSON_HEADERS = {
    "User-Agent": UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}
HTML_HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 12

# Cloudflare / bot-wall fingerprints. Any hit means "we could not read this",
# never "the account does not exist".
BOT_WALL = (
    "just a moment", "checking your browser", "cf-browser-verification",
    "enable javascript and cookies", "making sure you're not a bot",
    "attention required! | cloudflare", "access denied", "captcha",
    "please verify you are a human", "client challenge", "challenge-platform",
    "ddos protection", "request unsuccessful", "unusual traffic",
)

# Titles that mean "the page rendered a shell, not a profile". A scrape that
# returns one of these is a dead end, never a finding.
GENERIC_TITLES = {
    "", "sign up", "sign in", "log in", "login", "register", "home",
    "welcome", "loading", "error", "not found", "page not found",
    "trakt web: profile", "profile", "user", "account", "search",
    "instagram", "pinterest", "tiktok", "twitter", "x", "facebook",
    "spotify", "soundcloud", "youtube", "twitch", "telegram", "vk",
    "replit", "linktree", "about.me", "substack", "goodreads", "wattpad",
    "last.fm", "pypi", "osu!", "anilist", "rumble", "bitchute",
}


# ───────────────────────────── HTTP helpers ─────────────────────────────

def _get(url: str, headers: Optional[dict] = None, timeout: int = TIMEOUT,
         method: str = "GET", **kwargs) -> Optional[requests.Response]:
    try:
        return requests.request(method, url, headers=headers or JSON_HEADERS,
                                timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None


def _json(url: str, headers: Optional[dict] = None, timeout: int = TIMEOUT,
          method: str = "GET", **kwargs):
    resp = _get(url, headers=headers, timeout=timeout, method=method, **kwargs)
    if resp is None or resp.status_code != 200:
        return None
    text = resp.text.lstrip()
    if not text:
        return None
    if not text.startswith(("{", "[")):
        ctype = resp.headers.get("Content-Type", "")
        if "json" not in ctype:
            return None
    try:
        return resp.json()
    except Exception:
        return None


def _html(url: str, timeout: int = TIMEOUT) -> Optional[requests.Response]:
    resp = _get(url, headers=HTML_HEADERS, timeout=timeout)
    if resp is None or resp.status_code >= 500:
        return None
    return resp


def _blocked(resp: requests.Response) -> bool:
    head = resp.text[:4000].lower()
    return any(marker in head for marker in BOT_WALL)


def _soup(resp: requests.Response):
    if BeautifulSoup is None:
        return None
    try:
        return BeautifulSoup(resp.text[:400000], "html.parser")
    except Exception:
        return None


def _meta(soup, *names: str) -> str:
    """Read the first non-empty og:/name: meta tag among *names*."""
    if soup is None:
        return ""
    for name in names:
        tag = soup.find("meta", attrs={"property": name}) or soup.find(
            "meta", attrs={"name": name})
        if tag and tag.get("content"):
            value = str(tag["content"]).strip()
            if value:
                return value
    return ""


def _title(soup) -> str:
    if soup is None or soup.title is None:
        return ""
    return re.sub(r"\s+", " ", soup.title.get_text(" ", strip=True))[:180]


def _text(resp: requests.Response, limit: int = 60000) -> str:
    return (resp.text or "")[:limit]


def _clean(value) -> str:
    if value in (None, "", 0, False):
        return ""
    text = re.sub(r"<[^>]+>", " ", str(value))
    return re.sub(r"\s+", " ", text).strip()[:300]


def _profile(source: str, kind: str, url: str, name: str = "", bio: str = "",
             location: str = "", created: str = "", followers=None,
             facts: Optional[dict] = None,
             evidence: Optional[List[str]] = None) -> dict:
    return {
        "source": source, "kind": kind, "url": url,
        "name": _clean(name), "bio": _clean(bio),
        "location": _clean(location), "created": _clean(created),
        "followers": followers if followers not in (None, "") else "",
        "facts": {k: _clean(v) for k, v in (facts or {}).items() if _clean(v)},
        "evidence": evidence or [],
    }


def _scraped_identity(title: str, handle: str, *extra: str) -> bool:
    """True when a scraped page is a real profile page for *handle*.

    Rejects shell pages (``Sign Up``, ``Client Challenge``, platform slogans)
    and pages that never mention the handle or the expected identity.
    """
    clean = re.sub(r"\s+", " ", (title or "")).strip()
    if clean.lower().strip(" |-·:") in GENERIC_TITLES:
        return False
    haystack = " ".join([clean, *(e or "" for e in extra)]).lower()
    if handle.lower() in haystack:
        return True
    # Some platforms title the page with a display name only; require the
    # caller to have supplied an extra signal in that case.
    return False


def _looks_missing(text: str) -> bool:
    head = (text or "")[:6000].lower()
    return any(marker in head for marker in (
        "page not found", "user not found", "couldn't find", "could not find",
        "doesn't exist", "does not exist", "no longer available",
        "this account doesn't exist", "sorry, this page isn't available",
        "profile not found", "404 not found",
    ))


# ───────────────────────────── profile APIs ─────────────────────────────

def collect_github(handle: str) -> dict | None:
    user = _json(f"https://api.github.com/users/{handle}")
    if not user or not user.get("login"):
        return None
    repos = _json(f"https://api.github.com/users/{handle}/repos?sort=updated&per_page=6") or []
    events = _json(f"https://api.github.com/users/{handle}/events/public?per_page=5") or []
    return _profile(
        "GitHub", "code", user.get("html_url", ""),
        name=user.get("name") or user.get("login"),
        bio=user.get("bio") or "",
        location=user.get("location") or "",
        created=(user.get("created_at") or "")[:10],
        followers=user.get("followers", 0),
        facts={
            "company": user.get("company") or "",
            "blog": user.get("blog") or "",
            "public_email": user.get("email") or "",
            "twitter": user.get("twitter_username") or "",
            "repos": user.get("public_repos", 0),
            "gists": user.get("public_gists", 0),
            "following": user.get("following", 0),
            "recent_repos": ", ".join(r.get("name", "") for r in repos[:6] if r.get("name")),
            "recent_events": ", ".join(
                sorted({str(e.get("type", "")).replace("Event", "")
                        for e in events if e.get("type")})),
        },
        evidence=["api"],
    )


def collect_gitlab(handle: str) -> dict | None:
    users = _json(f"https://gitlab.com/api/v4/users?username={handle}")
    if not users or not isinstance(users, list):
        return None
    user = users[0]
    return _profile(
        "GitLab", "code", user.get("web_url", ""),
        name=user.get("name") or user.get("username"),
        bio=user.get("bio") or "", location=user.get("location") or "",
        created=(user.get("created_at") or "")[:10],
        facts={"state": user.get("state", ""), "org": user.get("organization", "")},
        evidence=["api"],
    )


def collect_keybase(handle: str) -> dict | None:
    data = _json(f"https://keybase.io/_/api/1.0/user/lookup.json?username={handle}")
    if not data or not data.get("them"):
        return None
    them = data["them"]
    if isinstance(them, list):
        them = them[0] if them else None
    if not them or not isinstance(them, dict):
        return None
    basics = them.get("basics") or {}
    if str(basics.get("username", "")).lower() != handle.lower():
        return None
    profile = them.get("profile") or {}
    proofs = []
    for proof in ((them.get("proofs_summary") or {}).get("all") or []):
        tag = proof.get("nametag") or proof.get("username") or proof.get("proof_type")
        if tag:
            proofs.append(str(tag))
    crypto = ((them.get("public_keys") or {}).get("primary") or {})
    return _profile(
        "Keybase", "identity", f"https://keybase.io/{handle}",
        name=profile.get("full_name") or handle,
        bio=profile.get("bio") or "", location=profile.get("location") or "",
        facts={
            "proofs": ", ".join(proofs[:12]),
            "proof_count": len(proofs),
            "pgp_fingerprint": crypto.get("key_fingerprint", ""),
            "devices": len(them.get("devices") or []),
        },
        evidence=["api", "proofs"] if proofs else ["api"],
    )


def collect_mastodon(handle: str) -> dict | None:
    """Look up the handle locally, then search across the fediverse."""
    data = _json(f"https://mastodon.social/api/v1/accounts/lookup?acct={handle}")
    if data and data.get("username"):
        return _profile(
            "Mastodon", "social", data.get("url", ""),
            name=data.get("display_name") or data.get("username"),
            bio=data.get("note", ""), created=(data.get("created_at") or "")[:10],
            followers=data.get("followers_count", 0),
            facts={
                "statuses": data.get("statuses_count", 0),
                "following": data.get("following_count", 0),
                "instance": "mastodon.social",
            },
            evidence=["api"],
        )
    found = _json(f"https://mastodon.social/api/v2/search?q={handle}&type=accounts&limit=5")
    for account in (found or {}).get("accounts") or []:
        acct = str(account.get("acct", ""))
        if acct.split("@")[0].lower() == handle.lower():
            return _profile(
                "Mastodon", "social", account.get("url", ""),
                name=account.get("display_name") or account.get("username"),
                bio=account.get("note", ""), created=(account.get("created_at") or "")[:10],
                followers=account.get("followers_count", 0),
                facts={"instance": acct.split("@")[1] if "@" in acct else "mastodon.social",
                       "statuses": account.get("statuses_count", 0)},
                evidence=["federated search"],
            )
    return None


def collect_pixelfed(handle: str) -> dict | None:
    data = _json(f"https://pixelfed.social/api/v1/accounts/lookup?acct={handle}")
    if not data or not data.get("username"):
        return None
    return _profile(
        "Pixelfed", "social", data.get("url", ""),
        name=data.get("display_name") or data.get("username"),
        bio=data.get("note", ""), created=(data.get("created_at") or "")[:10],
        followers=data.get("followers_count", 0),
        facts={"statuses": data.get("statuses_count", 0)},
        evidence=["api"],
    )


def collect_bluesky(handle: str) -> dict | None:
    for actor in (f"{handle}.bsky.social", handle):
        data = _json("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
                     f"?actor={quote(actor)}")
        if data and data.get("handle"):
            return _profile(
                "Bluesky", "social", f"https://bsky.app/profile/{data['handle']}",
                name=data.get("displayName") or data.get("handle"),
                bio=data.get("description", ""), created=(data.get("createdAt") or "")[:10],
                followers=data.get("followersCount", 0),
                facts={"handle": data.get("handle", ""),
                       "follows": data.get("followsCount", 0),
                       "posts": data.get("postsCount", 0)},
                evidence=["api"],
            )
    return None


def collect_gravatar(handle: str) -> dict | None:
    for candidate in (handle, f"{handle}@gmail.com"):
        digest = hashlib.md5(candidate.lower().encode()).hexdigest()
        data = _json(f"https://www.gravatar.com/{digest}.json")
        if not data or not data.get("entry"):
            continue
        entry = data["entry"][0]
        accounts = [a.get("shortname") or a.get("domain") for a in entry.get("accounts", [])]
        return _profile(
            "Gravatar", "identity", entry.get("profileUrl", ""),
            name=(entry.get("name") or {}).get("formatted", "") or entry.get("displayName", ""),
            bio=entry.get("aboutMe", ""), location=entry.get("currentLocation", ""),
            facts={
                "accounts": ", ".join(a for a in accounts if a)[:200],
                "account_count": len([a for a in accounts if a]),
            },
            evidence=["api"] + (["linked accounts"] if accounts else []),
        )
    return None


def collect_hackernews(handle: str) -> dict | None:
    data = _json(f"https://hacker-news.firebaseio.com/v0/user/{handle}.json")
    if not data or not isinstance(data, dict) or not data.get("id"):
        return None
    return _profile(
        "Hacker News", "forum", f"https://news.ycombinator.com/user?id={data['id']}",
        name=data.get("id"),
        bio=data.get("about", ""),
        created=time.strftime("%Y-%m-%d", time.gmtime(data.get("created", 0)))
        if data.get("created") else "",
        followers=data.get("karma", 0),
        facts={"karma": data.get("karma", 0),
               "submitted": len(data.get("submitted") or [])},
        evidence=["api"],
    )


def collect_lobsters(handle: str) -> dict | None:
    resp = _get(f"https://lobste.rs/u/{handle}.json", headers=JSON_HEADERS)
    if resp is None or resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if not data or not data.get("username"):
        return None
    return _profile(
        "Lobsters", "forum", f"https://lobste.rs/u/{data['username']}",
        name=data.get("username"), bio=data.get("about", ""),
        created=(data.get("created_at") or "")[:10],
        facts={"karma": data.get("karma", 0),
               "stories": data.get("stories_count", ""),
               "comments": data.get("comments_count", "")},
        evidence=["api"],
    )


def collect_dockerhub(handle: str) -> dict | None:
    data = _json(f"https://hub.docker.com/v2/users/{handle}/")
    if not data or not data.get("username"):
        return None
    return _profile(
        "Docker Hub", "code", f"https://hub.docker.com/u/{handle}",
        name=data.get("full_name") or data.get("username"),
        location=data.get("location", ""),
        created=(data.get("date_joined") or "")[:10],
        facts={"company": data.get("company", ""),
               "profile_url": data.get("profile_url", "")},
        evidence=["api"],
    )


def collect_gitea(handle: str) -> dict | None:
    data = _json(f"https://gitea.com/api/v1/users/{handle}")
    if not data or not data.get("login"):
        return None
    return _profile(
        "Gitea", "code", data.get("html_url", f"https://gitea.com/{handle}"),
        name=data.get("full_name") or data.get("login"),
        bio=data.get("description", ""), location=data.get("location", ""),
        created=(data.get("created") or "")[:10],
        facts={"website": data.get("website", ""), "repos": data.get("repo_count", "")},
        evidence=["api"],
    )


def collect_npm(handle: str) -> dict | None:
    data = _json(f"https://registry.npmjs.org/-/user/org.couchdb.user:{handle}")
    if not data or not data.get("name"):
        return None
    return _profile(
        "npm", "code", f"https://www.npmjs.com/~{data['name']}",
        name=data.get("name"), facts={"email": data.get("email", "")},
        evidence=["registry"],
    )


def collect_pypi(handle: str) -> dict | None:
    resp = _html(f"https://pypi.org/user/{handle}/")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    name = _title(soup)
    if not name or not _scraped_identity(name, handle):
        return None
    return _profile(
        "PyPI", "code", f"https://pypi.org/user/{handle}/",
        name=name.replace("· PyPI", "").strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_hackerone(handle: str) -> dict | None:
    data = _json(f"https://hackerone.com/{handle}.json")
    if not data or not isinstance(data, dict) or not data.get("username"):
        return None
    return _profile(
        "HackerOne", "security", f"https://hackerone.com/{handle}",
        name=data.get("name") or data.get("username"),
        bio=data.get("bio", ""), location=data.get("location", ""),
        created=(data.get("created_at") or "")[:10],
        followers=data.get("followers_count", 0),
        facts={"reputation": data.get("reputation", ""),
               "signal": data.get("signal", ""),
               "impact": data.get("impact", "")},
        evidence=["api"],
    )


def collect_wakatime(handle: str) -> dict | None:
    data = _json(f"https://wakatime.com/api/v1/users/{handle}")
    if not data or not (data.get("data") or {}).get("username"):
        return None
    user = data["data"]
    return _profile(
        "WakaTime", "code", f"https://wakatime.com/@{user['username']}",
        name=user.get("display_name") or user["username"],
        location=user.get("city", ""), created=(user.get("created_at") or "")[:10],
        facts={"languages": ", ".join(
            lang.get("name", "") for lang in (user.get("languages") or [])[:6])},
        evidence=["api"],
    )


def collect_ctftime(handle: str) -> dict | None:
    data = _json(f"https://ctftime.org/api/v1/users/{handle}/")
    if not data or not isinstance(data, dict):
        return None
    if not data.get("name") and not data.get("id"):
        return None
    return _profile(
        "CTFtime", "security", f"https://ctftime.org/user/{data.get('id', handle)}",
        name=data.get("name") or str(handle),
        facts={"team": (data.get("team") or {}).get("name", ""),
               "rating": (data.get("rating") or {}).get("rating", "")},
        evidence=["api"],
    )


# Codeberg's WAF rejects spoofed browser User-Agents; a plain client UA passes.
TOOL_HEADERS = {"User-Agent": "hackit-osint/4.0", "Accept": "application/json"}


def collect_codeberg(handle: str) -> dict | None:
    data = _json(f"https://codeberg.org/api/v1/users/{handle}", headers=TOOL_HEADERS)
    if not data or str(data.get("login", "")).lower() != handle.lower():
        return None
    return _profile(
        "Codeberg", "code", data.get("html_url") or f"https://codeberg.org/{handle}",
        name=data.get("full_name") or data.get("login"),
        bio=data.get("description", ""),
        location=data.get("location", ""),
        created=(data.get("created") or "")[:10],
        followers=data.get("followers_count", 0),
        facts={"repos": data.get("public_repos", ""), "website": data.get("website", "")},
        evidence=["api"],
    )


def collect_codeforces(handle: str) -> dict | None:
    data = _json(f"https://codeforces.com/api/user.info?handles={handle}")
    if not data or data.get("status") != "OK":
        return None
    rows = data.get("result") or []
    if not rows:
        return None
    user = rows[0]
    if str(user.get("handle", "")).lower() != handle.lower():
        return None
    name = " ".join(part for part in (user.get("firstName"), user.get("lastName")) if part)
    created = ""
    if user.get("registrationTimeSeconds"):
        created = time.strftime("%Y-%m-%d", time.gmtime(user["registrationTimeSeconds"]))
    return _profile(
        "Codeforces", "code", f"https://codeforces.com/profile/{user['handle']}",
        name=name or user["handle"],
        location=", ".join(x for x in (user.get("city"), user.get("country")) if x),
        created=created,
        facts={"rank": user.get("rank", ""), "rating": user.get("rating", ""),
               "max_rating": user.get("maxRating", ""),
               "organization": user.get("organization", "")},
        evidence=["api"],
    )


def collect_codewars(handle: str) -> dict | None:
    data = _json(f"https://www.codewars.com/api/v1/users/{handle}")
    if not data or str(data.get("username", "")).lower() != handle.lower():
        return None
    created = (data.get("memberSince") or "")[:10]
    ranks = data.get("ranks") or {}
    return _profile(
        "Codewars", "code", f"https://www.codewars.com/users/{data['username']}",
        name=data.get("name") or data["username"],
        created=created,
        facts={"honor": data.get("honor", ""),
               "clan": data.get("clan", ""),
               "rank": (ranks.get("overall") or {}).get("name", ""),
               "leaderboard": data.get("leaderboardPosition", "")},
        evidence=["api"],
    )


def collect_hackerrank(handle: str) -> dict | None:
    data = _json("https://www.hackerrank.com/rest/contests/master/hackers/"
                 f"{handle}/profile")
    model = (data or {}).get("model") or {}
    if not model or str(model.get("username", "")).lower() != handle.lower():
        return None
    return _profile(
        "HackerRank", "code", f"https://www.hackerrank.com/profile/{model['username']}",
        name=model.get("name") or model["username"],
        location=model.get("country", ""),
        created=(model.get("created_at") or "")[:10],
        followers=model.get("followers_count", 0),
        facts={"school": model.get("school", ""), "company": model.get("company", "")},
        evidence=["api"],
    )


# ───────────────────────────── gaming ─────────────────────────────

def collect_chesscom(handle: str) -> dict | None:
    data = _json(f"https://api.chess.com/pub/player/{handle}")
    if not data or not data.get("username"):
        return None
    stats = _json(f"https://api.chess.com/pub/player/{handle}/stats") or {}
    blitz = ((stats.get("chess_blitz") or {}).get("last") or {}).get("rating")
    return _profile(
        "Chess.com", "gaming", data.get("url", f"https://www.chess.com/member/{handle}"),
        name=data.get("name") or data.get("username"),
        bio=data.get("bio", ""), location=data.get("location", ""),
        created=time.strftime("%Y-%m-%d", time.gmtime(data["joined"]))
        if data.get("joined") else "",
        followers=data.get("followers", 0),
        facts={"title": data.get("title", ""), "blitz": blitz,
               "status": data.get("status", "")},
        evidence=["api"],
    )


def collect_lichess(handle: str) -> dict | None:
    data = _json(f"https://lichess.org/api/user/{handle}")
    if not data or not data.get("username"):
        return None
    perfs = data.get("perfs") or {}
    best = sorted(
        ((k, (v or {}).get("rating")) for k, v in perfs.items() if (v or {}).get("rating")),
        key=lambda kv: -kv[1])[:3]
    return _profile(
        "Lichess", "gaming", data.get("url", f"https://lichess.org/@/{handle}"),
        name=data.get("username"),
        bio=(data.get("profile") or {}).get("bio", ""),
        location=(data.get("profile") or {}).get("location", ""),
        created=time.strftime("%Y-%m-%d", time.gmtime(data["createdAt"] / 1000))
        if isinstance(data.get("createdAt"), (int, float)) else "",
        followers=data.get("followers", 0),
        facts={"top_ratings": ", ".join(f"{k} {v}" for k, v in best),
               "play_time": (data.get("playTime") or {}).get("total", "")},
        evidence=["api"],
    )


def collect_steam(handle: str) -> dict | None:
    resp = _get(f"https://steamcommunity.com/id/{handle}/?xml=1",
                headers={"User-Agent": UA, "Accept": "application/xml,text/xml,*/*"})
    if resp is None or resp.status_code != 200:
        return None
    body = resp.text
    if "<steamID64>" not in body:
        return None

    def tag(name: str) -> str:
        match = re.search(rf"<{name}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{name}>",
                          body, re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""

    return _profile(
        "Steam", "gaming", f"https://steamcommunity.com/id/{handle}",
        name=tag("steamID"), bio=tag("summary"), location=tag("location"),
        created=tag("memberSince"),
        facts={"steamid64": tag("steamID64"), "real_name": tag("realname"),
               "state": tag("stateMessage"), "avatar": tag("avatarFull")},
        evidence=["xml profile"],
    )


def collect_roblox(handle: str) -> dict | None:
    data = _json("https://users.roblox.com/v1/usernames/users", method="POST",
                 json={"usernames": [handle], "excludeBannedUsers": False})
    for user in (data or {}).get("data") or []:
        if str(user.get("name", "")).lower() == handle.lower():
            uid = user.get("id")
            detail = _json(f"https://users.roblox.com/v1/users/{uid}") or {}
            return _profile(
                "Roblox", "gaming", f"https://www.roblox.com/users/{uid}/profile",
                name=user.get("name"), bio=detail.get("description", ""),
                created=(detail.get("created") or "")[:10],
                facts={"display_name": user.get("displayName", ""), "id": uid,
                       "verified": detail.get("hasVerifiedBadge", "")},
                evidence=["api"],
            )
    return None


def collect_osu(handle: str) -> dict | None:
    resp = _html(f"https://osu.ppy.sh/users/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or handle.lower() not in title.lower():
        return None
    return _profile(
        "osu!", "gaming", f"https://osu.ppy.sh/users/{handle}",
        name=title.split("·")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_trakt(handle: str) -> dict | None:
    resp = _html(f"https://trakt.tv/users/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Trakt", "media", f"https://trakt.tv/users/{handle}",
        name=title.split(" - ")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_anilist(handle: str) -> dict | None:
    resp = _html(f"https://anilist.co/user/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or handle.lower() not in title.lower():
        return None
    return _profile(
        "AniList", "media", f"https://anilist.co/user/{handle}",
        name=title.split("·")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


# ───────────────────────────── media / social ─────────────────────────────

def collect_soundcloud(handle: str) -> dict | None:
    resp = _html(f"https://soundcloud.com/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "soundcloud" == title.lower() or _looks_missing(title):
        return None
    if handle.lower() not in title.lower():
        return None
    return _profile(
        "SoundCloud", "media", f"https://soundcloud.com/{handle}",
        name=title.split("|")[0].replace("Listen to music", "").strip(),
        bio=_meta(soup, "og:description", "description"),
        facts={"page_title": title}, evidence=["page"],
    )


def collect_spotify(handle: str) -> dict | None:
    resp = _html(f"https://open.spotify.com/user/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Spotify", "media", f"https://open.spotify.com/user/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_deezer(handle: str) -> dict | None:
    data = _json(f"https://api.deezer.com/user/{handle}")
    if not data or not data.get("name"):
        return None
    return _profile(
        "Deezer", "media", data.get("link", f"https://www.deezer.com/profile/{handle}"),
        name=data.get("name"), facts={"id": data.get("id", "")},
        evidence=["api"],
    )


def collect_lastfm(handle: str) -> dict | None:
    resp = _html(f"https://www.last.fm/user/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Last.fm", "media", f"https://www.last.fm/user/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_dailymotion(handle: str) -> dict | None:
    data = _json(f"https://api.dailymotion.com/user/{handle}"
                 "?fields=screenname,description,followers_total,created_time")
    if not data or not data.get("screenname"):
        return None
    return _profile(
        "Dailymotion", "media", f"https://www.dailymotion.com/{handle}",
        name=data.get("screenname"), bio=data.get("description", ""),
        created=time.strftime("%Y-%m-%d", time.gmtime(data["created_time"]))
        if data.get("created_time") else "",
        followers=data.get("followers_total", 0), evidence=["api"],
    )


def collect_imgur(handle: str) -> dict | None:
    # Public client id published in Imgur's own API docs — not a personal key.
    data = _json(f"https://api.imgur.com/3/account/{handle}",
                 headers={**JSON_HEADERS, "Authorization": "Client-ID 546c25a59c58ad7"})
    user = (data or {}).get("data") or {}
    if not user.get("url"):
        return None
    return _profile(
        "Imgur", "media", f"https://imgur.com/user/{user['url']}",
        name=user.get("url"), bio=user.get("bio", ""),
        created=time.strftime("%Y-%m-%d", time.gmtime(user["created"]))
        if user.get("created") else "",
        facts={"reputation": user.get("reputation", ""),
               "submitted": user.get("submitted", "")},
        evidence=["api"],
    )


def collect_telegram(handle: str) -> dict | None:
    resp = _html(f"https://t.me/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "telegram" == title.lower() or _looks_missing(title):
        return None
    body = _text(resp)
    members = ""
    match = re.search(r"([\d\s,.]+)\s*(?:members|subscribers)", body, re.IGNORECASE)
    if match:
        members = match.group(1).strip()
    kind = "channel" if "channel" in body[:4000].lower() else "user"
    return _profile(
        "Telegram", "messaging", f"https://t.me/{handle}",
        name=title.split("@")[-1] if "@" in title else handle,
        bio=_meta(soup, "og:description", "description"), followers=members,
        facts={"type": kind}, evidence=["page"],
    )


def collect_vk(handle: str) -> dict | None:
    resp = _html(f"https://vk.com/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "vk.com" in title.lower() or _looks_missing(title):
        return None
    return _profile(
        "VK", "social", f"https://vk.com/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_snapchat(handle: str) -> dict | None:
    resp = _html(f"https://www.snapchat.com/add/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Snapchat", "social", f"https://www.snapchat.com/add/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_threads(handle: str) -> dict | None:
    resp = _html(f"https://www.threads.net/@{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or handle.lower() not in title.lower():
        return None
    return _profile(
        "Threads", "social", f"https://www.threads.net/@{handle}",
        name=title.split("(")[0].strip().lstrip("@"),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_instagram(handle: str) -> dict | None:
    resp = _html(f"https://www.instagram.com/{handle}/")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "instagram" == title.lower() or _looks_missing(title):
        return None
    if handle.lower() not in title.lower():
        return None
    description = _meta(soup, "og:description", "description")
    followers = ""
    match = re.search(r"([\d,.]+[KMB]?)\s*Followers", description, re.IGNORECASE)
    if match:
        followers = match.group(1)
    return _profile(
        "Instagram", "social", f"https://www.instagram.com/{handle}/",
        name=title.split("(")[0].strip().lstrip("@").replace("Instagram", "").strip(),
        bio=description, followers=followers, evidence=["page"],
    )


def collect_pinterest(handle: str) -> dict | None:
    resp = _html(f"https://www.pinterest.com/{handle}/")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "pinterest" == title.lower() or _looks_missing(title):
        return None
    return _profile(
        "Pinterest", "social", f"https://www.pinterest.com/{handle}/",
        name=title.split("(")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_youtube(handle: str) -> dict | None:
    resp = _html(f"https://www.youtube.com/@{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "404" in title or _looks_missing(title):
        return None
    description = _meta(soup, "og:description", "description")
    subscribers = ""
    match = re.search(r"([\d,.]+[KMB]?)\s*subscribers", description, re.IGNORECASE)
    if match:
        subscribers = match.group(1)
    return _profile(
        "YouTube", "media", f"https://www.youtube.com/@{handle}",
        name=title.replace(" - YouTube", "").strip(),
        bio=description, followers=subscribers, evidence=["page"],
    )


def collect_twitch(handle: str) -> dict | None:
    resp = _html(f"https://www.twitch.tv/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or "twitch" == title.lower() or "404" in title:
        return None
    return _profile(
        "Twitch", "media", f"https://www.twitch.tv/{handle}",
        name=title.split(" - ")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_rumble(handle: str) -> dict | None:
    resp = _html(f"https://rumble.com/user/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Rumble", "media", f"https://rumble.com/user/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_bitchute(handle: str) -> dict | None:
    resp = _html(f"https://www.bitchute.com/channel/{handle}/")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "BitChute", "media", f"https://www.bitchute.com/channel/{handle}/",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_replit(handle: str) -> dict | None:
    resp = _html(f"https://replit.com/@{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Replit", "code", f"https://replit.com/@{handle}",
        name=title.split("-")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_aboutme(handle: str) -> dict | None:
    resp = _html(f"https://about.me/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "About.me", "identity", f"https://about.me/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_linktree(handle: str) -> dict | None:
    resp = _html(f"https://linktr.ee/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Linktree", "identity", f"https://linktr.ee/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_substack(handle: str) -> dict | None:
    data = _json(f"https://{handle}.substack.com/api/v1/archive?limit=3&sort=new")
    if isinstance(data, list) and data:
        posts = [p.get("title") for p in data if p.get("title")]
        return _profile(
            "Substack", "blog", f"https://{handle}.substack.com/",
            name=handle, facts={"recent_posts": ", ".join(posts[:3])},
            evidence=["api"],
        )
    resp = _html(f"https://{handle}.substack.com/")
    if resp is None or resp.status_code != 200:
        return None
    soup = _soup(resp)
    title = _title(soup)
    description = _meta(soup, "og:description", "description")
    if not title or not _scraped_identity(title, handle, description):
        return None
    return _profile("Substack", "blog", f"https://{handle}.substack.com/",
                    name=title.split("|")[0].strip(), bio=description,
                    evidence=["page"])


def collect_matrix(handle: str) -> dict | None:
    data = _json(f"https://matrix.org/_matrix/client/v3/profile/%40{quote(handle)}%3Amatrix.org")
    if not data or not data.get("displayname"):
        return None
    return _profile(
        "Matrix", "messaging", f"https://matrix.to/#/@{handle}:matrix.org",
        name=data.get("displayname"), evidence=["api"],
    )


def collect_lemmy(handle: str) -> dict | None:
    data = _json(f"https://lemmy.world/api/v3/user?username={handle}")
    person = ((data or {}).get("person_view") or {}).get("person") or {}
    if not person.get("name"):
        return None
    return _profile(
        "Lemmy", "forum", person.get("actor_id", ""),
        name=person.get("display_name") or person.get("name"),
        bio=person.get("bio", ""), created=(person.get("published") or "")[:10],
        facts={"posts": person.get("post_count", ""),
               "comments": person.get("comment_count", "")},
        evidence=["api"],
    )


def collect_wattpad(handle: str) -> dict | None:
    resp = _html(f"https://www.wattpad.com/user/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Wattpad", "writing", f"https://www.wattpad.com/user/{handle}",
        name=title.split("-")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


def collect_goodreads(handle: str) -> dict | None:
    resp = _html(f"https://www.goodreads.com/{handle}")
    if resp is None or resp.status_code != 200 or _blocked(resp):
        return None
    soup = _soup(resp)
    title = _title(soup)
    if not title or not _scraped_identity(title, handle,
                                          _meta(soup, "og:description", "description")):
        return None
    return _profile(
        "Goodreads", "books", f"https://www.goodreads.com/{handle}",
        name=title.split("|")[0].strip(),
        bio=_meta(soup, "og:description", "description"),
        evidence=["page"],
    )


# ───────────────────────────── domain collectors ─────────────────────────────

def collect_crtsh(domain: str) -> List[dict]:
    data = _json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
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
    return subdomains[:200]


def collect_certspotter(domain: str) -> List[dict]:
    data = _json("https://api.certspotter.com/v1/issuances"
                 f"?domain={domain}&include_subdomains=true&expand=dns_names", timeout=20)
    if not isinstance(data, list):
        return []
    seen, out = set(), []
    for row in data:
        for name in row.get("dns_names") or []:
            name = str(name).lower().lstrip("*.")
            if name.endswith(domain) and name not in seen and " " not in name:
                seen.add(name)
                out.append({"host": name, "first_seen": (row.get("not_before") or "")[:10]})
    return out[:200]


def collect_hackertarget(domain: str) -> List[dict]:
    resp = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
    if resp is None or resp.status_code != 200:
        return []
    body = resp.text.strip()
    if "error" in body[:80].lower() or "API count exceeded" in body:
        return []
    out = []
    for line in body.splitlines():
        if "," in line:
            host, ip = line.split(",", 1)
            out.append({"host": host.strip().lower(), "ip": ip.strip(), "first_seen": ""})
    return out[:200]


def collect_rapiddns(domain: str) -> List[dict]:
    resp = _html(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=20)
    if resp is None or resp.status_code != 200:
        return []
    out, seen = [], set()
    pattern = r"<td>([a-z0-9][a-z0-9.-]*\." + re.escape(domain) + r")</td>"
    for host in re.findall(pattern, resp.text, re.IGNORECASE):
        host = host.lower()
        if host not in seen:
            seen.add(host)
            out.append({"host": host, "first_seen": ""})
    return out[:200]


def collect_subdomain_center(domain: str) -> List[dict]:
    data = _json(f"https://api.subdomain.center/?domain={domain}", timeout=25)
    if not isinstance(data, list):
        return []
    return [{"host": str(h).lower(), "first_seen": ""} for h in data
            if str(h).lower().endswith(domain)][:300]


def collect_dns(domain: str) -> dict:
    result: Dict[str, List[str]] = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [],
        "SOA": [], "CAA": [],
    }
    for rtype in result:
        data = _json(f"https://dns.google/resolve?name={quote(domain)}&type={rtype}")
        if not data:
            continue
        for answer in data.get("Answer") or []:
            value = str(answer.get("data", "")).strip().strip('"')
            if value and value not in result[rtype]:
                result[rtype].append(value)
    return result


_RDAP_BOOTSTRAP: Optional[Dict[str, List[str]]] = None


def _rdap_servers(domain: str) -> List[str]:
    """Resolve the authoritative RDAP base URL for a TLD via IANA bootstrap."""
    global _RDAP_BOOTSTRAP
    if _RDAP_BOOTSTRAP is None:
        _RDAP_BOOTSTRAP = {}
        boot = _json("https://data.iana.org/rdap/dns.json", timeout=20) or {}
        for service in boot.get("services") or []:
            if not isinstance(service, list) or len(service) < 2:
                continue
            tlds, urls = service[0], service[1]
            for tld in tlds or []:
                clean = [str(u).rstrip("/") for u in (urls or []) if str(u).startswith("http")]
                if clean:
                    _RDAP_BOOTSTRAP[str(tld).lower()] = clean
    tld = domain.rsplit(".", 1)[-1].lower()
    bases = list(_RDAP_BOOTSTRAP.get(tld) or [])
    bases.append("https://rdap.org")          # aggregator fallback
    return bases


def collect_rdap(domain: str) -> dict:
    data = None
    for base in _rdap_servers(domain):
        data = _json(f"{base}/domain/{domain}", timeout=20,
                     headers={**JSON_HEADERS, "Accept": "application/rdap+json, application/json"})
        if isinstance(data, dict) and not data.get("errorCode"):
            break
        data = None
    if not data:
        return {}
    events = {e.get("eventAction"): (e.get("eventDate") or "")[:10]
              for e in data.get("events") or []}
    entities = []
    for entity in data.get("entities") or []:
        roles = ", ".join(entity.get("roles") or [])
        vcard = entity.get("vcardArray") or []
        name = ""
        if len(vcard) > 1:
            for item in vcard[1]:
                if item and item[0] == "fn":
                    name = item[3]
                    break
        if name:
            entities.append(f"{name} ({roles})")
    nameservers = [ns.get("ldhName", "").lower() for ns in data.get("nameservers") or []]
    registrar = next((e for e in entities if "registrar" in e), entities[0] if entities else "")
    return {
        "handle": data.get("handle", ""),
        "registrar": registrar,
        "entities": entities[:6],
        "created": events.get("registration", ""),
        "updated": events.get("last changed", ""),
        "expires": events.get("expiration", ""),
        "status": ", ".join(data.get("status") or []),
        "nameservers": [n for n in nameservers if n],
    }


def collect_wayback(domain: str) -> dict:
    data = _json("https://web.archive.org/cdx/search/cdx"
                 f"?url={quote(domain)}&output=json&limit=2000&fl=timestamp,original,statuscode",
                 timeout=25)
    if not isinstance(data, list) or len(data) < 2:
        return {}
    rows = data[1:]
    timestamps = sorted(str(r[0]) for r in rows if r and r[0])
    return {
        "snapshots": len(rows),
        "first": f"{timestamps[0][:4]}-{timestamps[0][4:6]}-{timestamps[0][6:8]}"
        if timestamps else "",
        "last": f"{timestamps[-1][:4]}-{timestamps[-1][4:6]}-{timestamps[-1][6:8]}"
        if timestamps else "",
        "sample": [str(r[1]) for r in rows[:3] if len(r) > 1],
    }


def collect_urlscan(domain: str) -> List[dict]:
    data = _json(f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=10")
    out = []
    for row in (data or {}).get("results") or []:
        page = row.get("page") or {}
        task = row.get("task") or {}
        out.append({
            "url": page.get("url", ""),
            "ip": page.get("ip", ""),
            "asn": page.get("asnname", ""),
            "country": page.get("country", ""),
            "server": page.get("server", ""),
            "scanned": (task.get("time") or "")[:10],
            "result": f"https://urlscan.io/result/{row.get('_id', '')}/",
        })
    return out


def collect_otx(domain: str) -> dict:
    general = _json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                    timeout=20)
    if not isinstance(general, dict):
        general = {}
    pdns = _json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                 timeout=20)
    if not isinstance(pdns, dict):
        pdns = {}
    records = []
    for row in (pdns.get("passive_dns") or [])[:20]:
        records.append({"host": row.get("hostname", ""), "ip": row.get("address", ""),
                        "first": (row.get("first") or "")[:10],
                        "last": (row.get("last") or "")[:10]})
    pulse = general.get("pulse_info") or {}
    return {
        "pulses": len(pulse.get("pulses") or []),
        "validation": ", ".join(general.get("validation") or []),
        "alexa": general.get("alexa", ""),
        "passive_dns": records,
        "tags": ", ".join(pulse.get("tags") or []),
    }


def collect_internetdb(ip: str) -> dict:
    data = _json(f"https://internetdb.shodan.io/{ip}", timeout=15)
    if not data or data.get("detail"):
        return {}
    return {
        "ip": ip,
        "ports": data.get("ports") or [],
        "hostnames": data.get("hostnames") or [],
        "cpes": (data.get("cpes") or [])[:8],
        "tags": data.get("tags") or [],
        "vulns": (data.get("vulns") or [])[:20],
        "cves": len(data.get("vulns") or []),
    }


def collect_ip_geo(domain: str) -> dict | None:
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return None
    data = _json(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,"
                 "isp,org,as,reverse,hosting,proxy")
    if not data or data.get("status") != "success":
        data = _json(f"https://ipinfo.io/{ip}/json")
        if not data or data.get("bogon"):
            return None
        return {"ip": ip, "country": data.get("country", ""),
                "region": data.get("region", ""), "city": data.get("city", ""),
                "isp": data.get("org", ""), "org": data.get("org", ""),
                "asn": data.get("org", ""), "hostname": data.get("hostname", "")}
    return {"ip": ip, "country": data.get("country", ""),
            "region": data.get("regionName", ""), "city": data.get("city", ""),
            "isp": data.get("isp", ""), "org": data.get("org", ""),
            "asn": data.get("as", ""), "hostname": data.get("reverse", ""),
            "hosting": bool(data.get("hosting")), "proxy": bool(data.get("proxy"))}


def collect_hstspreload(domain: str) -> dict:
    data = _json(f"https://hstspreload.org/api/v2/status?domain={domain}", timeout=15)
    if not data:
        return {}
    return {"status": data.get("status", ""), "bulk": data.get("bulk", ""),
            "preloaded": data.get("preloadedDomain", "")}


def collect_ssllabs(domain: str) -> dict:
    data = _json(f"https://api.ssllabs.com/api/v3/analyze?host={domain}&maxAge=24",
                 timeout=25)
    if not data or data.get("errors"):
        return {}
    endpoints = data.get("endpoints") or []
    grades = sorted({ep.get("grade", "") for ep in endpoints if ep.get("grade")})
    return {"status": data.get("status", ""), "grade": ", ".join(grades),
            "protocol": data.get("protocol", "")}


def collect_mnemonic_pdns(domain: str) -> List[dict]:
    data = _json(f"https://api.mnemonic.no/pdns/v3/{domain}", timeout=20)
    out = []
    for row in (data or {}).get("data") or []:
        first = row.get("firstSeenTimestamp")
        out.append({"host": row.get("query", ""), "ip": row.get("answer", ""),
                    "first": time.strftime("%Y-%m-%d", time.gmtime(first / 1000))
                    if first else ""})
    return out[:60]


def collect_email_dns(domain: str, dns: dict) -> dict:
    """Mail posture derived from the TXT record set already collected."""
    txt = " ".join(dns.get("TXT") or [])
    spf = next((t for t in dns.get("TXT") or [] if t.lower().startswith("v=spf1")), "")
    dmarc = _json(f"https://dns.google/resolve?name=_dmarc.{quote(domain)}&type=TXT") or {}
    dmarc_record = ""
    for answer in dmarc.get("Answer") or []:
        value = str(answer.get("data", "")).strip('"')
        if value.lower().startswith("v=dmarc1"):
            dmarc_record = value
            break
    return {
        "spf": spf,
        "dmarc": dmarc_record,
        "dkim_hint": bool(re.search(r"v=dkim1", txt, re.IGNORECASE)),
        "mx": dns.get("MX") or [],
        "has_mail": bool(dns.get("MX")),
    }


# ───────────────────────────── email collectors ─────────────────────────────

def collect_pgp(email: str) -> dict | None:
    for server, url in (
        ("keys.openpgp.org", f"https://keys.openpgp.org/vks/v1/by-email/{quote(email)}"),
        ("keyserver.ubuntu.com",
         f"https://keyserver.ubuntu.com/pks/lookup?op=get&search={quote(email)}"),
    ):
        resp = _get(url, headers={"User-Agent": UA}, timeout=15)
        if resp is None or resp.status_code != 200:
            continue
        if "BEGIN PGP PUBLIC KEY BLOCK" not in resp.text:
            continue
        uids = re.findall(r"^uid:\s*(.+)$", resp.text, re.MULTILINE | re.IGNORECASE)
        return {"server": server, "uids": [u.strip()[:120] for u in (uids or [email])][:6],
                "url": url}
    return None


def collect_disify_email(email: str) -> dict:
    data = _json(f"https://disify.com/api/email/{quote(email)}", timeout=15)
    if not data:
        return {}
    return {
        "format": data.get("format"), "disposable": data.get("disposable"),
        "dns": data.get("dns"), "alias": data.get("alias"),
        "domain": data.get("domain", ""), "free": data.get("free"),
        "role": data.get("role", ""), "gravatar": data.get("gravatar"),
    }


def collect_usercheck_email(email: str) -> dict:
    data = _json(f"https://api.usercheck.com/email/{quote(email)}", timeout=15)
    if not data:
        return {}
    return {
        "disposable": data.get("disposable"), "mx": data.get("mx"),
        "alias": data.get("alias"), "did_you_mean": data.get("did_you_mean", ""),
        "domain": data.get("domain", ""), "mx_records": data.get("mx_records", []),
    }


def collect_usercheck_domain(domain: str) -> dict:
    data = _json(f"https://api.usercheck.com/domain/{quote(domain)}", timeout=15)
    if not data:
        return {}
    return {
        "age_days": data.get("domain_age_in_days"),
        "mx": data.get("mx"), "mx_records": data.get("mx_records", []),
        "disposable": data.get("disposable"),
    }


# ───────────────────────────── registry ─────────────────────────────

@dataclass
class Collector:
    key: str
    name: str
    kind: str
    weight: int
    fn: Callable
    target: str = "handle"     # handle | domain | email


HANDLE_COLLECTORS: List[Collector] = [
    Collector("github", "GitHub", "code", 5, collect_github),
    Collector("gitlab", "GitLab", "code", 4, collect_gitlab),
    Collector("keybase", "Keybase", "identity", 5, collect_keybase),
    Collector("mastodon", "Mastodon", "social", 4, collect_mastodon),
    Collector("pixelfed", "Pixelfed", "social", 2, collect_pixelfed),
    Collector("bluesky", "Bluesky", "social", 4, collect_bluesky),
    Collector("gravatar", "Gravatar", "identity", 3, collect_gravatar),
    Collector("hackernews", "Hacker News", "forum", 3, collect_hackernews),
    Collector("lobsters", "Lobsters", "forum", 2, collect_lobsters),
    Collector("dockerhub", "Docker Hub", "code", 3, collect_dockerhub),
    Collector("gitea", "Gitea", "code", 3, collect_gitea),
    Collector("npm", "npm", "code", 3, collect_npm),
    Collector("pypi", "PyPI", "code", 3, collect_pypi),
    Collector("hackerone", "HackerOne", "security", 4, collect_hackerone),
    Collector("wakatime", "WakaTime", "code", 2, collect_wakatime),
    Collector("ctftime", "CTFtime", "security", 3, collect_ctftime),
    Collector("codeberg", "Codeberg", "code", 3, collect_codeberg),
    Collector("codeforces", "Codeforces", "code", 3, collect_codeforces),
    Collector("codewars", "Codewars", "code", 3, collect_codewars),
    Collector("hackerrank", "HackerRank", "code", 3, collect_hackerrank),
    Collector("chesscom", "Chess.com", "gaming", 3, collect_chesscom),
    Collector("lichess", "Lichess", "gaming", 3, collect_lichess),
    Collector("steam", "Steam", "gaming", 3, collect_steam),
    Collector("roblox", "Roblox", "gaming", 2, collect_roblox),
    Collector("osu", "osu!", "gaming", 2, collect_osu),
    Collector("trakt", "Trakt", "media", 2, collect_trakt),
    Collector("anilist", "AniList", "media", 2, collect_anilist),
    Collector("soundcloud", "SoundCloud", "media", 3, collect_soundcloud),
    Collector("spotify", "Spotify", "media", 3, collect_spotify),
    Collector("deezer", "Deezer", "media", 2, collect_deezer),
    Collector("lastfm", "Last.fm", "media", 2, collect_lastfm),
    Collector("dailymotion", "Dailymotion", "media", 2, collect_dailymotion),
    Collector("imgur", "Imgur", "media", 2, collect_imgur),
    Collector("telegram", "Telegram", "messaging", 4, collect_telegram),
    Collector("vk", "VK", "social", 3, collect_vk),
    Collector("snapchat", "Snapchat", "social", 2, collect_snapchat),
    Collector("threads", "Threads", "social", 3, collect_threads),
    Collector("instagram", "Instagram", "social", 4, collect_instagram),
    Collector("pinterest", "Pinterest", "social", 2, collect_pinterest),
    Collector("youtube", "YouTube", "media", 4, collect_youtube),
    Collector("twitch", "Twitch", "media", 3, collect_twitch),
    Collector("rumble", "Rumble", "media", 2, collect_rumble),
    Collector("bitchute", "BitChute", "media", 1, collect_bitchute),
    Collector("replit", "Replit", "code", 2, collect_replit),
    Collector("aboutme", "About.me", "identity", 2, collect_aboutme),
    Collector("linktree", "Linktree", "identity", 2, collect_linktree),
    Collector("substack", "Substack", "blog", 2, collect_substack),
    Collector("matrix", "Matrix", "messaging", 2, collect_matrix),
    Collector("lemmy", "Lemmy", "forum", 2, collect_lemmy),
    Collector("wattpad", "Wattpad", "writing", 1, collect_wattpad),
    Collector("goodreads", "Goodreads", "books", 2, collect_goodreads),
]

DOMAIN_COLLECTORS: List[Collector] = [
    Collector("rdap", "RDAP", "domain", 5, collect_rdap, "domain"),
    Collector("crtsh", "crt.sh", "domain", 4, collect_crtsh, "domain"),
    Collector("certspotter", "Cert Spotter", "domain", 3, collect_certspotter, "domain"),
    Collector("hackertarget", "HackerTarget", "domain", 3, collect_hackertarget, "domain"),
    Collector("rapiddns", "RapidDNS", "domain", 3, collect_rapiddns, "domain"),
    Collector("subdomain_center", "Subdomain Center", "domain", 2,
              collect_subdomain_center, "domain"),
    Collector("wayback", "Wayback Machine", "domain", 3, collect_wayback, "domain"),
    Collector("urlscan", "urlscan.io", "domain", 3, collect_urlscan, "domain"),
    Collector("otx", "AlienVault OTX", "domain", 3, collect_otx, "domain"),
    Collector("ip_geo", "IP Geo", "domain", 2, collect_ip_geo, "domain"),
    Collector("hstspreload", "HSTS Preload", "domain", 1, collect_hstspreload, "domain"),
    Collector("ssllabs", "SSL Labs", "domain", 2, collect_ssllabs, "domain"),
    Collector("mnemonic", "Mnemonic PDNS", "domain", 2, collect_mnemonic_pdns, "domain"),
    Collector("usercheck_domain", "UserCheck", "domain", 2, collect_usercheck_domain, "domain"),
]

EMAIL_COLLECTORS: List[Collector] = [
    Collector("pgp", "PGP Keyserver", "email", 3, collect_pgp, "email"),
    Collector("disify", "Disify", "email", 2, collect_disify_email, "email"),
    Collector("usercheck_email", "UserCheck", "email", 2, collect_usercheck_email, "email"),
]


# ───────────────────────────── orchestrator ─────────────────────────────

def _empty_bundle() -> Dict[str, object]:
    return {
        "profiles": [],
        "subdomains": [],
        "dns": {},
        "geo": {},
        "rdap": {},
        "wayback": {},
        "urlscan": [],
        "otx": {},
        "internetdb": {},
        "hstspreload": {},
        "ssllabs": {},
        "passive_dns": [],
        "domain_checks": {},
        "email_checks": {},
        "pgp": None,
        "mail": {},
        "sources_checked": 0,
        "sources_hit": 0,
        "errors": [],
    }


def _merge_subdomains(bundle: Dict[str, object], rows: List[dict]) -> None:
    existing = {item["host"] for item in bundle["subdomains"]}
    for row in rows:
        host = str(row.get("host", "")).lower().strip()
        if host and host not in existing:
            existing.add(host)
            bundle["subdomains"].append(row)


def collect_live_intel(
    handles: List[str],
    domain: str = "",
    email: str = "",
    on_found: Callable[[dict], None] | None = None,
    workers: int = 10,
    enabled: bool = True,
    handle_limit: int = 2,
    timeout: int = TIMEOUT,
) -> Dict[str, object]:
    """Run every keyless collector that applies to the target.

    Parameters
    ----------
    handles : candidate usernames, most canonical first.
    domain  : FQDN to enrich (empty to skip the domain phase).
    email   : address to enrich (empty to skip the email phase).
    on_found: callback invoked per verified profile, for live streaming.
    workers : thread pool size across all collectors.
    """
    out = _empty_bundle()
    if not enabled:
        return out

    primary = [h for h in handles[:handle_limit] if h and len(h) >= 2]
    tasks: Dict[object, tuple] = {}

    # A collector that never returns must not hold the whole scan hostage.
    budget = max(45.0, float(timeout) * 6.0)
    deadline = time.monotonic() + budget
    pool = ThreadPoolExecutor(max_workers=max(4, workers))
    try:
        for handle in primary:
            for collector in HANDLE_COLLECTORS:
                tasks[pool.submit(collector.fn, handle)] = (collector, handle)
            out["sources_checked"] += len(HANDLE_COLLECTORS)
        if domain:
            for collector in DOMAIN_COLLECTORS:
                tasks[pool.submit(collector.fn, domain)] = (collector, domain)
            out["sources_checked"] += len(DOMAIN_COLLECTORS)
        if email:
            for collector in EMAIL_COLLECTORS:
                tasks[pool.submit(collector.fn, email)] = (collector, email)
            out["sources_checked"] += len(EMAIL_COLLECTORS)

        for future in as_completed(tasks, timeout=max(deadline - time.monotonic(), 1.0)):
            collector, target = tasks[future]
            try:
                result = future.result()
            except Exception as exc:  # keep the scan alive, record the source
                out["errors"].append({"source": collector.name,
                                      "error": type(exc).__name__})
                continue
            if not result:
                continue
            out["sources_hit"] += 1

            if collector.target == "handle":
                if isinstance(result, dict) and result.get("source"):
                    result["weight"] = collector.weight
                    out["profiles"].append(result)
                    if on_found:
                        try:
                            on_found(result)
                        except Exception:
                            pass
            elif collector.target == "domain":
                if collector.key in ("crtsh", "certspotter", "hackertarget", "rapiddns"):
                    _merge_subdomains(out, result if isinstance(result, list) else [])
                elif collector.key == "rdap":
                    out["rdap"] = result
                elif collector.key == "wayback":
                    out["wayback"] = result
                elif collector.key == "urlscan":
                    out["urlscan"] = result
                elif collector.key == "otx":
                    out["otx"] = result
                elif collector.key == "ip_geo":
                    out["geo"] = result
                elif collector.key == "hstspreload":
                    out["hstspreload"] = result
                elif collector.key == "ssllabs":
                    out["ssllabs"] = result
                elif collector.key == "mnemonic":
                    out["passive_dns"] = result
                elif collector.key == "usercheck_domain":
                    out["domain_checks"] = result
            elif collector.target == "email":
                if collector.key == "pgp":
                    out["pgp"] = result
                else:
                    out["email_checks"][collector.key] = result
    except TimeoutError:
        for future, (collector, _target) in tasks.items():
            if future.done():
                continue
            future.cancel()
            out["errors"].append({"source": collector.name, "error": "timeout"})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # DNS needs the record set before the mail-posture derivation.
    if domain:
        dns = collect_dns(domain)
        out["dns"] = dns
        out["sources_checked"] += 1
        out["mail"] = collect_email_dns(domain, dns)
        if dns.get("A") or dns.get("MX"):
            out["sources_hit"] += 1
            geo = out.get("geo") if isinstance(out.get("geo"), dict) else {}
            if geo.get("ip"):
                db = collect_internetdb(geo["ip"])
                if db:
                    out["internetdb"] = db
                    out["sources_hit"] += 1

    out["profiles"].sort(key=lambda p: (-int(p.get("weight", 0)),
                                        str(p.get("source", ""))))
    out["subdomains"].sort(key=lambda item: item.get("host", ""))
    return out


def verified_sources(live_intel: Dict[str, object]) -> set[str]:
    """Lower-cased source names confirmed by a live collector."""
    return {str(p.get("source", "")).lower()
            for p in live_intel.get("profiles", []) if p.get("source")}
