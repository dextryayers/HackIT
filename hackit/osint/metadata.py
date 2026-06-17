from __future__ import annotations

import re
import json
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import quote_plus


def check_wayback(query: str) -> dict:
    result = {"snapshots": [], "total_archived": 0, "oldest": "", "newest": ""}
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url={quote_plus(query)}&output=json&limit=20&fl=timestamp,original,statuscode,length"
        req = Request(url, headers={"User-Agent": "HackIT-OSINT/2.0"})
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            if len(data) > 1:
                for row in data[1:]:
                    if len(row) >= 4:
                        result["snapshots"].append({
                            "timestamp": row[0],
                            "original": row[1],
                            "status": row[2],
                            "length": row[3],
                        })
                result["total_archived"] = len(result["snapshots"])
                if result["snapshots"]:
                    result["oldest"] = result["snapshots"][0]["timestamp"]
                    result["newest"] = result["snapshots"][-1]["timestamp"]
    except:
        pass
    return result


def check_google_cache(query: str) -> dict:
    result = {"available": False, "cached_date": "", "preview": ""}
    try:
        url = f"https://webcache.googleusercontent.com/search?q=cache:{quote_plus(query)}"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urlopen(req, timeout=10) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            date_match = re.search(r'(\d+\s+\w+\s+\d{4})', html)
            if date_match:
                result["cached_date"] = date_match.group(1)
            preview_match = re.search(r'<!--a lot of SAME-->.*?<pre>(.*?)</pre>', html, re.DOTALL)
            if preview_match:
                text = re.sub(r'<[^>]+>', '', preview_match.group(1))
                result["preview"] = text[:300]
            result["available"] = True
    except:
        pass
    return result


def check_pastebin_search(query: str) -> dict:
    result = {"pastes_found": [], "total_estimated": 0}
    try:
        url = f"https://www.google.com/search?q=site:pastebin.com+%22{quote_plus(query)}%22"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            links = re.findall(r'href="(https://pastebin\.com/\w+)"', html)
            result["pastes_found"] = list(set(links))[:15]
            result["total_estimated"] = len(result["pastes_found"])
    except:
        pass
    return result


def check_github_search(query: str) -> dict:
    result = {"code_results": "0", "repos": [], "user_results": ""}
    try:
        url = f"https://github.com/search?q=%22{quote_plus(query)}%22&type=code"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            count_match = re.search(r'(\d[\d,]*)\s+code\s+(?:results?)', html, re.IGNORECASE)
            if count_match:
                result["code_results"] = count_match.group(1)
            user_match = re.search(r'(\d[\d,]*)\s+users?\s+', html, re.IGNORECASE)
            if user_match:
                result["user_results"] = user_match.group(1)
            repo_links = re.findall(r'href="/([^/]+/[^/]+?)"', html)
            result["repos"] = list(set(repo_links))[:10]
    except:
        pass
    return result


def check_google_mentions(query: str) -> dict:
    result = {"total_results": "0", "top_sites": []}
    try:
        url = f"https://www.google.com/search?q=%22{quote_plus(query)}%22"
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        })
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            count_match = re.search(r'About ([\d,]+) results', html)
            if count_match:
                result["total_results"] = count_match.group(1)
            domains = re.findall(r'<cite[^>]*>(.*?)</cite>', html, re.DOTALL)
            for d in domains[:8]:
                clean = re.sub(r'<[^>]+>', '', d).strip()
                if clean:
                    result["top_sites"].append(clean[:80])
    except:
        pass
    return result


def extract_all(query: str) -> dict:
    return {
        "wayback": check_wayback(query),
        "google_cache": check_google_cache(query),
        "pastebin": check_pastebin_search(query),
        "github": check_github_search(query),
        "google_mentions": check_google_mentions(query),
    }
