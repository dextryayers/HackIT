import httpx
import re
import asyncio
import json
from typing import List, Optional
from urllib.parse import quote
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, extract_emails
from osint_common import normalize_target, extract_ips

AHMIA_SEARCH = "https://ahmia.fi/search"
ONIONLAND_SEARCH = "https://onionland.io/api/v1/search"
DARKSEARCH_API = "https://darksearch.io/api/v1/search"
PASTEBIN_RAW = "https://pastebin.com/raw"
GHOSTBIN_RAW = "https://ghostbin.com/paste"
DPASTE_RAW = "https://dpaste.org/api/v1"
BREACHPARSE_API = "https://breachdirectory.org/api/v1/search"
TORCH_SEARCH = "http://xmh57jrknzkhv6y3ls3cfitzf7k2w35di5p6a5lny4ox4y5z5e3pwyd.onion/search"
DARKEYE_SEARCH = "https://darkeye.onion/search"

DARKWEB_SEARCH_ENGINES = [
    ("Ahmia", "https://ahmia.fi/search/?q={}"),
    ("Torch", "http://torchdeedp3i2j6scr2mlpvkdso2by3cnrqixrj7k63qdw7qyivd7qad.onion/search?query={}"),
    ("OnionLand", "https://onionland.io/search?q={}"),
    ("DarkSearch", "https://darksearch.io/api/search?query={}"),
    ("Haystack", "https://haystack.com/search?q={}"),
    ("DarkEye", "https://darkeye.onion/search?q={}"),
    ("Phobos", "https://phobos.onion/search?q={}"),
    ("Candle", "http://gjobqjj7wyczbqj.search?q={}"),
    ("DeepSearch", "https://deepsearch.onion/search?q={}"),
    ("Tor66", "http://tor66seweb.onion/search?q={}"),
]

EXTRA_DARKWEB_SEARCH_ENGINES = [
    ("Excavator", "https://excavator.onion/search?q={}"),
    ("DarkMist", "https://darkmist.onion/search?q={}"),
    ("OnionSearch", "https://onionsearch.onion/search?q={}"),
    ("DeepWebSearch", "https://deepwebsearch.onion/search?q={}"),
    ("TorSearch", "https://torsearch.onion/search?q={}"),
    ("HiddenWiki", "https://hiddenwiki.onion/search?q={}"),
    ("DarkLink", "https://darklink.onion/search?q={}"),
    ("Underground", "https://underground.onion/search?q={}"),
    ("BlackWeb", "https://blackweb.onion/search?q={}"),
    ("ShadowWeb", "https://shadowweb.onion/search?q={}"),
]

RANSOMWARE_GROUPS = [
    "conti", "lockbit", "revil", "darkside", "blackmatter", "hive",
    "clop", "babuk", "avaddon", "pysa", "neps", "everest", "lorenz",
    "ransomexx", "cuba", "vice society", "royal", "blackcat", "alphv",
    "play", "8base", "abysslocker", "akira", "bashe", "bianlian",
    "blackbyte", "blacksuit", "cactus", "cryptnet", "crylock",
    "donutleaks", "dragonforce", "dukes", "hunters international",
    "inc ransom", "lockbit 3.0", "malas", "medusa", "mogilevich",
    "monti", "noescape", "qilin", "ragroup", "ragnar locker",
    "ranion", "ransomhouse", "redalert", "rhysida", "scattered spider",
    "snatch", "spider", "stormous", "sugar", "trigona", "x001xs",
    "dark angels", "fog", "hellcat", "knight", "lynx", "malek",
    "nitrogen", "onepercent", "phantom", "profit", "rancsom",
    "sarcoma", "spacebears", "sparta", "storm",
    "synack", "threeam", "toufan", "vanilla", "vicesociety",
]

EXTRA_RANSOMWARE_GROUPS = [
    "blackbasta", "crylock", "hades", "hellokitty", "hollyrust",
    "icefire", "karma", "leaktherapist", "lv", "mindware",
    "moneymessage", "mosesstaff", "nightsky", "nvampt",
    "onepiece", "pandora", "prolock", "prometheus", "pwnd",
    "quantum", "ragnarlocker", "ranion", "ranzy", "redalert",
    "sabbath", "sakura", "sirius", "sparta", "stormous",
    "sugar", "tarile", "tellthem", "threeam", "trigona",
    "vicesociety", "x001xs", "yanluowang",
]

HACKER_FORUMS = [
    "breached", "exploit", "raidforums", "nulled", "hackforums",
    "xss", "oracle", "sinfulsite", "cracking", "leakforum",
    "leaksforum", "cybercarders", "carder", "darkweb",
    "torum", "darknet", "parliament", "hell", "infraud",
    "xss.is", "exploit.in", "cracked.io", "leak.sx", "nulled.to",
    "torum", "infraud", "carding", "cvv",
    "antichat", "blackhatworld", "defcon", "0day", "kernelmode",
]

EXTRA_HACKER_FORUMS = [
    "4chan", "8kun", "telegram", "discord", "irc",
    "hack5", "insec", "wrzuta", "dark0de", "crdpro",
    "validmarket", "bestvalid", "accountmarket", "cardvilla",
    "bmstore", "dumpshop", "ccshop", "cvvshop",
    "safedumps", "validcc", "legitcarder", "cardempire",
    "hackerone", "bugcrowd", "synack", "intigriti",
    "forum.dark", "onion.forum", "hiddenforum",
]

THREAT_KEYWORDS = [
    "leak", "breach", "dump", "stolen", "compromised", "hacked",
    "credential", "password", "email", "database", "sql dump",
    "access", "shell", "backdoor", "exploit", "0day", "rce",
    "malware", "ransomware", "trojan", "rat", "botnet", "ddos",
    "cvv", "fullz", "ssn", "dox", "doxx", "phish",
]

EXTRA_THREAT_KEYWORDS = [
    "pii", "personally identifiable", "identity theft",
    "credit card", "bank account", "wire transfer", "paypal",
    "login credentials", "email access", "webmail", "imap",
    "vpn", "rdp", "shell access", "root access",
    "admin panel", "cpanel", "whm", "wordpress admin",
    "cryptocurrency", "bitcoin", "monero", "eth", "wallet",
    "counterfeit", "fake id", "passport", "drivers license",
    "carding", "cvv", "fullz", "dox", "ssn", "sin",
    "bulletproof", "hosting", "vps", "dedicated server",
]

PASTE_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "aws_key", "ssh", "private key",
    "-----BEGIN", "jwt", "bearer", "authorization", "basic auth",
]

DARKWEB_PARSE_PATTERNS = {
    "timestamp": r'\b(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}(:\d{2})?)\b',
    "description": r'<meta[^>]+name="description"[^>]+content="([^"]+)"',
    "tags": r'\b(?:category|tag|label)[:=]\s*["\']?([^"\'&\s,]+)',
    "onion_address": r'([a-z2-7]{16,}\.onion)',
}

HACKER_FORUM_CLEARNET_MIRRORS = [
    ("Breached", "https://breached.vc/search?q={}"),
    ("Exploit", "https://exploit.in/search?q={}"),
    ("Nulled", "https://nulled.to/search?q={}"),
    ("Cracked", "https://cracked.io/search?q={}"),
    ("SinfulSite", "https://sinfulsite.com/search?q={}"),
    ("LeaksForum", "https://leaksforum.com/search?q={}"),
    ("DarkNet", "https://darknet.to/search?q={}"),
    ("0Day", "https://0day.to/search?q={}"),
    ("Carding", "https://cardingforum.com/search?q={}"),
    ("Cracking", "https://cracking.org/search?q={}"),
]

def parse_darkweb_metadata(html: str, url: str = "") -> dict:
    metadata = {}
    try:
        ts_match = re.findall(DARKWEB_PARSE_PATTERNS["timestamp"], html)
        if ts_match:
            metadata["timestamps"] = [m[0] for m in ts_match[:3]]
        desc_match = re.search(DARKWEB_PARSE_PATTERNS["description"], html, re.IGNORECASE)
        if desc_match:
            metadata["description"] = desc_match.group(1)[:200]
        tag_match = re.findall(DARKWEB_PARSE_PATTERNS["tags"], html, re.IGNORECASE)
        if tag_match:
            metadata["tags"] = list(set(tag_match[:5]))
        onion_match = re.findall(DARKWEB_PARSE_PATTERNS["onion_address"], url + " " + html, re.IGNORECASE)
        if onion_match:
            metadata["onion_addresses"] = list(set(onion_match[:5]))
    except:
        pass
    return metadata

async def generic_search(engine_name: str, url_template: str, target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        url = url_template.format(quote(target))
        resp = await safe_fetch(client, url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]*)</a>', resp.text)
            titles = re.findall(r'<h[234][^>]*>(.*?)</h[234]>', resp.text, re.DOTALL)
            for i, (url, title) in enumerate(links[:10]):
                t = re.sub(r'<[^>]+>', '', title).strip() or url[:60]
                results.append({"url": url, "title": t, "snippet": "", "source": engine_name})
    except:
        pass
    return results

async def search_all_engines(target: str, client: httpx.AsyncClient) -> List[dict]:
    all_results = []
    all_engines = DARKWEB_SEARCH_ENGINES + EXTRA_DARKWEB_SEARCH_ENGINES
    tasks = [generic_search(name, tmpl, target, client) for name, tmpl in all_engines]
    engine_results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in engine_results:
        if isinstance(res, list):
            all_results.extend(res)
    return all_results

async def search_ahmia(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, f"{AHMIA_SEARCH}/?q={quote(target)}", timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            links = re.findall(r'<a[^>]+href="(http://[a-z0-9]{16,}\.onion[^"]*)"[^>]*>([^<]*)</a>', resp.text)
            snippets = re.findall(r'<p class="snippet"[^>]*>([^<]*)</p>', resp.text)
            for i, (url, title) in enumerate(links[:15]):
                snippet = snippets[i] if i < len(snippets) else ""
                results.append({"url": url, "title": title.strip() or url[:60], "snippet": snippet.strip(), "source": "Ahmia"})
    except:
        pass
    return results

async def search_onionland(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, f"{ONIONLAND_SEARCH}?query={quote(target)}&page=1", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("results", data.get("data", []))[:15]:
                if isinstance(item, dict):
                    results.append({
                        "url": item.get("url", item.get("link", "")),
                        "title": item.get("title", item.get("name", ""))[:100],
                        "snippet": item.get("description", item.get("snippet", ""))[:200],
                        "source": "OnionLand",
                    })
    except:
        pass
    return results

async def search_darksearch(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        payload = {"query": target, "page": 1}
        resp = await safe_fetch(client, DARKSEARCH_API, json=payload, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", data.get("results", []))[:15]:
                if isinstance(item, dict):
                    results.append({
                        "url": item.get("url", item.get("link", "")),
                        "title": item.get("title", "")[:100],
                        "snippet": item.get("description", item.get("snippet", ""))[:200],
                        "source": "DarkSearch",
                    })
    except:
        pass
    return results

async def search_pastebin(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, f"https://psbdmp.ws/api/v3/search?q={quote(target)}", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for entry in data[:20]:
                    paste_id = entry.get("id", "")
                    title = entry.get("title", entry.get("filename", ""))
                    section = entry.get("section", "")
                    if paste_id:
                        results.append({
                            "id": paste_id,
                            "title": f"Pastebin {paste_id}: {title[:80]}" if title else f"Pastebin {paste_id}",
                            "url": f"https://pastebin.com/{paste_id}",
                            "section": section,
                            "source": "Pastebin",
                        })
        resp2 = await safe_fetch(client, f"https://psbdmp.ws/api/v3/search?q={quote(target.split('.')[0])}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp2.status_code == 200:
            data2 = resp2.json()
            if isinstance(data2, list):
                seen_ids = {r.get("id", "") for r in results}
                for entry in data2[:10]:
                    paste_id = entry.get("id", "")
                    if paste_id not in seen_ids:
                        seen_ids.add(paste_id)
                        results.append({
                            "id": paste_id,
                            "title": f"Pastebin {paste_id}",
                            "url": f"https://pastebin.com/{paste_id}",
                            "source": "Pastebin",
                        })
    except:
        pass
    return results

async def fetch_paste_content(url: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await safe_fetch(client, url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.text[:5000]
    except:
        pass
    return ""

async def fetch_paste_content_fallback(paste_id: str, target: str, client: httpx.AsyncClient) -> str:
    fallback_urls = [
        f"https://scrape.pastebin.com/api_scrape_item.php&i={paste_id}",
        f"https://pastebin.pl/api/raw/{paste_id}",
        f"https://rentry.org/{target}/raw",
    ]
    for url in fallback_urls:
        try:
            resp = await safe_fetch(client, url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and len(resp.text) > 20:
                return resp.text[:5000]
        except:
            continue
    return ""

def analyze_content_for_threats(text: str, target: str) -> List[dict]:
    threats = []
    if not text:
        return threats
    text_lower = text.lower()
    found_keywords = set()
    all_threat_keywords = THREAT_KEYWORDS + EXTRA_THREAT_KEYWORDS
    for kw in all_threat_keywords:
        if kw in text_lower:
            found_keywords.add(kw)
    if found_keywords:
        threats.append({
            "entity": f"Threat keywords found: {', '.join(sorted(found_keywords)[:8])}",
            "type": "Threat Keyword Match",
            "color": "red",
            "threat": "High Risk",
        })
    emails = extract_emails(text)
    if emails:
        target_emails = [e for e in emails if target.lower() in e.lower()]
        if target_emails:
            threats.append({
                "entity": f"Target email(s) leaked: {', '.join(target_emails[:5])}",
                "type": "Credential Leak Indicator",
                "color": "red",
                "threat": "Critical",
            })
    ips = extract_ips(text)
    if ips:
        threats.append({
            "entity": f"IP addresses found: {', '.join(ips[:5])}",
            "type": "IP Disclosure",
            "color": "orange",
            "threat": "Elevated Risk",
        })
    for kw in PASTE_KEYWORDS:
        if kw in text_lower:
            threats.append({
                "entity": f"Secret/key pattern detected: {kw}",
                "type": "Sensitive Data Exposure",
                "color": "red",
                "threat": "High Risk",
            })
            break
    return threats

def check_ransomware_mentions(text: str, target: str) -> List[dict]:
    mentions = []
    text_lower = text.lower() + " " + target.lower()
    all_ransomware = RANSOMWARE_GROUPS + EXTRA_RANSOMWARE_GROUPS
    for group in all_ransomware:
        if group in text_lower:
            mentions.append(group)
    return mentions

def check_forum_mentions(text: str) -> List[dict]:
    mentions = []
    text_lower = text.lower()
    all_forums = HACKER_FORUMS + EXTRA_HACKER_FORUMS
    for forum in all_forums:
        if forum in text_lower:
            mentions.append(forum)
    return mentions

async def search_torch(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, f"{TORCH_SEARCH}?q={quote(target)}&action=search", timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]*)</a>', resp.text)
            snippets = re.findall(r'<p[^>]*class="[^"]*desc[^"]*"[^>]*>([^<]*)</p>', resp.text)
            for i, (url, title) in enumerate(links[:15]):
                snippet = snippets[i] if i < len(snippets) else ""
                results.append({"url": url, "title": title.strip() or url[:60], "snippet": snippet.strip(), "source": "Torch"})
    except:
        pass
    return results

async def search_darkeye(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await safe_fetch(client, f"{DARKEYE_SEARCH}?q={quote(target)}", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]*)</a>', resp.text)
            snippets = re.findall(r'<p[^>]*class="[^"]*result[^"]*"[^>]*>([^<]*)</p>', resp.text)
            for i, (url, title) in enumerate(links[:15]):
                snippet = snippets[i] if i < len(snippets) else ""
                results.append({"url": url, "title": title.strip() or url[:60], "snippet": snippet.strip(), "source": "DarkEye"})
    except:
        pass
    return results

async def search_recon(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    urls = [
        f"https://www.google.com/search?q={quote(f'site:onion {target}')}",
        f"https://duckduckgo.com/html/?q={quote(f'{target} deep web')}",
    ]
    try:
        for url in urls:
            try:
                resp = await safe_fetch(client, url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
                if resp.status_code == 200:
                    links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(?:<[^>]+>)*([^<]*)', resp.text)
                    for link_url, link_title in links[:10]:
                        if target.lower() in link_title.lower() or target.lower() in link_url.lower():
                            results.append({"url": link_url, "title": link_title.strip()[:100], "snippet": "", "source": "Recon"})
            except:
                continue
    except:
        pass
    return results

async def check_ramp_forum(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    ramp_urls = [
        "http://ramp4u5l4dxtd2l6tya5v5b7l6lxr5z5e5p5a5l5n5y5o5x5y5z5e3pwyd.onion",
        "http://ramp5l4dxtd2l6tya5v5b7l6lxr5z5e5p5a5l5n5y5o5x5y5z5e3pwyd.onion",
    ]
    try:
        for ramp_url in ramp_urls:
            try:
                resp = await safe_fetch(client, f"{ramp_url}/search?q={quote(target)}", timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    matches = re.findall(rf'[^.]*?{re.escape(target)}[^<]*', resp.text, re.IGNORECASE)
                    for match in matches[:10]:
                        results.append({
                            "url": ramp_url,
                            "title": f"RAMP mention: {match.strip()[:100]}",
                            "snippet": match.strip()[:200],
                            "source": "RAMP Forum",
                        })
            except:
                continue
    except:
        pass
    return results

async def search_forum_mirrors(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    for forum_name, url_tmpl in HACKER_FORUM_CLEARNET_MIRRORS:
        try:
            url = url_tmpl.format(quote(target))
            resp = await safe_fetch(client, url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp.status_code == 200 and len(resp.text) > 500:
                results.append({
                    "url": url,
                    "title": f"Mention on {forum_name} forum",
                    "snippet": resp.text[:200],
                    "source": f"ForumMirror/{forum_name}",
                })
        except:
            pass
    return results

def compute_darkweb_threat_score(all_darkweb_results: list, pastebin_results: list,
                                 ransom_mentions: list, forum_mentions: list,
                                 credential_leaks: int, target: str) -> dict:
    score = 0
    breakdown = {}

    dw_count = len(all_darkweb_results)
    if dw_count > 0:
        dw_score = min(dw_count * 5, 25)
        score += dw_score
        breakdown["dark_web_results"] = {"count": dw_count, "score": dw_score, "max": 25}

    paste_count = len(pastebin_results)
    if paste_count > 0:
        paste_score = min(paste_count * 4, 20)
        score += paste_score
        breakdown["paste_site_findings"] = {"count": paste_count, "score": paste_score, "max": 20}

    ransom_count = len(ransom_mentions)
    if ransom_count > 0:
        ransom_score = min(ransom_count * 10, 30)
        score += ransom_score
        breakdown["ransomware_mentions"] = {"count": ransom_count, "score": ransom_score, "max": 30}

    forum_count = len(forum_mentions)
    if forum_count > 0:
        forum_score = min(forum_count * 5, 15)
        score += forum_score
        breakdown["hacker_forum_mentions"] = {"count": forum_count, "score": forum_score, "max": 15}

    leak_count = credential_leaks
    if leak_count > 0:
        leak_score = min(leak_count * 10, 30)
        score += leak_score
        breakdown["credential_leaks"] = {"count": leak_count, "score": leak_score, "max": 30}

    score = min(score, 100)

    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    elif score >= 20:
        severity = "Low"
    else:
        severity = "Informational"

    return {
        "score": score,
        "severity": severity,
        "breakdown": breakdown,
    }

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    ahmia_results = await search_ahmia(normalized, client)
    onionland_results = await search_onionland(normalized, client)
    darksearch_results = await search_darksearch(normalized, client)
    torch_results = await search_torch(normalized, client)
    darkeye_results = await search_darkeye(normalized, client)
    recon_results = await search_recon(normalized, client)
    ramp_results = await check_ramp_forum(normalized, client)
    pastebin_results = await search_pastebin(normalized, client)
    all_engine_results = await search_all_engines(normalized, client)
    forum_mirror_results = await search_forum_mirrors(normalized, client)

    all_darkweb_results = ahmia_results + onionland_results + darksearch_results + torch_results + darkeye_results + recon_results + ramp_results + all_engine_results + forum_mirror_results

    global_ransom_mentions = []
    global_forum_mentions = []
    global_credential_leaks = 0

    if all_darkweb_results:
        for result in all_darkweb_results[:35]:
            url = result.get("url", "")
            title = result.get("title", "")[:200]
            snippet = result.get("snippet", "")
            source = result.get("source", "DarkWeb")

            findings.append(make_finding(
                title or url[:200],
                "Dark Web Mention", "DarkWebIntel",
                confidence="Low", color="red", threat_level="High Risk",
                status="Found", resolution=normalized,
                raw_data=f"[{source}] URL: {url}\nTitle: {title}\nSnippet: {snippet}",
                tags=[source.lower(), "dark-web", "mention"]))

            if snippet:
                threats = analyze_content_for_threats(snippet, normalized)
                for t in threats:
                    findings.append(make_finding(
                        t["entity"], t["type"], "DarkWebIntel",
                        confidence="Low", color=t["color"], threat_level=t["threat"],
                        resolution=url[:100],
                        tags=["threat-analysis", "dark-web"]))
                    if t["type"] == "Credential Leak Indicator":
                        global_credential_leaks += 1

                ransom_groups = check_ransomware_mentions(snippet, normalized)
                if ransom_groups:
                    global_ransom_mentions.extend(ransom_groups)
                    for group in ransom_groups[:3]:
                        findings.append(make_finding(
                            f"Ransomware group mentioned: {group}",
                            "Ransomware Intelligence", "DarkWebIntel",
                            confidence="Low", color="red", threat_level="Critical",
                            resolution=url[:100],
                            raw_data=f"Ransomware: {group}, Source: {url}",
                            tags=["ransomware", group.lower().replace(" ", "-")]))

                forums = check_forum_mentions(snippet)
                if forums:
                    global_forum_mentions.extend(forums)
                    for forum in forums[:3]:
                        findings.append(make_finding(
                            f"Hacker forum mentioned: {forum}",
                            "Hacker Forum Intel", "DarkWebIntel",
                            confidence="Low", color="red", threat_level="High Risk",
                            resolution=url[:100],
                            raw_data=f"Forum: {forum}, Source: {url}",
                            tags=["hacker-forum", forum.lower().replace(" ", "-")]))

        total_dw = len(all_darkweb_results)
        total_onion = sum(1 for r in all_darkweb_results if ".onion" in (r.get("url", "") or ""))
        threat_score = compute_darkweb_threat_score(
            all_darkweb_results, pastebin_results,
            global_ransom_mentions, global_forum_mentions,
            global_credential_leaks, normalized)

        engine_dist = {}
        for r in all_darkweb_results:
            s = r.get("source", "Unknown")
            engine_dist[s] = engine_dist.get(s, 0) + 1
        engine_str = ", ".join(f"{k}: {v}" for k, v in sorted(engine_dist.items(), key=lambda x: -x[1]))

        findings.append(make_finding(
            f"{total_dw} dark web results ({total_onion} .onion sites) from {len(engine_dist)} engines\n{engine_str}\nThreat Score: {threat_score['score']}/100 ({threat_score['severity']})",
            "Dark Web Search Summary", "DarkWebIntel",
            confidence="Medium", color="red", threat_level=threat_score['severity'],
            resolution=normalized,
            raw_data=f"Total: {total_dw}, .onion: {total_onion}, Score: {threat_score['score']}/100, Severity: {threat_score['severity']}, Breakdown: {json.dumps(threat_score['breakdown'])}",
            tags=["dark-web-summary", f"threat-score-{threat_score['score']}"]))

        if all_engine_results:
            findings.append(make_finding(
                f"{len(all_engine_results)} results from additional dark web search engines",
                "Multi-Engine Dark Web Search", "DarkWebIntel",
                confidence="Medium", color="slate", threat_level="Informational",
                resolution=normalized,
                tags=["multi-engine", "dark-web", "coverage"]))

        if forum_mirror_results:
            findings.append(make_finding(
                f"{len(forum_mirror_results)} hacker forum mirror mentions",
                "Hacker Forum Mirror Search", "DarkWebIntel",
                confidence="Low", color="red", threat_level="High Risk",
                resolution=normalized,
                tags=["forum-mirror", "dark-web"]))

    if pastebin_results:
        for paste in pastebin_results[:15]:
            paste_title = paste.get("title", "")[:200]
            paste_url = paste.get("url", "")
            paste_id = paste.get("id", "")

            findings.append(make_finding(
                paste_title, "Paste Site Leak", "DarkWebIntel",
                confidence="Low", color="red", threat_level="High Risk",
                status="Found", resolution=normalized,
                raw_data=f"Paste URL: {paste_url}, ID: {paste_id}",
                tags=["paste", "leak", "dark-web"]))

            paste_content = await fetch_paste_content(paste_url, client)
            if not paste_content and paste_id:
                paste_content = await fetch_paste_content_fallback(paste_id, normalized, client)
            if paste_content:
                threats = analyze_content_for_threats(paste_content, normalized)
                for t in threats:
                    findings.append(make_finding(
                        t["entity"], t["type"], "DarkWebIntel",
                        confidence="Low", color=t["color"], threat_level=t["threat"],
                        resolution=paste_url,
                        tags=["paste-content", "threat-analysis"]))
                    if t["type"] == "Credential Leak Indicator":
                        global_credential_leaks += 1

                ransom_groups = check_ransomware_mentions(paste_content, normalized)
                if ransom_groups:
                    global_ransom_mentions.extend(ransom_groups)
                    for group in ransom_groups[:3]:
                        findings.append(make_finding(
                            f"Paste mentions ransomware: {group}",
                            "Ransomware Paste Intel", "DarkWebIntel",
                            confidence="Low", color="red", threat_level="Critical",
                            resolution=paste_url,
                            raw_data=f"Ransomware: {group}, Paste: {paste_url}",
                            tags=["ransomware", group.lower().replace(" ", "-")]))

                forums = check_forum_mentions(paste_content)
                if forums:
                    global_forum_mentions.extend(forums)
                    for forum in forums[:3]:
                        findings.append(make_finding(
                            f"Paste mentions forum: {forum}",
                            "Hacker Forum Paste Intel", "DarkWebIntel",
                            confidence="Low", color="red", threat_level="High Risk",
                            resolution=paste_url,
                            tags=["hacker-forum", forum.lower().replace(" ", "-")]))

            target_leaks = [f for f in findings if f.type == "Credential Leak Indicator" and normalized.lower() in str(f.raw_data).lower()]
            if target_leaks:
                findings.append(make_finding(
                    f"DATA LEAK: Credentials referencing {normalized} found in paste",
                    "Target Data Leak", "DarkWebIntel",
                    confidence="Low", color="red", threat_level="Critical",
                    resolution=paste_url,
                    tags=["data-leak", "critical", "dark-web"]))

        findings.append(make_finding(
            f"{len(pastebin_results)} paste entries associated with target",
            "Paste Monitoring Summary", "DarkWebIntel",
            confidence="Medium", color="red", threat_level="Elevated Risk",
            resolution=normalized, tags=["paste-summary"]))

    source_count = {}
    for result in all_darkweb_results + pastebin_results:
        source = result.get("source", "Unknown")
        source_count[source] = source_count.get(source, 0) + 1
    if source_count:
        source_str = ", ".join(f"{k}: {v}" for k, v in sorted(source_count.items()))
        findings.append(make_finding(
            source_str, "Dark Web Source Distribution", "DarkWebIntel",
            confidence="Medium", color="slate", threat_level="Informational",
            resolution=normalized, tags=["source-distribution"]))

    if not all_darkweb_results and not pastebin_results:
        findings.append(make_finding(
            normalized, "Dark Web Intel No Results", "DarkWebIntel",
            confidence="Low", color="slate", threat_level="Informational",
            status="Not Found", resolution=normalized,
            raw_data="No dark web or paste data found for the target",
            tags=["empty"]))

    return findings
