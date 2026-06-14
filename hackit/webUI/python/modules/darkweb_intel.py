import httpx
import re
import asyncio
import json
from typing import List, Optional
from urllib.parse import quote
from models import IntelligenceFinding
from osint_common import normalize_target, make_finding, extract_emails, extract_ips

AHMIA_SEARCH = "https://ahmia.fi/search"
ONIONLAND_SEARCH = "https://onionland.io/api/v1/search"
DARKSEARCH_API = "https://darksearch.io/api/v1/search"
PASTEBIN_RAW = "https://pastebin.com/raw"
GHOSTBIN_RAW = "https://ghostbin.com/paste"
DPASTE_RAW = "https://dpaste.org/api/v1"
BREACHPARSE_API = "https://breachdirectory.org/api/v1/search"

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
]

HACKER_FORUMS = [
    "breached", "exploit", "raidforums", "nulled", "hackforums",
    "xss", "oracle", "sinfulsite", "cracking", "leakforum",
    "leaksforum", "cybercarders", "carder", "darkweb",
    "torum", "darknet", "parliament", "hell", "infraud",
]

THREAT_KEYWORDS = [
    "leak", "breach", "dump", "stolen", "compromised", "hacked",
    "credential", "password", "email", "database", "sql dump",
    "access", "shell", "backdoor", "exploit", "0day", "rce",
    "malware", "ransomware", "trojan", "rat", "botnet", "ddos",
    "cvv", "fullz", "ssn", "dox", "doxx", "phish",
]

PASTE_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "aws_key", "ssh", "private key",
    "-----BEGIN", "jwt", "bearer", "authorization", "basic auth",
]

async def search_ahmia(target: str, client: httpx.AsyncClient) -> List[dict]:
    results = []
    try:
        resp = await client.get(f"{AHMIA_SEARCH}/?q={quote(target)}", timeout=20.0,
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
        resp = await client.get(f"{ONIONLAND_SEARCH}?query={quote(target)}&page=1", timeout=15.0,
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
        resp = await client.post(DARKSEARCH_API, json=payload, timeout=15.0,
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
        resp = await client.get(f"https://psbdmp.ws/api/v3/search?q={quote(target)}", timeout=15.0,
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
        resp2 = await client.get(f"https://psbdmp.ws/api/v3/search?q={quote(target.split('.')[0])}", timeout=10.0,
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
        resp = await client.get(url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.text[:5000]
    except:
        pass
    return ""

def analyze_content_for_threats(text: str, target: str) -> List[dict]:
    threats = []
    if not text:
        return threats
    text_lower = text.lower()
    found_keywords = set()
    for kw in THREAT_KEYWORDS:
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
        target_emails = [e for e in emails if target.lower() in e.lower() or target.split('.')[0].lower() in e.lower()]
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
    for group in RANSOMWARE_GROUPS:
        if group in text_lower:
            mentions.append(group)
    return mentions

def check_forum_mentions(text: str) -> List[dict]:
    mentions = []
    text_lower = text.lower()
    for forum in HACKER_FORUMS:
        if forum in text_lower:
            mentions.append(forum)
    return mentions

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    normalized = normalize_target(target)

    ahmia_results = await search_ahmia(normalized, client)
    onionland_results = await search_onionland(normalized, client)
    darksearch_results = await search_darksearch(normalized, client)
    pastebin_results = await search_pastebin(normalized, client)

    all_darkweb_results = ahmia_results + onionland_results + darksearch_results
    if all_darkweb_results:
        for result in all_darkweb_results[:25]:
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

                ransom_groups = check_ransomware_mentions(snippet, normalized)
                if ransom_groups:
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
        findings.append(make_finding(
            f"{total_dw} dark web results ({total_onion} .onion sites)",
            "Dark Web Search Summary", "DarkWebIntel",
            confidence="Medium", color="red", threat_level="Elevated Risk",
            resolution=normalized,
            raw_data=f"Total: {total_dw}, .onion: {total_onion}",
            tags=["dark-web-summary"]))

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
            if paste_content:
                threats = analyze_content_for_threats(paste_content, normalized)
                for t in threats:
                    findings.append(make_finding(
                        t["entity"], t["type"], "DarkWebIntel",
                        confidence="Low", color=t["color"], threat_level=t["threat"],
                        resolution=paste_url,
                        tags=["paste-content", "threat-analysis"]))

                ransom_groups = check_ransomware_mentions(paste_content, normalized)
                if ransom_groups:
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
