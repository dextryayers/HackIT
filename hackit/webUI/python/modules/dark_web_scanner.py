import httpx
import asyncio
import re
import random
from urllib.parse import quote, urlparse
from models import IntelligenceFinding
from typing import List, Dict, Optional

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

THREAT_CLASSIFICATIONS = {
    "data_leak": {
        "keywords": ["leak", "dump", "exposed", "breach", "leaked", "database dump", "sql dump"],
        "threat": "High Risk",
        "color": "red",
    },
    "credential_exposure": {
        "keywords": ["password", "credentials", "login", "email:password", "combo", "user:pass"],
        "threat": "Critical",
        "color": "red",
    },
    "planned_attack": {
        "keywords": ["attack", "target", "hack", "ddos", "exploit", "vulnerability", "0day", "zero-day"],
        "threat": "Critical",
        "color": "red",
    },
    "pii_sale": {
        "keywords": ["ssn", "d.o.b", "date of birth", "fullz", "address", "credit card", "cvv", "identity"],
        "threat": "High Risk",
        "color": "orange",
    },
    "malware_distribution": {
        "keywords": ["malware", "trojan", "ransomware", "backdoor", "rat", "payload", "shell", "c2", "command & control"],
        "threat": "Critical",
        "color": "red",
    },
    "forum_mention": {
        "keywords": ["discussion", "thread", "post", "topic", "member"],
        "threat": "Elevated Risk",
        "color": "orange",
    },
    "marketplace_listing": {
        "keywords": ["sell", "buy", "price", "shop", "market", "listing", "sale", "vendor"],
        "threat": "High Risk",
        "color": "orange",
    },
}

DARKWEB_FORUMS = [
    "exploit", "raid", "breach", "cracking", "hack", "blackhat",
    "carding", "leaks", "warez", "dark", "tor", "hidden",
]

THREAT_INDICATORS = {
    "ransomware": ["ransomware", "lockbit", "hive", "blackcat", "clop", "alphv", "blackbasta", "royal", "play"],
    "hacktivism": ["hacktivist", "anonymous", "op", "operation", "defaced", "take down"],
    "apt": ["apt", "advanced persistent", "state-sponsored", "intel", "cyber espionage"],
}

PASTE_DETECT_KEYWORDS = [
    "password", "passwd", "secret", "token", "api", "key", "login", "email",
    "admin", "root", "database", "dump", "sql", "backup", "config", "env",
]

async def search_ahmia(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            result_items = re.findall(r'<div[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            for item in result_items[:20]:
                link = re.search(r'href="(https?://[^"]+)"', item)
                title = re.search(r'<h4[^>]*>(.*?)</h4>', item, re.DOTALL)
                snippet = re.search(r'<p[^>]*>(.*?)</p>', item, re.DOTALL)
                url = link.group(1) if link else ""
                title_text = re.sub(r'<[^>]+>', '', title.group(1)).strip() if title else ""
                snippet_text = re.sub(r'<[^>]+>', '', snippet.group(1)).strip() if snippet else ""
                if url:
                    results.append({
                        "url": url[:500],
                        "title": title_text[:200],
                        "snippet": snippet_text[:500],
                        "source": "Ahmia",
                    })
    except Exception:
        pass
    return results

async def search_onionland(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"https://onionland.io/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            result_blocks = re.findall(r'<div[^>]*class="[^"]*(?:result|search-result)[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            for block in result_blocks[:20]:
                link = re.search(r'href="(https?://[^"]+\.onion[^"]*)"', block)
                title = re.search(r'<a[^>]*>(.*?)</a>', block, re.DOTALL)
                snippet = re.search(r'<p[^>]*>(.*?)</p>', block, re.DOTALL)
                url = link.group(1) if link else ""
                title_text = re.sub(r'<[^>]+>', '', title.group(1)).strip() if title else ""
                snippet_text = re.sub(r'<[^>]+>', '', snippet.group(1)).strip() if snippet else ""
                if url:
                    results.append({
                        "url": url[:500],
                        "title": title_text[:200],
                        "snippet": snippet_text[:500],
                        "source": "OnionLand",
                    })
    except Exception:
        pass
    return results

async def search_darksearch(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"https://darksearch.io/api/search?query={quote(query)}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("data", [])[:20]:
                results.append({
                    "url": item.get("url", "")[:500],
                    "title": item.get("title", "")[:200],
                    "snippet": item.get("description", "")[:500],
                    "source": "DarkSearch",
                })
    except Exception:
        pass
    return results

async def search_torch(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"http://torchdeedp3i2j6scr2mlpvkdso2by3cnrqixrj7k63qdw7qyivd7qad.onion/search?query={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            result_items = re.findall(r'<div[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            for item in result_items[:20]:
                link = re.search(r'href="(https?://[^"]+)"', item)
                title = re.search(r'<h3[^>]*>(.*?)</h3>', item, re.DOTALL)
                snippet = re.search(r'<p[^>]*>(.*?)</p>', item, re.DOTALL)
                url = link.group(1) if link else ""
                title_text = re.sub(r'<[^>]+>', '', title.group(1)).strip() if title else ""
                snippet_text = re.sub(r'<[^>]+>', '', snippet.group(1)).strip() if snippet else ""
                if url:
                    results.append({
                        "url": url[:500],
                        "title": title_text[:200],
                        "snippet": snippet_text[:500],
                        "source": "Torch",
                    })
    except Exception:
        pass
    return results

async def search_haystack(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"https://haystack.com/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            result_items = re.findall(r'<div[^>]*class="[^"]*(?:result|haystack-result)[^"]*"[^>]*>(.*?)</div>', html, re.DOTALL)
            for item in result_items[:20]:
                link = re.search(r'href="(https?://[^"]+)"', item)
                title = re.search(r'<h[23][^>]*>(.*?)</h[23]>', item, re.DOTALL)
                snippet = re.search(r'<p[^>]*>(.*?)</p>', item, re.DOTALL)
                url = link.group(1) if link else ""
                title_text = re.sub(r'<[^>]+>', '', title.group(1)).strip() if title else ""
                snippet_text = re.sub(r'<[^>]+>', '', snippet.group(1)).strip() if snippet else ""
                if url:
                    results.append({
                        "url": url[:500],
                        "title": title_text[:200],
                        "snippet": snippet_text[:500],
                        "source": "Haystack",
                    })
    except Exception:
        pass
    return results

async def search_phobos(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"https://phobos.onion/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]*)</a>', html)
            for url, title in links[:15]:
                results.append({
                    "url": url[:500],
                    "title": title.strip()[:200] or url[:60],
                    "snippet": "",
                    "source": "Phobos",
                })
    except Exception:
        pass
    return results

async def search_sentor(client: httpx.AsyncClient, query: str) -> List[Dict]:
    results = []
    try:
        search_url = f"https://sentor.onion/search?q={quote(query)}"
        headers = {"User-Agent": UA}
        resp = await client.get(search_url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            html = resp.text
            links = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]*)</a>', html)
            for url, title in links[:15]:
                results.append({
                    "url": url[:500],
                    "title": title.strip()[:200] or url[:60],
                    "snippet": "",
                    "source": "Sentor",
                })
    except Exception:
        pass
    return results

def classify_threat(text: str) -> List[tuple]:
    classifications = []
    text_lower = text.lower()
    for classification, config in THREAT_CLASSIFICATIONS.items():
        matches = 0
        for keyword in config["keywords"]:
            if keyword in text_lower:
                matches += 1
        if matches >= 2:
            classifications.append((classification, config["threat"], config["color"]))
        elif matches >= 1:
            classifications.append((classification, "Elevated Risk", "orange"))
    for threat_type, indicators in THREAT_INDICATORS.items():
        for indicator in indicators:
            if indicator in text_lower:
                classifications.append((f"threat_{threat_type}", "Critical", "red"))
                break
    return classifications

def extract_onion_urls(text: str) -> List[str]:
    return re.findall(r'\b[a-z2-7]{16,56}\.onion\b', text)

def calculate_confidence(title: str, snippet: str, url: str) -> str:
    combined = f"{title} {snippet} {url}".lower()
    signals = 0
    for word in ["password", "leak", "breach", "dump", "hack", "exploit", "0day", "sell", "buy", "target"]:
        if word in combined:
            signals += 2
    for word in ["discuss", "thread", "post", "market", "forum"]:
        if word in combined:
            signals += 1
    if signals >= 4:
        return "High"
    elif signals >= 2:
        return "Medium"
    return "Low"

def detect_paste_content(text: str) -> List[str]:
    found = []
    text_lower = text.lower()
    for kw in PASTE_DETECT_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return found

async def process_result(result: Dict, query: str) -> List[IntelligenceFinding]:
    findings = []
    url = result.get("url", "")
    title = result.get("title", "")
    snippet = result.get("snippet", "")
    source = result.get("source", "DarkWeb")

    combined = f"{title} {snippet}"
    classifications = classify_threat(combined)
    confidence = calculate_confidence(title, snippet, url)
    is_onion = ".onion" in url
    onion_urls = extract_onion_urls(combined)
    all_onion_urls = set(onion_urls)
    if is_onion:
        all_onion_urls.add(url)

    paste_keywords = detect_paste_content(combined)
    if paste_keywords:
        findings.append(IntelligenceFinding(
            entity=f"Sensitive content indicators: {', '.join(paste_keywords[:5])}",
            type="DarkWeb: Sensitive Content Detection",
            source=f"DarkWeb/{source}",
            confidence=confidence,
            color="orange",
            threat_level="Elevated Risk",
            status="Monitoring",
            resolution=f"URL: {url[:200]}",
            raw_data=f"Keywords: {paste_keywords}\\nTitle: {title}",
            tags=["sensitive", "content-analysis", source.lower()]
        ))

    if classifications:
        primary_class = classifications[0]
        classification_name = primary_class[0]
        threat = primary_class[1]
        color = primary_class[2]
        display_label = classification_name.replace("_", " ").title()
        entity_text = title[:150] if title else url[:150]
        findings.append(IntelligenceFinding(
            entity=entity_text,
            type=f"DarkWeb: {display_label}",
            source=f"DarkWeb/{source}",
            confidence=confidence,
            color=color,
            threat_level=threat,
            status="Active Threat" if threat in ("Critical", "High Risk") else "Monitoring",
            resolution=f"URL: {url[:200]}",
            raw_data=f"Title: {title}\\nSnippet: {snippet}\\nSource: {source}",
            tags=["dark-web", "tor", source.lower(), classification_name] + (
                [f"onion:{u}" for u in list(all_onion_urls)[:3]] if all_onion_urls else [])
        ))
        if len(classifications) > 1:
            secondary = classifications[1]
            findings.append(IntelligenceFinding(
                entity=f"Additional classification: {secondary[0].replace('_', ' ').title()}",
                type="DarkWeb: Secondary Classification",
                source=f"DarkWeb/{source}",
                confidence=confidence,
                color=secondary[2],
                threat_level=secondary[1],
                status="Monitoring",
                resolution=url[:200],
                tags=["dark-web", "classification", secondary[0]]
            ))
    elif is_onion or any(domain in combined.lower() for domain in ["exploit", "breach", "hack", "forum", "market"]):
        findings.append(IntelligenceFinding(
            entity=title[:150] if title else url[:150],
            type="DarkWeb: Mention",
            source=f"DarkWeb/{source}",
            confidence=confidence,
            color="slate",
            threat_level="Elevated Risk",
            status="Monitoring",
            resolution=f"URL: {url[:200]}",
            raw_data=f"Title: {title}\\nSnippet: {snippet}",
            tags=["dark-web", "mention", source.lower()] + (
                [f"onion:{u}" for u in list(all_onion_urls)[:3]] if all_onion_urls else [])
        ))

    return findings

async def resolve_onion_services(all_results: List[Dict]) -> List[str]:
    onion_urls = set()
    for r in all_results:
        url = r.get("url", "")
        if ".onion" in url:
            onion_urls.add(url[:100])
        snippet = r.get("snippet", "")
        onion_urls.update(extract_onion_urls(snippet))
    return list(onion_urls)[:10]

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    queries = [domain]
    domain_parts = domain.split('.')
    if len(domain_parts) > 1:
        queries.append(domain_parts[0])

    if '@' in target:
        email_query = target.strip()
        queries = [email_query, email_query.split('@')[1]]

    all_results = []

    for query in queries[:2]:
        search_tasks = [
            search_ahmia(client, query),
            search_onionland(client, query),
            search_darksearch(client, query),
            search_torch(client, query),
            search_haystack(client, query),
            search_phobos(client, query),
            search_sentor(client, query),
        ]
        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        for result_list in search_results:
            if isinstance(result_list, list):
                for result in result_list:
                    if result not in all_results:
                        all_results.append(result)

    process_tasks = [process_result(result, domain) for result in all_results]
    processed = await asyncio.gather(*process_tasks, return_exceptions=True)
    for f_list in processed:
        if isinstance(f_list, list):
            findings.extend(f_list)

    onion_services = await resolve_onion_services(all_results)
    if onion_services:
        findings.append(IntelligenceFinding(
            entity=f"{len(onion_services)} .onion hidden services discovered",
            type="DarkWeb: Onion Services Discovery",
            source="DarkWebScanner",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            resolution=domain,
            raw_data="\\n".join(onion_services[:10]),
            tags=["onion", "hidden-service", "discovery"]
        ))

    threat_counts = {}
    source_counts = {}
    onion_urls_found = set()
    for f in findings:
        ftype = f.type
        threat_counts[ftype] = threat_counts.get(ftype, 0) + 1
        source = f.source.split('/')[-1] if '/' in f.source else f.source
        source_counts[source] = source_counts.get(source, 0) + 1
        for tag in f.tags:
            if tag.startswith("onion:"):
                onion_urls_found.add(tag.replace("onion:", ""))

    if findings:
        threat_levels = set(f.threat_level for f in findings)
        highest_threat = "Informational"
        if "Critical" in threat_levels:
            highest_threat = "Critical"
        elif "High Risk" in threat_levels:
            highest_threat = "High Risk"
        elif "Elevated Risk" in threat_levels:
            highest_threat = "Elevated Risk"

        summary_lines = [
            f"Total dark web findings: {len(findings)}",
            f"Highest threat level: {highest_threat}",
            f"Search engines used: 7 (Ahmia, OnionLand, DarkSearch, Torch, Haystack, Phobos, Sentor)",
            f"Sources: {', '.join(source_counts.keys())}",
        ]
        if onion_urls_found:
            summary_lines.append(f"Hidden services found: {', '.join(list(onion_urls_found)[:5])}")
        if threat_counts:
            summary_lines.append("Classification breakdown:")
            for cls, count in sorted(threat_counts.items(), key=lambda x: -x[1]):
                summary_lines.append(f"  {cls}: {count}")

        color = "red" if highest_threat in ("Critical", "High Risk") else "orange" if highest_threat == "Elevated Risk" else "slate"
        findings.append(IntelligenceFinding(
            entity=f"Dark Web Scan: {len(findings)} results | Highest: {highest_threat}",
            type="DarkWeb: Summary",
            source="DarkWebScanner",
            confidence="Medium",
            color=color,
            threat_level=highest_threat,
            raw_data="\\n".join(summary_lines),
            tags=["summary", "dark-web", "tor"] + [f"onion:{u}" for u in list(onion_urls_found)[:5]]
        ))

    return findings
