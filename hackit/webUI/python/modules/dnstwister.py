import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

COMMON_TLDS = ["com", "net", "org", "co", "io", "me", "tv", "info", "biz", "dev",
               "app", "xyz", "online", "site", "tech", "store", "blog", "cloud"]
COMMON_PREFIXES = ["www", "my", "the", "new", "go", "get", "app", "dev"]
COMMON_SUFFIXES = ["app", "online", "site", "web", "backup", "shop", "login", "help"]
MISSING_DOT_REPLACEMENTS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                            "6": "g", "7": "t", "8": "b", "9": "g"}

def generate_typosquatting_variants(domain: str) -> list:
    variants = []
    seen = set()
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return []
    sld, tld = parts
    base = sld

    for repl in COMMON_TLDS:
        if repl != tld:
            v = f"{sld}.{repl}"
            if v != domain and v not in seen:
                seen.add(v)
                variants.append((v, "TLD swap", f"Common TLD .{repl}"))

    for i in range(len(domain)):
        v = domain[:i] + domain[i+1:]
        if v and v not in seen:
            seen.add(v)
            variants.append((v, "Character omission", f"Missing char at pos {i}"))
        if i < len(domain) - 1:
            chars = list(domain)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            v = "".join(chars)
            if v != domain and v not in seen:
                seen.add(v)
                variants.append((v, "Adjacent swap", f"Swapped pos {i} and {i+1}"))

        for ch in "sx":
            v = domain[:i] + ch + domain[i:]
            if v not in seen:
                seen.add(v)
                variants.append((v, "Character insertion", f"Inserted '{ch}' at pos {i}"))

    for char, repl in MISSING_DOT_REPLACEMENTS.items():
        if char in domain:
            v = domain.replace(char, repl)
            if v != domain and v not in seen:
                seen.add(v)
                variants.append((v, "Homoglyph", f"'{char}'->'{repl}'"))

    for dot_pos in range(1, len(domain)):
        v = domain[:dot_pos] + "." + domain[dot_pos:]
        if v not in seen:
            seen.add(v)
            variants.append((v, "Missing dot", f"Dot after pos {dot_pos}"))

    for prefix in COMMON_PREFIXES:
        v = f"{prefix}{domain}"
        if v not in seen:
            seen.add(v)
            variants.append((v, "Prefix addition", f"Added '{prefix}'"))

    for suffix in COMMON_SUFFIXES:
        v = f"{domain}{suffix}"
        if v not in seen:
            seen.add(v)
            variants.append((v, "Suffix addition", f"Added '{suffix}'"))

    for i in range(1, len(base)):
        v = f"{base[:i]}.{base[i:]}.{tld}"
        if v not in seen and 2 < len(v) < 50:
            seen.add(v)
            variants.append((v, "Dot insertion in SLD", f"Dot at pos {i} in SLD"))

    return variants[:200]

def similarity_ratio(a: str, b: str) -> float:
    longer = max(a, b, key=len)
    shorter = min(a, b, key=len)
    if not longer:
        return 0.0
    edits = abs(len(a) - len(b))
    for c1, c2 in zip(a, b):
        if c1 != c2:
            edits += 1
    return 1.0 - (edits / len(longer))

def classify_typosquat_risk(variant: str, original: str, dns_resolved: bool, http_alive: bool) -> str:
    sim = similarity_ratio(variant, original)
    if dns_resolved and http_alive and sim > 0.85:
        return "Critical"
    if dns_resolved and sim > 0.8:
        return "High"
    if dns_resolved:
        return "Elevated Risk"
    if http_alive:
        return "Standard Target"
    return "Informational"

async def check_dns(variant: str) -> tuple:
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, lambda: socket.getaddrinfo(variant, 80, socket.AF_INET, socket.SOCK_STREAM))
        ips = list(set(a[4][0] for a in answers[:5]))
        return (True, ips)
    except:
        return (False, [])

async def check_http(variant: str, client: httpx.AsyncClient) -> tuple:
    try:
        resp = await client.get(f"http://{variant}", timeout=8.0, follow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        return (True, resp.status_code, resp.headers.get("server", ""), str(resp.headers.get("location", "")))
    except:
        return (False, 0, "", "")

async def check_via_dnstwister_api(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(f"https://dnstwister.report/api/v1/domain/{domain}", timeout=15.0,
                                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            fuzzy = data.get("fuzzy_domains", data.get("similar_domains", []))
            if isinstance(fuzzy, list):
                for entry in fuzzy[:15]:
                    if isinstance(entry, str):
                        findings.append(IntelligenceFinding(
                            entity=entry, type="Typosquat Variant (API)", source="DNSTwister",
                            confidence="Medium", color="orange", threat_level="Elevated Risk",
                            status="Potential Typosquat", resolution="Discovered via dnstwister API",
                            tags=["typosquat", "dns-twist"]
                        ))
                    elif isinstance(entry, dict):
                        name = entry.get("domain", entry.get("name", ""))
                        if name:
                            findings.append(IntelligenceFinding(
                                entity=name, type="Typosquat Variant (API)", source="DNSTwister",
                                confidence="Medium", color="orange", threat_level="Elevated Risk",
                                status="Potential Typosquat", resolution="Discovered via dnstwister API",
                                tags=["typosquat", "dns-twist"]
                            ))
    except:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    api_findings = await check_via_dnstwister_api(domain, client)
    findings.extend(api_findings)

    variants = generate_typosquatting_variants(domain)
    if not variants:
        return findings

    tasks = []
    for v, ctype, cdetail in variants:
        tasks.append((v, ctype, cdetail, check_dns(v)))
    tasks = [(v, ct, cd, dns_task) for v, ct, cd, dns_task in tasks]

    resolved_count = 0
    http_alive_count = 0
    critical_count = 0
    high_count = 0

    for v, ctype, cdetail in variants[:100]:
        dns_resolved, ips = await check_dns(v)
        http_alive, http_status, http_server, http_location = (False, 0, "", "")
        if dns_resolved:
            resolved_count += 1
            http_alive, http_status, http_server, http_location = await check_http(v, client)
            if http_alive:
                http_alive_count += 1

        risk = classify_typosquat_risk(v, domain, dns_resolved, http_alive)
        if risk == "Critical":
            critical_count += 1
        elif risk == "High":
            high_count += 1

        color_map = {
            "Critical": "red", "High": "orange", "Elevated Risk": "orange",
            "Standard Target": "slate", "Informational": "blue"
        }
        threat_map = {
            "Critical": "High Risk", "High": "Elevated Risk", "Elevated Risk": "Elevated Risk",
            "Standard Target": "Standard Target", "Informational": "Informational"
        }

        details_parts = [f"Type: {ctype}", f"{cdetail}"]
        if dns_resolved:
            details_parts.append(f"DNS resolved: {', '.join(ips[:3])}")
        if http_alive:
            details_parts.append(f"HTTP {http_status}")
            if http_server:
                details_parts.append(f"Server: {http_server}")
            if http_location:
                details_parts.append(f"Redirect: {http_location}")

        findings.append(IntelligenceFinding(
            entity=v,
            type=f"Typosquat: {ctype}",
            source="DNSTwister",
            confidence="High" if dns_resolved else "Medium",
            color=color_map.get(risk, "slate"),
            threat_level=threat_map.get(risk, "Informational"),
            status=risk,
            resolution="; ".join(details_parts),
            tags=["typosquat", "dns-twist", f"risk-{risk.lower().replace(' ', '-')}"]
        ))

    if variants:
        findings.append(IntelligenceFinding(
            entity=f"Typosquat scan summary: {len(variants)} variants, {resolved_count} DNS-resolved, {http_alive_count} HTTP-alive",
            type="DNSTwister Summary",
            source="DNSTwister",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{critical_count} critical, {high_count} high risk",
            tags=["typosquat", "summary"]
        ))

    phishing_terms = ["login", "secure", "account", "verify", "update", "confirm",
                      "bank", "paypal", "amazon", "google", "microsoft", "apple",
                      "support", "help", "service", "signin", "auth", "password",
                      "recover", "reset", "billing", "payment"]
    for variant, _, _ in variants[:100]:
        lower_v = variant.split(".")[0].lower() if "." in variant else variant.lower()
        matched_terms = [t for t in phishing_terms if t in lower_v]
        if matched_terms:
            findings.append(IntelligenceFinding(
                entity=f"{variant} contains phishing indicators: {', '.join(matched_terms)}",
                type="Phishing Keyword Match",
                source="DNSTwister",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Phishing Pattern",
                tags=["phishing", "typosquat"]
            ))

    return findings
