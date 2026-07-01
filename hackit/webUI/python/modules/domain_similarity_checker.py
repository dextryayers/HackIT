import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from models import IntelligenceFinding

COMMON_TLDS = [
    "com", "net", "org", "co", "io", "me", "tv", "info", "biz", "dev",
    "app", "xyz", "online", "site", "tech", "store", "blog", "cloud",
    "uk", "de", "fr", "eu", "ru", "jp", "cn", "br", "au", "in",
    "ca", "nl", "it", "es", "se", "no", "pl", "at", "ch", "be",
    "dk", "fi", "ie", "nz", "sg", "hk", "za", "mx", "ar", "cl",
    "cc", "email", "pro", "name", "mobi", "asia", "shop", "club",
    "vip", "live", "news", "media", "video", "wiki", "guru", "guide",
    "link", "world", "today", "space", "press", "social", "network",
    "agency", "group", "team", "solutions", "digital", "finance",
    "health", "law", "legal", "london", "nyc", "paris", "tokyo",
    "gdn", "uno", "win", "bid", "trade", "webcam", "science",
    "date", "men", "loan", "download", "review", "racing", "work",
    "click", "party", "top", "icu", "cf", "ga", "ml", "tk",
]

HOMOGRAPH_MAP = {
    'a': ['а', 'ɑ', 'α', 'à', 'á', 'â', 'ã', 'ä', 'å'],
    'b': ['Ь', 'ъ', 'в', 'β'],
    'c': ['с', 'ς', 'ϲ', '¢'],
    'd': ['ԁ', 'ɗ'],
    'e': ['е', 'ё', 'ē', 'ė', 'ę', 'ě', 'è', 'é', 'ê', 'ë', '€'],
    'f': ['ｆ', 'ƒ', 'ſ'],
    'g': ['ɡ', 'ĝ', 'ğ', 'ġ', 'ģ'],
    'h': ['һ', 'ħ', 'н'],
    'i': ['і', 'ı', 'ì', 'í', 'î', 'ï', 'ī', 'į', '¡'],
    'j': ['ј', 'ʝ', 'ϳ'],
    'k': ['κ', 'ќ', 'ķ', 'ĸ'],
    'l': ['ӏ', 'ւ', 'ι', 'Ι', 'ⅼ', 'ℓ'],
    'm': ['м', 'ṃ'],
    'n': ['п', 'η', 'ή', 'ň', 'ń', 'ņ', 'ñ'],
    'o': ['о', 'ο', 'σ', 'ô', 'ö', 'ò', 'ó', 'õ', 'ø', 'ō', 'œ', 'º'],
    'p': ['р', 'ρ', '₽'],
    'q': ['ԛ', 'զ'],
    'r': ['г', 'я', 'ř', 'ŕ', 'ŗ'],
    's': ['ѕ', 'ş', 'ś', 'š', 'ş', 'ŝ', 'ș'],
    't': ['т', 'ţ', 'ŧ'],
    'u': ['υ', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ů', 'ű', 'ų'],
    'v': ['ν', 'ѵ'],
    'w': ['ш', 'щ', 'ŵ'],
    'x': ['х', '×', 'χ'],
    'y': ['у', 'γ', 'ý', 'ÿ', 'ŷ'],
    'z': ['ź', 'ż', 'ž'],
    '0': ['о', 'Ο', 'ο'],
    '1': ['l', 'І', 'Ӏ'],
    '2': ['Շ', 'Ƨ'],
    '3': ['З', 'Յ'],
    '4': ['Մ'],
    '5': ['Ք'],
    '6': ['Ь'],
    '7': ['Ꭾ'],
    '8': ['Ȣ'],
    '9': ['Ց'],
}

PREFIXES = ["www", "my", "the", "new", "go", "get", "app", "dev", "best", "top",
            "free", "pro", "us", "uk", "de", "shop", "buy", "try", "find", "use",
            "run", "big", "web", "e", "i", "m", "k", "mc", "mac"]

SUFFIXES = ["app", "online", "site", "web", "backup", "shop", "login", "help",
            "support", "admin", "secure", "account", "update", "verify", "mail",
            "blog", "wiki", "forum", "chat", "live", "tv", "video", "media",
            "news", "info", "guide", "store", "market", "hub", "cloud", "host",
            "server", "system", "service", "center", "group", "team", "works",
            "lab", "labs", "corp", "inc", "ltd", "llc", "org", "io", "co",
            "saas", "api", "cdn", "dev", "test", "beta", "demo"]

async def check_dns(host: str):
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, 80, family=socket.AF_INET))
        ips = list(set(a[4][0] for a in ais[:5]))
        return True, ips
    except:
        return False, []

async def check_http(host: str, client: httpx.AsyncClient):
    try:
        resp = await client.get(f"http://{host}", timeout=8.0, follow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        title = ""
        try:
            m = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:3000], re.DOTALL | re.IGNORECASE)
            if m: title = m.group(1).strip()[:100]
        except: pass
        return True, resp.status_code, resp.headers.get("server", ""), str(resp.headers.get("location", "")), title
    except:
        return False, 0, "", "", ""

def generate_variants(domain: str):
    variants = []
    seen = set()
    parts = domain.rsplit(".", 1)
    if len(parts) != 2: return variants
    sld, tld = parts

    for repl in COMMON_TLDS:
        if repl != tld:
            v = f"{sld}.{repl}"
            if v not in seen: seen.add(v); variants.append((v, "TLD Swap", repl))

    for i in range(len(domain)):
        v = domain[:i] + domain[i+1:]
        if v and v not in seen: seen.add(v); variants.append((v, "Char Omission", str(i)))
        if i < len(domain) - 1:
            chars = list(domain)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            v = "".join(chars)
            if v not in seen: seen.add(v); variants.append((v, "Adjacent Swap", f"{i}/{i+1}"))
        for ch in "sx":
            v = domain[:i] + ch + domain[i:]
            if v not in seen: seen.add(v); variants.append((v, "Char Insertion", f"+{ch}@{i}"))

    for p in PREFIXES:
        v = f"{p}{domain}"
        if v not in seen: seen.add(v); variants.append((v, "Prefix", p))

    for s in SUFFIXES:
        v = f"{domain}{s}"
        if v not in seen: seen.add(v); variants.append((v, "Suffix", s))

    for i in range(1, len(sld)):
        v = f"{sld[:i]}.{sld[i:]}.{tld}"
        if v not in seen and len(v) < 50: seen.add(v); variants.append((v, "Dot in SLD", str(i)))

    for i, ch in enumerate(sld):
        if ch in HOMOGRAPH_MAP:
            for homoglyph in HOMOGRAPH_MAP[ch][:2]:
                v = f"{sld[:i]}{homoglyph}{sld[i+1:]}.{tld}"
                if v not in seen: seen.add(v); variants.append((v, "Homograph", f"'{ch}'->'{homoglyph}'"))

    for i in range(len(sld)):
        for repl in 'aeiou':
            if repl != sld[i]:
                v = f"{sld[:i]}{repl}{sld[i+1:]}.{tld}"
                if v not in seen: seen.add(v); variants.append((v, "Vowel Swap", f"{sld[i]}->{repl}"))

    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'b': '8', 'g': '9'}
    for orig, repl in leet_map.items():
        if orig in sld:
            v = f"{sld.replace(orig, repl)}.{tld}"
            if v not in seen: seen.add(v); variants.append((v, "Leet Speak", f"{orig}->{repl}"))

    return variants[:200]

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    original_ips = []
    try:
        ok, original_ips = await check_dns(domain)
    except: pass

    variants = generate_variants(domain)
    if not variants:
        findings.append(IntelligenceFinding(
            entity="Could not generate domain variants",
            type="Similarity Checker Error",
            source="Domain Similarity Checker",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Error",
            tags=["similarity", "error"]
        ))
        return findings

    resolved = 0
    http_alive = 0
    same_ip = 0
    parked = 0
    suspicious = 0

    for v, vtype, vdetail in variants[:80]:
        dns_ok, ips = await check_dns(v)
        http_ok, status, server, location, title = (False, 0, "", "", "")
        if dns_ok:
            resolved += 1
            http_ok, status, server, location, title = await check_http(v, client)
            if http_ok: http_alive += 1

        risk_color = "green"
        risk_threat = "Informational"
        risk_status = "Unresolved"
        if dns_ok:
            if original_ips and ips and ips[0] in original_ips:
                risk_color = "red"
                risk_threat = "Elevated Risk"
                risk_status = "Same IP"
                same_ip += 1
            else:
                risk_color = "orange"
                risk_threat = "Standard Target"
                risk_status = "Resolved - Different IP"

            if http_ok and status == 200:
                if title and any(kw in title.lower() for kw in ["parked", "sale", "buy", "domain", "coming soon", "for sale"]):
                    parked += 1
                    risk_threat = "Elevated Risk"
                    risk_status = "Parked"

        findings.append(IntelligenceFinding(
            entity=v,
            type=f"Domain Variant: {vtype}",
            source="Domain Similarity Checker",
            confidence="High" if dns_ok else "Medium",
            color=risk_color,
            threat_level=risk_threat,
            status=risk_status,
            resolution=f"{vtype}: {vdetail}" + (f" | IP: {ips[0]}" if ips else ""),
            raw_data=f"DNS: {'Resolved' if dns_ok else 'Unresolved'} | HTTP: {status if http_ok else 'N/A'} | Server: {server[:50]} | Title: {title[:50]}",
            tags=["similarity", "variant", vtype.lower().replace(" ", "-"), risk_status.lower().replace(" ", "-")]
        ))

    summary_parts = [f"Total variants: {len(variants)}", f"DNS resolved: {resolved}", f"HTTP alive: {http_alive}",
                     f"Same IP: {same_ip}", f"Parked: {parked}"]
    findings.append(IntelligenceFinding(
        entity=" | ".join(summary_parts),
        type="Domain Similarity Summary",
        source="Domain Similarity Checker",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status="Complete",
        tags=["similarity", "summary"]
    ))

    if same_ip > 0:
        findings.append(IntelligenceFinding(
            entity=f"{same_ip} variants resolve to same IP as original - possible mirror/phishing",
            type="Same-IP Variant Alert",
            source="Domain Similarity Checker",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Suspicious",
            tags=["similarity", "same-ip", "phishing"]
        ))

    if parked > 0:
        findings.append(IntelligenceFinding(
            entity=f"{parked} variants are parked domains",
            type="Parked Domain Detection",
            source="Domain Similarity Checker",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="Parked",
            tags=["similarity", "parked"]
        ))

    if http_alive > 0:
        findings.append(IntelligenceFinding(
            entity=f"{http_alive} live HTTP variants actively serving content",
            type="Active Variant Alert",
            source="Domain Similarity Checker",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            status="Active",
            tags=["similarity", "active"]
        ))

    return findings
