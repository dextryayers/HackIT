import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

COMMON_TLDS = [
    "com", "net", "org", "co", "io", "me", "tv", "info", "biz", "dev",
    "app", "xyz", "online", "site", "tech", "store", "blog", "cloud",
    "uk", "de", "fr", "eu", "ru", "jp", "cn", "br", "au", "in",
    "ca", "nl", "it", "es", "se", "no", "pl", "at", "ch", "be",
    "dk", "fi", "ie", "nz", "sg", "hk", "za", "mx", "ar", "cl",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.mx", "com.ar",
    "cc", "email", "pro", "name", "mobi", "asia", "tel", "travel",
    "shop", "club", "vip", "live", "news", "media", "video", "wiki",
    "guru", "guide", "link", "world", "today", "space", "press",
    "social", "network", "agency", "group", "team", "consulting",
    "services", "solutions", "management", "systems", "digital",
    "finance", "money", "cash", "credit", "loan", "invest",
    "health", "doctor", "hospital", "clinic", "pharmacy",
    "law", "legal", "attorney", "lawyer", "claim", "justice",
    "london", "nyc", "paris", "tokyo", "berlin", "moscow", "dubai",
    "gdn", "uno", "win", "bid", "trade", "webcam", "science",
    "date", "men", "loan", "download", "review", "racing", "accountant",
    "christmas", "rest", "faith", "country", "mom", "cricket", "work",
]

HOMOGRAPH_MAP = {
    'a': ['а', 'ɑ', 'α', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ā'],
    'b': ['Ь', 'ъ', 'в', 'β', 'Ь'],
    'c': ['с', 'ς', 'ϲ', '¢', '©'],
    'd': ['ԁ', 'd', 'ɗ', 'ԁ'],
    'e': ['е', 'ё', 'ē', 'ė', 'ę', 'ě', 'è', 'é', 'ê', 'ë', '€'],
    'f': ['ｆ', 'ƒ', 'ſ'],
    'g': ['ɡ', 'ĝ', 'ğ', 'ġ', 'ģ', 'ɢ'],
    'h': ['һ', 'ħ', 'н', 'п'],
    'i': ['і', 'ı', 'ì', 'í', 'î', 'ï', 'ī', 'į', '¡'],
    'j': ['ј', 'ʝ', 'ϳ', 'ј'],
    'k': ['κ', 'ќ', 'ķ', 'ĸ', 'κ'],
    'l': ['ӏ', 'ւ', 'ι', 'Ι', 'ⅼ', 'ℓ'],
    'm': ['м', 'ṃ', 'м'],
    'n': ['п', 'η', 'ή', 'ň', 'ń', 'ņ', 'ñ', 'η'],
    'o': ['о', 'ο', 'σ', 'ô', 'ö', 'ò', 'ó', 'õ', 'ø', 'ō', 'œ', 'º'],
    'p': ['р', 'ρ', '₽', 'ρ'],
    'q': ['ԛ', 'զ', 'ԛ'],
    'r': ['г', 'я', 'ř', 'ŕ', 'ŗ', 'г'],
    's': ['ѕ', 'ş', 'ś', 'š', 'ş', 'ŝ', 'ș', 'ѕ'],
    't': ['т', 'ţ', 'ŧ', 'ŧ', 'ţ'],
    'u': ['υ', 'ù', 'ú', 'û', 'ü', 'ũ', 'ū', 'ů', 'ű', 'ų'],
    'v': ['ν', 'ѵ', 'ѵ'],
    'w': ['ш', 'щ', 'ŵ'],
    'x': ['х', '×', 'χ', 'х'],
    'y': ['у', 'γ', 'ý', 'ÿ', 'ŷ', 'у'],
    'z': ['z', 'ź', 'ż', 'ž', 'ź'],
    '0': ['о', 'Ο', 'ο', 'Օ'],
    '1': ['l', 'І', 'Ӏ', 'ı'],
    '2': ['Շ', 'Ƨ'],
    '3': ['З', 'Յ'],
    '4': ['Մ', 'Ꮞ'],
    '5': ['Ք'],
    '6': ['Ь'],
    '7': ['Ꭾ'],
    '8': ['Ȣ', 'ȣ'],
    '9': ['Ց'],
}

COMMON_PREFIXES = [
    "www", "my", "the", "new", "go", "get", "app", "dev",
    "best", "top", "free", "pro", "us", "uk", "de", "en",
    "shop", "buy", "try", "find", "use", "run", "big", "old",
    "fast", "safe", "real", "hot", "cool", "win", "fun", "net",
    "web", "e", "i", "m", "k", "x", "mc", "mac",
]

COMMON_SUFFIXES = [
    "app", "online", "site", "web", "backup", "shop", "login", "help",
    "support", "admin", "secure", "account", "update", "verify", "mail",
    "blog", "wiki", "forum", "chat", "live", "tv", "video", "media",
    "news", "info", "guide", "world", "today", "space", "zone",
    "store", "market", "hub", "cloud", "host", "server", "system",
    "service", "center", "group", "team", "works", "lab", "labs",
    "corp", "inc", "ltd", "llc", "org", "net", "io", "co",
    "saas", "api", "cdn", "dev", "test", "stage", "beta", "demo",
]

ADDITIONAL_TLDS = [
    "academy", "accountant", "actor", "africa", "agency", "apartments",
    "archi", "army", "art", "associates", "attorney", "auction",
    "audio", "auto", "band", "bank", "bar", "bargains", "beauty",
    "beer", "best", "bet", "bike", "bingo", "bio", "black",
    "blue", "boo", "book", "boots", "boston", "bot", "boutique",
    "broker", "build", "builders", "business", "cab", "cafe",
    "call", "cam", "camera", "camp", "capital", "car", "cards",
    "care", "careers", "cars", "casa", "case", "cash", "casino",
    "catering", "catholic", "center", "ceo", "channel", "chat",
    "cheap", "church", "city", "claims", "cleaning", "click",
    "clinic", "clothing", "cloud", "club", "coach", "codes",
    "coffee", "college", "com", "community", "company", "computer",
    "condos", "construction", "consulting", "contact", "contractors",
    "cooking", "cool", "coop", "corsica", "country", "coupon",
    "courses", "cpa", "credit", "creditcard", "cricket", "cruises",
    "dad", "dance", "date", "dating", "day", "deals", "degree",
    "delivery", "democrat", "dental", "dentist", "design", "dev",
    "diamonds", "diet", "digital", "direct", "directory", "discount",
    "doctor", "dog", "domains", "download", "earth", "eat", "education",
    "email", "energy", "engineer", "engineering", "enterprises",
    "equipment", "error", "esq", "estate", "events", "exchange",
    "expert", "exposed", "express", "fail", "faith", "family",
    "fans", "farm", "fashion", "film", "finance", "financial",
    "fish", "fishing", "fit", "fitness", "flights", "florist",
    "flowers", "fly", "foo", "food", "football", "forex", "forsale",
    "foundation", "fr", "fund", "furniture", "futbol", "fyi",
    "gallery", "games", "garden", "gift", "gifts", "gives",
    "glass", "global", "gmbh", "gold", "golf", "gq", "graphics",
    "gratis", "green", "gripe", "grocery", "group", "guide",
    "guitars", "guru", "hair", "haus", "health", "healthcare",
    "help", "here", "hiphop", "hiv", "hockey", "holdings",
    "holiday", "homes", "horses", "hospital", "host", "hosting",
    "hotel", "house", "how", "immo", "immobilien", "industries",
    "info", "ing", "ink", "institute", "insure", "international",
    "investments", "io", "irish", "islam", "ist", "jeep", "jewelry",
    "juegos", "kaufen", "kim", "kitchen", "land", "law", "lawyer",
    "lease", "legal", "lgbt", "life", "lighting", "limited",
    "limo", "link", "live", "llc", "loan", "loans", "lol",
    "london", "love", "ltd", "luxury", "maison", "management",
    "map", "market", "marketing", "markets", "mba", "med",
    "media", "memorial", "men", "menu", "miami", "mobi", "moda",
    "money", "monster", "mortgage", "moscow", "movie", "museum",
    "music", "nagoya", "name", "navy", "net", "network", "news",
    "ngo", "ninja", "nyc", "okinawa", "one", "ong", "onl",
    "online", "ooo", "org", "organic", "partners", "parts",
    "party", "pay", "pet", "pets", "photo", "photography",
    "photos", "physio", "pics", "pictures", "pink", "pizza",
    "place", "plumbing", "plus", "poker", "porn", "press",
    "pro", "productions", "prof", "promo", "properties",
    "property", "pub", "pwc", "qa", "radio", "re", "realty",
    "recipes", "red", "rehab", "reise", "reisen", "rent",
    "rentals", "repair", "report", "republican", "rest",
    "restaurant", "review", "reviews", "rich", "rocks",
    "rodeo", "room", "ru", "run", "sale", "salon", "sbs",
    "school", "schule", "science", "scot", "security", "services",
    "sex", "sexy", "shiksha", "shoes", "shop", "shopping",
    "show", "shows", "site", "ski", "skin", "soccer", "social",
    "software", "solar", "solutions", "song", "space", "spa",
    "store", "stream", "studio", "study", "style", "sucks",
    "supplies", "supply", "support", "surf", "surgery", "systems",
    "talk", "tattoo", "tax", "taxi", "team", "tech", "technology",
    "tennis", "theater", "theatre", "tickets", "tips", "tires",
    "today", "tools", "top", "tours", "town", "toys", "trade",
    "trading", "training", "tube", "university", "uno", "vacations",
    "vegas", "ventures", "vet", "viajes", "video", "villas",
    "vin", "vip", "vision", "vlaanderen", "vodka", "vote",
    "voting", "voto", "voyage", "wang", "watch", "webcam",
    "website", "wedding", "wiki", "win", "wine", "work",
    "works", "world", "wtf", "xxx", "xyz", "yachts", "yoga",
    "yokohama", "zone",
]

MISSING_DOT_REPLACEMENTS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                            "6": "g", "7": "t", "8": "b", "9": "g"}

PHISHING_TERMS = [
    "login", "secure", "account", "verify", "update", "confirm",
    "bank", "paypal", "amazon", "google", "microsoft", "apple",
    "support", "help", "service", "signin", "auth", "password",
    "recover", "reset", "billing", "payment", "wallet", "token",
    "2fa", "mfa", "authenticate", "validation", "identity",
    "credential", "unlock", "activate", "reactivate", "restore",
    "security", "alert", "notice", "information", "required",
    "important", "urgent", "suspended", "limited", "restricted",
    "blocked", "disabled", "locked", "fraud", "unusual", "access",
    "confirm", "verification", "review", "documents", "statement",
    "transaction", "receipt", "invoice", "bill", "payment",
    "deposit", "withdraw", "transfer", "refund", "bonus", "prize",
    "winner", "reward", "gift", "coupon", "offer", "promotion",
]


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
                variants.append((v, "Homoglyph (leet)", f"'{char}'->'{repl}'"))

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

    for i, ch in enumerate(base):
        if ch in HOMOGRAPH_MAP:
            for homoglyph in HOMOGRAPH_MAP[ch][:3]:
                v = f"{base[:i]}{homoglyph}{base[i+1:]}.{tld}"
                if v != domain and v not in seen:
                    seen.add(v)
                    variants.append((v, "Homograph attack", f"'{ch}'->'{homoglyph}'"))

    bitsquatting_variants = []
    for i in range(len(base) * 8):
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx < len(base):
            char_ord = ord(base[byte_idx])
            new_ord = char_ord ^ (1 << bit_idx)
            if 32 <= new_ord <= 126:
                new_char = chr(new_ord)
                if new_char.isalnum() or new_char == '-':
                    new_text = list(base)
                    new_text[byte_idx] = new_char
                    v = f"{''.join(new_text)}.{tld}"
                    if v != domain and v not in seen:
                        seen.add(v)
                        bitsquatting_variants.append((v, "Bitsquatting", f"Bit flip at byte {byte_idx}, bit {bit_idx}"))
                        if len(bitsquatting_variants) >= 20:
                            break
        if len(bitsquatting_variants) >= 20:
            break
    variants.extend(bitsquatting_variants)

    added_tlds = ADDITIONAL_TLDS[:100]
    for tld_variant in added_tlds:
        if tld_variant != tld:
            v = f"{sld}.{tld_variant}"
            if v != domain and v not in seen:
                seen.add(v)
                variants.append((v, "TLD swap (extended)", f".{tld_variant}"))

    for i in range(1, len(base)):
        v = f"{base[:i]}{base[i:]}.{tld}"
        if v not in seen:
            seen.add(v)
            variants.append((v, "Double character", f"Doubled char at pos {i}"))

    for i in range(len(base)):
        if base[i] in 'aeiou':
            for repl in 'aeiou':
                if repl != base[i]:
                    v = f"{base[:i]}{repl}{base[i+1:]}.{tld}"
                    if v != domain and v not in seen:
                        seen.add(v)
                        variants.append((v, "Vowel swap", f"'{base[i]}'->'{repl}'"))

    for i in range(len(base)):
        v = f"{base[:i]}{base[i]}{base[i]}{base[i:]}.{tld}"
        if v not in seen:
            seen.add(v)
            variants.append((v, "Repeated character", f"'{base[i]}' repeated at pos {i}"))

    for i in range(1, len(base)):
        v = f"{base[:i]}-{base[i:]}.{tld}"
        if v not in seen:
            seen.add(v)
            variants.append((v, "Hyphen insertion", f"Hyphen at pos {i} in SLD"))

    return variants[:250]


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


def classify_variant_type(variant: str, ip: str, original_ip: str, http_status: int, http_location: str) -> str:
    if not ip:
        return "Unresolved"
    if ip == original_ip:
        if http_location:
            return "Same IP - Redirected"
        return "Same IP"
    if http_status in (301, 302, 307, 308):
        return "Redirected"
    if http_status == 200:
        return "Different IP - Live"
    return "Different IP"


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
        resp = await safe_fetch(client, f"http://{variant}", timeout=8.0, follow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
        server = resp.headers.get("server", "")
        ctype = resp.headers.get("content-type", "")
        title = ""
        try:
            m = re.search(r'<title[^>]*>(.*?)</title>', resp.text[:3000], re.DOTALL | re.IGNORECASE)
            if m:
                title = m.group(1).strip()[:100]
        except:
            pass
        return (True, resp.status_code, server, str(resp.headers.get("location", "")), ctype, title)
    except:
        return (False, 0, "", "", "", "")


async def check_via_dnstwister_api(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://dnstwister.report/api/v1/domain/{domain}", timeout=15.0,
                                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            fuzzy = data.get("fuzzy_domains", data.get("similar_domains", []))
            if isinstance(fuzzy, list):
                for entry in fuzzy[:15]:
                    if isinstance(entry, str):
                        findings.append(make_finding(
                            entity=entry, ftype="Typosquat Variant (API)", source="DNSTwister",
                            confidence="Medium", color="orange", threat_level="Elevated Risk",
                            status="Potential Typosquat", resolution="Discovered via dnstwister API",
                            tags=["typosquat", "dns-twist"]
                        ))
                    elif isinstance(entry, dict):
                        name = entry.get("domain", entry.get("name", ""))
                        if name:
                            findings.append(make_finding(
                                entity=name, ftype="Typosquat Variant (API)", source="DNSTwister",
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

    original_ips = []
    try:
        orig_ok, original_ips = await check_dns(domain)
    except:
        pass

    variants = generate_typosquatting_variants(domain)
    if not variants:
        return findings

    resolved_count = 0
    http_alive_count = 0
    critical_count = 0
    high_count = 0
    same_ip_count = 0
    diff_ip_count = 0
    redirect_count = 0
    parked_count = 0
    phishing_matches = []

    for v, ctype, cdetail in variants[:100]:
        dns_resolved, ips = await check_dns(v)
        http_alive, http_status, http_server, http_location, http_ctype, http_title = (False, 0, "", "", "", "")
        if dns_resolved:
            resolved_count += 1
            http_alive, http_status, http_server, http_location, http_ctype, http_title = await check_http(v, client)
            if http_alive:
                http_alive_count += 1

        variant_class = classify_variant_type(v, ips[0] if ips else "", original_ips[0] if original_ips else "", http_status, http_location)
        if variant_class == "Same IP" or variant_class == "Same IP - Redirected":
            same_ip_count += 1
        elif variant_class == "Different IP - Live":
            diff_ip_count += 1
        elif variant_class == "Redirected":
            redirect_count += 1

        risk = classify_typosquat_risk(v, domain, dns_resolved, http_alive)
        if risk == "Critical":
            critical_count += 1
        elif risk == "High":
            high_count += 1

        if http_status in (200,) and http_title and ("parked" in http_title.lower() or "domain" in http_title.lower() or "sale" in http_title.lower() or "coming soon" in http_title.lower()):
            parked_count += 1

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
            details_parts.append(f"Class: {variant_class}")
        if http_alive:
            details_parts.append(f"HTTP {http_status}")
            if http_server:
                details_parts.append(f"Server: {http_server}")
            if http_location:
                details_parts.append(f"Redirect: {http_location}")
            if http_title:
                details_parts.append(f"Title: {http_title}")

        findings.append(make_finding(
            entity=v,
            ftype=f"Typosquat: {ctype}",
            source="DNSTwister",
            confidence="High" if dns_resolved else "Medium",
            color=color_map.get(risk, "slate"),
            threat_level=threat_map.get(risk, "Informational"),
            status=risk,
            resolution="; ".join(details_parts),
            tags=["typosquat", "dns-twist", f"risk-{risk.lower().replace(' ', '-')}", f"class-{variant_class.lower().replace(' ', '-')}"]
        ))

    homograph_count = sum(1 for _, ct, _ in variants[:100] if ct == "Homograph attack")
    bitsquat_count = sum(1 for _, ct, _ in variants[:100] if ct == "Bitsquatting")

    if homograph_count > 0:
        findings.append(make_finding(
            entity=f"{homograph_count} homograph attack variants generated",
            ftype="Homograph Attack Analysis",
            source="DNSTwister",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Generated",
            raw_data=f"Cyrillic homograph variants: {homograph_count}",
            tags=["homograph", "cyrillic", "attack-vector"]
        ))

    if bitsquat_count > 0:
        findings.append(make_finding(
            entity=f"{bitsquat_count} bitsquatting variants generated",
            ftype="Bitsquatting Analysis",
            source="DNSTwister",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="Generated",
            raw_data=f"Bitsquatting variants: {bitsquat_count}",
            tags=["bitsquatting", "hardware-error"]
        ))

    if variants:
        findings.append(make_finding(
            entity=f"Typosquat scan summary: {len(variants)} variants, {resolved_count} DNS-resolved, {http_alive_count} HTTP-alive",
            type="DNSTwister Summary",
            source="DNSTwister",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{critical_count} critical, {high_count} high risk, {same_ip_count} same-IP, {diff_ip_count} diff-IP, {redirect_count} redirect, {parked_count} parked",
            tags=["typosquat", "summary"]
        ))

    for variant, ctype, cdetail in variants[:100]:
        lower_v = variant.split(".")[0].lower() if "." in variant else variant.lower()
        matched_terms = [t for t in PHISHING_TERMS if t in lower_v]
        if matched_terms:
            phishing_matches.append((variant, matched_terms))
            findings.append(make_finding(
                entity=f"{variant} contains phishing indicators: {', '.join(matched_terms)}",
                type="Phishing Keyword Match",
                source="DNSTwister",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Phishing Pattern",
                tags=["phishing", "typosquat"]
            ))

    if same_ip_count > 0:
        findings.append(make_finding(
            entity=f"{same_ip_count} variants resolve to SAME IP as original - possible mirror/phishing",
            ftype="Same-IP Cluster",
            source="DNSTwister",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Suspicious",
            raw_data=f"Variants sharing original IP: {same_ip_count}",
            tags=["same-ip", "mirror", "phishing"]
        ))

    if parked_count > 0:
        findings.append(make_finding(
            entity=f"{parked_count} variants appear to be PARKED domains (sinkhole)",
            type="Parked Domain Detection",
            source="DNSTwister",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="Parked",
            raw_data=f"Parked variants: {parked_count}",
            tags=["parked", "sinkhole"]
        ))

    if http_alive_count > 0:
        findings.append(make_finding(
            entity=f"{http_alive_count} HTTP-alive typosquat variants are actively serving content",
            ftype="Active Typosquat Alert",
            source="DNSTwister",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Active Threat",
            raw_data=f"Active typosquatting hosts: {http_alive_count}",
            tags=["active-threat", "typosquatting"]
        ))

    return findings
