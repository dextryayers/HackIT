import httpx
import re
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

CREDENTIAL_SOURCES = [
    ("LeakCheck", "https://leakcheck.io/api/public?check={}"),
    ("DeHashed", "https://dehashed.com/search?query={}"),
    ("IntelX", "https://intelx.io/search?q={}"),
    ("Snusbase", "https://snusbase.com/search?q={}"),
    ("LeakBase", "https://leakbase.io/search?q={}"),
    ("Scylla", "https://scylla.so/search?q={}"),
    ("ScatteredSecrets", "https://scatteredsecrets.com/search?q={}"),
    ("WeLeakInfo", "https://weleakinfo.com/search?q={}"),
    ("BreachDirectory", "https://breachdirectory.org/search?q={}"),
    ("COMB", "https://combolist.org/search?q={}"),
    ("AntiPublic", "https://antipublic.com/search?q={}"),
    ("PwnDB", "https://pwndb2am4tzkvold.onion/search?q={}"),
    ("LeakedSource", "https://leakedsource.ru/search?q={}"),
    ("RussianMarket", "https://russianmarket.to/search?q={}"),
    ("ExploitIN", "https://exploit.in/search?q={}"),
    ("Cracked", "https://cracked.to/search?q={}"),
    ("Nulled", "https://nulled.to/search?q={}"),
    ("DarkMarket", "https://darkmarket.su/search?q={}"),
    ("TorZon", "https://torzon.su/search?q={}"),
    ("WhiteMarket", "https://whitemarket.su/search?q={}"),
]

ACCESS_TYPES = {
    "vpn": ["vpn", "openvpn", "wireguard", "pptp", "l2tp"],
    "rdp": ["rdp", "remote desktop", "terminal server"],
    "ssh": ["ssh", "shell", "root access", "bash"],
    "email": ["email", "mail", "outlook", "exchange", "webmail"],
    "cpanel": ["cpanel", "whm", "plesk", "hosting control"],
    "database": ["mysql", "postgresql", "mongodb", "mssql", "oracle", "database"],
    "social": ["facebook", "twitter", "instagram", "linkedin", "tiktok"],
    "financial": ["bank", "paypal", "credit card", "western union", "money"],
}

PRICE_INDICATORS = [
    (r'\$\s*(\d+(?:\.\d{2})?)', "USD"),
    (r'€\s*(\d+(?:\.\d{2})?)', "EUR"),
    (r'₽\s*(\d+)', "RUB"),
    (r'(\d+)\s*BTC', "BTC"),
    (r'(\d+)\s*XMR', "XMR"),
]

PII_CATEGORIES = {
    "ssn": ["ssn", "social security", "tax id"],
    "passport": ["passport", "travel document"],
    "driver_license": ["driver license", "driving license", "dl"],
    "credit_card": ["credit card", "cc", "debit card", "amex", "visa", "mastercard"],
    "bank_account": ["bank account", "routing", "iban", "swift"],
    "fullz": ["fullz", "full info", "complete profile"],
    "dox": ["dox", "dossier", "personal file"],
}


async def search_source(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await safe_fetch(client, url, timeout=20.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 200:
            text = resp.text.lower()
            mentions = text.count(target.lower())
            prices = set()
            for pattern, currency in PRICE_INDICATORS:
                matches = re.findall(pattern, text)
                for m in matches[:2]:
                    prices.add(f"{m} {currency}")
            access_types_found = set()
            for atype, keywords in ACCESS_TYPES.items():
                if any(kw in text for kw in keywords):
                    access_types_found.add(atype)
            pii_types = set()
            for pcat, pkws in PII_CATEGORIES.items():
                if any(kw in text for kw in pkws):
                    pii_types.add(pcat)
            email_pairs = re.findall(r'([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:;|]\s*(\S+)', text)
            return {
                "name": name,
                "mentions": mentions,
                "prices": list(prices),
                "access_types": list(access_types_found),
                "pii_types": list(pii_types),
                "email_pairs": len(email_pairs),
            }
    except:
        pass
    return None


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    sources_with_data = 0

    for name, url_template in CREDENTIAL_SOURCES:
        result = await search_source(name, url_template, t, client)
        if result:
            all_results.append(result)
            if result["mentions"] > 0 or result["email_pairs"] > 0:
                sources_with_data += 1

    for result in all_results:
        if result["mentions"] > 0:
            findings.append(make_finding(
                entity=f"{result['name']}: {result['mentions']} mentions of {t}",
                ftype="CredMarket: Source Mention",
                source="CredMarketMonitor",
                confidence="Medium",
                color="red",
                category="Credential Market Intelligence",
                threat_level="Critical",
                status="Mentioned",
                resolution=t,
                tags=["credential", "market", result['name'].lower().replace(" ", "-")],
            ))

        if result["email_pairs"] > 0:
            findings.append(make_finding(
                entity=f"{result['name']}: {result['email_pairs']} credential pairs found",
                ftype="CredMarket: Credential Pairs",
                source="CredMarketMonitor",
                confidence="High",
                color="red",
                category="Credential Market Intelligence",
                threat_level="Critical",
                status="Credentials Found",
                resolution=t,
                tags=["credential", "pairs", "leaked"],
            ))

        if result["prices"]:
            for price in result["prices"][:3]:
                findings.append(make_finding(
                    entity=f"{result['name']}: Data priced at {price}",
                    ftype="CredMarket: Pricing Info",
                    source="CredMarketMonitor",
                    confidence="Medium",
                    color="orange",
                    category="Credential Market Intelligence",
                    threat_level="High Risk",
                    status="Price Identified",
                    resolution=t,
                    tags=["credential", "price", "market"],
                ))

        if result["access_types"]:
            at_str = ", ".join(result["access_types"])
            findings.append(make_finding(
                entity=f"{result['name']}: Access types for sale - {at_str}",
                ftype="CredMarket: Access Sales",
                source="CredMarketMonitor",
                confidence="Medium",
                color="red",
                category="Credential Market Intelligence",
                threat_level="Critical",
                status="Access Sold",
                resolution=t,
                tags=["credential", "access", "sale"] + result["access_types"],
            ))

        if result["pii_types"]:
            pii_str = ", ".join(result["pii_types"])
            findings.append(make_finding(
                entity=f"{result['name']}: PII data types - {pii_str}",
                ftype="CredMarket: PII Sales",
                source="CredMarketMonitor",
                confidence="Medium",
                color="red",
                category="Credential Market Intelligence",
                threat_level="Critical",
                status="PII Found",
                resolution=t,
                tags=["credential", "pii", "sale"] + result["pii_types"],
            ))

    all_access_types = set()
    all_pii_types = set()
    total_pairs = 0
    for r in all_results:
        all_access_types.update(r.get("access_types", []))
        all_pii_types.update(r.get("pii_types", []))
        total_pairs += r.get("email_pairs", 0)

    if all_access_types:
        findings.append(make_finding(
            entity=f"Total access types in market: {', '.join(sorted(all_access_types))}",
            type="CredMarket: Access Inventory",
            source="CredMarketMonitor",
            confidence="Medium",
            color="red",
            category="Credential Market Intelligence",
            threat_level="Critical",
            status="Mapped",
            resolution=t,
            tags=["credential", "access", "inventory"] + list(all_access_types),
        ))

    if all_pii_types:
        findings.append(make_finding(
            entity=f"PII data categories in market: {', '.join(sorted(all_pii_types))}",
            type="CredMarket: PII Inventory",
            source="CredMarketMonitor",
            confidence="Medium",
            color="red",
            category="Credential Market Intelligence",
            threat_level="Critical",
            status="Identified",
            resolution=t,
            tags=["credential", "pii", "inventory"] + list(all_pii_types),
        ))

    if total_pairs > 0:
        findings.append(make_finding(
            entity=f"Total {total_pairs} credential pairs found across darknet markets",
            ftype="CredMarket: Total Exposure",
            source="CredMarketMonitor",
            confidence="High",
            color="red",
            category="Credential Market Intelligence",
            threat_level="Critical",
            status="Exposed",
            resolution=t,
            tags=["credential", "exposure", "total"],
        ))

    if not all_results:
        findings.append(make_finding(
            entity="No credential market mentions found for target",
            ftype="CredMarket: Scan Complete",
            source="CredMarketMonitor",
            confidence="Low",
            color="emerald",
            category="Credential Market Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["credential", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Credential market scan complete: {sources_with_data} sources had data",
        ftype="CredMarket: Scan Summary",
        source="CredMarketMonitor",
        confidence="High",
        color="slate",
        category="Credential Market Intelligence",
        threat_level="Informational" if not sources_with_data else "Critical",
        status="Complete",
        resolution=t,
        tags=["credential", "summary"],
    ))

    return findings
