import httpx
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

CLEARNET_MIRRORS = [
    ("Ransomware.live", "https://ransomware.live/search?q={}"),
    ("dnm.watch", "https://dnm.watch/search?q={}"),
    ("DarkEye", "https://darkeye.io/search?q={}"),
    ("DarkFeed", "https://darkfeed.io/search?q={}"),
    ("RansomDB", "https://ransomdb.xyz/search?q={}"),
    ("LeakBase", "https://leakbase.io/search?q={}"),
    ("BreachForums", "https://breachforums.is/search?q={}"),
    ("Cracked", "https://cracked.to/search?q={}"),
    ("Nulled", "https://nulled.to/search?q={}"),
    ("XSS", "https://xss.is/search?q={}"),
    ("ExploitIN", "https://exploit.in/search?q={}"),
    ("RaidForums Archive", "https://raidforums.com/search?q={}"),
    ("DarkMarket", "https://darkmarket.su/search?q={}"),
    ("Russian Market", "https://russianmarket.to/search?q={}"),
    ("TorZon", "https://torzon.su/search?q={}"),
    ("Dread", "https://dreadforum.org/search?q={}"),
    ("The Hub", "https://thehub.su/search?q={}"),
    ("Ransomware News", "https://ransomwarenews.com/search?q={}"),
    ("DataBreachToday", "https://databreachtoday.com/search?q={}"),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/search/?q={}"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/search/?q={}"),
    ("The Record", "https://therecord.media/search?q={}"),
    ("CyberNews", "https://cybernews.com/search/?q={}"),
    ("HackRead", "https://www.hackread.com/search/{}"),
]

MARKETPLACE_KEYWORDS = {
    "stolen_data": ["stolen", "leaked", "dump", "database", "breach", "combo", "collection"],
    "access_sales": ["rdp", "ssh", "vpn", "shell", "access", "cpanel", "admin"],
    "exploit_sales": ["exploit", "0day", "zero-day", "vulnerability", "rce", "sql injection"],
    "ransomware": ["ransomware", "ransom", "encrypted", "leaked data", "ransom note"],
    "financial": ["credit card", "cc", "dumps", "bank login", "paypal", "wire transfer"],
    "credentials": ["password", "email:password", "login", "account", "credential"],
    "pii": ["ssn", "dox", "personal info", "identity", "fullz", "id card"],
    "drugs": ["drugs", "pharma", "pills", "weed", "cocaine", "mdma"],
    "services": "hacking service",
}

async def search_mirror(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await safe_fetch(client, 
            url,
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            follow_redirects=True,
        )
        if resp.status_code == 200 and len(resp.text) > 200:
            text = resp.text
            mentions = text.lower().count(target.lower())
            marketplace_hits = {}
            for category, keywords in MARKETPLACE_KEYWORDS.items():
                if isinstance(keywords, str):
                    keywords = [keywords]
                for kw in keywords:
                    if kw in text.lower():
                        marketplace_hits[category] = marketplace_hits.get(category, 0) + 1
            return {
                "name": name,
                "url": url,
                "mentions": mentions,
                "marketplace_hits": marketplace_hits,
                "content_length": len(text),
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
    sources_with_hits = 0

    for name, url_template in CLEARNET_MIRRORS:
        result = await search_mirror(name, url_template, t, client)
        if result:
            all_results.append(result)
            if result["mentions"] > 0 or result["marketplace_hits"]:
                sources_with_hits += 1

    if all_results:
        findings.append(make_finding(
            entity=f"Darknet scan: {sources_with_hits}/{len(CLEARNET_MIRRORS)} sources had mentions of {t}",
            type="Darknet: Coverage Report",
            source="DarknetMarketplace",
            confidence="High",
            color="slate",
            category="Darknet Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["darknet", "coverage", "marketplace"],
        ))

    most_critical_category = None
    for result in all_results:
        name = result["name"]
        mentions = result["mentions"]
        hits = result["marketplace_hits"]

        if mentions > 0:
            findings.append(make_finding(
                entity=f"{name}: {mentions} mentions of {t} found",
                ftype="Darknet: Source Mention",
                source="DarknetMarketplace",
                confidence="Medium",
                color="orange",
                category="Darknet Intelligence",
                threat_level="High Risk",
                status="Mentioned",
                resolution=t,
                tags=["darknet", name.lower().replace(" ", "-"), "mention"],
            ))

        if hits:
            for category, count in sorted(hits.items(), key=lambda x: x[1], reverse=True):
                threat_map = {
                    "stolen_data": "Critical", "access_sales": "Critical", "exploit_sales": "Critical",
                    "ransomware": "Critical", "financial": "Critical", "credentials": "Critical",
                    "pii": "High Risk", "services": "High Risk", "drugs": "High Risk",
                }
                threat = threat_map.get(category, "Medium Risk")
                color_map = {"Critical": "red", "High Risk": "orange", "Medium Risk": "yellow"}
                if most_critical_category is None or list(hits.keys()).index(category) < list(hits.keys()).index(most_critical_category):
                    most_critical_category = category
                findings.append(make_finding(
                    entity=f"{name}: {category.replace('_', ' ').title()} activity detected ({count} indicators)",
                    type=f"Darknet: {category.replace('_', ' ').title()}",
                    source="DarknetMarketplace",
                    confidence="Medium",
                    color=color_map.get(threat, "orange"),
                    category="Darknet Intelligence",
                    threat_level=threat,
                    status="Detected",
                    resolution=t,
                    tags=["darknet", category, name.lower().replace(" ", "-")],
                ))

    if most_critical_category:
        findings.append(make_finding(
            entity=f"Most significant darknet category: {most_critical_category.replace('_', ' ').title()}",
            type="Darknet: Risk Summary",
            source="DarknetMarketplace",
            confidence="Medium",
            color="red",
            category="Darknet Intelligence",
            threat_level="Critical",
            status="Alert",
            resolution=t,
            tags=["darknet", "risk", most_critical_category],
        ))

    if not all_results:
        findings.append(make_finding(
            entity="No darknet mentions found for target",
            ftype="Darknet: Scan Complete",
            source="DarknetMarketplace",
            confidence="Low",
            color="emerald",
            category="Darknet Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["darknet", "clean"],
        ))
    else:
        findings.append(make_finding(
            entity=f"Darknet scan complete: {sources_with_hits} sources had data on {t}",
            ftype="Darknet: Scan Summary",
            source="DarknetMarketplace",
            confidence="High",
            color="slate",
            category="Darknet Intelligence",
            threat_level="Informational" if not sources_with_hits else "High Risk",
            status="Complete",
            resolution=t,
            tags=["darknet", "summary"],
        ))

    return findings
