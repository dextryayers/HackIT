import httpx
import asyncio
import re
from collections import defaultdict
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
BUILTWITH_API = "https://api.builtwith.com/v21/api.json"

TECH_CATEGORIES = {
    "cms": "CMS",
    "framework": "Web Framework",
    "cdn": "CDN",
    "analytics": "Analytics",
    "tracking": "Tracking",
    "ad": "Advertising",
    "payment": "Payment Processor",
    "hosting": "Hosting",
    "email": "Email Service",
    "ssl": "SSL/TLS",
    "widget": "Widget",
    "cdn_provider": "CDN",
    "cms_framework": "CMS",
    "javascript_framework": "JavaScript Framework",
    "css_framework": "CSS Framework",
    "web_server": "Web Server",
    "os": "Operating System",
    "database": "Database",
    "programming_language": "Programming Language",
    "reverse_proxy": "Reverse Proxy",
    "security": "Security Service",
    "marketing_automation": "Marketing Automation",
    "tag_manager": "Tag Manager",
    "live_chat": "Live Chat",
    "video": "Video Platform",
    "font": "Font Service",
    "map": "Mapping Service",
}

EOL_TECHNOLOGIES = {
    "php 5": "End of Life since 2018",
    "php 7.0": "End of Life since 2018",
    "php 7.1": "End of Life since 2019",
    "php 7.2": "End of Life since 2020",
    "php 7.3": "End of Life since 2021",
    "php 7.4": "End of Life since 2022",
    "php 8.0": "Security Support only",
    "jquery 1": "End of Life",
    "jquery 2": "End of Life",
    "angularjs": "End of Life (1.x)",
    "internet explorer": "End of Life",
    "flash": "End of Life",
    "coldfusion": "End of Life support",
    "windows server 2003": "End of Life",
    "windows server 2008": "End of Life",
    "windows server 2012": "Extended Support only",
    "ubuntu 16": "End of Life",
    "ubuntu 18": "End of Life",
    "centos 6": "End of Life",
    "centos 7": "End of Life",
    "nginx 1.1": "Old version",
}

TECH_RISK_MAP = {
    "web_server": 2,
    "cdn": 1,
    "cms": 5,
    "framework": 3,
    "analytics": 2,
    "tracking": 3,
    "ad": 2,
    "payment": 7,
    "hosting": 3,
    "email": 4,
    "widget": 2,
    "javascript_framework": 2,
    "css_framework": 1,
    "database": 6,
    "os": 4,
    "programming_language": 3,
    "security": 1,
    "reverse_proxy": 2,
}

async def query_builtwith_api(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            BUILTWITH_API,
            params={"KEY": "", "LOOKUP": domain},
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def scrape_builtwith(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://builtwith.com/{domain}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            tech_entries = re.findall(r'data-tech="([^"]+)"', text)
            tech_names = re.findall(r'<a[^>]*href="/[^"]*"[^>]*>([^<]+)</a>', text)
            combined = set()
            for t in tech_entries + tech_names:
                t = t.strip()
                if len(t) > 2 and t not in ("Home", "About", "Contact"):
                    combined.add(t)
            return list(combined)[:40]
    except:
        pass
    return []

def detect_version(name: str) -> tuple:
    m = re.search(r'(v?\d+\.\d+(?:\.\d+)?)', name)
    if m:
        return m.group(1), name.replace(m.group(1), "").strip()
    return None, name

def check_eol(name: str, version: str = None) -> tuple:
    lower = name.lower()
    if version:
        check = f"{lower} {version}"
        for key, status in EOL_TECHNOLOGIES.items():
            if key in check:
                return True, status
    for key, status in EOL_TECHNOLOGIES.items():
        if key in lower:
            return True, status
    return False, None

def tech_risk_score(category: str) -> int:
    for cat_key, risk in TECH_RISK_MAP.items():
        if cat_key in category.lower():
            return risk
    return 3

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    api_data = await query_builtwith_api(t, client)
    api_results = api_data.get("Results", [])

    tech_groups = defaultdict(list)
    seen_techs = set()

    if api_results:
        for result in api_results[:3]:
            paths = result.get("Result", {}).get("Paths", [])
            for tech in paths[:40] if isinstance(paths, list) else []:
                if not isinstance(tech, dict):
                    continue
                tech_name = (tech.get("name") or tech.get("description", "")).strip()
                if not tech_name or tech_name in seen_techs:
                    continue
                seen_techs.add(tech_name)

                tech_cat_raw = tech.get("category", "").lower().replace(" ", "_")
                sub_cat = tech.get("subCategory", "")
                first_seen = tech.get("firstseen", "")
                last_seen = tech.get("lastseen", "")
                recent = tech.get("recent", False)
                is_paid = tech.get("paid", False)
                link_rel = tech.get("linkrelationship", "")

                display_cat = TECH_CATEGORIES.get(tech_cat_raw, tech.get("category", "Technology"))
                version, clean_name = detect_version(tech_name)
                is_eol, eol_note = check_eol(tech_name)
                risk = tech_risk_score(tech_cat_raw)

                confidence = "High" if recent else ("Medium" if last_seen else "Low")
                color = "red" if is_eol else ("orange" if risk >= 5 else ("slate" if risk >= 3 else "emerald"))
                threat = "High Risk" if is_eol else ("Elevated Risk" if risk >= 6 else "Informational")

                tags_list = ["technology", display_cat.lower().replace(" ", "-")]
                if is_eol:
                    tags_list.append("end-of-life")
                if is_paid:
                    tags_list.append("paid")
                tags_list.append(f"risk-{risk}")

                entity_parts = [clean_name or tech_name]
                if version:
                    entity_parts.append(f"v{version}")
                if first_seen:
                    entity_parts.append(f"(since {first_seen[:7]})")
                entity = " ".join(entity_parts)

                findings.append(IntelligenceFinding(
                    entity=entity,
                    type=f"BuiltWith: {display_cat}",
                    source="BuiltWith",
                    confidence=confidence,
                    color=color,
                    threat_level=threat,
                    status="Confirmed" if recent else "Historical",
                    raw_data=f"Category: {tech.get('category', '')} | Version: {version or 'N/A'} | First: {first_seen or 'N/A'} | Last: {last_seen or 'N/A'}",
                    tags=tags_list,
                ))

                tech_groups[display_cat].append(tech_name)

                if is_eol and eol_note:
                    findings.append(IntelligenceFinding(
                        entity=f"{clean_name or tech_name}: {eol_note}",
                        type="BuiltWith: End-of-Life Warning",
                        source="BuiltWith",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Confirmed",
                        tags=["technology", "end-of-life", "security"],
                    ))

    scraped_techs = await scrape_builtwith(t, client)
    for st in scraped_techs:
        if st not in seen_techs:
            seen_techs.add(st)
            version, clean_name = detect_version(st)
            entity = f"{clean_name or st} v{version}" if version else st
            findings.append(IntelligenceFinding(
                entity=entity,
                type="BuiltWith: Technology (Scraped)",
                source="BuiltWith",
                confidence="Medium",
                color="slate",
                status="Confirmed",
                tags=["technology", "scraped"],
            ))

    for cat, items in sorted(tech_groups.items(), key=lambda x: -len(x[1])):
        findings.append(IntelligenceFinding(
            entity=f"{cat}: {len(items)} technology(ies)",
            type="BuiltWith: Category Summary",
            source="BuiltWith",
            confidence="Medium",
            color="slate",
            status="Analyzed",
            tags=["technology", "summary", cat.lower().replace(" ", "-")],
        ))

    total_risk = sum(tech_risk_score(cat.lower().replace(" ", "_")) for cat in tech_groups)
    findings.append(IntelligenceFinding(
        entity=f"Technology risk score: {total_risk} across {len(seen_techs)} technology(ies)",
        type="BuiltWith: Risk Summary",
        source="BuiltWith",
        confidence="Medium",
        color="red" if total_risk > 50 else ("orange" if total_risk > 25 else "emerald"),
        threat_level="Elevated Risk" if total_risk > 25 else "Informational",
        status="Analyzed",
        tags=["technology", "risk-assessment", "summary"],
    ))

    if "CMS" in tech_groups:
        cms_list = ", ".join(tech_groups["CMS"][:5])
        findings.append(IntelligenceFinding(
            entity=f"CMS: {cms_list}",
            type="BuiltWith: CMS Detection",
            source="BuiltWith",
            confidence="High",
            color="blue",
            status="Confirmed",
            tags=["technology", "cms"],
        ))

    dependency_chains = []
    if "CDN" in tech_groups and "Web Server" in tech_groups:
        dependency_chains.append("CDN + Web Server")
    if "CMS" in tech_groups and "Database" in tech_groups:
        dependency_chains.append("CMS + Database")
    if "Analytics" in tech_groups and "Tag Manager" in tech_groups:
        dependency_chains.append("Analytics + Tag Manager")
    if dependency_chains:
        findings.append(IntelligenceFinding(
            entity=" | ".join(dependency_chains),
            type="BuiltWith: Dependency Chain",
            source="BuiltWith",
            confidence="Low",
            color="slate",
            status="Inferred",
            tags=["technology", "dependency"],
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No technology data for {t}",
            type="BuiltWith: No Results",
            source="BuiltWith",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["error"],
        ))

    return findings
