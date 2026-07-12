import re, asyncio
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, make_finding

PATENT_SOURCES = [
    ("Google Patents", "https://patents.google.com/?q={}&language=ENGLISH"),
    ("USPTO", "https://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PALL&p=1&u=/netahtml/PTO/srchnum.htm&r=0&f=S&l=50&TERM1={}&CO1=AND&TERM2=&CO2=AND&d=PTXT"),
    ("EPO", "https://worldwide.espacenet.com/patent/search?q={}"),
    ("WIPO PATENTSCOPE", "https://patentscope.wipo.int/search/en/search.jsf?query={}"),
    ("FPO", "https://www.freepatentsonline.com/result.html?p=1&srch={}&query_txt={}"),
    ("USPTO AppFT", "https://appft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PG01&p=1&u=/netahtml/PTO/srchnum.html&r=0&f=S&l=50&TERM1={}"),
    ("Lens.org", "https://www.lens.org/lens/search/patent/list?q={}"),
    ("Espacenet Worldwide", "https://worldwide.espacenet.com/patent/search?q={}"),
]

TECHNOLOGY_AREAS = [
    "artificial intelligence", "machine learning", "blockchain", "cybersecurity",
    "cloud computing", "iot", "semiconductor", "biotechnology", "pharmaceutical",
    "telecommunications", "renewable energy", "automotive", "aerospace",
    "medical devices", "software", "hardware", "networking", "data processing",
]

def extract_patent_ids(text: str) -> list:
    patterns = [
        r'(?:US|EP|WO|CN|JP|KR|DE|FR|GB|CH|CA|AU)\d{4,12}[A-Z]?\d?',
        r'(?:US|EP|WO)\d{7,12}',
        r'Patent\s*(?:No|Number|#|:)?\s*:?\s*(\d{7,12})',
        r'Publication\s*(?:No|Number|#|:)?\s*:?\s*(\d{7,12})',
    ]
    ids = set()
    for pattern in patterns:
        for match in re.findall(pattern, text, re.IGNORECASE):
            ids.add(match)
    return list(ids)

async def crawl(target: str, client) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    sem = asyncio.Semaphore(8)

    async def search_source(name, url_template):
        async with sem:
            try:
                url = url_template.format(quote(t))
                resp = await safe_fetch(client, url, timeout=15.0)
                if resp and resp.status_code == 200 and len(resp.text) > 500:
                    patent_ids = extract_patent_ids(resp.text)
                    target_count = resp.text.lower().count(t.lower())
                    return {"name": name, "patent_ids": patent_ids, "mentions": target_count}
            except Exception:
                pass
            return None

    tasks = [search_source(name, url_template) for name, url_template in PATENT_SOURCES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_patent_ids = []
    sources_with_data = 0

    for r in results:
        if isinstance(r, Exception) or not r:
            continue
        sources_with_data += 1
        name = r["name"]
        patent_ids = r["patent_ids"]

        findings.append(make_finding(
            entity=f"{name}: {len(patent_ids)} patent IDs found referencing {t}",
            ftype="Patent: Source Result",
            source="PatentIntelligence",
            confidence="Medium",
            color="sky",
            category="Patent Intelligence",
            threat_level="Informational",
            status="Found" if patent_ids else "Scanned",
            resolution=t,
            tags=["patent", name.lower().replace(" ", "-"), "search"],
        ))

        if patent_ids:
            all_patent_ids.extend(patent_ids)
            for pid in patent_ids[:3]:
                findings.append(make_finding(
                    entity=f"Patent ID: {pid} from {name}",
                    ftype="Patent: ID Discovery",
                    source="PatentIntelligence",
                    confidence="Medium",
                    color="blue",
                    category="Patent Intelligence",
                    threat_level="Informational",
                    status="Discovered",
                    resolution=t,
                    tags=["patent", "id", pid[:8]],
                ))

    for area in TECHNOLOGY_AREAS:
        if area in t or any(word in t for word in area.split()):
            findings.append(make_finding(
                entity=f"Potential technology area: {area.title()}",
                ftype="Patent: Technology Area",
                source="PatentIntelligence",
                confidence="Medium",
                color="slate",
                category="Patent Intelligence",
                threat_level="Informational",
                status="Identified",
                resolution=t,
                tags=["patent", "technology", area.lower().replace(" ", "-")],
            ))

    if all_patent_ids:
        unique_ids = list(set(all_patent_ids))
        findings.append(make_finding(
            entity=f"Total {len(unique_ids)} unique patent IDs found for {t}",
            ftype="Patent: Portfolio Estimate",
            source="PatentIntelligence",
            confidence="Medium",
            color="slate",
            category="Patent Intelligence",
            threat_level="Informational",
            status="Estimated",
            resolution=t,
            raw_data=f"Patent IDs: {', '.join(unique_ids[:10])}",
            tags=["patent", "portfolio", "estimate"],
        ))

        patent_offices = {"US": "USPTO", "EP": "EPO", "WO": "WIPO", "CN": "CNIPA", "JP": "JPO", "KR": "KIPO", "DE": "DPMA"}
        office_distribution = {}
        for pid in unique_ids:
            for prefix, office in patent_offices.items():
                if pid.startswith(prefix):
                    office_distribution[office] = office_distribution.get(office, 0) + 1
                    break
        if office_distribution:
            dist_str = ", ".join(f"{o}({c})" for o, c in sorted(office_distribution.items(), key=lambda x: x[1], reverse=True))
            findings.append(make_finding(
                entity=f"Patent office distribution: {dist_str}",
                ftype="Patent: Office Distribution",
                source="PatentIntelligence",
                confidence="Medium",
                color="slate",
                category="Patent Intelligence",
                threat_level="Informational",
                status="Analyzed",
                resolution=t,
                tags=["patent", "offices", "distribution"],
            ))
    else:
        findings.append(make_finding(
            entity="No patents found for target",
            ftype="Patent: Scan Complete",
            source="PatentIntelligence",
            confidence="Low",
            color="emerald",
            category="Patent Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["patent", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Patent scan complete: {len(all_patent_ids)} patent IDs from {sources_with_data}/{len(PATENT_SOURCES)} sources",
        ftype="Patent: Scan Summary",
        source="PatentIntelligence",
        confidence="High",
        color="slate",
        category="Patent Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["patent", "summary"],
    ))

    return findings
