import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

PATENT_SOURCES = [
    ("Google Patents", "https://patents.google.com/?q={}&language=ENGLISH"),
    ("USPTO", "https://patft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PALL&p=1&u=/netahtml/PTO/srchnum.htm&r=0&f=S&l=50&TERM1={}&CO1=AND&TERM2=&CO2=AND&d=PTXT"),
    ("EPO", "https://worldwide.espacenet.com/patent/search?q={}"),
    ("WIPO PATENTSCOPE", "https://patentscope.wipo.int/search/en/search.jsf?query={}"),
    ("FPO", "https://www.freepatentsonline.com/result.html?p=1&srch={}&query_txt={}"),
    ("USPTO AppFT", "https://appft.uspto.gov/netacgi/nph-Parser?Sect1=PTO1&Sect2=HITOFF&d=PG01&p=1&u=/netahtml/PTO/srchnum.html&r=0&f=S&l=50&TERM1={}"),
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


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_patent_ids = []
    sources_with_data = 0

    for name, url_template in PATENT_SOURCES:
        try:
            url = url_template.format(quote(t))
            resp = await client.get(
                url,
                timeout=20.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                follow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.text) > 500:
                patent_ids = extract_patent_ids(resp.text)
                target_count = resp.text.lower().count(t.lower())
                sources_with_data += 1

                findings.append(IntelligenceFinding(
                    entity=f"{name}: {len(patent_ids)} patent IDs found referencing {t}",
                    type="Patent: Source Result",
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
                        findings.append(IntelligenceFinding(
                            entity=f"Patent ID: {pid} from {name}",
                            type="Patent: ID Discovery",
                            source="PatentIntelligence",
                            confidence="Medium",
                            color="blue",
                            category="Patent Intelligence",
                            threat_level="Informational",
                            status="Discovered",
                            resolution=t,
                            tags=["patent", "id", pid[:8]],
                        ))
        except:
            pass

    for area in TECHNOLOGY_AREAS:
        if area in t or any(word in t for word in area.split()):
            findings.append(IntelligenceFinding(
                entity=f"Potential technology area: {area.title()}",
                type="Patent: Technology Area",
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
        findings.append(IntelligenceFinding(
            entity=f"Total {len(unique_ids)} unique patent IDs found for {t}",
            type="Patent: Portfolio Estimate",
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
            findings.append(IntelligenceFinding(
                entity=f"Patent office distribution: {dist_str}",
                type="Patent: Office Distribution",
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
        findings.append(IntelligenceFinding(
            entity="No patents found for target",
            type="Patent: Scan Complete",
            source="PatentIntelligence",
            confidence="Low",
            color="emerald",
            category="Patent Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["patent", "clean"],
        ))

    findings.append(IntelligenceFinding(
        entity=f"Patent scan complete: {len(all_patent_ids)} patent IDs from {sources_with_data} sources",
        type="Patent: Scan Summary",
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
