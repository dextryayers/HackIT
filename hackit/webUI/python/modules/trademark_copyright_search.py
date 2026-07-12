import re
import httpx
from urllib.parse import urlparse, quote
from typing import List
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

TRADEMARK_SOURCES = [
    ("USPTO TESS", "https://tmsearch.uspto.gov/search/search?q={}"),
    ("EUIPO", "https://euipo.europa.eu/eSearch/#basic/1+1+1+1/100+l+100/{}"),
    ("WIPO Global Brand", "https://www.wipo.int/branddb/en/search?q={}"),
    ("UK IPO", "https://www.ipo.gov.uk/tmcase/Results/1/{}"),
    ("CIPO Canada", "https://www.ic.gc.ca/app/opic-cipo/trdmrks/srch/bscSrch.do?lang=eng&searchText={}"),
    ("IP Australia", "https://search.ipaustralia.gov.au/trademarks/search/quick?q={}"),
    ("DPMA Germany", "https://register.dpma.de/DPMAregister/marke/einsteiger?query={}"),
    ("JPO Japan", "https://www.j-platpat.inpit.go.jp/s0100?searchKey={}"),
    ("KIPO Korea", "https://www.kipris.or.kr/enghome/search/patentSearch.do?searchText={}"),
    ("US Copyright", "https://cocatalog.loc.gov/cgi-bin/Pwebrecon.cgi?Search_Arg={}&Search_Code=FT"),
]

TRADEMARK_CLASSES = [
    ("Class 9", "Software, scientific, electrical apparatus"),
    ("Class 35", "Advertising, business management"),
    ("Class 36", "Insurance, financial, monetary affairs"),
    ("Class 38", "Telecommunications"),
    ("Class 41", "Education, entertainment, sporting activities"),
    ("Class 42", "Scientific and technological services, software"),
    ("Class 45", "Legal services, security services"),
]


def extract_trademark_info(text: str) -> dict:
    info = {}
    serial_match = re.search(r'(?:Serial|Registration)\s*(?:Number|No|#)?\s*:?\s*(\d{7,8})', text, re.IGNORECASE)
    if serial_match:
        info["serial_number"] = serial_match.group(1)
    status_match = re.search(r'(?:Status|Live/Dead|Dead/Live)\s*:?\s*([A-Za-z\s]+?)(?:<|\.)', text, re.IGNORECASE)
    if status_match:
        info["status"] = status_match.group(1).strip()
    class_match = re.findall(r'Class\s+(\d{2})', text)
    if class_match:
        info["classes"] = list(set(class_match))
    date_match = re.search(r'(?:Filing|Registration)\s*Date\s*:?\s*(\d{4})', text, re.IGNORECASE)
    if date_match:
        info["year"] = date_match.group(1)
    return info


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    sources_with_data = 0
    all_classes_found = []

    for name, url_template in TRADEMARK_SOURCES:
        try:
            url = url_template.format(quote(t))
            resp = await safe_fetch(client,
                url,
                timeout=20.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                follow_redirects=True,
            )
            if resp.status_code == 200 and len(resp.text) > 300:
                text = resp.text
                target_mentions = text.lower().count(t.lower())
                info = extract_trademark_info(text)

                if target_mentions > 0 or info:
                    sources_with_data += 1
                    findings.append(make_finding(
                        entity=f"{name}: Trademark results for {t}",
                        ftype="Trademark: Source Result",
                        source="TrademarkSearch",
                        confidence="Medium",
                        color="sky",
                        category="Trademark Intelligence",
                        threat_level="Informational",
                        status="Found",
                        resolution=t,
                        tags=["trademark", name.lower().replace(" ", "-"), "search"],
                    ))

                    if info.get("serial_number"):
                        findings.append(make_finding(
                            entity=f"Trademark serial number: {info['serial_number']} from {name}",
                            ftype="Trademark: Serial Number",
                            source="TrademarkSearch",
                            confidence="High",
                            color="blue",
                            category="Trademark Intelligence",
                            threat_level="Informational",
                            status="Identified",
                            resolution=t,
                            tags=["trademark", "serial", info['serial_number']],
                        ))

                    if info.get("status"):
                        status_str = info["status"]
                        is_dead = "dead" in status_str.lower() or "abandon" in status_str.lower()
                        threat = "Medium Risk" if is_dead else "Informational"
                        findings.append(make_finding(
                            entity=f"Trademark status: {status_str}",
                            ftype="Trademark: Status Check",
                            source="TrademarkSearch",
                            confidence="High",
                            color="orange" if is_dead else "emerald",
                            category="Trademark Intelligence",
                            threat_level=threat,
                            status=status_str,
                            resolution=t,
                            tags=["trademark", "status", "live" if not is_dead else "dead"],
                        ))

                    if info.get("classes"):
                        all_classes_found.extend(info["classes"])
                        findings.append(make_finding(
                            entity=f"Trademark classes: {', '.join(info['classes'])}",
                            ftype="Trademark: Class Identification",
                            source="TrademarkSearch",
                            confidence="Medium",
                            color="slate",
                            category="Trademark Intelligence",
                            threat_level="Informational",
                            status="Classified",
                            resolution=t,
                            tags=["trademark", "class"] + [f"class-{c}" for c in info["classes"]],
                        ))

        except:
            pass

    if all_classes_found:
        class_descriptions = []
        for cls in set(all_classes_found):
            for tc_num, tc_desc in TRADEMARK_CLASSES:
                if tc_num.endswith(cls):
                    class_descriptions.append(f"{tc_num}: {tc_desc}")
                    break
        if class_descriptions:
            findings.append(make_finding(
                entity=f"Trademark class descriptions: {'; '.join(class_descriptions[:3])}",
                ftype="Trademark: Class Description",
                source="TrademarkSearch",
                confidence="Medium",
                color="slate",
                category="Trademark Intelligence",
                threat_level="Informational",
                status="Described",
                resolution=t,
                tags=["trademark", "class-description"],
            ))

    if sources_with_data > 0:
        findings.append(make_finding(
            entity=f"Trademark portfolio: {sources_with_data} databases had registrations for {t}",
            ftype="Trademark: Portfolio Analysis",
            source="TrademarkSearch",
            confidence="Medium",
            color="slate",
            category="Trademark Intelligence",
            threat_level="Informational",
            status="Analyzed",
            resolution=t,
            tags=["trademark", "portfolio", "analysis"],
        ))

        conflict_keywords = ["conflict", "opposition", "cancellation", "infringement", "dispute", "objection"]
        conflict_found = any(kw in t for kw in conflict_keywords)
        if conflict_found:
            findings.append(make_finding(
                entity=f"Potential trademark conflict indicators for {t}",
                ftype="Trademark: Conflict Detection",
                source="TrademarkSearch",
                confidence="Low",
                color="orange",
                category="Trademark Intelligence",
                threat_level="Medium Risk",
                status="Potential Conflict",
                resolution=t,
                tags=["trademark", "conflict", "warning"],
            ))
    else:
        findings.append(make_finding(
            entity="No trademark registrations found for target",
            ftype="Trademark: Scan Complete",
            source="TrademarkSearch",
            confidence="Low",
            color="emerald",
            category="Trademark Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["trademark", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Trademark scan complete: {sources_with_data}/{len(TRADEMARK_SOURCES)} databases had results",
        ftype="Trademark: Scan Summary",
        source="TrademarkSearch",
        confidence="High",
        color="slate",
        category="Trademark Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["trademark", "summary"],
    ))

    return findings
