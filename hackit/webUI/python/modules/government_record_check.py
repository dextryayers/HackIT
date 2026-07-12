import re
from urllib.parse import urlparse, quote
from typing import List
from module_common import safe_fetch, make_finding

GOVERNMENT_SOURCES = [
    ("SEC EDGAR", "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={}&owner=exclude&count=10"),
    ("OpenCorporates", "https://api.opencorporates.com/v0.4/companies/search?q={}&per_page=10"),
    ("USPTO Trademarks", "https://tmsearch.uspto.gov/search/search?q={}"),
    ("FCC Registration", "https://www.fcc.gov/search?q={}"),
    ("SAM.gov", "https://sam.gov/search/?q={}"),
    ("Companies House UK", "https://find-and-update.company-information.service.gov.uk/search?q={}"),
    ("ASIC Australia", "https://connectonline.asic.gov.au/RegistrySearch/Search.aspx?searchText={}"),
    ("ACRA Singapore", "https://www.acra.gov.sg/search?q={}"),
    ("CA Corporations", "https://beta.canadasbusinessregistries.ca/search?q={}"),
    ("UK Charity Commission", "https://register-of-charities.charitycommission.gov.uk/charity-search?q={}"),
    ("EU Transparency", "https://ec.europa.eu/transparencyregister/public/consultation/search.do?query={}"),
    ("FDIC Banking", "https://www.fdic.gov/search?q={}"),
    ("US Courts PACER", "https://pacer.uscourts.gov/search?q={}"),
    ("US Copyright", "https://cocatalog.loc.gov/cgi-bin/Pwebrecon.cgi?Search_Arg={}&Search_Code=FT"),
    ("State Registrations", "https://www.sos.state.gov/search?q={}"),
]


async def search_source(name: str, url_template: str, target: str, client) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await safe_fetch(
            client,
            url,
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            follow_redirects=True,
        )
        if resp and resp.status_code == 200 and len(resp.text) > 200:
            text = resp.text
            target_count = text.lower().count(target.lower())
            emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', text)
            addresses = re.findall(r'\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Circle|Cir|Court|Ct)[,\s]+[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5}', text)
            phones = re.findall(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', text)
            return {
                "name": name,
                "url": url,
                "target_mentions": target_count,
                "emails": emails[:5],
                "addresses": addresses[:3],
                "phones": phones[:3],
                "content_length": len(text),
            }
    except:
        pass
    return None


async def crawl(target: str, client) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    sources_with_data = 0

    for name, url_template in GOVERNMENT_SOURCES:
        result = await search_source(name, url_template, t, client)
        if result:
            all_results.append(result)
            sources_with_data += 1

    if all_results:
        findings.append(make_finding(
            f"Government records scan: {sources_with_data}/{len(GOVERNMENT_SOURCES)} databases searched",
            ftype="Government: Coverage Report",
            source="GovRecordCheck",
            confidence="High",
            color="slate",
            category="Government Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["government", "records", "coverage"],
        ))

    for result in all_results:
        mention_count = result["target_mentions"]

        findings.append(make_finding(
            f"{result['name']}: {mention_count} mentions for {t}",
            ftype="Government: Database Result",
            source="GovRecordCheck",
            confidence="Medium",
            color="sky" if mention_count > 0 else "slate",
            category="Government Intelligence",
            threat_level="Informational",
            status="Found" if mention_count > 0 else "No Results",
            resolution=t,
            tags=["government", result['name'].lower().replace(" ", "-"), "database"],
        ))

        if result["emails"]:
            for email in result["emails"][:2]:
                findings.append(make_finding(
                    f"Email in government records: {email}",
                    ftype="Government: Email Discovery",
                    source="GovRecordCheck",
                    confidence="Medium",
                    color="orange",
                    category="Government Intelligence",
                    threat_level="Medium Risk",
                    status="Discovered",
                    resolution=t,
                    tags=["government", "email", "discovery"],
                ))

        if result["addresses"]:
            for addr in result["addresses"][:2]:
                findings.append(make_finding(
                    f"Address in government records: {addr[:100]}",
                    ftype="Government: Address Discovery",
                    source="GovRecordCheck",
                    confidence="Medium",
                    color="orange",
                    category="Government Intelligence",
                    threat_level="Medium Risk",
                    status="Discovered",
                    resolution=t,
                    tags=["government", "address", "discovery"],
                ))

        if result["phones"]:
            for phone in result["phones"][:2]:
                findings.append(make_finding(
                    f"Phone in government records: {phone}",
                    ftype="Government: Phone Discovery",
                    source="GovRecordCheck",
                    confidence="Medium",
                    color="orange",
                    category="Government Intelligence",
                    threat_level="Medium Risk",
                    status="Discovered",
                    resolution=t,
                    tags=["government", "phone", "discovery"],
                ))

    all_emails = []
    all_addresses = []
    for r in all_results:
        all_emails.extend(r.get("emails", []))
        all_addresses.extend(r.get("addresses", []))

    if all_emails:
        findings.append(make_finding(
            f"{len(set(all_emails))} unique emails found across government databases",
            ftype="Government: Email Aggregation",
            source="GovRecordCheck",
            confidence="Medium",
            color="orange",
            category="Government Intelligence",
            threat_level="Medium Risk",
            status="Aggregated",
            resolution=t,
            tags=["government", "email", "aggregation"],
        ))

    if all_addresses:
        findings.append(make_finding(
            f"{len(set(all_addresses))} unique addresses found across government databases",
            ftype="Government: Address Aggregation",
            source="GovRecordCheck",
            confidence="Medium",
            color="orange",
            category="Government Intelligence",
            threat_level="Medium Risk",
            status="Aggregated",
            resolution=t,
            tags=["government", "address", "aggregation"],
        ))

    if not all_results:
        findings.append(make_finding(
            "No government records found for target",
            ftype="Government: Scan Complete",
            source="GovRecordCheck",
            confidence="Low",
            color="emerald",
            category="Government Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["government", "clean"],
        ))

    return findings
