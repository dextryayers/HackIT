import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

FINANCIAL_SOURCES = [
    ("SEC EDGAR", "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={}&owner=exclude&count=10"),
    ("Yahoo Finance", "https://finance.yahoo.com/quote/{}"),
    ("Crunchbase", "https://www.crunchbase.com/search?query={}"),
    ("PitchBook", "https://pitchbook.com/search?q={}"),
    ("Bloomberg", "https://www.bloomberg.com/search?query={}"),
    ("Reuters Finance", "https://www.reuters.com/search/news?blob={}"),
    ("MarketWatch", "https://www.marketwatch.com/search?q={}"),
    ("Morningstar", "https://www.morningstar.com/search?q={}"),
    ("Fidelity", "https://www.fidelity.com/search?q={}"),
    ("Google Finance", "https://www.google.com/finance/search?q={}"),
    ("CNN Money", "https://money.cnn.com/search/?q={}"),
    ("Forbes", "https://www.forbes.com/search/?q={}"),
    ("Inc.com", "https://www.inc.com/search/{}"),
    ("BusinessWire", "https://www.businesswire.com/portal/site/home/search/?searchType=all&searchTerm={}"),
    ("PR Newswire", "https://www.prnewswire.com/search/?keyword={}"),
]

REVENUE_PATTERN = re.compile(r'(?:revenue|sales|turnover|income)\s*(?:of|:)?\s*\$?\s?([0-9,.]+)\s*(?:billion|million|thousand|B|M|K)?', re.IGNORECASE)
EMPLOYEE_PATTERN = re.compile(r'(?:employees|employee count|headcount|workforce|staff)\s*(?:of|:)?\s*([0-9,.]+)', re.IGNORECASE)
FUNDING_PATTERN = re.compile(r'(?:raised|funding|series\s+[A-Z]|seed|venture)\s*(?:of|:)?\s*\$?\s?([0-9,.]+)\s*(?:billion|million|B|M)?', re.IGNORECASE)
STOCK_PATTERN = re.compile(r'\$[A-Z]{1,5}\b')
YEAR_PATTERN = re.compile(r'\b(19[0-9]{2}|20[0-9]{2})\b')


async def search_financial(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await client.get(url, timeout=15.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 300:
            text = resp.text
            revenues = REVENUE_PATTERN.findall(text)
            employees = EMPLOYEE_PATTERN.findall(text)
            fundings = FUNDING_PATTERN.findall(text)
            stocks = STOCK_PATTERN.findall(text)
            mentions = text.lower().count(target.lower())
            return {
                "name": name,
                "mentions": mentions,
                "revenues": revenues[:3],
                "employees": employees[:3],
                "fundings": fundings[:3],
                "stocks": stocks[:5],
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
    sources_with_data = 0

    for name, url_template in FINANCIAL_SOURCES:
        result = await search_financial(name, url_template, t, client)
        if result:
            all_results.append(result)
            if result["mentions"] > 0:
                sources_with_data += 1

    all_revenues = []
    all_employees = []
    all_fundings = []
    all_stocks = []

    for result in all_results:
        if result["revenues"]:
            for rev in result["revenues"]:
                clean_rev = rev.strip().rstrip(".")
                if clean_rev not in all_revenues:
                    all_revenues.append(clean_rev)
        if result["employees"]:
            for emp in result["employees"]:
                clean_emp = emp.strip().rstrip(".")
                if clean_emp not in all_employees:
                    all_employees.append(clean_emp)
        if result["fundings"]:
            for fund in result["fundings"]:
                clean_fund = fund.strip().rstrip(".")
                if clean_fund not in all_fundings:
                    all_fundings.append(clean_fund)
        all_stocks.extend(result.get("stocks", []))

        if result["mentions"] > 0:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: {result['mentions']} financial mentions of {t}",
                type="Financial: Source Result",
                source="CompanyFinancial",
                confidence="Medium",
                color="sky",
                category="Financial Intelligence",
                threat_level="Informational",
                status="Found",
                resolution=t,
                tags=["financial", result['name'].lower().replace(" ", "-"), "mention"],
            ))

        if result["revenues"]:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: Revenue data found - {', '.join(result['revenues'][:2])}",
                type="Financial: Revenue Data",
                source="CompanyFinancial",
                confidence="Medium",
                color="blue",
                category="Financial Intelligence",
                threat_level="Informational",
                status="Revenue Found",
                resolution=t,
                tags=["financial", "revenue", "data"],
            ))

        if result["fundings"]:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: Funding data found - {', '.join(result['fundings'][:2])}",
                type="Financial: Funding Data",
                source="CompanyFinancial",
                confidence="Medium",
                color="blue",
                category="Financial Intelligence",
                threat_level="Informational",
                status="Funding Found",
                resolution=t,
                tags=["financial", "funding", "investment"],
            ))

        if result["employees"]:
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: Employee count data - {', '.join(result['employees'][:2])}",
                type="Financial: Employee Data",
                source="CompanyFinancial",
                confidence="Medium",
                color="slate",
                category="Financial Intelligence",
                threat_level="Informational",
                status="Employee Data Found",
                resolution=t,
                tags=["financial", "employees", "headcount"],
            ))

    if all_revenues:
        findings.append(IntelligenceFinding(
            entity=f"Revenue estimates: {', '.join(all_revenues[:3])}",
            type="Financial: Revenue Summary",
            source="CompanyFinancial",
            confidence="Medium",
            color="slate",
            category="Financial Intelligence",
            threat_level="Informational",
            status="Summarized",
            resolution=t,
            tags=["financial", "revenue", "summary"],
        ))

    if all_fundings:
        findings.append(IntelligenceFinding(
            entity=f"Funding rounds: {', '.join(all_fundings[:3])}",
            type="Financial: Funding Summary",
            source="CompanyFinancial",
            confidence="Medium",
            color="slate",
            category="Financial Intelligence",
            threat_level="Informational",
            status="Summarized",
            resolution=t,
            tags=["financial", "funding", "summary"],
        ))

    if all_employees:
        findings.append(IntelligenceFinding(
            entity=f"Employee estimates: {', '.join(all_employees[:3])}",
            type="Financial: Employee Summary",
            source="CompanyFinancial",
            confidence="Medium",
            color="slate",
            category="Financial Intelligence",
            threat_level="Informational",
            status="Summarized",
            resolution=t,
            tags=["financial", "employees", "summary"],
        ))

    if all_stocks:
        unique_stocks = list(set(all_stocks))
        findings.append(IntelligenceFinding(
            entity=f"Stock tickers found: {', '.join(unique_stocks[:5])}",
            type="Financial: Stock Tickers",
            source="CompanyFinancial",
            confidence="Medium",
            color="slate",
            category="Financial Intelligence",
            threat_level="Informational",
            status="Identified",
            resolution=t,
            tags=["financial", "stock", "ticker"],
        ))

    if not all_results:
        findings.append(IntelligenceFinding(
            entity="No financial data found for target",
            type="Financial: Scan Complete",
            source="CompanyFinancial",
            confidence="Low",
            color="emerald",
            category="Financial Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["financial", "clean"],
        ))

    findings.append(IntelligenceFinding(
        entity=f"Financial scan complete: {sources_with_data} sources had data",
        type="Financial: Scan Summary",
        source="CompanyFinancial",
        confidence="High",
        color="slate",
        category="Financial Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["financial", "summary"],
    ))

    return findings
