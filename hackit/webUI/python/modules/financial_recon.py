import httpx
import asyncio
import json
import re
from datetime import datetime
from typing import List, Optional
from models import IntelligenceFinding

YAHOO_FINANCE_URL = "https://query1.finance.yahoo.com/v8/finance/chart/{}"
COINGECKO_URL = "https://api.coingecko.com/api/v3/coins/{}"
OPENCORPORATES_URL = "https://api.opencorporates.com/v0.4/companies/search"
SEC_EDGAR_URL = "https://www.sec.gov/cgi-bin/browse-edgar"
CRUNCHBASE_URL = "https://api.crunchbase.com/api/v4/entities/organizations/{}"

async def yahoo_finance(symbol: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        url = YAHOO_FINANCE_URL.format(symbol)
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def coingecko(symbol: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        url = COINGECKO_URL.format(symbol.lower().replace("$", ""))
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def sec_edgar_search(company: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        params = {"action": "getcompany", "CIK": company, "output": "atom"}
        resp = await client.get(SEC_EDGAR_URL, params=params, timeout=10.0)
        if resp.status_code == 200:
            return resp.text[:2000]
    except:
        pass
    return None

async def search_opencorporates(company: str, client: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await client.get(OPENCORPORATES_URL,
            params={"q": company, "format": "json"}, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", {}).get("companies", [])
            if results:
                return results[0]
    except:
        pass
    return None

BANKING_KEYWORDS = {
    "swift": r"\b[a-zA-Z]{4}[a-zA-Z]{2}[a-zA-Z0-9]{2}([a-zA-Z0-9]{3})?\b",
    "iban": r"\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}\b",
    "routing": r"\b\d{9}\b",
    "creditcard": r"\b(?:\d{4}[ -]?){3}\d{4}\b",
}

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip()

    if any(c in t for c in ["$", "crypto", "coin", "token", "btc", "eth", "usdt"]):
        symbol = t.replace("$", "").lower().strip()
        cg_data = await coingecko(symbol, client)
        if cg_data and "error" not in cg_data:
            name = cg_data.get("name", symbol)
            price = cg_data.get("market_data", {}).get("current_price", {}).get("usd", "N/A")
            findings.append(IntelligenceFinding(
                entity=f"Crypto: {name} @ ${price} USD",
                type="Financial Recon: Cryptocurrency",
                source="CoinGecko",
                confidence="High",
                color="slate",
                status="Priced",
                resolution=t,
                tags=["financial", "crypto", symbol]
            ))

        yf_data = await yahoo_finance(symbol, client)
        if yf_data and "chart" in yf_data:
            result = yf_data.get("chart", {}).get("result", [{}])[0]
            meta = result.get("meta", {})
            findings.append(IntelligenceFinding(
                entity=f"Yahoo Finance: {meta.get('symbol', symbol)} - {meta.get('regularMarketPrice', 'N/A')}",
                type="Financial Recon: Stock Quote",
                source="Yahoo Finance",
                confidence="High",
                color="slate",
                status="Quoted",
                resolution=t,
                tags=["financial", "yahoo-finance", symbol]
            ))

    company_match = re.sub(r'[^a-zA-Z0-9\s]', '', t)
    if company_match:
        corp_data = await search_opencorporates(company_match, client)
        if corp_data:
            findings.append(IntelligenceFinding(
                entity=f"Corporate: {corp_data.get('name', company_match)}",
                type="Financial Recon: Corporate Registry",
                source="OpenCorporates",
                confidence="Medium",
                color="slate",
                status="Found",
                resolution=t,
                tags=["financial", "corporate"]
            ))

        sec_data = await sec_edgar_search(company_match, client)
        if sec_data and len(sec_data) > 200:
            findings.append(IntelligenceFinding(
                entity=f"SEC EDGAR filing data available for {company_match}",
                type="Financial Recon: SEC Filing",
                source="SEC EDGAR",
                confidence="High",
                color="slate",
                status="Retrieved",
                resolution=t,
                tags=["financial", "sec", "edgar"]
            ))

    for bank_type, pattern in BANKING_KEYWORDS.items():
        matches = re.findall(pattern, t)
        if matches:
            for m in matches[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"Potential {bank_type}: {m}",
                    type=f"Financial Recon: {bank_type.title()}",
                    source="FinancialRecon",
                    confidence="Low",
                    color="orange",
                    threat_level="Sensitive Data",
                    status=f"Matched {bank_type}",
                    resolution=t,
                    tags=["financial", bank_type, "pii"]
                ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No financial information found",
            type="Financial Recon: Complete",
            source="FinancialRecon",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["financial", "empty"]
        ))

    return findings
