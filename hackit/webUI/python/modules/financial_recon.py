import httpx
import re
import json
from models import IntelligenceFinding
from urllib.parse import urlparse, quote

FINANCIAL_KEYWORDS = [
    "revenue", "annual revenue", "quarterly revenue", "revenue growth",
    "funding", "series a", "series b", "series c", "series d", "seed funding",
    "valuation", "valuation:", "enterprise value", "market cap",
    "investors", "investment", "acquisition", "acquired", "exit",
    "ipo", "public offering", "s-1", "sec filing", "10-k", "10-q", "8-k",
    "profit", "net income", "gross margin", "operating margin", "ebitda",
    "total assets", "total liabilities", "cash flow", "free cash flow",
    "stock price", "share price", "market capitalization",
    "funding round", "venture capital", "private equity", "angel investor",
    "total funding", "raised", "funding amount",
    "ceo", "cfo", "chief financial officer", "chief executive",
    "board of directors", "board member", "advisory board",
    "subsidiary", "parent company", "holding company", "group company",
    "fortune 500", "fortune 1000", "public company", "private company",
    "annual report", "financial statement", "financial result",
    "fy2023", "fy2024", "fy2025", "fy2026", "fiscal year",
    "quarterly earnings", "earnings report", "investor relations",
    "dividend", "buyback", "share repurchase",
]

PAYMENT_PATTERNS = [
    (r"stripe\.com|Stripe\.js|stripe\.js|pk_live_|sk_live_|\"stripe\"|'stripe'", "Stripe"),
    (r"paypal\.com|paypal\.objects|PAYPAL|paypalcheckout|\"paypal\"|'paypal'", "PayPal"),
    (r"square\.com|Square\.js|sqpaymentform|\"square\"|'square'", "Square"),
    (r"braintree.*gateway|braintree\.js|btoken=", "Braintree"),
    (r"amazon.*pay|amazonpayments|OffAmazonPayments", "Amazon Pay"),
    (r"adyen\.com|adyen\.js|adyen\.encrypt", "Adyen"),
    (r"shopify.*pay|shopify\.js|shopify.*checkout", "Shopify Payments"),
    (r"recurly\.com|recurly\.js", "Recurly"),
    (r"chargebee\.com|chargebee\.js", "Chargebee"),
    (r"paddle\.com|paddle\.js", "Paddle"),
    (r"mollie\.com|mollie\.js", "Mollie"),
    (r"razorpay\.com|razorpay-", "Razorpay"),
    (r"instamojo\.com|instamojo-", "Instamojo"),
    (r"paystack\.com|paystack\.js", "Paystack"),
    (r"mercadopago\.com|mercadopago\.js", "Mercado Pago"),
    (r"pagseguro|pagseguro\.com", "PagSeguro"),
    (r"2checkout\.com|2co\.com|twocheckout", "2Checkout / Verifone"),
    (r"authorize\.net|accept\.js|AuthorizeNet", "Authorize.net"),
    (r"worldpay\.com|worldpay\.js", "Worldpay / FIS"),
    (r"eway\.com|eway\.js|eWAY", "eWay"),
]

COMPANY_EXTRACT = re.compile(
    r'(?:copyright|&copy;|©|powered by|company|inc\.|corp\.|llc|ltd\.|limited|gmbh|pvt\.|pty\.|sa\.|nv\.|plc)\s*(?::|,)?\s*([^,\n]{3,80})',
    re.IGNORECASE
)

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        parsed = urlparse(domain)
        domain = parsed.netloc
    base_url = f"https://{domain}"
    html = ""
    headers = {}

    try:
        resp = await client.get(base_url, timeout=12.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            html = resp.text if hasattr(resp, "text") else ""
            headers = dict(resp.headers)
    except Exception:
        try:
            resp = await client.get(f"http://{domain}", timeout=12.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp.status_code == 200:
                html = resp.text if hasattr(resp, "text") else ""
                headers = dict(resp.headers)
        except Exception:
            pass

    company_names = set()
    for match in COMPANY_EXTRACT.finditer(html):
        name = match.group(1).strip()
        if name and len(name) > 3 and not any(x in name.lower() for x in ["all rights", "reserved"]):
            company_names.add(name)

    company_name = ""
    if company_names:
        company_name = list(company_names)[0]
        findings.append(IntelligenceFinding(
            entity=company_name[:200],
            type="Financial - Detected Company Name",
            source="FinancialRecon",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data=f"Company found in page: {company_name}",
            tags=["company"]
        ))

    for pattern, proc in PAYMENT_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(IntelligenceFinding(
                entity=proc,
                type="Financial - Payment Processor Detected",
                source="FinancialRecon",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                raw_data=f"Detected {proc} on target website",
                tags=["payment", "processor"]
            ))

    for keyword in FINANCIAL_KEYWORDS:
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        matches = pattern.findall(html)
        if matches:
            context_matches = re.findall(
                r'(?:.{0,100})' + re.escape(keyword) + r'(?:.{0,100})',
                html, re.IGNORECASE
            )
            ctx = context_matches[0].strip()[:200] if context_matches else ""
            findings.append(IntelligenceFinding(
                entity=f"Mention: '{keyword}' ({len(matches)} occurrences)",
                type="Financial - Keyword Detection",
                source="FinancialRecon",
                confidence="Medium",
                color="orange" if any(w in keyword.lower() for w in ["funding", "revenue", "valuation", "raised", "ipo"]) else "slate",
                threat_level="Standard Target" if any(w in keyword.lower() for w in ["funding", "revenue", "valuation", "raised"]) else "Informational",
                raw_data=ctx[:500],
                tags=["financial", "keyword"]
            ))
            break

    try:
        org_name = company_name if company_name else domain.split(".")[0].title()
        edgar_url = f"https://efts.sec.gov/LATEST/search-index?q={quote(org_name)}&dateRange=all&startdt=&enddt="
        edgar_resp = await client.get(edgar_url, timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json"
            })
        if edgar_resp.status_code == 200:
            edgar_data = edgar_resp.json()
            if isinstance(edgar_data, dict):
                filings = edgar_data.get("hits", {}).get("hits", []) if "hits" in edgar_data else []
                if not filings and "total" in edgar_data:
                    filings_count = edgar_data.get("total", {}).get("value", 0)
                else:
                    filings_count = len(filings)
                if filings_count > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"{filings_count} SEC EDGAR filings for '{org_name}'",
                        type="Financial - SEC EDGAR Filings",
                        source="FinancialRecon",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"Found {filings_count} filings for {org_name} on SEC EDGAR",
                        tags=["sec", "edgar", "financial"]
                    ))
                    for filing in filings[:5]:
                        if isinstance(filing, dict):
                            src = filing.get("_source", filing)
                            form = src.get("form", "") or src.get("form_type", "")
                            desc = src.get("description", "") or src.get("display_name", "")
                            filed = src.get("filed", "") or src.get("date_filed", "")
                            if form or desc:
                                findings.append(IntelligenceFinding(
                                    entity=f"{form}: {desc[:150] if desc else 'N/A'} ({filed})",
                                    type="Financial - SEC Filing Detail",
                                    source="FinancialRecon",
                                    confidence="Medium",
                                    color="slate",
                                    raw_data=f"Form: {form} | Filed: {filed} | Description: {desc[:300]}",
                                    tags=["sec", "filing"]
                                ))
    except Exception:
        pass

    try:
        org_encoded = quote(org_name if company_name else domain)
        oc_url = f"https://api.opencorporates.com/v0.4/companies/search?q={org_encoded}"
        oc_resp = await client.get(oc_url, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                     "Accept": "application/json"})
        if oc_resp.status_code == 200:
            oc_data = oc_resp.json()
            oc_results = oc_data.get("results", {}).get("companies", [])
            if oc_results:
                for comp in oc_results[:3]:
                    cdata = comp.get("company", {})
                    name = cdata.get("name", "")
                    juris = cdata.get("jurisdiction_code", "")
                    inc_date = cdata.get("incorporation_date", "")
                    status = cdata.get("company_status", "")
                    if name:
                        findings.append(IntelligenceFinding(
                            entity=name[:200],
                            type="Financial - OpenCorporates Registration",
                            source="FinancialRecon",
                            confidence="Medium",
                            color="slate",
                            status=status or "Unknown",
                            resolution=f"Jurisdiction: {juris}",
                            raw_data=f"Company: {name} | Jurisdiction: {juris} | Incorporated: {inc_date} | Status: {status}",
                            tags=["corporate", "opencorporates"]
                        ))
    except Exception:
        pass

    try:
        cb_url = f"https://api.crunchbase.com/api/v4/autocomplete?query={quote(org_name if company_name else domain.split('.')[0])}&collection_ids=organizations&limit=3"
        cb_resp = await client.get(cb_url, timeout=10.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json"
            })
        if cb_resp.status_code == 200:
            cb_data = cb_resp.json()
            entities = cb_data.get("entities", [])
            if entities:
                for ent in entities[:3]:
                    identifier = ent.get("identifier", {})
                    name = identifier.get("value", "")
                    cb_uuid = identifier.get("uuid", "")
                    if name:
                        findings.append(IntelligenceFinding(
                            entity=name[:200],
                            type="Financial - Crunchbase Organization",
                            source="FinancialRecon",
                            confidence="Medium",
                            color="purple",
                            resolution=f"UUID: {cb_uuid}",
                            raw_data=f"Crunchbase: {name} ({cb_uuid})",
                            tags=["crunchbase", "company"]
                        ))
    except Exception:
        pass

    try:
        if company_name:
            gs_path = f"/search?q={quote(company_name)}+financials+revenue+funding"
            gs_url = f"https://html.duckduckgo.com/html/{gs_path}"
            gs_resp = await client.get(gs_url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if gs_resp.status_code == 200:
                gs_html = gs_resp.text
                snippet_pattern = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.DOTALL)
                snippets = snippet_pattern.findall(gs_html)
                financial_snippets = []
                for sn in snippets[:5]:
                    clean = re.sub(r'<[^>]+>', '', sn).strip()
                    if any(k in clean.lower() for k in ["revenue", "funding", "million", "billion", "valuation", "series", "raised"]):
                        financial_snippets.append(clean)
                for snippet in financial_snippets[:3]:
                    findings.append(IntelligenceFinding(
                        entity=snippet[:200],
                        type="Financial - Web Search Result",
                        source="FinancialRecon",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        raw_data=snippet[:500],
                        tags=["web-search", "financial"]
                    ))
    except Exception:
        pass

    try:
        if "stripe" in html.lower():
            stripe_json = {}
            stripe_matches = re.findall(r'Stripe.*?\{[^}]+key[^}]+"', html)
            for sm in stripe_matches[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"Stripe integration detected: {sm[:100]}",
                    type="Financial - Stripe Integration Detail",
                    source="FinancialRecon",
                    confidence="Medium",
                    color="purple",
                    tags=["stripe", "payment"]
                ))
    except Exception:
        pass

    try:
        price_patterns = [
            (r'\$\s*[\d,]+\.?\d*\s*(?:/mo|/month|/year|/yr|annually|monthly|per year|per month)', "Pricing Mention"),
            (r'starting\s+at\s*\$[\d,]+', "Starting Price"),
            (r'from\s*\$[\d,]+', "Price From"),
            (r'price[s]?\s*:\s*\$[\d,]+', "Explicit Price"),
            (r'plan[s]?\s*:\s*\$[\d,]+', "Plan Price"),
        ]
        for price_pat, price_type in price_patterns:
            price_matches = re.findall(price_pat, html, re.IGNORECASE)
            if price_matches:
                findings.append(IntelligenceFinding(
                    entity=f"{price_type}: {price_matches[0][:100]}",
                    type="Financial - Pricing Information",
                    source="FinancialRecon",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["pricing"]
                ))
                break
    except Exception:
        pass

    try:
        company_keywords = ["investor", "investors", "investor relations", "investors relations"]
        investor_found = any(k in html.lower() for k in company_keywords)
        if investor_found:
            findings.append(IntelligenceFinding(
                entity="Investor relations page exists",
                type="Financial - Investor Relations",
                source="FinancialRecon",
                confidence="High",
                color="purple",
                threat_level="Informational",
                tags=["investor"]
            ))
    except Exception:
        pass

    try:
        job_patterns = [
            (r"(?:hiring|careers|jobs|join us|work with us)", "Job Openings Mention"),
            (r"(?:glassdoor|linkedin|indeed)\.com/.*(?:company|jobs)", "Job Platform Link"),
        ]
        for jp, jt in job_patterns:
            if re.search(jp, html, re.IGNORECASE):
                findings.append(IntelligenceFinding(
                    entity=jt,
                    type="Financial - Employment Presence",
                    source="FinancialRecon",
                    confidence="Medium",
                    color="slate",
                    tags=["employment"]
                ))
                break
    except Exception:
        pass

    try:
        if company_name:
            relevant = [f for f in findings if "SEC EDGAR" in (f.type or "") or "OpenCorporates" in (f.type or "") or "Crunchbase" in (f.type or "")]
            findings.append(IntelligenceFinding(
                entity=f"Financial recon for {company_name}: {len(relevant)} data sources found",
                type="Financial - Summary",
                source="FinancialRecon",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                raw_data=f"Company: {company_name} | Sources with data: {len(relevant)}",
                tags=["summary"]
            ))
    except Exception:
        pass

    return findings
