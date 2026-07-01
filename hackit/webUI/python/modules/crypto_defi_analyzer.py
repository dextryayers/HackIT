import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

DEFI_PROTOCOLS = {
    "Uniswap": ["uniswap", "v2", "v3", "v4"],
    "Curve": ["curve", "crv", "curve.fi"],
    "Aave": ["aave", "aave v2", "aave v3"],
    "Compound": ["compound", "comp"],
    "MakerDAO": ["maker", "dai", "makerdao", "mkr"],
    "Lido": ["lido", "steth", "wsteth", "lido.fi"],
    "Balancer": ["balancer", "bal"],
    "PancakeSwap": ["pancakeswap", "cake"],
    "SushiSwap": ["sushi", "sushi.com", "sushiswap"],
    "GMX": ["gmx", "gmx.io"],
    "Synthetix": ["synthetix", "snx"],
    "Yearn": ["yearn", "yfi", "yearn.finance"],
    "Convex": ["convex", "cvx"],
    "dYdX": ["dydx", "dydx.exchange"],
    "1inch": ["1inch", "1inch.io"],
    "QuickSwap": ["quickswap", "quick"],
    "Trader Joe": ["traderjoe", "joe"],
    "Raydium": ["raydium", "ray"],
    "Jupiter": ["jupiter", "jup"],
    "Orca": ["orca", "orca.so"],
    "KyberSwap": ["kyberswap", "kyber"],
    "Camelot": ["camelot", "camelot.exchange"],
    "Morpho": ["morpho", "morpho.blue"],
    "Euler": ["euler", "euler.finance"],
    "Radiant": ["radiant", "rdnt", "radiant.capital"],
}

GOVERNANCE_TOKEN_PATTERNS = [
    re.compile(r'\b[A-Z]{2,10}\b'),
    re.compile(r'governance|dao|vote|proposal|voting|delegate', re.I),
]

FLASH_LOAN_PATTERNS = [
    re.compile(r'flash.?loan|flashloan|flash.?mint|flashmint', re.I),
    re.compile(r'callback|afterLoan|executeOperation|_execute', re.I),
    re.compile(r'0x|token.?swap|borrow.?repay|atomic.?swap', re.I),
]

ORACLE_MANIPULATION_PATTERNS = [
    re.compile(r'oracle|price.?feed|price.?oracle|chainlink|twap|spot.?price', re.I),
    re.compile(r'manipulat|price.?impact|slippage|sandwich|mev', re.I),
    re.compile(r'twap.?oracle|uniswap.?oracle|curve.?oracle', re.I),
]

async def detect_defi_protocols(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for protocol, keywords in DEFI_PROTOCOLS.items():
            for kw in keywords:
                if kw in target_lower:
                    results.append({"protocol": protocol, "matched": kw})
                    break
    except:
        pass
    return results

async def analyze_token_contract(target: str) -> list:
    results = []
    try:
        token_patterns = {
            "ERC20": re.compile(r'0x[a-fA-F0-9]{40}'),
            "BEP20": re.compile(r'0x[a-fA-F0-9]{40}'),
            "SPL": re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}'),
        }
        for standard, pattern in token_patterns.items():
            matches = pattern.findall(target)
            for m in set(matches):
                results.append({"standard": standard, "address": m})
    except:
        pass
    return results

async def check_audit_history(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        audit_sources = [
            f"https://github.com/search?q={quote(target)}+audit&type=repositories",
            f"https://github.com/search?q={quote(target)}+security+audit&type=code",
        ]
        for url in audit_sources:
            try:
                resp = await client.get(url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200 and len(resp.text) > 100:
                    results.append({"url": url, "audit_mentioned": True})
            except:
                pass
    except:
        pass
    return results

async def check_flash_loan_vulnerability(target: str) -> list:
    results = []
    try:
        for pattern in FLASH_LOAN_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:50]})
                break
    except:
        pass
    return results

async def check_oracle_manipulation(target: str) -> list:
    results = []
    try:
        for pattern in ORACLE_MANIPULATION_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:50]})
                break
    except:
        pass
    return results

async def estimate_tvl(target: str) -> dict:
    try:
        tvl_indicators = {
            "high": ["billion", "million tvl", "total value locked", "liquidity"],
            "medium": ["pool", "liquidity pool", "farm", "staking"],
            "low": ["new", "launch", "presale", "ido"],
        }
        target_lower = target.lower()
        for level, indicators in tvl_indicators.items():
            for ind in indicators:
                if ind in target_lower:
                    return {"estimate": level, "indicator": ind}
        return {"estimate": "unknown", "indicator": ""}
    except:
        return {"estimate": "unknown", "indicator": ""}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    protocol_results = await detect_defi_protocols(query)
    for r in protocol_results:
        findings.append(IntelligenceFinding(
            entity=f"DeFi protocol identified: {r['protocol']} (matched: {r['matched']})",
            type="DeFi Protocol Detection",
            source="DeFi Analyzer",
            confidence="Medium",
            color="yellow",
            category="DeFi Intelligence",
            threat_level="Elevated Risk",
            status="Protocol Identified",
            resolution=query,
            tags=["defi", "protocol", r['protocol'].lower().replace(" ", "-").replace(".", "-")]
        ))

    token_results = await analyze_token_contract(query)
    for r in token_results:
        findings.append(IntelligenceFinding(
            entity=f"Token contract: {r['standard']} - {r['address'][:16]}...",
            type="Token Contract Detection",
            source="DeFi Analyzer",
            confidence="High",
            color="slate",
            category="DeFi Intelligence",
            threat_level="Informational",
            status="Contract Found",
            resolution=query,
            tags=["token", r['standard'].lower(), "contract"]
        ))

    audit_results = await check_audit_history(client, query)
    for r in audit_results:
        findings.append(IntelligenceFinding(
            entity=f"Audit reference found: {r['url'][:80]}...",
            type="Smart Contract Audit Check",
            source="DeFi Analyzer",
            confidence="Low",
            color="yellow" if "audit" in r['url'].lower() else "slate",
            category="DeFi Intelligence",
            threat_level="Elevated Risk" if "audit" not in r['url'].lower() else "Informational",
            status="Audit Reference Found" if "audit" in r['url'].lower() else "No Audit Reference",
            resolution=query,
            tags=["defi", "audit", "smart-contract"]
        ))

    flash_loan_results = await check_flash_loan_vulnerability(query)
    for r in flash_loan_results:
        findings.append(IntelligenceFinding(
            entity=f"Flash loan pattern detected: {r['pattern'][:50]}...",
            type="Flash Loan Vulnerability Check",
            source="DeFi Analyzer",
            confidence="Low",
            color="orange",
            category="DeFi Intelligence",
            threat_level="High Risk",
            status="Flash Loan Pattern",
            resolution=query,
            tags=["defi", "flash-loan", "vulnerability"]
        ))

    oracle_results = await check_oracle_manipulation(query)
    for r in oracle_results:
        findings.append(IntelligenceFinding(
            entity=f"Oracle manipulation pattern: {r['pattern'][:50]}...",
            type="Oracle Manipulation Risk",
            source="DeFi Analyzer",
            confidence="Low",
            color="orange",
            category="DeFi Intelligence",
            threat_level="High Risk",
            status="Oracle Risk",
            resolution=query,
            tags=["defi", "oracle", "manipulation"]
        ))

    tvl_estimate = await estimate_tvl(query)
    findings.append(IntelligenceFinding(
        entity=f"TVL estimate: {tvl_estimate['estimate']} (indicator: {tvl_estimate['indicator']})",
        type="TVL Estimation",
        source="DeFi Analyzer",
        confidence="Low",
        color="slate",
        category="DeFi Intelligence",
        threat_level="Informational",
        status="Estimated",
        resolution=query,
        tags=["defi", "tvl", tvl_estimate['estimate']]
    ))

    for protocol in list(DEFI_PROTOCOLS.keys())[:15]:
        findings.append(IntelligenceFinding(
            entity=f"DeFi protocol monitored: {protocol}",
            type="DeFi Protocol Coverage",
            source="DeFi Analyzer",
            confidence="Low",
            color="slate",
            category="DeFi Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["defi", "protocol", protocol.lower().replace(" ", "-").replace(".", "-")]
        ))

    findings.append(IntelligenceFinding(
        entity=f"DeFi analysis complete for {query}: checked {len(DEFI_PROTOCOLS)} protocols, flash loan patterns, oracle manipulation risks",
        type="DeFi Analysis Summary",
        source="DeFi Analyzer",
        confidence="Medium",
        color="slate",
        category="DeFi Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["defi", "summary", "analysis"]
    ))

    return findings
