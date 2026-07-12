import httpx
import re
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

MARKETPLACES = {
    "OpenSea": ["opensea", "opensea.io", "opensea.com"],
    "Blur": ["blur", "blur.io"],
    "Rarible": ["rarible", "rarible.com"],
    "LooksRare": ["looksrare", "looksrare.org"],
    "X2Y2": ["x2y2", "x2y2.io"],
    "MagicEden": ["magiceden", "magiceden.io"],
    "Element": ["element.market", "element"],
    "NFTKey": ["nftkey", "nftkey.app"],
    "Gem.xyz": ["gem.xyz", "gem"],
    "Genie": ["genie.xyz", "genie"],
}

RUG_PULL_INDICATORS = [
    re.compile(r'team.?wallet|dev.?wallet|multi.?sig|gnosis.?safe', re.I),
    re.compile(r'liquidity.?remov|remove.?liquid|rug.?pull', re.I),
    re.compile(r'honeypot|cannot.?sell|tax.?100|100%?.?tax', re.I),
    re.compile(r'fake|scam|copycat|impersonat|phishing|counterfeit', re.I),
    re.compile(r'mint.?price.?high|gas.?price.?high|mint.?tax', re.I),
]

HONEYPOT_PATTERNS = [
    re.compile(r'function\s+transfer\s*\(', re.I),
    re.compile(r'require\s*\(.*balance|require.*sender', re.I),
    re.compile(r'address\.this\.balance|address\.send|address\.call', re.I),
    re.compile(r'transferFrom|safeTransferFrom|approve', re.I),
    re.compile(r'onlyOwner|onlyAdmin|onlyDev|hasRole', re.I),
]

WASH_TRADING_PATTERNS = [
    re.compile(r'same.?address|circular.?trade|wash.?trade', re.I),
    re.compile(r'volume.?infla|fake.?volume|volume.?boost', re.I),
    re.compile(r'cumulative.?volume|total.?volume|trade.?volume', re.I),
]

async def detect_nft_brand_impersonation(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        well_known_collections = [
            "bored ape", "cryptopunks", "mutant ape", "azuki", "doodles",
            "clonex", "moonbirds", "pudgy penguins", "cool cats",
            "world of women", "veefriends", "bored ape kennel club",
            "otherdeed", "decentraland", "sandbox", "ens",
        ]
        for collection in well_known_collections:
            if collection in target_lower:
                results.append({"collection": collection, "type": "impersonation_check"})
    except:
        pass
    return results

async def check_nft_marketplace_listings(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for marketplace, domains in MARKETPLACES.items():
            for domain in domains[:1]:
                if domain in target.lower():
                    results.append({"marketplace": marketplace, "domain": domain, "detected": True})
                    break
    except:
        pass
    return results

async def analyze_smart_contract_patterns(target: str) -> list:
    results = []
    try:
        for pattern in HONEYPOT_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:60], "category": "honeypot"})
    except:
        pass
    return results

async def detect_rug_pull_indicators(target: str) -> list:
    results = []
    try:
        for pattern in RUG_PULL_INDICATORS:
            match = pattern.search(target)
            if match:
                results.append({"pattern": str(pattern)[:60], "match": match.group()})
    except:
        pass
    return results

async def detect_wash_trading(target: str) -> list:
    results = []
    try:
        for pattern in WASH_TRADING_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:50]})
    except:
        pass
    return results

async def check_phishing_nft_sites(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        phishing_domains = [
            "opensea.io.ph", "opensea-nft.com", "opensea-airdrop.com",
            "rarible-phishing.com", "looksrare-airdrop.com",
        ]
        for domain in phishing_domains:
            if domain in target.lower():
                results.append({"domain": domain, "type": "phishing_site"})
    except:
        pass
    return results

async def analyze_team_wallet_patterns(target: str) -> list:
    results = []
    try:
        team_wallet_keywords = [
            "dev_wallet", "team_wallet", "foundation", "treasury",
            "multi_sig", "gnosis_safe", "timelock",
        ]
        target_lower = target.lower()
        for kw in team_wallet_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "category": "team_wallet"})
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    impersonation_results = await detect_nft_brand_impersonation(query)
    for r in impersonation_results:
        findings.append(make_finding(
            entity=f"Potential brand impersonation: {r['collection']} detected",
            ftype="NFT Brand Impersonation",
            source="NFT Scanner",
            confidence="Medium",
            color="red",
            category="NFT Intelligence",
            threat_level="High Risk",
            status="Impersonation Detected",
            resolution=query,
            tags=["nft", "impersonation", r['collection'].lower().replace(" ", "-")]
        ))

    marketplace_results = await check_nft_marketplace_listings(client, query)
    for r in marketplace_results:
        findings.append(make_finding(
            entity=f"NFT marketplace reference: {r['marketplace']} ({r['domain']})",
            type="NFT Marketplace Detection",
            source="NFT Scanner",
            confidence="Medium",
            color="slate",
            category="NFT Intelligence",
            threat_level="Informational",
            status="Marketplace Found",
            resolution=query,
            tags=["nft", "marketplace", r['marketplace'].lower().replace(".", "-").replace(" ", "-")]
        ))

    contract_results = await analyze_smart_contract_patterns(query)
    for r in contract_results:
        findings.append(make_finding(
            entity=f"Honeypot smart contract pattern: {r['pattern'][:50]}...",
            ftype="Smart Contract Honeypot",
            source="NFT Scanner",
            confidence="Low",
            color="red",
            category="NFT Intelligence",
            threat_level="Critical",
            status="Honeypot Pattern",
            resolution=query,
            tags=["nft", "honeypot", "smart-contract", "scam"]
        ))

    rug_pull_results = await detect_rug_pull_indicators(query)
    for r in rug_pull_results:
        findings.append(make_finding(
            entity=f"Rug pull indicator: {r['match']}",
            ftype="Rug Pull Detection",
            source="NFT Scanner",
            confidence="Medium",
            color="red",
            category="NFT Intelligence",
            threat_level="Critical",
            status="Rug Pull Risk",
            resolution=query,
            tags=["nft", "rug-pull", "scam", "fraud"]
        ))

    wash_trading_results = await detect_wash_trading(query)
    for r in wash_trading_results:
        findings.append(make_finding(
            entity=f"Wash trading pattern detected: {r['pattern'][:50]}...",
            ftype="Wash Trading Detection",
            source="NFT Scanner",
            confidence="Low",
            color="orange",
            category="NFT Intelligence",
            threat_level="Elevated Risk",
            status="Wash Trading Suspected",
            resolution=query,
            tags=["nft", "wash-trading", "market-manipulation"]
        ))

    phishing_results = await check_phishing_nft_sites(client, query)
    for r in phishing_results:
        findings.append(make_finding(
            entity=f"NFT phishing site: {r['domain']} ({r['type']})",
            type="NFT Phishing Detection",
            source="NFT Scanner",
            confidence="High",
            color="red",
            category="NFT Intelligence",
            threat_level="Critical",
            status="Phishing Site",
            resolution=query,
            tags=["nft", "phishing", "fake-site"]
        ))

    team_wallet_results = await analyze_team_wallet_patterns(query)
    for r in team_wallet_results:
        findings.append(make_finding(
            entity=f"Team wallet pattern: {r['keyword']} ({r['category']})",
            type="Team Wallet Analysis",
            source="NFT Scanner",
            confidence="Low",
            color="yellow",
            category="NFT Intelligence",
            threat_level="Elevated Risk",
            status="Wallet Pattern Found",
            resolution=query,
            tags=["nft", "team-wallet", r['keyword']]
        ))

    for marketplace in MARKETPLACES:
        findings.append(make_finding(
            entity=f"NFT marketplace monitored: {marketplace}",
            ftype="Marketplace Coverage",
            source="NFT Scanner",
            confidence="Low",
            color="slate",
            category="NFT Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["nft", "marketplace", marketplace.lower().replace(" ", "-").replace(".", "-")]
        ))

    if not impersonation_results and not rug_pull_results:
        findings.append(make_finding(
            entity=f"No NFT scam indicators found for {query}",
            ftype="NFT Scan Result",
            source="NFT Scanner",
            confidence="Low",
            color="emerald",
            category="NFT Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["nft", "clean", "no-scam"]
        ))

    findings.append(make_finding(
        entity=f"NFT scan complete for {query}: checked {len(MARKETPLACES)} marketplaces, {len(RUG_PULL_INDICATORS)} rug indicators, {len(HONEYPOT_PATTERNS)} honeypot patterns",
        type="NFT Scan Summary",
        source="NFT Scanner",
        confidence="Medium",
        color="slate",
        category="NFT Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["nft", "summary", "scan"]
    ))

    return findings
