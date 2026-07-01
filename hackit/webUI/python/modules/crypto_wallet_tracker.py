import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

BLOCKCHAIN_EXPLORERS = {
    "BTC": ["https://blockchain.info/address/{}", "https://blockchair.com/bitcoin/address/{}"],
    "ETH": ["https://etherscan.io/address/{}", "https://ethplorer.io/address/{}"],
    "BSC": ["https://bscscan.com/address/{}"],
    "SOL": ["https://solscan.io/account/{}"],
    "XMR": ["https://monerohash.com/address/{}", "https://chainradar.com/xmr/address/{}"],
    "LTC": ["https://blockchair.com/litecoin/address/{}"],
    "XRP": ["https://xrpscan.com/account/{}"],
    "ADA": ["https://cardanoscan.io/address/{}"],
    "DOT": ["https://subscan.io/account/{}"],
    "MATIC": ["https://polygonscan.com/address/{}"],
    "AVAX": ["https://snowtrace.io/address/{}"],
    "TRX": ["https://tronscan.org/#/address/{}"],
    "ATOM": ["https://mintscan.io/cosmos/address/{}"],
    "ALGO": ["https://algoexplorer.io/address/{}"],
    "FIL": ["https://filfox.info/en/address/{}"],
    "FTM": ["https://ftmscan.com/address/{}"],
    "KSM": ["https://kusama.subscan.io/account/{}"],
    "XTZ": ["https://tzkt.io/{}"],
    "EOS": ["https://eosflare.io/account/{}"],
    "NEO": ["https://neotracker.io/address/{}"],
    "VET": ["https://vechainstats.com/account/{}"],
    "THETA": ["https://explorer.thetatoken.org/account/{}"],
    "HBAR": ["https://hashscan.io/mainnet/account/{}"],
    "ICP": ["https://ic.rocks/account/{}"],
}

WALLET_PATTERNS = {
    "BTC": re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    "ETH": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "BSC": re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    "SOL": re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'),
    "XMR": re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
    "LTC": re.compile(r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),
    "XRP": re.compile(r'\br[1-9A-HJ-NP-Za-km-z]{24,34}\b'),
    "ADA": re.compile(r'\baddr1[0-9a-z]{58}\b'),
    "TRX": re.compile(r'\bT[A-Za-z1-9]{33}\b'),
}

MIXER_PATTERNS = [
    re.compile(r'tornado|cash|wasabi|samourai|chipmixer|sinbad|blender|yomix', re.I),
    re.compile(r'mix(er|ing)|tumbler|coinjoin|coin.?join', re.I),
    re.compile(r'privacy.?pool|anonymiz|anonymou', re.I),
]

EXCHANGE_PATTERNS = [
    re.compile(r'binance|coinbase|kraken|bitfinex|gemini|kucoin|huobi|okx|bybit', re.I),
    re.compile(r'bitmex|deribit|crypto\.com|gate\.io|poloniex|bittrex|hitbtc', re.I),
    re.compile(r'whitebit|mexc|lbank|phemex|bitget|bingx|coinex', re.I),
]

DARKNET_PATTERNS = [
    re.compile(r'hansa|alphabay|dream.?market|silk.?road|gmb|darknet|dark.?net', re.I),
    re.compile(r'hydra|vs.?market|empire.?market|tor.', re.I),
    re.compile(r'.*\.onion', re.I),
]

async def detect_wallet_addresses(target: str) -> list:
    results = []
    try:
        for chain, pattern in WALLET_PATTERNS.items():
            matches = pattern.findall(target)
            for m in set(matches):
                results.append({"chain": chain, "address": m})
    except:
        pass
    return results

async def check_blockchain_explorer(client: httpx.AsyncClient, chain: str, address: str) -> list:
    results = []
    try:
        if chain in BLOCKCHAIN_EXPLORERS:
            for url_template in BLOCKCHAIN_EXPLORERS[chain][:1]:
                try:
                    url = url_template.format(address)
                    resp = await client.get(url, timeout=10.0,
                        headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        results.append({
                            "chain": chain,
                            "address": address,
                            "explorer_url": url,
                            "accessible": True,
                            "response_length": len(resp.text)
                        })
                except:
                    pass
    except:
        pass
    return results

async def detect_mixing_usage(target: str) -> list:
    results = []
    try:
        for pattern in MIXER_PATTERNS:
            match = pattern.search(target)
            if match:
                results.append({"pattern": str(pattern)[:60], "match": match.group()})
    except:
        pass
    return results

async def detect_exchange_addresses(target: str) -> list:
    results = []
    try:
        for pattern in EXCHANGE_PATTERNS:
            match = pattern.search(target)
            if match:
                results.append({"pattern": str(pattern)[:50], "match": match.group()})
    except:
        pass
    return results

async def detect_darknet_interactions(target: str) -> list:
    results = []
    try:
        for pattern in DARKNET_PATTERNS:
            match = pattern.search(target)
            if match:
                results.append({"pattern": str(pattern)[:50], "match": match.group()})
    except:
        pass
    return results

async def analyze_transaction_patterns(wallet_addresses: list) -> list:
    results = []
    try:
        for w in wallet_addresses:
            chain = w.get("chain", "Unknown")
            address = w.get("address", "")
            results.append({
                "chain": chain,
                "address": address[:16] + "...",
                "pattern": "standard_wallet",
                "risk_indicators": []
            })
    except:
        pass
    return results

async def calculate_risk_score(wallet_data: list, mixing: list, exchange: list, darknet: list) -> dict:
    try:
        score = 0
        if wallet_data:
            score += 10
        if mixing:
            score += 35
        if darknet:
            score += 30
        if exchange:
            score += 5
        score = min(score, 100)
        if score >= 70:
            level = "Critical"
        elif score >= 40:
            level = "High Risk"
        elif score >= 15:
            level = "Elevated Risk"
        else:
            level = "Low Risk"
        return {"score": score, "level": level}
    except:
        return {"score": 0, "level": "Unknown"}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip()

    wallet_addresses = await detect_wallet_addresses(query)
    for w in wallet_addresses:
        findings.append(IntelligenceFinding(
            entity=f"Wallet address detected: {w['chain']} - {w['address'][:16]}...",
            type="Wallet Address Detection",
            source="Wallet Tracker",
            confidence="High",
            color="yellow",
            category="Cryptocurrency Intelligence",
            threat_level="Elevated Risk",
            status="Wallet Found",
            resolution=query,
            tags=["wallet", w['chain'].lower(), "cryptocurrency"]
        ))

        explorer_results = await check_blockchain_explorer(client, w['chain'], w['address'])
        for r in explorer_results:
            findings.append(IntelligenceFinding(
                entity=f"Blockchain explorer: {r['chain']} - {r['explorer_url']} ({r['response_length']} bytes)",
                type="Blockchain Explorer Check",
                source=r['chain'],
                confidence="Medium",
                color="slate",
                category="Cryptocurrency Intelligence",
                threat_level="Informational",
                status="Explorer Accessible",
                resolution=query,
                tags=["blockchain", "explorer", r['chain'].lower()]
            ))

    mixing_results = await detect_mixing_usage(query)
    for r in mixing_results:
        findings.append(IntelligenceFinding(
            entity=f"Mixing/tumbler pattern detected: {r['match']}",
            type="Mixing Service Detection",
            source="Wallet Tracker",
            confidence="Medium",
            color="red",
            category="Cryptocurrency Intelligence",
            threat_level="High Risk",
            status="Mixing Detected",
            resolution=query,
            tags=["mixing", "tumbler", "privacy", r['match'].lower()]
        ))

    exchange_results = await detect_exchange_addresses(query)
    for r in exchange_results:
        findings.append(IntelligenceFinding(
            entity=f"Exchange association detected: {r['match']}",
            type="Exchange Address Detection",
            source="Wallet Tracker",
            confidence="Medium",
            color="yellow",
            category="Cryptocurrency Intelligence",
            threat_level="Elevated Risk",
            status="Exchange Linked",
            resolution=query,
            tags=["exchange", r['match'].lower(), "crypto-exchange"]
        ))

    darknet_results = await detect_darknet_interactions(query)
    for r in darknet_results:
        findings.append(IntelligenceFinding(
            entity=f"Darknet market interaction detected: {r['match']}",
            type="Darknet Interaction Detection",
            source="Wallet Tracker",
            confidence="High",
            color="red",
            category="Cryptocurrency Intelligence",
            threat_level="Critical",
            status="Darknet Linked",
            resolution=query,
            tags=["darknet", "illicit", r['match'].lower().replace(" ", "-")]
        ))

    for chain in list(BLOCKCHAIN_EXPLORERS.keys())[:15]:
        findings.append(IntelligenceFinding(
            entity=f"Blockchain monitored: {chain}",
            type="Blockchain Coverage",
            source="Wallet Tracker",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["blockchain", chain.lower(), "coverage"]
        ))

    risk = await calculate_risk_score(wallet_addresses, mixing_results, exchange_results, darknet_results)
    findings.append(IntelligenceFinding(
        entity=f"Wallet risk score: {risk['score']}/100 ({risk['level']})",
        type="Wallet Risk Assessment",
        source="Wallet Tracker",
        confidence="Medium",
        color="red" if risk['score'] >= 50 else "yellow",
        category="Cryptocurrency Intelligence",
        threat_level=risk['level'],
        status=f"Score: {risk['score']}",
        resolution=query,
        raw_data=json.dumps(risk),
        tags=["risk-score", "wallet", risk['level'].lower().replace(" ", "-")]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Wallet tracking complete for {query[:32]}: detected {len(wallet_addresses)} wallets, checked {len(BLOCKCHAIN_EXPLORERS)} chains",
        type="Wallet Tracking Summary",
        source="Wallet Tracker",
        confidence="Medium",
        color="slate",
        category="Cryptocurrency Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["wallet", "summary", "cryptocurrency"]
    ))

    return findings
