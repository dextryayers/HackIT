import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

CENTRALIZED_EXCHANGES = {
    "Binance": ["binance", "binance.com", "b-nance", "biance"],
    "Coinbase": ["coinbase", "coinbase.com", "pro.coinbase"],
    "Kraken": ["kraken", "kraken.com"],
    "Bitfinex": ["bitfinex", "bitfinex.com"],
    "Gemini": ["gemini", "gemini.com"],
    "KuCoin": ["kucoin", "kucoin.com"],
    "Huobi": ["huobi", "huobi.com", "htx"],
    "OKX": ["okx", "okx.com", "okex"],
    "Bybit": ["bybit", "bybit.com"],
    "BitMEX": ["bitmex", "bitmex.com"],
    "Deribit": ["deribit", "deribit.com"],
    "Crypto.com": ["crypto.com", "crypto.com/exchange"],
    "Gate.io": ["gate.io", "gateio"],
    "Poloniex": ["poloniex", "poloniex.com"],
    "Bittrex": ["bittrex", "bittrex.com"],
    "HitBTC": ["hitbtc", "hitbtc.com", "hit-btc"],
    "WhiteBIT": ["whitebit", "whitebit.com"],
    "MEXC": ["mexc", "mexc.com"],
    "LBank": ["lbank", "lbank.com", "l-bank"],
    "Phemex": ["phemex", "phemex.com"],
    "Bitget": ["bitget", "bitget.com"],
    "BingX": ["bingx", "bingx.com"],
}

DECENTRALIZED_EXCHANGES = {
    "Uniswap": ["uniswap", "uniswap.org", "app.uniswap"],
    "PancakeSwap": ["pancakeswap", "pancakeswap.finance", "app.pancakeswap"],
    "SushiSwap": ["sushi", "sushi.com", "app.sushi"],
    "Curve": ["curve", "curve.fi"],
    "Balancer": ["balancer", "balancer.fi"],
    "Aave": ["aave", "aave.com"],
    "Compound": ["compound", "compound.finance"],
    "dYdX": ["dydx", "dydx.exchange"],
    "1inch": ["1inch", "app.1inch.io", "1inch.exchange"],
    "QuickSwap": ["quickswap", "quickswap.exchange"],
    "Trader Joe": ["traderjoe", "traderjoexyz"],
    "Raydium": ["raydium", "raydium.io"],
    "Orca": ["orca", "orca.so"],
    "Jupiter": ["jupiter", "jup.ag"],
    "GMX": ["gmx", "gmx.io", "app.gmx"],
    "Synthetix": ["synthetix", "synthetix.io"],
    "MakerDAO": ["makerdao", "makerdao.com", "oasis"],
    "KyberSwap": ["kyber", "kyberswap", "kyber.network"],
    "0x Protocol": ["0x", "0x.org", "0xprotocol"],
}

EXCHANGE_API_PATTERNS = [
    re.compile(r'/api/v\d+/order', re.I),
    re.compile(r'/api/v\d+/trade', re.I),
    re.compile(r'/api/v\d+/balance', re.I),
    re.compile(r'/api/v\d+/depth', re.I),
    re.compile(r'/api/v\d+/ticker', re.I),
    re.compile(r'/api/v\d+/kline', re.I),
    re.compile(r'/api/v\d+/market', re.I),
    re.compile(r'/sapi/v\d+/', re.I),
    re.compile(r'/rest/api/v\d+/', re.I),
    re.compile(r'/exchange/trading', re.I),
]

TRADING_PAIR_PATTERNS = [
    re.compile(r'\b[A-Z]{2,6}/[A-Z]{2,6}\b'),
    re.compile(r'\b[A-Z]{2,6}USDT\b'),
    re.compile(r'\b[A-Z]{2,6}BTC\b'),
    re.compile(r'\b[A-Z]{2,6}ETH\b'),
]

async def detect_exchange_association(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for exchange, indicators in CENTRALIZED_EXCHANGES.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"exchange": exchange, "type": "Centralized", "matched": ind})
                    break
        for exchange, indicators in DECENTRALIZED_EXCHANGES.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"exchange": exchange, "type": "Decentralized", "matched": ind})
                    break
    except:
        pass
    return results

async def check_exchange_endpoints(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        if not target.startswith(("http://", "https://")):
            base = f"https://{target}"
        else:
            base = target
        for pattern in EXCHANGE_API_PATTERNS:
            try:
                path = pattern.pattern.replace("\\/", "/").replace("\\d+", "1").replace("(", "").replace(")", "").replace("?", "").replace("+", "")
                path = path.strip("/")
                if not path:
                    continue
                url = f"{base}/{path}"
                resp = await client.get(url, timeout=5.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code < 500:
                    results.append({
                        "endpoint": f"/{path}",
                        "status": resp.status_code,
                        "exchange_api": True
                    })
            except:
                pass
    except:
        pass
    return results

async def extract_trading_pairs(target: str) -> list:
    results = []
    try:
        for pattern in TRADING_PAIR_PATTERNS:
            matches = pattern.findall(target)
            for m in set(matches):
                results.append({"pair": m})
    except:
        pass
    return results

async def check_exchange_wallet_patterns(target: str) -> list:
    results = []
    try:
        wallet_prefixes = {
            "Binance": ["0x", "bnb1", "1", "3"],
            "Coinbase": ["0x", "1", "3"],
            "Kraken": ["0x", "r", "1"],
        }
        target_lower = target.lower()
        for exchange, prefixes in wallet_prefixes.items():
            if exchange.lower() in target_lower:
                results.append({"exchange": exchange, "wallet_prefixes": prefixes})
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    exchange_results = await detect_exchange_association(query)
    for r in exchange_results:
        findings.append(IntelligenceFinding(
            entity=f"Exchange detected: {r['exchange']} ({r['type']}) - matched: {r['matched']}",
            type="Exchange Association",
            source="Exchange Detector",
            confidence="Medium",
            color="yellow" if r['type'] == "Centralized" else "orange",
            category="Cryptocurrency Intelligence",
            threat_level="Informational" if r['type'] == "Centralized" else "Elevated Risk",
            status="Exchange Identified",
            resolution=query,
            tags=["exchange", r['type'].lower(), r['exchange'].lower().replace(" ", "-").replace(".", "-")]
        ))

    api_results = await check_exchange_endpoints(client, query)
    for r in api_results:
        findings.append(IntelligenceFinding(
            entity=f"Exchange API endpoint: {r['endpoint']} (HTTP {r['status']})",
            type="Exchange API Detection",
            source="Exchange Detector",
            confidence="Medium",
            color="yellow",
            category="Cryptocurrency Intelligence",
            threat_level="Elevated Risk",
            status="API Endpoint Found",
            resolution=query,
            tags=["exchange-api", "endpoint", r['endpoint'].replace("/", "-").strip("-")]
        ))

    trading_pair_results = await extract_trading_pairs(query)
    for r in trading_pair_results:
        findings.append(IntelligenceFinding(
            entity=f"Trading pair detected: {r['pair']}",
            type="Trading Pair Detection",
            source="Exchange Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Intelligence",
            threat_level="Informational",
            status="Pair Found",
            resolution=query,
            tags=["trading-pair", r['pair'].replace("/", "-").lower()]
        ))

    wallet_results = await check_exchange_wallet_patterns(query)
    for r in wallet_results:
        findings.append(IntelligenceFinding(
            entity=f"Exchange wallet pattern: {r['exchange']} (prefixes: {', '.join(r['wallet_prefixes'])})",
            type="Exchange Wallet Detection",
            source="Exchange Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Intelligence",
            threat_level="Informational",
            status="Wallet Pattern Noted",
            resolution=query,
            tags=["exchange", "wallet", r['exchange'].lower().replace(" ", "-")]
        ))

    for exchange, indicators in list(CENTRALIZED_EXCHANGES.items())[:10]:
        findings.append(IntelligenceFinding(
            entity=f"CEX monitored: {exchange}",
            type="Exchange Coverage (CEX)",
            source="Exchange Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["cex", exchange.lower().replace(" ", "-").replace(".", "-")]
        ))

    for exchange, indicators in list(DECENTRALIZED_EXCHANGES.items())[:10]:
        findings.append(IntelligenceFinding(
            entity=f"DEX monitored: {exchange}",
            type="Exchange Coverage (DEX)",
            source="Exchange Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["dex", exchange.lower().replace(" ", "-").replace(".", "-")]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Exchange detection complete for {query}: checked {len(CENTRALIZED_EXCHANGES)} CEX + {len(DECENTRALIZED_EXCHANGES)} DEX = {len(CENTRALIZED_EXCHANGES) + len(DECENTRALIZED_EXCHANGES)} total exchanges",
        type="Exchange Detection Summary",
        source="Exchange Detector",
        confidence="Medium",
        color="slate",
        category="Cryptocurrency Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["exchange", "summary", "cryptocurrency"]
    ))

    return findings
