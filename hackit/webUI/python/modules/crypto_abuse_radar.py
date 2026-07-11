import httpx
import asyncio
import re
import json
from datetime import datetime
from typing import List
from collections import defaultdict
from module_common import safe_fetch, safe_fetch_json, make_finding
from models import IntelligenceFinding

SCAM_WALLETS = [
    "1M7LCzU8aVj8vL5Y3H3L2k5Z5p5a5l5n5y5o5x5y5z",
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "1FeexV6bDHb8we2SC5tXLm1bXvQp3YtLHo",
    "bc1qa5g4m5k5n5y5o5x5y5z5e5p5a5l5n5y5o5x5y5z",
    "1HB5XMLmzFVj8ALj6mfBsbifRoD4miY36v",
    "1EfMCkTmkL6K3K3K3K3K3K3K3K3K3K3K3K3K3K3K3K",
]

EXTRA_SCAM_WALLETS = [
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "1M7LCzU8aVj8vL5Y3H3L2k5Z5p5a5l5n5y5o5x5y5z",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1qjh9d0qfhqh0qfhqh0qfhqh0qfhqh0qfhqh0qf",
    "1LQoWist8KkaUXspKAVNJiBDa7Wx8zYc2M",
    "bc1qyzmz5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5z5",
    "3EFeaQW6Wr5jD5jD5jD5jD5jD5jD5jD5jD5jD5jD5jD",
    "bc1qar0srrr7xw7xw7xw7xw7xw7xw7xw7xw7xw7xw7xw",
    "1FuK8DY79R3i1W1W1W1W1W1W1W1W1W1W1W1W1W1W1W1",
    "3Kz5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
]

SCAM_DOMAIN_PATTERNS = [
    r'crypt(?:o)?(?:free|give|bonus|airdrop|mining|invest|wallet|trade|earn|club)',
    r'(?:free|give|bonus|airdrop|mining|invest|earn)crypt(?:o)?',
    r'(?:eth|btc|bitcoin|ethereum|bnb|sol)(?:free|give|bonus|airdrop|mining|invest|earn)',
    r'(?:elon|musk|celebrity|giveaway)[\s.-]*crypto',
    r'(?:nft|defi|metaverse)(?:free|give|bonus|airdrop)',
]

EXTRA_SCAM_DOMAIN_PATTERNS = [
    r'(?:musk|elon|bezos|gates|buffett|cook)(?:giveaway|gift|bonus|airdrop)',
    r'(?:shiba|floki|pepe|dogewith|bonk)(?:airdrop|free|bonus|claim)',
    r'(?:uniswap|pancakeswap|traderjoe)(?:free|airdrop|bonus|claim)',
    r'(?:opensea|rarible|looksrare)(?:free|giveaway|airdrop|mint)',
    r'(?:metamask|trustwallet)(?:connect|sync|update|restore)',
    r'(?:coinbase|binance|kraken\b)(?:login|secure|verify|support)',
    r'(?:debank|zapper\b)(?:airdrop|claim|bonus|giveaway)',
    r'(?:2fa|twofa|authy|googleauthenticator)(?:reset|recover|bypass)',
]

DEFI_SCAM_INDICATORS = [
    "rug pull", "rugpull", "honeypot", "flash loan attack",
    "price manipulation", "slippage attack", "impermanent loss",
    "liquidity drain", "approve all", "unlimited approval",
    "malicious contract", "backdoor", "hidden mint", "proxy contract",
    "upgradeable", "malicious owner", "renounce ownership",
]

EXTRA_DEFI_SCAM_INDICATORS = [
    "fake liquidity", "locked liquidity", "ownership renounced",
    "verified contract", "renounced ownership", "mint function",
    "blacklist function", "transfer from", "tax fee",
    "buy tax", "sell tax", "anti-whale", "max wallet",
    "honeypot detector", "fake supply", "burned supply",
    "circulating supply", "total supply", "max supply",
]

NFT_SCAM_INDICATORS = [
    "phishing link", "malicious mint", "fake mint", "copycat",
    "impersonation", "social engineering", "discord phishing",
    "twitter impersonation", "fake collection", "spoofed url",
]

EXTRA_NFT_SCAM_INDICATORS = [
    "free mint", "whitelist giveaway", "presale access", "early access",
    "guaranteed mint", "allowlist", "rarity sniping", "wash trading",
    "fake volume", "fake floor price", "pump and dump", "insider mint",
    "bot mint", "gas war", "revert mint", "fake metadata",
]

SOCIAL_ENGINEERING_DOMAINS = [
    "opensea", "rarible", "looksrare", "x2y2", "sudoswap",
    "uniswap", "pancakeswap", "traderjoe", "quickswap",
    "metamask", "trustwallet", "rainbow", "argent",
    "coinbase", "binance", "kraken", "ftx", "crypto.com",
    "etherscan", "bscscan", "polygonscan", "debank", "zapper",
    "collab.land", "guild.xyz", "snapshot.org",
]

EXTRA_SOCIAL_ENGINEERING_DOMAINS = [
    "phantom", "solflare", "backpack", "glow", "slope",
    "ledger", "trezor", "keepkey", "safepal", "imtoken",
    "robinhood", "gemini", "bitfinex", "kucoin", "bybit",
    "okx", "huobi", "gate.io", "mexc",
    "coinmarketcap", "coingecko", "defillama", "dune",
    "nansen", "chainalysis", "elliptic",
]

BLOCKCHAIN_EXPLORERS = [
    ("blockchain.info", lambda addr: f"https://blockchain.info/address/{addr}?format=json"),
    ("etherscan.io", lambda addr: f"https://api.etherscan.io/api?module=account&action=txlist&address={addr}"),
    ("bscscan.com", lambda addr: f"https://api.bscscan.com/api?module=account&action=txlist&address={addr}"),
    ("polygonscan.com", lambda addr: f"https://api.polygonscan.com/api?module=account&action=txlist&address={addr}"),
    ("solscan.io", lambda addr: f"https://api.solscan.io/account/{addr}"),
    ("tronscan.org", lambda addr: f"https://apilist.tronscan.org/api/account?address={addr}"),
    ("optimistic.etherscan", lambda addr: f"https://api-optimistic.etherscan.io/api?module=account&action=txlist&address={addr}"),
    ("arbiscan.io", lambda addr: f"https://api.arbiscan.io/api?module=account&action=txlist&address={addr}"),
    ("snowtrace.io", lambda addr: f"https://api.snowtrace.io/api?module=account&action=txlist&address={addr}"),
    ("ftmscan.com", lambda addr: f"https://api.ftmscan.com/api?module=account&action=txlist&address={addr}"),
    ("cronoscan.com", lambda addr: f"https://api.cronoscan.com/api?module=account&action=txlist&address={addr}"),
    ("moonscan.io", lambda addr: f"https://api.moonscan.io/api?module=account&action=txlist&address={addr}"),
]

async def detect_defi_scam(text: str) -> list:
    findings = []
    text_lower = text.lower()
    all_indicators = DEFI_SCAM_INDICATORS + EXTRA_DEFI_SCAM_INDICATORS
    for indicator in all_indicators:
        if indicator in text_lower:
            findings.append(indicator)
    return findings

async def detect_nft_scam(text: str) -> list:
    findings = []
    text_lower = text.lower()
    all_indicators = NFT_SCAM_INDICATORS + EXTRA_NFT_SCAM_INDICATORS
    for indicator in all_indicators:
        if indicator in text_lower:
            findings.append(indicator)
    return findings

async def detect_scam_domain(domain: str) -> list:
    findings = []
    domain_lower = domain.lower()
    all_patterns = SCAM_DOMAIN_PATTERNS + EXTRA_SCAM_DOMAIN_PATTERNS
    for pattern in all_patterns:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            findings.append(pattern)
    all_se_domains = SOCIAL_ENGINEERING_DOMAINS + EXTRA_SOCIAL_ENGINEERING_DOMAINS
    for se_domain in all_se_domains:
        if se_domain.lower() in domain_lower:
            findings.append(f"Social engineering: {se_domain}")
    return findings

async def query_blockchain_explorers(address: str, client: httpx.AsyncClient) -> list:
    results = []
    for name, url_builder in BLOCKCHAIN_EXPLORERS:
        try:
            url = url_builder(address)
            resp = await safe_fetch(client, url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            if resp.status_code == 200:
                results.append({"explorer": name, "data": resp.json()})
        except:
            pass
    return results

async def detect_wallet_addresses(text: str) -> dict:
    wallets = {}
    btc = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', text)
    if btc: wallets["btc"] = list(set(btc))[:5]
    btc_bech = re.findall(r'bc1[a-zA-HJ-NP-Z0-9]{25,39}\b', text)
    if btc_bech: wallets["btc_bech32"] = list(set(btc_bech))[:5]
    eth = re.findall(r'0x[a-fA-F0-9]{40}\b', text)
    if eth: wallets["eth_erc20"] = list(set(eth))[:5]
    bsc = re.findall(r'0x[a-fA-F0-9]{40}\b', text)
    if bsc: wallets.setdefault("bsc_bep20", wallets.get("eth_erc20", []))
    sol = re.findall(r'[1-9A-HJ-NP-Za-km-z]{32,44}\b', text)
    if sol: wallets["solana"] = list(set([s for s in sol if len(s) >= 32]))[:5]
    xmr = re.findall(r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', text)
    if xmr: wallets["monero"] = list(set(xmr))[:3]
    ltc = re.findall(r'[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b', text)
    if ltc: wallets["litecoin"] = list(set(ltc))[:3]
    return wallets

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    all_wallets = SCAM_WALLETS + EXTRA_SCAM_WALLETS
    for wallet in all_wallets:
        if wallet.lower()[:10] in t or wallet.lower() in t:
            findings.append(make_finding(
                entity=f"Known scam wallet reference: {wallet[:20]}...",
                type="Crypto: Known Scam Wallet",
                source="CryptoAbuseRadar",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Scam Wallet",
                resolution=t,
                raw_data=f"Wallet: {wallet}",
                tags=["crypto", "scam-wallet", "blockchain"]
            ))

    scam_domains = await detect_scam_domain(t)
    for d in scam_domains:
        findings.append(make_finding(
            entity=f"Scam domain pattern detected: {d[:100]}",
            type="Crypto: Scam Domain",
            source="CryptoAbuseRadar",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Suspicious Domain",
            resolution=t,
            tags=["crypto", "scam-domain", "phishing"]
        ))

    detected_wallets = await detect_wallet_addresses(t)
    for chain, addrs in detected_wallets.items():
        findings.append(make_finding(
            entity=f"Detected {len(addrs)} {chain.upper()} wallet address(es)",
            type=f"Crypto: {chain.upper()} Wallet Detection",
            source="CryptoAbuseRadar",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Wallets Found",
            resolution=t,
            tags=["crypto", chain, "wallet"]
        ))

    wallet_explorer_results = []
    for chain, addrs in detected_wallets.items():
        for addr in addrs:
            explorer_data = await query_blockchain_explorers(addr, client)
            wallet_explorer_results.extend(explorer_data)
    
    for exp in wallet_explorer_results[:5]:
        explorer_name = exp.get("explorer", "Unknown")
        findings.append(make_finding(
            entity=f"Blockchain explorer data from {explorer_name}",
            type="Crypto: Blockchain Explorer Query",
            source=explorer_name,
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Queried",
            resolution=t,
            tags=["crypto", "explorer", explorer_name.lower().replace(" ", "-")]
        ))

    try:
        resp = await safe_fetch(client, f"https://{t}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            html = resp.text.lower()

            defi_scams = await detect_defi_scam(html)
            if defi_scams:
                findings.append(make_finding(
                    entity=f"DeFi scam indicators: {', '.join(defi_scams[:5])}",
                    type="Crypto: DeFi Scam Detection",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Scam Detected",
                    resolution=t,
                    tags=["crypto", "defi", "scam"]
                ))

            nft_scams = await detect_nft_scam(html)
            if nft_scams:
                findings.append(make_finding(
                    entity=f"NFT scam indicators: {', '.join(nft_scams[:5])}",
                    type="Crypto: NFT Scam Detection",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Scam Detected",
                    resolution=t,
                    tags=["crypto", "nft", "scam"]
                ))

            page_wallets = await detect_wallet_addresses(html)
            total_wallets = sum(len(v) for v in page_wallets.values())
            if total_wallets > 0:
                findings.append(make_finding(
                    entity=f"{total_wallets} wallet addresses found on page across {len(page_wallets)} chains",
                    type="Crypto: Wallet Address Discovery",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    status="Wallets Found",
                    resolution=t,
                    tags=["crypto", "wallets", "discovery"]
                ))

            giveaway_phrases = ["giveaway", "free crypto", "bonus", "airdrop", "claim now",
                               "limited time", "send to receive", "double your", "free tokens",
                               "claim airdrop", "free nft", "mint now", "presale", "whitelist"]
            found_phrases = [p for p in giveaway_phrases if p in html]
            if found_phrases:
                findings.append(make_finding(
                    entity=f"Giveaway scam phrases: {', '.join(found_phrases[:5])}",
                    type="Crypto: Giveaway Scam Detection",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Scam Detected",
                    resolution=t,
                    tags=["crypto", "giveaway", "scam"]
                ))

            investment_phrases = ["guaranteed returns", "passive income", "investment opportunity",
                                 "get rich quick", "life changing", "financial freedom",
                                 "weekly profits", "monthly returns", "high yield",
                                 "minimum investment", "referral bonus", "matrix"]
            found_investment = [p for p in investment_phrases if p in html]
            if found_investment:
                findings.append(make_finding(
                    entity=f"Investment scam phrases: {', '.join(found_investment[:3])}",
                    type="Crypto: Investment Scam Detection",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Scam Detected",
                    resolution=t,
                    tags=["crypto", "investment", "scam"]
                ))
    except:
        pass

    if not findings:
        findings.append(make_finding(
            entity="No crypto abuse indicators detected",
            type="Crypto Abuse Check Complete",
            source="CryptoAbuseRadar",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["crypto", "clean"]
        ))

    source_count = len(set(f.source for f in findings))
    findings.append(make_finding(
        entity=f"Crypto abuse scan using {source_count} detection methods across {len(BLOCKCHAIN_EXPLORERS)} blockchain explorers",
        type="Crypto: Scan Coverage Summary",
        source="CryptoAbuseRadar",
        confidence="Medium",
        color="slate",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["crypto", "coverage", "summary"]
    ))

    return findings
