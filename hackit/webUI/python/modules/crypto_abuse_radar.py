import httpx
import asyncio
import re
import json
from datetime import datetime
from typing import List
from collections import defaultdict
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

SCAM_DOMAIN_PATTERNS = [
    r'crypt(?:o)?(?:free|give|bonus|airdrop|mining|invest|wallet|trade|earn|club)',
    r'(?:free|give|bonus|airdrop|mining|invest|earn)crypt(?:o)?',
    r'(?:eth|btc|bitcoin|ethereum|bnb|sol)(?:free|give|bonus|airdrop|mining|invest|earn)',
    r'(?:elon|musk|celebrity|giveaway)[\s.-]*crypto',
    r'(?:nft|defi|metaverse)(?:free|give|bonus|airdrop)',
]

DEFI_SCAM_INDICATORS = [
    "rug pull", "rugpull", "honeypot", "flash loan attack",
    "price manipulation", "slippage attack", "impermanent loss",
    "liquidity drain", "approve all", "unlimited approval",
    "malicious contract", "backdoor", "hidden mint", "proxy contract",
    "upgradeable", "malicious owner", "renounce ownership",
]

NFT_SCAM_INDICATORS = [
    "phishing link", "malicious mint", "fake mint", "copycat",
    "impersonation", "social engineering", "discord phishing",
    "twitter impersonation", "fake collection", "spoofed url",
]

SOCIAL_ENGINEERING_DOMAINS = [
    "opensea", "rarible", "looksrare", "x2y2", "sudoswap",
    "uniswap", "pancakeswap", "traderjoe", "quickswap",
    "metamask", "trustwallet", "rainbow", "argent",
    "coinbase", "binance", "kraken", "ftx", "crypto.com",
    "etherscan", "bscscan", "polygonscan", "debank", "zapper",
    "collab.land", "guild.xyz", "snapshot.org",
]

async def detect_defi_scam(text: str) -> list:
    findings = []
    text_lower = text.lower()
    for indicator in DEFI_SCAM_INDICATORS:
        if indicator in text_lower:
            findings.append(indicator)
    return findings

async def detect_nft_scam(text: str) -> list:
    findings = []
    text_lower = text.lower()
    for indicator in NFT_SCAM_INDICATORS:
        if indicator in text_lower:
            findings.append(indicator)
    return findings

async def detect_scam_domain(domain: str) -> list:
    findings = []
    domain_lower = domain.lower()
    for pattern in SCAM_DOMAIN_PATTERNS:
        if re.search(pattern, domain_lower, re.IGNORECASE):
            findings.append(pattern)
    for se_domain in SOCIAL_ENGINEERING_DOMAINS:
        if se_domain.lower() in domain_lower:
            findings.append(f"Social engineering: {se_domain}")
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    for wallet in SCAM_WALLETS:
        if wallet.lower()[:10] in t or wallet.lower() in t:
            findings.append(IntelligenceFinding(
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
        findings.append(IntelligenceFinding(
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

    try:
        resp = await client.get(f"https://{t}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            html = resp.text.lower()

            defi_scams = await detect_defi_scam(html)
            if defi_scams:
                findings.append(IntelligenceFinding(
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
                findings.append(IntelligenceFinding(
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

            wallet_addresses = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', html)
            bech32_addresses = re.findall(r'bc1[a-zA-HJ-NP-Z0-9]{25,39}\b', html)
            eth_addresses = re.findall(r'0x[a-fA-F0-9]{40}\b', html)
            all_wallets = wallet_addresses + bech32_addresses + eth_addresses
            if all_wallets:
                findings.append(IntelligenceFinding(
                    entity=f"{len(set(all_wallets))} wallet addresses found on page",
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
                               "limited time", "send to receive", "double your"]
            found_phrases = [p for p in giveaway_phrases if p in html]
            if found_phrases:
                findings.append(IntelligenceFinding(
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
    except:
        pass

    if not findings:
        findings.append(IntelligenceFinding(
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

    return findings
