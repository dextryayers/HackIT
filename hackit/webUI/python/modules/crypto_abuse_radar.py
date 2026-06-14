import httpx
import asyncio
import re
from models import IntelligenceFinding

CRYPTO_JACKING_PATTERNS = [
    r"coinhive", r"coin-hive", r"coin_?hive",
    r"cryptoloot", r"crypto-?loot",
    r"miner\.?", r"cryptonight", r"crypta",
    r"webmine", r"web-?mine", r"miner_?stat",
    r"jquery\.minernice", r"jquery\.miner",
    r"g2\.miner", r"p\.miner",
    r"miner\.minero", r"minecrunch",
    r"mine\.mine", r"miner_",
    r"coinimp", r"coin-imp",
    r"reased", r"reasedopera",
    r"deepminer", r"deeppool",
    r"monerominer", r"monero-?miner",
    r"xmr", r"monero",
    r"cryptobit", r"crypto-?bit",
    r"altminer", r"alt-?miner",
    r"minepool", r"mine-?pool",
    r"hashpools", r"hash-?pool",
    r"fcn", r"fpga", r"asic",
]

CRYPTO_WALLET_PATTERNS = {
    "btc": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "eth": r"\b0x[a-fA-F0-9]{40}\b",
    "xmr": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    "ltc": r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    "xrp": r"\br[1-9A-HJ-NP-Za-km-z]{25,34}\b",
    "doge": r"\bD[5-9][1-9A-HJ-NP-Za-km-z]{25,33}\b",
    "ada": r"\b[A-Za-z0-9]{50,}\b",
    "dot": r"\b1[1-9A-HJ-NP-Za-km-z]{47,}\b",
    "sol": r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b",
    "bnb": r"\b0x[a-fA-F0-9]{40}\b",
    "matic": r"\b0x[a-fA-F0-9]{40}\b",
    "usdt": r"\b0x[a-fA-F0-9]{40}\b",
}

KNOWN_SCAM_WALLETS = {
    "btc": [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "1L12q1L9q9MmL3q1L9q9MmL3q1L9q9Mm",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    ],
    "eth": [
        "0x0000000000000000000000000000000000000000",
        "0x1111111111111111111111111111111111111111",
    ],
}

KNOWN_SCAM_DOMAIN_PATTERNS = [
    r"(scam|fraud|phish|hack|fake|cheat|steal|ponzi|pyramid|mlm)",
    r"(doubler|multiplier|investment|high.?yield|hype)",
    r"(free.?btc|free.?eth|free.?crypto|giveaway)",
    r"(mining.?pool|cloud.?mining|mining.?cloud)",
    r"(bitcoin.?era|bitcoin.?revolution|crypto.?revolution)",
    r"(elon.?giveaway|musk.?giveaway|crypto.?giveaway)",
    r"(exchange|swap|trade|wallet|bridge).?(scam|hack|phish)",
]

CRYPTO_SCAM_API = "https://raw.githubusercontent.com"
CRYPTO_SCAM_DB_URL = "https://raw.githubusercontent.com/bitcoin/bitcoin/master/contrib/macdepy/README.md"

DNSBL_CRYPTO_DOMAINS = [
    "crypto", "blockchain", "bitcoin", "ethereum", "nft",
    "wallet", "mining", "coin", "token", "defi", "dao",
    "web3", "exchange", "swap", "bridge", "pool",
]

BLOCKCHAIN_EXPLORERS = {
    "blockchain.com": "Blockchain.com Explorer",
    "blockchair.com": "Blockchair",
    "etherscan.io": "Etherscan",
    "bscscan.com": "BscScan",
    "polygonscan.com": "PolygonScan",
    "snowtrace.io": "SnowTrace (Avalanche)",
    "solscan.io": "SolScan",
    "solana.fm": "Solana FM",
    "explorer.solana.com": "Solana Explorer",
    "tronscan.org": "Tronscan",
    "nearblocks.io": "NearBlocks",
    "xrpscan.com": "XRPScan",
    "adaex.org": "ADAEX",
    "cardanoscan.io": "CardanoScan",
    "atomscan.com": "AtomScan",
    "ping.pub": "Ping.pub",
    "mintscan.io": "MintScan",
    "bigdipper.live": "BigDipper",
    "explorer.chain.com": "Chain.com",
    "celoscan.io": "CeloScan",
    "ftmscan.com": "FTMScan",
    "arbiscan.io": "ArbiScan",
    "optimistic.etherscan.io": "Optimism Explorer",
}

MINING_POOL_PATTERNS = [
    r"mining.?pool", r"pool.?mining", r"miningpool",
    r"stratum", r"stratum\+tcp", r"stratum\+ssl",
    r"getwork", r"getblocktemplate", r"submitblock",
    r"nicehash", r"ethermine", r"f2pool", r"poolin",
    r"antpool", r"viabtc", r"slushpool", r"btc\.com",
    r"hiveon", r"2miners", r"flexpool", r"nanopool",
]

CRYPTO_JS_MINER_URLS = [
    "/hive.js", "/hive.min.js",
    "/coinhive.min.js",
    "/crypta.js", "/crypta.min.js",
    "/miner.js", "/miner.min.js",
    "/xmr.js", "/monero.js",
    "/webminer.js",
    "/deepminer.js",
    "/cryptonight.js",
    "/cryptonight.wasm",
    "/minero.js",
    "/coinimp.js",
    "/reased.js",
]


async def _check_html_for_crypto_jacking(html: str, url: str) -> list:
    findings = []
    html_lower = html.lower()

    for pattern in CRYPTO_JACKING_PATTERNS:
        if re.search(pattern, html_lower):
            findings.append(IntelligenceFinding(
                entity=f"Crypto-jacking script detected: {pattern}",
                type="Crypto-jacking",
                source="CryptoAbuseRadar",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Detected",
                resolution=url[:200],
                raw_data=f"Pattern '{pattern}' matched in HTML at {url}",
                tags=["crypto", "malware", "cryptojacking"]
            ))
            break

    for script_src in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html_lower):
        script_lower = script_src.lower()
        for miner_url in CRYPTO_JS_MINER_URLS:
            if miner_url in script_lower or miner_url in script_src:
                findings.append(IntelligenceFinding(
                    entity=f"Miner script: {script_src}",
                    type="Crypto-jacking Script",
                    source="CryptoAbuseRadar",
                    confidence="High",
                    color="red",
                    threat_level="Critical",
                    status="Confirmed",
                    resolution=url[:200],
                    raw_data=f"Script source: {script_src}",
                    tags=["crypto", "malware", "cryptojacking", "confirmed"]
                ))
                break

    for pattern in CRYPTO_JS_MINER_URLS:
        if pattern in html_lower:
            findings.append(IntelligenceFinding(
                entity=f"Known miner JS file: {pattern}",
                type="Crypto-jacking File",
                source="CryptoAbuseRadar",
                confidence="High",
                color="red",
                threat_level="Critical",
                status="Confirmed",
                raw_data=f"Miner file referenced in HTML: {pattern}",
                tags=["crypto", "malware", "cryptojacking"]
            ))

    return findings


async def _check_wallets_in_html(html: str, url: str) -> list:
    findings = []
    for currency, pattern in CRYPTO_WALLET_PATTERNS.items():
        matches = re.findall(pattern, html)
        seen = set()
        for match in matches[:5]:
            if match not in seen:
                seen.add(match)
                is_scam = match in KNOWN_SCAM_WALLETS.get(currency, [])
                risk = "Elevated Risk" if is_scam else "Standard Target"
                color = "red" if is_scam else "orange"
                tags = ["crypto", "wallet", currency]
                if is_scam:
                    tags.append("known-scam")
                    risk = "High Risk"
                    color = "red"

                findings.append(IntelligenceFinding(
                    entity=f"{currency.upper()} wallet: {match[:40]}...",
                    type="Cryptocurrency Wallet",
                    source="CryptoAbuseRadar",
                    confidence="High" if is_scam else "Medium",
                    color=color,
                    threat_level=risk,
                    status="Known Scam" if is_scam else "Detected",
                    raw_data=f"{currency.upper()} wallet: {match} found at {url}",
                    tags=tags
                ))
    return findings


async def _check_mining_pool_pages(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    pool_paths = ["/pool", "/pool/list", "/stats", "/mining", "/miner", "/stratum"]

    for path in pool_paths:
        try:
            resp = await client.get(f"{base}{path}", timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                body = resp.text.lower()
                for pattern in MINING_POOL_PATTERNS:
                    if re.search(pattern, body):
                        findings.append(IntelligenceFinding(
                            entity=f"Mining pool indicator at {path}: {pattern}",
                            type="Cryptocurrency Mining",
                            source="CryptoAbuseRadar",
                            confidence="Medium",
                            color="red",
                            threat_level="Elevated Risk",
                            status="Suspected",
                            raw_data=f"Pattern '{pattern}' found at {base}{path}",
                            tags=["crypto", "mining", "pool"]
                        ))
                        break
        except Exception:
            continue
    return findings


async def _check_dns_crypto(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        import dns.resolver

        for record_type in ['TXT', 'CNAME', 'NS']:
            try:
                answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, record_type))
                for r in answers:
                    text = str(r).lower()
                    for kw in DNSBL_CRYPTO_DOMAINS:
                        if kw in text:
                            findings.append(IntelligenceFinding(
                                entity=f"{record_type} record mentions '{kw}'",
                                type="Crypto-related DNS",
                                source="CryptoAbuseRadar",
                                confidence="Medium",
                                color="orange",
                                threat_level="Standard Target",
                                status="Detected",
                                resolution=str(r)[:200],
                                raw_data=f"DNS {record_type}: {text[:500]}",
                                tags=["crypto", "dns", kw]
                            ))
                            break
            except Exception:
                continue

        crypto_subdomains = [
            "wallet", "mining", "pool", "crypto", "bitcoin",
            "ethereum", "token", "swap", "exchange", "bridge",
            "stake", "defi", "nft", "dao", "coin",
        ]
        for sub in crypto_subdomains:
            try:
                fqdn = f"{sub}.{target}"
                await loop.run_in_executor(None, lambda: dns.resolver.resolve(fqdn, 'A'))
                findings.append(IntelligenceFinding(
                    entity=f"{fqdn} resolves",
                    type="Crypto-related Subdomain",
                    source="CryptoAbuseRadar",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Active",
                    raw_data=f"Subdomain {fqdn} resolves to an IP",
                    tags=["crypto", "subdomain", sub]
                ))
            except Exception:
                continue

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    base = f"https://{target}"
    html = ""

    try:
        resp = await client.get(base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            html = resp.text[:200000] if hasattr(resp, 'text') else ""

            jacking_findings = await _check_html_for_crypto_jacking(html, base)
            findings.extend(jacking_findings)

            wallet_findings = await _check_wallets_in_html(html, base)
            findings.extend(wallet_findings)

            scam_domains_found = []
            for scam_pattern in KNOWN_SCAM_DOMAIN_PATTERNS:
                if re.search(scam_pattern, target):
                    scam_domains_found.append(scam_pattern)
            if scam_domains_found:
                findings.append(IntelligenceFinding(
                    entity=f"Domain matches scam patterns",
                    type="Suspicious Domain Pattern",
                    source="CryptoAbuseRadar",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Suspicious",
                    raw_data=f"Domain '{target}' matches: {', '.join(scam_domains_found)}",
                    tags=["crypto", "scam", "phishing"]
                ))

        elif resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            for explorer_name, explorer_label in BLOCKCHAIN_EXPLORERS.items():
                if explorer_name in location.lower():
                    findings.append(IntelligenceFinding(
                        entity=explorer_label,
                        type="Blockchain Explorer Redirect",
                        source="CryptoAbuseRadar",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Redirect",
                        resolution=location[:200],
                        raw_data=f"Redirect to blockchain explorer: {location}",
                        tags=["crypto", "blockchain", "explorer"]
                    ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"HTTP error: {str(e)[:100]}",
            type="CryptoAbuseRadar Error",
            source="CryptoAbuseRadar",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))

    pool_findings = await _check_mining_pool_pages(target, client)
    findings.extend(pool_findings)

    dns_findings = await _check_dns_crypto(target, client)
    findings.extend(dns_findings)

    crypto_count = sum(1 for f in findings if "Crypto" in f.type or "crypto" in str(f.tags))
    wallet_count = sum(1 for f in findings if f.type == "Cryptocurrency Wallet")
    jacking_count = sum(1 for f in findings if "Crypto-jacking" in f.type or "Crypto-jacking" in f.source)
    scam_count = sum(1 for f in findings if f.threat_level == "High Risk" or f.threat_level == "Critical")

    if crypto_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"Crypto Abuse Scan: {wallet_count} wallets, {jacking_count} jacking, {scam_count} high-risk",
            type="Crypto Abuse Summary",
            source="CryptoAbuseRadar",
            confidence="Medium",
            color="red" if scam_count > 0 else ("orange" if wallet_count > 0 else "slate"),
            threat_level="High Risk" if scam_count > 0 else ("Elevated Risk" if jacking_count > 0 else "Standard Target"),
            status="Complete",
            resolution=f"{len(findings)} total findings",
            raw_data=f"Wallets: {wallet_count}, Jacking: {jacking_count}, Scam patterns: {scam_count}",
            tags=["crypto", "summary", "abuse"]
        ))

    return findings
