import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

MIXING_SERVICES = {
    "Tornado Cash": ["tornado", "tornado.cash", "tornadocash", "tc", "0x", "torn"],
    "Wasabi Wallet": ["wasabi", "wasabiwallet", "wasabi-wallet", "ww"],
    "Samourai Wallet": ["samourai", "samouraiwallet", "samourai-wallet", "sw", "whirlpool"],
    "ChipMixer": ["chipmixer", "chip-mixer", "chipmix"],
    "Sinbad": ["sinbad", "sinbad.io", "sinbadmixer"],
    "Blender": ["blender", "blender.io", "blendermixer"],
    "YoMix": ["yomix", "yomix.io", "yomixer"],
    "FixedFloat": ["fixedfloat", "fixed-float"],
    "ChangeNOW": ["changenow", "change-now"],
    "SwapSpace": ["swapspace", "swap-space"],
    "StealthEx": ["stealthex", "stealth-ex"],
    "ChangeHero": ["changehero", "change-hero"],
    "Godex": ["godex", "godex.io"],
    "SideShift": ["sideshift", "side-shift"],
    "Exolix": ["exolix", "exolix.com"],
    "MEXC": ["mexc", "mexc.com"],
    "SimpleSwap": ["simpleswap", "simple-swap"],
}

PRIVACY_COINS = {
    "Monero": ["monero", "xmr", "monero (xmr)"],
    "Zcash": ["zcash", "zec", "zcash (zec)"],
    "Dash": ["dash", "dash (dash)"],
    "Horizen": ["horizen", "zen", "horizen (zen)"],
    "Secret": ["secret", "scrt", "secret (scrt)"],
    "Verge": ["verge", "xvg", "verge (xvg)"],
    "PIVX": ["pivx", "pivx (pivx)"],
    "Navcoin": ["navcoin", "nav", "navcoin (nav)"],
    "Firo": ["firo", "firo (firo)", "zcoin"],
    "Beam": ["beam", "beam (beam)"],
    "Grin": ["grin", "grin (grin)"],
}

COINJOIN_PATTERNS = [
    re.compile(r'coinjoin|coin.?join|whirlpool|zero.?link|payjoin', re.I),
    re.compile(r'chaumian|blind.?signature|anonymity.?set', re.I),
    re.compile(r'mix|tumbler|blender|cleaner|washer', re.I),
]

MIXER_CONTRACT_PATTERNS = [
    re.compile(r'0x[a-fA-F0-9]{40}'),
    re.compile(r'(deposit|withdraw|mix|torn|anonymize|clean)', re.I),
    re.compile(r'relayer|fee.?recipient|reward.?pool', re.I),
]

async def detect_mixing_service(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for service, indicators in MIXING_SERVICES.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"service": service, "matched": ind, "type": "mixing_service"})
                    break
    except:
        pass
    return results

async def detect_privacy_coin(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for coin, indicators in PRIVACY_COINS.items():
            for ind in indicators:
                if ind in target_lower:
                    results.append({"coin": coin, "matched": ind, "type": "privacy_coin"})
                    break
    except:
        pass
    return results

async def detect_coinjoin_patterns(target: str) -> list:
    results = []
    try:
        for pattern in COINJOIN_PATTERNS:
            match = pattern.search(target)
            if match:
                results.append({"pattern": str(pattern)[:60], "match": match.group()})
    except:
        pass
    return results

async def check_mixer_contracts(target: str) -> list:
    results = []
    try:
        known_mixer_contracts = [
            "0x722122dF12DBA9bF2C70E5E5397E3C7dC33E0e1",
            "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBa9D",
            "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
            "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",
        ]
        target_lower = target.lower()
        for contract in known_mixer_contracts:
            if contract.lower() in target_lower:
                results.append({"contract": contract, "type": "known_mixer"})
    except:
        pass
    return results

async def check_atomic_swap_patterns(target: str) -> list:
    results = []
    try:
        atomic_swap_keywords = [
            "atomic swap", "cross-chain", "cross chain",
            "htlc", "hash time lock", "swap contract",
        ]
        target_lower = target.lower()
        for kw in atomic_swap_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "type": "atomic_swap"})
    except:
        pass
    return results

async def calculate_mixer_risk_score(mixing: list, privacy: list, coinjoin: list, contracts: list) -> dict:
    try:
        score = 0
        score += len(mixing) * 15
        score += len(privacy) * 10
        score += len(coinjoin) * 20
        score += len(contracts) * 25
        score = min(score, 100)
        if score >= 70:
            level = "Critical - Heavy Mixing"
        elif score >= 40:
            level = "High Risk - Mixing Likely"
        elif score >= 15:
            level = "Elevated Risk - Possible Mixing"
        else:
            level = "Low Risk"
        return {"score": score, "level": level}
    except:
        return {"score": 0, "level": "Unknown"}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    mixing_results = await detect_mixing_service(query)
    for r in mixing_results:
        findings.append(IntelligenceFinding(
            entity=f"Mixing service detected: {r['service']} (matched: {r['matched']})",
            type="Mixing Service Detection",
            source="Mixer Detector",
            confidence="High",
            color="red",
            category="Cryptocurrency Mixing",
            threat_level="High Risk",
            status="Mixer Identified",
            resolution=query,
            tags=["mixing", "mixer", r['service'].lower().replace(" ", "-").replace(".", "-")]
        ))

    privacy_coin_results = await detect_privacy_coin(query)
    for r in privacy_coin_results:
        findings.append(IntelligenceFinding(
            entity=f"Privacy coin detected: {r['coin']} (matched: {r['matched']})",
            type="Privacy Coin Detection",
            source="Mixer Detector",
            confidence="Medium",
            color="yellow",
            category="Cryptocurrency Mixing",
            threat_level="Elevated Risk",
            status="Privacy Coin Found",
            resolution=query,
            tags=["privacy-coin", r['coin'].lower().replace(" ", "-")]
        ))

    coinjoin_results = await detect_coinjoin_patterns(query)
    for r in coinjoin_results:
        findings.append(IntelligenceFinding(
            entity=f"Coinjoin pattern: {r['match']}",
            type="Coinjoin Detection",
            source="Mixer Detector",
            confidence="Medium",
            color="orange",
            category="Cryptocurrency Mixing",
            threat_level="Elevated Risk",
            status="Coinjoin Pattern",
            resolution=query,
            tags=["mixing", "coinjoin", r['match'].lower().replace(" ", "-")]
        ))

    contract_results = await check_mixer_contracts(query)
    for r in contract_results:
        findings.append(IntelligenceFinding(
            entity=f"Known mixer contract: {r['contract'][:16]}...",
            type="Mixer Contract Detection",
            source="Mixer Detector",
            confidence="High",
            color="red",
            category="Cryptocurrency Mixing",
            threat_level="Critical",
            status="Mixer Contract",
            resolution=query,
            tags=["mixing", "contract", "known-mixer"]
        ))

    atomic_swap_results = await check_atomic_swap_patterns(query)
    for r in atomic_swap_results:
        findings.append(IntelligenceFinding(
            entity=f"Atomic swap pattern: {r['keyword']}",
            type="Atomic Swap Detection",
            source="Mixer Detector",
            confidence="Low",
            color="yellow",
            category="Cryptocurrency Mixing",
            threat_level="Elevated Risk",
            status="Atomic Swap Pattern",
            resolution=query,
            tags=["mixing", "atomic-swap", r['keyword'].replace(" ", "-")]
        ))

    for service in MIXING_SERVICES:
        findings.append(IntelligenceFinding(
            entity=f"Mixing service monitored: {service}",
            type="Mixing Service Coverage",
            source="Mixer Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Mixing",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["mixing", "coverage", service.lower().replace(" ", "-").replace(".", "-")]
        ))

    for coin in PRIVACY_COINS:
        findings.append(IntelligenceFinding(
            entity=f"Privacy coin monitored: {coin}",
            type="Privacy Coin Coverage",
            source="Mixer Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Mixing",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["privacy-coin", "coverage", coin.lower().replace(" ", "-")]
        ))

    risk = await calculate_mixer_risk_score(mixing_results, privacy_coin_results, coinjoin_results, contract_results)
    findings.append(IntelligenceFinding(
        entity=f"Mixer risk score: {risk['score']}/100 ({risk['level']})",
        type="Mixing Risk Assessment",
        source="Mixer Detector",
        confidence="Medium",
        color="red" if risk['score'] >= 50 else "yellow",
        category="Cryptocurrency Mixing",
        threat_level=risk['level'],
        status=f"Score: {risk['score']}",
        resolution=query,
        raw_data=json.dumps(risk),
        tags=["mixing", "risk-score", risk['level'].lower().replace(" ", "-").replace("-heavy-mixing", "")]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Mixer detection complete for {query}: checked {len(MIXING_SERVICES)} services, {len(PRIVACY_COINS)} privacy coins, {len(COINJOIN_PATTERNS)} coinjoin patterns",
        type="Mixer Detection Summary",
        source="Mixer Detector",
        confidence="Medium",
        color="slate",
        category="Cryptocurrency Mixing",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["mixing", "summary", "detection"]
    ))

    return findings
