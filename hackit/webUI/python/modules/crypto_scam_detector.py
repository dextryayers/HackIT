import httpx
import re
import json
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

SCAM_PATTERNS = {
    "Ponzi Scheme": [
        re.compile(r'ponzi|pyramid|get.?rich|guaranteed.?return|passive.?income', re.I),
        re.compile(r'referral.?bonus|multi.?level|mlm|matrix|downline', re.I),
        re.compile(r'high.?yield|hype|hyper.?return|impossible.?return', re.I),
        re.compile(r'risk.?free|no.?risk|guaranteed.?profit|sure.?thing', re.I),
    ],
    "Fake ICO/IDO": [
        re.compile(r'presale|private.?sale|whitelist.?sale|seed.?round', re.I),
        re.compile(r'ico|ido|ieo|ino|launchpad|initial.?offering', re.I),
        re.compile(r'soft.?cap|hard.?cap|raise.?fund|fundraising', re.I),
        re.compile(r'whitepaper|tokenomics|roadmap|liquidity.?lock', re.I),
    ],
    "Phishing dApp": [
        re.compile(r'connect.?wallet|approve.?transaction|sign.?message|verify.?wallet', re.I),
        re.compile(r'metamask.?connect|walletconnect|web3.?connect', re.I),
        re.compile(r'claim.?airdrop|claim.?reward|claim.?token|free.?token', re.I),
        re.compile(r'stake|staking|farm|yield.?farm|liquidity.?pool', re.I),
    ],
    "Fake Airdrop": [
        re.compile(r'airdrop|free.?coin|free.?token|giveaway|reward.?distribution', re.I),
        re.compile(r'claim\s+(your\s+)?(token|coin|nft|crypto)', re.I),
        re.compile(r'drop\s+(your\s+)?(address|wallet)', re.I),
    ],
    "Investment Scam": [
        re.compile(r'trading.?bot|auto.?trade|copy.?trade|signal.?group|VIP.?signal', re.I),
        re.compile(r'investment.?platform|crypto.?invest|invest.?now|capital.?growth', re.I),
        re.compile(r'managed.?account|fund.?management|wealth.?management', re.I),
        re.compile(r'deposit.?bonus|welcome.?bonus|match.?bonus|trading.?bonus', re.I),
    ],
    "Romance/Trust Scam": [
        re.compile(r'pig.?butchering|romance.?scam|trust.?scam|investment.?romance', re.I),
        re.compile(r'send.?me.?crypto|help.?me.?transfer|emergency.?funds', re.I),
    ],
    "Fake Mining": [
        re.compile(r'cloud.?mining|mining.?pool|mining.?contract|hash.?power', re.I),
        re.compile(r'mine.?crypto|bitcoin.?mining|eth.?mining|mining.?profit', re.I),
        re.compile(r'mining.?rig|asic|gpu.?mining|mining.?hosting', re.I),
    ],
}

SCAM_DATABASE_URLS = [
    "https://raw.githubusercontent.com/MrBlaise/Scam-Tokens/master/tokens.json",
    "https://raw.githubusercontent.com/The-Blockchain-Company/scam-database/master/scams.json",
    "https://raw.githubusercontent.com/ethereum-lists/chainlist/master/_tokens/scam.json",
]

async def check_scam_databases(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        for db_url in SCAM_DATABASE_URLS:
            try:
                resp = await safe_fetch(client, db_url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        results.append({"database": db_url.split("/")[-1].replace(".json", ""), "found": True})
            except:
                pass
    except:
        pass
    return results

async def detect_ponzi_patterns(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for scam_type, patterns in SCAM_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(target_lower)
                if match:
                    results.append({"scam_type": scam_type, "matched": match.group()})
                    break
    except:
        pass
    return results

async def check_fake_ico_patterns(target: str) -> list:
    results = []
    try:
        ico_keywords = [
            "presale", "whitelist", "seed round", "private sale",
            "launchpad", "initial dex offering", "initial coin offering",
            "soft cap", "hard cap", "token sale",
        ]
        target_lower = target.lower()
        for kw in ico_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "category": "fake_ico"})
    except:
        pass
    return results

async def check_fake_airdrop_patterns(target: str) -> list:
    results = []
    try:
        airdrop_keywords = [
            "free token", "free coin", "airdrop", "claim your",
            "reward distribution", "token giveaway", "nft giveaway",
            "free mint", "whitelist giveaway",
        ]
        target_lower = target.lower()
        for kw in airdrop_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "category": "fake_airdrop"})
    except:
        pass
    return results

async def check_investment_scam_patterns(target: str) -> list:
    results = []
    try:
        investment_keywords = [
            "guaranteed return", "passive income", "high yield",
            "risk free", "double your", "instant profit",
            "trading signal", "copy trade", "auto trade",
            "investment platform", "managed account",
        ]
        target_lower = target.lower()
        for kw in investment_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "category": "investment_scam"})
    except:
        pass
    return results

async def check_phishing_dapp_patterns(target: str) -> list:
    results = []
    try:
        dapp_keywords = [
            "connect wallet", "approve transaction", "sign message",
            "verify wallet", "claim reward", "stake now",
            "walletconnect", "web3 connect",
        ]
        target_lower = target.lower()
        for kw in dapp_keywords:
            if kw in target_lower:
                results.append({"keyword": kw, "category": "phishing_dapp"})
    except:
        pass
    return results

async def calculate_scam_risk_score(detections: list, db_hits: list) -> dict:
    try:
        score = 0
        unique_scam_types = len(set(d.get("scam_type", "") for d in detections))
        total_detections = len(detections)
        score += unique_scam_types * 15
        score += min(total_detections * 5, 30)
        if db_hits:
            score += 25
        score = min(score, 100)
        if score >= 70:
            level = "Critical - Confirmed Scam"
        elif score >= 40:
            level = "High Risk - Suspicious"
        elif score >= 15:
            level = "Elevated Risk"
        else:
            level = "Low Risk"
        return {"score": score, "level": level, "detections": total_detections, "types": unique_scam_types}
    except:
        return {"score": 0, "level": "Unknown", "detections": 0, "types": 0}

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    db_results = await check_scam_databases(client, query)
    for r in db_results:
        findings.append(make_finding(
            entity=f"Target found in scam database: {r['database']}",
            ftype="Scam Database Hit",
            source=r['database'],
            confidence="High",
            color="red",
            category="Cryptocurrency Scam Detection",
            threat_level="Critical",
            status="Confirmed Scam",
            resolution=query,
            tags=["scam", "database", r['database'].lower().replace("_", "-")]
        ))

    ponzi_results = await detect_ponzi_patterns(query)
    for r in ponzi_results:
        findings.append(make_finding(
            entity=f"Scam pattern detected: {r['scam_type']} (matched: {r['matched']})",
            type="Scam Pattern Detection",
            source="Scam Detector",
            confidence="Medium",
            color="red" if r['scam_type'] in ["Ponzi Scheme", "Romance/Trust Scam"] else "orange",
            category="Cryptocurrency Scam Detection",
            threat_level="High Risk" if r['scam_type'] in ["Ponzi Scheme", "Romance/Trust Scam"] else "Elevated Risk",
            status="Pattern Matched",
            resolution=query,
            tags=["scam", r['scam_type'].lower().replace("/", "-").replace(" ", "-")]
        ))

    ico_results = await check_fake_ico_patterns(query)
    for r in ico_results:
        findings.append(make_finding(
            entity=f"Fake ICO indicator: {r['keyword']}",
            ftype="Fake ICO Detection",
            source="Scam Detector",
            confidence="Medium",
            color="orange",
            category="Cryptocurrency Scam Detection",
            threat_level="Elevated Risk",
            status="ICO Indicator",
            resolution=query,
            tags=["scam", "fake-ico", r['keyword'].replace(" ", "-")]
        ))

    airdrop_results = await check_fake_airdrop_patterns(query)
    for r in airdrop_results:
        findings.append(make_finding(
            entity=f"Fake airdrop indicator: {r['keyword']}",
            ftype="Fake Airdrop Detection",
            source="Scam Detector",
            confidence="Medium",
            color="orange",
            category="Cryptocurrency Scam Detection",
            threat_level="Elevated Risk",
            status="Airdrop Scam Indicator",
            resolution=query,
            tags=["scam", "fake-airdrop", r['keyword'].replace(" ", "-")]
        ))

    investment_results = await check_investment_scam_patterns(query)
    for r in investment_results:
        findings.append(make_finding(
            entity=f"Investment scam indicator: {r['keyword']}",
            ftype="Investment Scam Detection",
            source="Scam Detector",
            confidence="Medium",
            color="orange",
            category="Cryptocurrency Scam Detection",
            threat_level="Elevated Risk",
            status="Investment Scam Indicator",
            resolution=query,
            tags=["scam", "investment-scam", r['keyword'].replace(" ", "-")]
        ))

    dapp_results = await check_phishing_dapp_patterns(query)
    for r in dapp_results:
        findings.append(make_finding(
            entity=f"Phishing dApp indicator: {r['keyword']}",
            ftype="Phishing dApp Detection",
            source="Scam Detector",
            confidence="High",
            color="red",
            category="Cryptocurrency Scam Detection",
            threat_level="High Risk",
            status="Phishing dApp",
            resolution=query,
            tags=["scam", "phishing-dapp", r['keyword'].replace(" ", "-")]
        ))

    all_detections = ponzi_results + ico_results + airdrop_results + investment_results + dapp_results
    risk_score = await calculate_scam_risk_score(all_detections, db_results)
    findings.append(make_finding(
        entity=f"Scam risk score: {risk_score['score']}/100 ({risk_score['level']}) - {risk_score['detections']} detections, {risk_score['types']} scam types",
        type="Scam Risk Assessment",
        source="Scam Detector",
        confidence="Medium",
        color="red" if risk_score['score'] >= 50 else "yellow",
        category="Cryptocurrency Scam Detection",
        threat_level=risk_score['level'],
        status=f"Score: {risk_score['score']}",
        resolution=query,
        raw_data=json.dumps(risk_score),
        tags=["scam", "risk-score", risk_score['level'].lower().replace(" ", "-").replace("-confirmed-scam", "")]
    ))

    for scam_type in SCAM_PATTERNS.keys():
        findings.append(make_finding(
            entity=f"Scam type monitored: {scam_type}",
            ftype="Scam Coverage",
            source="Scam Detector",
            confidence="Low",
            color="slate",
            category="Cryptocurrency Scam Detection",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["scam", "coverage", scam_type.lower().replace("/", "-").replace(" ", "-")]
        ))

    findings.append(make_finding(
        entity=f"Scam detection complete for {query}: checked {len(SCAM_PATTERNS)} scam types, {len(SCAM_DATABASE_URLS)} databases, {sum(len(v) for v in SCAM_PATTERNS.values())} patterns",
        type="Scam Detection Summary",
        source="Scam Detector",
        confidence="Medium",
        color="slate",
        category="Cryptocurrency Scam Detection",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["scam", "summary", "detection"]
    ))

    return findings
