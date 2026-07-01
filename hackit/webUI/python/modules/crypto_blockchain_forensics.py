import httpx
import re
import json
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

TRANSACTION_PATTERNS = {
    "high_velocity": re.compile(r'multi(ple)?\s*(tx|transaction|send|transfer)', re.I),
    "large_amount": re.compile(r'\b\d{6,}\s*(btc|eth|usd|xmr|usdt)\b', re.I),
    "round_numbers": re.compile(r'\b(100|1000|10000|100000|1000000)\s*(btc|eth|usdt|xmr)\b', re.I),
    "frequent_small": re.compile(r'micro.?transact|dust|small.?amount|tiny.?tx', re.I),
}

CLUSTER_PATTERNS = {
    "exchange_cluster": re.compile(r'binance|coinbase|kraken|exchange|cex', re.I),
    "mixer_cluster": re.compile(r'tornado|washer|mixer|tumbler|coinjoin', re.I),
    "darknet_cluster": re.compile(r'hansa|alphabay|hydra|darknet|silk.?road', re.I),
    "defi_cluster": re.compile(r'uniswap|pancake|sushi|curve|balancer', re.I),
    "bridge_cluster": re.compile(r'bridge|wormhole|axelar|layerzero|multichain', re.I),
    "gambling_cluster": re.compile(r'casino|betting|poker|slot|gambling', re.I),
}

DUSTING_PATTERNS = [
    re.compile(r'dust(ing)?\s*(attack|transaction|send|transfer)', re.I),
    re.compile(r'0\.000[0-9a-fA-F]+|1\s*satoshi|tiny\s*amount', re.I),
    re.compile(r'de.?anonymiz|deanonymize|cluster.?track', re.I),
]

PROTOCOL_IDENTIFIERS = {
    "ERC20": re.compile(r'0x[a-fA-F0-9]{40}'),
    "ERC721": re.compile(r'0x[a-fA-F0-9]{40}'),
    "BEP20": re.compile(r'0x[a-fA-F0-9]{40}'),
    "SPL": re.compile(r'[1-9A-HJ-NP-Za-km-z]{32,44}'),
    "BRC20": re.compile(r'[a-zA-Z0-9]{4,12}'),
}

async def analyze_transaction_velocity(target: str) -> list:
    results = []
    try:
        for vel_type, pattern in TRANSACTION_PATTERNS.items():
            if pattern.search(target):
                results.append({"type": vel_type, "matched": True})
    except:
        pass
    return results

async def cluster_analysis(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for cluster_type, pattern in CLUSTER_PATTERNS.items():
            if pattern.search(target_lower):
                results.append({"cluster_type": cluster_type.replace("_cluster", ""), "matched": True})
    except:
        pass
    return results

async def detect_dusting(target: str) -> list:
    results = []
    try:
        for pattern in DUSTING_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:60]})
    except:
        pass
    return results

async def identify_protocol_usage(target: str) -> list:
    results = []
    try:
        for protocol, pattern in PROTOCOL_IDENTIFIERS.items():
            matches = pattern.findall(target)
            if matches:
                results.append({"protocol": protocol, "count": len(set(matches)), "samples": list(set(matches))[:3]})
    except:
        pass
    return results

async def analyze_counterparties(target: str) -> list:
    results = []
    try:
        address_pattern = re.compile(r'(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})')
        addresses = address_pattern.findall(target)
        for addr in set(addresses):
            results.append({"address": addr[:16] + "...", "role": "counterparty"})
    except:
        pass
    return results

async def timeline_reconstruction(target: str) -> list:
    results = []
    try:
        date_patterns = [
            re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'),
            re.compile(r'\d{4}-\d{2}-\d{2}'),
            re.compile(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2},?\s+\d{4}', re.I),
        ]
        for pattern in date_patterns:
            dates = pattern.findall(target)
            for d in set(dates):
                results.append({"date": d, "source": "extracted"})
        if results:
            results = sorted(results, key=lambda x: x["date"])[:10]
    except:
        pass
    return results

async def calculate_forensic_risk(clusters: list, dusting: list, velocity: list) -> dict:
    try:
        score = 0
        cluster_risk = {"darknet": 30, "mixer": 25, "gambling": 15, "bridge": 10, "defi": 5, "exchange": 0}
        for c in clusters:
            ct = c.get("cluster_type", "")
            score += cluster_risk.get(ct, 5)
        score += len(dusting) * 15
        score += len(velocity) * 5
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

    velocity_results = await analyze_transaction_velocity(query)
    for r in velocity_results:
        findings.append(IntelligenceFinding(
            entity=f"Transaction velocity pattern: {r['type']}",
            type="Transaction Velocity Analysis",
            source="Blockchain Forensics",
            confidence="Low",
            color="yellow",
            category="Blockchain Forensics",
            threat_level="Elevated Risk",
            status="Pattern Detected",
            resolution=query,
            tags=["forensics", "velocity", r['type'].replace("_", "-")]
        ))

    cluster_results = await cluster_analysis(query)
    for r in cluster_results:
        color_map = {"darknet": "red", "mixer": "red", "gambling": "orange", "bridge": "yellow", "defi": "slate", "exchange": "slate"}
        findings.append(IntelligenceFinding(
            entity=f"Behavior cluster: {r['cluster_type']}",
            type="Cluster Analysis",
            source="Blockchain Forensics",
            confidence="Medium",
            color=color_map.get(r['cluster_type'], "yellow"),
            category="Blockchain Forensics",
            threat_level="Critical" if r['cluster_type'] in ["darknet", "mixer"] else "Elevated Risk",
            status="Cluster Identified",
            resolution=query,
            tags=["forensics", "cluster", r['cluster_type']]
        ))

    dusting_results = await detect_dusting(query)
    for r in dusting_results:
        findings.append(IntelligenceFinding(
            entity=f"Dusting attack pattern detected: {r['pattern'][:50]}...",
            type="Dusting Attack Detection",
            source="Blockchain Forensics",
            confidence="Medium",
            color="orange",
            category="Blockchain Forensics",
            threat_level="High Risk",
            status="Dusting Detected",
            resolution=query,
            tags=["forensics", "dusting", "deanonymization"]
        ))

    protocol_results = await identify_protocol_usage(query)
    for r in protocol_results:
        findings.append(IntelligenceFinding(
            entity=f"Protocol usage: {r['protocol']} ({r['count']} instances)",
            type="Protocol Identification",
            source="Blockchain Forensics",
            confidence="Medium",
            color="slate",
            category="Blockchain Forensics",
            threat_level="Informational",
            status="Protocol Identified",
            resolution=query,
            tags=["forensics", "protocol", r['protocol'].lower()]
        ))

    counterparty_results = await analyze_counterparties(query)
    for r in counterparty_results[:10]:
        findings.append(IntelligenceFinding(
            entity=f"Transaction counterparty: {r['address']} ({r['role']})",
            type="Counterparty Analysis",
            source="Blockchain Forensics",
            confidence="Low",
            color="slate",
            category="Blockchain Forensics",
            threat_level="Informational",
            status="Counterparty Found",
            resolution=query,
            tags=["forensics", "counterparty", "address"]
        ))

    timeline_results = await timeline_reconstruction(query)
    for r in timeline_results:
        findings.append(IntelligenceFinding(
            entity=f"Transaction timeline: {r['date']}",
            type="Timeline Reconstruction",
            source="Blockchain Forensics",
            confidence="Low",
            color="slate",
            category="Blockchain Forensics",
            threat_level="Informational",
            status="Date Extracted",
            resolution=query,
            tags=["forensics", "timeline", r['date'][:10] if len(r['date']) > 10 else r['date']]
        ))

    risk = await calculate_forensic_risk(cluster_results, dusting_results, velocity_results)
    findings.append(IntelligenceFinding(
        entity=f"Forensic risk score: {risk['score']}/100 ({risk['level']})",
        type="Forensic Risk Score",
        source="Blockchain Forensics",
        confidence="Medium",
        color="red" if risk['score'] >= 50 else "yellow",
        category="Blockchain Forensics",
        threat_level=risk['level'],
        status=f"Score: {risk['score']}",
        resolution=query,
        raw_data=json.dumps(risk),
        tags=["forensics", "risk-score", risk['level'].lower().replace(" ", "-")]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Blockchain forensics complete for {query[:32]}: analyzed velocity, clusters, dusting, protocols, counterparties, timeline",
        type="Blockchain Forensics Summary",
        source="Blockchain Forensics",
        confidence="Medium",
        color="slate",
        category="Blockchain Forensics",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["forensics", "blockchain", "summary"]
    ))

    return findings
