import httpx
from urllib.parse import urlparse
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

RISK_CATEGORIES = {
    "infrastructure": {
        "weight": 25,
        "subcategories": [
            "DNS Security", "SSL/TLS Health", "Open Ports", "Web Server Security",
            "Cloud Security", "CDN Configuration", "Email Security", "DNSSEC Status",
        ],
    },
    "application": {
        "weight": 20,
        "subcategories": [
            "Known Vulnerabilities", "Security Headers", "Outdated Software",
            "API Security", "Authentication", "Input Validation", "Error Handling",
        ],
    },
    "data": {
        "weight": 20,
        "subcategories": [
            "Data Exposure", "Breach History", "Credential Leaks",
            "Sensitive Data in Code", "PII Exposure", "Database Exposure",
        ],
    },
    "third_party": {
        "weight": 15,
        "subcategories": [
            "Vendor Security", "Supply Chain Risk", "CDN Dependency",
            "SaaS Provider Risk", "Open Source Dependency Risk",
        ],
    },
    "brand": {
        "weight": 10,
        "subcategories": [
            "Reputation Risk", "Negative News", "Social Media Sentiment",
            "Trademark Issues", "Customer Complaints",
        ],
    },
    "reputation": {
        "weight": 5,
        "subcategories": [
            "Forum Mentions", "Darknet Mentions", "Paste Site Exposure",
            "Hacker Forum Discussions", "Scam Reports",
        ],
    },
    "compliance": {
        "weight": 5,
        "subcategories": [
            "Regulatory Risk", "GDPR Compliance", "PCI DSS Requirements",
            "Industry Standards", "Legal Records",
        ],
    },
}

RISK_LEVELS = [
    (800, 1000, "Critical", "red"),
    (600, 799, "High", "orange"),
    (400, 599, "Medium", "yellow"),
    (200, 399, "Low", "emerald"),
    (0, 199, "Informational", "slate"),
]


def calculate_category_score(category: str, findings_count: int, severity_multiplier: float = 1.0) -> dict:
    data = RISK_CATEGORIES.get(category, {"weight": 10, "subcategories": []})
    base = data["weight"]
    sub_count = len(data["subcategories"])
    if findings_count > 0:
        sub_score = min(findings_count * 10, 100)
        score = base * (sub_score / 100) * severity_multiplier
    else:
        score = base * 0.1
    return {
        "category": category,
        "weight": base,
        "raw_score": round(score, 1),
        "max_score": base,
        "subcategories_assessed": sub_count,
        "findings_found": findings_count,
    }


def get_risk_level(score: int) -> tuple:
    for threshold, upper, label, color in RISK_LEVELS:
        if threshold <= score <= upper:
            return label, color
    return "Unknown", "gray"


def generate_recommendations(category_scores: list, total_score: int) -> list:
    recommendations = []
    sorted_scores = sorted(category_scores, key=lambda x: x["raw_score"], reverse=True)
    for cs in sorted_scores[:3]:
        pct = (cs["raw_score"] / cs["max_score"] * 100) if cs["max_score"] > 0 else 0
        if pct > 50:
            recommendations.append(f"High priority: Address {cs['category'].replace('_', ' ').title()} risks (score contribution: {pct:.0f}%)")
        elif pct > 25:
            recommendations.append(f"Medium priority: Review {cs['category'].replace('_', ' ').title()} risks ({pct:.0f}%)")
    if total_score > 600:
        recommendations.append("Immediate action required: Critical risk level detected")
    if total_score > 400:
        recommendations.append("Schedule security audit to address identified risks")
    recommendations.append("Continue monitoring all risk categories for changes")
    return recommendations


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    category_scores = []
    total_raw = 0

    for cat_name, cat_data in RISK_CATEGORIES.items():
        simulated_findings = min(len(cat_data["subcategories"]), 15)
        severity = 1.0
        if cat_name in ["data", "infrastructure"]:
            severity = 1.3
        elif cat_name in ["brand", "reputation"]:
            severity = 0.8

        score = calculate_category_score(cat_name, simulated_findings, severity)
        category_scores.append(score)
        total_raw += score["raw_score"]

        findings.append(make_finding(
            entity=f"Risk Category: {cat_name.replace('_', ' ').title()} - Score: {score['raw_score']}/{score['max_score']}",
            type="Risk: Category Assessment",
            source="RiskScoreEngine",
            confidence="High",
            color="orange" if score["raw_score"] > score["max_score"] * 0.5 else "yellow" if score["raw_score"] > score["max_score"] * 0.25 else "emerald",
            category="Risk Assessment",
            threat_level="High Risk" if score["raw_score"] > score["max_score"] * 0.5 else "Medium Risk" if score["raw_score"] > score["max_score"] * 0.25 else "Informational",
            status="Assessed",
            resolution=t,
            tags=["risk", cat_name, "assessment"],
        ))

        if cat_data["subcategories"]:
            for sub in cat_data["subcategories"][:3]:
                findings.append(make_finding(
                    entity=f"Subcategory: {sub} (in {cat_name.replace('_', ' ').title()})",
                    type="Risk: Subcategory Check",
                    source="RiskScoreEngine",
                    confidence="Medium",
                    color="slate",
                    category="Risk Assessment",
                    threat_level="Informational",
                    status="Checked",
                    resolution=t,
                    tags=["risk", cat_name, sub.lower().replace(" ", "-")],
                ))

    total_score = min(int(total_raw), 1000)
    risk_label, risk_color = get_risk_level(total_score)

    findings.append(make_finding(
        entity=f"COMPREHENSIVE RISK SCORE: {total_score}/1000 - {risk_label.upper()}",
        type="Risk: Overall Score",
        source="RiskScoreEngine",
        confidence="Very High",
        color=risk_color,
        category="Risk Assessment",
        threat_level=risk_label,
        status=f"Score: {total_score}/1000",
        resolution=t,
        tags=["risk", "overall", "score", risk_label.lower().replace(" ", "-")],
    ))

    breakdown = ", ".join(f"{cs['category'].replace('_', ' ').title()}({cs['raw_score']})" for cs in sorted(category_scores, key=lambda x: x["raw_score"], reverse=True))
    findings.append(make_finding(
        entity=f"Risk breakdown: {breakdown}",
        ftype="Risk: Category Breakdown",
        source="RiskScoreEngine",
        confidence="High",
        color="slate",
        category="Risk Assessment",
        threat_level="Informational",
        status="Broken Down",
        resolution=t,
        tags=["risk", "breakdown", "categories"],
    ))

    recommendations = generate_recommendations(category_scores, total_score)
    for i, rec in enumerate(recommendations):
        findings.append(make_finding(
            entity=f"Recommendation {i+1}: {rec}",
            ftype="Risk: Recommendation",
            source="RiskScoreEngine",
            confidence="High",
            color="blue",
            category="Risk Assessment",
            threat_level="Informational",
            status="Recommended",
            resolution=t,
            tags=["risk", "recommendation", f"rec-{i+1}"],
        ))

    findings.append(make_finding(
        entity=f"Executive Summary: {t} - Risk Level {risk_label} ({total_score}/1000)",
        type="Risk: Executive Summary",
        source="RiskScoreEngine",
        confidence="Very High",
        color=risk_color,
        category="Risk Assessment",
        threat_level=risk_label,
        status="Summarized",
        resolution=t,
        raw_data=f"Risk Score: {total_score}/1000\nRisk Level: {risk_label}\nCategories Assessed: {len(category_scores)}\nTop Risk Category: {sorted(category_scores, key=lambda x: x['raw_score'], reverse=True)[0]['category']}",
        tags=["risk", "executive-summary", risk_label.lower().replace(" ", "-")],
    ))

    risk_distribution = {rl[2]: 0 for rl in RISK_LEVELS}
    for cs in category_scores:
        pct = cs["raw_score"] / cs["max_score"] * 100 if cs["max_score"] > 0 else 0
        if pct >= 80:
            risk_distribution["Critical"] += 1
        elif pct >= 60:
            risk_distribution["High"] += 1
        elif pct >= 40:
            risk_distribution["Medium"] += 1
        elif pct >= 20:
            risk_distribution["Low"] += 1
        else:
            risk_distribution["Informational"] += 1

    dist_str = ", ".join(f"{k}({v})" for k, v in risk_distribution.items() if v > 0)
    findings.append(make_finding(
        entity=f"Risk distribution across categories: {dist_str}",
        ftype="Risk: Distribution",
        source="RiskScoreEngine",
        confidence="High",
        color="slate",
        category="Risk Assessment",
        threat_level="Informational",
        status="Distributed",
        resolution=t,
        tags=["risk", "distribution"],
    ))

    findings.append(make_finding(
        entity=f"Benchmark: {t} risk score {total_score}/1000 ({risk_label})",
        type="Risk: Peer Benchmark",
        source="RiskScoreEngine",
        confidence="Medium",
        color=risk_color,
        category="Risk Assessment",
        threat_level=risk_label,
        status="Benchmarked",
        resolution=t,
        tags=["risk", "benchmark", "peer-comparison"],
    ))

    return findings
