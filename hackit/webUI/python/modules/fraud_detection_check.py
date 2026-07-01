import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

FRAUD_SOURCES = [
    ("ScamAdviser", "https://www.scamadviser.com/check-website/{}"),
    ("TrustPilot", "https://www.trustpilot.com/search?query={}"),
    ("Web of Trust", "https://www.mywot.com/scorecard/{}"),
    ("Better Business Bureau", "https://www.bbb.org/search?find_text={}"),
    ("RipOff Report", "https://www.ripoffreport.com/search?q={}"),
    ("ComplaintsBoard", "https://www.complaintsboard.com/search?q={}"),
    ("PissedConsumer", "https://www.pissedconsumer.com/search.html?search={}"),
    ("SiteJabber", "https://www.sitejabber.com/search?q={}"),
    ("Glassdoor", "https://www.glassdoor.com/Search/results.htm?keyword={}"),
    ("Indeed", "https://www.indeed.com/search?q={}"),
    ("Kununu", "https://www.kununu.com/search?q={}"),
    ("ReportFraud", "https://www.reportfraud.ftc.gov/search?q={}"),
    ("FraudWatch", "https://www.fraudwatchinternational.com/search?q={}"),
    ("ScamWatch", "https://www.scamwatch.gov.au/search?q={}"),
    ("ActionFraud", "https://www.actionfraud.police.uk/search?q={}"),
    ("FraudGuide", "https://www.fraudguide.com/search?q={}"),
    ("ConsumerAffairs", "https://www.consumeraffairs.com/search/?q={}"),
    ("ComplaintBoard", "https://www.complaintboard.com/search?q={}"),
    ("Scam Detector", "https://www.scam-detector.com/search?q={}"),
    ("Fraud.org", "https://www.fraud.org/search?q={}"),
]

RISK_KEYWORDS = {
    "scam": ["scam", "fraud", "fake", "illegitimate", "untrustworthy", "dishonest"],
    "complaint": ["complaint", "rip off", "ripoff", "scammed", "cheated", "stolen"],
    "legal": ["lawsuit", "class action", "settlement", "legal action", "sued", "summons"],
    "chargeback": ["chargeback", "refund", "dispute", "unauthorized charge"],
    "identity_theft": ["identity theft", "identity fraud", "id theft", "stolen identity"],
    "phishing": ["phishing", "spoof", "fake website", "lookalike", "imitation"],
    "regulatory": ["cease and desist", "regulatory", "fine", "penalty", "sanction"],
    "blacklist": ["blacklist", "blocklist", "banned", "suspended", "terminated"],
}

POSITIVE_KEYWORDS = ["trusted", "verified", "legitimate", "reliable", "recommended", "authentic", "safe", "secure", "top-rated", "certified"]


async def search_fraud_source(name: str, url_template: str, target: str, client: httpx.AsyncClient) -> dict:
    try:
        url = url_template.format(quote(target))
        resp = await client.get(url, timeout=15.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 200:
            text = resp.text.lower()
            mentions = text.count(target.lower())
            risk_hits = {}
            for category, keywords in RISK_KEYWORDS.items():
                for kw in keywords:
                    if kw in text:
                        risk_hits[category] = risk_hits.get(category, 0) + 1
                        break
            positive_signals = sum(1 for kw in POSITIVE_KEYWORDS if kw in text)
            rating_matches = re.findall(r'(\d+(?:\.\d+)?)\s*/\s*10', text)
            ratings = [float(r) for r in rating_matches if float(r) <= 10]
            avg_rating = sum(ratings) / len(ratings) if ratings else 0
            return {
                "name": name,
                "mentions": mentions,
                "risk_hits": risk_hits,
                "positive_signals": positive_signals,
                "avg_rating": avg_rating,
                "has_ratings": len(ratings) > 0,
            }
    except:
        pass
    return None


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    all_results = []
    sources_with_data = 0

    for name, url_template in FRAUD_SOURCES:
        result = await search_fraud_source(name, url_template, t, client)
        if result:
            all_results.append(result)
            if result["mentions"] > 0 or result["risk_hits"]:
                sources_with_data += 1

    total_risk_score = 0
    total_positive = 0
    for result in all_results:
        risk_count = sum(result.get("risk_hits", {}).values())
        pos = result.get("positive_signals", 0)
        total_risk_score += risk_count
        total_positive += pos

        if result["risk_hits"]:
            for category, count in sorted(result["risk_hits"].items(), key=lambda x: x[1], reverse=True)[:3]:
                threat_map = {
                    "scam": ("Critical", "red"), "complaint": ("High Risk", "orange"),
                    "legal": ("Critical", "red"), "chargeback": ("High Risk", "orange"),
                    "identity_theft": ("Critical", "red"), "phishing": ("Critical", "red"),
                    "regulatory": ("High Risk", "orange"), "blacklist": ("High Risk", "orange"),
                }
                threat, color = threat_map.get(category, ("Medium Risk", "yellow"))
                findings.append(IntelligenceFinding(
                    entity=f"{result['name']}: {category.replace('_', ' ').title()} detected ({count} indicators)",
                    type=f"Fraud: {category.replace('_', ' ').title()}",
                    source="FraudDetection",
                    confidence="Medium",
                    color=color,
                    category="Fraud Intelligence",
                    threat_level=threat,
                    status="Detected",
                    resolution=t,
                    tags=["fraud", category, result['name'].lower().replace(" ", "-")],
                ))

        if result["has_ratings"]:
            rating = result["avg_rating"]
            findings.append(IntelligenceFinding(
                entity=f"{result['name']}: Rating {rating:.1f}/10 for {t}",
                type="Fraud: Rating Check",
                source="FraudDetection",
                confidence="Medium",
                color="emerald" if rating >= 7 else "orange" if rating >= 4 else "red",
                category="Fraud Intelligence",
                threat_level="Low Risk" if rating >= 7 else "Medium Risk" if rating >= 4 else "High Risk",
                status="Rated",
                resolution=t,
                tags=["fraud", "rating", result['name'].lower().replace(" ", "-")],
            ))

    if all_results:
        findings.append(IntelligenceFinding(
            entity=f"Fraud detection scan: {sources_with_data}/{len(FRAUD_SOURCES)} sources had data on {t}",
            type="Fraud: Coverage Report",
            source="FraudDetection",
            confidence="High",
            color="slate",
            category="Fraud Intelligence",
            threat_level="Informational",
            status="Complete",
            resolution=t,
            tags=["fraud", "coverage"],
        ))

    if total_risk_score > total_positive:
        findings.append(IntelligenceFinding(
            entity=f"Overall fraud risk: HIGH ({total_risk_score} risk signals vs {total_positive} positive signals)",
            type="Fraud: Overall Assessment",
            source="FraudDetection",
            confidence="Medium",
            color="red",
            category="Fraud Intelligence",
            threat_level="Critical",
            status="High Risk",
            resolution=t,
            tags=["fraud", "assessment", "high-risk"],
        ))
    elif total_positive > total_risk_score:
        findings.append(IntelligenceFinding(
            entity=f"Overall fraud risk: LOW ({total_positive} positive signals vs {total_risk_score} risk signals)",
            type="Fraud: Overall Assessment",
            source="FraudDetection",
            confidence="Medium",
            color="emerald",
            category="Fraud Intelligence",
            threat_level="Informational",
            status="Low Risk",
            resolution=t,
            tags=["fraud", "assessment", "low-risk"],
        ))

    if not all_results:
        findings.append(IntelligenceFinding(
            entity="No fraud reports found for target",
            type="Fraud: Scan Complete",
            source="FraudDetection",
            confidence="Low",
            color="emerald",
            category="Fraud Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["fraud", "clean"],
        ))

    return findings
