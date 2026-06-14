import httpx
import asyncio
import socket
from datetime import datetime
from collections import defaultdict
from models import IntelligenceFinding

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

CATEGORY_MAP = {
    "3": "Fraud Orders",
    "4": "DDoS Attack",
    "5": "FTP Brute-Force",
    "6": "Ping of Death",
    "7": "Phishing",
    "8": "Fraud VoIP",
    "9": "Open Proxy",
    "10": "Web Spam",
    "11": "Email Spam",
    "12": "Blog Spam",
    "13": "VPN IP",
    "14": "Port Scan",
    "15": "Hacking",
    "16": "SQL Injection",
    "17": "Spoofing",
    "18": "Brute-Force",
    "19": "Bad Web Bot",
    "20": "Exploited Host",
    "21": "Web App Attack",
    "22": "SSH",
    "23": "IoT Targeted",
}

SEVERITY_MAP = {
    "DDoS Attack": "High Risk",
    "Hacking": "High Risk",
    "Brute-Force": "Elevated Risk",
    "SQL Injection": "High Risk",
    "Phishing": "High Risk",
    "Web App Attack": "Elevated Risk",
    "Bad Web Bot": "Standard Target",
    "Port Scan": "Standard Target",
    "SSH": "Standard Target",
    "Fraud Orders": "Elevated Risk",
    "Spoofing": "High Risk",
}

async def resolve_to_ips(domain: str) -> list:
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

def score_category(score: int):
    if score == 0:
        return "Clean", "emerald", "Informational", "clean"
    if score < 25:
        return "Low Risk", "slate", "Standard Target", "low-risk"
    if score < 50:
        return "Moderate Risk", "orange", "Standard Target", "moderate-risk"
    if score < 75:
        return "High Risk", "red", "Elevated Risk", "high-risk"
    return "Critical", "red", "High Risk", "critical"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    ips = await resolve_to_ips(t)
    if not ips:
        ips = [t]

    headers = {
        "User-Agent": ABUSEIPDB_UA,
        "Accept": "application/json",
        "Key": "",
    }

    country_dist = defaultdict(int)
    usage_dist = defaultdict(int)
    all_scores = []

    for ip in ips[:5]:
        try:
            resp = await client.get(
                f"{ABUSEIPDB_API}/check",
                params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
                headers=headers,
                timeout=15.0,
            )
            if resp.status_code != 200:
                continue

            data = resp.json().get("data", {})
            if not data:
                continue

            score = data.get("abuseConfidenceScore", 0)
            all_scores.append((ip, score))
            level, color, threat, tag = score_category(score)

            country = data.get("countryCode", "")
            if country:
                country_dist[country] += 1

            usage = data.get("usageType", "")
            if usage:
                usage_dist[usage] += 1

            findings.append(IntelligenceFinding(
                entity=f"Score: {score}/100 ({level})",
                type="AbuseIPDB Score",
                source="AbuseIPDB",
                confidence="High",
                color=color,
                threat_level=threat,
                status="Confirmed" if score > 0 else "Clean",
                resolution=ip,
                raw_data=f"abuseConfidenceScore={score}",
                tags=["threat-intel", "reputation", tag],
            ))

            if country:
                findings.append(IntelligenceFinding(
                    entity=f"{country}",
                    type="AbuseIPDB Country",
                    source="AbuseIPDB",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["geo", "infrastructure"],
                ))

            isp = data.get("isp", "")
            domain_name = data.get("domain", "")
            if isp or domain_name:
                findings.append(IntelligenceFinding(
                    entity=isp or domain_name,
                    type="AbuseIPDB ISP / Domain",
                    source="AbuseIPDB",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["infrastructure"],
                ))

            if usage:
                findings.append(IntelligenceFinding(
                    entity=f"Usage: {usage}",
                    type="AbuseIPDB Usage Type",
                    source="AbuseIPDB",
                    confidence="High",
                    color="slate",
                    status="Confirmed",
                    resolution=ip,
                    tags=["infrastructure"],
                ))

            total_reports = data.get("totalReports", 0)
            last_reported = data.get("lastReportedAt", "")
            if total_reports:
                report_threat = "High Risk" if total_reports > 10 else ("Elevated Risk" if total_reports > 3 else "Standard Target")
                findings.append(IntelligenceFinding(
                    entity=f"{total_reports} report(s), last: {(last_reported or 'N/A')[:10]}",
                    type="AbuseIPDB Report Volume",
                    source="AbuseIPDB",
                    confidence="High",
                    color="red" if total_reports > 5 else "orange",
                    threat_level=report_threat,
                    status="Confirmed",
                    resolution=ip,
                    tags=["threat-intel", "volume"],
                ))

            is_whitelisted = data.get("isWhitelisted", False)
            if is_whitelisted:
                findings.append(IntelligenceFinding(
                    entity="IP is whitelisted",
                    type="AbuseIPDB Whitelist",
                    source="AbuseIPDB",
                    confidence="High",
                    color="emerald",
                    status="Confirmed",
                    resolution=ip,
                    tags=["trusted"],
                ))

            hostnames = data.get("hostnames", [])
            if hostnames:
                for hn in hostnames[:3]:
                    findings.append(IntelligenceFinding(
                        entity=hn,
                        type="AbuseIPDB Hostname",
                        source="AbuseIPDB",
                        confidence="High",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["infrastructure", "dns"],
                    ))

            reports = data.get("reports", [])
            if reports:
                cat_counts = defaultdict(int)
                reporter_countries = defaultdict(int)
                date_buckets = defaultdict(int)

                for r in reports[:100]:
                    for c in r.get("categories", []):
                        cname = CATEGORY_MAP.get(str(c), f"Other ({c})")
                        cat_counts[cname] += 1
                    rc = r.get("reporterCountryCode", "") or r.get("reporterCountryName", "")
                    if rc:
                        reporter_countries[rc] += 1
                    reported_at = r.get("reportedAt", "")
                    if reported_at:
                        date_buckets[reported_at[:7]] += 1

                for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1])[:6]:
                    sev = SEVERITY_MAP.get(cat, "Standard Target")
                    findings.append(IntelligenceFinding(
                        entity=f"{cat}: {cnt} report(s)",
                        type="AbuseIPDB Category Breakdown",
                        source="AbuseIPDB",
                        confidence="High",
                        color="red" if sev == "High Risk" else "orange",
                        threat_level=sev,
                        status="Confirmed",
                        resolution=ip,
                        raw_data=f"{cat} reported {cnt} times",
                        tags=["threat-intel", "category-analysis"],
                    ))

                for rc, cnt in sorted(reporter_countries.items(), key=lambda x: -x[1])[:3]:
                    findings.append(IntelligenceFinding(
                        entity=f"Reports from {rc}: {cnt}",
                        type="AbuseIPDB Reporter Country",
                        source="AbuseIPDB",
                        confidence="Medium",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["geo", "reporting"],
                    ))

                for month, cnt in sorted(date_buckets.items())[:6]:
                    findings.append(IntelligenceFinding(
                        entity=f"{month}: {cnt} report(s)",
                        type="AbuseIPDB Reporting Trend",
                        source="AbuseIPDB",
                        confidence="Medium",
                        color="slate",
                        status="Confirmed",
                        resolution=ip,
                        tags=["threat-intel", "timeline"],
                    ))

        except:
            continue

    if len(all_scores) > 1:
        avg_score = sum(s for _, s in all_scores) / len(all_scores)
        findings.append(IntelligenceFinding(
            entity=f"Average confidence across {len(all_scores)} IP(s): {avg_score:.0f}/100",
            type="AbuseIPDB Multi-IP Summary",
            source="AbuseIPDB",
            confidence="Medium",
            color="red" if avg_score > 50 else "orange",
            threat_level="Elevated Risk" if avg_score > 25 else "Informational",
            status="Analyzed",
            tags=["threat-intel", "aggregate"],
        ))

    if country_dist:
        top_country = max(country_dist, key=country_dist.get)
        findings.append(IntelligenceFinding(
            entity=f"Top country: {top_country} ({country_dist[top_country]} IP(s))",
            type="AbuseIPDB Country Distribution",
            source="AbuseIPDB",
            confidence="Low",
            color="slate",
            status="Analyzed",
            tags=["geo", "distribution"],
        ))

    return findings
