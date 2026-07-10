import httpx
import asyncio
import json
import socket
from datetime import datetime
from typing import List
from models import IntelligenceFinding
from settings_store import get_api_key

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
ABUSE_URL = "https://www.abuseipdb.com/check"
ABUSE_REPORT_URL = "https://www.abuseipdb.com/report"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Attacks", 23: "IoT Targeted"
}

KNOWN_BLACKLIST_DOMAINS = {
    "spamhaus.org", "spamcop.net", "barracudacentral.org",
    "talosintelligence.com", "proofpoint.com", "mxtoolbox.com",
    "dnsbl.info", "uribl.com", "surbl.org",
}

async def query_api(ip: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{ABUSEIPDB_API}/check",
            params={"ipAddress": ip, "maxAgeInDays": "365", "verbose": ""},
            headers={"User-Agent": UA, "Accept": "application/json", "Key": get_api_key("abuseipdb")},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json().get("data", {})
    except:
        pass
    return {}

async def query_blacklist(client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            f"{ABUSEIPDB_API}/blacklist",
            params={"confidenceMinimum": "50", "limit": "500"},
            headers={"User-Agent": UA, "Accept": "application/json", "Key": get_api_key("abuseipdb")},
            timeout=30.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def check_website_blacklist(ip: str, client: httpx.AsyncClient) -> List[str]:
    blacklists = []
    for domain in KNOWN_BLACKLIST_DOMAINS:
        try:
            dnsbl_query = f"{'.'.join(reversed(ip.split('.')))}.{domain}"
            socket.gethostbyname(dnsbl_query)
            blacklists.append(domain)
        except:
            pass
    return blacklists

async def query_report_history(ip: str, client: httpx.AsyncClient) -> List[dict]:
    try:
        resp = await client.get(
            f"{ABUSEIPDB_API}/reports",
            params={"ipAddress": ip, "maxAgeInDays": "365"},
            headers={"User-Agent": UA, "Accept": "application/json", "Key": get_api_key("abuseipdb")},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json().get("data", [])
    except:
        pass
    return []

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    is_ip = False
    try:
        socket.inet_aton(t)
        is_ip = True
    except:
        pass

    if not is_ip:
        try:
            ip = socket.gethostbyname(t)
        except:
            ip = t
    else:
        ip = t

    api_data = await query_api(ip, client)

    if api_data:
        total_reports = api_data.get("totalReports", 0)
        abuse_confidence = api_data.get("abuseConfidenceScore", 0)
        isp = api_data.get("isp", "")
        domain = api_data.get("domain", "")
        country = api_data.get("countryCode", "")
        usage_type = api_data.get("usageType", "")
        is_whitelisted = api_data.get("isWhitelisted", False)
        last_reported = api_data.get("lastReportedAt", "")

        findings.append(IntelligenceFinding(
            entity=f"AbuseIPDB: {total_reports} reports, confidence={abuse_confidence}%",
            type="AbuseIPDB Report",
            source="AbuseIPDB",
            confidence="High",
            color="red" if abuse_confidence > 50 else ("orange" if abuse_confidence > 0 else "emerald"),
            threat_level="High Risk" if abuse_confidence > 50 else (f"Elevated Risk ({abuse_confidence}%)" if abuse_confidence > 0 else "Informational"),
            status="Reported" if total_reports > 0 else ("Whitelisted" if is_whitelisted else "Clean"),
            resolution=t,
            raw_data=json.dumps(api_data),
            tags=["abuseipdb", "report"]
        ))

        if isp:
            findings.append(IntelligenceFinding(
                entity=f"ISP: {isp}",
                type="AbuseIPDB ISP",
                source="AbuseIPDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Identified",
                resolution=t,
                tags=["abuseipdb", "isp"]
            ))

        if domain:
            findings.append(IntelligenceFinding(
                entity=f"Domain: {domain}",
                type="AbuseIPDB Domain",
                source="AbuseIPDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Related",
                resolution=t,
                tags=["abuseipdb", "domain"]
            ))

        if country:
            findings.append(IntelligenceFinding(
                entity=f"Country: {country}",
                type="AbuseIPDB Geolocation",
                source="AbuseIPDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Located",
                resolution=t,
                tags=["abuseipdb", "geolocation"]
            ))

        if usage_type:
            findings.append(IntelligenceFinding(
                entity=f"Usage type: {usage_type}",
                type="AbuseIPDB Usage",
                source="AbuseIPDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Classified",
                resolution=t,
                tags=["abuseipdb", "usage"]
            ))

        if is_whitelisted:
            findings.append(IntelligenceFinding(
                entity="IP is whitelisted in AbuseIPDB",
                type="AbuseIPDB Whitelist",
                source="AbuseIPDB",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                status="Whitelisted",
                resolution=t,
                tags=["abuseipdb", "whitelist"]
            ))

        if last_reported:
            findings.append(IntelligenceFinding(
                entity=f"Last reported: {last_reported}",
                type="AbuseIPDB Timeline",
                source="AbuseIPDB",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Known",
                resolution=t,
                tags=["abuseipdb", "timeline"]
            ))

    reports = await query_report_history(ip, client)
    if reports:
        findings.append(IntelligenceFinding(
            entity=f"Historical reports: {len(reports)} entries",
            type="AbuseIPDB History",
            source="AbuseIPDB",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="Available",
            resolution=t,
            tags=["abuseipdb", "history"]
        ))
        for r in reports[:5]:
            cat_ids = r.get("categories", [])
            cats = [ABUSE_CATEGORIES.get(c, str(c)) for c in cat_ids]
            comment = r.get("comment", "")[:100]
            findings.append(IntelligenceFinding(
                entity=f"Report: {', '.join(cats)} | {comment}",
                type="AbuseIPDB Report Detail",
                source="AbuseIPDB",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Reported",
                resolution=t,
                tags=["abuseipdb", "report-detail"]
            ))

    blacklists = await check_website_blacklist(ip, client)
    if blacklists:
        findings.append(IntelligenceFinding(
            entity=f"DNSBL listings: {len(blacklists)} blacklists ({', '.join(blacklists)})",
            type="AbuseIPDB DNSBL",
            source="AbuseIPDB",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Blacklisted",
            resolution=t,
            tags=["abuseipdb", "dnsbl"] + blacklists
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity="No AbuseIPDB data available",
            type="AbuseIPDB Check Complete",
            source="AbuseIPDB",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["abuseipdb", "empty"]
        ))

    return findings
