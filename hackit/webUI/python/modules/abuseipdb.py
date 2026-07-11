import httpx, json
from typing import List
from settings_store import get_api_key
from module_common import safe_fetch_json, safe_fetch, is_ip, resolve_ip, make_finding

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH Attacks", 23: "IoT Targeted",
}
KNOWN_BLACKLIST_DOMAINS = [
    "spamhaus.org", "spamcop.net", "barracudacentral.org",
    "talosintelligence.com", "proofpoint.com", "dnsbl.info",
    "uribl.com", "surbl.org",
]

async def query_api(ip: str, client: httpx.AsyncClient) -> dict:
    api_key = get_api_key("abuseipdb")
    if not api_key:
        return {}
    data = await safe_fetch_json(client, f"{ABUSEIPDB_API}/check", params={"ipAddress": ip, "maxAgeInDays": "365", "verbose": ""}, headers={"Accept": "application/json", "Key": api_key})
    return data.get("data", {}) if data else {}

async def query_report_history(ip: str, client: httpx.AsyncClient) -> List[dict]:
    api_key = get_api_key("abuseipdb")
    if not api_key:
        return []
    data = await safe_fetch_json(client, f"{ABUSEIPDB_API}/reports", params={"ipAddress": ip, "maxAgeInDays": "365"}, headers={"Accept": "application/json", "Key": api_key})
    return data.get("data", []) if data else []

async def check_dnsbl(ip: str, client: httpx.AsyncClient) -> List[str]:
    blacklists = []
    reversed_ip = ".".join(reversed(ip.split(".")))
    for domain in KNOWN_BLACKLIST_DOMAINS:
        try:
            resolve_ip(f"{reversed_ip}.{domain}")
            blacklists.append(domain)
        except OSError:
            pass
    return blacklists

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    ip = t if is_ip(t) else resolve_ip(t)
    if not ip:
        findings.append(make_finding("Could not resolve target IP", "AbuseIPDB Check Complete", source="AbuseIPDB", confidence="Low", color="red", status="Error", tags=["abuseipdb", "error"]))
        return findings

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

        clr = "red" if abuse_confidence > 50 else ("orange" if abuse_confidence > 0 else "emerald")
        tlv = "High Risk" if abuse_confidence > 50 else (f"Elevated Risk ({abuse_confidence}%)" if abuse_confidence > 0 else "Informational")
        st = "Reported" if total_reports > 0 else ("Whitelisted" if is_whitelisted else "Clean")
        findings.append(make_finding(f"AbuseIPDB: {total_reports} reports, confidence={abuse_confidence}%", "AbuseIPDB Report", source="AbuseIPDB", confidence="High", color=clr, threat_level=tlv, status=st, resolution=t, raw_data=json.dumps(api_data), tags=["abuseipdb", "report"]))
        if isp:
            findings.append(make_finding(f"ISP: {isp}", "AbuseIPDB ISP", source="AbuseIPDB", confidence="Medium", color="slate", resolution=t, tags=["abuseipdb", "isp"]))
        if domain:
            findings.append(make_finding(f"Domain: {domain}", "AbuseIPDB Domain", source="AbuseIPDB", confidence="Medium", color="slate", status="Related", resolution=t, tags=["abuseipdb", "domain"]))
        if country:
            findings.append(make_finding(f"Country: {country}", "AbuseIPDB Geolocation", source="AbuseIPDB", confidence="Medium", color="slate", status="Located", resolution=t, tags=["abuseipdb", "geolocation"]))
        if usage_type:
            findings.append(make_finding(f"Usage type: {usage_type}", "AbuseIPDB Usage", source="AbuseIPDB", confidence="Medium", color="slate", status="Classified", resolution=t, tags=["abuseipdb", "usage"]))
        if is_whitelisted:
            findings.append(make_finding("IP is whitelisted in AbuseIPDB", "AbuseIPDB Whitelist", source="AbuseIPDB", confidence="Medium", color="emerald", status="Whitelisted", resolution=t, tags=["abuseipdb", "whitelist"]))
        if last_reported:
            findings.append(make_finding(f"Last reported: {last_reported}", "AbuseIPDB Timeline", source="AbuseIPDB", confidence="Medium", color="slate", status="Known", resolution=t, tags=["abuseipdb", "timeline"]))

    reports = await query_report_history(ip, client)
    if reports:
        findings.append(make_finding(f"Historical reports: {len(reports)} entries", "AbuseIPDB History", source="AbuseIPDB", confidence="Medium", color="orange", threat_level="Elevated Risk", status="Available", resolution=t, tags=["abuseipdb", "history"]))
        for r in reports[:5]:
            cat_ids = r.get("categories", [])
            cats = [ABUSE_CATEGORIES.get(c, str(c)) for c in cat_ids]
            comment = r.get("comment", "")[:100]
            findings.append(make_finding(f"Report: {', '.join(cats)} | {comment}", "AbuseIPDB Report Detail", source="AbuseIPDB", confidence="Medium", color="orange", threat_level="Elevated Risk", status="Reported", resolution=t, tags=["abuseipdb", "report-detail"]))

    blacklists = await check_dnsbl(ip, client)
    if blacklists:
        findings.append(make_finding(f"DNSBL listings: {len(blacklists)} blacklists ({', '.join(blacklists)})", "AbuseIPDB DNSBL", source="AbuseIPDB", confidence="High", color="red", threat_level="High Risk", status="Blacklisted", resolution=t, tags=["abuseipdb", "dnsbl"] + blacklists))

    if not findings:
        findings.append(make_finding("No AbuseIPDB data available", "AbuseIPDB Check Complete", source="AbuseIPDB", confidence="Low", color="emerald", status="Not Found", resolution=t, tags=["abuseipdb", "empty"]))

    return findings
