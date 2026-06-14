import httpx
import socket
import asyncio
import json
import re
from models import IntelligenceFinding
from urllib.parse import urlparse

THREAT_LEVELS = {
    "malware": "High Risk",
    "phishing": "High Risk",
    "c2": "Critical",
    "command_and_control": "Critical",
    "scanning": "Elevated Risk",
    "botnet": "High Risk",
    "spam": "Elevated Risk",
    "ransomware": "Critical",
    "ddos": "High Risk",
    "fraud": "High Risk",
    "exploit": "High Risk",
    "trojan": "High Risk",
    "worm": "High Risk",
    "banking": "High Risk",
    "apt": "Critical",
    "suspicious": "Elevated Risk",
}


def classify_threat(tags: list[str], raw: str) -> tuple[str, str, str]:
    lower_raw = raw.lower()
    combined = " ".join(t.lower() for t in tags) + " " + lower_raw
    for keyword, level in sorted(THREAT_LEVELS.items(), key=lambda x: -len(x[0])):
        if keyword in combined:
            color_map = {"Critical": "red", "High Risk": "red",
                         "Elevated Risk": "orange", "Informational": "slate"}
            threat_type = keyword.replace("_", " ").title()
            if threat_type in ("C2", "Ddos", "Apt"):
                threat_type = threat_type.upper()
            return threat_type, level, color_map.get(level, "slate")
    return "Suspicious", "Elevated Risk", "orange"


def compute_threat_score(findings: list) -> int:
    score = 0
    weights = {
        "Critical": 40, "High Risk": 25,
        "Elevated Risk": 10, "Informational": 0,
    }
    for f in findings:
        threat = f.threat_level or "Informational"
        score += weights.get(threat, 5)
    return min(score, 100)


async def check_urlscan(domain: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    try:
        resp = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            if not results:
                return findings

            findings.append(IntelligenceFinding(
                entity=f"{len(results)} URLScan.io results for {domain}",
                type="URLScan Query",
                source="URLScan.io",
                confidence="High",
                color="purple",
                status=f"{len(results)} scans found",
                resolution=domain,
            ))

            malicious = 0
            for r in results[:15]:
                page = r.get("page", {})
                verdicts = r.get("verdicts", {})
                overall = verdicts.get("overall", {}) if verdicts else {}
                malicious_score = overall.get("maliciousScore", 0)
                is_malicious = overall.get("malicious", False)

                url = page.get("url", "")
                ip = page.get("ip", "")
                server = page.get("server", "")
                status_text = "Malicious" if is_malicious else "Clean"
                color = "red" if is_malicious else "emerald"
                if is_malicious:
                    malicious += 1

                findings.append(IntelligenceFinding(
                    entity=url[:200] if url else "N/A",
                    type="URLScan Result",
                    source="URLScan.io",
                    confidence="High" if is_malicious else "Medium",
                    color=color,
                    threat_level="High Risk" if is_malicious else "Informational",
                    status=status_text,
                    resolution=ip or "",
                    raw_data=f"Server: {server}, IP: {ip}, "
                             f"Malicious Score: {malicious_score}"
                             f"{', MALICIOUS' if is_malicious else ''}",
                    tags=["malicious", "urlscan"] if is_malicious else ["urlscan"],
                ))

            if malicious > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{malicious}/{len(results)} malicious scans on URLScan.io",
                    type="URLScan Malicious Summary",
                    source="URLScan.io",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status=f"{malicious} malicious",
                    resolution=domain,
                ))

    except Exception:
        pass
    return findings


async def check_otx(domain: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    try:
        resp = await client.get(
            f"https://otx.alienvault.com/otxapi/indicator/domain/{domain}",
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("pulses", []) or data.get("results", [])

            if pulses:
                for pulse in pulses[:15]:
                    name = pulse.get("name", "Unknown")
                    description = pulse.get("description", "")[:200]
                    tags = pulse.get("tags", [])
                    threat_type, level, color = classify_threat(tags,
                        f"{name} {description}")
                    tlp = pulse.get("tlp", "green")
                    adversary = pulse.get("adversary", "")

                    findings.append(IntelligenceFinding(
                        entity=name[:200],
                        type=f"OTX Pulse: {threat_type}",
                        source="AlienVault OTX",
                        confidence="Medium",
                        color=color,
                        threat_level=level,
                        status=f"TLP: {tlp}",
                        resolution=domain,
                        raw_data=f"Description: {description}, "
                                 f"Tags: {', '.join(tags[:10])}, "
                                 f"Adversary: {adversary}",
                        tags=tags[:10] + ["otx"],
                    ))

                findings.append(IntelligenceFinding(
                    entity=f"{len(pulses)} OTX pulses related to {domain}",
                    type="OTX Summary",
                    source="AlienVault OTX",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status=f"{len(pulses)} pulses",
                    resolution=domain,
                ))
                return findings

        public_url = f"https://otx.alienvault.com/indicator/domain/{domain}"
        resp2 = await client.get(public_url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp2.status_code == 200:
            html = resp2.text.lower()[:3000]
            if "not found" not in html and "404" not in html:
                findings.append(IntelligenceFinding(
                    entity=domain,
                    type="OTX Domain Check",
                    source="AlienVault OTX",
                    confidence="Low",
                    color="slate",
                    status="Domain found in OTX (limited data)",
                    resolution=domain,
                ))

    except Exception:
        pass
    return findings


async def check_abuseipdb(domain: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
        except Exception:
            return findings

        resp = await client.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            timeout=15.0,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            country = data.get("countryCode", "")
            domain_name = data.get("domain", "")
            is_whitelisted = data.get("isWhitelisted", False)
            isp = data.get("isp", "")
            usage = data.get("usageType", "")
            last_reported = data.get("lastReportedAt", "")

            if abuse_score > 0 or total_reports > 0:
                color = "red" if abuse_score > 50 else ("orange" if abuse_score > 0 else "slate")
                level = "High Risk" if abuse_score > 50 else ("Elevated Risk" if abuse_score > 0 else "Informational")

                findings.append(IntelligenceFinding(
                    entity=f"AbuseIPDB: {ip} (Score: {abuse_score}%, Reports: {total_reports})",
                    type="AbuseIPDB Report",
                    source="AbuseIPDB",
                    confidence="High" if abuse_score > 0 else "Medium",
                    color=color,
                    threat_level=level,
                    status=f"Score: {abuse_score}%" if abuse_score > 0 else "Clean",
                    resolution=ip,
                    raw_data=f"IP: {ip}, Domain: {domain_name}, ISP: {isp}, "
                             f"Country: {country}, Usage: {usage}, "
                             f"Reports: {total_reports}, "
                             f"Last Reported: {last_reported}",
                    tags=(["abuseipdb"] +
                          ["malicious"] if abuse_score > 50 else []),
                ))

                if total_reports > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"{total_reports} abuse reports, "
                               f"last: {last_reported or 'N/A'}",
                        type="AbuseIPDB Reports Summary",
                        source="AbuseIPDB",
                        confidence="High",
                        color=color,
                        threat_level=level,
                        status=f"{total_reports} reports",
                        resolution=ip,
                    ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"{ip} not found in AbuseIPDB database",
                    type="AbuseIPDB Check",
                    source="AbuseIPDB",
                    confidence="Medium",
                    color="emerald",
                    status="Clean",
                    resolution=ip,
                ))

        else:
            findings.append(IntelligenceFinding(
                entity=f"AbuseIPDB check for {domain} ({ip})",
                type="AbuseIPDB Status",
                source="AbuseIPDB",
                confidence="Low",
                color="slate",
                status=f"HTTP {resp.status_code}",
                resolution=ip,
            ))

    except Exception:
        pass
    return findings


async def check_ssl_blacklists(domain: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    try:
        cert_endpoint = f"https://crt.sh/?q={domain}&output=json"
        resp = await client.get(cert_endpoint, timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return findings

        entries = resp.json() if resp.text else []
        if not entries or not isinstance(entries, list):
            return findings

        names_seen = set()
        suspicious_certs = 0
        for entry in entries[:50]:
            name = entry.get("name_value", "")
            issuer = (entry.get("issuer_name") or "").lower()
            is_suspicious = any(kw in issuer for kw in
                ["self-signed", "untrusted", "invalid", "test", "fake",
                 "localhost", "internal"])
            if is_suspicious:
                for n in name.split("\n"):
                    n = n.strip()
                    if n and n not in names_seen:
                        names_seen.add(n)
                        suspicious_certs += 1
                        findings.append(IntelligenceFinding(
                            entity=n[:200],
                            type="Suspicious SSL Certificate",
                            source="CRT.sh / SSL Blacklist",
                            confidence="Medium",
                            color="orange",
                            threat_level="Elevated Risk",
                            status="Suspicious issuer",
                            raw_data=f"Issuer: {entry.get('issuer_name', '')}, "
                                     f"Not Before: {entry.get('not_before', '')}, "
                                     f"Not After: {entry.get('not_after', '')}",
                            tags=["ssl", "suspicious"],
                        ))

        if suspicious_certs > 0:
            findings.append(IntelligenceFinding(
                entity=f"{suspicious_certs} suspicious SSL certificates found for {domain}",
                type="SSL Blacklist Summary",
                source="CRT.sh / SSL Blacklist",
                confidence="High",
                color="red" if suspicious_certs > 3 else "orange",
                threat_level="High Risk" if suspicious_certs > 3 else "Elevated Risk",
                status=f"{suspicious_certs} suspicious certs",
                resolution=domain,
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="SSL Certificate Check",
                source="CRT.sh / SSL Blacklist",
                confidence="Medium",
                color="emerald",
                status="No suspicious certificates",
                resolution=domain,
            ))

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        urlscan_results = await check_urlscan(domain, client)
        findings.extend(urlscan_results)

        otx_results = await check_otx(domain, client)
        findings.extend(otx_results)

        abuse_results = await check_abuseipdb(domain, client)
        findings.extend(abuse_results)

        ssl_results = await check_ssl_blacklists(domain, client)
        findings.extend(ssl_results)

        total_score = compute_threat_score(findings)
        all_findings_count = len(findings)
        threat_findings = [f for f in findings
                          if f.threat_level in ("High Risk", "Critical")]
        elevated_findings = [f for f in findings
                            if f.threat_level == "Elevated Risk"]

        threat_text = f"Threat Score: {total_score}/100"
        threat_color = "red"
        if total_score < 20:
            threat_color = "emerald"
        elif total_score < 50:
            threat_color = "orange"

        findings.append(IntelligenceFinding(
            entity=threat_text,
            type="Aggregated Threat Score",
            source="ThreatIntel",
            confidence="High",
            color=threat_color,
            threat_level="High Risk" if total_score >= 50 else
                        "Elevated Risk" if total_score >= 20 else "Informational",
            status=f"Score: {total_score}%",
            resolution=domain,
            raw_data=f"Total: {total_score}/100, "
                     f"Threat findings: {len(threat_findings)}, "
                     f"Elevated: {len(elevated_findings)}, "
                     f"Total indicators: {all_findings_count}",
        ))

        source_summary = {}
        for f in findings:
            src = f.source
            source_summary[src] = source_summary.get(src, 0) + 1

        for src, count in source_summary.items():
            findings.append(IntelligenceFinding(
                entity=f"{src}: {count} findings",
                type="Source Summary",
                source="ThreatIntel",
                confidence="High",
                color="purple",
                status=f"{count} from {src}",
                resolution=domain,
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Threat intel error: {str(e)[:150]}",
            type="Threat Intel Error",
            source="ThreatIntel",
            confidence="Low",
            color="red",
            status="Error",
        ))

    return findings
