import re
import json
import asyncio
from collections import defaultdict
from urllib.parse import urlparse
from ..module_common import safe_fetch, make_finding

SOURCE_RELIABILITY = {
    "crt.sh": 0.95, "HackerTarget": 0.90, "BufferOver": 0.85, "RapidDNS": 0.80,
    "AlienVault OTX": 0.85, "ThreatCrowd": 0.70, "Anubis": 0.75, "URLScan.io": 0.80,
    "Riddler": 0.65, "Sonar Omnisint": 0.85, "Wayback Machine": 0.75, "Shodan": 0.90,
    "Censys": 0.90, "FOFA": 0.80, "ZoomEye": 0.75, "BinaryEdge": 0.80,
    "Netlas": 0.75, "FullHunt": 0.70, "LeakIX": 0.65, "IntelX": 0.70,
    "ONYPHE": 0.75, "PublicWWW": 0.60, "DNSDumpster": 0.75, "CertSpotter": 0.85,
    "GoogleCT": 0.95, "ThreatMiner": 0.70, "VirusTotal": 0.85, "DNSDB": 0.80,
    "DNSlytics": 0.65, "RIPEStat": 0.70, "Netcraft": 0.75, "PhishTank": 0.50,
    "Spyse": 0.75, "SecurityTrails": 0.90, "PassiveTotal": 0.85, "RiskIQ": 0.80,
    "CIRCL": 0.75, "DNSBufferOver": 0.80, "Omnisint": 0.85, "SearchEngine": 0.50,
    "GoogleDorks": 0.60, "BingSearch": 0.55, "DuckDuckGo": 0.50,
}

async def _from_crtsh(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20.0)
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            for entry in certs:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower()
                    if (sub.endswith("." + domain) or sub == domain) and "*" not in sub and sub not in seen:
                        seen.add(sub)
                        counts["crt.sh"] += 1
                        findings.append(make_finding(
                            entity=sub, ftype="Subdomain (Passive Discovery)", source="crt.sh",
                            confidence="High", color="emerald", category="Domain Reconnaissance",
                            threat_level="Informational", status="Discovered",
                            raw_data="Found in Certificate Transparency logs", tags=["subdomain", "ct-log"]
                        ))
    except Exception:
        pass

async def _from_hackertarget(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15.0)
        if resp.status_code == 200:
            for line in resp.text.split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub not in seen:
                        seen.add(sub)
                        counts["HackerTarget"] += 1
                        findings.append(make_finding(
                            entity=sub, ftype="Subdomain (Passive Discovery)", source="HackerTarget",
                            confidence="High", color="emerald", category="Domain Reconnaissance",
                            threat_level="Informational", status="Discovered",
                            raw_data="Found via passive DNS", tags=["subdomain", "passive-dns"]
                        ))
    except Exception:
        pass

async def _from_bufferover(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://dns.bufferover.run/dns?q=.{domain}", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry_type in ["FDNS_A", "RDNS"]:
                for entry in data.get(entry_type, []):
                    if isinstance(entry, str) and ',' in entry:
                        parts = entry.split(',')
                        sub = parts[1].strip().lower() if len(parts) >= 2 else ""
                        if sub.endswith("." + domain) and sub not in seen:
                            seen.add(sub)
                            counts["BufferOver"] += 1
                            findings.append(make_finding(
                                entity=sub, ftype="Subdomain (Passive Discovery)", source="BufferOver",
                                confidence="High", color="emerald", category="Domain Reconnaissance",
                                threat_level="Informational", status="Discovered",
                                raw_data=f"Found via {entry_type} ", tags=["subdomain", "bufferover"]
                            ))
    except Exception:
        pass

async def _from_rapiddns(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["RapidDNS"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="RapidDNS",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "rapiddns"]
                    ))
    except Exception:
        pass

async def _from_alienvault(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("passive_dns", []):
                sub = entry.get("hostname", "").lower()
                if sub.endswith("." + domain) and sub not in seen:
                    seen.add(sub)
                    counts["AlienVault OTX"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="AlienVault OTX",
                        confidence="High", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        raw_data="Found via OTX passive DNS", tags=["subdomain", "otx"]
                    ))
    except Exception:
        pass

async def _from_threatcrowd(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", []):
                sub = sub.lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["ThreatCrowd"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="ThreatCrowd",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "threatcrowd"]
                    ))
    except Exception:
        pass

async def _from_anubis(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://jldc.me/anubis/subdomains/{domain}", timeout=15.0)
        if resp.status_code == 200 and resp.text.strip().startswith("["):
            data = resp.json()
            for sub in data:
                if isinstance(sub, str) and sub.lower().endswith("." + domain) and sub.lower() not in seen:
                    sub = sub.lower()
                    seen.add(sub)
                    counts["Anubis"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Anubis",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "anubis"]
                    ))
    except Exception:
        pass

async def _from_urlscan(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                sub = page.get("domain", "").lower()
                if sub.endswith("." + domain) and sub not in seen:
                    seen.add(sub)
                    counts["URLScan.io"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="URLScan.io",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "urlscan"]
                    ))
    except Exception:
        pass

async def _from_sonar_omnisint(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://sonar.omnisint.io/subdomains/{domain}", timeout=15.0)
        if resp.status_code == 200 and resp.text.strip().startswith("["):
            data = resp.json()
            for sub in data:
                if isinstance(sub, str) and sub.lower().endswith("." + domain) and sub.lower() not in seen:
                    sub = sub.lower()
                    seen.add(sub)
                    counts["Sonar Omnisint"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Sonar Omnisint",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "omnisint"]
                    ))
    except Exception:
        pass

async def _from_wayback(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey", timeout=25.0)
        if resp.status_code == 200:
            data = resp.json()
            sub_pattern = re.compile(rf'https?://([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for row in data[1:]:
                if isinstance(row, list) and len(row) > 0:
                    m = sub_pattern.search(row[0])
                    if m:
                        sub = m.group(1).lower()
                        if sub not in seen:
                            seen.add(sub)
                            counts["Wayback Machine"] += 1
                            findings.append(make_finding(
                                entity=sub, ftype="Subdomain (Passive Discovery)", source="Wayback Machine",
                                confidence="Medium", color="emerald", category="Domain Reconnaissance",
                                threat_level="Informational", status="Discovered",
                                tags=["subdomain", "wayback"]
                            ))
    except Exception:
        pass

async def _from_shodan(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://www.shodan.io/search?query=hostname%3A.{domain}", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["Shodan"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Shodan",
                        confidence="High", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "shodan"]
                    ))
    except Exception:
        pass

async def _from_censys(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://search.censys.io/search?resource=hosts&q=services.service_name%3A%22HTTP%22+AND+dns.names%3A.{domain}", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["Censys"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Censys",
                        confidence="High", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "censys"]
                    ))
    except Exception:
        pass

async def _from_zoomeye(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://www.zoomeye.org/searchResult?q=hostname%3A.{domain}", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["ZoomEye"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="ZoomEye",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "zoomeye"]
                    ))
    except Exception:
        pass

async def _from_binaryedge(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://app.binaryedge.io/api/v2/query/search?query=domain%3A{domain}", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for event in data.get("events", data.get("results", [])):
                if isinstance(event, dict):
                    sub = event.get("hostname", event.get("domain", "")).lower()
                    if sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        counts["BinaryEdge"] += 1
                        findings.append(make_finding(
                            entity=sub, ftype="Subdomain (Passive Discovery)", source="BinaryEdge",
                            confidence="Medium", color="emerald", category="Domain Reconnaissance",
                            threat_level="Informational", status="Discovered",
                            tags=["subdomain", "binaryedge"]
                        ))
    except Exception:
        pass

async def _from_netlas(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://app.netlas.io/domains/?q=domain%3A.{domain}&source_type=include", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["Netlas"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Netlas",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "netlas"]
                    ))
    except Exception:
        pass

async def _from_fullhunt(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://fullhunt.io/api/v1/domain/{domain}/subdomains", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get("subdomains", data.get("domains", data.get("results", []))):
                if isinstance(sub, str) and sub.endswith("." + domain) and sub not in seen:
                    seen.add(sub)
                    counts["FullHunt"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="FullHunt",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "fullhunt"]
                    ))
    except Exception:
        pass

async def _from_onyphe(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://www.onyphe.io/search?query=domain%3A{domain}", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["ONYPHE"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="ONYPHE",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "onyphe"]
                    ))
    except Exception:
        pass

async def _from_publicwww(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://publicwww.com/websites/{domain}/", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["PublicWWW"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="PublicWWW",
                        confidence="Low", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "publicwww"]
                    ))
    except Exception:
        pass

async def _from_dnsdumpster(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://dnsdumpster.com/", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["DNSDumpster"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="DNSDumpster",
                        confidence="Medium", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "dnsdumpster"]
                    ))
    except Exception:
        pass

async def _from_certspotter(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data if isinstance(data, list) else data.get("results", []):
                if isinstance(entry, dict):
                    for dns_name in entry.get("dns_names", []):
                        sub = dns_name.lower()
                        if sub.endswith("." + domain) and "*" not in sub and sub not in seen:
                            seen.add(sub)
                            counts["CertSpotter"] += 1
                            findings.append(make_finding(
                                entity=sub, ftype="Subdomain (Passive Discovery)", source="CertSpotter",
                                confidence="High", color="emerald", category="Domain Reconnaissance",
                                threat_level="Informational", status="Discovered",
                                tags=["subdomain", "certspotter"]
                            ))
    except Exception:
        pass

async def _from_google_ct(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://certificate.transparency.google.com/?domain={domain}", timeout=15.0)
        if resp.status_code == 200:
            pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
            for m in pattern.finditer(resp.text):
                sub = m.group(1).lower()
                if sub not in seen:
                    seen.add(sub)
                    counts["GoogleCT"] += 1
                    findings.append(make_finding(
                        entity=sub, ftype="Subdomain (Passive Discovery)", source="Google CT",
                        confidence="High", color="emerald", category="Domain Reconnaissance",
                        threat_level="Informational", status="Discovered",
                        tags=["subdomain", "google-ct"]
                    ))
    except Exception:
        pass

async def _from_threatminer(domain: str, client: AsyncClient, seen: set, findings: list, counts: dict):
    try:
        resp = await safe_fetch(client, f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("results", []):
                if isinstance(entry, str):
                    sub = entry.lower()
                    if sub.endswith("." + domain) and sub not in seen:
                        seen.add(sub)
                        counts["ThreatMiner"] += 1
                        findings.append(make_finding(
                            entity=sub, ftype="Subdomain (Passive Discovery)", source="ThreatMiner",
                            confidence="Medium", color="emerald", category="Domain Reconnaissance",
                            threat_level="Informational", status="Discovered",
                            tags=["subdomain", "threatminer"]
                        ))
    except Exception:
        pass

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    seen = set()
    source_counts = defaultdict(int)

    await asyncio.gather(
        _from_crtsh(domain, client, seen, findings, source_counts),
        _from_hackertarget(domain, client, seen, findings, source_counts),
        _from_bufferover(domain, client, seen, findings, source_counts),
        _from_rapiddns(domain, client, seen, findings, source_counts),
        _from_alienvault(domain, client, seen, findings, source_counts),
        _from_threatcrowd(domain, client, seen, findings, source_counts),
        _from_anubis(domain, client, seen, findings, source_counts),
        _from_urlscan(domain, client, seen, findings, source_counts),
        _from_sonar_omnisint(domain, client, seen, findings, source_counts),
        _from_wayback(domain, client, seen, findings, source_counts),
        _from_shodan(domain, client, seen, findings, source_counts),
        _from_censys(domain, client, seen, findings, source_counts),
        _from_zoomeye(domain, client, seen, findings, source_counts),
        _from_binaryedge(domain, client, seen, findings, source_counts),
        _from_netlas(domain, client, seen, findings, source_counts),
        _from_fullhunt(domain, client, seen, findings, source_counts),
        _from_onyphe(domain, client, seen, findings, source_counts),
        _from_publicwww(domain, client, seen, findings, source_counts),
        _from_dnsdumpster(domain, client, seen, findings, source_counts),
        _from_certspotter(domain, client, seen, findings, source_counts),
        _from_google_ct(domain, client, seen, findings, source_counts),
        _from_threatminer(domain, client, seen, findings, source_counts),
    )

    if findings:
        source_summary = ", ".join(f"{s}: {c}" for s, c in sorted(source_counts.items(), key=lambda x: -x[1]))
        findings.insert(0, make_finding(
            entity=f"Total: {len(seen)} unique passive subdomains from {len(source_counts)} sources",
            ftype="Passive Subdomain Discovery - Summary",
            source="Passive Subdomain Discovery",
            confidence="High", color="blue", category="Domain Reconnaissance",
            threat_level="Informational", status="Summary",
            raw_data=source_summary, tags=["subdomain", "summary"]
        ))

        reliability_total = sum(SOURCE_RELIABILITY.get(s, 0.7) for s in source_counts for _ in range(source_counts[s]))
        reliability_count = sum(source_counts.values())
        avg_reliability = reliability_total / reliability_count if reliability_count > 0 else 0
        findings.append(make_finding(
            entity=f"Source Reliability Score: {avg_reliability:.0%} (avg of {reliability_count} signals)",
            ftype="Passive Subdomain Discovery - Reliability",
            source="Passive Subdomain Discovery",
            confidence="High",
            color="emerald" if avg_reliability >= 0.8 else "orange",
            threat_level="Informational", status=f"{avg_reliability:.0%}",
            raw_data=f"Average reliability: {avg_reliability:.3f} across {reliability_count} signals",
            tags=["reliability", "quality"]
        ))

        sources_used = len(source_counts)
        domain_coverage = "Comprehensive" if sources_used >= 15 else "Moderate" if sources_used >= 8 else "Limited"
        findings.append(make_finding(
            entity=f"Source coverage: {sources_used}/22 sources ({domain_coverage})",
            ftype="Passive Subdomain Discovery - Coverage",
            source="Passive Subdomain Discovery",
            confidence="High", color="purple",
            threat_level="Informational", status=domain_coverage,
            raw_data=f"Sources hit: {sources_used} out of 22 queried",
            tags=["coverage", "quality"]
        ))

    return findings
