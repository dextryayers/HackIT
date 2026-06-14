import httpx
import asyncio
import socket
from models import IntelligenceFinding
from collections import defaultdict

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        headers = {
            "User-Agent": UA,
            "Accept": "application/json",
        }

        vt_domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        resp = await client.get(vt_domain_url, headers=headers, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})

            last_analysis = attrs.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            total = sum(last_analysis.values()) if last_analysis else 0

            if total > 0:
                risk = "Elevated Risk" if malicious > 0 else "Standard Target"
                findings.append(IntelligenceFinding(
                    entity=f"{malicious} malicious / {suspicious} suspicious out of {total} engines",
                    type="VirusTotal Reputation",
                    source="VirusTotal",
                    confidence="High",
                    color="red" if malicious > 0 else "emerald",
                    threat_level=risk,
                    raw_data=f"VT Stats: {last_analysis}",
                    tags=["threat-intel"]
                ))

            categories = attrs.get("categories", {})
            if isinstance(categories, dict):
                seen_cats = set()
                for engine, cat in categories.items():
                    if cat and cat not in seen_cats:
                        seen_cats.add(cat)
                        findings.append(IntelligenceFinding(
                            entity=f"{cat} (by {engine})",
                            type="VT Category",
                            source="VirusTotal",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Categorized as {cat} by {engine}"
                        ))

            popularity = attrs.get("popularity_ranks", {})
            if isinstance(popularity, dict):
                for engine, rank_info in popularity.items():
                    if isinstance(rank_info, dict) and rank_info.get("rank"):
                        findings.append(IntelligenceFinding(
                            entity=f"{engine}: rank #{rank_info['rank']}",
                            type="VT Popularity Rank",
                            source="VirusTotal",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                        ))
                        break

            rep = attrs.get("reputation", 0)
            findings.append(IntelligenceFinding(
                entity=f"Reputation score: {rep}",
                type="VT Reputation Score",
                source="VirusTotal",
                confidence="Medium",
                color="emerald" if rep >= 0 else "red",
                threat_level="Informational",
            ))

        resp2 = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40",
            headers=headers, timeout=15.0
        )
        if resp2.status_code == 200:
            data2 = resp2.json()
            seen_subs = set()
            for item in data2.get("data", []):
                sub = item.get("id", "")
                if sub and sub not in seen_subs:
                    seen_subs.add(sub)
                    findings.append(IntelligenceFinding(
                        entity=sub,
                        type="Subdomain (VT)",
                        source="VirusTotal",
                        confidence="High",
                        color="blue",
                        raw_data=f"Found via VT domain subdomains API"
                    ))

        resp3 = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=20",
            headers=headers, timeout=15.0
        )
        if resp3.status_code == 200:
            data3 = resp3.json()
            seen_ips = set()
            for item in data3.get("data", []):
                attrs3 = item.get("attributes", {})
                ip = attrs3.get("ip_address", "") or attrs3.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    findings.append(IntelligenceFinding(
                        entity=ip,
                        type="Historical IP Resolution",
                        source="VirusTotal",
                        confidence="High",
                        color="slate",
                        resolution=f"Resolved from {domain}",
                        raw_data=f"IP {ip} historically associated with {domain}"
                    ))

        resp4 = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/urls?limit=20",
            headers=headers, timeout=15.0
        )
        if resp4.status_code == 200:
            data4 = resp4.json()
            for item in data4.get("data", []):
                url_attr = item.get("attributes", {})
                url_str = url_attr.get("url", "")
                if url_str:
                    findings.append(IntelligenceFinding(
                        entity=url_str[:200],
                        type="VT Associated URL",
                        source="VirusTotal",
                        confidence="Medium",
                        color="slate",
                        threat_level="Standard Target",
                        raw_data=url_str[:500]
                    ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"VT Error: {str(e)[:100]}",
            type="VirusTotal Error",
            source="VirusTotal",
            confidence="Low",
            color="red",
            threat_level="Informational"
        ))

    return findings
