import httpx
import json
from models import IntelligenceFinding

VT_API_BASE = "https://www.virustotal.com/api/v3"
PUBLIC_USER_AGENT = "Mozilla/5.0 (compatible; OSINTBot/1.0; +https://github.com/osintbot)"

async def _v3_get(client: httpx.AsyncClient, path: str, timeout: float = 15.0) -> dict | None:
    try:
        resp = await client.get(
            f"{VT_API_BASE}{path}",
            timeout=timeout,
            headers={
                "User-Agent": PUBLIC_USER_AGENT,
                "Accept": "application/json",
            },
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

async def _public_vt_html(client: httpx.AsyncClient, path: str, timeout: float = 15.0) -> str | None:
    try:
        resp = await client.get(
            f"https://www.virustotal.com{path}",
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        )
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None

async def analyze_domain(domain: str, findings: list, client: httpx.AsyncClient):
    data = await _v3_get(client, f"/domains/{domain}")
    if not data:
        return
    attrs = data.get("data", {}).get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    if stats:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        timeout_e = stats.get("timeout", 0)
        failure_e = stats.get("failure", 0)
        total = sum(stats.values())
        color = "red" if malicious > 0 else ("orange" if suspicious > 0 else "emerald")
        threat = "High Risk" if malicious > 0 else ("Elevated Risk" if suspicious > 0 else "Informational")
        findings.append(IntelligenceFinding(
            entity=f"VT: {malicious} malicious / {suspicious} suspicious / {total} engines",
            type="VT Full Analysis",
            source="VirusTotal Full",
            confidence="High",
            color=color,
            threat_level=threat,
            status="Analyzed",
            resolution=f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}",
            raw_data=str(stats),
            tags=["virustotal", "domain", "analysis"],
        ))
        if timeout_e or failure_e:
            findings.append(IntelligenceFinding(
                entity=f"Engines timeout: {timeout_e}, failure: {failure_e}",
                type="VT Engine Status",
                source="VirusTotal Full",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Warning",
                tags=["virustotal", "engine-status"],
            ))

    categories = attrs.get("categories", {})
    if isinstance(categories, dict) and categories:
        seen_cats = set()
        for engine, cat in categories.items():
            if cat not in seen_cats:
                seen_cats.add(cat)
                findings.append(IntelligenceFinding(
                    entity=f"{cat} (by {engine})",
                    type="VT Category",
                    source="VirusTotal Full",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Categorized",
                    tags=["virustotal", "category"],
                ))

    rep = attrs.get("reputation", 0)
    if rep is not None:
        findings.append(IntelligenceFinding(
            entity=f"VT Reputation Score: {rep}",
            type="VT Reputation",
            source="VirusTotal Full",
            confidence="Medium",
            color="emerald" if rep >= 0 else "red",
            threat_level="Informational",
            status="Scored",
            resolution=f"Score: {rep} (community votes - {attrs.get('total_votes', {}).get('harmless', 0)} harmless / {attrs.get('total_votes', {}).get('malicious', 0)} malicious)",
            tags=["virustotal", "reputation"],
        ))

    last_analysis = attrs.get("last_analysis_results", {})
    if isinstance(last_analysis, dict):
        for category_name in ("malicious", "suspicious"):
            engines_list = [(k, v) for k, v in last_analysis.items()
                          if isinstance(v, dict) and v.get("category") == category_name]
            for engine, result in engines_list[:5]:
                findings.append(IntelligenceFinding(
                    entity=f"{engine}: {result.get('result', category_name)}",
                    type=f"VT {'Malicious' if category_name == 'malicious' else 'Suspicious'} Engine",
                    source="VirusTotal Full",
                    confidence="High",
                    color="red" if category_name == "malicious" else "orange",
                    threat_level="High Risk" if category_name == "malicious" else "Elevated Risk",
                    status="Flagged",
                    resolution=f"Engine: {engine}, Category: {category_name}",
                    raw_data=str(result),
                    tags=["virustotal", "engine", category_name],
                ))

    if attrs.get("last_modification_date"):
        from datetime import datetime, timezone
        lm = attrs["last_modification_date"]
        if isinstance(lm, (int, float)):
            lm_str = datetime.fromtimestamp(lm, tz=timezone.utc).isoformat()
            findings.append(IntelligenceFinding(
                entity=f"Last analysis: {lm_str}",
                type="VT Last Analysis Date",
                source="VirusTotal Full",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Timestamped",
                tags=["virustotal", "timeline"],
            ))

    if attrs.get("first_submission_date"):
        from datetime import datetime, timezone
        fs = attrs["first_submission_date"]
        if isinstance(fs, (int, float)):
            fs_str = datetime.fromtimestamp(fs, tz=timezone.utc).isoformat()
            findings.append(IntelligenceFinding(
                entity=f"First submission: {fs_str}",
                type="VT First Submission",
                source="VirusTotal Full",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Timestamped",
                tags=["virustotal", "timeline"],
            ))

    if attrs.get("times_submitted"):
        ts = attrs["times_submitted"]
        findings.append(IntelligenceFinding(
            entity=f"Submitted {ts} times",
            type="VT Submission Count",
            source="VirusTotal Full",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Counted",
            tags=["virustotal", "submissions"],
        ))


async def analyze_urls(domain: str, findings: list, client: httpx.AsyncClient):
    data = await _v3_get(client, f"/domains/{domain}/urls", timeout=20.0)
    if not data:
        html_data = await _public_vt_html(client, f"/domain/{domain}/urls/")
        if html_data and "detected_urls" in html_data:
            import re
            url_blocks = re.findall(
                r'(https?://[^"\'<>\s]+).*?(\d+)\s*/\s*(\d+)',
                html_data[:50000],
                re.IGNORECASE,
            )
            for url, detected, total in url_blocks[:10]:
                findings.append(IntelligenceFinding(
                    entity=url[:200],
                    type="VT URL Detection",
                    source="VirusTotal Full",
                    confidence="Medium",
                    color="red" if int(detected) > 0 else "emerald",
                    threat_level="High Risk" if int(detected) > 0 else "Informational",
                    status="Detected" if int(detected) > 0 else "Clean",
                    resolution=f"{detected}/{total} engines detected",
                    raw_data=f"URL: {url}",
                    tags=["virustotal", "url"],
                ))
        return

    urls_data = data.get("data", [])
    for item in urls_data[:15]:
        url_attrs = item.get("attributes", {})
        url_str = url_attrs.get("url", "")
        url_stats = url_attrs.get("last_analysis_stats", {})
        if url_stats:
            m = url_stats.get("malicious", 0)
            s = url_stats.get("suspicious", 0)
            findings.append(IntelligenceFinding(
                entity=f"URL: {url_str[:150]}",
                type="VT URL Scan",
                source="VirusTotal Full",
                confidence="Medium",
                color="red" if m > 0 else ("orange" if s > 0 else "emerald"),
                threat_level="High Risk" if m > 0 else ("Elevated Risk" if s > 0 else "Informational"),
                status="Compromised" if m > 0 else ("Suspicious" if s > 0 else "Clean"),
                resolution=f"Malicious: {m}, Suspicious: {s}",
                raw_data=f"URL: {url_str[:300]} | Stats: {url_stats}",
                tags=["virustotal", "url"],
            ))


async def analyze_files(domain: str, findings: list, client: httpx.AsyncClient):
    data = await _v3_get(client, f"/domains/{domain}/files", timeout=20.0)
    if not data:
        html_data = await _public_vt_html(client, f"/domain/{domain}/files/")
        if html_data:
            import re
            file_matches = re.findall(
                r'([a-fA-F0-9]{64}).*?(\d+)\s*/\s*(\d+)',
                html_data[:50000],
            )
            for sha256, detected, total in file_matches[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"File: {sha256[:16]}...",
                    type="VT Domain File Sample",
                    source="VirusTotal Full",
                    confidence="Medium",
                    color="red" if int(detected) > 0 else "emerald",
                    threat_level="High Risk" if int(detected) > 0 else "Informational",
                    status="Malicious" if int(detected) > 0 else "Clean",
                    resolution=f"{detected}/{total} engines",
                    raw_data=f"SHA256: {sha256}",
                    tags=["virustotal", "file", "sample"],
                ))
        return

    files_data = data.get("data", [])
    for item in files_data[:10]:
        fa = item.get("attributes", {})
        sha = fa.get("sha256", "")[:16]
        fs = fa.get("last_analysis_stats", {})
        m = fs.get("malicious", 0)
        meaningful_name = fa.get("meaningful_name", "")
        findings.append(IntelligenceFinding(
            entity=f"File: {meaningful_name or sha}... ({m} malicious)",
            type="VT Domain File Sample",
            source="VirusTotal Full",
            confidence="Medium",
            color="red" if m > 0 else "emerald",
            threat_level="High Risk" if m > 0 else "Informational",
            status="Malicious" if m > 0 else "Clean",
            resolution=f"Malicious: {m}, Type: {fa.get('type_description', 'Unknown')}",
            raw_data=f"SHA256: {fa.get('sha256', '')}",
            tags=["virustotal", "file"],
        ))


async def analyze_passive_dns(domain: str, findings: list, client: httpx.AsyncClient):
    data = await _v3_get(client, f"/domains/{domain}/resolutions", timeout=20.0)
    if not data:
        return

    resolutions = data.get("data", [])
    unique_ips = set()
    unique_asns = set()
    ip_countries = set()
    for item in resolutions[:50]:
        ra = item.get("attributes", {})
        ip = ra.get("ip_address", "")
        if ip:
            unique_ips.add(ip)
        asn = ra.get("asn", "")
        if asn:
            unique_asns.add(asn)
        country = ra.get("country", "")
        if country:
            ip_countries.add(country)

    if unique_ips:
        findings.append(IntelligenceFinding(
            entity=f"Passive DNS: {len(unique_ips)} unique IPs ({', '.join(list(unique_ips)[:6])}{'...' if len(unique_ips) > 6 else ''})",
            type="VT Passive DNS",
            source="VirusTotal Full",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status="Resolved",
            resolution=f"IPs: {', '.join(unique_ips)}",
            raw_data=f"Total resolutions: {len(resolutions)}, Unique IPs: {', '.join(unique_ips)}",
            tags=["virustotal", "passive-dns", "infrastructure"],
        ))
    if unique_asns:
        findings.append(IntelligenceFinding(
            entity=f"ASNs: {', '.join(unique_asns)}",
            type="VT ASN Info",
            source="VirusTotal Full",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Resolved",
            tags=["virustotal", "asn"],
        ))
    if ip_countries:
        findings.append(IntelligenceFinding(
            entity=f"IP Countries: {', '.join(sorted(ip_countries))}",
            type="VT Geo Distribution",
            source="VirusTotal Full",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Mapped",
            tags=["virustotal", "geo"],
        ))


async def analyze_detected_urls(domain: str, findings: list, client: httpx.AsyncClient):
    html = await _public_vt_html(client, f"/domain/{domain}/detected_urls/")
    if not html:
        return

    import re
    url_rows = re.findall(
        r'<a[^>]*href="(https?://[^"]+)"[^>]*>.*?</a>.*?(\d+)\s*/\s*(\d+)',
        html[:100000],
        re.DOTALL,
    )
    for url, detected, total in url_rows[:15]:
        findings.append(IntelligenceFinding(
            entity=url[:200],
            type="VT Detected URL",
            source="VirusTotal Full",
            confidence="Medium",
            color="red" if int(detected) > 0 else "emerald",
            threat_level="High Risk" if int(detected) > 0 else "Informational",
            status="Flagged" if int(detected) > 0 else "Clean",
            resolution=f"Detection: {detected}/{total}",
            raw_data=f"URL: {url}",
            tags=["virustotal", "detected-url"],
        ))


async def analyze_comments(domain: str, findings: list, client: httpx.AsyncClient):
    html = await _public_vt_html(client, f"/domain/{domain}/comments/")
    if not html:
        return

    import re
    comment_blocks = re.findall(
        r'<div[^>]*class="[^"]*comment[^"]*"[^>]*>(.*?)</div>',
        html[:100000],
        re.DOTALL,
    )
    for i, block in enumerate(comment_blocks[:5]):
        text = re.sub(r'<[^>]+>', ' ', block).strip()
        text = re.sub(r'\s+', ' ', text)[:200]
        if text:
            findings.append(IntelligenceFinding(
                entity=f"Comment by community: {text[:150]}",
                type="VT Community Comment",
                source="VirusTotal Full",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="Found",
                raw_data=text[:500],
                tags=["virustotal", "community", "comment"],
            ))

    if len(comment_blocks) > 5:
        findings.append(IntelligenceFinding(
            entity=f"... and {len(comment_blocks) - 5} more community comments",
            type="VT Community Comments Summary",
            source="VirusTotal Full",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="Summary",
            tags=["virustotal", "community"],
        ))


async def analyze_threat_classification(domain: str, findings: list, client: httpx.AsyncClient):
    html = await _public_vt_html(client, f"/domain/{domain}/")
    if not html:
        return

    import re
    threat_types = re.findall(
        r'(malware|phishing|spam|malicious|suspicious|trojan|ransomware|banker|dropper|downloader|exploit|botnet|C2|c\/c|command.{0,10}control)',
        html[:100000],
        re.IGNORECASE,
    )
    seen_types = set()
    for tt in threat_types:
        ttl = tt.lower()
        if ttl not in seen_types:
            seen_types.add(ttl)
            findings.append(IntelligenceFinding(
                entity=f"Threat classification: {tt}",
                type="VT Threat Classification",
                source="VirusTotal Full",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Classified",
                tags=["virustotal", "threat", "classification"],
            ))

    vendor_breakdown = {}
    vendor_sections = re.findall(
        r'([A-Za-z0-9_.]+)\s*\(?(\w+)\)?\s*:?\s*(clean|malicious|suspicious|unrated|timeout)',
        html[:150000],
        re.IGNORECASE,
    )
    for vendor, verdict in vendor_sections:
        vv = verdict.lower()
        vendor_breakdown[vv] = vendor_breakdown.get(vv, 0) + 1
    if vendor_breakdown:
        findings.append(IntelligenceFinding(
            entity=f"Vendor breakdown: {', '.join(f'{k}: {v}' for k, v in vendor_breakdown.items())}",
            type="VT Vendor Breakdown",
            source="VirusTotal Full",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            status="Analyzed",
            tags=["virustotal", "vendors"],
        ))


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        await analyze_domain(domain, findings, client)
        await analyze_urls(domain, findings, client)
        await analyze_files(domain, findings, client)
        await analyze_passive_dns(domain, findings, client)
        await analyze_detected_urls(domain, findings, client)
        await analyze_comments(domain, findings, client)
        await analyze_threat_classification(domain, findings, client)

        if not findings:
            findings.append(IntelligenceFinding(
                entity=f"No VirusTotal data available for {domain} (public API limited)",
                type="VT No Data",
                source="VirusTotal Full",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                status="No Data",
                tags=["virustotal", "no-data"],
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"VirusTotal full analysis complete: {len(findings)} findings",
                type="VT Summary",
                source="VirusTotal Full",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Complete",
                tags=["virustotal", "summary"],
            ))

    except Exception:
        pass
    return findings
