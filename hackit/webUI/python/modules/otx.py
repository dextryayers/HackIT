import httpx
import asyncio
from models import IntelligenceFinding

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


async def _query_url_list(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/url_list?limit=100",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            urls = data.get("url_list", [])
            for entry in urls[:30]:
                url = entry.get("url", "")
                if url:
                    findings.append(IntelligenceFinding(
                        entity=url[:200],
                        type="OTX: Associated URL",
                        source="AlienVault OTX",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["otx", "url"],
                        raw_data=url[:500],
                    ))
            if urls:
                findings.append(IntelligenceFinding(
                    entity=f"{len(urls)} URLs associated in OTX",
                    type="OTX: URL Summary",
                    source="AlienVault OTX",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    tags=["otx", "summary"],
                ))
    except Exception:
        pass
    return findings


async def _query_passive_dns(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/passive_dns",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            records = data.get("passive_dns", [])
            for entry in records[:30]:
                host = entry.get("hostname", "")
                ip = entry.get("address", "")
                first = entry.get("first", "")
                last = entry.get("last", "")
                record_type = entry.get("record_type", "A")
                if host and (not host.endswith(domain)):
                    continue
                tags = ["otx", "passive-dns"]
                if first:
                    tags.append(f"first:{first[:10]}")
                if last:
                    tags.append(f"last:{last[:10]}")
                findings.append(IntelligenceFinding(
                    entity=host,
                    type=f"OTX: Passive DNS ({record_type})",
                    source="AlienVault OTX",
                    confidence="High",
                    color="emerald",
                    resolution=ip or "",
                    threat_level="Informational",
                    tags=tags,
                    raw_data=f"IP: {ip}, First: {first}, Last: {last}",
                ))
            if records:
                findings.append(IntelligenceFinding(
                    entity=f"{len(records)} passive DNS records for {domain}",
                    type="OTX: Passive DNS Summary",
                    source="AlienVault OTX",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    tags=["otx", "summary"],
                ))
    except Exception:
        pass
    return findings


async def _query_geo(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/geo",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            geo = resp.json()
            if isinstance(geo, dict):
                field_map = {
                    "country_code": ("OTX: Country Code", "slate"),
                    "country_name": ("OTX: Country", "slate"),
                    "city": ("OTX: City", "slate"),
                    "latitude": ("OTX: Latitude", "slate"),
                    "longitude": ("OTX: Longitude", "slate"),
                    "asn": ("OTX: ASN", "orange"),
                }
                for k, (ftype, color) in field_map.items():
                    v = geo.get(k)
                    if v:
                        findings.append(IntelligenceFinding(
                            entity=str(v)[:100],
                            type=ftype,
                            source="AlienVault OTX",
                            confidence="High",
                            color=color,
                            threat_level="Informational",
                            tags=["otx", "geo"],
                        ))
    except Exception:
        pass
    return findings


async def _query_malware(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/malware",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            samples = data.get("data", [])
            if samples:
                findings.append(IntelligenceFinding(
                    entity=f"{len(samples)} malware samples associated with {domain}",
                    type="OTX: Malware Association",
                    source="AlienVault OTX",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["otx", "malware"],
                    raw_data=str(samples[:5]),
                ))
                for sample in samples[:10]:
                    sha256 = sample.get("sha256", "")
                    date = sample.get("date", "")
                    malware_family = sample.get("malware_family", "")
                    if sha256:
                        tags = ["otx", "malware", "sample"]
                        if malware_family:
                            tags.append(f"family:{malware_family}")
                        findings.append(IntelligenceFinding(
                            entity=f"Malware sample: {sha256[:16]}...",
                            type="OTX: Malware Sample",
                            source="AlienVault OTX",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            tags=tags,
                            raw_data=f"SHA256: {sha256}, Date: {date}, Family: {malware_family}",
                        ))
    except Exception:
        pass
    return findings


async def _query_file_samples(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/file",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            samples = data.get("data", [])
            if samples:
                findings.append(IntelligenceFinding(
                    entity=f"{len(samples)} file samples associated with {domain}",
                    type="OTX: File Samples",
                    source="AlienVault OTX",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["otx", "file-sample"],
                    raw_data=str(samples[:3]),
                ))
    except Exception:
        pass
    return findings


async def _query_whois(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/whois",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                whois_fields = {
                    "registrar": "OTX: Whois Registrar",
                    "org": "OTX: Whois Organization",
                    "name": "OTX: Whois Name",
                    "email": "OTX: Whois Email",
                    "city": "OTX: Whois City",
                    "country": "OTX: Whois Country",
                    "phone": "OTX: Whois Phone",
                }
                for field, ftype in whois_fields.items():
                    val = data.get(field)
                    if val:
                        findings.append(IntelligenceFinding(
                            entity=str(val)[:200],
                            type=ftype,
                            source="AlienVault OTX",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            tags=["otx", "whois"],
                        ))
    except Exception:
        pass
    return findings


async def _query_subdomains(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/subdomains",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            subs = data.get("subdomains", []) if isinstance(data, dict) else data
            if isinstance(subs, list) and subs:
                findings.append(IntelligenceFinding(
                    entity=f"{len(subs)} subdomains from OTX",
                    type="OTX: Subdomains",
                    source="AlienVault OTX",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["otx", "subdomain"],
                    raw_data=", ".join(subs[:20]),
                ))
    except Exception:
        pass
    return findings


async def _query_cve(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/cve",
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            cves = data.get("data", []) if isinstance(data, dict) else []
            if cves:
                findings.append(IntelligenceFinding(
                    entity=f"{len(cves)} CVEs associated with {domain}",
                    type="OTX: CVE Correlations",
                    source="AlienVault OTX",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["otx", "cve", "vulnerability"],
                    raw_data=str(cves[:5]),
                ))
                for cve in cves[:10]:
                    if isinstance(cve, str):
                        findings.append(IntelligenceFinding(
                            entity=cve,
                            type="OTX: CVE Reference",
                            source="AlienVault OTX",
                            confidence="Medium",
                            color="orange",
                            threat_level="High Risk",
                            tags=["otx", "cve"],
                        ))
    except Exception:
        pass
    return findings


async def _query_pulses(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"{OTX_BASE}/domain/{domain}/pulses",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get("results", []) if isinstance(data, dict) else []
            if not pulses:
                pulses = data if isinstance(data, list) else []
            if pulses:
                findings.append(IntelligenceFinding(
                    entity=f"{len(pulses)} OTX pulses referencing {domain}",
                    type="OTX: Pulse Intelligence",
                    source="AlienVault OTX",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    tags=["otx", "pulse", "threat-intel"],
                ))
                for pulse in pulses[:10]:
                    if isinstance(pulse, dict):
                        name = pulse.get("name", "")
                        description = pulse.get("description", "")[:200]
                        author = pulse.get("author", {}).get("username", "Unknown")
                        created = pulse.get("created", "")
                        tags = pulse.get("tags", [])
                        findings.append(IntelligenceFinding(
                            entity=f"Pulse: {name[:100]}",
                            type="OTX: Threat Pulse",
                            source="AlienVault OTX",
                            confidence="Medium",
                            color="orange",
                            threat_level="Elevated Risk",
                            tags=["otx", "pulse", author] + (tags[:3] if tags else []),
                            raw_data=f"Author: {author}, Created: {created}, Desc: {description}",
                        ))
    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    results = await asyncio.gather(
        _query_url_list(domain, client),
        _query_passive_dns(domain, client),
        _query_geo(domain, client),
        _query_malware(domain, client),
        _query_file_samples(domain, client),
        _query_whois(domain, client),
        _query_subdomains(domain, client),
        _query_cve(domain, client),
        _query_pulses(domain, client),
        return_exceptions=True,
    )

    for res in results:
        if isinstance(res, list):
            findings.extend(res)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"OTX intelligence complete: {len(findings)} total findings for {domain}",
            type="OTX Summary",
            source="AlienVault OTX",
            confidence="High",
            color="purple",
            threat_level="Informational",
            tags=["otx", "summary"],
        ))

    return findings
