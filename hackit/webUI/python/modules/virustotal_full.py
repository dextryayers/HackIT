from typing import List
import httpx
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding
from settings_store import get_api_key

VT_API = "https://www.virustotal.com/api/v3"
VT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

REVIEWED_HASHES = set()

async def vt_get(endpoint: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await safe_fetch(client,
            f"{VT_API}/{endpoint}",
            headers={"User-Agent": VT_UA, "Accept": "application/json", "x-apikey": get_api_key("virustotal")},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

async def vt_ip_resolutions(ip: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"ip_addresses/{ip}/resolutions", client)

async def vt_ip_historical_whois(ip: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"ip_addresses/{ip}/historical_whois", client)

async def vt_domain_subdomains(domain: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"domains/{domain}/subdomains", client)

async def vt_domain_resolutions(domain: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"domains/{domain}/resolutions", client)

async def vt_url_relations(url_id: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"urls/{url_id}/relations", client)

async def vt_url_analyse(url: str, client: httpx.AsyncClient) -> dict:
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await vt_get(f"urls/{url_id}/analyses", client)
    except:
        pass
    return {}

async def vt_related_hashes(domain: str, client: httpx.AsyncClient) -> dict:
    return await vt_get(f"domains/{domain}/related_files", client)

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()

    target_is_ip = is_ip(t)

    if target_is_ip:
        res_data = await vt_ip_resolutions(t, client)
        resolutions = res_data.get("data", [])
        if resolutions:
            findings.append(make_finding(
                entity=f"DNS resolutions: {len(resolutions)} historical records",
                ftype="VT IP Resolutions",
                source="VirusTotal (Full)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["virustotal", "resolutions"]
            ))
            for res in resolutions[:5]:
                attrs = res.get("attributes", {})
                hostname = attrs.get("host_name", "unknown")
                date = attrs.get("date", "")
                findings.append(make_finding(
                    entity=f"Resolution: {hostname} ({date})",
                    ftype="VT IP Resolution Detail",
                    source="VirusTotal (Full)",
                    confidence="Medium",
                    color="slate",
                    status="Resolved",
                    resolution=t,
                    tags=["virustotal", "resolution"]
                ))

        whois_data = await vt_ip_historical_whois(t, client)
        data = whois_data.get("data", [])
        if data:
            findings.append(make_finding(
                entity=f"Historical WHOIS: {len(data)} records",
                ftype="VT IP WHOIS",
                source="VirusTotal (Full)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["virustotal", "whois"]
            ))
            for entry in data[:3]:
                findings.append(make_finding(
                    entity=f"WHOIS: {str(entry.get('attributes', {}))[:200]}",
                    ftype="VT IP WHOIS Detail",
                    source="VirusTotal (Full)",
                    confidence="Medium",
                    color="slate",
                    status="Found",
                    resolution=t,
                    tags=["virustotal", "whois"]
                ))

    else:
        sub_data = await vt_domain_subdomains(t, client)
        subdomains = sub_data.get("data", [])
        if subdomains:
            findings.append(make_finding(
                entity=f"Subdomains: {len(subdomains)} found",
                ftype="VT Subdomain Discovery",
                source="VirusTotal (Full)",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["virustotal", "subdomains"]
            ))
            for sub in subdomains[:5]:
                attrs = sub.get("attributes", {})
                sub_id = attrs.get("id", str(sub)[:100])
                findings.append(make_finding(
                    entity=f"Subdomain: {sub_id}",
                    ftype="VT Subdomain Detail",
                    source="VirusTotal (Full)",
                    confidence="Medium",
                    color="slate",
                    status="Found",
                    resolution=t,
                    tags=["virustotal", "subdomain"]
                ))

        res_data = await vt_domain_resolutions(t, client)
        resolutions = res_data.get("data", [])
        if resolutions:
            findings.append(make_finding(
                entity=f"Domain resolutions: {len(resolutions)} IP records",
                ftype="VT Domain Resolutions",
                source="VirusTotal (Full)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["virustotal", "domain-resolutions"]
            ))
            for res in resolutions[:5]:
                attrs = res.get("attributes", {})
                ip_addr = attrs.get("ip_address", "unknown")
                date = attrs.get("date", "")
                findings.append(make_finding(
                    entity=f"Resolved IP: {ip_addr} ({date})",
                    ftype="VT Resolution Detail",
                    source="VirusTotal (Full)",
                    confidence="Medium",
                    color="slate",
                    status="Resolved",
                    resolution=t,
                    tags=["virustotal", "resolution"]
                ))

        related_files = await vt_related_hashes(t, client)
        files_data = related_files.get("data", [])
        if files_data:
            findings.append(make_finding(
                entity=f"Related files: {len(files_data)} samples",
                ftype="VT Related Files",
                source="VirusTotal (Full)",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                status="Available",
                resolution=t,
                tags=["virustotal", "related-files"]
            ))
            for f in files_data[:5]:
                attrs = f.get("attributes", {})
                fhash = attrs.get("sha256", "")[:16]
                det = attrs.get("last_analysis_stats", {}).get("malicious", 0)
                findings.append(make_finding(
                    entity=f"Related file {fhash}... (det: {det})",
                    ftype="VT Related File Detail",
                    source="VirusTotal (Full)",
                    confidence="Medium",
                    color="orange" if det > 0 else "slate",
                    threat_level="Elevated Risk" if det > 0 else "Informational",
                    status="Found",
                    resolution=t,
                    tags=["virustotal", "related-file"]
                ))

    try:
        import base64
        url_id = base64.urlsafe_b64encode(t.encode()).decode().rstrip("=")
        rel_data = await vt_url_relations(url_id, client)
        relations = rel_data.get("data", [])
        if relations:
            findings.append(make_finding(
                entity=f"URL relations: {len(relations)} connected entities",
                ftype="VT URL Relations",
                source="VirusTotal (Full)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Available",
                resolution=t,
                tags=["virustotal", "relations"]
            ))
            for rel in relations[:5]:
                findings.append(make_finding(
                    entity=f"Relation: {str(rel.get('attributes', {}).get('id', str(rel)))[:150]}",
                    ftype="VT URL Relation Detail",
                    source="VirusTotal (Full)",
                    confidence="Low",
                    color="slate",
                    status="Found",
                    resolution=t,
                    tags=["virustotal", "relation"]
                ))
    except:
        pass

    if not findings:
        findings.append(make_finding(
            entity="No VirusTotal full intelligence data available",
            ftype="VT Full Check Complete",
            source="VirusTotal (Full)",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["virustotal", "empty"]
        ))

    return findings
