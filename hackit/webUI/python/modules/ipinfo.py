import httpx
from typing import List
from settings_store import get_api_key
from module_common import safe_fetch_json, make_finding, is_ip

IPINFO_API = "https://ipinfo.io"

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    t = target.strip().lower()
    if is_ip(t):
        ip = t
    else:
        import socket
        try:
            ip = socket.gethostbyname(t)
        except OSError:
            return findings

    api_key = get_api_key("ipinfo")
    params = {"token": api_key} if api_key else {}

    data = await safe_fetch_json(client, f"{IPINFO_API}/{ip}", params=params)
    if not data:
        return findings

    if data.get("ip"):
        findings.append(make_finding(
            entity=f"IP: {data['ip']} ({data.get('hostname','?')})",
            ftype="IPInfo: Geolocation",
            source="IPInfo",
            confidence="High", color="cyan",
            threat_level="Informational", status="Geolocated",
            raw_data=f"city={data.get('city')}, region={data.get('region')}, country={data.get('country')}, loc={data.get('loc')}",
            tags=["ipinfo", "geo", "ip"],
        ))

    if data.get("org"):
        org_parts = data["org"].split(" ", 1)
        asn = org_parts[0] if len(org_parts) > 0 else ""
        org_name = org_parts[1] if len(org_parts) > 1 else data["org"]
        findings.append(make_finding(
            entity=f"{org_name} ({asn})",
            ftype="IPInfo: Organization",
            source="IPInfo", confidence="High", color="slate",
            threat_level="Informational", status="Identified",
            tags=["ipinfo", "asn", "org"],
        ))

    if data.get("company"):
        comp = data["company"]
        findings.append(make_finding(
            entity=comp.get("name", "?"),
            ftype="IPInfo: Company",
            source="IPInfo", confidence="Medium", color="slate",
            threat_level="Informational", status="Registered",
            raw_data=f"domain={comp.get('domain','')}, type={comp.get('type','')}",
            tags=["ipinfo", "company"],
        ))

    if data.get("privacy"):
        priv = data["privacy"]
        if priv.get("vpn") or priv.get("proxy") or priv.get("tor") or priv.get("hosting"):
            findings.append(make_finding(
                entity=f"VPN={priv.get('vpn')} Proxy={priv.get('proxy')} TOR={priv.get('tor')} Hosting={priv.get('hosting')}",
                ftype="IPInfo: Privacy Detection",
                source="IPInfo", confidence="High", color="orange",
                threat_level="Elevated Risk", status="Detected",
                tags=["ipinfo", "privacy", "vpn", "proxy"],
            ))

    if data.get("abuse"):
        abuse = data["abuse"]
        findings.append(make_finding(
            entity=f"Abuse Contact: {abuse.get('email','?')}",
            ftype="IPInfo: Abuse Contact",
            source="IPInfo", confidence="Medium", color="slate",
            threat_level="Informational", status="Discovered",
            tags=["ipinfo", "abuse"],
        ))

    if data.get("asn"):
        asn_data = data["asn"]
        findings.append(make_finding(
            entity=f"AS{asn_data.get('asn','?')} - {asn_data.get('name','?')} ({asn_data.get('domain','?')})",
            ftype="IPInfo: ASN Detail",
            source="IPInfo", confidence="High", color="slate",
            threat_level="Informational", status="Identified",
            raw_data=f"route={asn_data.get('route','')}, type={asn_data.get('type','')}",
            tags=["ipinfo", "asn"],
        ))

    if not findings:
        findings.append(make_finding(
            entity=f"No IPInfo data for {t}",
            ftype="IPInfo: No Data",
            source="IPInfo", confidence="Low", color="emerald",
            threat_level="Informational", status="Empty",
            tags=["ipinfo", "empty"],
        ))

    return findings
