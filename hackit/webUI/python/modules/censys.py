import httpx, json
from typing import List
from urllib.parse import urlparse
from settings_store import get_api_key
from module_common import safe_fetch_json, safe_fetch, make_finding, is_ip

CENSYS_HOST = "https://search.censys.io/api/v2"
CENSYS_CERT = "https://search.censys.io/certificates"

async def crawl(target: str, client: httpx.AsyncClient) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    api_key = get_api_key("censys")
    if not api_key:
        return findings

    parts = api_key.split(":", 1)
    if len(parts) != 2:
        return findings
    uid, secret = parts
    auth = httpx.BasicAuth(uid, secret)

    host_data = await safe_fetch_json(client, f"{CENSYS_HOST}/hosts/{t}",
        auth=auth)
    if host_data and host_data.get("result"):
        result = host_data["result"]
        if result.get("services"):
            services = result["services"]
            findings.append(make_finding(
                entity=f"Censys: {len(services)} services found on {t}",
                ftype="Censys: Host Overview",
                source="Censys", confidence="High", color="blue",
                threat_level="Informational", status="Scanned",
                raw_data=json.dumps(services[:3]),
                tags=["censys", "host", "services"],
            ))
            for svc in services[:10]:
                port = svc.get("port", "?")
                service_name = svc.get("service_name", "?")
                transport = svc.get("transport_protocol", "?")
                findings.append(make_finding(
                    entity=f"{service_name}/{port} ({transport})",
                    ftype="Censys: Service",
                    source="Censys", confidence="High", color="slate",
                    threat_level="Informational", status="Discovered",
                    raw_data=f"port={port}, service={service_name}, transport={transport}",
                    tags=["censys", "service", f"port-{port}"],
                ))

        if result.get("location"):
            loc = result["location"]
            findings.append(make_finding(
                entity=f"{loc.get('city','?')}, {loc.get('country','?')}",
                ftype="Censys: Location",
                source="Censys", confidence="High", color="cyan",
                threat_level="Informational", status="Geolocated",
                tags=["censys", "location"],
            ))

        if result.get("autonomous_system"):
            asys = result["autonomous_system"]
            findings.append(make_finding(
                entity=f"AS{asys.get('asn','?')} - {asys.get('name','?')}",
                ftype="Censys: ASN",
                source="Censys", confidence="High", color="slate",
                threat_level="Informational", status="Identified",
                tags=["censys", "asn"],
            ))

    cert_data = await safe_fetch_json(client, f"{CENSYS_HOST}/certificates/search",
        params={"q": f"names: {t}", "per_page": 5}, auth=auth)
    if cert_data and cert_data.get("result"):
        hits = cert_data["result"].get("hits", [])
        if hits:
            findings.append(make_finding(
                entity=f"Censys: {len(hits)} certificates found for {t}",
                ftype="Censys: Certificate Overview",
                source="Censys", confidence="High", color="slate",
                threat_level="Informational", status="Discovered",
                tags=["censys", "certificate"],
            ))
            for cert in hits[:5]:
                names = cert.get("names", [])
                issuer = cert.get("issuer", {}).get("common_name", "?")
                fingerprint = cert.get("fingerprint_sha256", "")[:20]
                findings.append(make_finding(
                    entity=f"Cert: {', '.join(names[:3])} (Issuer: {issuer})",
                    ftype="Censys: Certificate",
                    source="Censys", confidence="High", color="slate",
                    threat_level="Informational", status="Registered",
                    raw_data=f"fingerprint={fingerprint}, issuer={issuer}",
                    tags=["censys", "certificate", "ssl"],
                ))

    return findings
