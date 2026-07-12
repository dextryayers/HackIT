import asyncio
import re
import socket
from datetime import datetime
from typing import List, Optional
from collections import defaultdict
from module_common import safe_fetch, make_finding, is_ip, resolve_ip

CDN_PROVIDERS = {
    "Cloudflare": ["cloudflare.com", "cdn.cloudflare.net", "cloudflare.net"],
    "Akamai": ["akamai.net", "akamaiedge.net", "akamaitechnologies.com"],
    "Fastly": ["fastly.net", "fastlylb.net"],
    "CloudFront": ["cloudfront.net", "amazonaws.com"],
    "CloudFlare": ["cloudflare.com", "cdn.cloudflare.net"],
    "StackPath": ["stackpathcdn.com", "stackpath.com"],
    "KeyCDN": ["keycdn.com", "kxcdn.com"],
    "Google Cloud CDN": ["googleusercontent.com", "gstatic.com", "googleapis.com"],
    "Microsoft Azure CDN": ["azureedge.net", "azure.com", "msftncsi.com"],
    "OVH CDN": ["ovh.net", "ovhcdn.com"],
    "BunnyCDN": ["bunnycdn.com", "b-cdn.net"],
    "CacheFly": ["cachefly.net", "cachefly.com"],
}

async def trace_asn(ip: str, client) -> Optional[dict]:
    try:
        resp = await safe_fetch(client, f"https://ipinfo.io/{ip}/json", timeout=10.0)
        if resp and resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

async def bgp_route(ip: str, client) -> Optional[dict]:
    try:
        resp = await safe_fetch(client, f"https://bgp.he.net/ip/{ip}", timeout=10.0)
        if resp and resp.status_code == 200:
            return {"html": resp.text[:2000]}
    except:
        pass
    return None

async def detect_cdn(domain: str, client) -> list:
    results = []
    try:
        resp = await safe_fetch(client, f"https://{domain}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp and resp.status_code in (200, 301, 302):
            headers = dict(resp.headers)
            server = headers.get("Server", "")
            via = headers.get("Via", "")
            cf_ray = headers.get("cf-ray", "")
            x_cache = headers.get("X-Cache", "")

            for provider, domains in CDN_PROVIDERS.items():
                for d in domains:
                    if d.lower() in server.lower() or d.lower() in via.lower():
                        results.append(provider)
                        break
            if cf_ray:
                results.append("Cloudflare")
            if x_cache:
                results.append(f"CDN with caching ({x_cache})")
    except:
        pass
    return results

ADDITIONAL_CDN_PROVIDERS = {
    "Imperva": ["incapsula.com", "imperva.com"],
    "Sucuri": ["sucuri.net", "sucuri.cloud"],
    "Cloudbric": ["cloudbric.com"],
    "BelugaCDN": ["belugacdn.com"],
    "CDN77": ["cdn77.com", "cdn77.org"],
    "CDNetworks": ["cdnetworks.com"],
    "CDNSun": ["cdnsun.com"],
    "Comcast CDN": ["comcast.net"],
    "DDos-Guard": ["ddos-guard.net"],
    "Deflect": ["deflect.ca"],
    "Distil Networks": ["distilnetworks.com"],
    "Edgecast": ["edgecast.com", "edgecastcdn.net"],
    "Facebook CDN": ["fbcdn.net"],
    "Fastly": ["fastly.com", "fastly.net"],
    "G-Core CDN": ["gcorelabs.com"],
    "Highwinds": ["hwcdn.net"],
    "Hostry CDN": ["hostry.com"],
    "Instart": ["instart.com"],
    "KeyCDN": ["keycdn.com"],
    "LeaseWeb CDN": ["leaseweb.com"],
    "Level3": ["level3.com"],
    "Limelight": ["limelight.com", "llnw.com", "llnwd.net"],
    "MaxCDN": ["maxcdn.com", "netdna.com"],
    "Mirror Image": ["mirror-image.com"],
    "Myra Security": ["myracloud.com"],
    "Netlify": ["netlify.com"],
    "NYI CDN": ["nyi.net"],
    "OnApp": ["onapp.com"],
    "Peer5": ["peer5.com"],
    "Pivot CDN": ["pivotcdn.com"],
    "Port CDN": ["portcdn.com"],
    "PowerCDN": ["powercdn.com"],
    "Publiusive": ["publiusive.com"],
    "Quantil": ["quantil.com"],
    "QuickPack": ["quickpack.com"],
    "Reflected Networks": ["reflected.net"],
    "Rocket CDN": ["rocketcdn.com"],
    "Section.io": ["section.io"],
    "ServerCDN": ["servercdn.net"],
    "Singular CDN": ["singularcdn.com"],
    "SkyCDN": ["skycdn.net"],
    "SnapCDN": ["snapcdn.com"],
    "StackCache": ["stackcache.com"],
    "Stream CDN": ["streamcdn.com"],
    "SwiftCDN": ["swiftcdn.com"],
    "Tata CDN": ["tatacdn.com"],
    "Transparent CDN": ["transparentcdn.com"],
    "Turbobytes": ["turbobytes.com"],
    "Varnish CDN": ["varnish.com", "varnish-cache.com"],
    "VoxCDN": ["voxcdn.com"],
    "Wingify": ["wingify.com"],
    "Wowza CDN": ["wowza.com"],
    "Yahoo CDN": ["yimg.com"],
    "Yandex CDN": ["yandex.net"],
    "Zenedge": ["zenedge.com"],
}

ALL_CDN_PROVIDERS = {**CDN_PROVIDERS, **ADDITIONAL_CDN_PROVIDERS}

async def check_tls_certificate(domain: str, client) -> list:
    findings = []
    try:
        import ssl
        import socket as sock
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock.socket()) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "")
                issuer = dict(x[0] for x in cert.get("issuer", []))
                org = issuer.get("organizationName", "")
                expires = cert.get("notAfter", "")
                serial = str(cert.get("serialNumber", ""))
                findings.append(make_finding(
                    f"TLS cert: CN={cn}, issuer={org}, expires={expires[:10]}",
                    ftype="Network Topology: TLS Certificate",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="slate",
                    status="Cert Retrieved",
                    resolution=domain,
                    tags=["network", "tls", "certificate"]
                ))
                san = cert.get("subjectAltName", [])
                if san:
                    names = [x[1] for x in san if x[0] == "DNS"]
                    findings.append(make_finding(
                        f"TLS SAN: {', '.join(names[:5])}",
                        ftype="Network Topology: TLS SAN",
                        source="NetworkTopologyMapper",
                        confidence="High",
                        color="slate",
                        status="SAN Retrieved",
                        resolution=domain,
                        tags=["network", "tls", "san"]
                    ))
    except:
        pass
    return findings

async def check_load_balancer(domain: str, client) -> list:
    findings = []
    lb_headers = ["x-load-balancer", "x-lb", "x-forwarded-for", "x-forwarded-host",
                  "x-forwarded-proto", "x-real-ip", "x-originating-ip", "x-nuxt-load-balancer"]
    try:
        resp = await safe_fetch(client, f"https://{domain}", timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp:
            headers = dict(resp.headers)
            for h in lb_headers:
                if h in {k.lower() for k in headers}:
                    findings.append(make_finding(
                        f"Load balancer header present: {h}",
                        ftype="Network Topology: Load Balancer",
                        source="NetworkTopologyMapper",
                        confidence="Medium",
                        color="slate",
                        status="Detected",
                        resolution=domain,
                        tags=["network", "load-balancer", h]
                    ))
    except:
        pass
    return findings

async def crawl(target: str, client) -> List:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    resolved = resolve_ip(t)
    if resolved:
        ip = resolved[0]
        findings.append(make_finding(
            f"{t} resolves to {ip}",
            ftype="Network Topology: DNS Resolution",
            source="NetworkTopologyMapper",
            confidence="High",
            color="slate",
            status="Resolved",
            resolution=t,
            tags=["network", "dns", "resolution"]
        ))

        asn_data = await trace_asn(ip, client)
        if asn_data:
            asn = asn_data.get("org", "")
            if asn:
                findings.append(make_finding(
                    f"ASN/ISP: {asn}",
                    ftype="Network Topology: ASN Discovery",
                    source="NetworkTopologyMapper",
                    confidence="High",
                    color="slate",
                    status="Identified",
                    resolution=t,
                    tags=["network", "asn", "isp"]
                ))

    cdns = await detect_cdn(t, client)
    if cdns:
        for cdn in cdns[:5]:
            findings.append(make_finding(
                f"CDN: {cdn}",
                ftype="Network Topology: CDN Detection",
                source="NetworkTopologyMapper",
                confidence="High",
                color="slate",
                status="Identified",
                resolution=t,
                tags=["network", "cdn", cdn.lower().replace(" ", "-")]
            ))

    tls_results = await check_tls_certificate(t, client)
    findings.extend(tls_results)

    lb_results = await check_load_balancer(t, client)
    findings.extend(lb_results)

    bgp_data = await bgp_route(t, client)
    if bgp_data:
        findings.append(make_finding(
            "BGP routing data available",
            ftype="Network Topology: BGP Route",
            source="NetworkTopologyMapper",
            confidence="Low",
            color="slate",
            status="Available",
            resolution=t,
            tags=["network", "bgp", "routing"]
        ))

    if not findings:
        findings.append(make_finding(
            "No network topology data found",
            ftype="Network Topology: Complete",
            source="NetworkTopologyMapper",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Not Found",
            resolution=t,
            tags=["network", "empty"]
        ))

    return findings
