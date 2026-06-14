import httpx
import json
from models import IntelligenceFinding

ZOOMEYE_API = "https://api.zoomeye.org"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    resolved_ips = set()

    try:
        dns_resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT}
        )
        if dns_resp.status_code == 200:
            dns_data = dns_resp.json()
            for answer in dns_data.get("Answer", []):
                if answer.get("type") == 1:
                    ip = answer.get("data", "")
                    if ip:
                        resolved_ips.add(ip)
                        findings.append(IntelligenceFinding(
                            entity=ip,
                            type="Resolved IP",
                            source="ZoomEye",
                            confidence="High",
                            color="blue",
                            threat_level="Informational",
                            status="Resolved",
                            resolution=ip,
                            raw_data=f"DNS A record: {domain} -> {ip}",
                            tags=["dns", "resolution"]
                        ))
    except Exception:
        pass

    try:
        host_search_url = f"{ZOOMEYE_API}/host/search"
        params = {"query": f"domain:{domain}", "page": 1, "size": 20}
        host_resp = await client.get(
            host_search_url,
            params=params,
            timeout=20.0,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json"
            }
        )
        if host_resp.status_code == 200:
            host_data = host_resp.json()
            matches = host_data.get("matches", [])
            total_matches = host_data.get("total", len(matches))

            for match in matches[:20]:
                ip = match.get("ip", "")
                port = match.get("portinfo", {}).get("port", "")
                protocol = match.get("portinfo", {}).get("protocol", "")
                service = match.get("portinfo", {}).get("service", "")
                app = match.get("portinfo", {}).get("app", "")
                banner = match.get("portinfo", {}).get("banner", "")
                os_name = match.get("portinfo", {}).get("os", "")
                hostname = match.get("portinfo", {}).get("hostname", "")
                country = match.get("geoinfo", {}).get("country", {}).get("name", "")
                city = match.get("geoinfo", {}).get("city", {}).get("name", "")
                continent = match.get("geoinfo", {}).get("continent", {}).get("name", "")
                asn = match.get("geoinfo", {}).get("asn", "")
                org = match.get("geoinfo", {}).get("organization", "")

                if ip:
                    resolved_ips.add(ip)

                if ip and port:
                    tags_list = ["zoomeye", "host"]
                    if service:
                        tags_list.append(service.lower().replace(" ", "-"))
                    if protocol:
                        tags_list.append(protocol.lower())

                    raw_parts = []
                    if service:
                        raw_parts.append(f"Service: {service}")
                    if app:
                        raw_parts.append(f"App: {app}")
                    if banner:
                        raw_parts.append(f"Banner: {banner[:100]}")
                    if os_name:
                        raw_parts.append(f"OS: {os_name}")
                    if country:
                        raw_parts.append(f"Country: {country}")

                    findings.append(IntelligenceFinding(
                        entity=f"{ip}:{port} ({service or protocol or 'unknown'})",
                        type="ZoomEye Host Service",
                        source="ZoomEye",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        status="Discovered",
                        resolution=ip,
                        raw_data=" | ".join(raw_parts) if raw_parts else json.dumps(match.get("portinfo", {}), default=str)[:500],
                        tags=tags_list
                    ))

                if app:
                    findings.append(IntelligenceFinding(
                        entity=f"{app} on {ip}:{port}",
                        type="Technology / Application",
                        source="ZoomEye",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"App: {app} | Port: {port} | Protocol: {protocol}",
                        tags=["technology", "application"]
                    ))

                if banner:
                    banner_truncated = banner[:200]
                    findings.append(IntelligenceFinding(
                        entity=f"Banner: {banner_truncated}",
                        type="Service Banner",
                        source="ZoomEye",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"Banner [{ip}:{port}]: {banner[:500]}",
                        tags=["banner"]
                    ))

                if os_name:
                    findings.append(IntelligenceFinding(
                        entity=f"{os_name} on {ip}",
                        type="Operating System",
                        source="ZoomEye",
                        confidence="Medium",
                        color="cyan",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"OS: {os_name} | IP: {ip}",
                        tags=["os"]
                    ))

                if country or city:
                    location = f"{city}, {country}" if city and country else (country or city)
                    findings.append(IntelligenceFinding(
                        entity=location,
                        type="Host Location",
                        source="ZoomEye",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"Location: {location} | Continent: {continent}",
                        tags=["geo", "location"]
                    ))

                if asn or org:
                    entity = f"{org} ({asn})" if org and asn else (org or asn)
                    findings.append(IntelligenceFinding(
                        entity=entity[:200],
                        type="ASN / Organization",
                        source="ZoomEye",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"ASN: {asn} | Org: {org}",
                        tags=["network", "asn"]
                    ))

                if service:
                    findings.append(IntelligenceFinding(
                        entity=f"{service} on {ip}:{port}",
                        type="Detected Service",
                        source="ZoomEye",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"Service: {service} | Protocol: {protocol} | Port: {port}",
                        tags=["service", protocol.lower() if protocol else ""]
                    ))

            if len(matches) > 20:
                findings.append(IntelligenceFinding(
                    entity=f"{total_matches} total ZoomEye host results for {domain} (showing 20)",
                    type="ZoomEye Host Results Summary",
                    source="ZoomEye",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Complete",
                    raw_data=f"Total: {total_matches} | Displayed: 20",
                    tags=["zoomeye", "summary"]
                ))
            elif matches:
                findings.append(IntelligenceFinding(
                    entity=f"{len(matches)} ZoomEye host results for {domain}",
                    type="ZoomEye Host Results Summary",
                    source="ZoomEye",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Complete",
                    raw_data=f"Total: {len(matches)}",
                    tags=["zoomeye", "summary"]
                ))

        elif host_resp.status_code == 401:
            findings.append(IntelligenceFinding(
                entity="ZoomEye API requires authentication (HTTP 401)",
                type="ZoomEye API Error",
                source="ZoomEye",
                confidence="High",
                color="red",
                threat_level="Informational",
                status="Unauthorized",
                tags=["error", "auth"]
            ))
        elif host_resp.status_code == 403:
            findings.append(IntelligenceFinding(
                entity="ZoomEye API access forbidden (HTTP 403)",
                type="ZoomEye API Error",
                source="ZoomEye",
                confidence="High",
                color="red",
                threat_level="Informational",
                status="Forbidden",
                tags=["error", "auth"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"ZoomEye host API error: {str(e)[:100]}",
            type="ZoomEye API Error",
            source="ZoomEye",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))

    try:
        web_search_url = f"{ZOOMEYE_API}/web/search"
        web_params = {"query": f"domain:{domain}", "page": 1, "size": 20}
        web_resp = await client.get(
            web_search_url,
            params=web_params,
            timeout=20.0,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json"
            }
        )
        if web_resp.status_code == 200:
            web_data = web_resp.json()
            web_matches = web_data.get("matches", [])
            web_total = web_data.get("total", len(web_matches))

            site_count = 0
            for site in web_matches[:15]:
                site_ip = site.get("ip", "")
                site_url = site.get("url", "")
                site_title = site.get("title", "")
                site_server = site.get("server", "")
                site_country = site.get("country", "")
                site_city = site.get("city", "")
                site_asn = site.get("asn", "")
                site_org = site.get("organization", "")

                if site_ip:
                    resolved_ips.add(site_ip)

                if site_url:
                    site_count += 1
                    findings.append(IntelligenceFinding(
                        entity=site_url[:200],
                        type="ZoomEye Web Site",
                        source="ZoomEye",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        resolution=site_ip,
                        raw_data=f"URL: {site_url} | Title: {site_title} | Server: {site_server}",
                        tags=["web", "site"]
                    ))

                if site_title:
                    findings.append(IntelligenceFinding(
                        entity=f"Title: {site_title[:200]}",
                        type="Web Page Title",
                        source="ZoomEye",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        resolution=site_ip,
                        raw_data=f"Title: {site_title} | URL: {site_url}",
                        tags=["web", "metadata"]
                    ))

                if site_server:
                    findings.append(IntelligenceFinding(
                        entity=site_server[:200],
                        type="Web Server (ZoomEye)",
                        source="ZoomEye",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        resolution=site_ip,
                        raw_data=f"Server: {site_server}",
                        tags=["web", "server"]
                    ))

            if web_matches:
                findings.append(IntelligenceFinding(
                    entity=f"{web_total} ZoomEye web results for {domain} (showing {site_count})",
                    type="ZoomEye Web Results Summary",
                    source="ZoomEye",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    status="Complete",
                    raw_data=f"Total: {web_total} | Displayed: {site_count}",
                    tags=["zoomeye", "web", "summary"]
                ))
    except Exception:
        pass

    try:
        ssl_keywords = ["ssl", "tls", "certificate", "cert", "https"]
        ssl_params = {"query": f"domain:{domain} port:443", "page": 1, "size": 10}
        ssl_resp = await client.get(
            host_search_url,
            params=ssl_params,
            timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        if ssl_resp.status_code == 200:
            ssl_data = ssl_resp.json()
            for match in ssl_data.get("matches", [])[:5]:
                portinfo = match.get("portinfo", {}) or {}
                ssl_info = portinfo.get("ssl", {}) or {}
                ssl_cert = ssl_info.get("cert", {}) or {}
                ssl_subject = ssl_cert.get("subject", "")
                ssl_issuer = ssl_cert.get("issuer", "")
                ssl_valid_to = ssl_cert.get("valid_to", "")
                ssl_algo = ssl_cert.get("sig_algo", "")
                ssl_version = ssl_info.get("version", "")

                ip = match.get("ip", "")

                if ssl_subject:
                    findings.append(IntelligenceFinding(
                        entity=f"SSL Subject: {ssl_subject}",
                        type="SSL Certificate Subject",
                        source="ZoomEye",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        resolution=ip,
                        raw_data=f"Subject: {ssl_subject} | Issuer: {ssl_issuer}",
                        tags=["ssl", "certificate"]
                    ))

                if ssl_issuer:
                    findings.append(IntelligenceFinding(
                        entity=f"SSL Issuer: {ssl_issuer}",
                        type="SSL Certificate Issuer",
                        source="ZoomEye",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        resolution=ip,
                        tags=["ssl", "certificate"]
                    ))

                if ssl_version:
                    findings.append(IntelligenceFinding(
                        entity=f"SSL/TLS: {ssl_version}",
                        type="SSL/TLS Version",
                        source="ZoomEye",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        resolution=ip,
                        tags=["ssl", "protocol"]
                    ))
    except Exception:
        pass

    try:
        for single_ip in list(resolved_ips)[:5]:
            ip_params = {"query": f"ip:{single_ip}", "page": 1, "size": 10}
            ip_resp = await client.get(
                host_search_url,
                params=ip_params,
                timeout=15.0,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
            )
            if ip_resp.status_code == 200:
                ip_data = ip_resp.json()
                ip_matches = ip_data.get("matches", [])
                port_set = set()
                service_set = set()
                for m in ip_matches:
                    pi = m.get("portinfo", {}) or {}
                    p = pi.get("port", "")
                    s = pi.get("service", "")
                    if p:
                        port_set.add(str(p))
                    if s:
                        service_set.add(s)
                if port_set:
                    findings.append(IntelligenceFinding(
                        entity=f"{single_ip}: open ports {', '.join(sorted(port_set, key=int)[:10])}",
                        type="ZoomEye IP Services",
                        source="ZoomEye",
                        confidence="Medium",
                        color="blue",
                        threat_level="Informational",
                        resolution=single_ip,
                        raw_data=f"IP: {single_ip} | Ports: {', '.join(port_set)} | Services: {', '.join(service_set)}",
                        tags=["ip", "services"]
                    ))
    except Exception:
        pass

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No ZoomEye data found for {domain}",
            type="ZoomEye No Results",
            source="ZoomEye",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="NoResults",
            tags=["zoomeye", "no-results"]
        ))

    return findings
