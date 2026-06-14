import httpx
import socket
import asyncio
import re
from models import IntelligenceFinding
from urllib.parse import urlparse

IP_API_FIELDS = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"

async def resolve_to_ips(domain: str) -> list:
    ips = []
    loop = asyncio.get_event_loop()
    try:
        addr = await loop.run_in_executor(None, lambda: socket.gethostbyname_ex(domain))
        ips.extend(addr[2])
    except Exception:
        pass
    try:
        for res in await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80)):
            ip = res[4][0]
            if ip and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips

async def geolocate_ip(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}?fields={IP_API_FIELDS}",
            timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if "://" in raw_target:
        parsed = urlparse(raw_target)
        target_host = parsed.netloc
    else:
        target_host = raw_target

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    is_ip = bool(ip_pattern.match(target_host))

    ips_to_check = []

    if is_ip:
        ips_to_check.append(target_host)
        try:
            host = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.gethostbyaddr(target_host)
            )
            if host and host[0]:
                findings.append(IntelligenceFinding(
                    entity=host[0],
                    type="Geo - Reverse DNS Hostname",
                    source="GeoRecon",
                    confidence="High",
                    color="blue",
                    resolution=f"PTR for {target_host}",
                    raw_data=f"Hostname: {host[0]}",
                    tags=["rdns"]
                ))
        except Exception:
            pass
    else:
        resolved = await resolve_to_ips(target_host)
        if not resolved:
            findings.append(IntelligenceFinding(
                entity=f"Could not resolve {target_host} to any IP",
                type="Geo - Resolution Error",
                source="GeoRecon",
                confidence="Low",
                color="red",
                threat_level="Informational"
            ))
            return findings
        ips_to_check = resolved
        for ip in resolved[:3]:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Geo - Resolved IP",
                source="GeoRecon",
                confidence="High",
                color="emerald",
                status="Active",
                resolution=f"DNS A record",
                raw_data=f"{target_host} -> {ip}",
                tags=["dns", "ip"]
            ))

    geo_results = []
    for ip in ips_to_check[:5]:
        geo = await geolocate_ip(client, ip)
        if geo:
            geo_results.append(geo)
        if len(geo_results) == 0:
            await asyncio.sleep(0.3)

    if not geo_results:
        findings.append(IntelligenceFinding(
            entity="No geolocation data available",
            type="Geo - No Data",
            source="GeoRecon",
            confidence="Low",
            color="orange",
            threat_level="Informational"
        ))
        return findings

    for idx, geo in enumerate(geo_results):
        ip = geo.get("query", ips_to_check[idx] if idx < len(ips_to_check) else "unknown")
        isp = geo.get("isp", "")
        org = geo.get("org", "")
        as_num = geo.get("as", "")
        as_name = geo.get("asname", "")
        city = geo.get("city", "")
        region = geo.get("regionName", "")
        country = geo.get("country", "")
        country_code = geo.get("countryCode", "")
        continent = geo.get("continent", "")
        lat = geo.get("lat")
        lon = geo.get("lon")
        timezone = geo.get("timezone", "")
        currency = geo.get("currency", "")
        reverse_dns = geo.get("reverse", "")
        is_proxy = geo.get("proxy", False)
        is_hosting = geo.get("hosting", False)
        is_mobile = geo.get("mobile", False)

        location_parts = [p for p in [city, region, country] if p]
        location_str = ", ".join(location_parts) if location_parts else "Unknown location"

        if city or country:
            findings.append(IntelligenceFinding(
                entity=location_str,
                type=f"Geo - Location ({ip})",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="emerald",
                status="Located",
                resolution=f"{lat}, {lon}" if lat and lon else "",
                raw_data=f"IP: {ip} | Location: {location_str} | Continent: {continent} | Country: {country_code}",
                tags=["geo", "location"]
            ))

        if lat and lon:
            maps_url = f"https://www.google.com/maps?q={lat},{lon}"
            findings.append(IntelligenceFinding(
                entity=f"{lat}, {lon}",
                type="Geo - Coordinates",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="emerald",
                raw_data=maps_url,
                tags=["geo", "coordinates", "map"]
            ))

        if timezone:
            utc_offset = geo.get("offset", "")
            offset_str = f" (UTC{'+' if utc_offset >= 0 else ''}{utc_offset//3600}:{abs(utc_offset)%3600//60:02d})" if utc_offset else ""
            findings.append(IntelligenceFinding(
                entity=f"{timezone}{offset_str}",
                type="Geo - Timezone",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="purple",
                raw_data=f"Timezone: {timezone} | UTC Offset: {offset_str}",
                tags=["geo", "timezone"]
            ))

        if currency:
            findings.append(IntelligenceFinding(
                entity=currency,
                type="Geo - Currency",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="slate",
                tags=["geo", "currency"]
            ))

        if isp:
            findings.append(IntelligenceFinding(
                entity=isp[:200],
                type="Geo - ISP",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="orange",
                raw_data=f"ISP: {isp}",
                tags=["geo", "isp"]
            ))

        if org:
            findings.append(IntelligenceFinding(
                entity=org[:200],
                type="Geo - Organization",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="orange",
                raw_data=f"Org: {org}",
                tags=["geo", "org"]
            ))

        if as_num:
            findings.append(IntelligenceFinding(
                entity=f"{as_num} ({as_name})" if as_name else as_num,
                type="Geo - ASN",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="orange",
                raw_data=f"ASN: {as_num} | Name: {as_name}",
                tags=["geo", "asn"]
            ))

        if reverse_dns:
            findings.append(IntelligenceFinding(
                entity=reverse_dns[:200],
                type="Geo - Reverse DNS",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="blue",
                resolution=f"PTR for {ip}",
                tags=["geo", "rdns"]
            ))

        if is_proxy:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Geo - Proxy/VPN/TOR Detected",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"{ip} is a proxy or VPN endpoint",
                tags=["geo", "proxy", "vpn"]
            ))

        if is_hosting:
            findings.append(IntelligenceFinding(
                entity=f"{ip} (hosted by {org or isp or 'Unknown'})",
                type="Geo - Hosting/Cloud Provider",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=f"{ip} is hosted infrastructure",
                tags=["geo", "hosting"]
            ))

        if is_mobile:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Geo - Mobile/Cellular Network",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="cyan",
                tags=["geo", "mobile"]
            ))

        if not is_proxy and not is_hosting and not is_mobile:
            findings.append(IntelligenceFinding(
                entity=ip,
                type="Geo - Residential/Consumer IP",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="emerald",
                tags=["geo", "residential"]
            ))

        if geo.get("district"):
            findings.append(IntelligenceFinding(
                entity=geo["district"],
                type="Geo - District",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="slate"
            ))

        if geo.get("zip"):
            findings.append(IntelligenceFinding(
                entity=geo["zip"],
                type="Geo - Postal Code",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="slate"
            ))

        if geo.get("continentCode"):
            findings.append(IntelligenceFinding(
                entity=f"{continent} ({geo['continentCode']})",
                type="Geo - Continent",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="slate"
            ))

        if country_code:
            flag_url = f"https://flagcdn.com/16x12/{country_code.lower()}.png"
            findings.append(IntelligenceFinding(
                entity=f"{country} ({country_code})",
                type="Geo - Country",
                source="GeoRecon (ip-api.com)",
                confidence="High",
                color="slate",
                raw_data=f"Country: {country} | Code: {country_code} | Flag: {flag_url}"
            ))

    if len(geo_results) > 1:
        countries = set(g.get("country", "") for g in geo_results if g.get("country"))
        orgs = set(g.get("org", "") for g in geo_results if g.get("org"))
        if len(countries) > 1:
            findings.append(IntelligenceFinding(
                entity=f"Multi-country hosting: {', '.join(sorted(countries))}",
                type="Geo - Cross-Border Distribution",
                source="GeoRecon",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                raw_data=f"IPs located in: {', '.join(sorted(countries))}",
                tags=["geo", "cdn", "global"]
            ))

        if len(orgs) > 1:
            findings.append(IntelligenceFinding(
                entity=f"Multiple providers: {', '.join(sorted(orgs))}",
                type="Geo - Multi-Provider Infrastructure",
                source="GeoRecon",
                confidence="High",
                color="orange",
                tags=["geo", "multi-provider"]
            ))
    else:
        first_geo = geo_results[0]
        lat = first_geo.get("lat")
        lon = first_geo.get("lon")
        city = first_geo.get("city", "")
        region = first_geo.get("regionName", "")
        country = first_geo.get("country", "")
        isp = first_geo.get("isp", "")

        if city and region and country:
            geo_str = f"{city}, {region}, {country}"
        elif city and country:
            geo_str = f"{city}, {country}"
        elif country:
            geo_str = country
        else:
            geo_str = "Unknown"

        if lat and lon:
            geo_str += f" ({lat:.2f}, {lon:.2f})"

        findings.append(IntelligenceFinding(
            entity=geo_str,
            type="Geo - Primary Location",
            source="GeoRecon",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            raw_data=f"Primary location of {target_host}: {geo_str}",
            tags=["geo", "summary"]
        ))

    return findings
