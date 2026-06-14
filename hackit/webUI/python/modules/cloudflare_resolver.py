import httpx
import asyncio
import re
import json
import socket
import struct
import hashlib
from urllib.parse import urlparse, quote
from models import IntelligenceFinding
from typing import List, Dict, Optional, Set

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "cpanel", "whm", "direct",
    "test", "portal", "support", "dev", "staging", "api", "app",
    "web", "mail2", "email", "mx", "pop3", "imap", "webdisk",
    "cpcalendars", "cpcontacts", "mysql", "autodiscover",
    "cpanel", "webmail", "localhost", "host", "hosting",
    "redirect", "forum", "wiki", "news", "shop", "store",
    "cdn", "static", "media", "img", "video", "download",
    "dns", "dns1", "dns2", "dns3", "dns4",
    "ns", "ns1", "ns2", "ns3", "ns4",
    "ftp", "ssh", "git", "jenkins", "jira", "confluence",
    "monitor", "status", "stats", "analytics", "tracking",
    "m", "mobile", "iphone", "android", "play",
    "remote", "remote2", "gateway", "proxy", "webproxy",
    "owa", "exchange", "rpc", "lyncdiscover", "sip",
]

CNAME_PATTERNS = {
    "cloudflare": [".cloudflare.", "cfcdn", "cloudflare-ip"],
    "cloudfront": [".cloudfront.net"],
    "akamai": [".akamai", "akamaiedge", "akamaihd"],
    "fastly": [".fastly.net"],
    "azure_cdn": [".azureedge.net", ".azurefd.net"],
    "gcp_cdn": [".cdn.google", "gcpcdn"],
    "aws_cdn": [".awsglobalaccelerator"],
}


def is_cloudflare_ip(ip: str) -> bool:
    cf_ranges = [
        ("103.21.244.0", "103.21.247.255"),
        ("103.22.200.0", "103.22.203.255"),
        ("103.31.4.0", "103.31.7.255"),
        ("141.101.64.0", "141.101.127.255"),
        ("108.162.192.0", "108.162.255.255"),
        ("190.93.240.0", "190.93.255.255"),
        ("188.114.96.0", "188.114.127.255"),
        ("197.234.240.0", "197.234.255.255"),
        ("198.41.128.0", "198.41.255.255"),
        ("162.158.0.0", "162.159.255.255"),
        ("104.16.0.0", "104.31.255.255"),
        ("172.64.0.0", "172.71.255.255"),
        ("131.0.72.0", "131.0.75.255"),
    ]
    try:
        ip_num = struct.unpack("!I", socket.inet_aton(ip))[0]
        for start, end in cf_ranges:
            start_num = struct.unpack("!I", socket.inet_aton(start))[0]
            end_num = struct.unpack("!I", socket.inet_aton(end))[0]
            if start_num <= ip_num <= end_num:
                return True
    except Exception:
        pass
    return False


def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def int_to_ip(num: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", num))


def compute_favicon_hash(resp_bytes: bytes) -> Optional[str]:
    if len(resp_bytes) < 100:
        return None
    mmh3 = hashlib.murmur3_32(resp_bytes)
    return format(mmh3 & 0xFFFFFFFF, '08x')


async def resolve_dns(hostname: str, record_type: str = "A") -> List[str]:
    results = []
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(hostname, record_type)
        for rdata in answers:
            results.append(str(rdata))
    except Exception:
        pass
    return results


async def check_http_on_port(client: httpx.AsyncClient, hostname: str, port: int) -> Optional[Dict]:
    try:
        url = f"http://{hostname}:{port}"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=10.0, follow_redirects=False)
        headers = dict(resp.headers)
        server = headers.get("server", "")
        if server and "cloudflare" not in server.lower():
            return {
                "ip": "",  # resolved at this point
                "server": server,
                "status": resp.status_code,
                "headers": headers,
            }
    except Exception:
        pass

    try:
        url = f"https://{hostname}:{port}"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=10.0, follow_redirects=False)
        headers = dict(resp.headers)
        server = headers.get("server", "")
        if server and "cloudflare" not in server.lower():
            return {
                "ip": "",
                "server": server,
                "status": resp.status_code,
                "headers": headers,
            }
    except Exception:
        pass
    return None


async def search_crtsh_certs(client: httpx.AsyncClient, domain: str) -> List[str]:
    names = []
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=30.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[:200]:
                name = entry.get("name_value", "")
                if name:
                    for n in name.split('\n'):
                        n = n.strip().lstrip('*.').rstrip('.')
                        if n and n not in names:
                            names.append(n)
    except Exception:
        pass
    return names


async def search_securitytrails(client: httpx.AsyncClient, domain: str) -> Dict:
    result = {"a_records": [], "mx_records": [], "ns_records": []}
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json", "APIKEY": "demo"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get("current_dns", {}).get("a", []):
                if isinstance(record, dict):
                    result["a_records"].append(record.get("ip", ""))
                elif isinstance(record, str):
                    result["a_records"].append(record)

        sub_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        resp2 = await client.get(sub_url, headers=headers, timeout=20.0)
        if resp2.status_code == 200:
            sub_data = resp2.json()
            result["subdomains"] = sub_data.get("subdomains", [])
    except Exception:
        pass
    return result


async def search_dnsdumpster(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = "https://dnsdumpster.com/"
        resp = await client.get(url, headers={"User-Agent": UA}, timeout=15.0)
        csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.text)

        headers = {
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://dnsdumpster.com/",
        }
        data = {"csrfmiddlewaretoken": csrf_match.group(1) if csrf_match else "", "targetip": domain}

        resp2 = await client.post(url, headers=headers, data=data, timeout=30.0)
        if resp2.status_code == 200:
            html = resp2.text
            ip_matches = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', html)
            for ip in set(ip_matches):
                if not is_cloudflare_ip(ip):
                    results.append({"ip": ip, "source": "DNSDumpster", "type": "potential_origin"})
    except Exception:
        pass
    return results


async def check_cname_resolution(client: httpx.AsyncClient, hostname: str) -> Optional[Dict]:
    try:
        cnames = await resolve_dns(hostname, "CNAME")
        if cnames:
            cname = cnames[0].rstrip('.')
            cname_ips = await resolve_dns(cname, "A")
            if cname_ips:
                detected_cdn = "Unknown"
                for cdn_name, patterns in CNAME_PATTERNS.items():
                    for pattern in patterns:
                        if pattern in cname.lower():
                            detected_cdn = cdn_name
                            break
                return {
                    "cname": cname,
                    "ip": cname_ips[0] if cname_ips else "",
                    "cdn": detected_cdn,
                    "is_cdn": detected_cdn != "Unknown",
                }
    except Exception:
        pass
    return None


async def check_shodan_favicon(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        favicon_url = f"https://{domain}/favicon.ico"
        resp = await client.get(favicon_url, headers={"User-Agent": UA}, timeout=15.0)
        if resp.status_code == 200:
            fav_hash = hashlib.md5(resp.content).hexdigest()
            shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash:{fav_hash}"
            headers = {"User-Agent": UA}
            shodan_resp = await client.get(shodan_url, headers=headers, timeout=20.0)
            if shodan_resp.status_code == 200:
                found_ips = re.findall(r'(?:\b(?:\d{1,3}\.){3}\d{1,3})\b', shodan_resp.text)
                for found_ip in set(found_ips):
                    if not is_cloudflare_ip(found_ip) and found_ip not in ips:
                        ips.append(found_ip)
    except Exception:
        pass
    return ips


async def rtt_analysis(hostname: str) -> List[str]:
    potential_origins = []
    try:
        import ping3
        resolved = await resolve_dns(hostname)
        if resolved:
            base_rtt = ping3.ping(hostname, timeout=3)
            if base_rtt:
                for last_octet in range(1, 255):
                    base_parts = resolved[0].rsplit('.', 1)
                    test_ip = f"{base_parts[0]}.{last_octet}"
                    if test_ip != resolved[0]:
                        rtt = ping3.ping(test_ip, timeout=1)
                        if rtt and rtt < base_rtt * 0.5:
                            potential_origins.append(test_ip)
    except Exception:
        pass
    return potential_origins


async def search_hackertarget_reverse_ip(client: httpx.AsyncClient, domain: str) -> List[str]:
    ips = []
    try:
        url = f"https://api.hackertarget.com/reverseip/?q={domain}"
        headers = {"User-Agent": UA}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                if line.strip() and not line.startswith("Host"):
                    ips.append(line.strip())
    except Exception:
        pass
    return ips


async def test_alternative_ports(client: httpx.AsyncClient, ip: str) -> List[Dict]:
    results = []
    alt_ports = [80, 443, 8080, 8443, 4443, 2053, 2083, 2087, 2096, 8880, 8888]
    for port in alt_ports:
        try:
            if port == 443 or port in [8443, 4443, 2083, 2087, 2096]:
                url = f"https://{ip}:{port}"
            else:
                url = f"http://{ip}:{port}"
            resp = await client.get(url, headers={"User-Agent": UA}, timeout=5.0, follow_redirects=False)
            headers = dict(resp.headers)
            server = headers.get("server", "")
            if server and "cloudflare" not in server.lower():
                results.append({
                    "port": port,
                    "server": server,
                    "status": resp.status_code,
                    "headers": {k: v for k, v in headers.items() if k.lower() in ("server", "x-powered-by", "cf-ray")},
                })
        except Exception:
            continue
    return results


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    is_cloudflare_detected = False
    origin_candidates = []

    try:
        resp = await client.get(f"https://{domain}", headers={"User-Agent": UA}, timeout=15.0, follow_redirects=True)
        headers = dict(resp.headers)
        cf_ray = headers.get("cf-ray", "")
        cf_cache = headers.get("cf-cache-status", "")
        server = headers.get("server", "")
        if "cloudflare" in server.lower() or cf_ray or cf_cache:
            is_cloudflare_detected = True
            findings.append(IntelligenceFinding(
                entity="Cloudflare detected via response headers",
                type="CDN: Cloudflare Detected",
                source="CloudflareResolver",
                confidence="High",
                color="blue",
                threat_level="Informational",
                tags=["cloudflare", "cdn", "detected"]
            ))
    except Exception:
        pass

    crtsh_names = await search_crtsh_certs(client, domain)
    subdomain_candidates = set()
    for name in crtsh_names:
        if name.endswith(f".{domain}") and name != domain:
            sub = name.replace(f".{domain}", "")
            subdomain_candidates.add(f"{sub}.{domain}")
    subdomain_candidates.update([f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS])

    st_data = await search_securitytrails(client, domain)
    historical_ips = st_data.get("a_records", [])
    for ip in set(historical_ips):
        if not is_cloudflare_ip(ip):
            origin_candidates.append({"ip": ip, "source": "SecurityTrails (historical)", "confidence": "Medium"})

    dnsdumpster_ips = await search_dnsdumpster(client, domain)
    for entry in dnsdumpster_ips:
        if entry["ip"] not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": entry["ip"], "source": entry["source"], "confidence": "Medium"})

    for subdomain in list(subdomain_candidates)[:30]:
        cname_info = await check_cname_resolution(client, subdomain)
        if cname_info and not cname_info["is_cdn"] and cname_info.get("ip"):
            if not is_cloudflare_ip(cname_info["ip"]):
                origin_candidates.append({
                    "ip": cname_info["ip"],
                    "source": f"CNAME resolution ({subdomain} -> {cname_info['cname']})",
                    "confidence": "High",
                })

        sub_ips = await resolve_dns(subdomain, "A")
        for sip in sub_ips:
            if not is_cloudflare_ip(sip) and sip not in [c["ip"] for c in origin_candidates]:
                origin_candidates.append({
                    "ip": sip,
                    "source": f"Subdomain DNS A record ({subdomain})",
                    "confidence": "Medium",
                })

    fav_ips = await check_shodan_favicon(client, domain)
    for ip in fav_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "Favicon hash match (Shodan)", "confidence": "Medium"})

    hackertarget_ips = await search_hackertarget_reverse_ip(client, domain)
    for ip in hackertarget_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "HackerTarget reverse IP", "confidence": "Low"})

    ssl_san_ips = []
    for cert_name in crtsh_names[:50]:
        if cert_name != domain:
            cert_ips = await resolve_dns(cert_name, "A")
            for ip in cert_ips:
                if not is_cloudflare_ip(ip) and ip not in ssl_san_ips:
                    ssl_san_ips.append(ip)
    for ip in ssl_san_ips:
        if ip not in [c["ip"] for c in origin_candidates]:
            origin_candidates.append({"ip": ip, "source": "SSL SAN DNS resolution", "confidence": "Medium"})

    seen_ips = set()
    for candidate in origin_candidates:
        ip = candidate["ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        alt_port_results = await test_alternative_ports(client, ip)
        alt_port_info = ""
        if alt_port_results:
            alt_port_info = " | Alt ports: " + ", ".join(f"{r['port']}:{r['server']}" for r in alt_port_results[:3])

        confidence = candidate.get("confidence", "Medium")
        source_info = candidate.get("source", "Unknown")

        tags = ["cloudflare-resolver", "origin-ip"]
        if alt_port_results:
            tags.append("alt-port-access")

        raw_data = f"IP: {ip}\nSource: {source_info}\nConfidence: {confidence}"
        if alt_port_results:
            for r in alt_port_results:
                raw_data += f"\nAlt port {r['port']}: {r['server']} (HTTP {r['status']})"

        findings.append(IntelligenceFinding(
            entity=f"Origin IP: {ip}",
            type="CDN: Origin IP Candidate",
            source=f"CloudflareResolver/{source_info.split('(')[0].strip()}",
            confidence=confidence,
            color="red" if confidence == "High" else ("orange" if confidence == "Medium" else "slate"),
            threat_level="High Risk" if confidence == "High" else ("Elevated Risk" if confidence == "Medium" else "Informational"),
            status="Potential Origin" if confidence in ("High", "Medium") else "Low Confidence",
            resolution=f"Confidence: {confidence}{alt_port_info}",
            raw_data=raw_data,
            tags=tags,
        ))

    if is_cloudflare_detected and findings:
        high_conf = [f for f in findings if f.confidence == "High" and "Origin IP" in f.type]
        med_conf = [f for f in findings if f.confidence == "Medium" and "Origin IP" in f.type]
        low_conf = [f for f in findings if f.confidence == "Low" and "Origin IP" in f.type]

        summary_lines = [
            f"Origin IP candidates found: {len(high_conf)} high, {len(med_conf)} medium, {len(low_conf)} low confidence",
            f"Total candidates: {len(origin_candidates)}",
            f"High confidence IPs: {', '.join([f.entity.replace('Origin IP: ', '') for f in high_conf]) if high_conf else 'None'}",
        ]

        findings.append(IntelligenceFinding(
            entity=f"Cloudflare Origin Resolution: {len(high_conf)} high-confidence origins",
            type="CDN: Origin Resolution Summary",
            source="CloudflareResolver",
            confidence="Medium",
            color="red" if high_conf else "orange",
            threat_level="High Risk" if high_conf else "Elevated Risk",
            raw_data="\n".join(summary_lines),
            tags=["summary", "cloudflare", "origin-resolution"]
        ))
    elif is_cloudflare_detected and not findings:
        findings.append(IntelligenceFinding(
            entity="Cloudflare detected but no origin IP found. Target likely fully proxied.",
            type="CDN: Origin Resolution",
            source="CloudflareResolver",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["cloudflare", "origin-not-found"]
        ))

    return findings
