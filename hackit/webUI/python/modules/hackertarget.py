import httpx
import asyncio
import json
from models import IntelligenceFinding
from urllib.parse import urlparse

HT_API_BASE = "https://api.hackertarget.com"

HT_ENDPOINTS = [
    ("hostsearch", f"{HT_API_BASE}/hostsearch/?q={{domain}}", "Subdomain", "HackerTarget HostSearch", "emerald"),
    ("whois", f"{HT_API_BASE}/whois/?q={{domain}}", "WHOIS Data", "HackerTarget WHOIS", "slate"),
    ("dnslookup", f"{HT_API_BASE}/dnslookup/?q={{domain}}", "DNS Record", "HackerTarget DNS", "blue"),
    ("pagelinks", f"{HT_API_BASE}/pagelinks/?q={{domain}}", "Page Links", "HackerTarget PageLinks", "purple"),
    ("zonetransfer", f"{HT_API_BASE}/zonetransfer/?q={{domain}}", "Zone Transfer Check", "HackerTarget ZoneTransfer", "orange"),
    ("reverseip", f"{HT_API_BASE}/reverseip/?q={{domain}}", "Reverse IP", "HackerTarget ReverseIP", "emerald"),
    ("geoip", f"{HT_API_BASE}/geoip/?q={{domain}}", "GeoIP", "HackerTarget GeoIP", "slate"),
    ("revdns", f"{HT_API_BASE}/reversedns/?q={{domain}}", "Reverse DNS", "HackerTarget ReverseDNS", "blue"),
    ("httpheaders", f"{HT_API_BASE}/httpheaders/?q={{domain}}", "HTTP Headers", "HackerTarget HTTPHeaders", "purple"),
    ("mxtest", f"{HT_API_BASE}/mxtest/?q={{domain}}", "Mail Server Test", "HackerTarget MXTest", "emerald"),
    ("dnstracer", f"{HT_API_BASE}/dnstracer/?q={{domain}}", "DNS Traceroute", "HackerTarget DNSTracer", "orange"),
    ("nmap", f"{HT_API_BASE}/nmap/?q={{domain}}", "NMAP Port Scan", "HackerTarget NMAP", "red"),
    ("subnetcalc", f"{HT_API_BASE}/subnetcalc/?q={{domain}}", "Subnet Calc", "HackerTarget SubnetCalc", "slate"),
    ("aslookup", f"{HT_API_BASE}/aslookup/?q={{domain}}", "AS Lookup", "HackerTarget ASLookup", "purple"),
    ("tcptraceroute", f"{HT_API_BASE}/tcptraceroute/?q={{domain}}", "TCP Traceroute", "HackerTarget TCPTrace", "orange"),
    ("sitereport", f"{HT_API_BASE}/sitereport/?q={{domain}}", "Site Report", "HackerTarget SiteReport", "blue"),
    ("threatcheck", f"{HT_API_BASE}/threatcheck/?q={{domain}}", "Threat Check", "HackerTarget ThreatCheck", "red"),
    ("ssltest", f"{HT_API_BASE}/ssltest/?q={{domain}}", "SSL Test", "HackerTarget SSLTest", "slate"),
]

MAX_RETRIES = 3
RETRY_DELAY = 2.0

async def call_endpoint(url: str, client: httpx.AsyncClient, retries: int = MAX_RETRIES) -> str | None:
    for attempt in range(retries):
        try:
            resp = await client.get(url, timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                return resp.text.strip()
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
        except Exception:
            if attempt < retries - 1:
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            continue
    return None

def parse_hostsearch(text: str, findings: list, source: str, ftype: str, color: str):
    seen = set()
    for line in text.split("\n"):
        if ',' in line:
            sub, ip = line.split(',', 1)
            sub_clean = sub.strip().lower()
            if sub_clean not in seen:
                seen.add(sub_clean)
                findings.append(IntelligenceFinding(
                    entity=sub_clean,
                    type=ftype,
                    source=source,
                    confidence="High",
                    color=color,
                    resolution=ip.strip(),
                    raw_data=f"{sub_clean} -> {ip.strip()}"
                ))

def parse_whois(text: str, findings: list, source: str, color: str):
    whois_keys = {
        "Registrar": "Whois Registrar",
        "Creation Date": "Whois Created",
        "Registry Expiry Date": "Whois Expires",
        "Name Server": "Whois Nameserver",
        "Registrant Organization": "Whois Organization",
        "Registrant Country": "Whois Country",
        "Domain Status": "Whois Status",
        "Updated Date": "Whois Updated",
        "Registrant Name": "Whois Registrant",
        "Registrant Email": "Whois Email",
        "Admin Email": "Whois Admin Email",
        "Tech Email": "Whois Tech Email",
        "DNSSEC": "Whois DNSSEC",
    }
    found_keys = {}
    for line in text.split("\n"):
        for key, ftype_name in whois_keys.items():
            if line.lower().startswith(key.lower()) and ':' in line:
                val = line.split(':', 1)[1].strip()
                if val and key not in found_keys:
                    found_keys[key] = True
                    findings.append(IntelligenceFinding(
                        entity=val[:200],
                        type=ftype_name,
                        source=source,
                        confidence="High",
                        color=color,
                        raw_data=line[:500]
                    ))
                break

def parse_dnslookup(text: str, findings: list, source: str, color: str):
    for line in text.split("\n"):
        if ':' in line:
            parts = line.split(':', 1)
            findings.append(IntelligenceFinding(
                entity=parts[1].strip()[:200],
                type=f"DNS {parts[0].strip()}",
                source=source,
                confidence="High",
                color=color,
                raw_data=line[:500]
            ))

def parse_reverseip(text: str, findings: list, source: str, color: str):
    seen = set()
    for line in text.split("\n"):
        if ',' in line:
            host, rest = line.split(',', 1)
            host_clean = host.strip().lower()
            if host_clean not in seen:
                seen.add(host_clean)
                findings.append(IntelligenceFinding(
                    entity=host_clean[:200],
                    type="Reverse IP Host",
                    source=source,
                    confidence="High",
                    color=color,
                    resolution=rest.strip()[:100],
                    raw_data=line[:500]
                ))

def parse_httpheaders(text: str, findings: list, source: str, color: str):
    seen = set()
    for line in text.split("\n"):
        if ':' in line and not line.startswith("#") and not line.startswith("//"):
            k, v = line.split(':', 1)
            k_clean = k.strip()
            v_clean = v.strip()
            if k_clean and v_clean and k_clean not in seen:
                seen.add(k_clean)
                findings.append(IntelligenceFinding(
                    entity=v_clean[:200],
                    type=f"HTTP Header: {k_clean}",
                    source=source,
                    confidence="High",
                    color=color,
                    raw_data=line[:500]
                ))

def parse_geoip(text: str, findings: list, source: str, color: str):
    for line in text.split("\n"):
        if ':' in line:
            k, v = line.split(':', 1)
            findings.append(IntelligenceFinding(
                entity=v.strip()[:200],
                type=f"GeoIP: {k.strip()}",
                source=source,
                confidence="High",
                color=color,
                raw_data=line[:500]
            ))

def parse_mxtest(text: str, findings: list, source: str, color: str):
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("API") and not line.startswith("#"):
            findings.append(IntelligenceFinding(
                entity=line[:200],
                type="Mail Server (MX Test)",
                source=source,
                confidence="Medium",
                color=color,
                raw_data=line[:500]
            ))

def parse_nmap(text: str, findings: list, source: str, color: str):
    open_ports = []
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("API") and not line.startswith("#"):
            is_open = "open" in line.lower()
            findings.append(IntelligenceFinding(
                entity=line[:200],
                type="NMAP Port Scan" if not is_open else "NMAP Open Port",
                source=source,
                confidence="High",
                color="red" if is_open else color,
                threat_level="Elevated Risk" if is_open else "Informational",
                raw_data=line[:500]
            ))
            if is_open:
                open_ports.append(line[:100])
    if open_ports:
        findings.append(IntelligenceFinding(
            entity=f"Open ports: {'; '.join(open_ports[:5])}",
            type="NMAP Open Ports Summary",
            source=source,
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            tags=["nmap", "open-ports"]
        ))

def parse_aslookup(text: str, findings: list, source: str, color: str):
    for line in text.split("\n"):
        if ':' in line:
            k, v = line.split(':', 1)
            findings.append(IntelligenceFinding(
                entity=v.strip()[:200],
                type=f"AS Lookup: {k.strip()}",
                source=source,
                confidence="High",
                color=color,
                raw_data=line[:500]
            ))

def parse_dnstracer(text: str, findings: list, source: str, color: str):
    hop_count = 0
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("API") and not line.startswith("#"):
            hop_count += 1
            findings.append(IntelligenceFinding(
                entity=line[:200],
                type="DNS Traceroute Hop",
                source=source,
                confidence="Medium",
                color=color,
                raw_data=line[:500]
            ))
    if hop_count > 0:
        findings.append(IntelligenceFinding(
            entity=f"DNS Traceroute: {hop_count} hops",
            type="DNS Traceroute Summary",
            source=source,
            confidence="Medium",
            color="purple",
            tags=["dns", "traceroute"]
        ))

def parse_ssltest(text: str, findings: list, source: str, color: str):
    for line in text.split("\n"):
        if ':' in line:
            k, v = line.split(':', 1)
            findings.append(IntelligenceFinding(
                entity=f"{k.strip()}: {v.strip()[:200]}",
                type="SSL Test Result",
                source=source,
                confidence="High",
                color="red" if "fail" in v.lower() or "error" in v.lower() else color,
                threat_level="Elevated Risk" if "fail" in v.lower() else "Informational",
                raw_data=line[:500]
            ))

PARSERS = {
    "hostsearch": parse_hostsearch,
    "whois": parse_whois,
    "dnslookup": parse_dnslookup,
    "reverseip": parse_reverseip,
    "httpheaders": parse_httpheaders,
    "geoip": parse_geoip,
    "mxtest": parse_mxtest,
    "nmap": parse_nmap,
    "aslookup": parse_aslookup,
    "dnstracer": parse_dnstracer,
    "ssltest": parse_ssltest,
}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if target.startswith("http"):
        domain = urlparse(target).netloc
    domain = domain.strip().lower()

    results_summary = {}
    total_endpoints = len(HT_ENDPOINTS)
    success_count = 0

    for name, url_tpl, ftype, source, color in HT_ENDPOINTS:
        url = url_tpl.format(domain=domain)
        try:
            text = await call_endpoint(url, client)
            if text:
                success_count += 1
                if name in PARSERS:
                    PARSERS[name](text, findings, source, ftype, color)
                else:
                    for line in text.split("\n")[:20]:
                        line_stripped = line.strip()
                        if line_stripped and not line_stripped.startswith("API"):
                            findings.append(IntelligenceFinding(
                                entity=line_stripped[:200],
                                type=ftype,
                                source=source,
                                confidence="Medium",
                                color=color,
                                raw_data=line_stripped[:500]
                            ))
                results_summary[name] = "Success"
        except Exception:
            results_summary[name] = "Failed"
            continue

    findings.append(IntelligenceFinding(
        entity=f"HackerTarget scan complete: {success_count}/{total_endpoints} endpoints succeeded",
        type="HackerTarget Scan Summary",
        source="HackerTarget",
        confidence="High",
        color="purple",
        threat_level="Informational",
        status=f"{success_count}/{total_endpoints}",
        resolution=domain,
        raw_data=f"Endpoints: {', '.join(f'{k}: {v}' for k, v in results_summary.items())}",
        tags=["hackertarget", "summary"]
    ))

    return findings
