import httpx
from models import IntelligenceFinding
from urllib.parse import urlparse

HT_API_BASE = "https://api.hackertarget.com"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if target.startswith("http"):
        domain = urlparse(target).netloc
    domain = domain.strip().lower()

    apis = [
        ("hostsearch", f"{HT_API_BASE}/hostsearch/?q={domain}", "Subdomain", "HackerTarget HostSearch", "emerald"),
        ("whois", f"{HT_API_BASE}/whois/?q={domain}", "WHOIS Data", "HackerTarget WHOIS", "slate"),
        ("dnslookup", f"{HT_API_BASE}/dnslookup/?q={domain}", "DNS Record", "HackerTarget DNS", "blue"),
        ("pagelinks", f"{HT_API_BASE}/pagelinks/?q={domain}", "Page Links", "HackerTarget PageLinks", "purple"),
        ("zonetransfer", f"{HT_API_BASE}/zonetransfer/?q={domain}", "Zone Transfer Check", "HackerTarget ZoneTransfer", "orange"),
        ("reverseip", f"{HT_API_BASE}/reverseip/?q={domain}", "Reverse IP", "HackerTarget ReverseIP", "emerald"),
        ("geoip", f"{HT_API_BASE}/geoip/?q={domain}", "GeoIP", "HackerTarget GeoIP", "slate"),
        ("revlookup", f"{HT_API_BASE}/reversedns/?q={domain}", "Reverse DNS", "HackerTarget ReverseDNS", "blue"),
    ]

    for name, url, ftype, source, color in apis:
        try:
            resp = await client.get(url, timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200 and "error" not in resp.text.lower()[:50]:
                text = resp.text.strip()
                lines = text.split("\n")

                if name == "hostsearch":
                    for line in lines:
                        if ',' in line:
                            sub, ip = line.split(',')
                            findings.append(IntelligenceFinding(
                                entity=sub.strip(),
                                type=ftype,
                                source=source,
                                confidence="High",
                                color=color,
                                resolution=ip.strip(),
                                raw_data=f"{sub.strip()} -> {ip.strip()}"
                            ))

                elif name == "geoip":
                    for line in lines:
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

                elif name == "whois":
                    whois_keys = {
                        "Registrar": "Whois Registrar",
                        "Creation Date": "Whois Created",
                        "Registry Expiry Date": "Whois Expires",
                        "Name Server": "Whois Nameserver",
                        "Registrant Organization": "Whois Organization",
                        "Registrant Country": "Whois Country",
                        "Domain Status": "Whois Status",
                    }
                    for line in lines:
                        for key, ftype_name in whois_keys.items():
                            if line.lower().startswith(key.lower()) and ':' in line:
                                val = line.split(':', 1)[1].strip()
                                if val:
                                    findings.append(IntelligenceFinding(
                                        entity=val[:200],
                                        type=ftype_name,
                                        source=source,
                                        confidence="High",
                                        color=color,
                                        raw_data=line[:500]
                                    ))
                                break

                elif name == "dnslookup":
                    for line in lines:
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

                elif name == "reverseip":
                    for line in lines:
                        if ',' in line:
                            host, rest = line.split(',', 1)
                            findings.append(IntelligenceFinding(
                                entity=host.strip()[:200],
                                type="Reverse IP Host",
                                source=source,
                                confidence="High",
                                color=color,
                                resolution=rest.strip()[:100],
                                raw_data=line[:500]
                            ))

                else:
                    for line in lines[:20]:
                        line = line.strip()
                        if line and not line.startswith("API"):
                            findings.append(IntelligenceFinding(
                                entity=line[:200],
                                type=ftype,
                                source=source,
                                confidence="Medium",
                                color=color,
                                raw_data=line[:500]
                            ))

        except Exception as e:
            continue

    return findings
