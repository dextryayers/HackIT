import httpx
from models import IntelligenceFinding
import re
from collections import defaultdict

async def crawl(target, client):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    seen = set()

    async def from_crtsh():
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = await client.get(url, timeout=20.0)
            if resp.status_code == 200:
                data = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if (sub.endswith("." + domain) or sub == domain) and "*" not in sub:
                            if sub not in seen:
                                seen.add(sub)
                                findings.append(IntelligenceFinding(
                                    entity=sub,
                                    type="Subdomain (Passive)",
                                    source="crt.sh",
                                    confidence="High",
                                    color="emerald",
                                    category="Domain & DNS Enumeration",
                                    threat_level="Standard Target",
                                    status="Existing",
                                    raw_data="Found in Certificate Transparency Logs"
                                ))
        except: pass

    async def from_hackertarget():
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = await client.get(url, timeout=15.0)
            if resp.status_code == 200:
                for line in resp.text.split("\n"):
                    if "," in line:
                        sub, ip = line.split(",")
                        sub = sub.strip().lower()
                        if sub not in seen:
                            seen.add(sub)
                            findings.append(IntelligenceFinding(
                                entity=sub,
                                type="Subdomain (Passive)",
                                source="HackerTarget",
                                confidence="High",
                                color="emerald",
                                category="Domain & DNS Enumeration",
                                threat_level="Standard Target",
                                status="Existing",
                                resolution=ip,
                                raw_data=f"Resolved to {ip} via passive DNS"
                            ))
        except: pass

    async def from_bufferover():
        try:
            resp = await client.get(
                f"https://dns.bufferover.run/dns?q=.{domain}",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry_type in ["FDNS_A", "RDNS"]:
                    for entry in data.get(entry_type, []):
                        if isinstance(entry, str) and ',' in entry:
                            parts = entry.split(',')
                            sub = parts[1].strip().lower() if len(parts) >= 2 else ""
                            ip_part = parts[0].strip() if len(parts) >= 2 else ""
                            if sub.endswith("." + domain) and sub not in seen:
                                seen.add(sub)
                                findings.append(IntelligenceFinding(
                                    entity=sub,
                                    type="Subdomain (Passive)",
                                    source="BufferOver",
                                    confidence="High",
                                    color="emerald",
                                    category="Domain & DNS Enumeration",
                                    threat_level="Standard Target",
                                    resolution=ip_part,
                                    raw_data=f"Found via {entry_type} DNS data"
                                ))
        except: pass

    async def from_rapiddns():
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = await client.get(url, timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                pattern = re.compile(rf'([\w.-]+\.{re.escape(domain)})', re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    sub = m.group(1).lower()
                    if sub not in seen:
                        seen.add(sub)
                        findings.append(IntelligenceFinding(
                            entity=sub,
                            type="Subdomain (Passive)",
                            source="RapidDNS",
                            confidence="Medium",
                            color="emerald",
                            category="Domain & DNS Enumeration",
                            threat_level="Standard Target",
                            raw_data="Found via RapidDNS.io"
                        ))
        except: pass

    await asyncio.gather(
        from_crtsh(),
        from_hackertarget(),
        from_bufferover(),
        from_rapiddns(),
    )

    if findings:
        sources_used = defaultdict(int)
        for f in findings:
            sources_used[f.source] += 1
        source_str = ", ".join(f"{s}: {c}" for s, c in sources_used.items())
        findings.insert(0, IntelligenceFinding(
            entity=f"Total: {len(seen)} passive subdomains from {len(sources_used)} sources",
            type="Passive Subdomain Summary",
            source="Passive Recon",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=source_str
        ))

    return findings

import asyncio
