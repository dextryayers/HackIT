import httpx
import re
import json
import socket
import asyncio
from urllib.parse import urlparse
from module_base import BaseScanner

WHOIS_SOURCES = [
    {"name":"HackerTarget","url":"https://api.hackertarget.com/whois/?q={domain}","type":"text","weight":1},
    {"name":"whois.com","url":"https://www.whois.com/whois/{domain}","type":"html","weight":2},
    {"name":"WhoisXMLAPI","url":"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json","type":"json","weight":3},
    {"name":"Verisign","url":"https://whois.verisign.com/?domain={domain}","type":"html","weight":4},
]

TLD_WHOIS = {"com":"whois.verisign.com","net":"whois.verisign.com","org":"whois.pir.org","io":"whois.nic.io",
    "co":"whois.nic.co","app":"whois.nic.google","dev":"whois.nic.google","xyz":"whois.nic.xyz",
    "me":"whois.nic.me","uk":"whois.nic.uk","de":"whois.denic.de","fr":"whois.nic.fr",
    "ca":"whois.cira.ca","au":"whois.auda.org.au","in":"whois.registry.in","eu":"whois.eu",
    "cloud":"whois.nic.cloud","tech":"whois.nic.tech","store":"whois.nic.store","site":"whois.nic.site",
    "online":"whois.nic.online","tv":"whois.nic.tv",
}

RDAP_URLS = [
    "https://rdap.verisign.com/com/v1/domain/{domain}","https://rdap.verisign.com/net/v1/domain/{domain}",
    "https://rdap.pir.org/domain/{domain}","https://rdap.afilias.net/rdap/domain/{domain}",
    "https://rdap.nic.google/domain/{domain}","https://rdap.nic.xyz/domain/{domain}",
    "https://rdap.nic.io/domain/{domain}","https://rdap.nic.co/domain/{domain}",
    "https://rdap.denic.de/domain/{domain}","https://rdap.nic.uk/domain/{domain}",
    "https://rdap.auda.org.au/domain/{domain}","https://rdap.cira.ca/domain/{domain}",
    "https://rdap.nic.fr/domain/{domain}","https://rdap.nic.eu/domain/{domain}",
]

FIELDS_OF_INTEREST = {
    "Registrar":"Whois Registrar","Registrant Organization":"Whois Organization",
    "Registrant Name":"Whois Registrant Name","Registrant Email":"Whois Email",
    "Registrant Phone":"Whois Phone","Registrant Country":"Whois Country",
    "Registrant State":"Whois Location","Admin Email":"Whois Admin Email",
    "Tech Email":"Whois Tech Email","Name Server":"Whois Nameserver",
    "Creation Date":"Whois Domain Created","Registry Expiry Date":"Whois Domain Expires",
    "Expiration Date":"Whois Domain Expires","Updated Date":"Whois Domain Updated",
}

DOMAIN_STATUS_CODES = {
    "clientTransferProhibited":"Domain locked (transfer prohibited)",
    "clientDeleteProhibited":"Domain locked (delete prohibited)",
    "clientUpdateProhibited":"Domain locked (update prohibited)",
    "serverTransferProhibited":"Registry lock (transfer)",
    "serverDeleteProhibited":"Registry lock (delete)",
    "serverUpdateProhibited":"Registry lock (update)",
    "clientHold":"Domain not resolving (client hold)",
    "serverHold":"Domain not resolving (registry hold)",
    "ok":"Domain active (OK)",
    "inactive":"Domain inactive",
    "redemptionPeriod":"Redemption grace period",
    "pendingDelete":"Pending deletion",
}

class WhoisScanner(BaseScanner):
    name = "whois"

    async def _fetch(self, url: str) -> str | None:
        resp = await self.safe_request(url, timeout=12, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if resp and resp.status_code == 200 and len(resp.text) > 100:
            if "error" not in resp.text.lower()[:200] and "not found" not in resp.text.lower()[:300]:
                return resp.text
        return None

    async def _tcp_whois(self, domain: str) -> str | None:
        tld = domain.split(".")[-1] if "." in domain else ""
        server = TLD_WHOIS.get(tld, "whois.verisign-grs.com")
        loop = asyncio.get_event_loop()
        def query():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((server, 43))
                sock.send(f"{domain}\r\n".encode())
                data = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    data += chunk
                    if len(data) > 65536: break
                sock.close()
                return data.decode("utf-8", errors="ignore")
            except: return None
        return await loop.run_in_executor(None, query)

    def _parse_text(self, text: str) -> dict:
        result = {}
        for line in text.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("%") and not line.startswith("#"):
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k and v and len(k) < 60 and len(v) < 500:
                    result[k] = v
        return result

    async def scan(self) -> list:
        results = []
        domain = self.target

        best_text = None
        best_source = None
        for src in sorted(WHOIS_SOURCES, key=lambda s: s["weight"]):
            text = await self._fetch(src["url"].format(domain=domain))
            if text:
                best_text = text; best_source = src; break

        if not best_text:
            raw = await self._tcp_whois(domain)
            if raw and len(raw) > 100:
                best_text = raw; best_source = {"name":"Direct WHOIS (TCP 43)","type":"text"}

        for rdap_url in RDAP_URLS:
            resp = await self.safe_request(rdap_url.format(domain=domain), timeout=10, headers={
                "User-Agent": "Mozilla/5.0", "Accept": "application/json"
            })
            if resp and resp.status_code == 200:
                if not best_text:
                    best_text = resp.text; best_source = {"name":"RDAP","type":"json"}
                break

        if not best_text:
            f = self.finding(entity=f"No WHOIS data available for {domain}", ftype="Whois No Data",
                confidence="Low", color="slate", threat_level="Informational", status="No Data", tags=["whois"])
            if f: results.append(f)
            return results

        parsed = self._parse_text(best_text)
        if best_source.get("type") == "json" or best_text.strip().startswith("{"):
            try:
                data = json.loads(best_text)
                if "whoisRecord" in data: data = data["whoisRecord"]
                if not parsed: parsed = self._parse_text(json.dumps(data, indent=2))
            except:
                parsed = self._parse_text(best_text)

        f = self.finding(entity=f"WHOIS data for {domain} (source: {best_source['name']})",
            ftype="Whois Source", confidence="High", color="slate", threat_level="Informational",
            status="Retrieved", raw_data=f"Source: {best_source['name']}", tags=["whois","source"])
        if f: results.append(f)

        seen_contacts = set()
        for key, val in parsed.items():
            for search_key, ftype in FIELDS_OF_INTEREST.items():
                if search_key.lower() in key.lower():
                    if val not in seen_contacts:
                        seen_contacts.add(val)
                        f = self.finding(entity=val[:200], ftype=ftype, confidence="High", color="slate",
                            threat_level="Informational", status="Extracted",
                            raw_data=f"{key}: {val[:500]}", tags=["whois","contact"])
                        if f: results.append(f)
                    break

        for key, val in parsed.items():
            if "status" in key.lower():
                for code, desc in DOMAIN_STATUS_CODES.items():
                    if code.lower() in val.lower():
                        f = self.finding(entity=f"Status: {code} - {desc}", ftype="Whois Domain Status",
                            confidence="High", color="orange" if "hold" in code or "prohibit" in code else "emerald",
                            threat_level="Informational", status="Status Code",
                            tags=["whois","domain-status"])
                        if f: results.append(f)
                        break

        dnssec = next((v for k,v in parsed.items() if "dnssec" in k.lower()), None)
        if dnssec:
            f = self.finding(entity=f"DNSSEC: {dnssec}", ftype="Whois DNSSEC", confidence="High",
                color="emerald" if "signed" in str(dnssec).lower() else "slate",
                threat_level="Informational", status="Detected", tags=["whois","dnssec"])
            if f: results.append(f)

        nameservers = [v.strip().rstrip(".") for k,v in parsed.items()
                       if "name server" in k.lower() or "nameserver" in k.lower()]
        nameservers = list(dict.fromkeys(nameservers))
        if nameservers:
            f = self.finding(entity=f"Nameservers: {', '.join(nameservers[:5])}",
                ftype="Whois Nameservers", confidence="High", color="blue",
                threat_level="Informational", status="Extracted",
                raw_data=", ".join(nameservers), tags=["whois","nameservers"])
            if f: results.append(f)

        dates = {}
        for k,v in parsed.items():
            lk = k.lower()
            if "creation date" in lk or "created" in lk: dates["created"] = v
            elif "expir" in lk: dates["expires"] = v
            elif "updated" in lk: dates["updated"] = v
        if dates:
            f = self.finding(entity=f"Dates: {' | '.join(f'{k}: {v}' for k,v in dates.items())}",
                ftype="Whois Domain Dates", confidence="High", color="purple",
                threat_level="Informational", status="Timeline", tags=["whois","dates"])
            if f: results.append(f)

        f = self.finding(entity=f"WHOIS analysis complete: {len(parsed)} fields extracted",
            ftype="Whois Summary", confidence="High", color="purple",
            threat_level="Informational", status="Complete", tags=["whois","summary"])
        if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = WhoisScanner(target, client)
    return await scanner.scan()
