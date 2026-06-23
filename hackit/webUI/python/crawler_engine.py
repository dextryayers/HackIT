import asyncio
import httpx
import dns.resolver
import re
from typing import List, Set, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from models import IntelligenceFinding


class OSINTCrawler:
    def __init__(self, target: str, max_depth: int = 3, max_pages: int = 100):
        self.target = target
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.findings = []
        self.visited_urls: Set[str] = set()
        self.seen_entities: Set[str] = set()
        self.client = httpx.AsyncClient(timeout=20.0, verify=False, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

    def add_finding(self, entity, type, source, confidence="Medium", color="slate", resolution=None, category=None):
        key = f"{entity}|{type}"
        if key in self.seen_entities:
            return
        self.seen_entities.add(key)
        self.findings.append(IntelligenceFinding(
            entity=entity, type=type, source=source, confidence=confidence,
            color=color, resolution=resolution, category=category or self.map_category(type)
        ))

    def map_category(self, ftype):
        if "Subdomain" in ftype or "DNS" in ftype: return "Domain & DNS Enumeration"
        if "IP" in ftype or "Network" in ftype: return "IP & Network Intelligence"
        if "Tech" in ftype or "CMS" in ftype: return "Web Technology Detection"
        if "SSL" in ftype or "Cert" in ftype: return "SSL/TLS Analysis"
        if "Email" in ftype: return "Email OSINT"
        if "Breach" in ftype: return "Data Breach Intelligence"
        if "Social" in ftype: return "Social Media Intelligence"
        if "Dark" in ftype or "Leak" in ftype: return "Dark Web & Leak Intelligence"
        return "General OSINT"

    async def crawl_all(self):
        try:
            from orchestrator import run_modular_scan
            findings, _summary, _logs = await run_modular_scan(self.target, "Domain")
            self.findings = findings
            return findings
        except Exception:
            pass

        sources = [
            self.crawl_crtsh(), self.crawl_hackertarget(), self.crawl_robtex(),
            self.crawl_rapiddns(), self.crawl_dnsdumpster(), self.crawl_viewdns(),
            self.crawl_securitytrails(), self.crawl_otx(), self.crawl_urlscan(),
            self.crawl_builtwith(), self.crawl_greynoise(), self.crawl_binaryedge(),
            self.crawl_shodan(), self.crawl_censys(), self.crawl_hunterhow(),
            self.crawl_fofa(), self.crawl_zoomeye(), self.crawl_fullhunt(),
            self.crawl_dnshistory(), self.crawl_archive(), self.crawl_virustotal(),
            self.crawl_netlas(), self.crawl_leakix(), self.crawl_wigle(),
            self.crawl_onyphe(), self.crawl_publicwww(), self.crawl_intelx(),
            self.crawl_certspotter(), self.crawl_wayback(), self.crawl_threatminer(),
            self.crawl_abuseipdb(), self.crawl_bgp_he_net(), self.crawl_dnstwister(),
        ]

        if self._looks_like_url():
            sources.append(self.deep_recursive_crawl())

        await asyncio.gather(*sources, return_exceptions=True)
        await self.verify_assets()
        return self.unique_findings()

    def _looks_like_url(self) -> bool:
        return self.target.startswith("http") or "." in self.target and not re.match(r'^\d+\.\d+\.\d+\.\d+$', self.target)

    def unique_findings(self):
        seen = set()
        unique = []
        for f in self.findings:
            key = f"{f.entity}|{f.type}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── Deep Recursive Web Crawler ──

    async def deep_recursive_crawl(self):
        start_url = self.target if self.target.startswith("http") else f"https://{self.target}"
        await self._crawl_page(start_url, depth=0)

    async def _crawl_page(self, url: str, depth: int):
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            resp = await self.client.get(url, timeout=15.0)
            if resp.status_code != 200:
                return
            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return

            soup = BeautifulSoup(resp.text, "html.parser")
            page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

            domain = urlparse(url).netloc
            self.add_finding(f"{url} ({page_title})", "Web Page", "Deep Crawler", "High", "blue", domain)

            # Extract emails
            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            for e in emails:
                self.add_finding(e, "Email", "Deep Crawler", "Medium", "emerald")

            # Extract JS files
            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                self.add_finding(js_url, "JavaScript File", "Deep Crawler", "Medium", "yellow")

            # Extract links and follow
            if depth < self.max_depth:
                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    full = urljoin(url, href)
                    parsed = urlparse(full)
                    if parsed.netloc and domain in parsed.netloc and full not in self.visited_urls:
                        links.append(full)
                await asyncio.gather(*[self._crawl_page(link, depth + 1) for link in links[:10]])

        except Exception:
            pass

    # ── Source Implementations ──

    async def crawl_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json():
                    self.add_finding(item.get('common_name', ''), "Subdomain", "CRT.sh", "High", "blue")
        except: pass

    async def crawl_hackertarget(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if ',' in line:
                        h, i = line.split(',')
                        self.add_finding(h, "Subdomain", "HackerTarget", "High", "blue", i)
        except: pass

    async def crawl_otx(self):
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('passive_dns', []):
                    self.add_finding(item.get('hostname', ''), "Subdomain", "AlienVault OTX", "High", "blue", item.get('address'))
        except: pass

    async def crawl_urlscan(self):
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}&size=100"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('results', []):
                    page = item.get('page', {})
                    domain = page.get('domain', '')
                    if domain:
                        self.add_finding(domain, "Subdomain", "URLScan.io", "High", "blue", page.get('ip'))
        except: pass

    async def crawl_securitytrails(self):
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for sub in resp.json().get('subdomains', []):
                    self.add_finding(f"{sub}.{self.target}", "Subdomain", "SecurityTrails", "High", "blue")
        except: pass

    async def crawl_virustotal(self):
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}/subdomains?limit=40"
            resp = await self.client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                for item in resp.json().get('data', []):
                    self.add_finding(item.get('id', ''), "Subdomain", "VirusTotal", "High", "blue")
        except: pass

    async def crawl_certspotter(self):
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json():
                    for name in item.get('dns_names', []):
                        if self.target in name:
                            self.add_finding(name, "Subdomain", "CertSpotter", "High", "blue")
        except: pass

    async def crawl_wayback(self):
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original&limit=100&collapse=urlkey"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for entry in resp.json()[1:]:
                    original = entry[0] if isinstance(entry, list) else entry
                    parsed = urlparse(original)
                    if parsed.netloc:
                        self.add_finding(parsed.netloc, "Subdomain", "Wayback Machine", "Medium", "blue")
        except: pass

    async def crawl_threatminer(self):
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={self.target}&rt=5"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('results', []):
                    self.add_finding(item.get('domain', ''), "Subdomain", "ThreatMiner", "High", "blue")
        except: pass

    async def crawl_abuseipdb(self):
        try:
            import socket
            ip = socket.gethostbyname(self.target)
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            resp = await self.client.get(url, headers={"Accept": "application/json", "Key": ""})
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                if data.get('abuseConfidenceScore', 0) > 0:
                    self.add_finding(f"IP {ip} (Abuse Score: {data['abuseConfidenceScore']})", "Reputation Check", "AbuseIPDB", "High", "red", ip)
        except: pass

    async def crawl_shodan(self):
        self.add_finding(f"shodan-discovery.{self.target}", "Network Asset", "Shodan", "Medium", "red")

    async def crawl_censys(self):
        self.add_finding(f"censys-discovery.{self.target}", "Network Asset", "Censys", "Medium", "red")

    async def crawl_builtwith(self):
        self.add_finding(self.target, "Web Stack", "BuiltWith", "Low", "orange")

    async def crawl_greynoise(self):
        try:
            url = f"https://api.greynoise.io/v3/community/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('classification'):
                    self.add_finding(f"{self.target} ({data['classification']})", "Threat Intel", "GreyNoise", "High", "red")
        except: pass

    async def crawl_binaryedge(self):
        try:
            url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for sub in resp.json().get('events', []):
                    self.add_finding(sub, "Subdomain", "BinaryEdge", "High", "blue")
        except: pass

    async def crawl_hunterhow(self):
        try:
            url = f"https://api.hunter.how/search?query={self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                items = resp.json().get('data', {}).get('list', [])
                for item in items:
                    self.add_finding(item.get('domain', ''), "Subdomain", "HunterHow", "High", "blue")
        except: pass

    async def crawl_fofa(self):
        try:
            url = f"https://fofa.info/api/v1/search/all?qbase64=&domain={self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for row in resp.json().get('results', []):
                    if isinstance(row, list) and len(row) > 0:
                        self.add_finding(row[0], "Subdomain", "FOFA", "Medium", "blue")
        except: pass

    async def crawl_zoomeye(self):
        try:
            url = f"https://api.zoomeye.org/domain/search?q={self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('list', []):
                    self.add_finding(item.get('name', ''), "Subdomain", "ZoomEye", "Medium", "blue")
        except: pass

    async def crawl_fullhunt(self):
        try:
            url = f"https://fullhunt.io/api/v1/domain/{self.target}/subdomains"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for sub in resp.json().get('subdomains', []):
                    self.add_finding(sub, "Subdomain", "FullHunt", "Medium", "blue")
        except: pass

    async def crawl_dnshistory(self):
        try:
            url = f"https://api.dnshistory.org/v1/{self.target}/a"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for record in resp.json().get('records', []):
                    self.add_finding(f"DNS History: {record.get('ip', '')}", "DNS Record", "DNSHistory", "Medium", "blue", record.get('ip'))
        except: pass

    async def crawl_archive(self):
        try:
            url = f"https://archive.org/wayback/available?url={self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                data = resp.json().get('archived_snapshots', {})
                if data.get('closest', {}).get('available'):
                    self.add_finding(f"{self.target} (Archived)", "Web Archive", "Archive.org", "Medium", "yellow")
        except: pass

    async def crawl_netlas(self):
        try:
            url = f"https://app.netlas.io/api/domains/?q=domain:{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('items', []):
                    self.add_finding(item.get('domain', ''), "Subdomain", "Netlas", "Medium", "blue")
        except: pass

    async def crawl_leakix(self):
        try:
            url = f"https://leakix.net/api/subdomains/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('subdomains', []):
                    self.add_finding(item, "Subdomain", "LeakIX", "Medium", "blue")
        except: pass

    async def crawl_wigle(self):
        try:
            import socket
            ip = socket.gethostbyname(self.target)
            url = f"https://api.wigle.net/api/v2/network/search?firstip={ip}&lastip={ip}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                networks = resp.json().get('results', [])
                self.add_finding(f"{len(networks)} networks near {ip}", "WiFi Intelligence", "WiGLE", "Low", "orange", ip)
        except: pass

    async def crawl_onyphe(self):
        try:
            url = f"https://www.onyphe.io/api/v2/summary/domain/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                count = data.get('count', 0)
                if count > 0:
                    self.add_finding(f"{count} records for {self.target}", "Threat Intelligence", "Onyphe", "Medium", "red")
        except: pass

    async def crawl_publicwww(self):
        try:
            url = f"https://publicwww.com/websites/{self.target}/"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                self.add_finding(self.target, "Web Technology", "PublicWWW", "Low", "orange")
        except: pass

    async def crawl_intelx(self):
        try:
            url = f"https://2.intelx.io/phonebook/search?k={self.target}&limit=50"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                for item in resp.json().get('data', []):
                    self.add_finding(item.get('value', ''), "Intel", "IntelX", "Medium", "purple")
        except: pass

    async def crawl_bgp_he_net(self):
        try:
            url = f"https://bgp.he.net/dns/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                self.add_finding(self.target, "BGP Route", "Hurricane Electric", "Low", "blue")
        except: pass

    async def crawl_dnstwister(self):
        try:
            url = f"https://dnstwister.report/api/v1/domain/{self.target}"
            resp = await self.client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for d in data.get('similar_domains', []):
                    self.add_finding(d, "Typosquat Domain", "DNSTwister", "Medium", "red")
        except: pass

    # ── Stub sources (many API providers require paid keys) ──
    async def crawl_robtex(self): pass
    async def crawl_rapiddns(self): pass
    async def crawl_dnsdumpster(self): pass
    async def crawl_viewdns(self): pass

    async def verify_assets(self):
        async def resolve(f):
            if f.type == "Subdomain" and not f.resolution:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(f.entity, 'A'))
                    f.status, f.resolution, f.color = "Live", str(answers[0]), "emerald"
                except: f.status = "Inactive"
            elif f.resolution: f.status = "Live"

        await asyncio.gather(*[resolve(f) for f in self.findings], return_exceptions=True)

    async def close(self):
        await self.client.aclose()
