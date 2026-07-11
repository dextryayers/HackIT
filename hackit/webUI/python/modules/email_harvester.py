import httpx
import asyncio
import re
import base64
from collections import defaultdict
from urllib.parse import urlparse
from module_base import BaseScanner

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
OBFUSCATED_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+\s*\[?@?at\]?\s*[a-zA-Z0-9.\-]+\s*\[?\.?dot?\]?\.[a-zA-Z]{2,}", re.IGNORECASE)
HIDDEN_AT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\[\.\][a-zA-Z]{2,}", re.IGNORECASE)

class EmailHarvesterScanner(BaseScanner):
    name = "email_harvester"

    def _dedup_and_merge(self, all_emails: dict, new_emails: dict):
        for email, sources in new_emails.items():
            email = email.lower().strip(".,;:()[]{}<>\"'")
            if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
                continue
            if email in all_emails:
                existing = all_emails[email]
                if isinstance(existing, list):
                    existing.extend(s for s in (sources if isinstance(sources, list) else [sources]) if s not in existing)
                else:
                    merged = [existing]
                    merged.extend(s for s in (sources if isinstance(sources, list) else [sources]) if s not in merged)
                    all_emails[email] = merged
            else:
                all_emails[email] = sources if isinstance(sources, list) else [sources]

    async def _fetch_page(self, url: str):
        try:
            resp = await self.safe_request(url, timeout=15, follow_redirects=True, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            })
            return resp.text if resp else None
        except:
            return None

    async def _search_scrape(self, url: str, source_name: str, all_emails: dict, domain: str):
        try:
            resp = await self.safe_request(url, timeout=10, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            if resp and resp.status_code == 200:
                emails = {}
                pattern = re.compile(rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}", re.IGNORECASE)
                for m in pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = source_name
                self._dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scan(self) -> list:
        results = []
        domain = self.target
        all_emails = {}
        email_pattern = re.compile(rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}", re.IGNORECASE)
        domain_clean = domain.replace("www.", "")

        search_tasks = [
            self._search_scrape(f"https://www.bing.com/search?q=%22%40{domain}%22&count=50", "Bing Search", all_emails, domain),
            self._search_scrape(f"https://www.google.com/search?q=%22%40{domain}%22", "Google Search", all_emails, domain),
            self._search_scrape(f"https://duckduckgo.com/html/?q=%22%40{domain}%22", "DuckDuckGo Search", all_emails, domain),
            self._search_scrape(f"https://yandex.com/search/?text=%22%40{domain}%22", "Yandex Search", all_emails, domain),
            self._search_scrape(f"https://api.hackertarget.com/pagelinks/?q={domain}", "HackerTarget", all_emails, domain),
            self._search_scrape(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&limit=200", "Wayback Machine", all_emails, domain),
        ]
        await asyncio.gather(*search_tasks)

        async def scrape_pgp_keyservers():
            emails = {}
            for server in ["https://keyserver.ubuntu.com", "https://pgp.mit.edu"]:
                try:
                    resp = await self.safe_request(f"{server}/pks/lookup?search={domain}&op=index&fingerprint=on", timeout=15, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    })
                    if resp and resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            email = m.group(0).lower()
                            if domain in email.split("@")[-1]:
                                emails[email] = f"PGP Keyserver ({server.split('//')[1].split('/')[0]})"
                except:
                    pass
            self._dedup_and_merge(all_emails, emails)

        async def scrape_github_commits():
            try:
                resp = await self.safe_request(f"https://api.github.com/search/commits?q={domain}+type:Commit&per_page=100", timeout=15, headers={
                    "User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.cloak-preview",
                })
                if resp and resp.status_code == 200:
                    emails = {}
                    data = resp.json()
                    for item in data.get("items", []):
                        commit = item.get("commit", {})
                        for person in (commit.get("author", {}), commit.get("committer", {})):
                            email = person.get("email", "")
                            if email and domain in email.split("@")[-1]:
                                emails[email.lower()] = "GitHub Commits"
                        for m in EMAIL_RE.finditer(commit.get("message", "")):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "GitHub Commits"
                    self._dedup_and_merge(all_emails, emails)
            except:
                pass

        async def scrape_linkedin_via_google_cache():
            queries = [
                f"site:linkedin.com/company {domain} email",
                f"site:linkedin.com {domain} \"@\"",
                f"inurl:linkedin.com/company/{domain_clean}",
            ]
            emails = {}
            for q in queries:
                try:
                    resp = await self.safe_request(f"https://webcache.googleusercontent.com/search?q=cache:{q.replace(' ', '%20')}", timeout=10, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    })
                    if resp and resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            dom = e.split("@")[-1]
                            if domain in dom or any(g in dom for g in ["gmail.com","outlook.com","yahoo.com","hotmail.com"]):
                                emails[e] = "LinkedIn (Google Cache)"
                except:
                    pass
            self._dedup_and_merge(all_emails, emails)

        async def scrape_page_emails():
            sources_data = await asyncio.gather(
                self._fetch_page(f"https://{domain}"), self._fetch_page(f"http://{domain}"),
                self._fetch_page(f"https://www.{domain}"), return_exceptions=True,
            )
            emails = {}
            for html in sources_data:
                if isinstance(html, Exception) or not html:
                    continue
                for m in OBFUSCATED_EMAIL_RE.finditer(html):
                    cleaned = re.sub(r"\s*\[?@?at\]?\s*", "@", m.group(0), flags=re.IGNORECASE)
                    cleaned = re.sub(r"\s*\[?\.?dot?\]?\s*", ".", cleaned, flags=re.IGNORECASE)
                    cleaned = cleaned.replace(" ", "").lower()
                    if domain in cleaned.split("@")[-1]:
                        emails[cleaned] = "Obfuscated Email Pattern"
                for m in HIDDEN_AT_RE.finditer(html):
                    cleaned = m.group(0).replace("[.]", ".").replace("[dot]", ".").lower()
                    if domain in cleaned.split("@")[-1]:
                        emails[cleaned] = "Obfuscated Email Pattern"
                for m in re.finditer(r"[a-zA-Z0-9._%+\-]+\s*\(?\s*at\s*\)?\s*[a-zA-Z0-9.\-]+\s*\(?\s*dot\s*\)?\s*[a-zA-Z]{2,}", html, re.IGNORECASE):
                    cleaned = re.sub(r"\s*\(?\s*at\s*\)?\s*", "@", m.group(0), flags=re.IGNORECASE)
                    cleaned = re.sub(r"\s*\(?\s*dot\s*\)?\s*", ".", cleaned, flags=re.IGNORECASE)
                    cleaned = cleaned.replace(" ", "").lower()
                    if domain in cleaned.split("@")[-1]:
                        emails[cleaned] = "Obfuscated Email Pattern"
                for match in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
                    for m in EMAIL_RE.finditer(match.group(1)):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "Hidden Email (HTML Comment)"
                for match in re.finditer(r'display\s*:\s*none|visibility\s*:\s*hidden|style\s*=\s*["\']display\s*:\s*none', html, re.IGNORECASE):
                    start = max(0, match.start() - 500)
                    snippet = html[start:min(len(html), match.end() + 500)]
                    for m in EMAIL_RE.finditer(snippet):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "Hidden Email (CSS Hidden)"
                for match in re.finditer(r'type=["\']hidden["\'].*?value=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    for m in EMAIL_RE.finditer(match.group(1)):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "Hidden Email (Hidden Input)"
                for match in re.finditer(r'base64,\s*([A-Za-z0-9+/=]+)', html):
                    try:
                        decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="ignore")
                        for m in EMAIL_RE.finditer(decoded):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "Hidden Email (Base64 Encoded)"
                    except:
                        pass
                for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    script_url = match.group(1)
                    if script_url.startswith("/"):
                        script_url = f"https://{domain}{script_url}"
                    elif not script_url.startswith("http"):
                        script_url = f"https://{domain}/{script_url}"
                    try:
                        js_resp = await self.safe_request(script_url, timeout=10, headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                        })
                        if js_resp:
                            for m in EMAIL_RE.finditer(js_resp.text):
                                e = m.group(0).lower()
                                emails[e] = "JavaScript (External Script)"
                    except:
                        pass
                for match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
                    inline_js = match.group(1)
                    for m in EMAIL_RE.finditer(inline_js):
                        e = m.group(0).lower()
                        emails[e] = "JavaScript (Inline Script)"
            self._dedup_and_merge(all_emails, emails)

        async def scrape_more_sources():
            emails = {}
            for name, tpl in [
                ("Baidu", "https://www.baidu.com/s?wd=%22%40{domain}%22"),
                ("Yahoo", "https://search.yahoo.com/search?p=%22%40{domain}%22"),
                ("Ask", "https://www.ask.com/web?q=%22%40{domain}%22"),
                ("Mojeek", "https://www.mojeek.com/search?q=%22%40{domain}%22"),
                ("Swisscows", "https://swisscows.com/web?query=%22%40{domain}%22"),
                ("Dogpile", "https://www.dogpile.com/serp?q=%22%40{domain}%22"),
                ("Exalead", "https://www.exalead.com/search/web/results/?q=%22%40{domain}%22"),
            ]:
                try:
                    resp = await self.safe_request(tpl.format(domain=domain), timeout=10, headers={"User-Agent": "Mozilla/5.0"})
                    if resp and resp.status_code == 200:
                        for m in email_pattern.finditer(resp.text):
                            emails[m.group(0).lower()] = f"{name} Search"
                except:
                    pass
            for url in [f"https://{domain}/sitemap.xml", f"https://{domain}/robots.txt",
                        f"http://{domain}/sitemap.xml", f"http://{domain}/robots.txt"]:
                try:
                    resp = await self.safe_request(url, timeout=10, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    if resp and resp.status_code == 200:
                        src = "Sitemap" if "sitemap" in url else "Robots.txt"
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"Site File ({src})"
                except:
                    pass
            for feed_url in [f"https://{domain}/feed", f"https://{domain}/rss.xml", f"https://{domain}/atom.xml"]:
                try:
                    resp = await self.safe_request(feed_url, timeout=10, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    if resp and resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"RSS Feed ({feed_url.rstrip('/').split('/')[-1]})"
                except:
                    pass
            for path in ["contact","contact-us","about","team","staff","people","leadership"]:
                for proto in ("https", "http"):
                    try:
                        resp = await self.safe_request(f"{proto}://{domain}/{path}", timeout=8, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                        if resp and resp.status_code == 200:
                            for m in EMAIL_RE.finditer(resp.text):
                                e = m.group(0).lower()
                                if domain in e.split("@")[-1]:
                                    emails[e] = f"Page ({path})"
                    except:
                        pass
            for p in ["info","contact","support","sales","admin","help","hello","careers","jobs","hr","billing","accounts","finance","marketing","pr","press","media","partners","business","enquiries","mail","office","team","webmaster","postmaster","hostmaster","abuse","noreply","feedback","newsletter","social","community","legal","privacy","security","engineering","tech","it","devops","system","network"]:
                emails[f"{p}@{domain}".lower()] = f"Role-Based ({p})"
            for url in [f"https://{domain}", f"http://{domain}", f"https://www.{domain}"]:
                try:
                    resp = await self.safe_request(url, timeout=10, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    if resp and resp.status_code == 200:
                        for m in re.finditer(r'href=["\']mailto:([^"\']+)["\']', resp.text, re.IGNORECASE):
                            mailto = m.group(1).split("?")[0]
                            for mm in EMAIL_RE.finditer(mailto):
                                e = mm.group(0).lower()
                                dom = e.split("@")[-1]
                                if domain in dom:
                                    emails[e] = "Mailto Link"
                                elif any(g in dom for g in ["gmail.com","yahoo.com","hotmail.com","outlook.com"]):
                                    emails[e] = "Mailto (Third-Party)"
                except:
                    pass
            self._dedup_and_merge(all_emails, emails)

        await asyncio.gather(
            scrape_pgp_keyservers(), scrape_github_commits(), scrape_linkedin_via_google_cache(),
            scrape_page_emails(), scrape_more_sources(),
            self._search_scrape(f"https://crt.sh/?q=%25.{domain}&output=json", "Certificate Transparency", all_emails, domain),
            self._search_scrape(f"https://groups.google.com/groups/search?q=%22%40{domain}%22&num=50", "Google Groups", all_emails, domain),
            self._search_scrape(f"https://api.github.com/search/gists?q=%22%40{domain}%22&per_page=50", "GitHub Gist", all_emails, domain),
            self._search_scrape(f"https://news.google.com/search?q=%22%40{domain}%22", "Google News", all_emails, domain),
            self._search_scrape(f"https://www.bing.com/news/search?q=%22%40{domain}%22", "Bing News", all_emails, domain),
            self._search_scrape(f"https://www.reddit.com/search.json?q=%22%40{domain}%22&limit=50", "Reddit", all_emails, domain),
        )

        bad_domains = {"example.com","example.org","example.net","domain.com","test.com","email.com","mail.com"}
        for email in list(all_emails.keys()):
            dom = email.split("@")[-1]
            if dom in bad_domains or not re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", dom):
                all_emails.pop(email, None)
            local = email.split("@")[0]
            if re.match(r"^[0-9.]+$", local):
                all_emails.pop(email, None)

        for email, sources in all_emails.items():
            src_list = sources if isinstance(sources, list) else [sources]
            f = self.finding(
                entity=email, ftype="Email Address", source="EmailHarvester",
                confidence="High", color="blue", category="Email OSINT",
                threat_level="Informational", status="Harvested",
                raw_data=f"Sources: {', '.join(src_list)}",
                tags=["email", "harvested"]
            )
            if f: results.append(f)

        patterns = defaultdict(int)
        for email in all_emails:
            local = email.split("@")[0]
            if re.match(r"^[a-z]+\.[a-z]+$", local): patterns["first.last"] += 1
            if re.match(r"^[a-z]+\.[a-z]{1}$", local): patterns["first.li"] += 1
            if re.match(r"^[a-z]{1}\.[a-z]+$", local): patterns["fi.last"] += 1
            if "_" in local: patterns["underscore_separator"] += 1
            if "-" in local: patterns["hyphen_separator"] += 1
            if re.match(r"^[a-z]+[0-9]", local): patterns["alphanumeric_prefix"] += 1
            if re.match(r"^[a-z]+$", local): patterns["single_word_username"] += 1
            if len(local) <= 3: patterns["short_username"] += 1
        for pat, cnt in sorted(patterns.items(), key=lambda x: -x[1]):
            f = self.finding(
                entity=f"Email Pattern: {pat}", ftype="Email Analysis",
                confidence="Medium" if cnt > 1 else "Low", color="purple",
                category="Email OSINT", threat_level="Informational",
                raw_data=f"{pat}: {cnt} email(s)", tags=["analysis", "pattern"]
            )
            if f: results.append(f)

        if all_emails:
            domains_found = defaultdict(list)
            for email in all_emails:
                domains_found[email.split("@")[-1]].append(email)
            f = self.finding(
                entity=f"Email Domain Diversity: {len(domains_found)} domains across {len(all_emails)} emails",
                ftype="Email Analysis", confidence="High", color="purple",
                category="Email OSINT", threat_level="Informational",
                raw_data=", ".join(sorted(domains_found.keys())[:20]),
                tags=["analysis", "diversity"]
            )
            if f: results.append(f)
            for d, ems in sorted(domains_found.items(), key=lambda x: -len(x[1]))[:10]:
                f = self.finding(
                    entity=f"Emails on {d}", ftype="Email Domain",
                    confidence="Medium", color="slate", category="Email OSINT",
                    threat_level="Informational",
                    raw_data=f"{len(ems)} email(s): {', '.join(ems[:5])}",
                    tags=["analysis", "domain"]
                )
                if f: results.append(f)

            source_counts = defaultdict(int)
            for email, sources in all_emails.items():
                src_list = sources if isinstance(sources, list) else [sources]
                for s in src_list:
                    source_counts[s.split(" (")[0] if "(" in s else s] += 1
            f = self.finding(
                entity=f"Email Source Distribution ({len(all_emails)} emails)",
                ftype="Email Analysis", confidence="High", color="cyan",
                category="Email OSINT", threat_level="Informational",
                raw_data=" | ".join(f"{s}: {c}" for s,c in sorted(source_counts.items(), key=lambda x: -x[1])),
                tags=["analysis", "sources"]
            )
            if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = EmailHarvesterScanner(target, client)
    return await scanner.scan()
