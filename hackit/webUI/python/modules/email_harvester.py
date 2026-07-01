import httpx
import asyncio
import re
import base64
from models import IntelligenceFinding
from collections import defaultdict
from urllib.parse import urlparse, urljoin

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
OBFUSCATED_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+\s*\[?@?at\]?\s*[a-zA-Z0-9.\-]+\s*\[?\.?dot?\]?\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
HIDDEN_AT_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\[\.\][a-zA-Z]{2,}", re.IGNORECASE)


def _dedup_and_merge(all_emails: dict, new_emails: dict):
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


async def crawl(target, client):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    all_emails = {}
    email_pattern = re.compile(rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}", re.IGNORECASE)
    domain_clean = domain.replace("www.", "")

    async def scrape_bing():
        try:
            resp = await client.get(
                f"https://www.bing.com/search?q=%22%40{domain}%22&count=50",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "Bing Search"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_google():
        try:
            resp = await client.get(
                f"https://www.google.com/search?q=%22%40{domain}%22",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "Google Search"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_duckduckgo():
        try:
            resp = await client.get(
                f"https://duckduckgo.com/html/?q=%22%40{domain}%22",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "DuckDuckGo Search"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_yandex():
        try:
            resp = await client.get(
                f"https://yandex.com/search/?text=%22%40{domain}%22",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "Yandex Search"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_hackertarget():
        try:
            resp = await client.get(
                f"https://api.hackertarget.com/pagelinks/?q={domain}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "HackerTarget"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_wayback_emails():
        try:
            resp = await client.get(
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&limit=200",
                timeout=30.0,
            )
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "Wayback Machine"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_pgp_keyservers():
        servers = [
            "https://keyserver.ubuntu.com",
            "https://pgp.mit.edu",
        ]
        emails = {}
        for server in servers:
            try:
                resp = await client.get(
                    f"{server}/pks/lookup?search={domain}&op=index&fingerprint=on",
                    timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                if resp.status_code == 200:
                    for m in EMAIL_RE.finditer(resp.text):
                        email = m.group(0).lower()
                        if domain in email.split("@")[-1]:
                            emails[email] = f"PGP Keyserver ({server.split('//')[1].split('/')[0]})"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_github_commits():
        try:
            resp = await client.get(
                f"https://api.github.com/search/commits?q={domain}+type:Commit&per_page=100",
                timeout=15.0,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/vnd.github.cloak-preview",
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                emails = {}
                for item in data.get("items", []):
                    commit = item.get("commit", {})
                    author = commit.get("author", {})
                    committer = commit.get("committer", {})
                    for person in (author, committer):
                        email = person.get("email", "")
                        if email and domain in email.split("@")[-1]:
                            emails[email.lower()] = "GitHub Commits"
                    msg = commit.get("message", "")
                    for m in EMAIL_RE.finditer(msg):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "GitHub Commits"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_linkedin_via_google_cache():
        try:
            queries = [
                f"site:linkedin.com/company {domain} email",
                f"site:linkedin.com {domain} \"@\"",
                f"inurl:linkedin.com/company/{domain_clean}",
            ]
            emails = {}
            for q in queries:
                try:
                    resp = await client.get(
                        f"https://webcache.googleusercontent.com/search?q=cache:{q.replace(' ', '%20')}",
                        timeout=10.0,
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    )
                    if resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1] or any(
                                dom in e.split("@")[-1] for dom in ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]
                            ):
                                emails[e] = "LinkedIn (Google Cache)"
                except:
                    pass
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_obfuscated_emails():
        sources_data = await asyncio.gather(
            _fetch_page(f"https://{domain}"),
            _fetch_page(f"http://{domain}"),
            _fetch_page(f"https://www.{domain}"),
            return_exceptions=True,
        )
        emails = {}
        for html in sources_data:
            if isinstance(html, Exception) or not html:
                continue
            for m in OBFUSCATED_EMAIL_RE.finditer(html):
                raw = m.group(0)
                cleaned = re.sub(r"\s*\[?@?at\]?\s*", "@", raw, flags=re.IGNORECASE)
                cleaned = re.sub(r"\s*\[?\.?dot?\]?\s*", ".", cleaned, flags=re.IGNORECASE)
                cleaned = cleaned.replace(" ", "").lower()
                if domain in cleaned.split("@")[-1]:
                    emails[cleaned] = "Obfuscated Email Pattern"
            for m in HIDDEN_AT_RE.finditer(html):
                cleaned = m.group(0).replace("[.]", ".").replace("[dot]", ".").lower()
                if domain in cleaned.split("@")[-1]:
                    emails[cleaned] = "Obfuscated Email Pattern"
            for m in re.finditer(r"[a-zA-Z0-9._%+\-]+\s*\(?\s*at\s*\)?\s*[a-zA-Z0-9.\-]+\s*\(?\s*dot\s*\)?\s*[a-zA-Z]{2,}", html, re.IGNORECASE):
                raw = m.group(0)
                cleaned = re.sub(r"\s*\(?\s*at\s*\)?\s*", "@", raw, flags=re.IGNORECASE)
                cleaned = re.sub(r"\s*\(?\s*dot\s*\)?\s*", ".", cleaned, flags=re.IGNORECASE)
                cleaned = cleaned.replace(" ", "").lower()
                if domain in cleaned.split("@")[-1]:
                    emails[cleaned] = "Obfuscated Email Pattern"
        _dedup_and_merge(all_emails, emails)

    async def scrape_hidden_emails():
        sources_data = await asyncio.gather(
            _fetch_page(f"https://{domain}"),
            _fetch_page(f"http://{domain}"),
            _fetch_page(f"https://www.{domain}"),
            return_exceptions=True,
        )
        emails = {}
        for html in sources_data:
            if isinstance(html, Exception) or not html:
                continue
            for match in re.finditer(r"<!--(.*?)-->", html, re.DOTALL):
                comment = match.group(1)
                for m in EMAIL_RE.finditer(comment):
                    e = m.group(0).lower()
                    if domain in e.split("@")[-1]:
                        emails[e] = "Hidden Email (HTML Comment)"
            for match in re.finditer(
                r'display\s*:\s*none|visibility\s*:\s*hidden|style\s*=\s*["\']display\s*:\s*none',
                html, re.IGNORECASE,
            ):
                start = max(0, match.start() - 500)
                end = min(len(html), match.end() + 500)
                snippet = html[start:end]
                for m in EMAIL_RE.finditer(snippet):
                    e = m.group(0).lower()
                    if domain in e.split("@")[-1]:
                        emails[e] = "Hidden Email (CSS Hidden)"
            for match in re.finditer(r'type=["\']hidden["\'].*?value=["\']([^"\']+)["\']', html, re.IGNORECASE):
                val = match.group(1)
                for m in EMAIL_RE.finditer(val):
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
                except Exception:
                    pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_js_emails():
        sources_data = await asyncio.gather(
            _fetch_page(f"https://{domain}"),
            _fetch_page(f"http://{domain}"),
            _fetch_page(f"https://www.{domain}"),
            return_exceptions=True,
        )
        emails = {}
        for html in sources_data:
            if isinstance(html, Exception) or not html:
                continue
            for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                script_url = match.group(1)
                if script_url.startswith("/"):
                    script_url = f"https://{domain}{script_url}"
                elif not script_url.startswith("http"):
                    script_url = f"https://{domain}/{script_url}"
                try:
                    js_resp = await client.get(script_url, timeout=10.0, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    })
                    if js_resp.status_code == 200:
                        for m in EMAIL_RE.finditer(js_resp.text):
                            e = m.group(0).lower()
                            emails[e] = "JavaScript (External Script)"
                except Exception:
                    pass
            for match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
                inline_js = match.group(1)
                for m in EMAIL_RE.finditer(inline_js):
                    e = m.group(0).lower()
                    emails[e] = "JavaScript (Inline Script)"
                for m in re.finditer(r'["\']([a-zA-Z0-9._%+\-]+(?:\s*\+\s*["\']@["\']\s*\+\s*["\'])[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']', inline_js):
                    raw = m.group(1)
                    cleaned = raw.replace('" + "', "").replace("' + '", "").replace(" ", "").lower()
                    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", cleaned):
                        emails[cleaned] = "JavaScript (Concatenated Email)"
                for m in re.finditer(r'(?:var|let|const)\s+\w+\s*=\s*["\'][^"\']*@[^"\']*["\']', inline_js):
                    var_match = re.search(r'["\']([^"\']*@[^"\']*)["\']', m.group(0))
                    if var_match:
                        e = var_match.group(1).lower()
                        if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", e):
                            emails[e] = "JavaScript (Variable Assignment)"
                for m in re.finditer(r'["\']([^"\']*)["\']\s*\+\s*["\']@["\']\s*\+\s*["\']([^"\']*)["\']', inline_js):
                    local = m.group(1)
                    dom = m.group(2)
                    combined = (local + "@" + dom).replace('"', "").replace("'", "").replace(" ", "").lower()
                    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", combined):
                        emails[combined] = "JavaScript (Concatenated Email)"
        _dedup_and_merge(all_emails, emails)

    async def generate_email_permutations():
        names_data = await asyncio.gather(
            _fetch_page(f"https://{domain}"),
            _fetch_page(f"http://{domain}"),
            _fetch_page(f"https://www.{domain}"),
            return_exceptions=True,
        )
        names = set()
        for html in names_data:
            if isinstance(html, Exception) or not html:
                continue
            for match in re.finditer(r'(?:linkedin\.com/in/|twitter\.com/|facebook\.com/|instagram\.com/)[a-zA-Z0-9_.-]+', html, re.IGNORECASE):
                path = match.group(0).split("/")[-1].lower()
                if path and len(path) > 2 and path != domain_clean:
                    names.add(path)
            for match in re.finditer(r'\b(?:Dr\.|Mr\.|Ms\.|Mrs\.)\s+([A-Z][a-z]+)\b', html):
                names.add(match.group(1).lower())
            for match in re.finditer(r'\babout["\']?>\s*(?:<[^>]*>)*\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)', html[:5000]):
                full = match.group(1).lower()
                parts = full.split()
                if len(parts) >= 2:
                    names.add(parts[0])
                    names.add(parts[-1])
                    names.add(full.replace(" ", "."))
            for match in re.finditer(r'(?:team|people|staff|about|leadership|member)[^<]{0,200}?' + re.escape(domain[:3]), html[:10000], re.IGNORECASE):
                for m in re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b', match.group(0)):
                    full = m.group(0).lower()
                    parts = full.split()
                    if len(parts) >= 2:
                        names.add(parts[0])
                        names.add(parts[-1])
                        names.add(parts[0] + "." + parts[-1] if len(parts) == 2 else full.replace(" ", "."))

        patterns_list = []
        for name in names:
            parts = name.replace(".", " ").replace("_", " ").replace("-", " ").split()
            if len(parts) == 1:
                patterns_list.append((f"{parts[0]}@{domain}", f"Permuted: {{name}}@{domain}"))
                patterns_list.append((f"{parts[0][0]}{parts[0]}@{domain}", f"Permuted: {{i}}{{l}}@{domain}"))
            elif len(parts) >= 2:
                first = parts[0]
                last = parts[-1]
                fi = first[0] if first else ""
                li = last[0] if last else ""
                patterns_list.append((f"{first}.{last}@{domain}", "Permuted: first.last@domain"))
                patterns_list.append((f"{first}{last}@{domain}", "Permuted: firstlast@domain"))
                patterns_list.append((f"{fi}{last}@{domain}", "Permuted: firstinitiallast@domain"))
                patterns_list.append((f"{first}{li}@{domain}", "Permuted: firstlastinitial@domain"))
                patterns_list.append((f"{fi}.{last}@{domain}", "Permuted: f.last@domain"))
                patterns_list.append((f"{first}.{li}@{domain}", "Permuted: first.l@domain"))
                patterns_list.append((f"{first}_{last}@{domain}", "Permuted: first_last@domain"))
                patterns_list.append((f"{first}-{last}@{domain}", "Permuted: first-last@domain"))
                patterns_list.append((f"{first}@{domain}", "Permuted: first@domain"))
                patterns_list.append((f"{last}@{domain}", "Permuted: last@domain"))
                patterns_list.append((f"{first}{li}{last}@{domain}", "Permuted: first+lastinitial+last@domain"))
                if len(parts) >= 3:
                    middle = parts[1]
                    mi = middle[0] if middle else ""
                    patterns_list.append((f"{first}.{middle}.{last}@{domain}", "Permuted: first.middle.last@domain"))
                    patterns_list.append((f"{fi}{mi}{last}@{domain}", "Permuted: fmiddleinitiallast@domain"))
                    patterns_list.append((f"{first}.{mi}.{last}@{domain}", "Permuted: first.mi.last@domain"))
                if len(parts) >= 2 and len(first) > 1 and len(last) > 1:
                    patterns_list.append((f"{first[:2]}{last}@{domain}", "Permuted: first2last@domain"))
                    patterns_list.append((f"{first}.{last[:2]}@{domain}", "Permuted: first.la@domain"))

        all_domain_emails = {e: src for e, src in all_emails.items() if domain in e.split("@")[-1]}
        known_names = set()
        for email in all_domain_emails:
            local = email.split("@")[0]
            local_clean = local.replace(".", " ").replace("_", " ").replace("-", " ")
            for part in local_clean.split():
                if len(part) > 2:
                    known_names.add(part)
            if "." in local:
                parts = local.split(".")
                for p in parts:
                    if len(p) > 2:
                        known_names.add(p)

        for known_name in known_names:
            parts = known_name.split()
            if len(parts) == 1:
                patterns_list.append((f"{known_name}@{domain}", "Permuted (from known): name@domain"))
                patterns_list.append((f"{known_name[0]}{known_name}@{domain}", "Permuted (from known): firstletter+name@domain"))

        existing = set(all_emails.keys())
        for email, source in patterns_list:
            email = email.lower()
            if email not in existing:
                if email not in all_emails:
                    existing.add(email)
                _dedup_and_merge(all_emails, {email: source})

    async def scrape_more_search_engines():
        engines = [
            ("Baidu", "https://www.baidu.com/s?wd=%22%40{domain}%22"),
            ("Yahoo", "https://search.yahoo.com/search?p=%22%40{domain}%22"),
            ("Ask", "https://www.ask.com/web?q=%22%40{domain}%22"),
            ("Mojeek", "https://www.mojeek.com/search?q=%22%40{domain}%22"),
            ("Swisscows", "https://swisscows.com/web?query=%22%40{domain}%22"),
            ("Dogpile", "https://www.dogpile.com/serp?q=%22%40{domain}%22"),
            ("Exalead", "https://www.exalead.com/search/web/results/?q=%22%40{domain}%22"),
        ]
        headers = {"User-Agent": "Mozilla/5.0"}
        emails = {}
        for name, tpl in engines:
            try:
                resp = await client.get(tpl.format(domain=domain), timeout=10.0, headers=headers)
                if resp.status_code == 200:
                    for m in email_pattern.finditer(resp.text):
                        emails[m.group(0).lower()] = f"{name} Search"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_certificate_transparency():
        try:
            resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30.0)
            if resp.status_code == 200:
                emails = {}
                for entry in resp.json():
                    for nv in entry.get("name_value", "").split("\n"):
                        for m in EMAIL_RE.finditer(nv):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "Certificate Transparency"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_sitemap_robots():
        urls = [
            f"https://{domain}/sitemap.xml", f"https://{domain}/robots.txt",
            f"https://{domain}/sitemap_index.xml", f"https://{domain}/sitemap/",
            f"http://{domain}/sitemap.xml", f"http://{domain}/robots.txt",
        ]
        emails = {}
        for url in urls:
            try:
                resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    src = "Sitemap" if "sitemap" in url else "Robots.txt"
                    for m in EMAIL_RE.finditer(resp.text):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = f"Site File ({src})"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_rss_feeds():
        feed_urls = [
            f"https://{domain}/feed", f"https://{domain}/feed.xml",
            f"https://{domain}/rss", f"https://{domain}/rss.xml",
            f"https://{domain}/atom.xml", f"https://{domain}/feed/atom",
        ]
        emails = {}
        for url in feed_urls:
            try:
                resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    name = url.rstrip("/").split("/")[-1]
                    for m in EMAIL_RE.finditer(resp.text):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = f"RSS Feed ({name})"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_contact_about_pages():
        paths = [
            "contact", "contact-us", "about", "about-us", "team", "our-team",
            "staff", "people", "company", "leadership", "management",
            "who-we-are", "meet-the-team", "employees",
        ]
        emails = {}
        for path in paths:
            for proto in ("https", "http"):
                try:
                    url = f"{proto}://{domain}/{path}"
                    resp = await client.get(url, timeout=8.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"Page ({path})"
                        for m in OBFUSCATED_EMAIL_RE.finditer(resp.text):
                            cleaned = re.sub(r"\s*\[?@?at\]?\s*", "@", m.group(0), flags=re.IGNORECASE)
                            cleaned = re.sub(r"\s*\[?\.?dot?\]?\s*", ".", cleaned, flags=re.IGNORECASE)
                            cleaned = cleaned.replace(" ", "").lower()
                            if domain in cleaned.split("@")[-1]:
                                emails[cleaned] = f"Page Obfuscated ({path})"
                except:
                    pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_pdf_files():
        try:
            resp = await client.get(f"https://www.google.com/search?q=site:{domain}+filetype:pdf", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return
            pdf_urls = list(set(re.findall(r'href=["\'](https?://[^"\']+\.pdf)["\']', resp.text)))[:15]
            emails = {}
            for pdf_url in pdf_urls:
                try:
                    pdf_resp = await client.get(pdf_url, timeout=20.0, headers={"User-Agent": "Mozilla/5.0"})
                    if pdf_resp.status_code == 200:
                        for m in EMAIL_RE.finditer(pdf_resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"PDF ({pdf_url.split('/')[-1][:30]})"
                except:
                    pass
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_dns_dmarc():
        try:
            import dns.resolver
        except ImportError:
            return
        emails = {}
        for record, src in [("_dmarc", "DMARC DNS"), ("_tlsrpt", "TLS-RPT DNS")]:
            try:
                for rdata in dns.resolver.resolve(f"{record}.{domain}", 'TXT'):
                    for m in EMAIL_RE.finditer(rdata.to_text()):
                        e = m.group(0).lower()
                        emails[e] = src
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_gitlab_commits():
        try:
            resp = await client.get(f"https://gitlab.com/api/v4/projects?search={domain}&per_page=50", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return
            emails = {}
            for proj in resp.json():
                pid = proj.get("id")
                if not pid:
                    continue
                try:
                    cr = await client.get(f"https://gitlab.com/api/v4/projects/{pid}/repository/commits?per_page=30", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                    if cr.status_code == 200:
                        for c in cr.json():
                            ae = c.get("author_email", "")
                            if ae and domain in ae.split("@")[-1]:
                                emails[ae.lower()] = "GitLab Commits"
                except:
                    pass
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_google_groups():
        try:
            resp = await client.get(f"https://groups.google.com/groups/search?q=%22%40{domain}%22&num=50", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for m in email_pattern.finditer(resp.text):
                    emails[m.group(0).lower()] = "Google Groups"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_github_gists():
        try:
            resp = await client.get(f"https://api.github.com/search/gists?q=%22%40{domain}%22&per_page=50", timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"})
            if resp.status_code != 200:
                return
            emails = {}
            for item in resp.json().get("items", []):
                for fname, finfo in item.get("files", {}).items():
                    for m in EMAIL_RE.finditer(finfo.get("content", "")):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "GitHub Gist"
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_news_mentions():
        sources = [
            ("Google News", f"https://news.google.com/search?q=%22%40{domain}%22"),
            ("Bing News", f"https://www.bing.com/news/search?q=%22%40{domain}%22"),
        ]
        emails = {}
        for name, url in sources:
            try:
                resp = await client.get(url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for m in email_pattern.finditer(resp.text):
                        emails[m.group(0).lower()] = name
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_role_based_emails():
        prefixes = [
            "info", "contact", "support", "sales", "admin", "help", "hello",
            "careers", "jobs", "hr", "billing", "accounts", "finance",
            "marketing", "pr", "press", "media", "partners", "business",
            "enquiries", "mail", "office", "team", "webmaster", "postmaster",
            "hostmaster", "abuse", "noreply", "feedback", "newsletter",
            "social", "community", "legal", "privacy", "security",
            "engineering", "tech", "it", "devops", "system", "network",
        ]
        _dedup_and_merge(all_emails, {f"{p}@{domain}".lower(): f"Role-Based ({p})" for p in prefixes})

    async def scrape_mailto_links():
        urls = [f"https://{domain}", f"http://{domain}", f"https://www.{domain}"]
        emails = {}
        for url in urls:
            try:
                resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for m in re.finditer(r'href=["\']mailto:([^"\']+)["\']', resp.text, re.IGNORECASE):
                        mailto = m.group(1).split("?")[0]
                        for mm in EMAIL_RE.finditer(mailto):
                            e = mm.group(0).lower()
                            dom = e.split("@")[-1]
                            if domain in dom:
                                emails[e] = "Mailto Link"
                            elif any(g in dom for g in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]):
                                emails[e] = "Mailto (Third-Party)"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_html_encoded():
        urls = [f"https://{domain}", f"http://{domain}", f"https://www.{domain}"]
        emails = {}
        for url in urls:
            try:
                resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    continue
                html = resp.text
                for m in re.finditer(r'&#([0-9]+);', html):
                    try:
                        ch = chr(int(m.group(1)))
                    except:
                        continue
                    if ch == "@":
                        snippet = html[max(0, m.start()-80):min(len(html), m.end()+80)]
                        decoded = re.sub(r'&#([0-9]+);', lambda x: chr(int(x.group(1))) if 32 <= int(x.group(1)) <= 126 else x.group(0), snippet)
                        for mm in EMAIL_RE.finditer(decoded):
                            e = mm.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "HTML Entity Encoded"
                for m in re.finditer(r'&#x([0-9a-fA-F]+);', html):
                    try:
                        ch = chr(int(m.group(1), 16))
                    except:
                        continue
                    if ch == "@":
                        snippet = html[max(0, m.start()-80):min(len(html), m.end()+80)]
                        decoded = re.sub(r'&#x([0-9a-fA-F]+);', lambda x: chr(int(x.group(1), 16)) if 32 <= int(x.group(1), 16) <= 126 else x.group(0), snippet)
                        for mm in EMAIL_RE.finditer(decoded):
                            e = mm.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "HTML Hex Encoded"
                for m in re.finditer(r'[a-zA-Z0-9._%+\-]+\s*\[\s*@\s*\]\s*[a-zA-Z0-9.\-]+\s*\[\s*\.\s*\]\s*[a-zA-Z]{2,}', html):
                    cleaned = m.group(0).replace("[", "").replace("]", "").replace(" ", "").lower()
                    if domain in cleaned.split("@")[-1]:
                        emails[cleaned] = "HTML Bracket Encoded"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_wayback_cdx():
        try:
            resp = await client.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original,timestamp&limit=500", timeout=30.0)
            if resp.status_code == 200:
                emails = {}
                for line in resp.text.split("\n"):
                    parts = line.strip().split(" ")
                    if parts:
                        for m in EMAIL_RE.finditer(parts[0]):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "Wayback CDX URL"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_wayback_snapshots():
        try:
            cdx = await client.get(f"http://web.archive.org/cdx/search/cdx?url={domain}&output=text&fl=timestamp&limit=10&sort=timestamp", timeout=20.0)
            if cdx.status_code != 200:
                return
            timestamps = [l.strip() for l in cdx.text.strip().split("\n") if l.strip()][:5]
            emails = {}
            for ts in timestamps:
                try:
                    snap = await client.get(f"https://web.archive.org/web/{ts}/{domain}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
                    if snap.status_code == 200:
                        for m in EMAIL_RE.finditer(snap.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"Wayback ({ts[:8]})"
                except:
                    pass
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_bitbucket_repos():
        try:
            resp = await client.get(f"https://api.bitbucket.org/2.0/repositories?q=description~%22{domain}%22&pagelen=50", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return
            emails = {}
            for repo in resp.json().get("values", []):
                oe = repo.get("owner", {}).get("email", "") or repo.get("owner", {}).get("display_name", "")
                if oe and "@" in oe and domain in oe.split("@")[-1]:
                    emails[oe.lower()] = "Bitbucket Repo"
                for lt, ld in repo.get("links", {}).items():
                    href = ld.get("href", "") if isinstance(ld, dict) else ""
                    for m in EMAIL_RE.finditer(href):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = f"Bitbucket Link ({lt})"
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_github_code_search():
        try:
            resp = await client.get(f"https://api.github.com/search/code?q=%22%40{domain}%22&per_page=50", timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"})
            if resp.status_code != 200:
                return
            items = resp.json().get("items", [])
            emails = {}
            for item in items:
                raw_url = item.get("html_url", "").replace("/blob/", "/raw/")
                try:
                    raw = await client.get(raw_url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                    if raw.status_code == 200:
                        for m in EMAIL_RE.finditer(raw.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = "GitHub Code"
                except:
                    pass
            _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_careers_pages():
        paths = ["careers", "jobs", "career", "job", "join-us", "work-with-us"]
        emails = {}
        for path in paths:
            for proto in ("https", "http"):
                try:
                    resp = await client.get(f"{proto}://{domain}/{path}", timeout=8.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code == 200:
                        for m in EMAIL_RE.finditer(resp.text):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]:
                                emails[e] = f"Careers ({path})"
                except:
                    pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_reddit():
        try:
            resp = await client.get(f"https://www.reddit.com/search.json?q=%22%40{domain}%22&limit=50", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for child in resp.json().get("data", {}).get("children", []):
                    d = child.get("data", {})
                    text = f"{d.get('title', '')} {d.get('selftext', '')}"
                    for m in EMAIL_RE.finditer(text):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "Reddit"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_stackoverflow():
        try:
            resp = await client.get(f"https://api.stackexchange.com/2.3/search?order=desc&sort=relevance&q={domain}&site=stackoverflow&filter=withbody", timeout=10.0)
            if resp.status_code == 200:
                emails = {}
                for item in resp.json().get("items", []):
                    for m in EMAIL_RE.finditer(item.get("body", "")):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]:
                            emails[e] = "Stack Overflow"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def scrape_paste_sites():
        urls = [
            f"https://psbdmp.ws/api/search/{domain}",
            f"https://pastebin.com/search?q={domain}",
        ]
        emails = {}
        for url in urls:
            try:
                resp = await client.get(url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    name = url.split("/")[2]
                    for m in email_pattern.finditer(resp.text):
                        emails[m.group(0).lower()] = f"Paste Site ({name})"
            except:
                pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_rdap_whois():
        try:
            resp = await client.get(f"https://rdap.verisign.com/com/v1/domain/{domain}", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for entity in resp.json().get("entities", []):
                    for vcard in entity.get("vcardArray", []):
                        if isinstance(vcard, list):
                            for item in vcard:
                                if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                                    e = item[3].lower()
                                    if domain in e.split("@")[-1]:
                                        emails[e] = "RDAP WHOIS"
                _dedup_and_merge(all_emails, emails)
        except:
            pass

    async def generate_advanced_permutations():
        names_data = await asyncio.gather(
            _fetch_page(f"https://{domain}"), _fetch_page(f"http://{domain}"),
            _fetch_page(f"https://www.{domain}"), return_exceptions=True,
        )
        names = set()
        for html in names_data:
            if isinstance(html, Exception) or not html:
                continue
            for m in EMAIL_RE.finditer(html):
                for p in re.split(r'[._\-]', m.group(0).split("@")[0].lower()):
                    if len(p) > 2 and not any(c in "0123456789" for c in p):
                        names.add(p)
            for m in re.finditer(r'\b([A-Z][a-z]+)\b', html):
                w = m.group(1).lower()
                if len(w) > 2:
                    names.add(w)
        sep = [".", "_", "-", ""]
        patterns = []
        for name in names:
            if len(name) < 3:
                continue
            for s in sep:
                patterns.append((f"{name}{s}{name}@{domain}", f"AdvPerm: {name}{s}{name}"))
                patterns.append((f"{name}{s}admin@{domain}", f"AdvPerm: {name}{s}admin"))
                patterns.append((f"admin{s}{name}@{domain}", f"AdvPerm: admin{s}{name}"))
        existing = set(all_emails.keys())
        for email, source in patterns:
            el = email.lower()
            if el not in existing and re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", el):
                existing.add(el)
                _dedup_and_merge(all_emails, {el: source})

    async def detect_email_format():
        known = [e for e in all_emails if domain in e.split("@")[-1]]
        if not known:
            return
        samples = await asyncio.gather(
            *[_fetch_page(f"https://{domain}/{p}") for p in ["team", "about", "contact", "people"]],
            return_exceptions=True,
        )
        names = []
        for html in samples:
            if isinstance(html, Exception) or not html:
                continue
            for m in re.finditer(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b', html):
                parts = m.group(1).split()
                if 2 <= len(parts) <= 4:
                    names.append((parts[0].lower(), parts[-1].lower()))
        new_emails = {}
        for first, last in set(names):
            fi, li = first[0], last[0]
            for cand, src in [
                (f"{first}.{last}@{domain}", "Predicted: first.last"),
                (f"{first}{last}@{domain}", "Predicted: firstlast"),
                (f"{fi}.{last}@{domain}", "Predicted: f.last"),
                (f"{first}.{li}@{domain}", "Predicted: first.l"),
                (f"{fi}{last}@{domain}", "Predicted: filast"),
                (f"{first}_{last}@{domain}", "Predicted: first_last"),
                (f"{first}@{domain}", "Predicted: first"),
            ]:
                if cand not in all_emails:
                    new_emails[cand] = src
        _dedup_and_merge(all_emails, new_emails)

    async def validate_domain_emails():
        bad_domains = {"example.com", "example.org", "example.net", "domain.com", "test.com", "email.com", "mail.com"}
        to_remove = set()
        for email in all_emails:
            dom = email.split("@")[-1]
            if dom in bad_domains or not re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", dom):
                to_remove.add(email)
            local = email.split("@")[0]
            if re.match(r"^[0-9.]+$", local):
                to_remove.add(email)
        for email in to_remove:
            all_emails.pop(email, None)

    async def _fetch_page(url):
        try:
            resp = await client.get(url, timeout=15.0, follow_redirects=True, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            })
            return resp.text if resp.status_code == 200 else None
        except Exception:
            return None

    async def detect_disposable_email_domains():
        disposable = {
            "mailinator.com","guerrillamail.com","tempmail.com","10minutemail.com","throwaway.email",
            "yopmail.com","maildrop.cc","getnada.com","sharklasers.com","trashmail.com",
            "temp-mail.org","fakeinbox.com","dispostable.com","burnermail.io","mytemp.email",
            "spambox.us","mailnator.com","mailcatch.com","emailondeck.com","spamgourmet.com",
            "jetable.org","kasmail.com","wegwerfmail.de","spamdecoy.net","mail7.io",
            "mailsac.com","tempinbox.xyz","anonbox.net","spamhereplease.com","spamhole.com",
        }
        for email in list(all_emails.keys()):
            dom = email.split("@")[-1]
            if dom in disposable:
                _dedup_and_merge(all_emails, {email: f"Disposable Domain ({dom})"})

    async def analyze_email_patterns():
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
            findings.append(IntelligenceFinding(
                entity=f"Email Pattern: {pat}",
                type="Email Analysis",
                source=f"EmailHarvester (Pattern Analysis)",
                confidence="Medium" if cnt > 1 else "Low",
                color="purple", category="Email OSINT", threat_level="Informational",
                raw_data=f"{pat}: {cnt} email(s)",
                tags=["analysis", "pattern"]
            ))

    async def analyze_email_diversity():
        if not all_emails: return
        domains_found = defaultdict(list)
        for email in all_emails:
            domains_found[email.split("@")[-1]].append(email)
        findings.append(IntelligenceFinding(
            entity=f"Email Domain Diversity: {len(domains_found)} domains across {len(all_emails)} emails",
            type="Email Analysis",
            source="EmailHarvester (Diversity)",
            confidence="High", color="purple", category="Email OSINT", threat_level="Informational",
            raw_data=", ".join(sorted(domains_found.keys())[:20]),
            tags=["analysis", "diversity"]
        ))
        for d, ems in sorted(domains_found.items(), key=lambda x: -len(x[1]))[:10]:
            findings.append(IntelligenceFinding(
                entity=f"Emails on {d}", type="Email Domain",
                source="EmailHarvester (Diversity)",
                confidence="Medium", color="slate", category="Email OSINT", threat_level="Informational",
                raw_data=f"{len(ems)} email(s): {', '.join(ems[:5])}",
                tags=["analysis", "domain"]
            ))

    async def analyze_email_stats():
        if not all_emails: return
        lengths = [len(e) for e in all_emails]
        local_lens = [len(e.split("@")[0]) for e in all_emails]
        findings.append(IntelligenceFinding(
            entity=f"Email Length Stats (N={len(all_emails)})",
            type="Email Analysis",
            source="EmailHarvester (Statistics)",
            confidence="High", color="cyan", category="Email OSINT", threat_level="Informational",
            raw_data=f"Min:{min(lengths)} Max:{max(lengths)} Avg:{sum(lengths)//len(lengths)} | Local Min:{min(local_lens)} Max:{max(local_lens)} Avg:{sum(local_lens)//len(local_lens)}",
            tags=["analysis", "statistics"]
        ))

    async def analyze_email_sources():
        if not all_emails: return
        source_counts = defaultdict(int)
        for email, sources in all_emails.items():
            src_list = sources if isinstance(sources, list) else [sources]
            for s in src_list:
                source_counts[s.split(" (")[0] if "(" in s else s] += 1
        findings.append(IntelligenceFinding(
            entity=f"Email Source Distribution ({len(all_emails)} emails)",
            type="Email Analysis",
            source="EmailHarvester (Sources)",
            confidence="High", color="cyan", category="Email OSINT", threat_level="Informational",
            raw_data=" | ".join(f"{s}: {c}" for s,c in sorted(source_counts.items(), key=lambda x: -x[1])),
            tags=["analysis", "sources"]
        ))
        multi = sum(1 for s in all_emails.values() if isinstance(s, list) and len(s) > 1)
        findings.append(IntelligenceFinding(
            entity=f"Multi-Source Emails: {multi}",
            type="Email Analysis",
            source="EmailHarvester (Sources)",
            confidence="Medium", color="green", category="Email OSINT", threat_level="Informational",
            raw_data=f"{multi} email(s) found from multiple independent sources",
            tags=["analysis", "confidence"]
        ))

    async def classify_role_emails():
        role_prefixes = {
            "info","contact","support","sales","admin","help","hello","careers","jobs",
            "hr","billing","accounts","finance","marketing","pr","press","media",
            "partners","business","enquiries","mail","office","team","webmaster",
            "postmaster","hostmaster","abuse","noreply","feedback","newsletter",
            "social","community","legal","privacy","security","engineering","tech",
            "it","devops","system","network","editor","editorial","recruitment",
            "bookings","reservations","orders","shop","store","service","services",
        }
        found = set()
        for email in all_emails:
            local = email.split("@")[0].lower()
            if local in role_prefixes or any(local.startswith(p) for p in role_prefixes):
                found.add(email)
        if found:
            findings.append(IntelligenceFinding(
                entity=f"Role-Based Emails: {len(found)}",
                type="Email Analysis",
                source="EmailHarvester (Role Classification)",
                confidence="High", color="yellow", category="Email OSINT", threat_level="Informational",
                raw_data=", ".join(sorted(found)[:20]),
                tags=["analysis", "role-based"]
            ))

    async def email_risk_scoring():
        if not all_emails: return
        risk_map = {}
        for email in all_emails:
            score = 0
            local = email.split("@")[0]
            dom = email.split("@")[-1]
            reasons = []
            if len(local) <= 2: score += 2; reasons.append("short_local")
            if re.search(r'[0-9]{4,}', local): score += 1; reasons.append("contains_year")
            if dom in {"gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","mail.com"}: score += 0
            elif dom == "protonmail.com": score += 0
            elif dom == "tempmail.com": score += 3; reasons.append("disposable")
            if email not in risk_map or score > risk_map[email][0]:
                risk_map[email] = (score, reasons)
        low = sum(1 for v in risk_map.values() if v[0] == 0)
        med = sum(1 for v in risk_map.values() if v[0] == 1)
        high = sum(1 for v in risk_map.values() if v[0] >= 2)
        findings.append(IntelligenceFinding(
            entity=f"Email Risk Distribution | Low: {low} Med: {med} High: {high}",
            type="Email Analysis",
            source="EmailHarvester (Risk Scoring)",
            confidence="Medium", color="orange", category="Email OSINT", threat_level="Informational",
            raw_data=f"Risk scoring based on local-part length, numeric patterns, domain reputation",
            tags=["analysis", "risk"]
        ))

    async def scrape_securitytrails():
        try:
            resp = await client.get(f"https://securitytrails.com/domain/{domain}/dns", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for m in EMAIL_RE.finditer(resp.text):
                    e = m.group(0).lower()
                    if domain in e.split("@")[-1]: emails[e] = "SecurityTrails"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_urlscan():
        try:
            resp = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=50", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for result in resp.json().get("results", []):
                    for m in EMAIL_RE.finditer(str(result.get("page", {}))):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]: emails[e] = "URLScan.io"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_virustotal():
        try:
            resp = await client.get(f"https://www.virustotal.com/ui/domains/{domain}/comments", timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            if resp.status_code == 200:
                emails = {}
                for c in resp.json().get("data", []):
                    for m in EMAIL_RE.finditer(str(c.get("attributes", {}))):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]: emails[e] = "VirusTotal"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_shodan():
        try:
            resp = await client.get(f"https://www.shodan.io/search?query=hostname%3A{domain}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for m in EMAIL_RE.finditer(resp.text):
                    e = m.group(0).lower()
                    if domain in e.split("@")[-1]: emails[e] = "Shodan"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_google_dorks():
        dorks = [
            f"site:linkedin.com \"{domain}\" email", f"site:github.com \"{domain}\" \"@\"",
            f"site:pastebin.com \"{domain}\"", f"\"@{domain}\" filetype:xls",
            f"\"@{domain}\" filetype:csv", f"\"@{domain}\" filetype:txt",
            f"\"@{domain}\" intitle:contact", f"\"@{domain}\" inurl:team",
            f"\"@{domain}\" inurl:staff",
        ]
        emails = {}
        for dork in dorks:
            try:
                resp = await client.get(f"https://www.google.com/search?q={dork.replace(' ', '+')}", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for m in email_pattern.finditer(resp.text): emails[m.group(0).lower()] = f"Google Dork ({dork[:30]})"
            except: pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_social_media_profiles():
        urls = [f"https://{domain}", f"http://{domain}", f"https://www.{domain}"]
        social_patterns = [
            (r'linkedin\.com/(?:company|in)/[\w-]+', 'LinkedIn'),
            (r'twitter\.com/\w{1,15}', 'Twitter'),
            (r'facebook\.com/[\w._-]+', 'Facebook'),
            (r'instagram\.com/[\w_.]+', 'Instagram'),
            (r'youtube\.com/(?:c|channel|user)/[\w-]+', 'YouTube'),
            (r'github\.com/[\w-]+', 'GitHub'),
            (r't\.me/\w+', 'Telegram'),
            (r'discord\.gg/[\w]+', 'Discord'),
        ]
        for url in urls:
            try:
                resp = await client.get(url, timeout=10.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for pat, label in social_patterns:
                        for m in re.finditer(pat, resp.text, re.IGNORECASE):
                            findings.append(IntelligenceFinding(
                                entity=m.group(0).lower(),
                                type="Social Media Profile",
                                source=f"EmailHarvester ({label})",
                                confidence="High", color="green", category="Email OSINT", threat_level="Informational",
                                raw_data=f"Found on {domain} homepage",
                                tags=["social-media"]
                            ))
            except: pass

    async def scrape_whois_deep():
        try:
            resp = await client.get(f"https://rdap.verisign.com/com/v1/domain/{domain}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                emails = {}
                for entity in data.get("entities", []):
                    for vcard in entity.get("vcardArray", []):
                        if isinstance(vcard, list):
                            for item in vcard:
                                if isinstance(item, list) and len(item) >= 4:
                                    if item[0] == "email":
                                        e = item[3].lower()
                                        emails[e] = f"RDAP ({','.join(entity.get('roles',['unknown']))})"
                                    elif item[0] == "tel":
                                        findings.append(IntelligenceFinding(
                                            entity=item[3], type="Phone Number",
                                            source="EmailHarvester (RDAP)",
                                            confidence="High", color="orange", category="Email OSINT", threat_level="Informational",
                                            raw_data=f"Phone in RDAP for {domain}",
                                            tags=["contact"]
                                        ))
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_forum_results():
        forums = [
            ("StackOverflow", f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&sort=relevance&q={domain}&site=stackoverflow"),
            ("ServerFault", f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&sort=relevance&q={domain}&site=serverfault"),
            ("SuperUser", f"https://api.stackexchange.com/2.3/search/excerpts?order=desc&sort=relevance&q={domain}&site=superuser"),
        ]
        emails = {}
        for name, url in forums:
            try:
                resp = await client.get(url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        for m in EMAIL_RE.finditer(item.get("body", "") + item.get("title", "")):
                            e = m.group(0).lower()
                            if domain in e.split("@")[-1]: emails[e] = f"Forum ({name})"
            except: pass
        _dedup_and_merge(all_emails, emails)

    async def scrape_telegram_search():
        try:
            resp = await client.get(f"https://t.me/s/{domain}", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for m in EMAIL_RE.finditer(resp.text):
                    e = m.group(0).lower()
                    if domain in e.split("@")[-1]: emails[e] = "Telegram"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def scrape_hackerone_bugcrowd():
        for platform in [f"hackerone.com/teams/{domain}", f"bugcrowd.com/{domain}"]:
            try:
                resp = await client.get(f"https://{platform}", timeout=10.0, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    emails = {}
                    for m in EMAIL_RE.finditer(resp.text):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]: emails[e] = f"Security Platform ({platform.split('/')[0]})"
                    _dedup_and_merge(all_emails, emails)
            except: pass

    async def scrape_keybase():
        try:
            resp = await client.get(f"https://keybase.io/_/api/1.0/user/lookup.json?q={domain}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                emails = {}
                for user in resp.json().get("them", []):
                    for m in EMAIL_RE.finditer(str(user)):
                        e = m.group(0).lower()
                        if domain in e.split("@")[-1]: emails[e] = "Keybase"
                _dedup_and_merge(all_emails, emails)
        except: pass

    async def generate_tool_recommendations():
        recs = []
        if all_emails:
            recs.append("theHarvester: python3 theHarvester.py -d {domain} -b all")
            recs.append("sherlock: sherlock {domain}")
            recs.append("holehe: holehe {email} (check OAuth signups)")
            recs.append("social-analyzer: npm run start {domain}")
            recs.append("hatbeat: hatbeat -d {domain}")
            recs.append("infoga: infoga -d {domain}")
            recs.append("recon-ng: use recon/contacts/domains/hunter_io")
        if recs:
            findings.append(IntelligenceFinding(
                entity=f"Tool Recommendations ({len(recs)})",
                type="Guidance",
                source="EmailHarvester (Suggestions)",
                confidence="High", color="cyan", category="Email OSINT", threat_level="Informational",
                raw_data="\n".join(recs),
                tags=["guidance", "tools"]
            ))

    await asyncio.gather(
        scrape_bing(),
        scrape_google(),
        scrape_duckduckgo(),
        scrape_yandex(),
        scrape_hackertarget(),
        scrape_wayback_emails(),
        scrape_pgp_keyservers(),
        scrape_github_commits(),
        scrape_linkedin_via_google_cache(),
        scrape_obfuscated_emails(),
        scrape_hidden_emails(),
        scrape_js_emails(),
        generate_email_permutations(),
        scrape_more_search_engines(),
        scrape_certificate_transparency(),
        scrape_sitemap_robots(),
        scrape_rss_feeds(),
        scrape_contact_about_pages(),
        scrape_pdf_files(),
        scrape_dns_dmarc(),
        scrape_gitlab_commits(),
        scrape_google_groups(),
        scrape_github_gists(),
        scrape_news_mentions(),
        scrape_role_based_emails(),
        scrape_mailto_links(),
        scrape_html_encoded(),
        scrape_wayback_cdx(),
        scrape_wayback_snapshots(),
        scrape_bitbucket_repos(),
        scrape_github_code_search(),
        scrape_careers_pages(),
        scrape_reddit(),
        scrape_stackoverflow(),
        scrape_paste_sites(),
        scrape_rdap_whois(),
        generate_advanced_permutations(),
        detect_email_format(),
        validate_domain_emails(),
        scrape_securitytrails(),
        scrape_urlscan(),
        scrape_virustotal(),
        scrape_shodan(),
        scrape_google_dorks(),
        scrape_social_media_profiles(),
        scrape_whois_deep(),
        scrape_forum_results(),
        scrape_telegram_search(),
        scrape_hackerone_bugcrowd(),
        scrape_keybase(),
    )

    await asyncio.gather(
        detect_disposable_email_domains(),
        analyze_email_patterns(),
        analyze_email_diversity(),
        analyze_email_stats(),
        analyze_email_sources(),
        classify_role_emails(),
        email_risk_scoring(),
        generate_tool_recommendations(),
    )

    for email, sources in all_emails.items():
        source_list = sources if isinstance(sources, list) else [sources]
        primary_source = source_list[0]
        domain_part = email.split("@")[-1]
        is_primary = domain_part == domain or domain_part.endswith("." + domain)
        findings.append(IntelligenceFinding(
            entity=email,
            type="Email Address",
            source=f"EmailHarvester ({primary_source})",
            confidence="High" if is_primary else "Medium",
            color="cyan" if is_primary else "slate",
            category="Email OSINT",
            threat_level="Informational",
            raw_data=f"Found via {' + '.join(source_list)} | Domain: {domain_part}",
            tags=["email"] if is_primary else ["email", "third-party"]
        ))

    if all_emails:
        domains_used = defaultdict(list)
        for email in all_emails:
            dom = email.split("@")[-1]
            domains_used[dom].append(email)

        for dom, emails in sorted(domains_used.items(), key=lambda x: -len(x[1])):
            if dom != domain:
                findings.append(IntelligenceFinding(
                    entity=f"{len(emails)} email(s) on {dom}",
                    type="Email Domain Relationship",
                    source="EmailHarvester (Correlation)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"Third-party domain {dom} has {len(emails)} email(s)",
                    tags=["correlation"]
                ))

        source_breakdown = defaultdict(set)
        for email, sources in all_emails.items():
            src_list = sources if isinstance(sources, list) else [sources]
            for s in src_list:
                base = s.split(" (")[0] if "(" in s else s
                source_breakdown[base].add(email)

        source_summary = "; ".join(
            f"{src}: {len(emails)}" for src, emails in sorted(source_breakdown.items(), key=lambda x: -len(x[1]))
        )

        tld_analysis = defaultdict(int)
        for email in all_emails:
            dom = email.split("@")[-1]
            tld = dom.split(".")[-1]
            tld_analysis[tld] += 1
        tld_summary = "; ".join(f".{tld}: {count}" for tld, count in sorted(tld_analysis.items(), key=lambda x: -x[1]))

        primary_emails = [e for e in all_emails if e.split("@")[-1] == domain or e.split("@")[-1].endswith("." + domain)]
        third_party_emails = [e for e in all_emails if e not in primary_emails]
        new_vs_total = f"Total: {len(all_emails)} unique emails | Primary domain: {len(primary_emails)} | Third-party: {len(third_party_emails)}"

        findings.append(IntelligenceFinding(
            entity=f"Total: {len(all_emails)} unique email addresses",
            type="Email Harvest Summary",
            source="EmailHarvester",
            confidence="High",
            color="cyan",
            threat_level="Informational",
            raw_data=f"{new_vs_total} | Sources: {source_summary} | TLDs: {tld_summary}",
            tags=["summary"]
        ))

    return findings
