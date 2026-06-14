import httpx
import asyncio
import re
from models import IntelligenceFinding
from collections import defaultdict

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

async def crawl(target, client):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    all_emails = {}
    email_pattern = re.compile(rf"[a-zA-Z0-9._%+\-]+@{re.escape(domain)}", re.IGNORECASE)

    async def scrape_bing():
        try:
            resp = await client.get(
                f"https://www.bing.com/search?q=%22%40{domain}%22&count=50",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            if resp.status_code == 200:
                for m in email_pattern.finditer(resp.text):
                    email = m.group(0).lower()
                    if email not in all_emails:
                        all_emails[email] = "Bing Search"
        except: pass

    async def scrape_google():
        try:
            resp = await client.get(
                f"https://www.google.com/search?q=%22%40{domain}%22",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if resp.status_code == 200:
                for m in email_pattern.finditer(resp.text):
                    email = m.group(0).lower()
                    if email not in all_emails:
                        all_emails[email] = "Google Search"
        except: pass

    async def scrape_duckduckgo():
        try:
            resp = await client.get(
                f"https://duckduckgo.com/html/?q=%22%40{domain}%22",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if resp.status_code == 200:
                for m in email_pattern.finditer(resp.text):
                    email = m.group(0).lower()
                    if email not in all_emails:
                        all_emails[email] = "DuckDuckGo Search"
        except: pass

    async def scrape_pgp():
        try:
            resp = await client.get(
                f"https://api.hackertarget.com/pagelinks/?q={domain}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                for m in email_pattern.finditer(resp.text):
                    email = m.group(0).lower()
                    if email not in all_emails:
                        all_emails[email] = "HackerTarget"
        except: pass

    async def scrape_wayback_emails():
        try:
            resp = await client.get(
                f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&limit=200",
                timeout=30.0,
            )
            if resp.status_code == 200:
                for m in email_pattern.finditer(resp.text):
                    email = m.group(0).lower()
                    if email not in all_emails:
                        all_emails[email] = "Wayback Machine"
        except: pass

    await asyncio.gather(
        scrape_bing(),
        scrape_google(),
        scrape_duckduckgo(),
        scrape_pgp(),
        scrape_wayback_emails(),
    )

    for email, source in all_emails.items():
        domain_part = email.split("@")[-1]
        is_primary = domain_part == domain or domain_part.endswith("." + domain)
        findings.append(IntelligenceFinding(
            entity=email,
            type="Email Address",
            source=f"EmailHarvester ({source})",
            confidence="High" if is_primary else "Medium",
            color="cyan" if is_primary else "slate",
            category="Email OSINT",
            threat_level="Informational",
            raw_data=f"Found via {source} | Domain: {domain_part}",
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

        findings.append(IntelligenceFinding(
            entity=f"Total: {len(all_emails)} unique email addresses",
            type="Email Harvest Summary",
            source="EmailHarvester",
            confidence="High",
            color="cyan",
            threat_level="Informational",
            raw_data=f"Found {len(all_emails)} emails from {len(set(v for v in all_emails.values()))} sources",
            tags=["summary"]
        ))

    return findings
