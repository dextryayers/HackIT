import re
import json
from urllib.parse import urlparse, quote
from ..module_common import safe_fetch, make_finding

CORPORATE_KEYWORDS = [
    "about", "company", "team", "contact", "careers", "jobs", "press",
    "news", "blog", "investors", "partners", "leadership", "management",
    "board", "executive", "founder", "ceo", "cto", "cfo", "coo",
]

JOB_BOARDS = [
    "linkedin.com/jobs", "indeed.com", "glassdoor.com", "ziprecruiter.com",
    "monster.com", "careerbuilder.com", "dice.com", "angel.co",
    "wellfound.com", "hackernews", "stackoverflow.com/jobs",
]

async def _extract_whois_corporate(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://api.hackertarget.com/whois/?q={domain}", timeout=12.0)
        if resp.status_code == 200:
            text = resp.text
            org = None
            for line in text.split("\n"):
                if "Registrant Organization" in line and ":" in line:
                    org = line.split(":", 1)[1].strip()
                    break
            if org and org != "N/A" and len(org) > 3:
                findings.append(make_finding(
                    entity=org[:200],
                    ftype="Corporate Intel - WHOIS Organization",
                    source="HackerTarget",
                    confidence="High",
                    color="blue",
                    status="Identified",
                    raw_data=f"WHOIS Registrant Organization: {org}",
                    tags=["corporate", "whois", "organization"]
                ))
            email_lines = set()
            for line in text.split("\n"):
                if "@" in line and ("Email" in line or "email" in line):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    if "@" in val:
                        email_lines.add(val)
            for email in list(email_lines)[:5]:
                findings.append(make_finding(
                    entity=email[:200],
                    ftype="Corporate Intel - WHOIS Email Contact",
                    source="HackerTarget",
                    confidence="High",
                    color="orange",
                    status="Contact",
                    raw_data=f"WHOIS email: {email}",
                    tags=["corporate", "contact", "email"]
                ))
    except Exception:
        pass
    return findings

async def _extract_company_from_copyright(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp&limit=5&filter=statuscode:200", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:6]:
                if isinstance(row, list) and len(row) >= 2:
                    orig = row[0]
                    ts = row[1]
                    try:
                        snap = await safe_fetch(client, f"http://web.archive.org/web/{ts}if_/{orig}", timeout=10.0)
                        if snap.status_code == 200:
                            html = snap.text[:50000]
                            copyright_m = re.search(r'(?:Copyright|&copy;|©)\s*(?:&nbsp;)?\s*(?:20\d\d[-\s]*)?\s*([^<.]+?)(?:\.|,|\s+All\s+rights|\s+<)', html, re.I)
                            if copyright_m:
                                company = copyright_m.group(1).strip()
                                if 3 < len(company) < 150:
                                    findings.append(make_finding(
                                        entity=company[:200],
                                        ftype="Corporate Intel - Copyright Notice",
                                        source="Wayback Machine",
                                        confidence="High",
                                        color="slate",
                                        status="Extracted",
                                        raw_data=f"Copyright: {company} [{ts[:8]}]",
                                        tags=["corporate", "copyright"]
                                    ))
                            contact_emails = set(re.findall(r'[\w.+-]+@[\w.-]+\.\w{2,}', html))
                            for email in list(contact_emails)[:5]:
                                findings.append(make_finding(
                                    entity=email,
                                    ftype="Corporate Intel - Email from Cached Page",
                                    source="Wayback Machine",
                                    confidence="High",
                                    color="orange",
                                    status="Discovered",
                                    tags=["corporate", "email", "contact"]
                                ))
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def _search_company_mentions(domain: str, client: AsyncClient) -> list:
    findings = []
    search_terms = [
        f'"site:crunchbase.com" "{domain}"',
        f'"site:linkedin.com" "{domain}" company',
        f'"site:glassdoor.com" "{domain}"',
        f'"site:news.google.com" "{domain}"',
    ]
    for term in search_terms:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q={quote(term)}&num=10", timeout=15.0)
            if resp.status_code == 200:
                snippets = re.findall(r'<span[^>]*class="[^"]*BNeawe[^"]*"[^>]*>([^<]*)</span>', resp.text)
                for snippet in snippets[:5]:
                    if domain.lower() in snippet.lower() or any(kw in snippet.lower() for kw in ["employee", "company", "review", "funding"]):
                        findings.append(make_finding(
                            entity=snippet[:200].strip(),
                            ftype="Corporate Intel - Search Mention",
                            source="Google Search",
                            confidence="Low",
                            color="slate",
                            status="Mentioned",
                            raw_data=f"Search result: {snippet[:500]}",
                            tags=["corporate", "search", "mention"]
                        ))
        except Exception:
            pass
    return findings

async def _check_job_postings(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q={quote(f'site:linkedin.com/jobs OR site:indeed.com OR site:glassdoor.com {domain}')}", timeout=15.0)
        if resp.status_code == 200:
            job_links = re.findall(r'href="(https?://[^"]*(?:linkedin\.com/jobs|indeed\.com|glassdoor\.com)[^"]*)"', resp.text)
            if job_links:
                findings.append(make_finding(
                    entity=f"{len(job_links)} job posting(s) found",
                    ftype="Corporate Intel - Job Postings",
                    source="Google Search",
                    confidence="Low",
                    color="slate",
                    status="Jobs Found",
                    raw_data=f"Job posting URLs: {', '.join(job_links[:5])}",
                    tags=["corporate", "jobs", "recruitment"]
                ))
                for link in job_links[:5]:
                    findings.append(make_finding(
                        entity=link[:200],
                        ftype="Corporate Intel - Job Posting URL",
                        source="Google Search",
                        confidence="Low",
                        color="slate",
                        tags=["corporate", "jobs", "url"]
                    ))
    except Exception:
        pass
    return findings

async def _check_ssl_organization(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15.0)
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            orgs_found = set()
            for cert in certs[:100]:
                issuer = str(cert.get("issuer_name", ""))
                subject = str(cert.get("subject", ""))
                for field in [issuer, subject]:
                    org_m = re.search(r'O\s*=\s*([^,]+)', field)
                    if org_m:
                        orgs_found.add(org_m.group(1).strip())
            for org in list(orgs_found)[:5]:
                if 3 < len(org) < 100:
                    findings.append(make_finding(
                        entity=org,
                        ftype="Corporate Intel - SSL Certificate Organization",
                        source="crt.sh",
                        confidence="High",
                        color="slate",
                        status="Extracted",
                        raw_data=f"SSL cert organization: {org}",
                        tags=["corporate", "ssl", "organization"]
                    ))
    except Exception:
        pass
    return findings

async def _check_reviews_news(domain: str, client: AsyncClient) -> list:
    findings = []
    platforms = [
        ("site:bbb.org", "Better Business Bureau"),
        ("site:g2.com", "G2 Review"),
        ("site:capterra.com", "Capterra Review"),
        ("site:trustpilot.com", "Trustpilot"),
        ("site:sitejabber.com", "Sitejabber"),
    ]
    for site_query, platform in platforms:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q={quote(site_query)}+{domain}", timeout=15.0)
            if resp.status_code == 200:
                result_count = len(re.findall(r'<div[^>]*class="[^"]*g[^"]*"', resp.text))
                if result_count > 0:
                    findings.append(make_finding(
                        entity=f"{platform}: {result_count} result(s)",
                        ftype="Corporate Intel - Business Review/Listing",
                        source="Google Search",
                        confidence="Low",
                        color="slate",
                        status="Listed",
                        raw_data=f"{platform} has {result_count} results for {domain}",
                        tags=["corporate", platform.lower().replace(" ", "-")]
                    ))
        except Exception:
            pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    whois_findings = await _extract_whois_corporate(domain, client)
    findings.extend(whois_findings)

    copyright_findings = await _extract_company_from_copyright(domain, client)
    findings.extend(copyright_findings)

    search_findings = await _search_company_mentions(domain, client)
    findings.extend(search_findings)

    jobs_findings = await _check_job_postings(domain, client)
    findings.extend(jobs_findings)

    ssl_findings = await _check_ssl_organization(domain, client)
    findings.extend(ssl_findings)

    review_findings = await _check_reviews_news(domain, client)
    findings.extend(review_findings)

    if findings:
        findings.append(make_finding(
            entity=f"Corporate Intelligence complete: {len(findings)} findings",
            ftype="Corporate Intel - Summary",
            source="Passive Corporate Intel",
            confidence="High", color="purple",
            status="Complete",
            tags=["corporate", "summary"]
        ))

    return findings
