import httpx
import asyncio
import re
import urllib.parse
from models import IntelligenceFinding

DORK_TEMPLATES = [
    {"query": "site:{domain} filetype:pdf", "category": "Documents", "sensitivity": "Low"},
    {"query": "site:{domain} filetype:xls OR filetype:xlsx", "category": "Spreadsheets", "sensitivity": "Medium"},
    {"query": "site:{domain} filetype:doc OR filetype:docx", "category": "Documents", "sensitivity": "Medium"},
    {"query": "site:{domain} filetype:sql", "category": "Database Dump", "sensitivity": "Critical"},
    {"query": "site:{domain} filetype:txt", "category": "Text Files", "sensitivity": "Low"},
    {"query": "site:{domain} filetype:log", "category": "Log Files", "sensitivity": "Critical"},
    {"query": "site:{domain} filetype:conf OR filetype:config", "category": "Configuration", "sensitivity": "High"},
    {"query": "site:{domain} filetype:ini", "category": "Configuration", "sensitivity": "High"},
    {"query": "site:{domain} filetype:xml", "category": "Data Files", "sensitivity": "Medium"},
    {"query": "site:{domain} filetype:json", "category": "Data Files", "sensitivity": "Medium"},
    {"query": "site:{domain} filetype:yml OR filetype:yaml", "category": "Configuration", "sensitivity": "High"},
    {"query": "site:{domain} filetype:env", "category": "Environment File", "sensitivity": "Critical"},
    {"query": "site:{domain} filetype:csv", "category": "Spreadsheets", "sensitivity": "Medium"},
    {"query": "site:{domain} filetype:pem OR filetype:key", "category": "Private Keys/Certs", "sensitivity": "Critical"},
    {"query": "site:{domain} filetype:cer OR filetype:crt", "category": "Certificates", "sensitivity": "High"},
    {"query": "site:{domain} filetype:bak OR filetype:backup", "category": "Backup Files", "sensitivity": "High"},
    {"query": "site:{domain} filetype:swp OR filetype:swo", "category": "Editor Backup", "sensitivity": "High"},
    {"query": "site:{domain} filetype:rdp", "category": "RDP Files", "sensitivity": "High"},
    {"query": "site:{domain} filetype:ovpn", "category": "VPN Config", "sensitivity": "High"},
    {"query": "site:{domain} filetype:pfx OR filetype:p12", "category": "Certificate Store", "sensitivity": "Critical"},
    {"query": "site:{domain} intitle:\"index of\"", "category": "Directory Listing", "sensitivity": "Medium"},
    {"query": "site:{domain} intitle:\"index of /\"", "category": "Directory Listing", "sensitivity": "Medium"},
    {"query": "site:{domain} intitle:admin", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} intitle:login", "category": "Login Pages", "sensitivity": "Medium"},
    {"query": "site:{domain} intitle:dashboard", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} intitle:panel", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} intitle:\"web console\"", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} intitle:\"control panel\"", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} inurl:admin", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} inurl:backup", "category": "Backup Files", "sensitivity": "High"},
    {"query": "site:{domain} inurl:wp-admin OR inurl:wp-config", "category": "WordPress", "sensitivity": "High"},
    {"query": "site:{domain} inurl:config", "category": "Configuration", "sensitivity": "High"},
    {"query": "site:{domain} inurl:test", "category": "Test Pages", "sensitivity": "Medium"},
    {"query": "site:{domain} inurl:api", "category": "API Endpoints", "sensitivity": "High"},
    {"query": "site:{domain} inurl:secret", "category": "Secrets", "sensitivity": "Critical"},
    {"query": "site:{domain} inurl:private", "category": "Private Files", "sensitivity": "High"},
    {"query": "site:{domain} inurl:dashboard", "category": "Admin Pages", "sensitivity": "High"},
    {"query": "site:{domain} inurl:debug", "category": "Debug Pages", "sensitivity": "High"},
    {"query": "site:{domain} inurl:phpmyadmin OR inurl:adminer", "category": "Database Admin", "sensitivity": "Critical"},
    {"query": "site:{domain} inurl:.git", "category": "Git Exposure", "sensitivity": "Critical"},
    {"query": "site:{domain} inurl:.svn", "category": "SVN Exposure", "sensitivity": "Critical"},
    {"query": "site:{domain} intext:password", "category": "Password Disclosure", "sensitivity": "Critical"},
    {"query": "site:{domain} intext:\"username\"", "category": "Credential Disclosure", "sensitivity": "High"},
    {"query": "site:{domain} intext:\"api_key\" OR intext:\"apikey\"", "category": "API Key Disclosure", "sensitivity": "Critical"},
    {"query": "site:{domain} intext:secret", "category": "Secrets Disclosure", "sensitivity": "Critical"},
    {"query": "site:{domain} intext:\"auth_token\" OR intext:\"accesstoken\"", "category": "Token Disclosure", "sensitivity": "Critical"},
    {"query": "site:{domain} intext:\"sql syntax\" OR intext:\"mysql_fetch\"", "category": "SQL Errors", "sensitivity": "High"},
    {"query": "site:{domain} intext:\"fatal error\" OR intext:\"stack trace\"", "category": "Error Messages", "sensitivity": "Medium"},
    {"query": "site:{domain} intext:\"smtp\" OR intext:\"mailhost\"", "category": "Mail Config", "sensitivity": "High"},
    {"query": "site:{domain} intext:\"db_password\" OR intext:\"db_user\"", "category": "Database Credentials", "sensitivity": "Critical"},
    {"query": "site:{domain} ext:php intitle:phpinfo", "category": "PHPInfo", "sensitivity": "High"},
]

SENSITIVITY_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SENSITIVITY_COLOR = {"Low": "blue", "Medium": "slate", "High": "orange", "Critical": "red"}

SEARCH_URLS = [
    "https://www.google.com/search?q={q}&num=10&hl=en",
    "https://search.brave.com/search?q={q}",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

RESULT_RE = re.compile(
    r'<a[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)
CITE_RE = re.compile(r'<cite[^>]*>(.*?)</cite>', re.IGNORECASE | re.DOTALL)
SNIPPET_RE = re.compile(r'<span[^>]*class=["\'][^"\']*st[^"\']*["\'][^>]*>(.*?)</span>', re.IGNORECASE | re.DOTALL)

def build_search_url(dork_query: str) -> str:
    encoded = urllib.parse.quote_plus(dork_query)
    return SEARCH_URLS[0].format(q=encoded)

def parse_serp_results(html: str, domain: str) -> list:
    parsed = []
    results = RESULT_RE.findall(html)
    for url, title in results:
        url = url.strip()
        if domain.replace(".", r"\.") in url:
            parsed.append({
                "url": url,
                "title": re.sub(r'<[^>]+>', '', title).strip()[:200],
            })
    return parsed

def estimate_sensitivity(sensitivity: str, has_results: bool) -> str:
    if not has_results:
        return "Informational"
    return sensitivity

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urllib.parse.urlparse(domain).netloc

    category_counts = {}
    sensitivity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    total_dorks = len(DORK_TEMPLATES)

    for i, dork_def in enumerate(DORK_TEMPLATES):
        query = dork_def["query"].format(domain=domain)
        category = dork_def["category"]
        sensitivity = dork_def["sensitivity"]
        url = build_search_url(query)

        try:
            headers = {"User-Agent": USER_AGENTS[i % len(USER_AGENTS)],
                       "Accept-Language": "en-US,en;q=0.9",
                       "Accept": "text/html,application/xhtml+xml"}
            resp = await client.get(url, headers=headers, timeout=12.0, follow_redirects=True)

            if resp.status_code == 200 and len(resp.text) > 500:
                results = parse_serp_results(resp.text, domain)
                if results:
                    sensitivity_counts[sensitivity] += 1
                    category_counts[category] = category_counts.get(category, 0) + 1
                    effective_sensitivity = estimate_sensitivity(sensitivity, bool(results))
                    color = SENSITIVITY_COLOR.get(sensitivity, "slate")

                    for res in results[:3]:
                        findings.append(IntelligenceFinding(
                            entity=res["url"][:250],
                            type=f"Dork: {category}",
                            source="DorkEngine",
                            confidence="Medium",
                            color=color,
                            threat_level=effective_sensitivity,
                            status="Found",
                            resolution=f"Dork: {query[:150]}",
                            tags=["dork", category.lower().replace(" ", "-")]
                        ))

                    findings.append(IntelligenceFinding(
                        entity=f"{len(results)} results for {category} dork",
                        type=f"Dork Summary: {category}",
                        source="DorkEngine",
                        confidence="Medium",
                        color=color,
                        threat_level=effective_sensitivity,
                        status="Discovered",
                        resolution=query[:200],
                        tags=["dork", "summary"]
                    ))

        except Exception:
            continue

    total_found = sum(sensitivity_counts.values())
    critical_found = sensitivity_counts.get("Critical", 0)
    high_found = sensitivity_counts.get("High", 0)

    if total_found > 0:
        findings.append(IntelligenceFinding(
            entity=f"Dork scan complete: {total_found}/{total_dorks} dorks matched, "
                   f"{critical_found} critical, {high_found} high",
            type="Dork Engine Summary",
            source="DorkEngine",
            confidence="High",
            color="red" if critical_found > 0 else ("orange" if high_found > 0 else "purple"),
            threat_level="Elevated Risk" if critical_found > 0 else "Informational",
            status="Complete",
            resolution=f"{critical_found} critical findings, {high_found} high findings",
            tags=["dork", "summary"]
        ))

        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            findings.append(IntelligenceFinding(
                entity=f"{cat}: {count} dork matches",
                type="Dork Category Breakdown",
                source="DorkEngine",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status="Count",
                tags=["dork", "statistics"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No dork results found for {domain}",
            type="Dork Engine Summary",
            source="DorkEngine",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            status="No Results",
            tags=["dork", "summary"]
        ))

    return findings
