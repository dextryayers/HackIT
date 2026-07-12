import re
from urllib.parse import urlparse
from ..module_common import safe_fetch, safe_fetch_json, make_finding

BREACH_DATABASES = [
    "HaveIBeenPwned", "Dehashed", "LeakCheck", "IntelX", "SnusBase",
    "ScrapedIn", "COMB (Combination of Many Breaches)", "AntiPublic",
    "Collection #1", "Collection #2-5", "BreachCompilation", "Paste Sites",
    "Credential Stuffing DB", "Firewall Monitor", "LeakBase",
    "Exploit.in", "RaidForums", "Nulled.to", "Cracked.to",
    "Siph0n", "Verify-email.org", "EmailRep",
]

BREACH_CATEGORIES = {
    "social_media": ["linkedin", "facebook", "twitter", "instagram", "snapchat", "tiktok"],
    "gaming": ["minecraft", "steam", "epic games", "ubisoft", "origin", "battle.net", "riot"],
    "forums": ["raidforums", "nulled", "cracked", "hackforums", "xss"],
    "services": ["adobe", "last.fm", "dropbox", "canva", "disqus", "myspace", "tumblr"],
    "financial": ["capitol one", "equifax", "target", "home depot"],
    "entertainment": ["netflix", "spotify", "twitch", "patreon", "adult friendfinder"],
    "tech": ["github", "gitlab", "atlassian", "slack", "mongodb"],
    "education": ["udemy", "coursera", "edx", "khan academy"],
    "health": ["23andme", "healthcare.gov", "anthem"],
    "communication": ["whatsapp", "telegram", "discord", "skype", "viber"],
}

RISK_SCORE_MAP = {
    "credential": 10, "password": 10, "financial": 9, "medical": 9,
    "social security": 10, "ssn": 10, "credit card": 10, "ccn": 10,
    "email": 5, "username": 4, "ip": 3, "phone": 6, "address": 5,
    "dob": 7, "date of birth": 7, "secret": 10, "token": 8, "api": 9,
}

PASTE_PATTERNS = [
    "pastebin.com", "paste.ee", "paste.org", "dumpz.org", "ghostbin.com",
    "hastebin.com", "rentry.co", "telegra.ph", "controlc.com", "dpaste.org",
]

async def _check_hibp_domain(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://haveibeenpwned.com/domain/{domain}")
        if resp and resp.status_code == 200:
            breach_sections = re.findall(r'<h3[^>]*class="[^"]*breach-title[^"]*"[^>]*>([^<]+)</h3>', resp.text, re.I)
            if breach_sections:
                findings.append(make_finding(
                    entity=f"{len(breach_sections)} breaches found for domain",
                    ftype="Breach Intel - HaveIBeenPwned Domain Check",
                    source="HaveIBeenPwned",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Breached",
                    raw_data=f"Found {len(breach_sections)} breaches: {', '.join(breach_sections[:10])}",
                    tags=["breach", "hibp", "domain"]
                ))
                for breach in breach_sections[:15]:
                    breach = breach.strip()
                    if breach:
                        findings.append(make_finding(
                            entity=breach[:200],
                            ftype="Breach Intel - Domain Breach Name",
                            source="HaveIBeenPwned",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Compromised",
                            raw_data=f"Breach: {breach}",
                            tags=["breach", "hibp", breach.lower().replace(" ", "-")]
                        ))
            else:
                findings.append(make_finding(
                    entity=f"No breaches found for domain",
                    ftype="Breach Intel - HIBP Clean",
                    source="HaveIBeenPwned",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    status="Clean",
                    tags=["breach", "hibp", "clean"]
                ))
    except Exception:
        pass
    return findings

async def _check_firewall_monitor(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://firewall.monitor/domain/{domain}", timeout=15.0)
        if resp.status_code == 200:
            leak_data = re.findall(r'(?:[\w._%+-]+@[\w.-]+\.\w{2,})', resp.text)
            if leak_data:
                unique_leaks = list(set(leak_data))
                findings.append(make_finding(
                    entity=f"{len(unique_leaks)} emails/credentials leaked on Firewall Monitor",
                    ftype="Breach Intel - Firewall Monitor Leaks",
                    source="Firewall Monitor",
                    confidence="Medium",
                    color="red",
                    threat_level="High Risk",
                    status="Leaked",
                    raw_data=f"Sample leaks: {', '.join(unique_leaks[:5])}",
                    tags=["breach", "firewall-monitor", "leak"]
                ))
    except Exception:
        pass
    return findings

async def _check_paste_sites(domain: str, client: AsyncClient) -> list:
    findings = []
    for paste_url in PASTE_PATTERNS[:5]:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q=site:{paste_url}+{domain}", timeout=15.0)
            if resp.status_code == 200:
                if f"{paste_url}" in resp.text and domain in resp.text:
                    paste_count = len(re.findall(rf'{re.escape(domain)}', resp.text))
                    findings.append(make_finding(
                        entity=f"Domain mentioned on {paste_url} ({paste_count} mentions)",
                        ftype="Breach Intel - Paste Site Mention",
                        source=f"Paste Sites ({paste_url})",
                        confidence="Low",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Mentioned",
                        raw_data=f"Domain references on {paste_url}: {paste_count}",
                        tags=["breach", "paste", paste_url.split(".")[0]]
                    ))
        except Exception:
            pass
    return findings

async def _assess_aggregate_risk(domain: str, findings_sofar: list) -> list:
    findings = []
    breach_count = sum(1 for f in findings_sofar if "breach" in f.type.lower() or "leak" in f.type.lower())
    risk_signals = set()
    for f in findings_sofar:
        for tag in f.tags:
            for keyword, score in RISK_SCORE_MAP.items():
                if keyword in tag.lower() or keyword in f.type.lower():
                    risk_signals.add(keyword)
    risk_score = len(risk_signals) * 2 + breach_count * 3
    risk_level = "Low Risk" if risk_score < 5 else "Moderate Risk" if risk_score < 15 else "High Risk" if risk_score < 30 else "Critical Risk"
    color_map = {"Low Risk": "emerald", "Moderate Risk": "orange", "High Risk": "red", "Critical Risk": "darkred"}
    findings.append(make_finding(
        entity=f"Aggregate breach risk score: {risk_score}/100 ({risk_level})",
        ftype="Breach Intel - Aggregate Risk Assessment",
        source="Passive Breach Intel",
        confidence="Medium" if breach_count > 0 else "Low",
        color=color_map.get(risk_level, "slate"),
        threat_level=risk_level,
        status=f"Risk: {risk_level}",
        raw_data=f"Risk score: {risk_score}, Breach signals: {breach_count}, Risk factors: {', '.join(risk_signals)}",
        tags=["breach", "risk-assessment", "aggregate"]
    ))
    return findings

async def _check_credential_stuffing_dbs(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.google.com/search?q=%22{domain}%22+%22password%22+OR+%22credential%22+OR+%22combo%22+OR+%22leak%22+OR+%22dump%22", timeout=15.0)
        if resp.status_code == 200:
            result_stats = re.search(r'About ([\d,]+) results', resp.text)
            if result_stats:
                count_str = result_stats.group(1).replace(",", "")
                count = int(count_str) if count_str.isdigit() else 0
                if count > 0:
                    findings.append(make_finding(
                        entity=f"~{count:,} search results for credential/leak mentions",
                        ftype="Breach Intel - Credential Stuffing Search",
                        source="Passive Breach Intel",
                        confidence="Low",
                        color="orange" if count > 100 else "slate",
                        threat_level="Elevated Risk" if count > 100 else "Informational",
                        status=f"{count:,} results",
                        raw_data=f"Credential stuffing search results: ~{count:,}",
                        tags=["breach", "credential-stuffing", "search"]
                    ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    findings.append(make_finding(
        entity=f"Starting passive breach intelligence for {domain}",
        ftype="Breach Intel - Start",
        source="Passive Breach Intel",
        confidence="High", color="blue",
        status="Started",
        tags=["breach", "start"]
    ))

    hibp_findings = await _check_hibp_domain(domain, client)
    findings.extend(hibp_findings)

    fw_findings = await _check_firewall_monitor(domain, client)
    findings.extend(fw_findings)

    paste_findings = await _check_paste_sites(domain, client)
    findings.extend(paste_findings)

    stuffing_findings = await _check_credential_stuffing_dbs(domain, client)
    findings.extend(stuffing_findings)

    risk_findings = await _assess_aggregate_risk(domain, findings)
    findings.extend(risk_findings)

    breach_db_findings = []
    for db_name in BREACH_DATABASES[:10]:
        try:
            resp = await safe_fetch(client, f"https://www.google.com/search?q=%22{domain}%22+%22{db_name}%22", timeout=10.0)
            if resp.status_code == 200:
                estimate_match = re.search(r'About ([\d,]+) results', resp.text)
                if estimate_match:
                    est = estimate_match.group(1).replace(",", "")
                    est_int = int(est) if est.isdigit() else 0
                    if est_int > 0:
                        breach_db_findings.append(make_finding(
                            entity=f"{domain} appears in {db_name} ({est_int:,} results)",
                            ftype=f"Breach Intel - Database Reference: {db_name}",
                            source="Passive Breach Intel",
                            confidence="Low",
                            color="orange" if est_int > 50 else "slate",
                            threat_level="Elevated Risk",
                            status="Referenced",
                            raw_data=f"Search results linking domain to {db_name}: {est_int:,}",
                            tags=["breach", db_name.lower().replace(" ", "-"), "database"]
                        ))
        except Exception:
            pass
    findings.extend(breach_db_findings)

    if findings:
        findings.append(make_finding(
            entity=f"Passive breach intelligence complete: {len(findings)} findings",
            ftype="Breach Intel - Summary",
            source="Passive Breach Intel",
            confidence="High", color="purple",
            status="Complete",
            tags=["breach", "summary"]
        ))

    return findings
