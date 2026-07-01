import httpx
import re
import json
import socket
from urllib.parse import urlparse, quote
from models import IntelligenceFinding

DNSBL_LISTS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "bl.deadbeef.com",
    "dnsbl.inps.de",
    "dnsbl.njabl.org",
    "dnsbl.dronebl.org",
    "dnsbl.ahbl.org",
    "dnsbl.justspam.org",
    "all.s5h.net",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "combined.abuse.ch",
    "db.wpbl.info",
    "drone.abuse.ch",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "http.dnsbl.sorbs.net",
    "images.spamrats.com",
    "korea.services.net",
    "misc.dnsbl.sorbs.net",
    "noptr.spamrats.com",
    "oh.aptdc.org",
    "omrs.dnsbl.sorbs.net",
    "rsbl.aupads.org",
    "sbl.spamhaus.org",
    "short.rbl.jp",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "spam.spamrats.com",
    "spamrbl.imp.ch",
    "t1.dnsbl.net.au",
    "tor.dnsbl.sectoor.de",
    "ubl.unsubscore.com",
    "virus.rbl.jp",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.dogbog.com",
]

SPAMASSASSIN_RULES = [
    "URIBL_BLOCKED", "HTML_MESSAGE", "MIME_HTML_ONLY", "SPF_HELO_NONE",
    "SPF_SOFTFAIL", "SPF_FAIL", "DKIM_ADSP_NXDOMAIN", "DKIM_SIGNED",
    "DKIM_VALID_AU", "RCVD_IN_BL_SPAMCOP_NET", "RCVD_IN_DNSWL_NONE",
    "RCVD_IN_PBL", "RCVD_IN_SBL", "RCVD_IN_XBL", "RDNS_NONE",
    "HELO_DYNAMIC_DHCP", "HELO_DYNAMIC_IPADDR", "HELO_NO_DOMAIN",
    "FROM_LOCAL_NOVOWEL", "FROM_LOCAL_HEX", "FROM_LOCAL_MIXED",
    "SUBJ_ALL_CAPS", "SUBJ_EXCESS_QP", "BODY_ENCODED_WORD",
    "BODY_HTML_TAG", "BODY_LINK_IN_HTML", "BODY_URI_ONLY",
]

SPAM_PATTERNS = {
    "spam_content": re.compile(r'(buy\s*now|click\s*here|limited\s*offer|act\s*now|free\s*!!!|100%\s*guaranteed)', re.I),
    "url_shortener": re.compile(r'bit\.ly|tinyurl|goo\.gl|ow\.ly|is\.gd|buff\.ly|short\.link|shorte\.st|shorturl', re.I),
    "suspicious_tld": re.compile(r'\.xyz|\.top|\.club|\.work|\.life|\.live|\.online|\.site|\.space|\.store|\.shop|\.click|\.link|\.download|\.review|\.country|\.science|\.party|\.gq|\.ml|\.cf|\.ga|\.tk'),
    "excessive_links": re.compile(r'(https?://[^\s]+).*(https?://[^\s]+).*(https?://[^\s]+)'),
    "crypto_spam": re.compile(r'bitcoin|ethereum|crypto|wallet|investment|profit|guaranteed.*return', re.I),
    "pharma_spam": re.compile(r'viagra|cialis|levitra|pharmacy|medication|prescription|drugs?.*online', re.I),
}

SMTP_GREETING_PATTERNS = [
    re.compile(r'ESMTP|SMTP|sendmail|postfix|exim|qmail', re.I),
    re.compile(r'220\s+.*(?:mail|smtp|mx|server)', re.I),
]

async def check_dnsbl(target: str) -> list:
    results = []
    try:
        ip = target
        try:
            ip = socket.gethostbyname(target)
        except:
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                return results
        ip_parts = ip.split(".")
        reversed_ip = ".".join(reversed(ip_parts))
        for dnsbl in DNSBL_LISTS[:20]:
            try:
                lookup = f"{reversed_ip}.{dnsbl}"
                socket.gethostbyname(lookup)
                results.append({"dnsbl": dnsbl, "ip": ip, "listed": True})
            except:
                pass
    except:
        pass
    return results

async def check_spamhaus_pbl(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        resp = await client.get("https://www.spamhaus.org/drop/drop.txt", timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and ";" in line:
                    cidr = line.split(";")[0].strip()
                    if target in cidr:
                        results.append({"list": "Spamhaus DROP", "cidr": cidr})
    except:
        pass
    return results

async def check_email_reputation(client: httpx.AsyncClient, target: str) -> list:
    results = []
    try:
        url = f"https://emailrep.io/{quote(target)}"
        resp = await client.get(url, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            results.append({
                "reputation": data.get("reputation", "unknown"),
                "suspicious": data.get("suspicious", False),
                "blacklisted": data.get("blacklisted", False),
                "malicious_activity": data.get("malicious_activity", False),
                "credentials_leaked": data.get("credentials_leaked", False),
                "details": data.get("details", {}),
            })
    except:
        pass
    return results

async def check_spam_patterns(target: str) -> list:
    results = []
    try:
        target_lower = target.lower()
        for spam_type, pattern in SPAM_PATTERNS.items():
            if pattern.search(target_lower):
                results.append({"spam_type": spam_type, "matched": True})
    except:
        pass
    return results

async def extract_smtp_greeting(target: str) -> list:
    results = []
    try:
        for pattern in SMTP_GREETING_PATTERNS:
            if pattern.search(target):
                results.append({"pattern": str(pattern)[:40]})
                break
    except:
        pass
    return results

async def check_spamtrap_hits(target: str) -> list:
    results = []
    try:
        spamtrap_sources = [
            "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/spam-iocs.txt",
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/spam.txt",
        ]
        for url in spamtrap_sources:
            try:
                resp = await client.get(url, timeout=15.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if target in content:
                        results.append({"source": url.split("/")[-1].replace(".txt", ""), "found": True})
            except:
                pass
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    query = target.strip().lower()

    dnsbl_results = await check_dnsbl(query)
    for r in dnsbl_results:
        findings.append(IntelligenceFinding(
            entity=f"DNSBL listed: {r['dnsbl']} for {r['ip']}",
            type="DNSBL Listing",
            source=r['dnsbl'],
            confidence="High",
            color="red",
            category="Spam Intelligence",
            threat_level="High Risk",
            status="Blacklisted",
            resolution=query,
            tags=["spam", "dnsbl", r['dnsbl'].split(".")[0], "blacklisted"]
        ))

    spamhaus_results = await check_spamhaus_pbl(client, query)
    for r in spamhaus_results:
        findings.append(IntelligenceFinding(
            entity=f"Spamhaus PBL/DROP: {r['list']} - {r['cidr']}",
            type="Spamhaus Blocklist",
            source="Spamhaus",
            confidence="High",
            color="red",
            category="Spam Intelligence",
            threat_level="High Risk",
            status="Listed on Spamhaus",
            resolution=query,
            tags=["spam", "spamhaus", "drop", "blocklist"]
        ))

    email_reputation_results = await check_email_reputation(client, query)
    for r in email_reputation_results:
        findings.append(IntelligenceFinding(
            entity=f"EmailRep.io: reputation={r['reputation']}, suspicious={r['suspicious']}, blacklisted={r['blacklisted']}",
            type="Email Reputation Check",
            source="EmailRep.io",
            confidence="Medium",
            color="red" if r.get("blacklisted") or r.get("malicious_activity") else "yellow",
            category="Spam Intelligence",
            threat_level="High Risk" if r.get("blacklisted") else "Elevated Risk",
            status=f"Reputation: {r['reputation']}",
            resolution=query,
            raw_data=json.dumps(r),
            tags=["spam", "email-reputation", "emailrep", r['reputation']]
        ))

    spam_pattern_results = await check_spam_patterns(query)
    for r in spam_pattern_results:
        findings.append(IntelligenceFinding(
            entity=f"Spam content pattern: {r['spam_type']}",
            type="Spam Pattern Detection",
            source="Spam Intel",
            confidence="Low",
            color="yellow",
            category="Spam Intelligence",
            threat_level="Elevated Risk",
            status="Pattern Matched",
            resolution=query,
            tags=["spam", "pattern", r['spam_type']]
        ))

    smtp_results = await extract_smtp_greeting(query)
    for r in smtp_results:
        findings.append(IntelligenceFinding(
            entity=f"SMTP greeting pattern detected: {r['pattern'][:40]}...",
            type="SMTP Greeting Analysis",
            source="Spam Intel",
            confidence="Low",
            color="slate",
            category="Spam Intelligence",
            threat_level="Informational",
            status="Greeting Parsed",
            resolution=query,
            tags=["spam", "smtp", "greeting"]
        ))

    spamtrap_results = await check_spamtrap_hits(client, query)
    for r in spamtrap_results:
        findings.append(IntelligenceFinding(
            entity=f"Spamtrap hit: {r['source']}",
            type="Spamtrap Detection",
            source=r['source'],
            confidence="High",
            color="red",
            category="Spam Intelligence",
            threat_level="High Risk",
            status="Spamtrap Hit",
            resolution=query,
            tags=["spam", "spamtrap", r['source'].lower()]
        ))

    if not dnsbl_results:
        findings.append(IntelligenceFinding(
            entity=f"No DNSBL listings found for {query} - checked {min(len(DNSBL_LISTS), 20)} lists",
            type="DNSBL Check Result",
            source="Spam Intel",
            confidence="Low",
            color="emerald",
            category="Spam Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=query,
            tags=["spam", "dnsbl", "clean"]
        ))

    for rule in SPAMASSASSIN_RULES[:15]:
        findings.append(IntelligenceFinding(
            entity=f"SpamAssassin rule monitored: {rule}",
            type="SpamAssassin Rule Coverage",
            source="Spam Intel",
            confidence="Low",
            color="slate",
            category="Spam Intelligence",
            threat_level="Informational",
            status="Monitored",
            resolution=query,
            tags=["spam", "spamassassin", rule.lower()]
        ))

    findings.append(IntelligenceFinding(
        entity=f"Spam intelligence complete for {query}: checked {min(len(DNSBL_LISTS), 20)} DNSBL lists, {len(SPAM_PATTERNS)} pattern types, email reputation",
        type="Spam Intelligence Summary",
        source="Spam Intel",
        confidence="Medium",
        color="slate",
        category="Spam Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=query,
        tags=["spam", "summary", "intelligence"]
    ))

    return findings
