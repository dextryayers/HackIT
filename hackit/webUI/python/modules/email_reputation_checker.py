import httpx
import asyncio
import re
import socket
import dns.resolver
from urllib.parse import urlparse
from models import IntelligenceFinding
from settings_store import get_api_key
from typing import List, Dict, Optional
from datetime import datetime

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "dnsbl-1.uceprotect.net",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "b.barracudacentral.org",
    "dnsbl.dronebl.org",
    "dnsbl.ahbl.org",
    "ix.dnsbl.manitu.net",
    "dnsbl.njabl.org",
    "rbl-plus.mail-abuse.org",
    "rhsbl.sorbs.net",
    "bl.emailbasura.org",
    "bl.deadbeef.com",
    "blackholes.mail-abuse.org",
    "rbl.schulte.org",
    "cbl.abuseat.org",
    "dnsbl.kempt.net",
    "dnsbl.justspam.org",
    "dnsbl.cyberlogic.net",
    "truncate.gbudb.net",
    "dnsbl.inps.de",
    "bl.score.senderscore.com",
    "dnsbl.spfbl.net",
    "spam.dnsbl.sorbs.net",
    "dnsbl.httpbl.net",
    "hostkarma.junkemailfilter.com",
    "no-more-funn.moensted.dk",
    "korea.services.net",
    "access.spamcop.net",
    "web.dnsbl.sorbs.net",
    "rbl.megarbl.net",
    "ubl.unsubscore.com",
    "dnsbl.cobion.com",
    "spamrbl.imp.ch",
    "rbl.talkactive.net",
]

URIBL_SERVERS = [
    "multi.uribl.com",
    "black.uribl.com",
    "grey.uribl.com",
    "red.uribl.com",
]

SURBL_SERVERS = [
    "multi.surbl.org",
    "black.surbl.org",
]

SPAMHAUS_DQS_SERVERS = [
    "dbl.spamhaus.org",
    "dblquery.spamhaus.org",
]

SMTP_BANNER_PATTERNS = {
    "postfix": r"Postfix",
    "exim": r"Exim",
    "sendmail": r"Sendmail",
    "qmail": r"qmail",
    "exchange": r"Microsoft (ESMTP|Exchange)",
    "gmail": r"Google Mail|GMX|google.com",
    "outlook": r"Outlook|Hotmail|microsoft",
    "protonmail": r"ProtonMail",
    "zoho": r"Zoho",
    "iredmail": r"iredmail",
    "zimbra": r"Zimbra",
    "hmailserver": r"hmailserver",
    "mailenable": r"MailEnable",
    "kerio": r"Kerio",
    "mailcow": r"mailcow",
    "cyrus": r"Cyrus",
}


def ip_to_reverse(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


async def query_dnsbl(client: httpx.AsyncClient, ip: str, dnsbl_host: str) -> bool:
    try:
        reverse_ip = ip_to_reverse(ip)
        query = f"{reverse_ip}.{dnsbl_host}"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(query, "A")
        return len(answers) > 0
    except Exception:
        return False


async def check_spf_record(domain: str) -> Dict:
    result = {"has_spf": False, "spf_record": "", "issues": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith("v=spf1"):
                result["has_spf"] = True
                result["spf_record"] = txt[:500]
                if "~all" not in txt and "-all" not in txt and "?all" not in txt:
                    result["issues"].append("SPF lacks hard/soft fail mechanism")
                if "+all" in txt:
                    result["issues"].append("SPF allows all senders (+all)")
                if "redirect=" in txt:
                    result["issues"].append("SPF uses redirect (may be complex)")
                break
        if not result["has_spf"]:
            result["issues"].append("No SPF record found")
    except Exception:
        result["issues"].append("Unable to query SPF record")
    return result


async def check_dkim_record(domain: str) -> Dict:
    result = {"has_dkim": False, "selectors": [], "issues": []}
    common_selectors = ["default", "google", "dkim", "selector1", "selector2", "s1", "s2", "mail", "mx", "protonmail", "zoho"]
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt = str(rdata)
                    if "v=DKIM1" in txt:
                        result["has_dkim"] = True
                        result["selectors"].append(selector)
                        break
            except Exception:
                continue
        if not result["has_dkim"]:
            result["issues"].append("No DKIM record found")
    except Exception:
        result["issues"].append("Unable to query DKIM records")
    return result


async def check_dmarc_record(domain: str) -> Dict:
    result = {"has_dmarc": False, "dmarc_record": "", "policy": "", "issues": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith("v=DMARC1"):
                result["has_dmarc"] = True
                result["dmarc_record"] = txt[:500]
                policy_match = re.search(r'p=(\w+)', txt)
                if policy_match:
                    result["policy"] = policy_match.group(1)
                    if policy_match.group(1) == "none":
                        result["issues"].append("DMARC policy is 'none' (no protection)")
                    elif policy_match.group(1) == "quarantine":
                        result["issues"].append("DMARC policy is 'quarantine' (moderate protection)")
                    elif policy_match.group(1) == "reject":
                        pass
                else:
                    result["issues"].append("DMARC record missing policy")
                if "rua=" not in txt:
                    result["issues"].append("DMARC missing aggregate report URI (rua)")
                if "ruf=" not in txt:
                    result["issues"].append("DMARC missing forensic report URI (ruf)")
                if "pct=" in txt:
                    pct_match = re.search(r'pct=(\d+)', txt)
                    if pct_match and int(pct_match.group(1)) < 100:
                        result["issues"].append(f"DMARC policy applies to only {pct_match.group(1)}% of mail")
                break
        if not result["has_dmarc"]:
            result["issues"].append("No DMARC record found")
    except Exception:
        result["issues"].append("Unable to query DMARC record")
    return result


async def check_ptr_record(ip: str) -> Dict:
    result = {"has_ptr": False, "ptr_record": "", "matches_domain": False}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        reverse_ip = ip_to_reverse(ip)
        answers = resolver.resolve(f"{reverse_ip}.in-addr.arpa", "PTR")
        for rdata in answers:
            ptr = str(rdata).rstrip('.')
            result["has_ptr"] = True
            result["ptr_record"] = ptr
            break
    except Exception:
        pass
    return result


async def check_mx_records(domain: str) -> Dict:
    result = {"has_mx": False, "mx_records": [], "issues": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        for rdata in answers:
            mx = str(rdata.exchange).rstrip('.')
            preference = rdata.preference
            result["mx_records"].append({"host": mx, "preference": preference})
        result["has_mx"] = len(result["mx_records"]) > 0
        if not result["has_mx"]:
            result["issues"].append("No MX records found")
    except Exception:
        result["issues"].append("Unable to query MX records")
    return result


async def smtp_banner_grab(ip: str, port: int = 25) -> Dict:
    result = {"banner": "", "has_starttls": False, "is_open_relay": False, "issues": []}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        result["banner"] = banner[:200]

        for mta_name, pattern in SMTP_BANNER_PATTERNS.items():
            if re.search(pattern, banner, re.I):
                result["mta_software"] = mta_name
                break

        if "ESMTP" in banner:
            result["has_starttls"] = True
    except Exception as e:
        result["issues"].append(f"SMTP connection failed: {str(e)[:50]}")
    return result


async def check_open_relay(ip: str) -> Dict:
    result = {"is_open_relay": False, "test_results": []}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, 25))
        sock.recv(1024)

        sock.sendall(b"EHLO test.com\r\n")
        response = sock.recv(1024).decode("utf-8", errors="ignore")

        if "250 " not in response:
            sock.sendall(b"MAIL FROM:<test@test.com>\r\n")
            resp1 = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall(b"RCPT TO:<test@example.com>\r\n")
            resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
            if "250" in resp1 and "250" in resp2:
                result["is_open_relay"] = True
                result["test_results"].append("Server accepted relay test")

        sock.sendall(b"QUIT\r\n")
        sock.close()
    except Exception:
        pass
    return result


async def check_mxtoolbox_blacklist(client: httpx.AsyncClient, domain: str) -> List[Dict]:
    results = []
    try:
        url = f"https://mxtoolbox.com/api/v1/lookup/blacklist/{domain}"
        headers = {"User-Agent": UA, "Accept": "application/json"}
        resp = await client.get(url, headers=headers, timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("records", []):
                results.append({
                    "source": "MXToolbox",
                    "blacklist": entry.get("Name", ""),
                    "delisted": entry.get("Delist", False),
                    "status": entry.get("Status", ""),
                })
    except Exception:
        pass
    return results


async def get_ips_for_domain(domain: str) -> List[str]:
    ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            ips.append(str(rdata))
    except Exception:
        pass
    try:
        answers = resolver.resolve(domain, "AAAA")
        for rdata in answers:
            ips.append(str(rdata))
    except Exception:
        pass
    return ips


async def resolve_mx_to_ips(mx_host: str) -> List[str]:
    ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(mx_host, "A")
        for rdata in answers:
            ips.append(str(rdata))
    except Exception:
        pass
    return ips


async def check_ip_quality(client: httpx.AsyncClient, ip: str) -> Dict:
    result = {"score": None, "success": False, "source": "", "details": ""}
    try:
        resp = await client.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"User-Agent": UA, "Accept": "application/json", "Key": ""},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            result["score"] = score
            result["success"] = True
            result["source"] = "AbuseIPDB"
            result["details"] = f"abuseConfidenceScore={score}, totalReports={data.get('totalReports', 0)}"
            return result
    except Exception:
        pass
    try:
        resp = await client.get(
            f"https://ipqualityscore.com/api/json/ip/{ip}",
            headers={"User-Agent": UA},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                score = data.get("fraud_score", 0)
                result["score"] = score
                result["success"] = True
                result["source"] = "IPQualityScore"
                result["details"] = f"fraud_score={score}, proxy={data.get('proxy', False)}, vpn={data.get('vpn', False)}"
                return result
    except Exception:
        pass
    try:
        resp = await client.get(f"http://ip-api.com/json/{ip}", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                proxy = data.get("proxy", False)
                hosting = data.get("hosting", False)
                score = 50 if proxy or hosting else 0
                result["score"] = score
                result["success"] = True
                result["source"] = "ip-api.com"
                result["details"] = f"proxy={proxy}, hosting={hosting}, org={data.get('org', '')}"
                return result
    except Exception:
        pass
    return result


async def url_safe_check(client: httpx.AsyncClient, domain: str) -> Dict:
    result = {"malicious": False, "threats": [], "source": "GoogleSafeBrowsing", "success": False}
    try:
        payload = {
            "client": {"clientId": "email-rep-checker", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"https://{domain}"}],
            },
        }
        resp = await client.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=",
            json=payload,
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            if matches:
                result["malicious"] = True
                for m in matches:
                    result["threats"].append(m.get("threatType", "Unknown"))
            result["success"] = True
            return result
    except Exception:
        pass
    return result


async def url_vt_check(client: httpx.AsyncClient, domain: str) -> Dict:
    result = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "source": "VirusTotal", "success": False}
    try:
        url_id = domain.encode("utf-8").hex()
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"User-Agent": UA, "x-apikey": get_api_key("email_rep")},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["malicious"] = stats.get("malicious", 0)
            result["suspicious"] = stats.get("suspicious", 0)
            result["harmless"] = stats.get("harmless", 0)
            result["undetected"] = stats.get("undetected", 0)
            result["success"] = True
            return result
    except Exception:
        pass
    try:
        resp = await client.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": f"https://{domain}"},
            headers={"User-Agent": UA, "x-apikey": get_api_key("email_rep"), "Accept": "application/json"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            analysis_id = data.get("data", {}).get("id", "")
            if analysis_id:
                result["submitted"] = True
                result["analysis_id"] = analysis_id
    except Exception:
        pass
    return result


async def spamassassin_rules_check(spf: Dict, dkim: Dict, dmarc: Dict, mx_info: Dict) -> Dict:
    score = 0
    rules = []
    if not spf["has_spf"]:
        score += 3.5
        rules.append("NO_SPF_RECORD +3.5")
    elif "+all" in spf.get("spf_record", ""):
        score += 2.5
        rules.append("SPF_ALLOW_ALL +2.5")
    elif "~all" not in spf.get("spf_record", "") and "-all" not in spf.get("spf_record", ""):
        score += 1.5
        rules.append("SPF_NO_FAIL_MECHANISM +1.5")
    if not dkim["has_dkim"]:
        score += 3.0
        rules.append("NO_DKIM_RECORD +3.0")
    if not dmarc["has_dmarc"]:
        score += 2.5
        rules.append("NO_DMARC_RECORD +2.5")
    elif dmarc["policy"] == "none":
        score += 1.5
        rules.append("DMARC_POLICY_NONE +1.5")
    if not mx_info["has_mx"]:
        score += 2.0
        rules.append("NO_MX_RECORD +2.0")
    if dmarc.get("issues") and any("rua" in i for i in dmarc["issues"]):
        score += 0.5
        rules.append("DMARC_NO_RUA +0.5")
    return {"score": round(score, 1), "rules": rules, "verdict": "PASS" if score < 5 else ("PROBABLE_SPAM" if score < 8 else "SPAM")}


async def compute_email_sending_score(spf: Dict, dkim: Dict, dmarc: Dict, dnsbl_data: Dict, ptr_data: Dict, mx_info: Dict) -> Dict:
    score = 50
    breakdown = []
    if spf["has_spf"]:
        if "-all" in spf.get("spf_record", ""):
            score += 15
            breakdown.append("SPF(hardfail)+15")
        elif "~all" in spf.get("spf_record", ""):
            score += 10
            breakdown.append("SPF(softfail)+10")
        else:
            score += 5
            breakdown.append("SPF(present)+5")
    else:
        score -= 20
        breakdown.append("SPF(missing)-20")
    if dkim["has_dkim"]:
        score += 15
        breakdown.append(f"DKIM({len(dkim['selectors'])}sel)+15")
    else:
        score -= 15
        breakdown.append("DKIM(missing)-15")
    if dmarc["has_dmarc"]:
        if dmarc["policy"] == "reject":
            score += 15
            breakdown.append("DMARC(reject)+15")
        elif dmarc["policy"] == "quarantine":
            score += 10
            breakdown.append("DMARC(quarantine)+10")
        else:
            score += 5
            breakdown.append("DMARC(none)+5")
    else:
        score -= 15
        breakdown.append("DMARC(missing)-15")
    blacklisted_count = dnsbl_data.get("blacklisted_count", 0)
    total_checked = dnsbl_data.get("total_checked", 1)
    if total_checked > 0:
        bl_ratio = blacklisted_count / total_checked
        penalty = int(bl_ratio * 30)
        score -= penalty
        if penalty > 0:
            breakdown.append(f"DNSBL({blacklisted_count}listed)-{penalty}")
    has_ptr = ptr_data.get("has_ptr", False)
    if has_ptr:
        score += 5
        breakdown.append("PTR(present)+5")
    else:
        score -= 5
        breakdown.append("PTR(missing)-5")
    if mx_info["has_mx"] and len(mx_info["mx_records"]) > 0:
        score += 5
        breakdown.append("MX(configured)+5")
    else:
        score -= 5
        breakdown.append("MX(missing)-5")
    score = max(0, min(100, score))
    return {"score": score, "breakdown": breakdown}


async def check_multi_mx_blacklist(client: httpx.AsyncClient, mx_info: Dict) -> List[Dict]:
    results = []
    if not mx_info["has_mx"]:
        return results
    for mx in mx_info["mx_records"]:
        mx_host = mx["host"]
        ips = await resolve_mx_to_ips(mx_host)
        for ip in ips:
            listed_servers = []
            for dnsbl in DNSBL_SERVERS[:10]:
                try:
                    listed = await query_dnsbl(client, ip, dnsbl)
                    if listed:
                        listed_servers.append(dnsbl)
                except Exception:
                    continue
            if listed_servers:
                results.append({
                    "mx_host": mx_host,
                    "mx_ip": ip,
                    "listed_servers": listed_servers,
                    "listed_count": len(listed_servers),
                })
    return results


async def check_rdns_consistency(ip: str, ptr_record: str, domain: str, mx_hosts: List[str]) -> Dict:
    result = {"consistent": False, "hostname_match": "", "details": []}
    if not ptr_record:
        result["details"].append("No PTR record to verify")
        return result
    helo_candidates = [domain] + mx_hosts
    for candidate in helo_candidates:
        if candidate and candidate.lower() in ptr_record.lower():
            result["consistent"] = True
            result["hostname_match"] = candidate
            result["details"].append(f"PTR matches: {candidate}")
            return result
    result["details"].append(f"PTR '{ptr_record}' does not match any known hostname")
    return result


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    spf = await check_spf_record(domain)
    dkim = await check_dkim_record(domain)
    dmarc = await check_dmarc_record(domain)
    mx_info = await check_mx_records(domain)

    if spf["has_spf"]:
        findings.append(IntelligenceFinding(
            entity=f"SPF: {spf['spf_record'][:150]}",
            type="Email: SPF Record",
            source="EmailReputation",
            confidence="High",
            color="emerald" if not spf["issues"] else "orange",
            threat_level="Informational",
            raw_data=spf["spf_record"],
            tags=["email-security", "spf"]
        ))
    for issue in spf["issues"]:
        findings.append(IntelligenceFinding(
            entity=f"SPF Issue: {issue}",
            type="Email: SPF Issue",
            source="EmailReputation",
            confidence="High",
            color="red" if "no SPF" in issue.lower() or "+all" in issue else "orange",
            threat_level="High Risk" if "+all" in issue or "no SPF" in issue.lower() else "Elevated Risk",
            tags=["email-security", "spf", "issue"]
        ))

    if dkim["has_dkim"]:
        findings.append(IntelligenceFinding(
            entity=f"DKIM: selectors found ({', '.join(dkim['selectors'][:5])})",
            type="Email: DKIM Record",
            source="EmailReputation",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            tags=["email-security", "dkim"]
        ))
    for issue in dkim["issues"]:
        findings.append(IntelligenceFinding(
            entity=f"DKIM Issue: {issue}",
            type="Email: DKIM Issue",
            source="EmailReputation",
            confidence="Medium",
            color="orange" if "no DKIM" in issue.lower() else "slate",
            threat_level="Elevated Risk" if "no DKIM" in issue.lower() else "Informational",
            tags=["email-security", "dkim", "issue"]
        ))

    if dmarc["has_dmarc"]:
        color_map = {"reject": "emerald", "quarantine": "orange", "none": "red"}
        findings.append(IntelligenceFinding(
            entity=f"DMARC Policy: {dmarc['policy']}",
            type="Email: DMARC Record",
            source="EmailReputation",
            confidence="High",
            color=color_map.get(dmarc["policy"], "slate"),
            threat_level="Informational" if dmarc["policy"] == "reject" else ("Elevated Risk" if dmarc["policy"] == "quarantine" else "High Risk"),
            raw_data=dmarc["dmarc_record"],
            tags=["email-security", "dmarc"]
        ))
    for issue in dmarc["issues"]:
        findings.append(IntelligenceFinding(
            entity=f"DMARC Issue: {issue}",
            type="Email: DMARC Issue",
            source="EmailReputation",
            confidence="High",
            color="red" if "no DMARC" in issue.lower() else "orange",
            threat_level="High Risk" if "no DMARC" in issue.lower() else "Elevated Risk",
            tags=["email-security", "dmarc", "issue"]
        ))

    if mx_info["has_mx"]:
        for mx in mx_info["mx_records"][:5]:
            findings.append(IntelligenceFinding(
                entity=f"MX: {mx['host']} (priority {mx['preference']})",
                type="Email: MX Record",
                source="EmailReputation",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"{mx['host']} pref={mx['preference']}",
                tags=["email-security", "mx"]
            ))
    for issue in mx_info["issues"]:
        findings.append(IntelligenceFinding(
            entity=f"MX Issue: {issue}",
            type="Email: MX Issue",
            source="EmailReputation",
            confidence="Medium",
            color="red",
            threat_level="High Risk" if "no MX" in issue.lower() else "Elevated Risk",
            tags=["email-security", "mx", "issue"]
        ))

    try:
        bimi_answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT")
        for r in bimi_answers:
            txt = str(r)
            if "v=BIMI1" in txt:
                findings.append(IntelligenceFinding(
                    entity=f"BIMI record found for {domain}",
                    type="Email: BIMI Record",
                    source="EmailReputation",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=txt[:500],
                    tags=["email-security", "bimi"]
                ))
                logo_match = re.search(r"l=https?://\S+", txt)
                if logo_match:
                    findings.append(IntelligenceFinding(
                        entity=f"BIMI Logo: {logo_match.group(0)[2:]}",
                        type="Email: BIMI Logo",
                        source="EmailReputation",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        tags=["email-security", "bimi"]
                    ))
                break
    except:
        pass

    try:
        mta_sts_answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT")
        for r in mta_sts_answers:
            txt = str(r)
            if "v=STSv1" in txt:
                findings.append(IntelligenceFinding(
                    entity=f"MTA-STS DNS record found for {domain}",
                    type="Email: MTA-STS Record",
                    source="EmailReputation",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=txt[:500],
                    tags=["email-security", "mta-sts"]
                ))
                break
    except:
        pass

    if dmarc["has_dmarc"]:
        dmarc_check = dmarc.get("dmarc_record", "")
        if dmarc_check:
            aspf = re.search(r"aspf\s*=\s*([rs])", dmarc_check)
            adkim = re.search(r"adkim\s*=\s*([rs])", dmarc_check)
            if aspf:
                findings.append(IntelligenceFinding(
                    entity=f"DMARC SPF Alignment: {'Strict' if aspf.group(1) == 'r' else 'Relaxed'}",
                    type="Email: DMARC SPF Alignment",
                    source="EmailReputation",
                    confidence="High",
                    color="emerald" if aspf.group(1) == 'r' else "orange",
                    threat_level="Informational" if aspf.group(1) == 'r' else "Elevated Risk",
                    tags=["email-security", "dmarc", "alignment"]
                ))
            if adkim:
                findings.append(IntelligenceFinding(
                    entity=f"DMARC DKIM Alignment: {'Strict' if adkim.group(1) == 'r' else 'Relaxed'}",
                    type="Email: DMARC DKIM Alignment",
                    source="EmailReputation",
                    confidence="High",
                    color="emerald" if adkim.group(1) == 'r' else "orange",
                    threat_level="Informational" if adkim.group(1) == 'r' else "Elevated Risk",
                    tags=["email-security", "dmarc", "alignment"]
                ))

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        dnskey_answers = resolver.resolve(domain, "DNSKEY")
        if dnskey_answers:
            findings.append(IntelligenceFinding(
                entity=f"DNSSEC enabled for {domain} ({len(dnskey_answers)} DNSKEY records)",
                type="Email: DNSSEC Status",
                source="EmailReputation",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                raw_data=f"DNSKEY records: {len(dnskey_answers)}",
                tags=["email-security", "dnssec"]
            ))
    except dns.resolver.NoAnswer:
        pass
    except:
        pass

    spamass = await spamassassin_rules_check(spf, dkim, dmarc, mx_info)
    sa_color = "emerald" if spamass["verdict"] == "PASS" else ("orange" if spamass["verdict"] == "PROBABLE_SPAM" else "red")
    sa_threat = "Informational" if spamass["verdict"] == "PASS" else ("Elevated Risk" if spamass["verdict"] == "PROBABLE_SPAM" else "High Risk")
    findings.append(IntelligenceFinding(
        entity=f"SpamAssassin Score: {spamass['score']} ({spamass['verdict']})",
        type="Email: SpamAssassin Rules",
        source="EmailReputation",
        confidence="Medium",
        color=sa_color,
        threat_level=sa_threat,
        raw_data=f"Score: {spamass['score']} | Verdict: {spamass['verdict']} | Rules: {'; '.join(spamass['rules'][:10])}",
        tags=["email-security", "spamassassin"]
    ))

    ips = await get_ips_for_domain(domain)

    dnsbl_data = {"blacklisted_count": 0, "total_checked": 0}
    ptr_global_data = {"has_ptr": False}

    for idx, ip in enumerate(ips):
        ptr = await check_ptr_record(ip)
        if ptr["has_ptr"]:
            ptr_global_data["has_ptr"] = True
        ptr_data = ptr

        if ptr["has_ptr"]:
            matches = domain in ptr["ptr_record"] or any(
                mx["host"] in ptr["ptr_record"] for mx in mx_info.get("mx_records", [])
            )
            ptr_global_data["ptr_record"] = ptr["ptr_record"]
            color = "emerald" if matches else "orange"
            findings.append(IntelligenceFinding(
                entity=f"PTR: {ptr['ptr_record']}",
                type="Email: Reverse DNS (PTR)",
                source="EmailReputation",
                confidence="High",
                color=color,
                threat_level="Informational" if matches else "Elevated Risk",
                status="Match" if matches else "Mismatch",
                raw_data=f"IP {ip} -> {ptr['ptr_record']}",
                tags=["email-security", "ptr", "rdns"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"No PTR record for IP {ip}",
                type="Email: Reverse DNS (PTR)",
                source="EmailReputation",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                tags=["email-security", "ptr", "missing"]
            ))

        rdns_check = await check_rdns_consistency(ip, ptr.get("ptr_record", ""), domain, [mx["host"] for mx in mx_info.get("mx_records", [])])
        findings.append(IntelligenceFinding(
            entity=f"RDNS Consistency: {'Match' if rdns_check['consistent'] else 'Mismatch'}",
            type="Email: RDNS Consistency",
            source="EmailReputation",
            confidence="Medium",
            color="emerald" if rdns_check["consistent"] else "orange",
            threat_level="Informational" if rdns_check["consistent"] else "Elevated Risk",
            raw_data=f"IP {ip}: {'; '.join(rdns_check['details'][:3])}",
            tags=["email-security", "rdns", "consistency"]
        ))

        banner_info = await smtp_banner_grab(ip)
        if banner_info.get("banner"):
            findings.append(IntelligenceFinding(
                entity=f"SMTP Banner: {banner_info['banner'][:120]}",
                type="Email: SMTP Banner",
                source="EmailReputation",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=banner_info["banner"],
                tags=["email-security", "smtp"]
            ))
        if banner_info.get("mta_software"):
            findings.append(IntelligenceFinding(
                entity=f"MTA Software: {banner_info['mta_software']}",
                type="Email: MTA Fingerprint",
                source="EmailReputation",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["email-security", "mta"]
            ))
        if banner_info.get("has_starttls"):
            findings.append(IntelligenceFinding(
                entity=f"STARTTLS supported on {ip}",
                type="Email: STARTTLS",
                source="EmailReputation",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                tags=["email-security", "starttls"]
            ))

        relay_test = await check_open_relay(ip)
        if relay_test["is_open_relay"]:
            findings.append(IntelligenceFinding(
                entity=f"Open relay detected on {ip}",
                type="Email: Open Relay",
                source="EmailReputation",
                confidence="High",
                color="red",
                threat_level="Critical",
                tags=["email-security", "open-relay", "critical"]
            ))

        dnsbl_tasks = [query_dnsbl(client, ip, dnsbl) for dnsbl in DNSBL_SERVERS]
        dnsbl_results = await asyncio.gather(*dnsbl_tasks, return_exceptions=True)

        listed_count = 0
        listed_servers = []
        for dnsbl, listed in zip(DNSBL_SERVERS, dnsbl_results):
            if isinstance(listed, bool) and listed:
                listed_count += 1
                listed_servers.append(dnsbl)

        dnsbl_data["blacklisted_count"] += listed_count
        dnsbl_data["total_checked"] += len(DNSBL_SERVERS)

        if listed_count > 0:
            findings.append(IntelligenceFinding(
                entity=f"IP {ip} listed on {listed_count} DNSBL(s)",
                type="Email: Blacklisted",
                source="EmailReputation",
                confidence="High",
                color="red",
                threat_level="High Risk" if listed_count >= 3 else "Elevated Risk",
                status="Blacklisted",
                raw_data=f"Listed on: {', '.join(listed_servers[:5])}",
                tags=["email-security", "blacklist", "dnsbl"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"IP {ip} not found on blacklists",
                type="Email: Blacklist Check",
                source="EmailReputation",
                confidence="Medium",
                color="emerald",
                threat_level="Informational",
                tags=["email-security", "blacklist", "clean"]
            ))

        ip_quality = await check_ip_quality(client, ip)
        if ip_quality["success"]:
            qscore = ip_quality["score"]
            qcolor = "emerald" if qscore == 0 else ("orange" if qscore < 50 else "red")
            qthreat = "Informational" if qscore == 0 else ("Elevated Risk" if qscore < 50 else "High Risk")
            findings.append(IntelligenceFinding(
                entity=f"IP Quality Score: {qscore}/100 from {ip_quality['source']}",
                type="Email: IP Reputation",
                source="EmailReputation",
                confidence="Medium",
                color=qcolor,
                threat_level=qthreat,
                raw_data=ip_quality["details"],
                tags=["email-security", "ip-reputation", "quality"]
            ))

    mxtoolbox_results = await check_mxtoolbox_blacklist(client, domain)
    for entry in mxtoolbox_results:
        if entry.get("delisted") is False:
            findings.append(IntelligenceFinding(
                entity=f"Listed on {entry.get('blacklist', 'Unknown RBL')}",
                type="Email: RBL Listed",
                source="EmailReputation/MXToolbox",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                status="Blacklisted",
                tags=["email-security", "rbl", "mxtoolbox"]
            ))

    multi_mx_issues = await check_multi_mx_blacklist(client, mx_info)
    for mx_issue in multi_mx_issues:
        findings.append(IntelligenceFinding(
            entity=f"MX {mx_issue['mx_host']} ({mx_issue['mx_ip']}) listed on {mx_issue['listed_count']} DNSBL(s)",
            type="Email: Multi-MX Blacklist",
            source="EmailReputation",
            confidence="Medium",
            color="red",
            threat_level="High Risk" if mx_issue['listed_count'] >= 3 else "Elevated Risk",
            raw_data=f"Listed on: {', '.join(mx_issue['listed_servers'][:5])}",
            tags=["email-security", "multi-mx", "blacklist"]
        ))
    if mx_info["has_mx"] and len(mx_info["mx_records"]) > 1 and not multi_mx_issues:
        findings.append(IntelligenceFinding(
            entity=f"All {len(mx_info['mx_records'])} MX servers clean on DNSBLs",
            type="Email: Multi-MX Clean",
            source="EmailReputation",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            tags=["email-security", "multi-mx", "clean"]
        ))

    sending_score = await compute_email_sending_score(spf, dkim, dmarc, dnsbl_data, ptr_global_data, mx_info)
    s_score = sending_score["score"]
    s_color = "emerald" if s_score >= 70 else ("orange" if s_score >= 40 else "red")
    s_threat = "Informational" if s_score >= 70 else ("Elevated Risk" if s_score >= 40 else "High Risk")
    findings.append(IntelligenceFinding(
        entity=f"Email Sending Score: {s_score}/100",
        type="Email: Sending Score",
        source="EmailReputation",
        confidence="High",
        color=s_color,
        threat_level=s_threat,
        raw_data=f"Score: {s_score}/100 | Breakdown: {'; '.join(sending_score['breakdown'])}",
        tags=["email-security", "sending-score", "composite"]
    ))

    url_sb = await url_safe_check(client, domain)
    if url_sb["success"]:
        if url_sb["malicious"]:
            findings.append(IntelligenceFinding(
                entity=f"Domain flagged by Google Safe Browsing: {', '.join(url_sb['threats'])}",
                type="Email: URL Threat",
                source="EmailReputation/GoogleSafeBrowsing",
                confidence="High",
                color="red",
                threat_level="Critical",
                raw_data=f"Threats: {', '.join(url_sb['threats'])}",
                tags=["email-security", "url-scan", "google-safebrowsing"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity="Domain not flagged by Google Safe Browsing",
                type="Email: URL Threat",
                source="EmailReputation/GoogleSafeBrowsing",
                confidence="Low",
                color="emerald",
                threat_level="Informational",
                tags=["email-security", "url-scan", "google-safebrowsing"]
            ))

    url_vt = await url_vt_check(client, domain)
    if url_vt["success"]:
        vt_color = "red" if url_vt["malicious"] > 0 else ("orange" if url_vt["suspicious"] > 0 else "emerald")
        vt_threat = "High Risk" if url_vt["malicious"] > 0 else ("Elevated Risk" if url_vt["suspicious"] > 0 else "Informational")
        findings.append(IntelligenceFinding(
            entity=f"VirusTotal: {url_vt['malicious']} malicious, {url_vt['suspicious']} suspicious, {url_vt['harmless']} harmless",
            type="Email: VirusTotal Scan",
            source="EmailReputation/VirusTotal",
            confidence="Low",
            color=vt_color,
            threat_level=vt_threat,
            raw_data=f"malicious={url_vt['malicious']} suspicious={url_vt['suspicious']} harmless={url_vt['harmless']} undetected={url_vt['undetected']}",
            tags=["email-security", "url-scan", "virustotal"]
        ))

    if findings:
        summary_lines = [
            f"Total email findings: {len(findings)}",
            f"SPF: {'OK' if spf['has_spf'] else 'Missing'}",
            f"DKIM: {'OK' if dkim['has_dkim'] else 'Missing'}",
            f"DMARC: {'OK' if dmarc['has_dmarc'] else 'Missing'} (policy: {dmarc['policy'] or 'none'})",
        ]
        blacklisted_count = sum(1 for f in findings if "Blacklisted" in f.type or "RBL Listed" in f.type)
        if blacklisted_count:
            summary_lines.append(f"Blacklisted on {blacklisted_count} listing(s)")
        summary_lines.append(f"Sending Score: {s_score}/100")
        summary_lines.append(f"SpamAssassin: {spamass['score']} ({spamass['verdict']})")

        findings.append(IntelligenceFinding(
            entity=f"Email Reputation: {len(findings)} checks | Blacklisted: {blacklisted_count > 0} | Score: {s_score}/100",
            type="Email: Summary",
            source="EmailReputation",
            confidence="Medium",
            color="red" if blacklisted_count > 0 else "emerald",
            threat_level="High Risk" if blacklisted_count > 0 else "Informational",
            raw_data="\n".join(summary_lines),
            tags=["summary", "email-reputation"]
        ))

        email_auth_ok = spf["has_spf"] and dkim["has_dkim"] and dmarc["has_dmarc"]
        dmarc_good = dmarc["policy"] in ("reject", "quarantine")
        has_ptr = ptr_global_data.get("has_ptr", False)
        posture_issues = []
        if not spf["has_spf"]:
            posture_issues.append("SPF missing")
        if not dkim["has_dkim"]:
            posture_issues.append("DKIM missing")
        if not dmarc["has_dmarc"]:
            posture_issues.append("DMARC missing")
        elif not dmarc_good:
            posture_issues.append("DMARC policy not restrictive")
        if not has_ptr:
            posture_issues.append("No PTR records")
        if blacklisted_count > 0:
            posture_issues.append(f"Blacklisted on {blacklisted_count} lists")
        if s_score < 50:
            posture_issues.append(f"Low sending score ({s_score})")

        if len(posture_issues) == 0:
            posture = "Strong"
            posture_color = "emerald"
            posture_threat = "Informational"
        elif len(posture_issues) <= 2:
            posture = "Moderate"
            posture_color = "orange"
            posture_threat = "Elevated Risk"
        else:
            posture = "Weak"
            posture_color = "red"
            posture_threat = "High Risk"

        posture_raw = f"Posture: {posture} | EmailAuth: {'OK' if email_auth_ok else 'Issues'} | DMARC: {dmarc['policy'] or 'none'} | Score: {s_score}/100 | SA: {spamass['score']} | Issues: {'; '.join(posture_issues) if posture_issues else 'None'}"
        findings.append(IntelligenceFinding(
            entity=f"Email Security Posture: {posture}",
            type="Email: Security Posture Summary",
            source="EmailReputation",
            confidence="High",
            color=posture_color,
            threat_level=posture_threat,
            status=posture,
            raw_data=posture_raw,
            tags=["email-security", "posture", "comprehensive"]
        ))

    async def detect_email_provider():
        provider_map = {
            "google.com": "Google Workspace/Gmail", "googlemail.com": "Google Workspace/Gmail",
            "outlook.com": "Microsoft 365/Outlook", "protection.outlook.com": "Microsoft 365",
            "mail.protection.outlook.com": "Microsoft 365",
            "protonmail": "ProtonMail", "protonmail.ch": "ProtonMail",
            "zoho.com": "Zoho Mail", "zimbra": "Zimbra",
            "mxr.mail.qq": "Tencent QQ Mail", "mxw.mail.qq": "Tencent QQ Mail",
            "mx1.qiye.qq": "Tencent Enterprise", "mx2.qiye.qq": "Tencent Enterprise",
            "mx01.mail.icloud": "Apple iCloud Mail", "mx02.mail.icloud": "Apple iCloud Mail",
            "amazonses.com": "Amazon SES", "aws": "Amazon SES",
            "sparkpostmail.com": "SparkPost", "sparkpost": "SparkPost",
            "sendgrid.net": "SendGrid", "sendgrid": "SendGrid",
            "mailgun.org": "Mailgun", "mailgun": "Mailgun",
            "mx.yandex": "Yandex Mail", "yandex": "Yandex Mail",
            "mail.ru": "Mail.ru", "mx.mail.ru": "Mail.ru",
            "fastmail": "Fastmail", "messagingengine.com": "Fastmail",
            "postmarkapp.com": "Postmark", "pm.mtasv.net": "Postmark",
            "mx.migadu.com": "Migadu", "mx1.migadu.com": "Migadu",
        }
        if mx_info["has_mx"]:
            provider = "Unknown/Custom"
            for mx in mx_info["mx_records"]:
                mx_host = mx["host"].lower()
                for key, name in provider_map.items():
                    if key in mx_host:
                        provider = name
                        break
                if provider != "Unknown/Custom":
                    break
            findings.append(IntelligenceFinding(
                entity=f"Email Provider: {provider}",
                type="Email: Provider Detection",
                source="EmailReputation",
                confidence="High" if provider != "Unknown/Custom" else "Medium",
                color="slate",
                threat_level="Informational",
                tags=["email-security", "provider"]
            ))
            findings.append(IntelligenceFinding(
                entity=f"MX Count: {len(mx_info['mx_records'])} server(s)",
                type="Email: MX Server Count",
                source="EmailReputation",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["email-security", "mx-count"]
            ))

    async def check_web_headers():
        for proto in ["https", "http"]:
            try:
                resp = await client.get(f"{proto}://{domain}", timeout=8.0, follow_redirects=True,
                    headers={"User-Agent": UA})
                hdrs = {k.lower(): v for k, v in dict(resp.headers).items()}
                status = resp.status_code
                findings.append(IntelligenceFinding(
                    entity=f"Website: HTTP {status} ({len(resp.content)} bytes)",
                    type="Email: Web Presence",
                    source="EmailReputation",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["web"]))
                for hdr in ["strict-transport-security", "x-frame-options", "content-security-policy",
                            "x-content-type-options", "referrer-policy", "permissions-policy"]:
                    if hdr in hdrs:
                        findings.append(IntelligenceFinding(
                            entity=f"Security Header: {hdr}={hdrs[hdr][:80]}",
                            type="Email: Security Header",
                            source="EmailReputation",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            tags=["web", "security-header"]))
                break
            except: pass

    async def check_subdomains():
        common = ["mail", "smtp", "imap", "pop3", "webmail", "email", "mx", "autodiscover", "m"]
        for sub in common:
            try:
                resp = await client.get(f"https://{sub}.{domain}", timeout=5.0,
                    headers={"User-Agent": UA}, follow_redirects=False)
                if resp.status_code < 400:
                    findings.append(IntelligenceFinding(
                        entity=f"Subdomain: {sub}.{domain} (HTTP {resp.status_code})",
                        type="Email: Subdomain Discovery",
                        source="EmailReputation",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["discovery"]))
            except: pass

    async def check_ssl_cert():
        try:
            import ssl, socket
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                issuer = dict(cert.get("issuer", [[["", ""]]])[0]).get("commonName", "Unknown")
                findings.append(IntelligenceFinding(
                    entity=f"SSL Issuer: {issuer}",
                    type="Email: SSL Certificate",
                    source="EmailReputation",
                    confidence="High",
                    color="slate",
                    tags=["ssl"]))
                ver = s.version()
                findings.append(IntelligenceFinding(
                    entity=f"TLS Version: {ver}",
                    type="Email: TLS Version",
                    source="EmailReputation",
                    confidence="High",
                    color="emerald" if "TLSv1.2" in ver or "TLSv1.3" in ver else "orange",
                    tags=["ssl"]))
        except: pass

    async def check_securitytxt():
        for path in [f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"]:
            try:
                resp = await client.get(path, timeout=8.0, headers={"User-Agent": UA})
                if resp.status_code == 200 and len(resp.text.strip()) > 20:
                    findings.append(IntelligenceFinding(
                        entity="Security.txt found",
                        type="Email: Security.txt",
                        source="EmailReputation",
                        confidence="High", color="emerald", tags=["security"]))
                    for m in re.finditer(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", resp.text):
                        findings.append(IntelligenceFinding(
                            entity=f"Contact: {m.group(0)}",
                            type="Email: Security Contact",
                            source="EmailReputation",
                            confidence="High", color="blue", tags=["contact"]))
                    break
            except: pass

    async def generate_recommendations():
        recs = []
        if not spf["has_spf"]:
            recs.append("Publish an SPF record to prevent spoofing")
        if "+all" in spf.get("spf_record", ""):
            recs.append("Remove +all from SPF - it allows any sender")
        if "~all" not in spf.get("spf_record", "") and "-all" not in spf.get("spf_record", "") and spf["has_spf"]:
            recs.append("Add a fail mechanism (~all or -all) to SPF")
        if not dkim["has_dkim"]:
            recs.append("Configure DKIM signing for outgoing mail")
        if not dmarc["has_dmarc"]:
            recs.append("Publish a DMARC record to protect against spoofing")
        elif dmarc["policy"] == "none":
            recs.append("Strengthen DMARC policy from 'none' to 'quarantine' or 'reject'")
        if dmarc["has_dmarc"] and "rua=" not in dmarc.get("dmarc_record", ""):
            recs.append("Add rua tag to DMARC for aggregate reporting")
        if dnsbl_data.get("blacklisted_count", 0) > 0:
            recs.append("Investigate DNSBL listings and request delisting")
        if not ptr_global_data.get("has_ptr", False):
            recs.append("Configure PTR records for your mail server IPs")
        if s_score < 50:
            recs.append("Improve email authentication to increase sending score")
        for i, rec in enumerate(recs[:6]):
            findings.append(IntelligenceFinding(
                entity=f"Rec {i+1}: {rec}",
                type="Email: Recommendation",
                source="EmailReputation",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                tags=["recommendation"]))

    async def check_mx_geo():
        if mx_info["has_mx"]:
            for mx in mx_info["mx_records"][:3]:
                mx_host = mx["host"]
                ips = await resolve_mx_to_ips(mx_host)
                for ip in ips[:2]:
                    try:
                        resp = await client.get(f"http://ip-api.com/json/{ip}", timeout=8.0)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("status") == "success":
                                findings.append(IntelligenceFinding(
                                    entity=f"MX {mx_host} ({ip}): {data.get('city', '')}, {data.get('countryCode', '')} - {data.get('org', '')}",
                                    type="Email: MX Geo Location",
                                    source="EmailReputation",
                                    confidence="Medium",
                                    color="slate",
                                    tags=["geo"]))
                    except: pass

    async def check_domain_risk_analysis():
        domain_to_check = domain
        is_free = any(dom in domain_to_check for dom in
            ["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","protonmail.com","mail.com"])
        findings.append(IntelligenceFinding(
            entity=f"Email Type: {'Free/Consumer' if is_free else 'Custom/Corporate'}",
            type="Email: Domain Classification",
            source="EmailReputation",
            confidence="High",
            color="slate",
            tags=["classification"]))
        tld = domain_to_check.rsplit(".", 1)[-1].lower() if "." in domain_to_check else ""
        uncommon_tlds = {"tk","ml","ga","cf","gq","xyz","top","work","loan","date","download","men"}
        if tld in uncommon_tlds:
            findings.append(IntelligenceFinding(
                entity=f"Uncommon TLD detected: .{tld}",
                type="Email: Risk Factor",
                source="EmailReputation",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                tags=["risk"]))

    await asyncio.gather(
        detect_email_provider(),
        check_web_headers(),
        check_subdomains(),
        check_ssl_cert(),
        check_securitytxt(),
        generate_recommendations(),
        check_mx_geo(),
        check_domain_risk_analysis(),
    )

    return findings
