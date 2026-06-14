import httpx
import asyncio
import re
import socket
import dns.resolver
from urllib.parse import urlparse
from models import IntelligenceFinding
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

    ips = await get_ips_for_domain(domain)

    for ip in ips:
        ptr = await check_ptr_record(ip)

        if ptr["has_ptr"]:
            matches = domain in ptr["ptr_record"] or any(
                mx["host"] in ptr["ptr_record"] for mx in mx_info.get("mx_records", [])
            )
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

        findings.append(IntelligenceFinding(
            entity=f"Email Reputation: {len(findings)} checks | Blacklisted: {blacklisted_count > 0}",
            type="Email: Summary",
            source="EmailReputation",
            confidence="Medium",
            color="red" if blacklisted_count > 0 else "emerald",
            threat_level="High Risk" if blacklisted_count > 0 else "Informational",
            raw_data="\n".join(summary_lines),
            tags=["summary", "email-reputation"]
        ))

    return findings
