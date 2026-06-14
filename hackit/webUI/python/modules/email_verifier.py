import httpx
import asyncio
import re
import dns.resolver
from models import IntelligenceFinding

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

SMTP_GREETINGS = {
    "gmail.com": "smtp.gmail.com",
    "yahoo.com": "smtp.mail.yahoo.com",
    "outlook.com": "smtp-mail.outlook.com",
    "hotmail.com": "smtp-mail.outlook.com",
    "live.com": "smtp-mail.outlook.com",
    "aol.com": "smtp.aol.com",
    "protonmail.com": "mail.protonmail.ch",
    "mail.com": "smtp.mail.com",
    "zoho.com": "smtp.zoho.com",
    "yandex.com": "smtp.yandex.com",
    "gmx.com": "smtp.gmx.com",
    "icloud.com": "smtp.mail.me.com",
}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    emails = set()
    loop = asyncio.get_event_loop()

    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
        if mx_hosts:
            for mx in mx_hosts:
                findings.append(IntelligenceFinding(
                    entity=mx,
                    type="Mail Server (MX)",
                    source="Email Verifier",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Mail exchange: {mx}"
                ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"No MX records for {domain}",
            type="Mail Server Status",
            source="Email Verifier",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Cannot receive emails"
        ))
        return findings

    try:
        spf_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        has_spf = False
        for r in spf_records:
            txt = str(r)
            if txt.startswith("v=spf1"):
                has_spf = True
                findings.append(IntelligenceFinding(
                    entity=txt[:200],
                    type="SPF Record",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=txt[:2000],
                    tags=["email-security"]
                ))

                if "~all" in txt:
                    findings.append(IntelligenceFinding(
                        entity="SPF SoftFail (~all)",
                        type="SPF Configuration",
                        source="Email Verifier",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        raw_data="SPF uses soft fail - emails may be spoofed"
                    ))
                elif "-all" in txt:
                    findings.append(IntelligenceFinding(
                        entity="SPF HardFail (-all)",
                        type="SPF Configuration",
                        source="Email Verifier",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data="SPF uses hard fail - good protection"
                    ))
                elif "?all" in txt:
                    findings.append(IntelligenceFinding(
                        entity="SPF Neutral (?all)",
                        type="SPF Weakness",
                        source="Email Verifier",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data="SPF uses neutral - emails can be spoofed"
                    ))
                break
        if not has_spf:
            findings.append(IntelligenceFinding(
                entity=f"No SPF record for {domain}",
                type="Missing SPF",
                source="Email Verifier",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"{domain} vulnerable to email spoofing",
                tags=["email-security"]
            ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"Cannot query SPF for {domain}",
            type="SPF Error",
            source="Email Verifier",
            confidence="Medium",
            color="orange",
            threat_level="Informational"
        ))

    try:
        dmarc_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'))
        for r in dmarc_records:
            dmarc = str(r)
            findings.append(IntelligenceFinding(
                entity=dmarc[:200],
                type="DMARC Record",
                source="Email Verifier",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                raw_data=dmarc[:2000],
                tags=["email-security"]
            ))
            if "p=reject" in dmarc:
                findings.append(IntelligenceFinding(
                    entity="DMARC Policy: Reject",
                    type="DMARC Policy",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))
            elif "p=quarantine" in dmarc:
                findings.append(IntelligenceFinding(
                    entity="DMARC Policy: Quarantine",
                    type="DMARC Policy",
                    source="Email Verifier",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                ))
            elif "p=none" in dmarc:
                findings.append(IntelligenceFinding(
                    entity="DMARC Policy: None (Monitoring Only)",
                    type="DMARC Policy Weakness",
                    source="Email Verifier",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    tags=["email-security"]
                ))
    except:
        findings.append(IntelligenceFinding(
            entity=f"No DMARC record for {domain}",
            type="Missing DMARC",
            source="Email Verifier",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"{domain} vulnerable to email spoofing",
            tags=["email-security"]
        ))

    for selector in ['default', 'google', 'mail', 'k1', 'dkim', 'mx']:
        try:
            dkim_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT'))
            for r in dkim_records:
                findings.append(IntelligenceFinding(
                    entity=f"DKIM (selector: {selector})",
                    type="DKIM Record",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    resolution=str(r)[:150],
                    threat_level="Informational",
                    raw_data=str(r)[:2000],
                    tags=["email-security"]
                ))
                break
        except: pass

    email_security_score = 0
    if any(f.type == "SPF Record" for f in findings): email_security_score += 3
    if any(f.type == "DMARC Record" for f in findings): email_security_score += 3
    if any(f.type == "DKIM Record" for f in findings): email_security_score += 3
    if any("p=reject" in (f.raw_data or "") for f in findings): email_security_score += 1
    if any("HardFail" in (f.raw_data or "") for f in findings): email_security_score += 1

    findings.append(IntelligenceFinding(
        entity=f"Email Security Score: {email_security_score}/10",
        type="Email Security Summary",
        source="Email Verifier",
        confidence="High",
        color="emerald" if email_security_score >= 7 else ("orange" if email_security_score >= 4 else "red"),
        threat_level="Informational" if email_security_score >= 7 else ("Standard Target" if email_security_score >= 4 else "Elevated Risk"),
        raw_data=f"Score: {email_security_score}/10 (SPF+DKIM+DMARC)",
        tags=["email-security", "summary"]
    ))

    return findings
