import httpx
import asyncio
import re
import dns.resolver
import base64
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

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "dkim", "mx", "selector1", "selector2",
    "s1", "s2", "smtp", "email", "mailer", "pm", "protonmail", "zoho",
    "outlook", "office365", "microsoft", "mandrill", "sendgrid", "sparkpost",
    "mailgun", "postmark", "amazonses", "ses", "dkim1", "dkim2", "key1",
    "2023", "2024", "2025", "2026", "ed25519", "rsa", "x", "z", "mta",
    "selector", "smtp01", "smtp02", "exch", "pod", "pod1", "pod2",
    "cluster", "node1", "node2", "hk1", "hk2", "eu1", "eu2", "us1", "us2",
    "dk", "dk01", "dk02", "key", "key2", "key3", "pub", "pubkey",
    "rsa2048", "rsa1024", "256", "512", "1024", "2048",
    "mta1", "mta2", "mta3", "mail1", "mail2", "em1", "em2",
    "sg", "send", "mailchimp", "mandrillapp", "spf",
    "sig1", "sig2", "dkim2019", "dkim2020", "dkim2021", "dkim2022",
    "dkim2023", "dkim2024", "dkim2025", "dkim2026",
    "dkim01", "dkim02", "dkim03", "mxhost", "smtp-relay", "relay",
    "inbound", "outbound", "transaction", "bulk", "marketing",
    "prod", "stage", "c1", "c2", "c3", "selector-a", "selector-b",
    "selector01", "selector02", "mxs", "mxb", "mxp",
]

DNSBL_LIST = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "b.barracudacentral.org",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "db.wpbl.info",
    "dnsbl.dronebl.org",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
    "dnsbl.netsec.net",
    "dnsbl.njabl.org",
    "dnsbl.tornevall.org",
    "duinv.aupads.org",
    "dyna.spamrats.com",
    "escalations.dnsbl.net",
    "fnfno.dnsbl.net",
    "forbidden.dnsbl.net",
    "hostkarma.junkemailfilter.com",
    "korea.services.net",
    "l2.bbfh.ext.sbl",
    "l3.bbfh.ext.sbl",
    "mail-abuse.blacklist.jippg.org",
    "netscan.rbl.blockedservers.com",
    "new.spam.dnsbl.sorbs.net",
    "no-more-funn.moensted.dnsbl.net",
    "noptr.spamrats.com",
    "old.spam.dnsbl.sorbs.net",
    "ornl.dnsbl.net",
    "pbl.spamhaus.org",
    "rbl.efnetrbl.org",
    "rbl.interserver.net",
    "rbl.megarbl.net",
    "rbl.realtimeblacklist.com",
    "rbl.schulte.org",
    "rbl.spamlab.com",
    "rbl.talkactive.net",
    "relays.dnsbl.net",
    "singular.ttk.pte.hu",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.dnsbl.anonmails.de",
    "spam.dnsbl.sorbs.net",
    "spam.pedantic.org",
    "spam.rbl.blockedservers.com",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "torexit.dan.me.uk",
    "ubl.unsubscore.com",
    "web.dnsbl.net",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.dogsiemens.com",
]

DKIM_KEY_PATTERN = re.compile(r"p\s*=\s*([A-Za-z0-9+/=]+)")
BIMI_PATTERN = re.compile(r"l=https?://\S+")

def estimate_key_strength(dkim_txt: str):
    if "ed25519" in dkim_txt:
        return ("Ed25519 (Strong)", "High", "emerald")
    p_match = DKIM_KEY_PATTERN.search(dkim_txt)
    if not p_match:
        return ("Unknown key", "Low", "red")
    key_data = p_match.group(1)
    try:
        decoded = base64.b64decode(key_data + "==")
        bit_length = len(decoded) * 8
        if bit_length >= 2048:
            return (f"RSA {bit_length}-bit (Strong)", "High", "emerald")
        elif bit_length >= 1024:
            return (f"RSA {bit_length}-bit (Adequate)", "Medium", "orange")
        else:
            return (f"RSA {bit_length}-bit (Weak)", "Low", "red")
    except Exception:
        key_len = len(key_data)
        if key_len > 400:
            return ("RSA 2048+ bit (estimated)", "High", "emerald")
        elif key_len > 200:
            return ("RSA 1024+ bit (estimated)", "Medium", "orange")
        else:
            return ("Key too short or unknown", "Low", "red")

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    emails = set()
    loop = asyncio.get_event_loop()
    checks_performed = []
    checks_passed = []
    checks_failed = []

    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        mx_hosts = [str(r.exchange).rstrip('.') for r in mx_records]
        if mx_hosts:
            checks_performed.append("MX Records")
            checks_passed.append("MX Records")
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
        checks_performed.append("MX Records")
        checks_failed.append("MX Records")
        findings.append(IntelligenceFinding(
            entity="Email Security Score: 0/50 (0%)",
            type="Email Security Summary",
            source="Email Verifier",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data="Score: 0/50 | No MX records - domain cannot receive email",
            tags=["email-security", "summary"]
        ))
        return findings

    has_spf = False
    try:
        spf_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        for r in spf_records:
            txt = str(r)
            if txt.startswith("v=spf1"):
                has_spf = True
                checks_performed.append("SPF Record")
                checks_passed.append("SPF Record")
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
            checks_performed.append("SPF Record")
            checks_failed.append("SPF Record")
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
        checks_performed.append("SPF Record")
        checks_failed.append("SPF Record")
        findings.append(IntelligenceFinding(
            entity=f"Cannot query SPF for {domain}",
            type="SPF Error",
            source="Email Verifier",
            confidence="Medium",
            color="orange",
            threat_level="Informational"
        ))

    has_dmarc = False
    dmarc_policy = None
    try:
        dmarc_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", 'TXT'))
        for r in dmarc_records:
            dmarc = str(r)
            has_dmarc = True
            checks_performed.append("DMARC Record")
            checks_passed.append("DMARC Record")
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
                dmarc_policy = "reject"
                findings.append(IntelligenceFinding(
                    entity="DMARC Policy: Reject",
                    type="DMARC Policy",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                ))
            elif "p=quarantine" in dmarc:
                dmarc_policy = "quarantine"
                findings.append(IntelligenceFinding(
                    entity="DMARC Policy: Quarantine",
                    type="DMARC Policy",
                    source="Email Verifier",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                ))
            elif "p=none" in dmarc:
                dmarc_policy = "none"
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
        checks_performed.append("DMARC Record")
        checks_failed.append("DMARC Record")
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

    dkim_found = []
    for selector in COMMON_DKIM_SELECTORS:
        try:
            dkim_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT'))
            for r in dkim_records:
                dkim_txt = str(r)
                key_strength, key_conf, key_color = estimate_key_strength(dkim_txt)
                findings.append(IntelligenceFinding(
                    entity=f"DKIM (selector: {selector}) - {key_strength}",
                    type="DKIM Record",
                    source="Email Verifier",
                    confidence="High",
                    color=key_color,
                    resolution=str(r)[:150],
                    threat_level="Informational",
                    raw_data=str(r)[:2000],
                    tags=["email-security"]
                ))
                dkim_found.append(selector)
                break
        except:
            pass

    if dkim_found:
        checks_performed.append("DKIM Record")
        checks_passed.append("DKIM Record")
    else:
        checks_performed.append("DKIM Record")
        checks_failed.append("DKIM Record")
        findings.append(IntelligenceFinding(
            entity=f"No DKIM records found (checked {len(COMMON_DKIM_SELECTORS)} selectors)",
            type="Missing DKIM",
            source="Email Verifier",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"None of {len(COMMON_DKIM_SELECTORS)} common selectors have DKIM keys",
            tags=["email-security"]
        ))

    try:
        mta_sts_txt = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        )
        for r in mta_sts_txt:
            mta_txt = str(r)
            if "v=STSv1" in mta_txt:
                checks_performed.append("MTA-STS (DNS)")
                checks_passed.append("MTA-STS (DNS)")
                findings.append(IntelligenceFinding(
                    entity=mta_txt[:200],
                    type="MTA-STS Record (DNS)",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=mta_txt[:2000],
                    tags=["email-security", "mta-sts"]
                ))
            break
    except:
        checks_performed.append("MTA-STS (DNS)")
        checks_failed.append("MTA-STS (DNS)")

    try:
        mta_sts_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        mta_resp = await client.get(mta_sts_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"})
        if mta_resp.status_code == 200:
            mta_policy = mta_resp.text.strip()
            if "v=STSv1" in mta_policy:
                checks_performed.append("MTA-STS (HTTP)")
                checks_passed.append("MTA-STS (HTTP)")
                findings.append(IntelligenceFinding(
                    entity=f"MTA-STS Policy Active (HTTP endpoint)",
                    type="MTA-STS Policy",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=mta_policy[:2000],
                    tags=["email-security", "mta-sts"]
                ))
                mode_match = re.search(r"mode:\s*(\w+)", mta_policy)
                if mode_match:
                    mode = mode_match.group(1)
                    color = "emerald" if mode == "enforce" else ("orange" if mode == "testing" else "red")
                    findings.append(IntelligenceFinding(
                        entity=f"MTA-STS Mode: {mode}",
                        type="MTA-STS Mode",
                        source="Email Verifier",
                        confidence="High",
                        color=color,
                        threat_level="Informational"
                    ))
    except:
        checks_performed.append("MTA-STS (HTTP)")
        checks_failed.append("MTA-STS (HTTP)")

    try:
        tls_rpt_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        )
        for r in tls_rpt_records:
            tls_txt = str(r)
            if "v=TLSRPT" in tls_txt:
                checks_performed.append("TLS-RPT")
                checks_passed.append("TLS-RPT")
                findings.append(IntelligenceFinding(
                    entity=tls_txt[:200],
                    type="TLS-RPT Record",
                    source="Email Verifier",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=tls_txt[:2000],
                    tags=["email-security", "tls-rpt"]
                ))
            break
    except:
        checks_performed.append("TLS-RPT")
        checks_failed.append("TLS-RPT")

    try:
        bimi_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        )
        for r in bimi_records:
            bimi_txt = str(r)
            checks_performed.append("BIMI")
            checks_passed.append("BIMI")
            findings.append(IntelligenceFinding(
                entity=bimi_txt[:200],
                type="BIMI Record",
                source="Email Verifier",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=bimi_txt[:2000],
                tags=["email-security", "bimi"]
            ))
            logo_match = BIMI_PATTERN.search(bimi_txt)
            if logo_match:
                findings.append(IntelligenceFinding(
                    entity=f"BIMI Logo: {logo_match.group(0)[2:]}",
                    type="BIMI Logo URL",
                    source="Email Verifier",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    tags=["email-security", "bimi"]
                ))
            break
    except:
        checks_performed.append("BIMI")
        checks_failed.append("BIMI")

    smtp_banner = None
    if mx_hosts:
        try:
            smtp_target = mx_hosts[0]
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(smtp_target, 25), timeout=8.0
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=5.0)
            banner_str = banner.decode("utf-8", errors="ignore").strip()
            writer.close()
            if banner_str:
                smtp_banner = banner_str
                checks_performed.append("SMTP Banner Grab")
                checks_passed.append("SMTP Banner Grab")
                findings.append(IntelligenceFinding(
                    entity=f"SMTP Banner: {banner_str[:200]}",
                    type="SMTP Banner",
                    source="Email Verifier",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=banner_str[:2000],
                    tags=["email-security", "smtp"]
                ))
        except Exception:
            checks_performed.append("SMTP Banner Grab")
            checks_failed.append("SMTP Banner Grab")
            findings.append(IntelligenceFinding(
                entity=f"SMTP on {mx_hosts[0]}:25 not responding",
                type="SMTP Banner",
                source="Email Verifier",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                raw_data="Could not grab SMTP banner on port 25"
            ))

    dnsbl_hits = []
    if mx_hosts:
        for mx in mx_hosts:
            try:
                mx_ip_records = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(mx, 'A')
                )
                for mx_ip_rec in mx_ip_records:
                    mx_ip = str(mx_ip_rec)
                    for bl in DNSBL_LIST:
                        try:
                            rev_parts = mx_ip.split('.')
                            rev_parts.reverse()
                            lookup = '.'.join(rev_parts) + '.' + bl
                            await loop.run_in_executor(
                                None, lambda: dns.resolver.resolve(lookup, 'A')
                            )
                            dnsbl_hits.append((mx, mx_ip, bl))
                        except Exception:
                            pass
                    break
            except Exception:
                pass

    if dnsbl_hits:
        checks_performed.append("DNSBL Check")
        checks_failed.append("DNSBL Check")
        for mx, mx_ip, bl in dnsbl_hits:
            findings.append(IntelligenceFinding(
                entity=f"{mx} ({mx_ip}) listed on {bl}",
                type="DNSBL Listing",
                source="Email Verifier",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"Mail server {mx} ({mx_ip}) found on DNSBL: {bl}",
                tags=["email-security", "dnsbl"]
            ))
    else:
        checks_performed.append("DNSBL Check")
        checks_passed.append("DNSBL Check")

    try:
        dnssec_loop = asyncio.get_event_loop()
        dnssec_result = await dnssec_loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'DNSKEY'))
        if dnssec_result:
            checks_performed.append("DNSSEC")
            checks_passed.append("DNSSEC")
            findings.append(IntelligenceFinding(
                entity=f"DNSSEC enabled: {len(dnssec_result)} DNSKEY record(s)",
                type="DNSSEC Status",
                source="Email Verifier",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                raw_data=f"DNSSEC configured with {len(dnssec_result)} DNSKEY records",
                tags=["email-security", "dnssec"]
            ))
    except dns.resolver.NoAnswer:
        checks_performed.append("DNSSEC")
        checks_failed.append("DNSSEC")
    except:
        pass

    for mx in mx_hosts[:3]:
        for port in [465, 587]:
            try:
                rdr, wrtr = await asyncio.wait_for(asyncio.open_connection(mx, port), timeout=4.0)
                bnner = await asyncio.wait_for(rdr.readline(), timeout=3.0)
                bnner_str = bnner.decode("utf-8", errors="ignore").strip()
                wrtr.close()
                if bnner_str:
                    checks_performed.append(f"SMTP Port {port}")
                    checks_passed.append(f"SMTP Port {port}")
                    findings.append(IntelligenceFinding(
                        entity=f"SMTP Banner on {mx}:{port}: {bnner_str[:150]}",
                        type=f"SMTP Banner (Port {port})",
                        source="Email Verifier",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=bnner_str[:1000],
                        tags=["email-security", "smtp", f"port-{port}"]
                    ))
            except:
                checks_performed.append(f"SMTP Port {port}")
                checks_failed.append(f"SMTP Port {port}")

    if mx_hosts:
        try:
            mx_ip_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(mx_hosts[0], 'A'))
            for mx_ip_rec in mx_ip_records:
                mx_ip = str(mx_ip_rec)
                try:
                    rev = dns.resolver.resolve_address(mx_ip)
                    rev_name = str(rev[0]).rstrip('.')
                    if rev_name:
                        checks_performed.append("MX rDNS")
                        checks_passed.append("MX rDNS")
                        findings.append(IntelligenceFinding(
                            entity=f"MX rDNS: {mx_hosts[0]} ({mx_ip}) -> {rev_name}",
                            type="MX Reverse DNS",
                            source="Email Verifier",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"{mx_ip} resolves to {rev_name}",
                            tags=["email-security", "mx", "rdns"]
                        ))
                        if mx_hosts[0].lower() not in rev_name.lower() and mx_hosts[0].lower().rstrip('.') not in rev_name.lower():
                            checks_performed.append("MX rDNS Match")
                            checks_failed.append("MX rDNS Match")
                            findings.append(IntelligenceFinding(
                                entity=f"MX rDNS mismatch: {mx_hosts[0]} != {rev_name}",
                                type="MX rDNS Mismatch",
                                source="Email Verifier",
                                confidence="Medium",
                                color="orange",
                                threat_level="Standard Target",
                                tags=["email-security", "mx", "rdns"]
                            ))
                        else:
                            checks_performed.append("MX rDNS Match")
                            checks_passed.append("MX rDNS Match")
                except:
                    pass
                break
        except:
            pass

    try:
        dmarc_check = None
        for f in findings:
            if f.type == "DMARC Record":
                dmarc_check = f.raw_data
                break
        if dmarc_check:
            for tag, label in [("aspf", "SPF Alignment"), ("adkim", "DKIM Alignment")]:
                m = re.search(rf"{tag}\s*=\s*([rs])", dmarc_check)
                if m:
                    val = "Strict" if m.group(1) == "r" else "Relaxed"
                    checks_performed.append(label)
                    checks_passed.append(label) if m.group(1) == "r" else checks_failed.append(label)
                    findings.append(IntelligenceFinding(
                        entity=f"DMARC {label}: {val}",
                        type=f"DMARC {label}",
                        source="Email Verifier",
                        confidence="High",
                        color="emerald" if m.group(1) == "r" else "orange",
                        threat_level="Informational" if m.group(1) == "r" else "Standard Target",
                        tags=["email-security", "dmarc"]
                    ))
            for tag, label in [("rua", "DMARC RUA"), ("ruf", "DMARC RUF")]:
                m = re.search(rf"{tag}\s*=\s*(mailto:\S+)", dmarc_check)
                if m:
                    findings.append(IntelligenceFinding(
                        entity=f"{label}: {m.group(1)[:200]}",
                        type=label,
                        source="Email Verifier",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=m.group(1),
                        tags=["email-security", "dmarc"]
                    ))
    except:
        pass

    spf_macros = False
    spf_dns_lookups = 0
    spf_record = None
    for f in findings:
        if "v=spf1" in (f.raw_data or ""):
            spf_record = f.raw_data
            break
    if spf_record:
        spf_macros = bool(re.search(r'[%{}]', spf_record))
        if spf_macros:
            findings.append(IntelligenceFinding(
                entity="SPF macros detected - may cause expansion issues",
                type="SPF Macro Warning",
                source="Email Verifier",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                tags=["email-security", "spf"]
            ))
        incl_count = len(re.findall(r'\binclude:', spf_record))
        redirect_count = len(re.findall(r'\bredirect=', spf_record))
        a_count = len(re.findall(r'\ba[:\s]', spf_record))
        mx_count = len(re.findall(r'\bmx[:\s]', spf_record))
        spf_dns_lookups = incl_count + redirect_count + a_count + mx_count
        if spf_dns_lookups > 8:
            findings.append(IntelligenceFinding(
                entity=f"SPF ~{spf_dns_lookups} DNS lookups - near limit",
                type="SPF DNS Lookup Warning",
                source="Email Verifier",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                raw_data=f"Estimated lookups: {spf_dns_lookups} (limit: 10)",
                tags=["email-security", "spf"]
            ))
        elif spf_dns_lookups >= 10:
            findings.append(IntelligenceFinding(
                entity=f"SPF exceeds 10 DNS lookup limit (~{spf_dns_lookups})",
                type="SPF DNS Lookup Exceeded",
                source="Email Verifier",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"SPF PermError risk: ~{spf_dns_lookups} lookups",
                tags=["email-security", "spf"]
            ))

    score = 0
    max_score = 50
    score_breakdown = []

    if any(f.type == "SPF Record" for f in findings):
        score += 4
        score_breakdown.append("SPF: 4")
    if any(f.type == "DMARC Record" for f in findings):
        score += 4
        score_breakdown.append("DMARC: 4")
    dkim_count = sum(1 for f in findings if f.type == "DKIM Record")
    if dkim_count > 0:
        score += min(dkim_count * 2, 4)
        score_breakdown.append(f"DKIM({dkim_count}): {min(dkim_count*2, 4)}")

    if any("p=reject" in (f.raw_data or "") for f in findings) or any("HardFail" in (f.raw_data or "") for f in findings):
        score += 2
        score_breakdown.append("HardFail/Reject: 2")
    elif any("p=quarantine" in (f.entity or "") for f in findings):
        score += 1
        score_breakdown.append("Quarantine: 1")

    if any(f.type == "MTA-STS Policy" or f.type == "MTA-STS Record (DNS)" for f in findings):
        score += 2
        score_breakdown.append("MTA-STS: 2")
    elif any(f.type == "MTA-STS Record (DNS)" for f in findings):
        score += 1
        score_breakdown.append("MTA-STS(DNS): 1")

    if any(f.type == "TLS-RPT Record" for f in findings):
        score += 2
        score_breakdown.append("TLS-RPT: 2")

    if any(f.type == "BIMI Record" for f in findings):
        score += 2
        score_breakdown.append("BIMI: 2")

    if any(f.type == "SMTP Banner" for f in findings):
        score += 2
        score_breakdown.append("SMTP: 2")

    if any(f.type == "SMTP Banner (Port 465)" for f in findings):
        score += 2
        score_breakdown.append("SMTP465: 2")
    if any(f.type == "SMTP Banner (Port 587)" for f in findings):
        score += 2
        score_breakdown.append("SMTP587: 2")

    if not dnsbl_hits:
        score += 3
        score_breakdown.append("DNSBL(clean): 3")
    elif any(f.type == "DNSBL Listing" for f in findings):
        score += 0
        score_breakdown.append("DNSBL(listed): 0")

    if any(f.type == "DNSSEC Status" and "enabled" in (f.entity or "") for f in findings):
        score += 3
        score_breakdown.append("DNSSEC: 3")
    if any(f.type == "MX Reverse DNS" for f in findings):
        score += 2
        score_breakdown.append("MX rDNS: 2")
    if any(f.type == "MX rDNS Mismatch" for f in findings):
        score -= 1
        score_breakdown.append("rDNS mismatch: -1")
    if any(f.type == "DMARC SPF Alignment" for f in findings):
        score += 2
        score_breakdown.append("SPF align: 2")
    if any(f.type == "DMARC DKIM Alignment" for f in findings):
        score += 2
        score_breakdown.append("DKIM align: 2")
    if any(f.type == "DMARC RUA" for f in findings):
        score += 1
        score_breakdown.append("DMARC RUA: 1")
    if any(f.type == "DMARC RUF" for f in findings):
        score += 1
        score_breakdown.append("DMARC RUF: 1")
    if any(f.type == "SPF Macro Warning" for f in findings):
        score -= 1
        score_breakdown.append("SPF macros: -1")
    if any(f.type == "SPF DNS Lookup Warning" for f in findings):
        score -= 1
        score_breakdown.append("SPF lookups: -1")
    elif any(f.type == "SPF DNS Lookup Exceeded" for f in findings):
        score -= 2
        score_breakdown.append("SPF lookups: -2")

    score_pct = round((score / max_score) * 100)
    risk_level = "Low Risk" if score_pct >= 80 else ("Moderate Risk" if score_pct >= 50 else "High Risk")
    risk_color = "emerald" if score_pct >= 80 else ("orange" if score_pct >= 50 else "red")

    summary_lines = []
    for check in sorted(set(checks_performed)):
        status = "\u2705" if check in checks_passed else "\u274c"
        if check == "DNSBL Check":
            status = "\u2705" if check in checks_passed else "\u26a0\ufe0f"
        summary_lines.append(f"  {status} {check}")

    summary_raw = (
        f"Score: {score}/{max_score} ({score_pct}%)\n"
        f"Breakdown: {' + '.join(score_breakdown)}\n"
        f"Risk: {risk_level}\n"
        f"DKIM selectors found: {len(dkim_found)} ({', '.join(dkim_found) if dkim_found else 'none'})\n"
        f"DNSBL hits: {len(dnsbl_hits)}\n"
        f"Checks:\n" + "\n".join(summary_lines)
    )

    findings.append(IntelligenceFinding(
        entity=f"Email Security Score: {score}/{max_score} ({score_pct}%)",
        type="Email Security Summary",
        source="Email Verifier",
        confidence="High",
        color=risk_color,
        threat_level=risk_level,
        raw_data=summary_raw,
        tags=["email-security", "summary"]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Email Security Overview for {domain}",
        type="Email Security Findings Summary",
        source="Email Verifier",
        confidence="High",
        color=risk_color,
        threat_level=risk_level,
        raw_data=(
            f"Domain: {domain}\n"
            f"Score: {score}/{max_score} ({score_pct}%)\n"
            f"MX: {'+'.join(mx_hosts) if mx_hosts else 'None'}\n"
            f"SPF: {'Present' if has_spf else 'Missing'}\n"
            f"DMARC: {'Present (' + (dmarc_policy or 'unknown') + ')' if has_dmarc else 'Missing'}\n"
            f"DKIM Selectors: {len(dkim_found)} found\n"
            f"MTA-STS: {'Present' if any('MTA-STS' in (f.type or '') for f in findings) else 'Missing'}\n"
            f"TLS-RPT: {'Present' if any('TLS-RPT' in (f.type or '') for f in findings) else 'Missing'}\n"
            f"BIMI: {'Present' if any('BIMI' in (f.type or '') for f in findings) else 'Missing'}\n"
            f"SMTP Reachable: {bool(smtp_banner)}\n"
            f"DNSBL Listings: {len(dnsbl_hits)}\n"
            f"Checks: {len(checks_passed)} passed / {len(checks_failed)} failed"
        ),
        tags=["email-security", "overview"]
    ))

    return findings
