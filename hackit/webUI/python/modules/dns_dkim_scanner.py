import asyncio
import dns.resolver
import re
from models import IntelligenceFinding

DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "dkim", "mx", "selector1", "selector2",
    "s1", "s2", "smtp", "email", "support", "admin", "noreply", "reply",
    "outbound", "inbound", "transactional", "bulk", "marketing", "newsletter",
    "notification", "no-reply", "info", "contact", "sales", "billing",
    "account", "security", "abuse", "postmaster", "hostmaster", "webmaster",
    "zoho", "protonmail", "proton", "mailgun", "sendgrid", "mandrill",
    "sparkpost", "postmark", "amazonses", "ses", "aws", "azure",
    "dkim._domainkey", "dkim1", "dkim2", "dkim3", "dkim2018", "dkim2020",
    "dkim2023", "dkim2024", "eig", "eig1", "eig2", "mta", "mta1", "mta2",
    "pm", "pm1", "pm2", "pm3", "zmail", "ymail", "rocketmail",
    "ems", "ems1", "ems2", "x", "x1", "x2", "y", "y1", "y2",
    "z", "z1", "z2", "a", "b", "c", "d", "e", "f", "g", "h",
    "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z", "alpha", "beta", "gamma", "delta",
    "primary", "secondary", "main", "backup", "alt", "extra",
    "hosted", "managed", "cloud", "saas", "paas",
    "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "jan2023", "feb2023", "mar2023", "jan2024", "feb2024",
    "q1", "q2", "q3", "q4", "q12023", "q22023", "q12024",
    "v1", "v2", "v3", "ver1", "ver2", "ver3",
    "ed25519", "rsa", "rsa1", "rsa2", "ecdsa", "ecdsa1",
    "dkim-rsa", "dkim-ed25519", "dkim-sha256",
    "staging", "test", "dev", "prod", "production",
    "cpanel", "whm", "directadmin", "plesk",
    "gmail", "yahoo", "outlook", "hotmail", "live", "msn",
    "exchange", "office365", "o365", "microsoft", "microsoftonline",
    "googlemail", "aspmx", "mx1", "mx2", "mail1", "mail2",
    "mailgun1", "mailgun2", "sg", "sg1", "sendgrid1", "sendgrid2",
    "sp", "sp1", "sp2", "pm", "pm1", "pm2", "zohomail",
    "protonmail1", "protonmail2", "fastmail", "fastmail1",
    "titan", "titan1", "migadu", "mxroute", "namecheap",
    "godaddy", "secureserver", "cloudflare", "cloudflare1",
    "yandex", "yandex1", "rambler", "mailru",
    "heirloom", "dyn", "networksolutions", "register",
    "domainkey", "dkim._domainkey.default", "_domainkey",
    "dkim-live", "dkim-test", "selector", "s",
    "dkimselector", "dkim-selector", "key", "key1", "key2",
    "pubkey", "publickey", "dkimkey", "dkim-key",
    "dkim01", "dkim02", "dkim03", "dkim04", "dkim05",
    "dkim001", "dkim002", "dkim003",
    "smtp-out", "smtp-in", "out", "in", "relay",
    "ems", "emailsecurity", "email-secure",
    "mxv", "mxv1", "mxv2",
    "dkim._domainkey.mx",
    "google._domainkey", "mail._domainkey",
    "default._domainkey", "dkim._domainkey",
    "proton._domainkey", "zoho._domainkey",
    "sendgrid._domainkey", "mailgun._domainkey",
    "postmark._domainkey", "sparkpost._domainkey",
    "amazonses._domainkey", "ses._domainkey",
    "fastmail._domainkey", "titan._domainkey",
    "yandex._domainkey", "outlook._domainkey",
    "office365._domainkey", "exchange._domainkey",
    "godaddy._domainkey", "namecheap._domainkey",
    "cloudflare._domainkey", "secureserver._domainkey",
]

async def get_txt(domain: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        return [str(r) for r in answers]
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    found_selectors = []
    total_tested = 0

    batch_size = 50
    for i in range(0, len(DKIM_SELECTORS), batch_size):
        batch = DKIM_SELECTORS[i:i+batch_size]
        tasks = []
        for selector in batch:
            dkim_domain = f"{selector}._domainkey.{domain}"
            tasks.append(get_txt(dkim_domain))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for selector, records in zip(batch, results):
            total_tested += 1
            if isinstance(records, list) and records:
                dkim_domain = f"{selector}._domainkey.{domain}"
                found_selectors.append((selector, records))

    for selector, records in found_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        for record in records:
            findings.append(IntelligenceFinding(
                entity=f"{selector}._domainkey.{domain}",
                type="DKIM Record Found",
                source="DNS DKIM Scanner",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Active",
                resolution=record[:300],
                raw_data=record[:2000],
                tags=["dkim", "selector", selector]
            ))

            parsed = parse_dkim_record(record)
            if parsed:
                key_type = parsed.get('k', 'rsa')
                key_data = parsed.get('p', '')
                service = parsed.get('s', '*')
                flags = parsed.get('t', '')
                hash_algo = parsed.get('h', 'sha256')

                findings.append(IntelligenceFinding(
                    entity=f"DKIM key type: {key_type}, hash: {hash_algo}, service: {service}",
                    type="DKIM Key Parameters",
                    source="DNS DKIM Scanner",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Parsed",
                    resolution=dkim_domain,
                    tags=["dkim", "key-type", key_type]
                ))

                if key_type.lower() == 'ed25519':
                    findings.append(IntelligenceFinding(
                        entity=f"Modern ED25519 key on {selector}",
                        type="DKIM Modern Algorithm",
                        source="DNS DKIM Scanner",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="Modern",
                        resolution=dkim_domain,
                        tags=["dkim", "ed25519", "modern"]
                    ))

                if key_data:
                    try:
                        import base64
                        key_bytes = base64.b64decode(key_data)
                        key_bits = len(key_bytes) * 8
                        if key_type.lower() == 'rsa':
                            if key_bits < 1024:
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key size: {key_bits} bits (WEAK - below 1024)",
                                    type="DKIM Key Size Warning",
                                    source="DNS DKIM Scanner",
                                    confidence="High",
                                    color="red",
                                    threat_level="Elevated Risk",
                                    status="Weak Key",
                                    resolution=dkim_domain,
                                    raw_data=f"Key size {key_bits} bits is below recommended minimum of 1024",
                                    tags=["dkim", "key-size", "weak"]
                                ))
                            elif key_bits < 2048:
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key size: {key_bits} bits (acceptable, 2048+ recommended)",
                                    type="DKIM Key Size",
                                    source="DNS DKIM Scanner",
                                    confidence="High",
                                    color="orange",
                                    threat_level="Informational",
                                    status="Acceptable",
                                    resolution=dkim_domain,
                                    tags=["dkim", "key-size"]
                                ))
                            else:
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key size: {key_bits} bits (strong)",
                                    type="DKIM Key Size",
                                    source="DNS DKIM Scanner",
                                    confidence="High",
                                    color="emerald",
                                    threat_level="Informational",
                                    status="Strong Key",
                                    resolution=dkim_domain,
                                    tags=["dkim", "key-size", "strong"]
                                ))
                    except:
                        pass

                if 'y' in flags:
                    findings.append(IntelligenceFinding(
                        entity=f"DKIM key with t=y (testing mode) on {selector}",
                        type="DKIM Testing Mode",
                        source="DNS DKIM Scanner",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        status="Testing Mode",
                        resolution=dkim_domain,
                        tags=["dkim", "testing"]
                    ))

                if service and service != '*':
                    findings.append(IntelligenceFinding(
                        entity=f"DKIM service type: {service} on {selector}",
                        type="DKIM Service Type",
                        source="DNS DKIM Scanner",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        status="Service Defined",
                        resolution=dkim_domain,
                        tags=["dkim", "service", service]
                    ))

    if found_selectors:
        selectors_list = [s for s, _ in found_selectors]
        findings.append(IntelligenceFinding(
            entity=f"Found {len(found_selectors)} DKIM selector(s): {', '.join(selectors_list)}",
            type="DKIM Discovery Summary",
            source="DNS DKIM Scanner",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status=f"{len(found_selectors)} Selectors",
            raw_data=f"Total tested: {total_tested} | Found: {len(found_selectors)} | Selectors: {', '.join(selectors_list)}",
            tags=["dkim", "summary"]
        ))

        provider = identify_dkim_provider(found_selectors)
        if provider:
            findings.append(IntelligenceFinding(
                entity=f"DKIM provider detected: {provider}",
                type="DKIM Provider Detection",
                source="DNS DKIM Scanner",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Detected",
                tags=["dkim", "provider", provider.lower().replace(" ", "-")]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No DKIM records found among {total_tested} selectors for {domain}",
            type="DKIM Discovery Summary",
            source="DNS DKIM Scanner",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            status="No DKIM",
            raw_data=f"Tested {total_tested} common DKIM selectors, none found",
            tags=["dkim", "missing"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"DKIM scan: tested {total_tested} selectors, found {len(found_selectors)} active",
        type="DKIM Scan Summary",
        source="DNS DKIM Scanner",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["dkim", "summary"]
    ))

    return findings

def parse_dkim_record(record: str):
    try:
        record = record.strip('"').strip("'")
        parts = record.split(';')
        result = {}
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                result[key.strip().lower()] = value.strip()
        return result
    except:
        return None

def identify_dkim_provider(found_selectors):
    selectors = [s.lower() for s, _ in found_selectors]
    selectors_str = " ".join(selectors)
    provider_map = {
        "Google Workspace / Gmail": ["google"],
        "Microsoft / Office 365": ["selector1", "selector2", "exchange", "office365", "o365", "microsoftonline"],
        "Zoho Mail": ["zoho"],
        "ProtonMail": ["protonmail", "proton"],
        "Mailgun": ["mailgun"],
        "SendGrid": ["sendgrid", "sg"],
        "Amazon SES": ["amazonses", "ses"],
        "FastMail": ["fastmail"],
        "Titan Email": ["titan"],
        "Yandex Mail": ["yandex"],
        "GoDaddy": ["godaddy", "secureserver"],
        "Namecheap": ["namecheap"],
        "Cloudflare": ["cloudflare"],
        "Postmark": ["postmark"],
        "SparkPost": ["sparkpost"],
        "MXRoute": ["mxroute"],
        "Migadu": ["migadu"],
    }
    for provider, sigs in provider_map.items():
        if any(s in selectors_str for s in sigs):
            return provider
    if len(found_selectors) <= 2:
        return "Custom/In-house DKIM"
    return "Multiple Providers"
