import asyncio
import dns.resolver
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

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

    dmarc_domain = f"_dmarc.{domain}"
    txt_records = await get_txt(dmarc_domain)
    dmarc_records = [r for r in txt_records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        findings.append(make_finding(
            entity=f"No DMARC record for {domain}",
            ftype="DMARC Record Missing",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="No DMARC",
            raw_data="Missing DMARC means anyone can spoof email from this domain with no detection",
            tags=["dmarc", "missing", "email-security"]
        ))
        findings.append(make_finding(
            entity=f"DMARC domain: {dmarc_domain}",
            ftype="DMARC Domain Check",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Checked",
            tags=["dmarc", "domain"]
        ))
        return findings

    for dmarc in dmarc_records:
        dmarc_clean = dmarc.strip('"')
        findings.append(make_finding(
            entity=dmarc_clean[:300],
            ftype="DMARC Record Raw",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="DMARC Found",
            raw_data=dmarc_clean[:2000],
            tags=["dmarc", "record"]
        ))

        parsed = parse_dmarc(dmarc_clean)
        if not parsed:
            findings.append(make_finding(
                entity=f"Failed to parse DMARC record",
                ftype="DMARC Parse Error",
                source="DNS DMARC Analyzer",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Parse Error",
                tags=["dmarc", "error"]
            ))
            continue

        policy = parsed.get('p', '').lower()
        sp_policy = parsed.get('sp', '').lower()
        pct = parsed.get('pct', '100')
        rua = parsed.get('rua', '')
        ruf = parsed.get('ruf', '')
        adkim = parsed.get('adkim', 'r').lower()
        aspf = parsed.get('aspf', 'r').lower()
        fo = parsed.get('fo', '0')
        rf = parsed.get('rf', 'afrf')
        ri = parsed.get('ri', '86400')

        policy_color = "green" if policy == 'reject' else "orange" if policy == 'quarantine' else "red"
        policy_threat = "Informational" if policy == 'reject' else "Standard Target" if policy == 'quarantine' else "Elevated Risk"
        findings.append(make_finding(
            entity=f"DMARC policy: p={policy} ({'Reject' if policy == 'reject' else 'Quarantine' if policy == 'quarantine' else 'None'})",
            type="DMARC Policy",
            source="DNS DMARC Analyzer",
            confidence="High",
            color=policy_color,
            threat_level=policy_threat,
            status=f"p={policy}",
            raw_data=f"Domain policy determines how receivers handle DMARC-failing email",
            tags=["dmarc", "policy", policy]
        ))

        if sp_policy:
            sp_color = "green" if sp_policy == 'reject' else "orange" if sp_policy == 'quarantine' else "red"
            findings.append(make_finding(
                entity=f"Subdomain policy: sp={sp_policy}",
                ftype="DMARC Subdomain Policy",
                source="DNS DMARC Analyzer",
                confidence="High",
                color=sp_color,
                threat_level="Informational",
                status=f"sp={sp_policy}",
                tags=["dmarc", "subdomain", sp_policy]
            ))
        else:
            findings.append(make_finding(
                entity=f"No subdomain policy (sp=missing, defaults to p={policy})",
                type="DMARC Subdomain Policy",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="Inherited",
                tags=["dmarc", "subdomain"]
            ))

        pct_val = int(pct) if pct.isdigit() else 100
        if pct_val < 100:
            findings.append(make_finding(
                entity=f"DMARC policy applies to {pct_val}% of email (pct={pct})",
                type="DMARC Policy Percentage",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status=f"pct={pct}",
                raw_data=f"Only {pct_val}% of email is subject to DMARC policy",
                tags=["dmarc", "pct"]
            ))
        else:
            findings.append(make_finding(
                entity=f"DMARC applies to 100% of email (pct={pct})",
                type="DMARC Full Coverage",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Full Coverage",
                tags=["dmarc", "pct"]
            ))

        adkim_label = "Strict" if adkim == 's' else "Relaxed"
        findings.append(make_finding(
            entity=f"DKIM alignment: adkim={adkim} ({adkim_label})",
            type="DMARC DKIM Alignment",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="emerald" if adkim == 's' else "slate",
            threat_level="Informational",
            status=adkim_label,
            tags=["dmarc", "adkim", "dkim"]
        ))

        aspf_label = "Strict" if aspf == 's' else "Relaxed"
        findings.append(make_finding(
            entity=f"SPF alignment: aspf={aspf} ({aspf_label})",
            type="DMARC SPF Alignment",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="emerald" if aspf == 's' else "slate",
            threat_level="Informational",
            status=aspf_label,
            tags=["dmarc", "aspf", "spf"]
        ))

        if rua:
            findings.append(make_finding(
                entity=f"RUA (Aggregate Reports): {rua[:200]}",
                type="DMARC Reporting (RUA)",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Reporting Configured",
                raw_data=f"Aggregate report URI: {rua}",
                tags=["dmarc", "rua", "reporting"]
            ))
        else:
            findings.append(make_finding(
                entity=f"No RUA configured - no aggregate reports",
                ftype="DMARC Reporting (RUA)",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="No RUA",
                tags=["dmarc", "rua", "missing"]
            ))

        if ruf:
            findings.append(make_finding(
                entity=f"RUF (Forensic Reports): {ruf[:200]}",
                type="DMARC Forensic Reporting (RUF)",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Forensic Config",
                raw_data=f"Forensic report URI: {ruf}",
                tags=["dmarc", "ruf", "forensic"]
            ))
        else:
            findings.append(make_finding(
                entity=f"No RUF configured - no forensic reports",
                ftype="DMARC Forensic Reporting (RUF)",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="slate",
                threat_level="Informational",
                status="No RUF",
                tags=["dmarc", "ruf"]
            ))

        fo_val = fo
        fo_desc = []
        if '0' in fo_val: fo_desc.append("Generate report if all alignments fail")
        if '1' in fo_val: fo_desc.append("Generate report if any alignment fails")
        if 'd' in fo_val: fo_desc.append("Generate report if DKIM fails")
        if 's' in fo_val: fo_desc.append("Generate report if SPF fails")
        findings.append(make_finding(
            entity=f"FO (Failure Options): {fo_val} - {'; '.join(fo_desc)}",
            type="DMARC Failure Options (FO)",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"fo={fo_val}",
            tags=["dmarc", "fo"]
        ))

        ri_val = ri
        findings.append(make_finding(
            entity=f"Report interval: {ri_val}s ({int(ri_val)//3600}h)",
            type="DMARC Report Interval",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"ri={ri_val}",
            tags=["dmarc", "ri"]
        ))

        rf_val = rf
        findings.append(make_finding(
            entity=f"Report format: {rf_val}",
            ftype="DMARC Report Format",
            source="DNS DMARC Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status=f"rf={rf_val}",
            tags=["dmarc", "rf"]
        ))

        if policy == 'none':
            findings.append(make_finding(
                entity=f"DMARC policy is 'none' - domain is NOT protected from spoofing!",
                ftype="DMARC Protection Level",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Not Protected",
                tags=["dmarc", "none", "unprotected"]
            ))
        elif policy == 'quarantine':
            findings.append(make_finding(
                entity=f"DMARC policy is 'quarantine' - spoofed email sent to spam",
                ftype="DMARC Protection Level",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="Quarantine Only",
                tags=["dmarc", "quarantine"]
            ))
        else:
            findings.append(make_finding(
                entity=f"DMARC policy is 'reject' - domain is protected against spoofing",
                ftype="DMARC Protection Level",
                source="DNS DMARC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Protected",
                tags=["dmarc", "reject", "protected"]
            ))

        dmarc_check = check_dmarc_failures(policy, sp_policy, rua, ruf, pct_val, adkim, aspf)
        for check in dmarc_check:
            findings.append(make_finding(
                entity=check['msg'],
                ftype="DMARC Compliance Issue",
                source="DNS DMARC Analyzer",
                confidence=check['confidence'],
                color=check['color'],
                threat_level=check['threat'],
                status=check['status'],
                tags=["dmarc", "compliance"]
            ))

    findings.append(make_finding(
        entity=f"DMARC analysis complete for {domain}",
        ftype="DMARC Analysis Summary",
        source="DNS DMARC Analyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["dmarc", "summary"]
    ))

    return findings

def parse_dmarc(record: str):
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

def check_dmarc_failures(policy, sp_policy, rua, ruf, pct, adkim, aspf):
    issues = []
    if policy == 'none':
        issues.append({
            'msg': 'Consider upgrading DMARC policy from "none" to "quarantine" then "reject"',
            'confidence': 'High', 'color': 'orange', 'threat': 'Standard Target', 'status': 'Recommendation'
        })
    if not rua:
        issues.append({
            'msg': 'Add rua tag to receive DMARC aggregate reports for visibility',
            'confidence': 'Medium', 'color': 'orange', 'threat': 'Informational', 'status': 'Recommendation'
        })
    if pct < 100 and policy != 'none':
        issues.append({
            'msg': f'Increase pct from {pct}% to 100% for full protection',
            'confidence': 'High', 'color': 'orange', 'threat': 'Standard Target', 'status': 'Recommendation'
        })
    return issues
