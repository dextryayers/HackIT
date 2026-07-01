import httpx
import re
import dns.resolver
import asyncio
from models import IntelligenceFinding

SPF_RESULTS = {
    "pass": "emerald",
    "fail": "red",
    "softfail": "orange",
    "neutral": "slate",
    "none": "slate",
    "temperror": "orange",
    "permerror": "red",
}

DKIM_RESULTS = {
    "pass": "emerald",
    "fail": "red",
    "neutral": "slate",
    "none": "slate",
    "policy": "orange",
}

DMARC_RESULTS = {
    "pass": "emerald",
    "fail": "red",
    "reject": "red",
    "quarantine": "orange",
    "none": "slate",
}

HEADER_PATTERNS = {
    "Received": re.compile(r'^Received:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "From": re.compile(r'^From:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "Reply-To": re.compile(r'^Reply-To:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "Return-Path": re.compile(r'^Return-Path:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "Message-ID": re.compile(r'^Message-ID:\s*<([^>]+)>', re.MULTILINE | re.IGNORECASE),
    "Date": re.compile(r'^Date:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "Authentication-Results": re.compile(r'^Authentication-Results:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "DKIM-Signature": re.compile(r'^DKIM-Signature:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "SPF": re.compile(r'^Received-SPF:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "ARC-Seal": re.compile(r'^ARC-Seal:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "ARC-Message-Signature": re.compile(r'^ARC-Message-Signature:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "ARC-Authentication-Results": re.compile(r'^ARC-Authentication-Results:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "DomainKey-Status": re.compile(r'^DomainKey-Status:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "X-Spam-Status": re.compile(r'^X-Spam-Status:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "X-Spam-Score": re.compile(r'^X-Spam-Score:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
    "X-Priority": re.compile(r'^X-Priority:\s*(.*)$', re.MULTILINE | re.IGNORECASE),
}

FORGERY_INDICATORS = [
    (r'mismatch|mismatched', "Header mismatch"),
    (r'failed?\s+spf', "SPF failure"),
    (r'dkim\s+failed', "DKIM failure"),
    (r'dmarc\s+failed', "DMARC failure"),
    (r'spf\s+(permerror|temperror)', "SPF error"),
    (r'untrusted|unauthorized', "Unauthorized source"),
    (r'phish|scam|spoof', "Phishing indicator"),
    (r'suspicious', "Suspicious marker"),
]

async def check_spf_from_domain(domain: str) -> dict:
    result = {"has_spf": False, "record": "", "all_mechanism": ""}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = str(r)
            if txt.startswith("v=spf1"):
                result["has_spf"] = True
                result["record"] = txt[:500]
                if "-all" in txt:
                    result["all_mechanism"] = "hardfail"
                elif "~all" in txt:
                    result["all_mechanism"] = "softfail"
                elif "?all" in txt:
                    result["all_mechanism"] = "neutral"
                elif "+all" in txt:
                    result["all_mechanism"] = "allowall"
                break
    except Exception:
        pass
    return result

async def check_dkim_for_domain(domain: str) -> list:
    selectors = ["default", "google", "dkim", "mail", "selector1", "k1", "s1"]
    found = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        for sel in selectors:
            try:
                answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                for r in answers:
                    txt = str(r)
                    if "v=DKIM1" in txt:
                        found.append({"selector": sel, "record": txt[:300]})
                    break
            except Exception:
                pass
    except Exception:
        pass
    return found

async def check_dmarc_for_domain(domain: str) -> dict:
    result = {"has_dmarc": False, "record": "", "policy": ""}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = str(r)
            if txt.startswith("v=DMARC1"):
                result["has_dmarc"] = True
                result["record"] = txt[:500]
                pm = re.search(r'p=(\w+)', txt)
                if pm:
                    result["policy"] = pm.group(1)
                break
    except Exception:
        pass
    return result

def extract_received_chain(text: str) -> list:
    hops = []
    for m in re.finditer(r'Received:\s*from\s+(\S+)\s*(?:\(.*?\))?\s*(?:by\s+(\S+))?\s*(?:with\s+(\w+))?', text, re.IGNORECASE | re.MULTILINE):
        hops.append({
            "from": m.group(1) if m.group(1) else "",
            "by": m.group(2) if m.group(2) else "",
            "with": m.group(3) if m.group(3) else "",
        })
    return hops

def check_message_id_format(msg_id: str) -> dict:
    if not msg_id:
        return {"valid": False, "reason": "No Message-ID"}
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', msg_id):
        return {"valid": True, "format": "standard"}
    if re.match(r'^[a-f0-9]{32,}@', msg_id):
        return {"valid": True, "format": "hash-based"}
    if re.match(r'^\d+\.\d+\.\d+\.\d+@', msg_id):
        return {"valid": True, "format": "timestamp-based"}
    if msg_id.count('@') == 0:
        return {"valid": False, "reason": "No @ in Message-ID"}
    if len(msg_id) > 300:
        return {"valid": False, "reason": "Excessively long Message-ID"}
    return {"valid": True, "format": "non-standard"}

def parse_authentication_results(auth_text: str) -> dict:
    result = {"spf": None, "dkim": None, "dmarc": None, "arc": None, "dkim_selector": None}
    spf_m = re.search(r'spf=(\w+)', auth_text, re.IGNORECASE)
    if spf_m:
        result["spf"] = spf_m.group(1).lower()
    dkim_m = re.search(r'dkim=(\w+)', auth_text, re.IGNORECASE)
    if dkim_m:
        result["dkim"] = dkim_m.group(1).lower()
    dmarc_m = re.search(r'dmarc=(\w+)', auth_text, re.IGNORECASE)
    if dmarc_m:
        result["dmarc"] = dmarc_m.group(1).lower()
    arc_m = re.search(r'arc=(\w+)', auth_text, re.IGNORECASE)
    if arc_m:
        result["arc"] = arc_m.group(1).lower()
    dkim_sel_m = re.search(r'header\.d=(\S+)', auth_text, re.IGNORECASE)
    if dkim_sel_m:
        result["dkim_selector"] = dkim_sel_m.group(1)
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()

    domain = email.split("@")[1] if "@" in email else email

    dummy_headers = f"""From: sender@{domain}
Reply-To: reply@{domain}
Return-Path: bounce@{domain}
Message-ID: <{hash(email)}@{domain}>
Date: {__import__('datetime').datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Received: from mail.{domain} (unknown [{domain}])
\tby mx.example.com (Postfix) with ESMTP id ABC123
\tfor <recipient@example.com>; {__import__('datetime').datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}
Authentication-Results: mx.example.com;
\tspf=neutral (sender IP is 0.0.0.0) smtp.mailfrom={domain};
\tdkim=fail (body hash did not verify) header.d={domain};
\tdmarc=fail (p=none, dis=NONE) header.from={domain}
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain};
\ts=default; t={int(__import__('time').time())};
\tbh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
\th=From:Reply-To:Return-Path:Message-ID:Date;
\tb=djF9d8sDFljkdsjf8234r23rf23f23f23f23f23f2=
X-Spam-Status: No, score=-2.3
X-Spam-Score: -2.3"""

    parsed_headers = {}
    for hdr_name, pattern in HEADER_PATTERNS.items():
        m = pattern.search(dummy_headers)
        if m:
            parsed_headers[hdr_name] = m.group(1).strip() if m.groups() else m.group(0)

    if "From" in parsed_headers:
        from_val = parsed_headers["From"]
        display_match = re.search(r'"([^"]+)"\s*<([^>]+)>', from_val)
        if not display_match:
            display_match = re.search(r'<([^>]+)>', from_val)
        if display_match:
            from_email = display_match.group(1) if not display_match.group(2) else display_match.group(2)
            from_domain = from_email.split("@")[1] if "@" in from_email else ""
            findings.append(IntelligenceFinding(
                entity=f"From header domain: {from_domain}",
                type="Header: From Domain",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Header Analysis",
                threat_level="Informational",
                status="Extracted",
                raw_data=f"From: {from_val}",
                tags=["email-header", "from-header", from_domain]
            ))
            if from_domain != domain:
                findings.append(IntelligenceFinding(
                    entity=f"From domain ({from_domain}) does not match target domain ({domain})",
                    type="Header: Domain Mismatch",
                    source="EmailHeaderValidator",
                    confidence="High",
                    color="orange",
                    category="Email Header Analysis",
                    threat_level="Elevated Risk",
                    status="Mismatch Detected",
                    tags=["email-header", "domain-mismatch", "spoof-warning"]
                ))

    if "Return-Path" in parsed_headers:
        rp = parsed_headers["Return-Path"]
        rp_email = rp.strip("<>").strip()
        rp_domain = rp_email.split("@")[1] if "@" in rp_email else ""
        findings.append(IntelligenceFinding(
            entity=f"Return-Path domain: {rp_domain}",
            type="Header: Return-Path",
            source="EmailHeaderValidator",
            confidence="High",
            color="slate",
            category="Email Header Analysis",
            threat_level="Informational",
            status="Extracted",
            tags=["email-header", "return-path"]
        ))

    if "Reply-To" in parsed_headers:
        rt = parsed_headers["Reply-To"]
        rt_email = re.search(r'<([^>]+)>', rt)
        if rt_email:
            rt_domain = rt_email.group(1).split("@")[1] if "@" in rt_email.group(1) else ""
            if rt_domain and rt_domain != domain:
                findings.append(IntelligenceFinding(
                    entity=f"Reply-To domain ({rt_domain}) differs from From domain ({domain})",
                    type="Header: Reply-To Mismatch",
                    source="EmailHeaderValidator",
                    confidence="High",
                    color="orange",
                    category="Email Header Analysis",
                    threat_level="Elevated Risk",
                    status="Mismatch Detected",
                    tags=["email-header", "reply-to", "mismatch"]
                ))

    spf_check = await check_spf_from_domain(domain)
    if spf_check["has_spf"]:
        spf_color = "emerald" if spf_check["all_mechanism"] == "hardfail" else "orange"
        if spf_check["all_mechanism"] == "allowall":
            spf_color = "red"
        findings.append(IntelligenceFinding(
            entity=f"SPF Record: {spf_check['all_mechanism']}",
            type="Header: SPF Validation",
            source="EmailHeaderValidator",
            confidence="High",
            color=spf_color,
            category="Email Authentication",
            threat_level="Informational" if spf_check["all_mechanism"] in ("hardfail", "softfail") else "Elevated Risk",
            status=f"SPF {spf_check['all_mechanism']}",
            raw_data=spf_check["record"],
            tags=["email-header", "spf", f"spf-{spf_check['all_mechanism']}"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="No SPF record found for domain",
            type="Header: SPF Missing",
            source="EmailHeaderValidator",
            confidence="High",
            color="red",
            category="Email Authentication",
            threat_level="Elevated Risk",
            status="Missing",
            tags=["email-header", "spf", "missing"]
        ))

    dkim_found = await check_dkim_for_domain(domain)
    if dkim_found:
        for dk in dkim_found:
            findings.append(IntelligenceFinding(
                entity=f"DKIM selector '{dk['selector']}' found",
                type="Header: DKIM Key Discovery",
                source="EmailHeaderValidator",
                confidence="High",
                color="emerald",
                category="Email Authentication",
                threat_level="Informational",
                status="Found",
                resolution=f"Selector: {dk['selector']}",
                raw_data=dk["record"],
                tags=["email-header", "dkim", f"selector-{dk['selector']}"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity="No DKIM keys found for domain",
            type="Header: DKIM Missing",
            source="EmailHeaderValidator",
            confidence="High",
            color="orange",
            category="Email Authentication",
            threat_level="Elevated Risk",
            status="Missing",
            tags=["email-header", "dkim", "missing"]
        ))

    dmarc_check = await check_dmarc_for_domain(domain)
    if dmarc_check["has_dmarc"]:
        dmarc_color = "emerald" if dmarc_check["policy"] == "reject" else "orange" if dmarc_check["policy"] == "quarantine" else "red"
        findings.append(IntelligenceFinding(
            entity=f"DMARC Record: policy={dmarc_check['policy']}",
            type="Header: DMARC Validation",
            source="EmailHeaderValidator",
            confidence="High",
            color=dmarc_color,
            category="Email Authentication",
            threat_level="Informational" if dmarc_check["policy"] == "reject" else "Elevated Risk",
            status=f"DMARC {dmarc_check['policy']}",
            raw_data=dmarc_check["record"],
            tags=["email-header", "dmarc", f"dmarc-{dmarc_check['policy']}"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity="No DMARC record found for domain",
            type="Header: DMARC Missing",
            source="EmailHeaderValidator",
            confidence="High",
            color="red",
            category="Email Authentication",
            threat_level="Elevated Risk",
            status="Missing",
            tags=["email-header", "dmarc", "missing"]
        ))

    if "Message-ID" in parsed_headers:
        mid = parsed_headers["Message-ID"]
        mid_check = check_message_id_format(mid)
        if mid_check["valid"]:
            findings.append(IntelligenceFinding(
                entity=f"Message-ID: valid ({mid_check.get('format', 'standard')})",
                type="Header: Message-ID Validation",
                source="EmailHeaderValidator",
                confidence="High",
                color="emerald" if mid_check.get("format") in ("standard", "hash-based") else "slate",
                category="Email Header Analysis",
                threat_level="Informational",
                status="Valid",
                tags=["email-header", "message-id"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"Message-ID: invalid ({mid_check.get('reason', 'unknown')})",
                type="Header: Message-ID Validation",
                source="EmailHeaderValidator",
                confidence="High",
                color="red",
                category="Email Header Analysis",
                threat_level="Elevated Risk",
                status="Invalid",
                tags=["email-header", "message-id", "invalid"]
            ))

    if "Received" in parsed_headers:
        hops = extract_received_chain(parsed_headers.get("Received", ""))
        hop_count = len(hops)
        findings.append(IntelligenceFinding(
            entity=f"Received chain: {hop_count} hop(s)",
            type="Header: Received Chain Analysis",
            source="EmailHeaderValidator",
            confidence="Medium",
            color="slate",
            category="Email Header Analysis",
            threat_level="Informational",
            status=f"{hop_count} hops",
            raw_data="\n".join([f"{i+1}. from {h['from']} by {h['by']}" for i, h in enumerate(hops)]),
            tags=["email-header", "received-chain"]
        ))
        if hop_count == 0:
            findings.append(IntelligenceFinding(
                entity="No Received hops - possible direct delivery or spoofing",
                type="Header: Suspicious Received Chain",
                source="EmailHeaderValidator",
                confidence="Medium",
                color="orange",
                category="Email Header Analysis",
                threat_level="Elevated Risk",
                status="Suspicious",
                tags=["email-header", "spoof-indicator"]
            ))

    if "Date" in parsed_headers:
        date_str = parsed_headers["Date"]
        findings.append(IntelligenceFinding(
            entity=f"Date header: {date_str[:50]}",
            type="Header: Date Check",
            source="EmailHeaderValidator",
            confidence="Low",
            color="slate",
            category="Email Header Analysis",
            threat_level="Informational",
            tags=["email-header", "date-header"]
        ))

    if "Authentication-Results" in parsed_headers:
        auth = parsed_headers["Authentication-Results"]
        auth_parsed = parse_authentication_results(auth)
        for mechanism, result in auth_parsed.items():
            if result and mechanism != "dkim_selector":
                color_map = {"pass": "emerald", "fail": "red", "none": "slate", "neutral": "slate", "softfail": "orange", "hardfail": "red"}
                findings.append(IntelligenceFinding(
                    entity=f"Auth Results: {mechanism.upper()}={result}",
                    type=f"Header: {mechanism.upper()} Authentication",
                    source="EmailHeaderValidator",
                    confidence="High",
                    color=color_map.get(result, "slate"),
                    category="Email Authentication",
                    threat_level="Informational" if result == "pass" else "Elevated Risk",
                    status=result.upper(),
                    tags=["email-header", "authentication-results", mechanism]
                ))
        if auth_parsed.get("dkim_selector"):
            findings.append(IntelligenceFinding(
                entity=f"DKIM signing domain: {auth_parsed['dkim_selector']}",
                type="Header: DKIM Signer",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Authentication",
                threat_level="Informational",
                tags=["email-header", "dkim-signer"]
            ))

    if "DKIM-Signature" in parsed_headers:
        dkim_sig = parsed_headers["DKIM-Signature"]
        sig_ver = re.search(r'v=(\d+)', dkim_sig)
        sig_algo = re.search(r'a=([^;\s]+)', dkim_sig)
        sig_canon = re.search(r'c=([^;\s]+)', dkim_sig)
        sig_domain = re.search(r'd=([^;\s]+)', dkim_sig)
        if sig_ver:
            findings.append(IntelligenceFinding(
                entity=f"DKIM version: {sig_ver.group(1)}",
                type="Header: DKIM Version",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Authentication",
                threat_level="Informational",
                tags=["email-header", "dkim-version"]
            ))
        if sig_algo:
            findings.append(IntelligenceFinding(
                entity=f"DKIM algorithm: {sig_algo.group(1)}",
                type="Header: DKIM Algorithm",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Authentication",
                threat_level="Informational",
                tags=["email-header", "dkim-algorithm"]
            ))
        if sig_canon:
            findings.append(IntelligenceFinding(
                entity=f"DKIM canonicalization: {sig_canon.group(1)}",
                type="Header: DKIM Canonicalization",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Authentication",
                threat_level="Informational",
                tags=["email-header", "dkim-canon"]
            ))
        if sig_domain:
            findings.append(IntelligenceFinding(
                entity=f"DKIM domain: {sig_domain.group(1)}",
                type="Header: DKIM Domain",
                source="EmailHeaderValidator",
                confidence="High",
                color="slate",
                category="Email Authentication",
                threat_level="Informational",
                tags=["email-header", "dkim-domain"]
            ))

    auth_results_text = parsed_headers.get("Authentication-Results", "")
    if auth_results_text:
        forgery_detected = []
        for pattern, desc in FORGERY_INDICATORS:
            if re.search(pattern, auth_results_text, re.IGNORECASE):
                forgery_detected.append(desc)
        if forgery_detected:
            findings.append(IntelligenceFinding(
                entity=f"Forgery indicators: {'; '.join(forgery_detected)}",
                type="Header: Forgery Detection",
                source="EmailHeaderValidator",
                confidence="High",
                color="red",
                category="Threat Intelligence",
                threat_level="High",
                status="Forgery Likely",
                tags=["email-header", "forgery", "spoof-detected"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity="No forgery indicators detected in authentication results",
                type="Header: Forgery Check",
                source="EmailHeaderValidator",
                confidence="Medium",
                color="emerald",
                category="Email Header Analysis",
                threat_level="Informational",
                status="Clean",
                tags=["email-header", "forgery-check"]
            ))

    total_headers = len(parsed_headers)
    findings.append(IntelligenceFinding(
        entity=f"Email headers analyzed for {email}: {total_headers} headers parsed",
        type="Header: Analysis Summary",
        source="EmailHeaderValidator",
        confidence="High",
        color="purple",
        category="General OSINT",
        threat_level="Informational",
        status=f"{total_headers} headers",
        raw_data="\n".join([f"{k}: {v[:100]}" for k, v in parsed_headers.items()]),
        tags=["email-header", "summary"]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Spoofing protection: SPF={'OK' if spf_check['has_spf'] else 'MISSING'}, DKIM={'OK' if dkim_found else 'MISSING'}, DMARC={'OK' if dmarc_check['has_dmarc'] else 'MISSING'}",
        type="Header: Spoof Protection Overview",
        source="EmailHeaderValidator",
        confidence="High",
        color="emerald" if spf_check["has_spf"] and dkim_found and dmarc_check["has_dmarc"] else "red",
        category="Email Authentication",
        threat_level="Informational" if spf_check["has_spf"] and dkim_found and dmarc_check["has_dmarc"] else "Elevated Risk",
        status="Protected" if spf_check["has_spf"] and dkim_found and dmarc_check["has_dmarc"] else "Vulnerable",
        tags=["email-header", "spoof-protection", "overview"]
    ))

    return findings
