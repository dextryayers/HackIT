import httpx
import re
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

SPF_ALL_MECHANISMS = {
    "-all": "HardFail (reject all)",
    "~all": "SoftFail (mark as spam)",
    "+all": "PermitAll (no protection)",
    "?all": "Neutral (no policy)",
}

DMARC_POLICIES = {
    "p=none": "No enforcement (monitoring only)",
    "p=quarantine": "Quarantine (mark as spam)",
    "p=reject": "Reject (hard fail)",
}

DKIM_KEY_SIZES = {1024: "Weak", 2048: "Standard", 4096: "Strong"}

KNOWN_EMAIL_PROVIDERS = {
    "google": "Google Workspace", "googlemail": "Google Workspace",
    "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
    "mail.protection": "Microsoft 365", "zoho": "Zoho Mail",
    "protonmail": "ProtonMail", "yandex": "Yandex Mail",
    "mailgun": "Mailgun", "sendgrid": "SendGrid",
    "fastmail": "FastMail", "rackspace": "Rackspace",
    "icloud": "Apple iCloud", "mx.cloudflare": "Cloudflare Email",
}

async def _analyze_spf(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            spf_records = []
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    if txt.startswith("v=spf"):
                        spf_records.append(txt)
            if spf_records:
                for i, spf in enumerate(spf_records):
                    findings.append(IntelligenceFinding(
                        entity=f"SPF: {spf[:300]}",
                        type="Email Security - SPF Record",
                        source="Passive Email Security",
                        confidence="High",
                        color="slate",
                        status="SPF Configured",
                        raw_data=f"SPF record #{i+1}: {spf}",
                        tags=["email", "spf"]
                    ))
                    for mech, desc in SPF_ALL_MECHANISMS.items():
                        if mech in spf.split():
                            findings.append(IntelligenceFinding(
                                entity=f"SPF {mech}: {desc}",
                                type="Email Security - SPF All Mechanism",
                                source="Passive Email Security",
                                confidence="High",
                                color="emerald" if mech == "-all" else ("orange" if mech == "~all" else "red"),
                                threat_level="Informational" if mech == "-all" else ("Elevated Risk" if mech == "~all" else "High Risk"),
                                status=desc,
                                raw_data=f"SPF all mechanism is {mech}: {desc}",
                                tags=["email", "spf", mech[1:] if mech.startswith("-") or mech.startswith("~") or mech.startswith("+") or mech.startswith("?") else mech]
                            ))
                    includes = re.findall(r'include:([\w.]+)', spf)
                    for inc in includes:
                        findings.append(IntelligenceFinding(
                            entity=f"SPF include: {inc}",
                            type="Email Security - SPF Include Chain",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            status="SPF Include",
                            raw_data=f"Include: {inc}",
                            tags=["email", "spf", "include"]
                        ))
                    ip4_ranges = re.findall(r'ip4:([\d./]+)', spf)
                    for ip_range in ip4_ranges:
                        findings.append(IntelligenceFinding(
                            entity=f"SPF authorized IP: {ip_range}",
                            type="Email Security - SPF IP4 Range",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            raw_data=f"ip4: {ip_range}",
                            tags=["email", "spf", "ip4"]
                        ))
                    redirect = re.search(r'redirect=([\w.]+)', spf)
                    if redirect:
                        findings.append(IntelligenceFinding(
                            entity=f"SPF redirect: {redirect.group(1)}",
                            type="Email Security - SPF Redirect",
                            source="Passive Email Security",
                            confidence="High",
                            color="orange",
                            status="SPF Redirect",
                            raw_data=f"Redirect to {redirect.group(1)}",
                            tags=["email", "spf", "redirect"]
                        ))
                if len(spf_records) > 1:
                    findings.append(IntelligenceFinding(
                        entity=f"{len(spf_records)} SPF records found (should be exactly 1)",
                        type="Email Security - Multiple SPF Records",
                        source="Passive Email Security",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Misconfigured",
                        raw_data=f"Multiple SPF records: {len(spf_records)}",
                        tags=["email", "spf", "misconfiguration"]
                    ))
            else:
                findings.append(IntelligenceFinding(
                    entity="No SPF record configured",
                    type="Email Security - Missing SPF",
                    source="Passive Email Security",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Missing",
                    raw_data="No SPF record found",
                    tags=["email", "spf", "missing"]
                ))
    except Exception:
        pass
    return findings

async def _analyze_dkim(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    common_selectors = ["default", "google", "dkim", "mail", "selector1", "selector2",
                        "s1", "s2", "k1", "k2", "2020", "2021", "2022", "2023", "2024",
                        "x", "mx", "email", "zoho", "protonmail", "sendgrid", "mailgun",
                        "mandrill", "sparkpost", "postmark", "amazonses", "dkim1", "dkim2"]
    for selector in common_selectors:
        try:
            resp = await client.get(
                f"https://dns.google/resolve?name={selector}._domainkey.{domain}&type=TXT",
                timeout=8.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                for ans in answers:
                    if ans.get("type") == 16:
                        dkim_val = ans.get("data", "")
                        if "v=dkim1" in dkim_val.lower() or "v=DKIM1" in dkim_val:
                            findings.append(IntelligenceFinding(
                                entity=f"DKIM selector '{selector}' found",
                                type="Email Security - DKIM Record",
                                source="Passive Email Security",
                                confidence="High",
                                color="emerald",
                                status="DKIM Configured",
                                raw_data=f"DKIM selector: {selector} -> {dkim_val[:500]}",
                                tags=["email", "dkim", f"sel-{selector}"]
                            ))
                            key_size_m = re.search(r'k=(\w+)', dkim_val)
                            if key_size_m:
                                key_type = key_size_m.group(1)
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key type: {key_type}",
                                    type="Email Security - DKIM Key Type",
                                    source="Passive Email Security",
                                    confidence="High",
                                    color="slate",
                                    raw_data=f"DKIM key type for {selector}: {key_type}",
                                    tags=["email", "dkim", "key-type"]
                                ))
                            key_data_m = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_val)
                            if key_data_m:
                                key_b64 = key_data_m.group(1)
                                key_length = len(key_b64) * 6 // 8
                                strength = "Unknown"
                                for ks, label in DKIM_KEY_SIZES.items():
                                    if key_length <= ks + 256 and key_length >= ks - 256:
                                        strength = label
                                        break
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key length: ~{key_length} bits ({strength})",
                                    type="Email Security - DKIM Key Strength",
                                    source="Passive Email Security",
                                    confidence="Medium",
                                    color="emerald" if strength in ("Standard", "Strong") else "orange",
                                    threat_level="Informational" if strength in ("Standard", "Strong") else "Elevated Risk",
                                    raw_data=f"Selector {selector} key length ~{key_length} bits",
                                    tags=["email", "dkim", "key-strength"]
                                ))
        except Exception:
            pass
    return findings

async def _analyze_dmarc(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            dmarc_records = []
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    if txt.startswith("v=dmarc1"):
                        dmarc_records.append(txt)
            if dmarc_records:
                for dmarc in dmarc_records:
                    findings.append(IntelligenceFinding(
                        entity=f"DMARC: {dmarc[:300]}",
                        type="Email Security - DMARC Record",
                        source="Passive Email Security",
                        confidence="High",
                        color="slate",
                        status="DMARC Configured",
                        raw_data=f"DMARC record: {dmarc}",
                        tags=["email", "dmarc"]
                    ))
                    p_match = re.search(r'p=(\w+)', dmarc)
                    if p_match:
                        policy = p_match.group(1)
                        full_policy = DMARC_POLICIES.get(f"p={policy}", f"Unknown ({policy})")
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC policy: p={policy} ({full_policy})",
                            type="Email Security - DMARC Policy",
                            source="Passive Email Security",
                            confidence="High",
                            color="emerald" if policy == "reject" else ("orange" if policy == "quarantine" else "red"),
                            threat_level="Informational" if policy == "reject" else ("Standard Target" if policy == "quarantine" else "High Risk"),
                            status=f"Policy: {policy}",
                            raw_data=f"DMARC p={policy}: {full_policy}",
                            tags=["email", "dmarc", f"p-{policy}"]
                        ))
                    sp_match = re.search(r'sp=(\w+)', dmarc)
                    if sp_match:
                        sp_policy = sp_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC subdomain policy: sp={sp_policy}",
                            type="Email Security - DMARC Subdomain Policy",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            raw_data=f"DMARC sp={sp_policy}",
                            tags=["email", "dmarc", f"sp-{sp_policy}"]
                        ))
                    pct_match = re.search(r'pct=(\d+)', dmarc)
                    if pct_match:
                        pct = pct_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC policy applies to {pct}% of email",
                            type="Email Security - DMARC Sampling",
                            source="Passive Email Security",
                            confidence="High",
                            color="orange" if int(pct) < 100 else "emerald",
                            threat_level="Standard Target" if int(pct) < 100 else "Informational",
                            raw_data=f"DMARC pct={pct}%",
                            tags=["email", "dmarc", "pct"]
                        ))
                    rua_match = re.search(r'rua=mailto:([^;]+)', dmarc)
                    if rua_match:
                        rua = rua_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC reporting (rua): {rua}",
                            type="Email Security - DMARC RUA",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            raw_data=f"DMARC RUA: {rua}",
                            tags=["email", "dmarc", "rua"]
                        ))
                    ruf_match = re.search(r'ruf=mailto:([^;]+)', dmarc)
                    if ruf_match:
                        ruf = ruf_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC forensic reporting (ruf): {ruf}",
                            type="Email Security - DMARC RUF",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            raw_data=f"DMARC RUF: {ruf}",
                            tags=["email", "dmarc", "ruf"]
                        ))
                    fo_match = re.search(r'fo=(\d+)', dmarc)
                    if fo_match:
                        fo = fo_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC forensic options: fo={fo}",
                            type="Email Security - DMARC Forensic Options",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            tags=["email", "dmarc", "fo"]
                        ))
                    ri_match = re.search(r'ri=(\d+)', dmarc)
                    if ri_match:
                        ri = ri_match.group(1)
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC report interval: {ri} seconds",
                            type="Email Security - DMARC Report Interval",
                            source="Passive Email Security",
                            confidence="High",
                            color="slate",
                            tags=["email", "dmarc", "ri"]
                        ))
            else:
                findings.append(IntelligenceFinding(
                    entity="No DMARC record configured",
                    type="Email Security - Missing DMARC",
                    source="Passive Email Security",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Missing",
                    raw_data="No _dmarc.{domain} TXT record found",
                    tags=["email", "dmarc", "missing"]
                ))
    except Exception:
        pass
    return findings

async def _check_bimi(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=default._bimi.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    if "v=bimi1" in txt:
                        findings.append(IntelligenceFinding(
                            entity=f"BIMI: {txt[:300]}",
                            type="Email Security - BIMI Record",
                            source="Passive Email Security",
                            confidence="High",
                            color="emerald",
                            status="BIMI Configured",
                            raw_data=txt,
                            tags=["email", "bimi"]
                        ))
                        logo_match = re.search(r'l=([^;]+)', txt)
                        if logo_match:
                            findings.append(IntelligenceFinding(
                                entity=f"BIMI logo: {logo_match.group(1)}",
                                type="Email Security - BIMI Logo URL",
                                source="Passive Email Security",
                                confidence="High",
                                color="slate",
                                tags=["email", "bimi", "logo"]
                            ))
    except Exception:
        pass
    return findings

async def _check_mta_sts(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "").lower()
                    if "v=sts" in txt:
                        findings.append(IntelligenceFinding(
                            entity=f"MTA-STS: {txt[:300]}",
                            type="Email Security - MTA-STS Record",
                            source="Passive Email Security",
                            confidence="High",
                            color="emerald",
                            status="MTA-STS Configured",
                            raw_data=txt,
                            tags=["email", "mta-sts"]
                        ))
    except Exception:
        pass
    return findings

async def _check_mx_analysis(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name={domain}&type=MX",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            mx_entries = []
            for ans in answers:
                if ans.get("type") == 15:
                    mx_full = ans.get("data", "")
                    mx_parts = mx_full.split()
                    if len(mx_parts) >= 2:
                        priority = mx_parts[0]
                        server = mx_parts[1].rstrip(".")
                        mx_entries.append((int(priority), server))
            mx_entries.sort()
            if mx_entries:
                priorities = [p for p, s in mx_entries]
                findings.append(IntelligenceFinding(
                    entity=f"MX: {len(mx_entries)} servers, priorities {min(priorities)}-{max(priorities)}",
                    type="Email Security - MX Summary",
                    source="Passive Email Security",
                    confidence="High",
                    color="slate",
                    status="MX Servers",
                    raw_data=f"MX entries: {mx_entries}",
                    tags=["email", "mx"]
                ))
                for prio, server in mx_entries[:5]:
                    provider = "Custom/Unknown"
                    for keyword, prov in KNOWN_EMAIL_PROVIDERS.items():
                        if keyword in server.lower():
                            provider = prov
                            break
                    findings.append(IntelligenceFinding(
                        entity=f"MX (prio {prio}): {server}",
                        type=f"Email Security - MX Server: {provider}",
                        source="Passive Email Security",
                        confidence="High",
                        color="slate",
                        raw_data=f"MX priority {prio}: {server}",
                        tags=["email", "mx", provider.lower().replace(" ", "-")]
                    ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    spf_findings = await _analyze_spf(domain, client)
    findings.extend(spf_findings)

    dkim_findings = await _analyze_dkim(domain, client)
    findings.extend(dkim_findings)

    dmarc_findings = await _analyze_dmarc(domain, client)
    findings.extend(dmarc_findings)

    bimi_findings = await _check_bimi(domain, client)
    findings.extend(bimi_findings)

    mta_findings = await _check_mta_sts(domain, client)
    findings.extend(mta_findings)

    mx_findings = await _check_mx_analysis(domain, client)
    findings.extend(mx_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Email Security Assessment complete: {len(findings)} findings",
            type="Email Security - Summary",
            source="Passive Email Security",
            confidence="High", color="purple",
            status="Complete",
            tags=["email", "summary"]
        ))

    return findings
