import httpx
import re
import json
from urllib.parse import urlparse
from models import IntelligenceFinding

SPF_MECHANISMS = ["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists", "redirect"]

DMARC_FO_OPTIONS = {
    "0": "Generate reports if all checks fail",
    "1": "Generate reports if any check fails",
    "d": "Generate reports if DKIM fails",
    "s": "Generate reports if SPF fails",
}

DKIM_SELECTORS_COMMON = [
    "default", "google", "dkim", "mail", "selector1", "selector2",
    "s1", "s2", "k1", "k2", "2020", "2021", "2022", "2023", "2024",
    "x", "mx", "email", "zoho", "protonmail", "sendgrid", "mailgun",
    "mandrill", "sparkpost", "postmark", "amazonses", "dkim1", "dkim2",
    "smtp", "smtpapi", "beta", "pm", "mta", "edge", "cname",
]

async def _analyze_spf_deep(domain: str, client: httpx.AsyncClient) -> list:
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
            for ans in answers:
                if ans.get("type") == 16:
                    txt = ans.get("data", "")
                    if txt.startswith("v=spf1"):
                        findings.append(IntelligenceFinding(
                            entity=f"SPF: {txt[:300]}",
                            type="Forensic Email - SPF Record",
                            source="Google DoH",
                            confidence="High", color="slate",
                            status="SPF Found",
                            tags=["forensic", "email", "spf"]
                        ))
                        for mech in SPF_MECHANISMS:
                            matches = re.findall(rf'(?:^|\s)({mech}(?::[^\s]+)?)(?:\s|$)', txt, re.I)
                            for m in matches:
                                mtype = m.split(":")[0].lower()
                                mval = m.split(":", 1)[1] if ":" in m else ""
                                if mtype == "all":
                                    mechanism_type = "HardFail" if m == "-all" else ("SoftFail" if m == "~all" else ("Neutral" if m == "?all" else "PermitAll"))
                                    findings.append(IntelligenceFinding(
                                        entity=f"SPF {mtype}={m} ({mechanism_type})",
                                        type="Forensic Email - SPF All Mechanism",
                                        source="Google DoH",
                                        confidence="High",
                                        color="emerald" if m == "-all" else ("orange" if m == "~all" else "red"),
                                        threat_level="Informational" if m == "-all" else ("Standard Target" if m == "~all" else "High Risk"),
                                        raw_data=f"All mechanism: {m}",
                                        tags=["forensic", "email", "spf", mtype]
                                    ))
                                else:
                                    findings.append(IntelligenceFinding(
                                        entity=f"SPF {mtype}: {mval[:200]}" if mval else f"SPF {mtype}",
                                        type=f"Forensic Email - SPF {mtype.upper()} Mechanism",
                                        source="Google DoH",
                                        confidence="High", color="slate",
                                        raw_data=m,
                                        tags=["forensic", "email", "spf", mtype]
                                    ))
                        spf_redirect = re.search(r'redirect=([\w.]+)', txt)
                        if spf_redirect:
                            redirect_domain = spf_redirect.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"SPF redirect chain to {redirect_domain}",
                                type="Forensic Email - SPF Redirect Chain",
                                source="Google DoH",
                                confidence="High", color="orange",
                                raw_data=f"Redirect to {redirect_domain}",
                                tags=["forensic", "email", "spf", "redirect"]
                            ))
                            try:
                                redir_resp = await client.get(
                                    f"https://dns.google/resolve?name={redirect_domain}&type=TXT",
                                    timeout=10.0,
                                    headers={"Accept": "application/json"}
                                )
                                if redir_resp.status_code == 200:
                                    redir_data = redir_resp.json()
                                    for r_ans in redir_data.get("Answer", []):
                                        if r_ans.get("type") == 16 and r_ans.get("data", "").startswith("v=spf1"):
                                            findings.append(IntelligenceFinding(
                                                entity=f"SPF redirect target: {redirect_domain} -> {r_ans['data'][:200]}",
                                                type="Forensic Email - SPF Redirect Target",
                                                source="Google DoH",
                                                confidence="High", color="slate",
                                                tags=["forensic", "email", "spf", "redirect-target"]
                                            ))
                            except Exception:
                                pass
    except Exception:
        pass
    return findings

async def _analyze_dkim_deep(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    for selector in DKIM_SELECTORS_COMMON:
        try:
            resp = await client.get(
                f"https://dns.google/resolve?name={selector}._domainkey.{domain}&type=TXT",
                timeout=8.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for ans in data.get("Answer", []):
                    if ans.get("type") == 16:
                        dkim_txt = ans.get("data", "")
                        if "v=DKIM1" in dkim_txt or "v=dkim1" in dkim_txt:
                            findings.append(IntelligenceFinding(
                                entity=f"DKIM selector: {selector}",
                                type="Forensic Email - DKIM Selector Found",
                                source="Google DoH",
                                confidence="High", color="emerald",
                                status="DKIM Active",
                                raw_data=f"Selector {selector}: {dkim_txt[:500]}",
                                tags=["forensic", "email", "dkim", f"sel-{selector}"]
                            ))
                            k_match = re.search(r'k=(\w+)', dkim_txt)
                            if k_match:
                                key_type = k_match.group(1)
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM key type: {key_type}",
                                    type="Forensic Email - DKIM Algorithm",
                                    source="Google DoH",
                                    confidence="High", color="slate",
                                    tags=["forensic", "email", "dkim", "algorithm"]
                                ))
                            p_match = re.search(r'p=([A-Za-z0-9+/=]+)', dkim_txt)
                            if p_match:
                                key_data = p_match.group(1)
                                if key_data == "" or len(key_data) < 10:
                                    findings.append(IntelligenceFinding(
                                        entity=f"DKIM key is REVOKED/empty on selector '{selector}'",
                                        type="Forensic Email - DKIM Key Revoked",
                                        source="Google DoH",
                                        confidence="High", color="red",
                                        threat_level="High Risk",
                                        status="Revoked",
                                        raw_data=f"DKIM p field is empty for {selector}",
                                        tags=["forensic", "email", "dkim", "revoked"]
                                    ))
                                else:
                                    key_bits = len(key_data) * 6 // 8
                                    findings.append(IntelligenceFinding(
                                        entity=f"DKIM key size: ~{key_bits} bits",
                                        type="Forensic Email - DKIM Key Strength",
                                        source="Google DoH",
                                        confidence="Medium",
                                        color="emerald" if key_bits >= 2048 else "orange",
                                        threat_level="Informational" if key_bits >= 2048 else "Elevated Risk",
                                        tags=["forensic", "email", "dkim", "key-size"]
                                    ))
                            t_match = re.search(r't=([\w:]+)', dkim_txt)
                            if t_match:
                                flags = t_match.group(1)
                                if "s" in flags:
                                    findings.append(IntelligenceFinding(
                                        entity=f"DKIM flag: t={flags} (strict - subdomains only)",
                                        type="Forensic Email - DKIM Flags",
                                        source="Google DoH",
                                        confidence="High", color="slate",
                                        tags=["forensic", "email", "dkim", "flags"]
                                    ))
                            s_match = re.search(r's=(\w+)', dkim_txt)
                            if s_match:
                                svc_type = s_match.group(1)
                                findings.append(IntelligenceFinding(
                                    entity=f"DKIM service type: {svc_type}",
                                    type="Forensic Email - DKIM Service Type",
                                    source="Google DoH",
                                    confidence="High", color="slate",
                                    tags=["forensic", "email", "dkim", "service"]
                                ))
        except Exception:
            pass
    return findings

async def _analyze_dmarc_deep(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    dmarc_txt = ans.get("data", "")
                    if dmarc_txt.startswith("v=DMARC1"):
                        findings.append(IntelligenceFinding(
                            entity=f"DMARC: {dmarc_txt[:300]}",
                            type="Forensic Email - DMARC Record",
                            source="Google DoH",
                            confidence="High", color="slate",
                            status="DMARC Configured",
                            tags=["forensic", "email", "dmarc"]
                        ))
                        p_match = re.search(r'p=(\w+)', dmarc_txt)
                        if p_match:
                            policy = p_match.group(1)
                            desc_map = {"none": "No enforcement", "quarantine": "Spam folder", "reject": "Reject"}
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC p={policy} ({desc_map.get(policy, 'Unknown')})",
                                type="Forensic Email - DMARC Policy",
                                source="Google DoH",
                                confidence="High",
                                color="emerald" if policy == "reject" else ("orange" if policy == "quarantine" else "red"),
                                threat_level="Informational" if policy == "reject" else ("Standard Target" if policy == "quarantine" else "High Risk"),
                                tags=["forensic", "email", "dmarc", f"p-{policy}"]
                            ))
                        sp_match = re.search(r'sp=(\w+)', dmarc_txt)
                        if sp_match:
                            sub_policy = sp_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC subdomain sp={sub_policy}",
                                type="Forensic Email - DMARC Subdomain Policy",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "dmarc", f"sp-{sub_policy}"]
                            ))
                        fo_match = re.search(r'fo=([\d:]+)', dmarc_txt)
                        if fo_match:
                            fo_val = fo_match.group(1)
                            fo_desc = DMARC_FO_OPTIONS.get(fo_val, "Custom")
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC fo={fo_val} ({fo_desc})",
                                type="Forensic Email - DMARC Forensic Options",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "dmarc", "fo"]
                            ))
                        rf_match = re.search(r'rf=(\w+)', dmarc_txt)
                        if rf_match:
                            rf_val = rf_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC report format: rf={rf_val}",
                                type="Forensic Email - DMARC Report Format",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "dmarc", "rf"]
                            ))
                        ri_match = re.search(r'ri=(\d+)', dmarc_txt)
                        if ri_match:
                            ri_val = ri_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC report interval: {ri_val}s",
                                type="Forensic Email - DMARC Report Interval",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "dmarc", "ri"]
                            ))
                        pct_match = re.search(r'pct=(\d+)', dmarc_txt)
                        if pct_match:
                            pct_val = pct_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC applies to {pct_val}% of email",
                                type="Forensic Email - DMARC Sampling Rate",
                                source="Google DoH",
                                confidence="High",
                                color="emerald" if pct_val == "100" else "orange",
                                raw_data=f"DMARC pct={pct_val}%",
                                tags=["forensic", "email", "dmarc", "pct"]
                            ))
                        rua_match = re.search(r'rua=mailto:([^;\s]+)', dmarc_txt)
                        if rua_match:
                            rua = rua_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC rua: {rua}",
                                type="Forensic Email - DMARC Aggregate Report URI",
                                source="Google DoH",
                                confidence="High", color="orange",
                                tags=["forensic", "email", "dmarc", "rua"]
                            ))
                        ruf_match = re.search(r'ruf=mailto:([^;\s]+)', dmarc_txt)
                        if ruf_match:
                            ruf = ruf_match.group(1)
                            findings.append(IntelligenceFinding(
                                entity=f"DMARC ruf: {ruf}",
                                type="Forensic Email - DMARC Forensic Report URI",
                                source="Google DoH",
                                confidence="High", color="orange",
                                tags=["forensic", "email", "dmarc", "ruf"]
                            ))
    except Exception:
        pass
    return findings

async def _check_mta_sts_tlsrpt(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=_mta-sts.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    txt = ans.get("data", "")
                    if "v=STSv1" in txt:
                        findings.append(IntelligenceFinding(
                            entity=f"MTA-STS: {txt[:300]}",
                            type="Forensic Email - MTA-STS Record",
                            source="Google DoH",
                            confidence="High", color="emerald",
                            status="MTA-STS Configured",
                            tags=["forensic", "email", "mta-sts"]
                        ))
                        id_match = re.search(r'id=(\S+)', txt)
                        if id_match:
                            findings.append(IntelligenceFinding(
                                entity=f"MTA-STS policy ID: {id_match.group(1)}",
                                type="Forensic Email - MTA-STS Policy ID",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "mta-sts", "id"]
                            ))
    except Exception:
        pass
    try:
        resp = await client.get(
            f"https://dns.google/resolve?name=_smtp._tls.{domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    txt = ans.get("data", "")
                    if "v=TLSRPTv1" in txt:
                        findings.append(IntelligenceFinding(
                            entity=f"TLS-RPT: {txt[:300]}",
                            type="Forensic Email - TLS Reporting Record",
                            source="Google DoH",
                            confidence="High", color="emerald",
                            status="TLS-RPT Configured",
                            tags=["forensic", "email", "tls-rpt"]
                        ))
                        rua_tls = re.search(r'rua=mailto:([^;\s]+)', txt)
                        if rua_tls:
                            findings.append(IntelligenceFinding(
                                entity=f"TLS-RPT rua: {rua_tls.group(1)}",
                                type="Forensic Email - TLS Report URI",
                                source="Google DoH",
                                confidence="High", color="slate",
                                tags=["forensic", "email", "tls-rpt", "rua"]
                            ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    spf_findings = await _analyze_spf_deep(domain, client)
    findings.extend(spf_findings)

    dkim_findings = await _analyze_dkim_deep(domain, client)
    findings.extend(dkim_findings)

    dmarc_findings = await _analyze_dmarc_deep(domain, client)
    findings.extend(dmarc_findings)

    mta_findings = await _check_mta_sts_tlsrpt(domain, client)
    findings.extend(mta_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"Forensic Email Analysis complete: {len(findings)} findings",
            type="Forensic Email - Summary",
            source="Forensic Email Analysis",
            confidence="High", color="purple",
            status="Complete",
            tags=["forensic", "email", "summary"]
        ))

    return findings
