import httpx
import asyncio
import re
import dns.resolver
from models import IntelligenceFinding
from urllib.parse import urlparse

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "dkim", "mx", "selector1", "selector2",
    "s1", "s2", "smtp", "email", "mailer", "pm", "protonmail", "zoho",
    "outlook", "office365", "microsoft", "mandrill", "sendgrid", "sparkpost",
    "mailgun", "postmark", "amazonses", "ses", "dkim1", "dkim2", "key1",
    "2023", "2024", "2025", "2026", "ed25519", "rsa", "x", "z", "mta"
]

DKIM_KEY_PATTERN = re.compile(r"p\s*=\s*([A-Za-z0-9+/=]+)")
BIMI_PATTERN = re.compile(r"l=https?://\S+")

def parse_spf_mechanisms(spf_record: str):
    mechanisms = []
    parts = spf_record.split()
    for part in parts:
        if part.startswith("v=spf1"):
            continue
        if part.startswith("include:"):
            mechanisms.append(("include", part[8:]))
        elif part.startswith("redirect="):
            mechanisms.append(("redirect", part[9:]))
        elif part.startswith("a"):
            if ":" in part:
                mechanisms.append(("a", part[2:]))
            else:
                mechanisms.append(("a", "*"))
        elif part.startswith("mx"):
            if ":" in part:
                mechanisms.append(("mx", part[3:]))
            else:
                mechanisms.append(("mx", "*"))
        elif part.startswith("ip4:"):
            mechanisms.append(("ip4", part[4:]))
        elif part.startswith("ip6:"):
            mechanisms.append(("ip6", part[4:]))
        elif part.startswith("exists:"):
            mechanisms.append(("exists", part[7:]))
        elif part.startswith("ptr"):
            mechanisms.append(("ptr", part[4:] if ":" in part else "*"))
        elif part in ["~all", "-all", "+all", "?all"]:
            mechanisms.append(("all", part))
        elif part.startswith("~") or part.startswith("-") or part.startswith("+"):
            mechanisms.append(("all", part))
    return mechanisms

def estimate_key_strength(dkim_txt: str):
    if "ed25519" in dkim_txt:
        return ("Ed25519 (Strong)", "High", "emerald")
    p_match = DKIM_KEY_PATTERN.search(dkim_txt)
    if not p_match:
        return ("Unknown key", "Low", "red")
    key_data = p_match.group(1)
    try:
        import base64
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
        domain = urlparse(domain).netloc

    loop = asyncio.get_event_loop()
    spf_raw = None
    dmarc_raw = None
    dkim_found = []

    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        mx_hosts = []
        for r in mx_records:
            mx_host = str(r.exchange).rstrip('.')
            mx_prio = r.preference
            mx_hosts.append((mx_prio, mx_host))
            mx_provider = "Unknown"
            for provider, domains in [
                ("Google Workspace", ["google.com", "googlemail.com"]),
                ("Microsoft 365", ["protection.outlook.com", "mail.protection.outlook.com"]),
                ("Zoho", ["zoho.com", "zohomail.com"]),
                ("ProtonMail", ["protonmail.ch", "protonmail.com"]),
                ("Fastmail", ["messagingengine.com"]),
                ("Mailgun", ["mailgun.org"]),
                ("SendGrid", ["sendgrid.net"]),
                ("Amazon SES", ["amazonses.com"]),
                ("Yandex", ["yandex.net"]),
                ("OVH", ["ovh.net"]),
            ]:
                if any(d in mx_host.lower() for d in domains):
                    mx_provider = provider
                    break
            findings.append(IntelligenceFinding(
                entity=f"{mx_host} (priority {mx_prio})",
                type=f"Email Security - MX Server ({mx_provider})",
                source="EmailSecurityDeep",
                confidence="High",
                color="slate",
                resolution=f"Provider: {mx_provider}",
                raw_data=f"MX: {mx_host} (prio {mx_prio})",
                tags=["email-security", "mx"]
            ))

        if mx_hosts:
            findings.append(IntelligenceFinding(
                entity=f"{len(mx_hosts)} MX servers, primary: {mx_hosts[0][1]}",
                type="Email Security - MX Summary",
                source="EmailSecurityDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Total MX: {len(mx_hosts)}, Prio list: {', '.join(f'{p} {h}' for p,h in mx_hosts)}",
                tags=["email-security", "mx"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"No MX records: {str(e)[:60]}",
            type="Email Security - MX Error",
            source="EmailSecurityDeep",
            confidence="High",
            color="red",
            threat_level="High Risk",
            raw_data=f"Cannot receive emails at {domain}",
            tags=["email-security", "mx"]
        ))

    try:
        txt_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        for r in txt_records:
            txt = str(r)
            if txt.startswith("v=spf1"):
                spf_raw = txt
                spf_mechs = parse_spf_mechanisms(txt)
                findings.append(IntelligenceFinding(
                    entity=txt[:250],
                    type="Email Security - SPF Record",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=txt[:2000],
                    tags=["email-security", "spf"]
                ))
                for mech_type, mech_val in spf_mechs:
                    if mech_type == "all":
                        if mech_val == "-all" or mech_val == "-":
                            findings.append(IntelligenceFinding(
                                entity="SPF HardFail (-all) - Strong protection",
                                type="Email Security - SPF Policy",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="emerald",
                                threat_level="Informational",
                                tags=["email-security", "spf"]
                            ))
                        elif mech_val == "~all" or mech_val == "~":
                            findings.append(IntelligenceFinding(
                                entity="SPF SoftFail (~all) - Emails may be spoofed",
                                type="Email Security - SPF Weakness",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="orange",
                                threat_level="Elevated Risk",
                                tags=["email-security", "spf"]
                            ))
                        elif mech_val == "?all" or mech_val == "?":
                            findings.append(IntelligenceFinding(
                                entity="SPF Neutral (?all) - No enforcement",
                                type="Email Security - SPF Vulnerability",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="red",
                                threat_level="High Risk",
                                tags=["email-security", "spf"]
                            ))
                    elif mech_type == "include":
                        findings.append(IntelligenceFinding(
                            entity=f"Include: {mech_val}",
                            type="Email Security - SPF Include Mechanism",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="slate",
                            raw_data=f"SPF delegates to: {mech_val}"
                        ))
                        try:
                            incl_txt = await loop.run_in_executor(
                                None, lambda: dns.resolver.resolve(mech_val, 'TXT')
                            )
                            for ir in incl_txt:
                                itxt = str(ir)
                                if itxt.startswith("v=spf1"):
                                    sub_mechs = parse_spf_mechanisms(itxt)
                                    for smt, smv in sub_mechs:
                                        findings.append(IntelligenceFinding(
                                            entity=f"{smt}:{smv[:100]}",
                                            type="Email Security - SPF Inherited ({mech_val})",
                                            source="EmailSecurityDeep",
                                            confidence="Medium",
                                            color="slate",
                                            raw_data=f"From {mech_val}: {smt}:{smv[:200]}"
                                        ))
                                    break
                        except Exception:
                            pass
                    elif mech_type in ("ip4", "ip6"):
                        findings.append(IntelligenceFinding(
                            entity=f"{mech_type}: {mech_val}",
                            type="Email Security - SPF IP Allow",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="slate",
                            raw_data=f"Authorized sender: {mech_type}:{mech_val}"
                        ))
                    elif mech_type == "redirect":
                        findings.append(IntelligenceFinding(
                            entity=f"Redirect: {mech_val}",
                            type="Email Security - SPF Redirect",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="slate"
                        ))
                break
        if not spf_raw:
            findings.append(IntelligenceFinding(
                entity=f"No SPF record for {domain}",
                type="Email Security - Missing SPF",
                source="EmailSecurityDeep",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data=f"{domain} has no SPF - vulnerable to spoofing",
                tags=["email-security", "spf"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"SPF query error: {str(e)[:60]}",
            type="Email Security - SPF Error",
            source="EmailSecurityDeep",
            confidence="Medium",
            color="orange",
            tags=["email-security", "spf"]
        ))

    try:
        dmarc_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        )
        for r in dmarc_records:
            dmarc_raw = str(r)
            findings.append(IntelligenceFinding(
                entity=dmarc_raw[:250],
                type="Email Security - DMARC Record",
                source="EmailSecurityDeep",
                confidence="High",
                color="emerald",
                raw_data=dmarc_raw[:2000],
                tags=["email-security", "dmarc"]
            ))
            policy_match = re.search(r"p\s*=\s*(\w+)", dmarc_raw)
            if policy_match:
                policy = policy_match.group(1)
                if policy == "reject":
                    findings.append(IntelligenceFinding(
                        entity="DMARC Policy: reject - Strong protection",
                        type="Email Security - DMARC Policy",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        tags=["email-security", "dmarc"]
                    ))
                elif policy == "quarantine":
                    findings.append(IntelligenceFinding(
                        entity="DMARC Policy: quarantine - Moderate protection",
                        type="Email Security - DMARC Policy",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        tags=["email-security", "dmarc"]
                    ))
                elif policy == "none":
                    findings.append(IntelligenceFinding(
                        entity="DMARC Policy: none - Monitoring only, no protection",
                        type="Email Security - DMARC Weakness",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data="DMARC p=none means no enforcement against spoofing",
                        tags=["email-security", "dmarc"]
                    ))

            sp_match = re.search(r"sp\s*=\s*(\w+)", dmarc_raw)
            if sp_match:
                sp_policy = sp_match.group(1)
                findings.append(IntelligenceFinding(
                    entity=f"DMARC Subdomain Policy: {sp_policy}",
                    type="Email Security - DMARC Subdomain Policy",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    tags=["email-security", "dmarc"]
                ))

            rua_match = re.search(r"rua\s*=\s*(mailto:\S+)", dmarc_raw)
            if rua_match:
                rua_addr = rua_match.group(1)
                findings.append(IntelligenceFinding(
                    entity=rua_addr[:200],
                    type="Email Security - DMARC RUA (Aggregate Reports)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    raw_data=f"RUA: {rua_addr}",
                    tags=["email-security", "dmarc"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity="No DMARC reporting (rua) configured",
                    type="Email Security - DMARC Reporting Gap",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    tags=["email-security", "dmarc"]
                ))

            ruf_match = re.search(r"ruf\s*=\s*(mailto:\S+)", dmarc_raw)
            if ruf_match:
                ruf_addr = ruf_match.group(1)
                findings.append(IntelligenceFinding(
                    entity=ruf_addr[:200],
                    type="Email Security - DMARC RUF (Forensic Reports)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    raw_data=f"RUF: {ruf_addr}",
                    tags=["email-security", "dmarc"]
                ))

            pct_match = re.search(r"pct\s*=\s*(\d+)", dmarc_raw)
            if pct_match:
                pct_val = int(pct_match.group(1))
                if pct_val < 100:
                    findings.append(IntelligenceFinding(
                        entity=f"DMARC applies to {pct_val}% of email",
                        type="Email Security - DMARC Sampling",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        raw_data=f"DMARC policy only applies to {pct_val}% of messages"
                    ))

            fo_match = re.search(r"fo\s*=\s*([\d:]+)", dmarc_raw)
            if fo_match:
                fo_val = fo_match.group(1)
                findings.append(IntelligenceFinding(
                    entity=f"DMARC Forensic options: {fo_val}",
                    type="Email Security - DMARC FO",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    tags=["email-security", "dmarc"]
                ))

            rf_match = re.search(r"rf\s*=\s*(\w+)", dmarc_raw)
            if rf_match:
                rf_val = rf_match.group(1)
                findings.append(IntelligenceFinding(
                    entity=f"DMARC Report Format: {rf_val}",
                    type="Email Security - DMARC RF",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate"
                ))
            break
        if not dmarc_raw:
            raise Exception("No DMARC")
    except Exception:
        findings.append(IntelligenceFinding(
            entity=f"No DMARC record for {domain}",
            type="Email Security - Missing DMARC",
            source="EmailSecurityDeep",
            confidence="High",
            color="red",
            threat_level="High Risk",
            raw_data=f"No DMARC - domain can be spoofed",
            tags=["email-security", "dmarc"]
        ))

    for selector in COMMON_DKIM_SELECTORS:
        try:
            dkim_records = await loop.run_in_executor(
                None, lambda: dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            )
            for r in dkim_records:
                dkim_txt = str(r)
                key_strength, key_conf, key_color = estimate_key_strength(dkim_txt)
                findings.append(IntelligenceFinding(
                    entity=f"DKIM (selector: {selector}) - {key_strength}",
                    type="Email Security - DKIM Record",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color=key_color,
                    resolution=key_strength,
                    raw_data=dkim_txt[:2000],
                    tags=["email-security", "dkim"]
                ))

                if "h=sha256" in dkim_txt or "h=sha1" in dkim_txt:
                    if "h=sha1" in dkim_txt:
                        findings.append(IntelligenceFinding(
                            entity=f"DKIM {selector} uses SHA-1 (deprecated)",
                            type="Email Security - DKIM Weak Hash",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="red",
                            threat_level="Elevated Risk",
                            tags=["email-security", "dkim"]
                        ))

                if "s=email" in dkim_txt:
                    findings.append(IntelligenceFinding(
                        entity=f"DKIM {selector} service type: email",
                        type="Email Security - DKIM Service Type",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate"
                    ))

                dkim_found.append(selector)
                break
        except Exception:
            continue

    if not dkim_found:
        findings.append(IntelligenceFinding(
            entity=f"No DKIM records found",
            type="Email Security - Missing DKIM",
            source="EmailSecurityDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Checked {len(COMMON_DKIM_SELECTORS)} selectors, none found",
            tags=["email-security", "dkim"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"DKIM active on {len(dkim_found)} selector(s): {', '.join(dkim_found[:5])}",
            type="Email Security - DKIM Summary",
            source="EmailSecurityDeep",
            confidence="High",
            color="slate",
            tags=["email-security", "dkim"]
        ))

    try:
        bimi_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"default._bimi.{domain}", 'TXT')
        )
        for r in bimi_records:
            bimi_txt = str(r)
            findings.append(IntelligenceFinding(
                entity=bimi_txt[:250],
                type="Email Security - BIMI Record",
                source="EmailSecurityDeep",
                confidence="High",
                color="purple",
                raw_data=bimi_txt[:2000],
                tags=["email-security", "bimi"]
            ))
            logo_match = BIMI_PATTERN.search(bimi_txt)
            if logo_match:
                findings.append(IntelligenceFinding(
                    entity=f"BIMI Logo: {logo_match.group(0)[2:]}",
                    type="Email Security - BIMI Logo URL",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="purple",
                    tags=["email-security", "bimi"]
                ))
            break
    except Exception:
        pass

    try:
        vmc_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"default._bimi.{domain}", 'CNAME')
        )
        for r in vmc_records:
            vmc_target = str(r.target).rstrip('.')
            if vmc_target:
                findings.append(IntelligenceFinding(
                    entity=f"BIMI VMC: {vmc_target}",
                    type="Email Security - BIMI VMC (Verified Mark Certificate)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="purple",
                    tags=["email-security", "bimi"]
                ))
            break
    except Exception:
        pass

    try:
        mta_sts_txt = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_mta-sts.{domain}", 'TXT')
        )
        for r in mta_sts_txt:
            mta_txt = str(r)
            if "v=STSv1" in mta_txt:
                findings.append(IntelligenceFinding(
                    entity=mta_txt[:250],
                    type="Email Security - MTA-STS Record (DNS)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=mta_txt[:2000],
                    tags=["email-security", "mta-sts"]
                ))
            break
    except Exception:
        pass

    try:
        mta_sts_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        mta_resp = await client.get(mta_sts_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"})
        if mta_resp.status_code == 200:
            mta_policy = mta_resp.text.strip()
            if "v=STSv1" in mta_policy:
                findings.append(IntelligenceFinding(
                    entity=f"MTA-STS Policy Active (HTTP endpoint)",
                    type="Email Security - MTA-STS Policy",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=mta_policy[:2000],
                    tags=["email-security", "mta-sts"]
                ))
                mode_match = re.search(r"mode:\s*(\w+)", mta_policy)
                if mode_match:
                    mode = mode_match.group(1)
                    if mode == "enforce":
                        findings.append(IntelligenceFinding(
                            entity="MTA-STS Mode: enforce",
                            type="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="emerald"
                        ))
                    elif mode == "testing":
                        findings.append(IntelligenceFinding(
                            entity="MTA-STS Mode: testing",
                            type="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="orange"
                        ))
                    elif mode == "none":
                        findings.append(IntelligenceFinding(
                            entity="MTA-STS Mode: none",
                            type="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="red"
                        ))
                mx_match = re.search(r"mx:\s*(\S+)", mta_policy)
                if mx_match:
                    findings.append(IntelligenceFinding(
                        entity=f"MTA-STS MX: {mx_match.group(1)}",
                        type="Email Security - MTA-STS Allowed MX",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate"
                    ))
    except Exception:
        pass

    try:
        tls_rpt_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_smtp._tls.{domain}", 'TXT')
        )
        for r in tls_rpt_records:
            tls_txt = str(r)
            if "v=TLSRPT" in tls_txt:
                findings.append(IntelligenceFinding(
                    entity=tls_txt[:250],
                    type="Email Security - TLS-RPT Record",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=tls_txt[:2000],
                    tags=["email-security", "tls-rpt"]
                ))
                rua_mat = re.search(r"rua\s*=\s*(mailto:\S+)", tls_txt)
                if rua_mat:
                    findings.append(IntelligenceFinding(
                        entity=f"TLS-RPT Reporting: {rua_mat.group(1)}",
                        type="Email Security - TLS-RPT RUA",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate"
                    ))
            break
    except Exception:
        pass

    try:
        arc_records = await loop.run_in_executor(
            None, lambda: dns.resolver.resolve(f"_arc._domainkey.{domain}", 'TXT')
        )
        for r in arc_records:
            arc_txt = str(r)
            findings.append(IntelligenceFinding(
                entity=arc_txt[:200],
                type="Email Security - ARC Record",
                source="EmailSecurityDeep",
                confidence="High",
                color="slate",
                tags=["email-security", "arc"]
            ))
            break
    except Exception:
        pass

    score = 0
    max_score = 20
    score_breakdown = []

    if any("SPF Record" in (f.type or "") or "v=spf1" in (f.raw_data or "") for f in findings):
        score += 4
        score_breakdown.append("SPF: 4")
    if any("DMARC Record" in (f.type or "") or "v=DMARC" in (f.raw_data or "") for f in findings):
        score += 4
        score_breakdown.append("DMARC: 4")
    dkim_count = sum(1 for f in findings if "DKIM Record" in (f.type or ""))
    if dkim_count > 0:
        score += min(dkim_count * 2, 4)
        score_breakdown.append(f"DKIM({dkim_count}): {min(dkim_count*2, 4)}")

    if any("HardFail" in (f.entity or "") or "reject" in (f.entity or "").lower() for f in findings):
        score += 2
        score_breakdown.append("HardFail/Reject: 2")
    elif any("quarantine" in (f.entity or "").lower() for f in findings):
        score += 1
        score_breakdown.append("Quarantine: 1")

    if any("BIMI Record" in (f.type or "") for f in findings):
        score += 2
        score_breakdown.append("BIMI: 2")
    if any("MTA-STS Policy" in (f.type or "") or "MTA-STS Record" in (f.type or "") for f in findings):
        score += 2
        score_breakdown.append("MTA-STS: 2")
    if any("TLS-RPT" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("TLS-RPT: 1")
    if any("ARC Record" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("ARC: 1")

    score_pct = round((score / max_score) * 100)
    risk_level = "Low Risk" if score_pct >= 80 else ("Moderate Risk" if score_pct >= 50 else "High Risk")
    risk_color = "emerald" if score_pct >= 80 else ("orange" if score_pct >= 50 else "red")

    findings.append(IntelligenceFinding(
        entity=f"Email Security Score: {score}/{max_score} ({score_pct}%)",
        type="Email Security - Composite Score",
        source="EmailSecurityDeep",
        confidence="High",
        color=risk_color,
        threat_level=risk_level,
        raw_data=f"Score: {score}/{max_score} | Breakdown: {' + '.join(score_breakdown)} | {risk_level}",
        tags=["email-security", "summary"]
    ))

    return findings
