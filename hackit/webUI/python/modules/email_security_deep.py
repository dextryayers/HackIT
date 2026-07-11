import httpx
import asyncio
import re
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

COMMON_DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "dkim", "mx", "selector1", "selector2",
    "s1", "s2", "smtp", "email", "mailer", "pm", "protonmail", "zoho",
    "outlook", "office365", "microsoft", "mandrill", "sendgrid", "sparkpost",
    "mailgun", "postmark", "amazonses", "ses", "dkim1", "dkim2", "key1",
    "2023", "2024", "2025", "2026", "ed25519", "rsa", "x", "z", "mta",
    "dkim3", "dkim4", "dkim5", "mx1", "mx2", "mailer1", "mailer2",
    "emails", "mailing", "mailinglist", "newsletter", "transactional",
    "bounce", "bounces", "feedback", "noreply", "no-reply",
    "selector", "smtp01", "smtp02", "exch", "pod", "pod1", "pod2",
    "cluster", "node1", "node2", "node3", "hk1", "hk2", "hk3",
    "eu1", "eu2", "eu3", "us1", "us2", "us3", "ap1", "ap2",
    "dk", "dk01", "dk02", "key", "key2", "key3", "pub", "pubkey",
    "rsa2048", "rsa1024", "256", "512", "1024", "2048",
    "mta1", "mta2", "mta3", "mta4", "mta5",
    "mail1", "mail2", "mail3", "em1", "em2", "em3",
    "sg", "send", "mailchimp", "mandrillapp", "spf",
    "dkim._domainkey", "selector._domainkey", "sig1", "sig2",
    "dkim2010", "dkim2011", "dkim2012", "dkim2013", "dkim2014",
    "dkim2015", "dkim2016", "dkim2017", "dkim2018", "dkim2019",
    "dkim2020", "dkim2021", "dkim2022", "dkim2023", "dkim2024",
    "dkim2025", "dkim2026", "dkim01", "dkim02", "dkim03",
    "dkim-2023", "dkim-2024", "dkim-2025", "dkim-2026",
    "mxhost", "smtp-relay", "relay", "edge", "border",
    "inbound", "outbound", "transaction", "bulk", "marketing",
    "ml", "list", "list1", "d1", "d2", "d3",
    "dkim_prod", "dkim_staging", "prod", "stage",
    "email-security", "security", "auth", "auth1",
    "c1", "c2", "c3", "e1", "e2", "f1", "f2",
    "g1", "g2", "h1", "h2", "selector01", "selector02",
    "selector-a", "selector-b", "selector-c", "selector-d",
    "smtp-auth", "dkim-relay", "mxs", "mxb", "mxp",
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

def _check_mx_smtp_sync(mx_host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((mx_host, 25))
        banner = b""
        try:
            banner = sock.recv(4096)
        except Exception:
            sock.close()
            return {"banner": None, "starttls": False, "tls_version": None, "ehlo_caps": [], "ehlo_raw": None, "error": "No banner"}
        banner_str = banner.decode("utf-8", errors="ignore").strip()
        sock.send(b"EHLO deepcheck.local\r\n")
        ehlo_data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                ehlo_data += chunk
                text = ehlo_data.decode("utf-8", errors="ignore")
                if "\r\n" in text:
                    lines = text.split("\r\n")
                    for line in lines:
                        clean = line.strip()
                        if len(clean) >= 4 and clean[3:4] == " " and clean[:3].isdigit():
                            ehlo_data = text.encode("utf-8", errors="ignore")
                            break
                    else:
                        continue
                    break
            except Exception:
                break
        ehlo_text = ehlo_data.decode("utf-8", errors="ignore")
        caps = []
        for line in ehlo_text.split("\r\n"):
            line = line.strip()
            if line.startswith("250-"):
                caps.append(line[4:].strip())
            elif line.startswith("250 "):
                caps.append(line[4:].strip())
        has_starttls = any(c.upper() == "STARTTLS" for c in caps) or any("STARTTLS" in c.upper() for c in caps)
        auth_mechs = []
        tls_opts = []
        for c in caps:
            if c.upper().startswith("AUTH "):
                auth_mechs = c[5:].strip().split()
            elif c.upper().startswith("AUTH="):
                auth_mechs = c[5:].strip().split()
        for c in caps:
            if c.upper().startswith("TLS") or c.upper() == "STARTTLS" or "REQUIRETLS" in c.upper():
                tls_opts.append(c)
        extensions = {}
        for c in caps:
            if c.upper().startswith("SIZE "):
                try:
                    extensions["SIZE"] = int(c[5:].strip())
                except Exception:
                    extensions["SIZE"] = c[5:].strip()
            elif c.upper() in ("PIPELINING", "8BITMIME", "SMTPUTF8", "DSN", "CHUNKING", "BINARYMIME", "ENHANCEDSTATUSCODES", "VRFY", "EXPN"):
                extensions[c.upper()] = True
        tls_version = None
        sock2 = None
        if has_starttls and banner.startswith(b"2"):
            try:
                sock.send(b"STARTTLS\r\n")
                resp = b""
                try:
                    resp = sock.recv(4096)
                except Exception:
                    pass
                if resp.startswith(b"220"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        sock2 = ctx.wrap_socket(sock, server_hostname=mx_host, do_handshake_on_connect=True)
                        tls_version = sock2.version()
                    except Exception as e:
                        tls_version = f"TLS fail: {str(e)[:30]}"
                else:
                    if resp:
                        tls_version = resp.decode("utf-8", errors="ignore").strip()[:80]
            except Exception as e:
                tls_version = f"Error: {str(e)[:30]}"
        if sock2 is not None:
            try:
                sock2.close()
            except Exception:
                pass
        else:
            try:
                sock.close()
            except Exception:
                pass
        return {
            "banner": banner_str,
            "starttls": has_starttls,
            "tls_version": tls_version,
            "ehlo_caps": caps,
            "ehlo_raw": ehlo_text[:2000],
            "auth_mechs": auth_mechs,
            "tls_opts": tls_opts,
            "extensions": extensions,
            "error": None
        }
    except Exception as e:
        return {"banner": None, "starttls": False, "tls_version": None, "ehlo_caps": [], "ehlo_raw": None, "auth_mechs": [], "tls_opts": [], "extensions": {}, "error": str(e)[:80]}

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
            findings.append(make_finding(
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
            findings.append(make_finding(
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
        mx_hosts = []
        findings.append(make_finding(
            entity=f"No MX records: {str(e)[:60]}",
            type="Email Security - MX Error",
            source="EmailSecurityDeep",
            confidence="High",
            color="red",
            threat_level="High Risk",
            raw_data=f"Cannot receive emails at {domain}",
            tags=["email-security", "mx"]
        ))

    if mx_hosts:
        for mx_prio, mx_host in mx_hosts:
            try:
                tlsa_records = await loop.run_in_executor(
                    None, lambda h=mx_host: dns.resolver.resolve(f"_25._tcp.{h}", 'TLSA')
                )
                tlsa_count = 0
                for r in tlsa_records:
                    tlsa_count += 1
                    tlsa_str = str(r)
                    findings.append(make_finding(
                        entity=f"DANE TLSA for {mx_host}: {tlsa_str[:200]}",
                        ftype="Email Security - DANE/TLSA Record",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="emerald",
                        raw_data=tlsa_str[:2000],
                        tags=["email-security", "dane", "tlsa"]
                    ))
                if tlsa_count > 0:
                    findings.append(make_finding(
                        entity=f"{mx_host}: {tlsa_count} TLSA record(s)",
                        type="Email Security - DANE/TLSA Summary",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        tags=["email-security", "dane", "tlsa"]
                    ))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass

        for mx_prio, mx_host in mx_hosts:
            smtp_result = await loop.run_in_executor(None, _check_mx_smtp_sync, mx_host)
            if smtp_result.get("error") and not smtp_result.get("banner"):
                findings.append(make_finding(
                    entity=f"SMTP {mx_host}:25 - {smtp_result['error']}",
                    ftype="Email Security - SMTP Connection Error",
                    source="EmailSecurityDeep",
                    confidence="Medium",
                    color="orange",
                    tags=["email-security", "smtp"]
                ))
                continue
            if smtp_result["banner"]:
                findings.append(make_finding(
                    entity=f"SMTP Banner: {smtp_result['banner'][:150]}",
                    ftype=f"Email Security - SMTP Banner ({mx_host})",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    raw_data=smtp_result["banner"][:2000],
                    tags=["email-security", "smtp"]
                ))
            if smtp_result["starttls"]:
                findings.append(make_finding(
                    entity=f"STARTTLS supported on {mx_host}",
                    ftype="Email Security - SMTP STARTTLS",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    tags=["email-security", "smtp", "tls"]
                ))
            else:
                findings.append(make_finding(
                    entity=f"No STARTTLS on {mx_host} - traffic sent in plaintext",
                    ftype="Email Security - SMTP No TLS",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["email-security", "smtp", "tls"]
                ))
            if smtp_result["tls_version"] and isinstance(smtp_result["tls_version"], str) and smtp_result["tls_version"].startswith("TLS"):
                findings.append(make_finding(
                    entity=f"TLS version on {mx_host}: {smtp_result['tls_version']}",
                    ftype="Email Security - SMTP TLS Version",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald" if "1.2" in smtp_result["tls_version"] or "1.3" in smtp_result["tls_version"] else "orange",
                    raw_data=smtp_result["tls_version"],
                    tags=["email-security", "smtp", "tls"]
                ))
            if smtp_result["ehlo_caps"]:
                auth_str = ", ".join(smtp_result.get("auth_mechs", [])) or "None"
                findings.append(make_finding(
                    entity=f"EHLO capabilities on {mx_host}: {len(smtp_result['ehlo_caps'])} extensions",
                    type="Email Security - SMTP EHLO Extensions",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    raw_data=f"Auth: {auth_str}\nTLS opts: {', '.join(smtp_result.get('tls_opts', []))}\nExtensions: {', '.join(smtp_result['ehlo_caps'][:20])}",
                    tags=["email-security", "smtp", "ehlo"]
                ))
                if smtp_result.get("auth_mechs"):
                    findings.append(make_finding(
                        entity=f"SMTP AUTH mechanisms on {mx_host}: {', '.join(smtp_result['auth_mechs'])}",
                        type="Email Security - SMTP Authentication Mechanisms",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        raw_data=", ".join(smtp_result["auth_mechs"]),
                        tags=["email-security", "smtp", "auth"]
                    ))
                if "PIPELINING" in smtp_result.get("extensions", {}):
                    findings.append(make_finding(
                        entity=f"PIPELINING supported on {mx_host}",
                        ftype="Email Security - SMTP Extension",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        tags=["email-security", "smtp", "extension"]
                    ))
                if "SMTPUTF8" in smtp_result.get("extensions", {}):
                    findings.append(make_finding(
                        entity=f"SMTPUTF8 supported on {mx_host}",
                        ftype="Email Security - SMTP Extension",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        tags=["email-security", "smtp", "extension"]
                    ))
                if "DSN" in smtp_result.get("extensions", {}):
                    findings.append(make_finding(
                        entity=f"DSN (Delivery Status Notification) on {mx_host}",
                        type="Email Security - SMTP Extension",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        tags=["email-security", "smtp", "extension"]
                    ))
                ext_size = smtp_result.get("extensions", {}).get("SIZE")
                if ext_size:
                    findings.append(make_finding(
                        entity=f"Max message size on {mx_host}: {ext_size} bytes",
                        ftype="Email Security - SMTP Max Size",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        tags=["email-security", "smtp", "extension"]
                    ))

    try:
        txt_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'TXT'))
        for r in txt_records:
            txt = str(r)
            if txt.startswith("v=spf1"):
                spf_raw = txt
                spf_mechs = parse_spf_mechanisms(txt)
                findings.append(make_finding(
                    entity=txt[:250],
                    ftype="Email Security - SPF Record",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=txt[:2000],
                    tags=["email-security", "spf"]
                ))
                for mech_type, mech_val in spf_mechs:
                    if mech_type == "all":
                        if mech_val == "-all" or mech_val == "-":
                            findings.append(make_finding(
                                entity="SPF HardFail (-all) - Strong protection",
                                type="Email Security - SPF Policy",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="emerald",
                                threat_level="Informational",
                                tags=["email-security", "spf"]
                            ))
                        elif mech_val == "~all" or mech_val == "~":
                            findings.append(make_finding(
                                entity="SPF SoftFail (~all) - Emails may be spoofed",
                                type="Email Security - SPF Weakness",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="orange",
                                threat_level="Elevated Risk",
                                tags=["email-security", "spf"]
                            ))
                        elif mech_val == "?all" or mech_val == "?":
                            findings.append(make_finding(
                                entity="SPF Neutral (?all) - No enforcement",
                                type="Email Security - SPF Vulnerability",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="red",
                                threat_level="High Risk",
                                tags=["email-security", "spf"]
                            ))
                    elif mech_type == "include":
                        findings.append(make_finding(
                            entity=f"Include: {mech_val}",
                            ftype="Email Security - SPF Include Mechanism",
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
                                        findings.append(make_finding(
                                            entity=f"{smt}:{smv[:100]}",
                                            ftype="Email Security - SPF Inherited ({mech_val})",
                                            source="EmailSecurityDeep",
                                            confidence="Medium",
                                            color="slate",
                                            raw_data=f"From {mech_val}: {smt}:{smv[:200]}"
                                        ))
                                    break
                        except Exception:
                            pass
                    elif mech_type in ("ip4", "ip6"):
                        findings.append(make_finding(
                            entity=f"{mech_type}: {mech_val}",
                            ftype="Email Security - SPF IP Allow",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="slate",
                            raw_data=f"Authorized sender: {mech_type}:{mech_val}"
                        ))
                    elif mech_type == "redirect":
                        findings.append(make_finding(
                            entity=f"Redirect: {mech_val}",
                            ftype="Email Security - SPF Redirect",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="slate"
                        ))

                if re.search(r'[%{}]', txt):
                    findings.append(make_finding(
                        entity=f"SPF macros detected - complex expansion may cause misconfiguration",
                        ftype="Email Security - SPF Macro Expansion",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        raw_data=txt[:500],
                        tags=["email-security", "spf", "macro"]
                    ))

                dns_lookups = sum(1 for m in spf_mechs if m[0] in ("include", "redirect", "a", "mx", "ptr", "exists"))
                if dns_lookups > 8:
                    findings.append(make_finding(
                        entity=f"SPF requires ~{dns_lookups} DNS lookups (limit: 10) - risk of PermError",
                        type="Email Security - SPF DNS Lookup Limit",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        raw_data=f"Estimated DNS lookups: {dns_lookups} from {len(spf_mechs)} mechanisms. Per-mechanism breakdown may vary with includes.",
                        tags=["email-security", "spf", "dns-limit"]
                    ))
                elif dns_lookups >= 10:
                    findings.append(make_finding(
                        entity=f"SPF exceeds recommended 10 DNS lookup limit (~{dns_lookups} lookups) - risk of PermError",
                        type="Email Security - SPF DNS Lookup Limit Exceeded",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"Estimated DNS lookups: {dns_lookups}. SPF will fail for receivers enforcing the 10-lookup limit.",
                        tags=["email-security", "spf", "dns-limit"]
                    ))

                break
        if not spf_raw:
            findings.append(make_finding(
                entity=f"No SPF record for {domain}",
                ftype="Email Security - Missing SPF",
                source="EmailSecurityDeep",
                confidence="High",
                color="red",
                threat_level="High Risk",
                raw_data=f"{domain} has no SPF - vulnerable to spoofing",
                tags=["email-security", "spf"]
            ))
    except Exception as e:
        findings.append(make_finding(
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
            findings.append(make_finding(
                entity=dmarc_raw[:250],
                ftype="Email Security - DMARC Record",
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
                    findings.append(make_finding(
                        entity="DMARC Policy: reject - Strong protection",
                        ftype="Email Security - DMARC Policy",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        tags=["email-security", "dmarc"]
                    ))
                elif policy == "quarantine":
                    findings.append(make_finding(
                        entity="DMARC Policy: quarantine - Moderate protection",
                        ftype="Email Security - DMARC Policy",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        tags=["email-security", "dmarc"]
                    ))
                elif policy == "none":
                    findings.append(make_finding(
                        entity="DMARC Policy: none - Monitoring only, no protection",
                        ftype="Email Security - DMARC Weakness",
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
                findings.append(make_finding(
                    entity=f"DMARC Subdomain Policy: {sp_policy}",
                    ftype="Email Security - DMARC Subdomain Policy",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    tags=["email-security", "dmarc"]
                ))

            rua_match = re.search(r"rua\s*=\s*(mailto:\S+)", dmarc_raw)
            if rua_match:
                rua_addr = rua_match.group(1)
                findings.append(make_finding(
                    entity=rua_addr[:200],
                    ftype="Email Security - DMARC RUA (Aggregate Reports)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    raw_data=f"RUA: {rua_addr}",
                    tags=["email-security", "dmarc"]
                ))
                rua_clean = rua_addr.replace("mailto:", "")
                rua_parts = rua_clean.split("@")
                if len(rua_parts) == 2:
                    rua_local, rua_domain = rua_parts
                    rua_format = "Unknown"
                    if "dmarc" in rua_local.lower() or "rua" in rua_local.lower():
                        rua_format = "Standard (dmarc+subdomain@domain)"
                    elif "report" in rua_local.lower():
                        rua_format = "Report-based"
                    elif "postmark" in rua_domain.lower():
                        rua_format = "Postmark DMARC"
                    elif "dmarcian" in rua_domain.lower():
                        rua_format = "dmarcian"
                    elif "uriports" in rua_domain.lower():
                        rua_format = "URIports"
                    elif "sendmail" in rua_domain.lower():
                        rua_format = "Sendmail"
                    elif "valimail" in rua_domain.lower():
                        rua_format = "Valimail"
                    elif "agari" in rua_domain.lower():
                        rua_format = "Agari"
                    elif "proofpoint" in rua_domain.lower():
                        rua_format = "Proofpoint"
                    elif "mimecast" in rua_domain.lower():
                        rua_format = "Mimecast"
                    elif "barracuda" in rua_domain.lower():
                        rua_format = "Barracuda"
                    elif "dmarcreport" in rua_domain.lower() or "dmarc-report" in rua_domain.lower():
                        rua_format = "Standardized DMARC Reporter"
                    elif "google" in rua_domain.lower():
                        rua_format = "Google Workspace DMARC Reporting"
                    else:
                        rua_domain_parts = rua_domain.split(".")
                        if len(rua_domain_parts) >= 2 and rua_local == f"{domain}!{domain}" or rua_local.startswith(f"{domain}!"):
                            rua_format = "BIMI/IETF Standard (local-part!domain@reporter)"
                        elif "!" in rua_local:
                            rua_format = "Tagged reporting format"
                    findings.append(make_finding(
                        entity=f"DMARC aggregate report format: {rua_format}",
                        ftype="Email Security - DMARC RUA Format Analysis",
                        source="EmailSecurityDeep",
                        confidence="Medium",
                        color="slate",
                        raw_data=f"RUA: {rua_addr}, Format: {rua_format}",
                        tags=["email-security", "dmarc", "reporting"]
                    ))
            else:
                findings.append(make_finding(
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
                findings.append(make_finding(
                    entity=ruf_addr[:200],
                    ftype="Email Security - DMARC RUF (Forensic Reports)",
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
                    findings.append(make_finding(
                        entity=f"DMARC applies to {pct_val}% of email",
                        ftype="Email Security - DMARC Sampling",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="orange",
                        raw_data=f"DMARC policy only applies to {pct_val}% of messages"
                    ))

            fo_match = re.search(r"fo\s*=\s*([\d:]+)", dmarc_raw)
            if fo_match:
                fo_val = fo_match.group(1)
                findings.append(make_finding(
                    entity=f"DMARC Forensic options: {fo_val}",
                    ftype="Email Security - DMARC FO",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate",
                    tags=["email-security", "dmarc"]
                ))

            rf_match = re.search(r"rf\s*=\s*(\w+)", dmarc_raw)
            if rf_match:
                rf_val = rf_match.group(1)
                findings.append(make_finding(
                    entity=f"DMARC Report Format: {rf_val}",
                    ftype="Email Security - DMARC RF",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="slate"
                ))
            break
        if not dmarc_raw:
            raise Exception("No DMARC")
    except Exception:
        findings.append(make_finding(
            entity=f"No DMARC record for {domain}",
            ftype="Email Security - Missing DMARC",
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
                findings.append(make_finding(
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
                        findings.append(make_finding(
                            entity=f"DKIM {selector} uses SHA-1 (deprecated)",
                            type="Email Security - DKIM Weak Hash",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="red",
                            threat_level="Elevated Risk",
                            tags=["email-security", "dkim"]
                        ))

                if "s=email" in dkim_txt:
                    findings.append(make_finding(
                        entity=f"DKIM {selector} service type: email",
                        ftype="Email Security - DKIM Service Type",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate"
                    ))

                dkim_found.append(selector)
                break
        except Exception:
            continue

    if not dkim_found:
        findings.append(make_finding(
            entity=f"No DKIM records found",
            ftype="Email Security - Missing DKIM",
            source="EmailSecurityDeep",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            raw_data=f"Checked {len(COMMON_DKIM_SELECTORS)} selectors, none found",
            tags=["email-security", "dkim"]
        ))
    else:
        findings.append(make_finding(
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
            findings.append(make_finding(
                entity=bimi_txt[:250],
                ftype="Email Security - BIMI Record",
                source="EmailSecurityDeep",
                confidence="High",
                color="purple",
                raw_data=bimi_txt[:2000],
                tags=["email-security", "bimi"]
            ))
            logo_match = BIMI_PATTERN.search(bimi_txt)
            if logo_match:
                findings.append(make_finding(
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
                findings.append(make_finding(
                    entity=f"BIMI VMC: {vmc_target}",
                    ftype="Email Security - BIMI VMC (Verified Mark Certificate)",
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
                findings.append(make_finding(
                    entity=mta_txt[:250],
                    ftype="Email Security - MTA-STS Record (DNS)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=mta_txt[:2000],
                    tags=["email-security", "mta-sts"]
                ))
            break
    except Exception:
        pass

    mta_sts_mx_list = []
    try:
        mta_sts_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        mta_resp = await safe_fetch(client, mta_sts_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"})
        if mta_resp.status_code == 200:
            mta_policy = mta_resp.text.strip()
            if "v=STSv1" in mta_policy:
                findings.append(make_finding(
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
                        findings.append(make_finding(
                            entity="MTA-STS Mode: enforce",
                            ftype="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="emerald"
                        ))
                    elif mode == "testing":
                        findings.append(make_finding(
                            entity="MTA-STS Mode: testing",
                            ftype="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="orange"
                        ))
                    elif mode == "none":
                        findings.append(make_finding(
                            entity="MTA-STS Mode: none",
                            ftype="Email Security - MTA-STS Mode",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="red"
                        ))
                mx_match = re.search(r"mx:\s*(\S+)", mta_policy)
                if mx_match:
                    findings.append(make_finding(
                        entity=f"MTA-STS MX: {mx_match.group(1)}",
                        type="Email Security - MTA-STS Allowed MX",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate"
                    ))
                mta_sts_mx_matches = re.findall(r"mx:\s*(\S+)", mta_policy, re.IGNORECASE)
                mta_sts_mx_list = [m.lower().rstrip('.') for m in mta_sts_mx_matches]
                if mta_sts_mx_list and mx_hosts:
                    dns_mx_set = set(h.lower().rstrip('.') for _, h in mx_hosts)
                    sts_mx_set = set(mta_sts_mx_list)
                    missing_in_sts = dns_mx_set - sts_mx_set
                    extra_in_sts = sts_mx_set - dns_mx_set
                    if missing_in_sts or extra_in_sts:
                        mismatch_parts = []
                        if missing_in_sts:
                            mismatch_parts.append(f"DNS MX not in policy: {', '.join(sorted(missing_in_sts))}")
                        if extra_in_sts:
                            mismatch_parts.append(f"Policy lists unknown MX: {', '.join(sorted(extra_in_sts))}")
                        findings.append(make_finding(
                            entity=f"MTA-STS policy MX mismatch: {'; '.join(mismatch_parts)}",
                            type="Email Security - MTA-STS Policy Mismatch",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="orange",
                            threat_level="Elevated Risk",
                            raw_data=f"DNS MX: {', '.join(sorted(h.lower() for _, h in mx_hosts))} | STS MX: {', '.join(sorted(mta_sts_mx_list))}",
                            tags=["email-security", "mta-sts"]
                        ))
                    else:
                        findings.append(make_finding(
                            entity=f"MTA-STS policy MXes match DNS MX servers",
                            ftype="Email Security - MTA-STS Policy Validated",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="emerald",
                            tags=["email-security", "mta-sts"]
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
                findings.append(make_finding(
                    entity=tls_txt[:250],
                    ftype="Email Security - TLS-RPT Record",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald",
                    raw_data=tls_txt[:2000],
                    tags=["email-security", "tls-rpt"]
                ))
                rua_mat = re.search(r"rua\s*=\s*(mailto:\S+)", tls_txt)
                if rua_mat:
                    findings.append(make_finding(
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
            findings.append(make_finding(
                entity=arc_txt[:200],
                ftype="Email Security - ARC Record",
                source="EmailSecurityDeep",
                confidence="High",
                color="slate",
                tags=["email-security", "arc"]
            ))
            break
    except Exception:
        pass

    for mx_prio, mx_host in mx_hosts[:3]:
        for port in [465, 587, 2525]:
            try:
                psock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                psock.settimeout(4)
                psock.connect((mx_host, port))
                pbanner = b""
                try:
                    pbanner = psock.recv(4096)
                except:
                    pass
                pbanner_str = pbanner.decode("utf-8", errors="ignore").strip()
                if pbanner_str:
                    findings.append(make_finding(
                        entity=f"SMTP on port {port}: {pbanner_str[:150]}",
                        ftype=f"Email Security - SMTP Alternate Port ({port})",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="slate",
                        raw_data=pbanner_str[:1000],
                        tags=["email-security", "smtp", f"port-{port}"]
                    ))
                psock.close()
            except:
                pass

    for mx_prio, mx_host in mx_hosts[:3]:
        try:
            vsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            vsock.settimeout(4)
            vsock.connect((mx_host, 25))
            vsock.recv(4096)
            for cmd in ["VRFY test", "EXPN test"]:
                vsock.send(f"{cmd}\r\n".encode())
                try:
                    vresp = vsock.recv(4096).decode("utf-8", errors="ignore").strip()
                    if vresp and not vresp.startswith("5") and not vresp.startswith("2"):
                        continue
                    if vresp.startswith("2"):
                        findings.append(make_finding(
                            entity=f"{cmd} succeeded on {mx_host}: {vresp[:100]}",
                            ftype="Email Security - SMTP User Enumeration Risk",
                            source="EmailSecurityDeep",
                            confidence="High",
                            color="red",
                            threat_level="Elevated Risk",
                            raw_data=vresp[:1000],
                            tags=["email-security", "smtp", "enumeration"]
                        ))
                except:
                    pass
            try:
                vsock.send(b"QUIT\r\n")
            except:
                pass
            vsock.close()
        except:
            pass

    try:
        dnssec_loop = asyncio.get_event_loop()
        dnssec_result = await dnssec_loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'DNSKEY'))
        if dnssec_result:
            key_count = len(dnssec_result)
            findings.append(make_finding(
                entity=f"DNSSEC enabled: {key_count} DNSKEY record(s)",
                type="Email Security - DNSSEC Status",
                source="EmailSecurityDeep",
                confidence="High",
                color="emerald",
                raw_data=f"DNSSEC configured with {key_count} DNSKEY records",
                tags=["email-security", "dnssec"]
            ))
    except dns.resolver.NoAnswer:
        findings.append(make_finding(
            entity="DNSSEC not enabled",
            ftype="Email Security - DNSSEC Status",
            source="EmailSecurityDeep",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            tags=["email-security", "dnssec"]
        ))
    except Exception:
        pass

    for mx_prio, mx_host in mx_hosts[:3]:
        try:
            mx_loop = asyncio.get_event_loop()
            mx_a = mx_loop.run_in_executor(None, lambda: dns.resolver.resolve(mx_host, 'A'))
            mx_aaaa = mx_loop.run_in_executor(None, lambda: dns.resolver.resolve(mx_host, 'AAAA'))
            try:
                for r in await mx_a:
                    ip = str(r)
                    try:
                        rev = dns.resolver.resolve_address(ip)
                        rev_name = str(rev[0]).rstrip('.')
                        if rev_name:
                            findings.append(make_finding(
                                entity=f"MX {mx_host} ({ip}) rDNS: {rev_name}",
                                type="Email Security - MX Reverse DNS",
                                source="EmailSecurityDeep",
                                confidence="High",
                                color="slate",
                                raw_data=f"{ip} -> {rev_name}",
                                tags=["email-security", "mx", "rdns"]
                            ))
                            if mx_host.lower() not in rev_name.lower() and mx_host.lower().rstrip('.') not in rev_name.lower():
                                findings.append(make_finding(
                                    entity=f"MX {mx_host} rDNS mismatch: {rev_name}",
                                    ftype="Email Security - MX rDNS Mismatch",
                                    source="EmailSecurityDeep",
                                    confidence="Medium",
                                    color="orange",
                                    tags=["email-security", "mx", "rdns"]
                                ))
                    except:
                        pass
            except:
                pass
        except:
            pass

    for mx_prio, mx_host in mx_hosts[:3]:
        try:
            import ssl as ssl_mod
            ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock.settimeout(5)
            ssl_sock.connect((mx_host, 465))
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            try:
                tls = ctx.wrap_socket(ssl_sock, server_hostname=mx_host, do_handshake_on_connect=True)
                cert = tls.getpeercert()
                tls_version = tls.version()
                tls.close()
                if cert:
                    cn = dict(cert.get("subject", [[["", ""]]])[0]).get("commonName", "")
                    issuer = dict(cert.get("issuer", [[["", ""]]])[0]).get("commonName", "")
                    sans = [v for _, v in cert.get("subjectAltName", [])]
                    not_after = cert.get("notAfter", "")
                    findings.append(make_finding(
                        entity=f"SSL cert on {mx_host}:465 - CN: {cn}, TLS: {tls_version}",
                        ftype="Email Security - MX SSL Certificate (port 465)",
                        source="EmailSecurityDeep",
                        confidence="High",
                        color="emerald" if "TLSv1.2" in str(tls_version) or "TLSv1.3" in str(tls_version) else "orange",
                        raw_data=f"CN: {cn} | SANS: {', '.join(sans[:5])} | Issuer: {issuer} | Expires: {not_after} | TLS: {tls_version}",
                        tags=["email-security", "ssl", "certificate"]
                    ))
            except Exception as e:
                findings.append(make_finding(
                    entity=f"SSL error for {mx_host}:465 - {str(e)[:60]}",
                    type="Email Security - MX SSL Handshake Error",
                    source="EmailSecurityDeep",
                    confidence="Medium",
                    color="orange",
                    tags=["email-security", "ssl"]
                ))
        except:
            pass

    try:
        dmarc_check = None
        for f in findings:
            if "DMARC Record" in (f.type or ""):
                dmarc_check = f.raw_data
                break
        if dmarc_check:
            aspf = re.search(r"aspf\s*=\s*([rs])", dmarc_check)
            adkim = re.search(r"adkim\s*=\s*([rs])", dmarc_check)
            if aspf:
                findings.append(make_finding(
                    entity=f"DMARC SPF Alignment: {'Strict (r)' if aspf.group(1) == 'r' else 'Relaxed (s)'}",
                    type="Email Security - DMARC Alignment (SPF)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald" if aspf.group(1) == 'r' else "orange",
                    tags=["email-security", "dmarc", "alignment"]
                ))
            if adkim:
                findings.append(make_finding(
                    entity=f"DMARC DKIM Alignment: {'Strict (r)' if adkim.group(1) == 'r' else 'Relaxed (s)'}",
                    type="Email Security - DMARC Alignment (DKIM)",
                    source="EmailSecurityDeep",
                    confidence="High",
                    color="emerald" if adkim.group(1) == 'r' else "orange",
                    tags=["email-security", "dmarc", "alignment"]
                ))
    except Exception:
        pass

    score = 0
    max_score = 40
    score_breakdown = []

    if any("SPF Record" in (f.type or "") or "v=spf1" in (f.raw_data or "") for f in findings):
        score += 3
        score_breakdown.append("SPF: 3")
    if any("DMARC Record" in (f.type or "") or "v=DMARC" in (f.raw_data or "") for f in findings):
        score += 3
        score_breakdown.append("DMARC: 3")
    dkim_count = sum(1 for f in findings if "DKIM Record" in (f.type or ""))
    if dkim_count > 0:
        dkim_score = min(dkim_count, 4)
        score += dkim_score
        score_breakdown.append(f"DKIM({dkim_count}): {dkim_score}")

    if any("HardFail" in (f.entity or "") or "reject" in (f.entity or "").lower() for f in findings):
        score += 2
        score_breakdown.append("HardFail/Reject: 2")
    elif any("quarantine" in (f.entity or "").lower() for f in findings):
        score += 1
        score_breakdown.append("Quarantine: 1")

    if any("BIMI Record" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("BIMI: 1")
    mta_sts_present = any("MTA-STS Policy" in (f.type or "") or "MTA-STS Record" in (f.type or "") for f in findings)
    if mta_sts_present:
        score += 2
        score_breakdown.append("MTA-STS: 2")
    if any("TLS-RPT" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("TLS-RPT: 1")
    if any("ARC Record" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("ARC: 1")
    if any("DANE/TLSA Record" in (f.type or "") for f in findings):
        score += 2
        score_breakdown.append("DANE: 2")
    if any("SMTP STARTTLS" in (f.type or "") or "SMTP - STARTTLS" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("STARTTLS: 1")
    if any("SMTP TLS Version" in (f.type or "") and ("TLSv1.2" in (f.entity or "") or "TLSv1.3" in (f.entity or "")) for f in findings):
        score += 1
        score_breakdown.append("TLSv1.2+: 1")
    if any("SPF Macro" in (f.type or "") for f in findings):
        score -= 1
        score_breakdown.append("SPF Macros: -1")
    if any("SPF DNS Lookup Limit" in (f.type or "") for f in findings):
        score -= 1
        score_breakdown.append("SPF Lookups: -1")
    if any("MTA-STS Policy Validated" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("MTA-STS match: 1")
    elif any("MTA-STS Policy Mismatch" in (f.type or "") for f in findings):
        score -= 1
        score_breakdown.append("MTA-STS mismatch: -1")
    if any("SPF Policy" in (f.type or "") and "HardFail" in (f.entity or "") for f in findings):
        score += 1
        score_breakdown.append("SPF HardFail: 1")
    if any("EHLO" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("EHLO: 1")

    if any("DNSSEC enabled" in (f.entity or "") for f in findings):
        score += 2
        score_breakdown.append("DNSSEC: 2")
    if any("DNSSEC not enabled" in (f.entity or "") for f in findings):
        score -= 1
        score_breakdown.append("No DNSSEC: -1")
    if any("MX SSL Certificate" in (f.type or "") and "TLSv1" in (str(f.raw_data) or "") for f in findings):
        score += 2
        score_breakdown.append("MX SSL: 2")
    if any("MX Reverse DNS" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("MX rDNS: 1")
    if any("MX rDNS Mismatch" in (f.type or "") for f in findings):
        score -= 1
        score_breakdown.append("rDNS mismatch: -1")
    if any("DMARC Alignment" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("DMARC align: 1")
    if any("DMARC Alignment (SPF)" in (f.type or "") and "Strict" in (f.entity or "") for f in findings):
        score += 1
        score_breakdown.append("SPF strict: 1")
    if any("DMARC Alignment (DKIM)" in (f.type or "") and "Strict" in (f.entity or "") for f in findings):
        score += 1
        score_breakdown.append("DKIM strict: 1")
    if any("SMTP Alternate Port" in (f.type or "") for f in findings):
        score += 1
        score_breakdown.append("Alt ports: 1")
    if any("SMTP User Enumeration" in (f.type or "") for f in findings):
        score -= 2
        score_breakdown.append("Enumeration: -2")

    s_present = any("SPF Record" in (f.type or "") for f in findings)
    d_present = any("DMARC Record" in (f.type or "") for f in findings)
    k_present = dkim_count > 0
    m_present = mta_sts_present
    t_present = any("TLS-RPT" in (f.type or "") for f in findings)
    auth_chain_count = sum([s_present, d_present, k_present, m_present, t_present])
    if auth_chain_count >= 4:
        score += 2
        score_breakdown.append(f"AuthChain({auth_chain_count}/5): 2")
    elif auth_chain_count >= 2:
        score += 1
        score_breakdown.append(f"AuthChain({auth_chain_count}/5): 1")

    score = max(0, min(score, max_score))
    score_pct = round((score / max_score) * 100)

    if score_pct >= 95:
        grade = "A+"
        risk_level = "Low Risk"
        risk_color = "emerald"
    elif score_pct >= 80:
        grade = "A"
        risk_level = "Low Risk"
        risk_color = "emerald"
    elif score_pct >= 65:
        grade = "B"
        risk_level = "Low-Medium Risk"
        risk_color = "emerald"
    elif score_pct >= 50:
        grade = "C"
        risk_level = "Moderate Risk"
        risk_color = "orange"
    elif score_pct >= 30:
        grade = "D"
        risk_level = "Elevated Risk"
        risk_color = "orange"
    else:
        grade = "F"
        risk_level = "High Risk"
        risk_color = "red"

    findings.append(make_finding(
        entity=f"Email Security Grade: {grade} (Score: {score}/{max_score}, {score_pct}%)",
        type="Email Security - Composite Score",
        source="EmailSecurityDeep",
        confidence="High",
        color=risk_color,
        threat_level=risk_level,
        raw_data=f"Grade: {grade} | Score: {score}/{max_score} ({score_pct}%) | Breakdown: {' + '.join(score_breakdown)} | AuthChain: {auth_chain_count}/5 | {risk_level}",
        tags=["email-security", "summary"]
    ))

    findings.append(make_finding(
        entity=f"Email authentication chain: {auth_chain_count}/5 pillars (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)",
        type="Email Security - Authentication Chain",
        source="EmailSecurityDeep",
        confidence="High",
        color="slate" if auth_chain_count >= 3 else "orange",
        threat_level="Informational" if auth_chain_count >= 4 else ("Standard Target" if auth_chain_count >= 2 else "Elevated Risk"),
        raw_data=f"SPF={'Y' if s_present else 'N'}, DKIM={'Y' if k_present else 'N'}, DMARC={'Y' if d_present else 'N'}, MTA-STS={'Y' if m_present else 'N'}, TLS-RPT={'Y' if t_present else 'N'}",
        tags=["email-security", "summary", "auth-chain"]
    ))

    return findings
