import json
import sys
import re

# ─── ANSI COLORS ──────────────────────────────────────────────────────
C = {
    "R": "\033[91m",     # Red (warnings)
    "G": "\033[92m",     # Green (positive)
    "Y": "\033[93m",     # Yellow (fields)
    "B": "\033[94m",     # Blue
    "M": "\033[95m",     # Magenta (section titles)
    "C": "\033[96m",     # Cyan (subpoints)
    "W": "\033[97m",     # White
    "GR": "\033[90m",    # Gray
    "BD": "\033[1m",     # Bold
    "DM": "\033[2m",     # Dim
    "RV": "\033[7m",     # Reverse
    "RS": "\033[0m",     # Reset
    "E": "",             # Empty / no color
}

def _c(tag, text):
    """Wraps text in ANSI color tag if text is non-empty."""
    if text and text.strip():
        return f"{C.get(tag, '')}{text}{C['RS']}"
    return text

def _list(d, key):
    v = d.get(key)
    return v if isinstance(v, list) else []

def _dict(d, key):
    v = d.get(key)
    return v if isinstance(v, dict) else {}

def _str(d, key, default=""):
    v = d.get(key)
    return v if isinstance(v, str) and v else default

def _val(d, key, default):
    v = d.get(key)
    return v if v is not None else default

def _join(items, default="None"):
    if not items:
        return default
    try:
        return ", ".join(str(x) for x in items)
    except (TypeError, ValueError):
        return default

def _safe_join(iterable, sep=", "):
    if not iterable:
        return ""
    try:
        return sep.join(str(x) for x in iterable)
    except (TypeError, ValueError):
        return ""

def _hn(val):
    """Human-readable non-empty, else '—'."""
    return val if val and val.strip() else "—"

# ─── SECTION HELPERS ──────────────────────────────────────────────────

def _section(title, num=""):
    """Main section header with color."""
    num_str = f" {num}" if num else ""
    line = "━" * 70
    return f"\n{_c('M', line)}\n{_c('BD', '')}{_c('M', f'  POIN{num_str}: {title}')}\n{_c('M', line)}\n"

def _sub(num, title):
    """Subsection header."""
    return f"\n  {_c('C', f'{num} {title}')}\n"

def _field(name, value, default="Not available"):
    """Single field with color."""
    if value is None or (isinstance(value, str) and not value.strip()):
        val_colored = _c('GR', default)
    else:
        val_colored = _c('W', str(value))
    return f"  {_c('Y', name)}: {val_colored}\n"

def _tag(name, value, tag="W", default="—"):
    """Field with configurable value color tag."""
    if value is None or (isinstance(value, str) and not value.strip()):
        val_colored = _c('GR', default)
    else:
        val_colored = _c(tag, str(value))
    return f"  {_c('Y', name)}: {val_colored}\n"

def _multi_field(name, items, default="None found"):
    if not items:
        return f"  {_c('Y', name)}: {_c('GR', default)}\n"
    result = f"  {_c('Y', name)}:\n"
    for item in items:
        result += f"    {_c('C', '•')} {item}\n"
    return result

def _pair(k, v, tag="W"):
    """Inline key: value pair."""
    return f"{_c('GR', k)}: {_c(tag, str(v))}"

def _yesno(val):
    """Green Yes / Red No with label."""
    if val:
        return _c('G', "Yes")
    return _c('R', "No")

def _risk(level):
    """Color-code risk levels."""
    if level.lower() in ("critical", "high"):
        return _c('R', level)
    if level.lower() == "medium":
        return _c('Y', level)
    return _c('G', level)

# ─── CROSS-REFERENCE ENRICHMENT ───────────────────────────────────────

def _enrich(target, *sources):
    """Return first non-empty value from target or any source."""
    if target and isinstance(target, str) and target.strip() and target not in ("Not available", "—", "None", "Unknown"):
        return target
    for s in sources:
        if s and isinstance(s, str) and s.strip() and s not in ("Not available", "—", "None", "Unknown"):
            return s
    return target or sources[-1] if sources else "—"

def _calc_domain_age(created_str):
    """Calculate approximate domain age in years."""
    import re
    if not created_str:
        return "—"
    m = re.match(r'(\d{4})', created_str)
    if m:
        try:
            age = 2026 - int(m.group(1))
            return f"{age} years"
        except:
            pass
    return created_str

# ─── MAIN CORRELATION ENGINE ──────────────────────────────────────────

def correlate(results):
    sections = []

    # ── HEADER ──────────────────────────────────────────────────────
    sections.append(f"\n{_c('M', '█' * 78)}")
    sections.append(f"{_c('BD', '')}{_c('M', '  H A C K I T   F R A M E W O R K   U L T I M A T E')}")
    sections.append(f"{_c('BD', '')}{_c('M', '  F U L L   R E C O N N A I S S A N C E   M A P P I N G')}")
    sections.append(f"{_c('M', '█' * 78)}")

    for res in results:
        url = _str(res, "url", "N/A")
        domain = url.replace("https://", "").replace("http://", "").split("/")[0] if url != "N/A" else "N/A"

        # Pre-extract all data bags
        w       = _dict(res, "whois")
        dns     = _dict(res, "dns_enum")
        dns_s   = _dict(res, "dns")
        techs   = _dict(res, "technologies")
        hdrs    = _dict(res, "headers")
        waf     = _dict(res, "waf")
        wa      = _dict(res, "web_audit")
        ssl     = _dict(res, "ssl_analysis")
        cert    = _dict(ssl, "certificate")
        tr      = _dict(res, "tech_report")
        api     = _dict(res, "api_discovery")
        threat  = _dict(res, "threat_intel")
        way     = _dict(res, "wayback")
        ha      = _dict(res, "header_analysis")
        dh      = _dict(res, "dns_history")
        pdns    = _dict(res, "passive_dns")
        osint   = _dict(res, "osint_data")
        infra   = _dict(res, "infra_forensics")
        origin  = _dict(res, "origin_discovery")
        contacts = _dict(res, "scraped_contacts")
        netlist = _list(res, "network")
        nf      = netlist[0] if netlist else {}
        cms_cloud = _dict(res, "cms_cloud")
        cc_assets = _dict(cms_cloud, "cloud_assets")

        ip        = _str(res, "ip")
        asn_val   = _str(nf, "asn") or "—"
        asn_org   = _str(nf, "org") or ""
        asn_route = _str(nf, "asn_route") or ""
        asn_cc    = _str(nf, "asn_country") or ""
        geo       = _str(nf, "geo") or ""
        geo_city  = _str(nf, "geo_city") or ""
        geo_region = _str(nf, "geo_region") or ""
        geo_country = _str(nf, "geo_country") or ""
        isp       = _str(nf, "isp") or ""
        net_owner = _str(nf, "net_owner") or ""
        net_notes = _str(nf, "notes") or ""
        nf_proxy  = nf.get("proxy")
        nf_mobile = nf.get("mobile")
        nf_os     = _str(nf, "os") or ""

        # Common derived values
        ns_list   = _list(dns, "nameservers") or _list(dns, "ns")
        txt_list  = _list(dns, "txt") or _list(dns_s, "txt")
        spf_r     = "Not configured"
        dmarc_r   = "Not configured"
        dkim_r    = "Not configured"
        for t in txt_list:
            tl = t.lower()
            if "v=spf1" in tl:      spf_r = t
            if "v=dmarc1" in tl or "dmarc" in tl: dmarc_r = t
            if "v=dkim" in tl or "dkim" in tl:    dkim_r = t

        mx_targets = _list(dns, "mx") or _list(dns_s, "mx")
        email_route = "Unknown"
        for mx in mx_targets:
            ml = mx.lower()
            if "google" in ml:                         email_route = "Google Workspace"
            elif "outlook" in ml or "microsoft" in ml: email_route = "Microsoft 365"
            elif "amazonses" in ml or "aws" in ml:     email_route = "Amazon SES"
            elif "cloudflare" in ml:                   email_route = "Cloudflare Email Routing"
            elif "hetzner" in ml:                      email_route = "Hetzner"
            elif "mailgun" in ml:                      email_route = "Mailgun"

        can_spoof = False
        if "v=spf1" in spf_r and "-all" not in spf_r and "~all" not in spf_r: can_spoof = True
        if "p=none" in dmarc_r: can_spoof = True

        # ====================================================================
        # POIN 1: TARGET IDENTITY & REGISTRATION
        # ====================================================================
        s = _section("TARGET IDENTITY & REGISTRATION", "1")

        s += _sub("1.1", "Domain Overview")
        s += _field("Target URL", url)
        s += _tag("Page Title", _str(res, "title"), "C")
        s += _tag("Description", _str(res, "description", "No brief available."), "GR")
        s += _tag("Industry Classification", _str(res, "industry", "General Technology / Internet Services"), "B")

        s += _sub("1.2", "Registrar Details")
        registrar = _str(w, "registrar") or _str(w, "org") or "—"
        s += _field("Registrar", registrar)
        s += _field("IANA ID", _str(w, "iana_id"))
        s += _field("WHOIS Server", _str(w, "whois_server"))
        s += _field("Abuse Contact", _str(w, "abuse"))
        s += _field("WHOIS Privacy", _c('Y', "Enabled (REDACTED)") if w.get("privacy_enabled") else _c('G', "Disabled (Public)"))

        s += _sub("1.3", "Registrant Contact")
        s += _field("Registrant Name", _str(w, "registrant_name"))
        s += _field("Registrant Organization", _str(w, "org"))
        s += _field("Registrant ID", _str(w, "registrant_id"))
        s += _field("Registrant Email", _str(w, "email") or _join(_list(contacts, "emails"), "—"))
        s += _field("Phone", _str(w, "phone"))
        s += _field("Address", _str(w, "address"))

        s += _sub("1.4", "Administrative & Technical Contacts")
        s += _field("Admin Email", _str(w, "admin_email"))
        s += _field("Admin Organization", _str(w, "admin_org"))
        s += _field("Admin Phone", _str(w, "admin_phone"))
        s += _field("Tech Email", _str(w, "tech_email"))
        s += _field("Tech Organization", _str(w, "tech_org"))
        s += _field("Tech Phone", _str(w, "tech_phone"))

        s += _sub("1.5", "Domain Timeline & Lifecycle")
        created = _str(w, "created")
        updated = _str(w, "updated")
        expires = _str(w, "expires")
        s += _field("Created", created)
        s += _field("Updated", updated)
        s += _field("Expires", expires)
        s += _field("Domain Age", _calc_domain_age(created))
        if created and expires:
            s += _field("Expiry Status", _c('G', "Active") if "202" in expires else _c('R', "Expired / Unknown"))

        s += _sub("1.6", "DNS Security & Domain Config")
        s += _field("DNSSEC", _str(w, "dnssec"))
        s += _multi_field("Name Servers (WHOIS)", _list(w, "name_servers"))
        s += _multi_field("Domain Statuses", _list(w, "domain_statuses"))
        s += _multi_field("Aliases / Also-Known-As", _list(w, "aliases") or _list(res, "aliases"))

        sections.append(s)

        # ====================================================================
        # POIN 2: NETWORK INFRASTRUCTURE & ROUTING
        # ====================================================================
        s = _section("NETWORK INFRASTRUCTURE & ROUTING", "2")

        s += _sub("2.1", "IP Addressing")
        all_v4 = _list(dns, "a") or _list(dns_s, "a")
        all_v6 = _list(dns, "aaaa")
        s += _field("Primary IPv4 (used)", ip if ip else _join(all_v4))
        s += _multi_field("All A Records (IPv4)", all_v4)
        s += _multi_field("AAAA Records (IPv6)", all_v6)
        s += _field("Total IPs Resolved", str(len(set(all_v4 + all_v6))))

        s += _sub("2.2", "ASN & BGP Routing")
        s += _field("ASN", asn_val)
        if asn_org:
            s += _field("AS Organization", asn_org)
        if asn_route:
            s += _field("AS Route (CIDR)", asn_route)
        s += _field("ASN Country", asn_cc)
        s += _field("Net Owner", net_owner)

        s += _sub("2.3", "Geographic Location")
        s += _field("Full Geo", geo)
        if geo_city:
            s += _field("City", geo_city)
        if geo_region:
            s += _field("Region / State", geo_region)
        if geo_country:
            s += _field("Country", geo_country)

        s += _sub("2.4", "Hosting & Connectivity")
        s += _field("ISP", isp)
        s += _field("ISP / Net Owner", net_owner)
        s += _field("Hosting Type", _str(nf, "hosting"))
        s += _field("Proxy / VPN Detected", _c('R', "Yes") if nf_proxy else _c('G', "No"))
        s += _field("Mobile Network", _c('Y', "Yes") if nf_mobile else _c('G', "No"))
        if nf_os:
            s += _field("Remote OS (passive)", nf_os)
        if net_notes:
            s += _field("Infrastructure Notes", net_notes)

        s += _sub("2.5", "CDN / WAF / Proxy Layer")
        cdn_provider = _str(waf, "provider", "Direct")
        s += _field("CDN / Reverse Proxy", cdn_provider)
        s += _field("WAF Type", _str(waf, "waf_type"))
        waf_detected = waf.get("detected")
        s += _tag("WAF Detected", "Yes" if waf_detected else "No", "R" if waf_detected else "G")
        origin_ip = _str(origin, "origin_ip")
        if origin_ip:
            s += _field("Origin IP (uncovered)", origin_ip)
        else:
            s += _tag("Origin IP", "Hidden behind CDN", "GR")
        if hdrs:
            for cdn_hdr in ["CF-Ray", "CF-Cache-Status", "X-Amz-Cf-Id", "X-Cache", "X-Sucuri-ID"]:
                if hdrs.get(cdn_hdr):
                    s += _field(f"CDN Header: {cdn_hdr}", hdrs[cdn_hdr])
        if hdrs and "Server" in hdrs and "cloudflare" in hdrs.get("Server", "").lower():
            s += _field("Cloudflare Data Center", hdrs.get("CF-Ray", "").split("-")[-1] if "-" in hdrs.get("CF-Ray", "") else "Unknown")

        sections.append(s)

        # ====================================================================
        # POIN 3: DNS RECORDS & MAIL SECURITY
        # ====================================================================
        s = _section("DNS RECORDS & EMAIL SECURITY", "3")

        s += _sub("3.1", "Nameservers")
        s += _multi_field("Authoritative NS", ns_list)

        s += _sub("3.2", "Address Records")
        s += _multi_field("A Records", _list(dns, "a") or _list(dns_s, "a"))
        s += _multi_field("AAAA Records", _list(dns, "aaaa"))
        s += _multi_field("CNAME Records", _list(dns, "cname"))
        s += _multi_field("SOA Record", [_str(dns, "soa")] if _str(dns, "soa") else [])

        s += _sub("3.3", "Mail Configuration & Security")
        s += _multi_field("MX Records", mx_targets)
        s += _field("Email Routing Platform", email_route)
        s += _field("SPF Record", spf_r)
        s += _field("DMARC Record", dmarc_r)
        s += _field("DKIM Record", dkim_r)
        # SPF analysis
        spf_analysis = "—"
        if "v=spf1" in spf_r:
            if "-all" in spf_r:
                spf_analysis = _c('G', "Hard-fail (most secure)")
            elif "~all" in spf_r:
                spf_analysis = _c('Y', "Soft-fail (moderate)")
            elif "?all" in spf_r:
                spf_analysis = _c('R', "Neutral (no protection)")
            else:
                spf_analysis = _c('R', "No fail mechanism — spoofable")
        s += _tag("SPF Hardening", spf_analysis.split("(")[0].strip() if "(" in str(spf_analysis) else spf_analysis, "G")
        # DMARC analysis
        dmarc_analysis = _c('GR', "Not configured — email spoofable")
        if "p=reject" in dmarc_r:
            dmarc_analysis = _c('G', "Reject policy (most secure)")
        elif "p=quarantine" in dmarc_r:
            dmarc_analysis = _c('Y', "Quarantine policy (moderate)")
        elif "p=none" in dmarc_r:
            dmarc_analysis = _c('R', "None policy — monitoring only")
        s += _tag("DMARC Policy Strength", dmarc_analysis, "G")
        s += _tag("Spoofing Risk", "VULNERABLE" if can_spoof else "Protected", "R" if can_spoof else "G")

        s += _sub("3.4", "Service & Infrastructure Records")
        srv_list = _list(dns, "srv")
        s += _multi_field("SRV Records", srv_list)
        caa_list = _list(dns, "caa")
        s += _multi_field("CAA Records", caa_list)
        s += _multi_field("TXT Records", txt_list)
        zone_xfer = _str(dns, "zone_transfer")
        if "REFUSED" in zone_xfer or "secure" in zone_xfer.lower():
            zone_tag = _c('G', "Protected (REFUSED)")
        elif zone_xfer:
            zone_tag = _c('R', zone_xfer)
        else:
            zone_tag = _c('GR', "Not tested")
        s += _tag("Zone Transfer (AXFR)", zone_tag, "G")

        sections.append(s)

        # ====================================================================
        # POIN 4: SSL/TLS CERTIFICATE & CIPHER SECURITY
        # ====================================================================
        s = _section("SSL/TLS CERTIFICATE & CIPHER SECURITY", "4")

        s += _sub("4.1", "Certificate Identity")
        s += _field("Common Name (CN)", _str(cert, "cn"))
        sans = _list(cert, "sans")
        s += _multi_field("Subject Alternative Names (SANs)", sans)

        s += _sub("4.2", "Issuance & Chain")
        s += _field("Issuer (CA Organization)", _str(cert, "issuer"))
        s += _field("Issuer Organization", _str(cert, "issuer_org"))
        s += _multi_field("Full Chain (Issuers)", _list(cert, "chain_issuers"))
        s += _field("Chain Length", _val(cert, "chain_length", "—"))
        s += _multi_field("OCSP Responders", _list(cert, "ocsp_server"))
        s += _multi_field("Issuer URLs", _list(cert, "issuer_url"))

        s += _sub("4.3", "Validity & Expiry")
        s += _field("Valid From", _str(cert, "validity_from"))
        s += _field("Valid Until", _str(cert, "validity_to"))
        days_left = _val(cert, "days_remaining", "—")
        if days_left != "—":
            try:
                dl = int(days_left)
                expiry_tag = "G" if dl > 30 else ("Y" if dl > 7 else "R")
                s += _tag("Days Remaining", f"{dl} days", expiry_tag)
            except:
                s += _field("Days Remaining", days_left)
        else:
            s += _field("Days Remaining", "—")
        expired = cert.get("expired")
        s += _tag("Expired", "YES (CRITICAL!)" if expired else "No (valid)", "R" if expired else "G")
        self_sig = cert.get("self_signed")
        s += _tag("Self-Signed", "Yes" if self_sig else "No", "R" if self_sig else "G")
        s += _field("Serial Number", _str(cert, "serial"))
        s += _field("Certificate Version", _val(cert, "version", "—"))

        s += _sub("4.4", "Key Usage & Extensions")
        s += _multi_field("Key Usage", _list(cert, "key_usage"))
        s += _multi_field("Extended Key Usage", _list(cert, "ext_key_usage"))
        s += _multi_field("CRL Distribution Points", _list(cert, "crl_distribution"))
        s += _tag("Is CA Certificate", "Yes" if cert.get("is_ca") else "No", "R" if cert.get("is_ca") else "G")
        mpl = cert.get("max_path_len", -1)
        if mpl >= 0:
            s += _field("Max Path Length", str(mpl))
        s += _multi_field("Certificate Policy OIDs", _list(cert, "policy_ids"))
        s += _multi_field("Permitted DNS Domains", _list(cert, "permitted_domains"))
        s += _multi_field("Excluded DNS Domains", _list(cert, "excluded_domains"))

        s += _sub("4.5", "Cryptographic Parameters")
        tls_v   = _str(cert, "tls_version")
        cipher  = _str(cert, "cipher_suite")
        pk      = _str(cert, "public_key")
        pk_sz   = _val(cert, "public_key_size", "—")
        sig     = _str(cert, "sig_algorithm")
        s += _tag("TLS Version", tls_v, "G" if "1.3" in tls_v else ("Y" if "1.2" in tls_v else "R"))
        s += _tag("Cipher Suite", cipher, "G" if "GCM" in cipher or "CHACHA20" in cipher else "Y")
        s += _field("Public Key Algorithm", f"{pk} ({pk_sz} bits)" if pk_sz != "—" else pk)
        s += _field("Public Key Size", pk_sz if pk_sz != "—" else "—")
        s += _field("Signature Algorithm", sig)

        s += _sub("4.6", "Fingerprints")
        s += _field("SHA-1 Fingerprint", _str(cert, "fingerprint_sha1"))
        s += _field("SHA-256 Fingerprint", _str(cert, "fingerprint_sha256"))

        s += _sub("4.7", "Protocol & Vulnerability Audit")
        protos = _str(ssl, "protocols")
        vulns  = _str(ssl, "vulns")
        if protos:
            s += _field("Protocol Support", protos)
        if vulns:
            # Parse vulnerabilities for summary
            vuln_lines = [l.strip() for l in vulns.split("\n") if "MITIGATED" in l or "NOT_APPLICABLE" in l or "VULNERABLE" in l or "INSECURE" in l]
            if vuln_lines:
                for vl in vuln_lines[:20]:
                    parts = vl.split(":")
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        status_raw = parts[1].strip()
                        if "MITIGATED" in status_raw or "NOT_APPLICABLE" in status_raw:
                            status = _c('G', status_raw)
                        elif "VULNERABLE" in status_raw or "INSECURE" in status_raw:
                            status = _c('R', status_raw)
                        else:
                            status = _c('Y', status_raw)
                        s += f"    {_c('Y', name)}: {status}\n"
                    else:
                        s += f"    {vl}\n"
            else:
                s += _field("Vulnerabilities", vulns)

        sections.append(s)

        # ====================================================================
        # POIN 5: WEB APPLICATION & TECHNOLOGY STACK
        # ====================================================================
        s = _section("WEB APPLICATION & TECHNOLOGY STACK", "5")

        s += _sub("5.1", "HTTP Response Overview")
        status_code = res.get("status", 0)
        st_tag = "G" if status_code == 200 else ("Y" if 300 <= status_code < 400 else "R")
        s += _tag("HTTP Status", str(status_code), st_tag)
        s += _tag("Page Title", _str(res, "title"), "C")
        s += _tag("Server Header", _str(res, "server") or "—", "W")
        s += _tag("X-Powered-By", _str(tr, "backend") or _str(hdrs, "X-Powered-By") or "—", "B")

        s += _sub("5.2", "All HTTP Response Headers")
        if hdrs:
            for hdr_name in sorted(hdrs.keys()):
                val = hdrs[hdr_name]
                # Truncate very long header values
                if len(val) > 120:
                    val = val[:117] + "..."
                # Color security headers
                hdr_lower = hdr_name.lower()
                if hdr_lower in ("content-security-policy", "x-frame-options", "strict-transport-security"):
                    s += f"    {_c('G', hdr_name)}: {val}\n"
                elif hdr_lower in ("set-cookie", "x-powered-by", "server"):
                    s += f"    {_c('Y', hdr_name)}: {val}\n"
                elif hdr_lower.startswith("x-"):
                    s += f"    {_c('C', hdr_name)}: {val}\n"
                elif hdr_lower.startswith("cf-"):
                    s += f"    {_c('B', hdr_name)}: {val}\n"
                else:
                    s += f"    {_c('GR', hdr_name)}: {val}\n"

        s += _sub("5.3", "Security Headers Assessment")
        sec_headers = {
            "Content-Security-Policy":     ("CSP",          "R"),
            "X-Frame-Options":             ("XFO",          "R"),
            "Strict-Transport-Security":   ("HSTS",         "R"),
            "X-Content-Type-Options":      ("XCTO",         "Y"),
            "Permissions-Policy":          ("Permissions",  "Y"),
            "Referrer-Policy":             ("Referrer",     "Y"),
            "Access-Control-Allow-Origin": ("CORS",         "Y"),
        }
        for hdr, (lab, severity) in sec_headers.items():
            val = ha.get(lab) if ha else hdrs.get(hdr, "")
            if val and val not in ("MISSING", "Not set"):
                s += f"    {_c('G', f'✓ {hdr}')}: {val}\n"
            else:
                if severity == "R":
                    s += f"    {_c('R', f'✗ {hdr}')}: MISSING — HIGH RISK\n"
                else:
                    s += f"    {_c('Y', f'✗ {hdr}')}: Not set — MEDIUM RISK\n"

        if wa:
            cookies = _list(wa, "cookies")
            if cookies:
                s += _multi_field("Cookies", cookies)
            unexpected = _list(wa, "unexpected")
            if unexpected:
                s += _multi_field("Warning — Debug / Unexpected Headers", unexpected)
            grade = _str(wa, "grade", "F")
            grade_tag = "G" if grade in ("A", "A+", "B") else ("Y" if grade in ("C", "D") else "R")
            s += _tag("Security Grade", grade, grade_tag)

        s += _sub("5.4", "Frontend Technologies")
        s += _field("Frontend Framework", _str(tr, "frontend"))
        s += _field("WebSockets Support", _c('G', "Yes") if tr.get("web_sockets") else _c('GR', "No / Not detected"))
        js_libs = _list(tr, "js_libs")
        if js_libs:
            s += _multi_field("JavaScript Libraries", [j.get("name", str(j)) if isinstance(j, dict) else str(j) for j in js_libs])
        else:
            s += _field("JavaScript Libraries", _c('GR', "None detected"))
        css = _list(tr, "css_frameworks")
        if css:
            s += _multi_field("CSS Frameworks", [c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in css])
        else:
            s += _field("CSS Frameworks", _c('GR', "None detected"))
        build = _list(tr, "build_tools")
        if build:
            s += _multi_field("Build Tools / Bundlers", [b.get("name", str(b)) if isinstance(b, dict) else str(b) for b in build])
        ssg = _str(tr, "ssg")
        if ssg:
            s += _field("Static Site Generator", ssg)

        s += _sub("5.5", "Backend Technologies")
        s += _field("Backend Framework", _str(tr, "backend"))
        s += _field("Web Server", _str(tr, "web_server") or _str(res, "server"))
        s += _field("Reverse Proxy", _str(tr, "reverse_proxy"))
        s += _field("Programming Language", _str(tr, "programming_lang"))
        s += _field("Database", _str(tr, "database"))
        s += _field("Operating System", _str(tr, "os"))

        s += _sub("5.6", "CMS & Content Management")
        s += _field("CMS", _str(tr, "cms"))
        s += _field("E-Commerce Platform", _str(tr, "ecommerce"))
        s += _field("Cache Plugin / CDN Cache", _str(tr, "cache_plugin"))

        s += _sub("5.7", "Analytics, Tracking & Third-Party")
        analytics = _list(tr, "analytics")
        if analytics:
            s += _multi_field("Analytics / Trackers", [a.get("name", str(a)) if isinstance(a, dict) else str(a) for a in analytics])
        s += _field("Tag Manager", _str(tr, "tag_manager"))
        payments = _list(tr, "payment_gateways")
        if payments:
            s += _multi_field("Payment Gateways", [p.get("name", str(p)) if isinstance(p, dict) else str(p) for p in payments])
        chats = _list(tr, "chat_widgets")
        if chats:
            s += _multi_field("Chat Widgets / Live Support", [c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in chats])
        s += _field("CDN (Tech Report)", _str(tr, "cdn") or _str(waf, "provider"))

        sections.append(s)

        # ====================================================================
        # POIN 6: SECURITY POSTURE & FORENSICS
        # ====================================================================
        s = _section("SECURITY POSTURE & FORENSICS", "6")

        s += _sub("6.1", "Web Application Firewall & CDN")
        s += _field("Provider", _str(waf, "provider"))
        s += _tag("WAF Detected", "Yes" if waf.get("detected") else "No", "G" if not waf.get("detected") else "Y")
        s += _field("WAF Type", _str(waf, "waf_type"))

        s += _sub("6.2", "Cookie & Session Security")
        auth = _str(res, "auth_session", "")
        if auth:
            if "No cookies" in auth:
                s += _c('GR', "  No cookies set in response.\n")
            elif "JWT" in auth:
                s += _c('R', "  JWTs detected — verify token security\n")
            if "CSRF" in auth:
                s += _field("CSRF Protection", "Not detected" if "No CSRF" in auth else "Detected")
        else:
            s += _c('GR', "  No session data available.\n")
        if wa:
            cookies = _list(wa, "cookies")
            if cookies:
                for ck in cookies:
                    secure = "Secure" in ck
                    httponly = "HttpOnly" in ck
                    samesite = "SameSite" in ck
                    flags = []
                    if secure:   flags.append(_c('G', "Secure"))
                    if httponly: flags.append(_c('G', "HttpOnly"))
                    if samesite: flags.append(_c('G', "SameSite"))
                    if not flags:
                        flags.append(_c('R', "INSECURE — missing flags"))
                    s += f"    {_c('Y', 'Cookie')}: {ck[:60]}... | {', '.join(flags)}\n"

        s += _sub("6.3", "Entropy & Payload Analysis")
        forensics = _str(res, "forensics", "")
        entropy_found = False
        for line in forensics.split("\n"):
            l = line.strip()
            if "entropy" in l.lower():
                try:
                    e_val = l.split(":")[-1].strip()
                    s += _field("Body Entropy", e_val)
                    entropy_found = True
                except:
                    pass
            if "Risk" in l and "level" in l.lower():
                s += _field("Forensic Risk Level", l.split(":")[-1].strip())
            if "secrets" in l.lower() or "secret" in l.lower():
                s += _c('Y', f"  {l}\n")
        if not entropy_found:
            s += _c('GR', "  Entropy analysis: Not available\n")

        s += _sub("6.4", "Security Header Warnings & Leaks")
        if forensics:
            for line in forensics.split("\n"):
                l = line.strip()
                if "[MISSING" in l or "[MISSING DEBUG" in l:
                    parts = l.split("]")
                    if len(parts) >= 2:
                        severity = parts[-1].strip().strip("()")
                        sev_tag = "R" if "HIGH" in severity else ("Y" if "MEDIUM" in severity else "GR")
                        s += f"    {_c(sev_tag, parts[0].strip() + ']')} {_c(sev_tag, severity)}\n"
                elif "[MISSING INFO]" in l:
                    s += f"    {_c('Y', l.strip())}\n"

        sections.append(s)

        # ====================================================================
        # POIN 7: DNS HISTORY & PASSIVE RECONNAISSANCE
        # ====================================================================
        s = _section("DNS HISTORY & PASSIVE RECONNAISSANCE", "7")

        s += _sub("7.1", "Historical DNS Records")
        hist_a = _list(dh, "historical_a") or _list(osint, "hackertarget_ips")
        s += _multi_field("Historical A Records", hist_a)
        s += _multi_field("Historical NS Records", _list(dh, "historical_ns"))
        s += _multi_field("Historical MX Records", _list(dh, "historical_mx"))

        s += _sub("7.2", "Certificate Transparency (CT Logs)")
        crtsh = _list(osint, "crtsh_subdomains")
        s += _multi_field("Subdomains from crt.sh", crtsh)

        s += _sub("7.3", "Passive DNS Intelligence")
        internal = _list(pdns, "possible_internal_domains")
        s += _multi_field("Possible Internal / Non-Routed", internal)
        last_seen = _list(pdns, "last_seen_ips")
        s += _multi_field("Last Seen IPs (Passive DNS)", last_seen)

        # Lua / Ruby plugin data
        lua_out = _str(res, "lua_tech", "")
        if lua_out:
            s += _sub("7.4", "Lua Plugin Extras")
            for item in lua_out.split("|"):
                if item.strip():
                    s += _field("Lua Detected", item.strip())

        sections.append(s)

        # ====================================================================
        # POIN 8: SUBDOMAINS & ASSET DISCOVERY
        # ====================================================================
        s = _section("SUBDOMAINS & ASSET DISCOVERY", "8")

        subdomains_found = []
        web_techs = []
        for name, info in techs.items():
            cat = info.get("category", "")
            if "infrastructure" in cat.lower() or "subdomain" in cat.lower():
                subdomains_found.append(f"{name} → {_str(info, 'version', 'Unknown source')}")
            else:
                web_techs.append((name, info))

        s += _sub("8.1", "Discovered Subdomains")
        s += _multi_field("All Subdomains", subdomains_found)

        s += _sub("8.2", "Technology Distribution by Subdomain")
        for name, info in web_techs:
            ver = info.get("version", "")
            conf = info.get("confidence", 0)
            cat = info.get("category", "")
            line = f"  {_c('C', '•')} {_c('W', name)}"
            if ver:
                line += f" {_c('GR', f'v{ver}')}"
            line += f" {_c('GR', f'[{cat}]')} {_c('GR', f'(confidence: {conf}%)')}"
            s += line + "\n"

        s += _sub("8.3", "Cloud & Shadow Assets")
        if cc_assets:
            for b in _list(cc_assets, "s3_buckets"):
                s += f"    {_c('Y', 'AWS S3')}: {b}\n"
            for b in _list(cc_assets, "gcp_buckets"):
                s += f"    {_c('Y', 'GCP Storage')}: {b}\n"
            for b in _list(cc_assets, "firebase"):
                s += f"    {_c('Y', 'Firebase')}: {b}\n"
            gh = _str(cc_assets, "github_org")
            if gh:
                s += f"    {_c('Y', 'GitHub Org')}: {gh}\n"
        else:
            s += _c('GR', "    None discovered via passive methods\n")

        s += _sub("8.4", "Third-Party Integrations")
        tp = _str(res, "third_party")
        if tp and "No third-party" not in tp and "Total third-party" not in tp:
            for line in tp.split("\n"):
                if line.strip():
                    s += f"    {_c('C', '•')} {line.strip()}\n"
        else:
            s += _c('GR', "    None discovered\n")

        sections.append(s)

        # ====================================================================
        # POIN 9: ARCHIVED & HISTORICAL WEB DATA
        # ====================================================================
        s = _section("ARCHIVED & HISTORICAL WEB DATA", "9")

        s += _sub("9.1", "Wayback Machine (Internet Archive)")
        snapshots = way.get("snapshots", 0)
        if snapshots and snapshots > 0:
            s += _field("Total Snapshots", str(snapshots))
            s += _field("Oldest Snapshot", _str(way, "oldest_snapshot"))
            s += _field("Newest Snapshot", _str(way, "newest_snapshot"))
            way_urls = _list(way, "urls")
            if way_urls:
                s += _multi_field("Historical URLs (Wayback)", way_urls[:20])
        else:
            s += _c('GR', "  No Wayback Machine snapshots found for this domain.\n")

        s += _sub("9.2", "CommonCrawl Coverage")
        cc = _dict(way, "commoncrawl")
        if cc:
            s += _c('G', "  ✓ CommonCrawl data available\n")
            cc_urls = _list(cc, "urls")
            if cc_urls:
                s += _multi_field("CommonCrawl URLs", cc_urls[:10])
        else:
            s += _c('GR', "  No CommonCrawl data available.\n")

        s += _sub("9.3", "Forgotten / Orphaned Paths")
        forgotten = _list(way, "forgotten_paths")
        if forgotten:
            s += _multi_field("Orphaned Paths (potential info leak)", forgotten)
        else:
            s += _c('GR', "  None discovered.\n")

        sections.append(s)

        # ====================================================================
        # POIN 10: THREAT INTELLIGENCE
        # ====================================================================
        s = _section("THREAT INTELLIGENCE & INCIDENT HISTORY", "10")

        s += _sub("10.1", "VirusTotal")
        vt = _dict(threat, "virustotal")
        s += _field("Detections", str(vt.get("detections", 0)))
        s += _field("Malicious Flag", _c('R', "YES") if vt.get("malicious") else _c('G', "No"))

        s += _sub("10.2", "AlienVault OTX")
        av_data = _dict(threat, "alienvault")
        av_urls = _list(av_data, "urls")
        if av_urls:
            s += _multi_field("URLs from OTX", av_urls)
        s += _field("Malware Association", _c('R', "Yes") if av_data.get("malware") else _c('G', "No"))

        s += _sub("10.3", "SecurityTrails")
        st = _dict(threat, "securitytrails")
        st_subs = _list(st, "subdomains")
        if st_subs:
            s += _multi_field("Subdomains from SecurityTrails", st_subs)
        else:
            s += _c('GR', "  No SecurityTrails data available.\n")

        s += _sub("10.4", "URLScan.io")
        urlscan_urls = _list(threat, "urlscan")
        if urlscan_urls:
            s += _multi_field("Recent Scan Results", urlscan_urls)
        else:
            s += _c('GR', "  No URLScan.io data available.\n")

        s += _sub("10.5", "Blacklist & Reputation")
        s += _field("Blacklisted", _c('R', "Yes") if threat.get("blacklisted") else _c('G', "No"))
        if threat.get("blacklisted"):
            s += _multi_field("Blacklist Sources", _list(threat, "blacklist_sources"))
        s += _field("Phishing Detected", _c('R', "Yes") if threat.get("phishing_detected") else _c('G', "No"))
        s += _field("HaveIBeenPwned", _c('R', "Breached") if threat.get("haveibeenpwned") else _c('G', "Not found"))

        sections.append(s)

        # ====================================================================
        # POIN 11: CONTACT DISCOVERY & SOCIAL PRESENCE
        # ====================================================================
        s = _section("CONTACT DISCOVERY & SOCIAL PRESENCE", "11")

        s += _sub("11.1", "Emails")
        emails = _list(contacts, "emails")
        s += _multi_field("Emails from Page", emails)
        ruby_emails_raw = _str(res, "ruby_emails")
        if ruby_emails_raw and ruby_emails_raw.startswith("{"):
            try:
                re_data = json.loads(ruby_emails_raw)
                if re_data.get("emails"):
                    s += _multi_field("Additional Emails (Ruby)", re_data["emails"])
            except (json.JSONDecodeError, TypeError):
                pass

        s += _sub("11.2", "Phones")
        s += _multi_field("Phones from Page", _list(contacts, "phones"))

        s += _sub("11.3", "Social Media Profiles")
        body = _str(res, "body", "").lower()
        socials = []
        if "twitter.com/" in body or "x.com/" in body:     socials.append("Twitter / X")
        if "linkedin.com/company/" in body:                 socials.append("LinkedIn")
        if "github.com/" in body:                           socials.append("GitHub")
        if "facebook.com/" in body:                         socials.append("Facebook")
        if "instagram.com/" in body:                        socials.append("Instagram")
        if "youtube.com/" in body:                          socials.append("YouTube")
        if "tiktok.com/" in body:                           socials.append("TikTok")
        if "reddit.com/" in body:                           socials.append("Reddit")
        if "medium.com/" in body:                           socials.append("Medium")
        if "discord.com/" in body or "discord.gg/" in body: socials.append("Discord")
        if "telegram" in body:                              socials.append("Telegram")
        if "whatsapp.com/" in body:                         socials.append("WhatsApp")
        s += _multi_field("Profiles Found", socials)

        s += _sub("11.4", "Ruby Cloud & JS Plugin Data")
        ruby_cloud_raw = _str(res, "ruby_cloud")
        if ruby_cloud_raw and ruby_cloud_raw.startswith("{"):
            try:
                rc = json.loads(ruby_cloud_raw)
                providers = rc.get("providers", [])
                if providers:
                    s += _multi_field("Cloud Providers (Ruby)", providers)
                cdn = rc.get("cdn")
                if cdn is not None:
                    s += _field("CDN (Ruby)", _c('G', "Yes") if cdn else _c('GR', "No"))
                details = rc.get("details", {})
                for k, v in details.items():
                    if v:
                        s += _field(f"Cloud Detail: {k}", str(v))
            except (json.JSONDecodeError, TypeError):
                pass

        sections.append(s)

        # ====================================================================
        # POIN 12: API & ENDPOINT ANALYSIS
        # ====================================================================
        s = _section("API & ENDPOINT ANALYSIS", "12")

        s += _sub("12.1", "API Endpoint Discovery")
        api_endpoints = _list(api, "endpoints")
        if api_endpoints:
            s += _multi_field("API Endpoints Found", api_endpoints)
        else:
            s += _c('GR', "  No API endpoints discovered in page source / JS.\n")

        s += _sub("12.2", "API Type Detection")
        s += _tag("RESTful API", "Yes" if api.get("restful") else "Not detected", "G" if api.get("restful") else "GR")
        s += _tag("GraphQL", "Yes (introspection possible?)" if api.get("graphql") else "Not detected", "R" if api.get("graphql") else "GR")
        s += _field("OpenAPI / Swagger", _str(api, "spec_files"))
        s += _field("API Versions", _str(api, "api_versions"))
        s += _field("Auth Mechanisms", _str(api, "auth_mechanisms"))

        s += _sub("12.3", "Fuzzing & Hidden Endpoints")
        fp_results = _list(res, "endpoints")
        if fp_results:
            s += _multi_field("Discovered Paths (fuzz / passive)", fp_results)
            sensitive_paths = [p for p in fp_results if any(s in p.lower() for s in
                              [".env", ".git", "backup", "admin", "debug", "config",
                               "wp-", "graphql", "swagger", "api-docs", "phpinfo",
                               "server-status", "actuator", ".svn", ".ds_store"])]
            if sensitive_paths:
                s += _c('R', "  ⚠ Potential sensitive files discovered:\n")
                for sp in sensitive_paths[:10]:
                    s += f"    {_c('R', sp)}\n"
        else:
            s += _c('GR', "  Active fuzzing not executed (passive mode).\n")

        sections.append(s)

        # ====================================================================
        # POIN 13: INFRASTRUCTURE DIAGRAM
        # ====================================================================
        s = _section("INFRASTRUCTURE DIAGRAM", "13")

        cdn_detected = waf.get("detected") and _str(waf, "provider") != "Direct"
        cdn_name = _str(waf, "provider", "Unknown CDN") if cdn_detected else "No CDN"
        backend = _str(tr, "backend", "Unknown")
        web_srv = _str(tr, "web_server") or _str(res, "server") or "Unknown"
        rev_proxy = _str(tr, "reverse_proxy", "Unknown")
        api_status = "Detected" if api.get("restful") or api.get("graphql") else "Not detected"
        cms_name = _str(tr, "cms", "Unknown")
        db_name = _str(tr, "database", "inferred")
        issuer_n = _str(cert, "issuer", "Unknown CA")

        diagram = f"""
  {_c('W', 'Internet')}
      {_c('GR', '|')}
      {_c('GR', 'v')}
  [{_c('BD', '')}{_c('B' if cdn_detected else 'GR', cdn_name)}]
      {_c('GR', '|')}
      {_c('GR', 'v')}
  [{_c('BD', '')}{_c('C', f'Load Balancer / Reverse Proxy ({rev_proxy})')}]
      {_c('GR', '|')}
      {_c('GR', 'v')}
  [{_c('BD', '')}{_c('M', f'Web Server ({web_srv})')}]
      {_c('GR', '|')}
      {_c('GR', '+--')} [{_c('BD', '')}{_c('Y', f'Application ({backend})')}]
      {_c('GR', '|')}        {_c('GR', '|')}
      {_c('GR', '|')}        {_c('GR', '+--')} [{_c('BD', '')}{_c('M', f'API ({api_status})')}]
      {_c('GR', '|')}        {_c('GR', '|')}
      {_c('GR', '|')}        {_c('GR', '+--')} [{_c('BD', '')}{_c('C', f'CMS ({cms_name})')}]
      {_c('GR', '|')}
      {_c('GR', '+--')} [{_c('BD', '')}{_c('B', f'Database ({db_name})')}]
      {_c('GR', '|')}
      {_c('GR', '+--')} [{_c('BD', '')}{_c('W', f'DNS: {len(ns_list)} nameservers')}]
      {_c('GR', '|')}
      {_c('GR', '+--')} [{_c('BD', '')}{_c('G', f'Mail: {email_route}')}]
      {_c('GR', '|')}
      {_c('GR', '+--')} [{_c('BD', '')}{_c('C', f'SSL: {issuer_n}')}]
"""
        s += diagram

        # Security summary at bottom
        s += _sub("13.1", "Security Summary")

        # Count missing security headers
        missing_critical = 0
        missing_medium = 0
        for hdr, (lab, _) in sec_headers.items():
            val = ha.get(lab) if ha else hdrs.get(hdr, "")
            if not val or val in ("MISSING", "Not set"):
                if lab in ("CSP", "HSTS", "XFO"):
                    missing_critical += 1
                else:
                    missing_medium += 1

        s += _tag("Missing Critical Security Headers", str(missing_critical), "R" if missing_critical > 0 else "G")
        s += _tag("Missing Medium Security Headers", str(missing_medium), "Y" if missing_medium > 0 else "G")

        headers_grade = "A" if missing_critical == 0 and missing_medium <= 1 else \
                        "B" if missing_critical == 0 else \
                        "C" if missing_critical <= 1 else "F"
        hg_tag = "G" if headers_grade in ("A", "B") else ("Y" if headers_grade == "C" else "R")
        s += _tag("Headers Security Grade", headers_grade, hg_tag)

        tls_grade = "A"
        tls_v_str = _str(cert, "tls_version")
        if tls_v_str and "1.3" in tls_v_str:
            tls_grade = "A"
        elif tls_v_str and "1.2" in tls_v_str:
            tls_grade = "B"
        else:
            tls_grade = "C"
        tg = "G" if tls_grade == "A" else ("Y" if tls_grade == "B" else "R")
        s += _tag("TLS Security Grade", tls_grade, tg)

        email_grade = "A" if not can_spoof and email_route != "Unknown" else \
                      "B" if not can_spoof else "F"
        eg = "G" if email_grade in ("A", "B") else "R"
        s += _tag("Email Security Grade", email_grade, eg)

        sections.append(s)

        # ====================================================================
        # POIN 14: PLUGIN EXTENSIONS (Lua & Ruby)
        # ====================================================================
        s = _section("PLUGIN EXTENSIONS (LUA & RUBY)", "14")
        plugin_results = _dict(res, "plugin_results")

        if plugin_results:
            # Lua plugins
            lua_checks = [
                ("lua_csp_analyzer", "CSP Analyzer"),
                ("lua_link_extractor", "Link Extractor"),
                ("lua_seo_scanner", "SEO Scanner"),
                ("lua_pwa_detector", "PWA Detector"),
                ("lua_form_scanner", "Form Scanner"),
                ("lua_meta_extractor", "Meta Extractor"),
                ("lua_security_header_analyzer", "Security Header Analyzer"),
            ]
            s += _sub("14.1", "Lua Plugins")
            for key, label in lua_checks:
                raw = plugin_results.get(key, "")
                if raw:
                    try:
                        data = json.loads(raw)
                        if isinstance(data, dict) and data.get("status") == "ok":
                            s += f"  {_c('G', f'✓ {label}')}\n"
                            for k, v in data.items():
                                if k == "status": continue
                                if isinstance(v, list) and len(v) > 0:
                                    s += _multi_field(f"  {k}", v[:10])
                                elif isinstance(v, str) and v:
                                    s += f"    {_c('Y', k)}: {_c('W', str(v)[:100])}\n"
                        else:
                            err = data.get("error", "Unknown error") if isinstance(data, dict) else "Invalid output"
                            s += f"  {_c('R', f'✗ {label}')}: {_c('GR', err)}\n"
                    except (json.JSONDecodeError, TypeError):
                        s += f"  {_c('Y', f'? {label}')}: {_c('GR', str(raw)[:80])}\n"
                else:
                    s += f"  {_c('GR', f'— {label}: No data')}\n"

            # Ruby plugins
            ruby_checks = [
                ("ruby_dns_bruteforcer", "DNS Bruteforcer"),
                ("ruby_tech_fingerprinter", "Tech Fingerprinter"),
                ("ruby_content_security_checker", "Content Security Checker"),
                ("ruby_link_discovery", "Link Discovery"),
                ("ruby_waf_detector", "WAF Detector"),
                ("ruby_cms_detector", "CMS Detector"),
                ("ruby_cdn_detector", "CDN Detector"),
            ]
            s += _sub("14.2", "Ruby Plugins")
            for key, label in ruby_checks:
                raw = plugin_results.get(key, "")
                if raw:
                    try:
                        data = json.loads(raw)
                        if isinstance(data, dict) and "error" not in data:
                            s += f"  {_c('G', f'✓ {label}')}\n"
                            for k, v in data.items():
                                if isinstance(v, list) and len(v) > 0:
                                    s += _multi_field(f"  {k}", v[:10])
                                elif isinstance(v, bool):
                                    s += _tag(f"  {k}", str(v), "G" if v else "GR")
                                elif isinstance(v, (int, float)):
                                    s += _tag(f"  {k}", str(v), "W")
                                elif isinstance(v, str) and v:
                                    s += _tag(f"  {k}", v[:120], "W")
                        else:
                            err = data.get("error", "Unknown error") if isinstance(data, dict) else "Invalid output"
                            s += f"  {_c('R', f'✗ {label}')}: {_c('GR', err)}\n"
                    except (json.JSONDecodeError, TypeError):
                        s += f"  {_c('Y', f'? {label}')}: {_c('GR', str(raw)[:80])}\n"
                else:
                    s += f"  {_c('GR', f'— {label}: No data')}\n"
        else:
            s += _c('GR', "  No plugin extension data available.\n")

        sections.append(s)

        # POIN 15: DNS SECURITY EXTENSIONS (DNSSEC)
        s = _section("POIN 15: DNS SECURITY EXTENSIONS")
        dns_sec = _dict(res, "dns_sec")
        if dns_sec:
            dnskey = dns_sec.get("dnskey_records") or []
            ds = dns_sec.get("ds_records") or []
            rrsig = dns_sec.get("rrsig_records") or []
            cds = dns_sec.get("cds_records") or []
            cdnskey = dns_sec.get("cdnskey_records") or []
            nsec = dns_sec.get("nsec_records") or []
            nsec3param = dns_sec.get("nsec3param_records") or []

            has_dnssec = bool(dnskey or ds or rrsig)
            s += _sub("15.1", "DNSSEC Status")
            s += _tag("  DNSSEC Enabled", _yesno(has_dnssec), "E")
            if has_dnssec:
                total_records = len(dnskey) + len(ds) + len(rrsig) + len(cds) + len(cdnskey) + len(nsec) + len(nsec3param)
                s += _tag("  Total DNSSEC Records", str(total_records), "W")

                if dnskey:
                    s += _sub("15.2", "DNSKEY Records")
                    flags_detected = set()
                    algorithms_detected = set()
                    for r in dnskey:
                        s += f"    {_c('W', r[:120])}\n"
                        parts = r.split()
                        if len(parts) >= 3:
                            flags_detected.add(parts[0])
                            algorithms_detected.add(parts[2])
                    s += _tag("  Flags", ", ".join(sorted(flags_detected)) if flags_detected else "N/A", "W")
                    s += _tag("  Algorithms", ", ".join(sorted(algorithms_detected)) if algorithms_detected else "N/A", "C")

                if ds:
                    s += _sub("15.3", "DS Records (Delegation Signer)")
                    for r in ds:
                        s += f"    {_c('W', r[:120])}\n"

                if cds:
                    s += _sub("15.4", "CDS Records (Child DS)")
                    for r in cds:
                        s += f"    {_c('W', r[:120])}\n"

                if cdnskey:
                    s += _sub("15.5", "CDNSKEY Records (Child DNSKEY)")
                    for r in cdnskey:
                        s += f"    {_c('W', r[:120])}\n"

                if nsec:
                    s += _sub("15.6", "NSEC Records")
                    for r in nsec[:5]:
                        s += f"    {_c('W', r[:120])}\n"

                if nsec3param:
                    s += _sub("15.7", "NSEC3PARAM Records")
                    for r in nsec3param:
                        s += f"    {_c('W', r[:120])}\n"

                if rrsig:
                    s += _sub("15.8", "RRSIG Records (Signature)")
                    for r in rrsig[:3]:
                        s += f"    {_c('W', r[:120])}\n"
            else:
                s += _c('Y', "  DNSSEC not enabled — domain is vulnerable to DNS spoofing/cache poisoning\n")
                s += _c('GR', "  Recommendation: Enable DNSSEC with your DNS provider to sign zone records.\n")
        else:
            s += _c('GR', "  No DNSSEC data available.\n")

        sections.append(s)

    return "\n".join(sections)

if __name__ == "__main__":
    try:
        data = sys.stdin.read()
        if "---JSON_START---" in data:
            data = data.split("---JSON_START---")[1].split("---JSON_END---")[0]
        results = json.loads(data)
        intelligence = correlate(results)
        print(intelligence)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
