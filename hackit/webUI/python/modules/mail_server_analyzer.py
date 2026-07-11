import asyncio
import socket
import ssl
import re
import time
import httpx
import dns.asyncresolver
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

SMTP_PORTS = [25, 465, 587, 2525]
SMTP_BANNER_TIMEOUT = 5.0

SMTP_EXTENSIONS = {
    "PIPELINING": "Command pipelining supported",
    "SIZE": "Message size limit advertised",
    "DSN": "Delivery Status Notifications",
    "ENHANCEDSTATUSCODES": "Enhanced status codes",
    "8BITMIME": "8-bit MIME transport",
    "SMTPUTF8": "UTF-8 email addressing",
    "CHUNKING": "Chunking (BDAT) support",
    "BINARYMIME": "Binary MIME support",
    "STARTTLS": "STARTTLS for secure upgrade",
    "AUTH": "SMTP Authentication",
    "AUTH=LOGIN": "AUTH LOGIN mechanism",
    "AUTH=PLAIN": "AUTH PLAIN mechanism",
    "AUTH=CRAM-MD5": "AUTH CRAM-MD5 mechanism",
    "AUTH=DIGEST-MD5": "AUTH DIGEST-MD5 mechanism",
    "AUTH=XOAUTH2": "AUTH XOAUTH2 (OAuth 2.0)",
    "VRFY": "VRFY command supported",
    "EXPN": "EXPN command supported",
    "ETRN": "ETRN command supported",
    "HELP": "HELP command supported",
    "XCLIENT": "XCLIENT extension",
    "XFORWARD": "XFORWARD extension",
}

SERVER_SIGNATURES = {
    "postfix": ["Postfix", "ESMTP Postfix"],
    "exim": ["Exim", "ESMTP Exim"],
    "sendmail": ["Sendmail", "ESMTP Sendmail"],
    "microsoft": ["Exchange", "Microsoft ESMTP"],
    "gmail": ["Google", "Gmail", "google.com"],
    "outlook": ["Office365", "Outlook", "outlook.com"],
    "protonmail": ["ProtonMail", "protonmail"],
    "zoho": ["Zoho", "Zoho Mail"],
    "qmail": ["qmail", "qmail ESMTP"],
    "dovecot": ["Dovecot"],
    "courier": ["Courier"],
    "openbsd": ["OpenSMTPD"],
    "iredmail": ["iRedMail"],
    "zimbra": ["Zimbra"],
    "roundcube": ["Roundcube"],
    "squirrelmail": ["SquirrelMail"],
    "hmailserver": ["hMailServer"],
    "mailenable": ["MailEnable"],
    "kerio": ["Kerio"],
    "scalix": ["Scalix"],
    "cyrus": ["Cyrus"],
    "mailcow": ["mailcow"],
    "mailu": ["Mailu"],
    "wildduck": ["WildDuck"],
}

TEST_EMAIL = "test@example.com"
TEST_EXTERNAL_DOMAIN = "example.com"

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
    "mta1", "mta2", "mail1", "mail2", "em1", "em2",
    "sg", "send", "mailchimp", "mandrillapp", "sig1", "sig2",
    "dkim2019", "dkim2020", "dkim2021", "dkim2022",
    "dkim2023", "dkim2024", "dkim2025", "dkim2026",
    "prod", "stage", "selector-a", "selector-b",
    "selector01", "selector02", "mxs", "mxb", "mxp",
]

async def connect_smtp(host, port, use_tls=False):
    try:
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.create_connection((host, port), timeout=SMTP_BANNER_TIMEOUT)),
            timeout=SMTP_BANNER_TIMEOUT
        )
        sock.settimeout(SMTP_BANNER_TIMEOUT)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        reader = asyncio.StreamReader(limit=65536)
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_acceptor_socket(lambda: protocol, sock)
        return sock, reader
    except Exception:
        return None, None

async def recv_response(reader, timeout=3.0):
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=timeout)
        return data.decode("utf-8", errors="replace").strip()
    except Exception:
        return ""

async def send_command(writer, command, reader, timeout=3.0):
    try:
        writer.write((command + "\r\n").encode())
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        return await recv_response(reader, timeout)
    except Exception:
        return ""

async def fetch_mx_records(domain):
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, "MX")
        records = []
        for rdata in answers:
            priority = rdata.preference
            exchange = str(rdata.exchange).rstrip(".")
            records.append((priority, exchange))
        return sorted(records, key=lambda x: x[0])
    except Exception:
        return []

async def fetch_tlsa_records(domain):
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(f"_25._tcp.{domain}", "TLSA")
        records = []
        for rdata in answers:
            usage_desc = {
                0: "PKIX-TA (CA constraint)",
                1: "PKIX-EE (Service certificate constraint)",
                2: "DANE-TA (Trust anchor assertion)",
                3: "DANE-EE (Domain-issued certificate)",
            }.get(rdata.usage, f"Unknown usage {rdata.usage}")
            selector_desc = {
                0: "Full certificate",
                1: "SubjectPublicKeyInfo",
            }.get(rdata.selector, f"Unknown selector {rdata.selector}")
            mtype_desc = {
                0: "Full certificate",
                1: "SHA-256 hash",
                2: "SHA-512 hash",
            }.get(rdata.mtype, f"Unknown type {rdata.mtype}")
            cert_hex = rdata.cert.hex()
            records.append({
                "usage": rdata.usage,
                "selector": rdata.selector,
                "mtype": rdata.mtype,
                "usage_desc": usage_desc,
                "selector_desc": selector_desc,
                "mtype_desc": mtype_desc,
                "cert_hash": cert_hex[:64] + "..." if len(cert_hex) > 64 else cert_hex,
            })
        return records
    except Exception:
        return []

async def resolve_host_record(hostname):
    try:
        resolver = dns.asyncresolver.Resolver()
        ipv4 = []
        ipv6 = []
        try:
            a_answers = await resolver.resolve(hostname, "A")
            ipv4 = [str(r) for r in a_answers]
        except Exception:
            pass
        try:
            aaaa_answers = await resolver.resolve(hostname, "AAAA")
            ipv6 = [str(r) for r in aaaa_answers]
        except Exception:
            pass
        return ipv4, ipv6
    except Exception:
        return [], []

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    host = target.strip().lower()
    if host.startswith("http"):
        from urllib.parse import urlparse
        host = urlparse(host).netloc

    try:
        mx_records = await fetch_mx_records(host)
        if mx_records:
            for priority, exchange in mx_records:
                findings.append(make_finding(
                    entity=f"{exchange} (priority {priority})",
                    type="MX Record",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"MX: {exchange} | Priority: {priority} | Domain: {host}",
                    tags=["dns", "mx", "mail"]
                ))
            findings.append(make_finding(
                entity=f"{len(mx_records)} MX records found for {host}",
                type="MX Record Summary",
                source="MailServerAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=" | ".join(f"{e}({p})" for p, e in mx_records),
                tags=["dns", "mx", "summary"]
            ))
        else:
            findings.append(make_finding(
                entity=f"No MX records for {host}",
                ftype="MX Record",
                source="MailServerAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"No MX records found - email may not be hosted here",
                tags=["dns", "mx", "warning"]
            ))

        tlsa_records = await fetch_tlsa_records(host)
        if tlsa_records:
            for rec in tlsa_records:
                findings.append(make_finding(
                    entity=f"TLSA: {rec['usage_desc']} / {rec['selector_desc']} / {rec['mtype_desc']}",
                    ftype="DANE TLSA Record",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"Usage={rec['usage']} Selector={rec['selector']} Type={rec['mtype']} Cert={rec['cert_hash']}",
                    tags=["dns", "tlsa", "dane", "security"]
                ))
            findings.append(make_finding(
                entity=f"{len(tlsa_records)} TLSA record(s) for {host}",
                type="DANE TLSA Summary",
                source="MailServerAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"Total TLSA records: {len(tlsa_records)}",
                tags=["dns", "tlsa", "dane", "summary"]
            ))

        mx_resolved = {}
        if mx_records:
            for _, exchange in mx_records:
                ipv4, ipv6 = await resolve_host_record(exchange)
                mx_resolved[exchange] = (ipv4, ipv6)
                if ipv4 or ipv6:
                    ip_list = ipv4 + ipv6
                    findings.append(make_finding(
                        entity=f"{exchange} resolves to {', '.join(ip_list)}",
                        type="MX Hostname Resolution",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"MX: {exchange} | A: {', '.join(ipv4) if ipv4 else 'none'} | AAAA: {', '.join(ipv6) if ipv6 else 'none'}",
                        tags=["dns", "mx", "resolution"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"{exchange} has no A/AAAA records",
                        ftype="MX Hostname Resolution",
                        source="MailServerAnalyzer",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        raw_data=f"MX host {exchange} does not resolve",
                        tags=["dns", "mx", "resolution", "warning"]
                    ))

        spf_present = False
        spf_record_raw = None
        try:
            resolver = dns.asyncresolver.Resolver()
            txt_answers = await resolver.resolve(host, "TXT")
            for r in txt_answers:
                txt = str(r)
                if txt.startswith("v=spf1"):
                    spf_present = True
                    spf_record_raw = txt
                    findings.append(make_finding(
                        entity=f"SPF record found for {host}",
                        ftype="SPF Record",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=txt[:500],
                        tags=["dns", "spf", "email-security"]
                    ))
                    break
            if not spf_present:
                findings.append(make_finding(
                    entity=f"No SPF record for {host}",
                    ftype="SPF Record Missing",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"No SPF record found - domain may be spoofable",
                    tags=["dns", "spf", "email-security", "warning"]
                ))
        except Exception:
            findings.append(make_finding(
                entity=f"Could not query SPF for {host}",
                ftype="SPF Record Error",
                source="MailServerAnalyzer",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["dns", "spf", "error"]
            ))

        dmarc_present = False
        dmarc_record_raw = None
        try:
            resolver = dns.asyncresolver.Resolver()
            dmarc_answers = await resolver.resolve(f"_dmarc.{host}", "TXT")
            for r in dmarc_answers:
                txt = str(r)
                if "v=DMARC" in txt:
                    dmarc_present = True
                    dmarc_record_raw = txt
                    findings.append(make_finding(
                        entity=f"DMARC record found for {host}",
                        ftype="DMARC Record",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=txt[:500],
                        tags=["dns", "dmarc", "email-security"]
                    ))
                    break
            if not dmarc_present:
                findings.append(make_finding(
                    entity=f"No DMARC record for {host}",
                    ftype="DMARC Record Missing",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"No DMARC record found - domain may be spoofable",
                    tags=["dns", "dmarc", "email-security", "warning"]
                ))
        except Exception:
            findings.append(make_finding(
                entity=f"Could not query DMARC for {host}",
                ftype="DMARC Record Error",
                source="MailServerAnalyzer",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["dns", "dmarc", "error"]
            ))

        dkim_found_selectors = []
        for selector in COMMON_DKIM_SELECTORS:
            try:
                resolver = dns.asyncresolver.Resolver()
                dkim_answers = await resolver.resolve(f"{selector}._domainkey.{host}", "TXT")
                for r in dkim_answers:
                    txt = str(r)
                    if "v=DKIM1" in txt or "p=" in txt:
                        dkim_found_selectors.append(selector)
                        findings.append(make_finding(
                            entity=f"DKIM record found (selector: {selector})",
                            type="DKIM Record",
                            source="MailServerAnalyzer",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            raw_data=txt[:500],
                            tags=["dns", "dkim", "email-security"]
                        ))
                        break
            except Exception:
                continue
        if not dkim_found_selectors:
            findings.append(make_finding(
                entity=f"No DKIM records found for {host}",
                ftype="DKIM Record Missing",
                source="MailServerAnalyzer",
                confidence="High",
                color="orange",
                threat_level="Informational",
                raw_data=f"Checked {len(COMMON_DKIM_SELECTORS)} common selectors, none found",
                tags=["dns", "dkim", "email-security", "warning"]
            ))
        else:
            findings.append(make_finding(
                entity=f"DKIM active on {len(dkim_found_selectors)} selector(s): {', '.join(dkim_found_selectors[:5])}",
                type="DKIM Summary",
                source="MailServerAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data=f"Selectors: {', '.join(dkim_found_selectors)}",
                tags=["dns", "dkim", "email-security", "summary"]
            ))

        try:
            resolver = dns.asyncresolver.Resolver()
            bimi_answers = await resolver.resolve(f"default._bimi.{host}", "TXT")
            for r in bimi_answers:
                txt = str(r)
                if "v=BIMI1" in txt:
                    findings.append(make_finding(
                        entity=f"BIMI record found for {host}",
                        ftype="BIMI Record",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        raw_data=txt[:500],
                        tags=["dns", "bimi", "email-security"]
                    ))
                break
        except:
            pass

        try:
            resolver = dns.asyncresolver.Resolver()
            mta_sts_answers = await resolver.resolve(f"_mta-sts.{host}", "TXT")
            for r in mta_sts_answers:
                txt = str(r)
                if "v=STSv1" in txt:
                    findings.append(make_finding(
                        entity=f"MTA-STS DNS record found for {host}",
                        ftype="MTA-STS Record",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=txt[:500],
                        tags=["dns", "mta-sts", "email-security"]
                    ))
                break
        except:
            pass

        try:
            resolver = dns.asyncresolver.Resolver()
            dnskey_answers = await resolver.resolve(host, "DNSKEY")
            if dnskey_answers:
                findings.append(make_finding(
                    entity=f"DNSSEC enabled for {host} ({len(dnskey_answers)} DNSKEY records)",
                    type="DNSSEC Status",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    raw_data=f"DNSKEY records: {len(dnskey_answers)}",
                    tags=["dns", "dnssec", "email-security"]
                ))
        except dns.asyncresolver.NoAnswer:
            pass
        except:
            pass

        mx_rdns_ok = True
        if mx_records:
            for _, exchange in mx_records[:2]:
                try:
                    resolver = dns.asyncresolver.Resolver()
                    a_answers = await resolver.resolve(exchange, "A")
                    for a in a_answers:
                        ip = str(a)
                        try:
                            rev = await resolver.resolve_address(ip)
                            rev_name = str(rev[0]).rstrip(".")
                            if rev_name:
                                findings.append(make_finding(
                                    entity=f"MX {exchange} ({ip}) rDNS: {rev_name}",
                                    type="MX rDNS Record",
                                    source="MailServerAnalyzer",
                                    confidence="High",
                                    color="slate",
                                    threat_level="Informational",
                                    raw_data=f"{ip} -> {rev_name}",
                                    tags=["dns", "mx", "rdns"]
                                ))
                                if exchange.lower() not in rev_name.lower() and exchange.lower().rstrip(".") not in rev_name.lower():
                                    mx_rdns_ok = False
                                    findings.append(make_finding(
                                        entity=f"MX {exchange} rDNS mismatch: {rev_name}",
                                        ftype="MX rDNS Mismatch",
                                        source="MailServerAnalyzer",
                                        confidence="Medium",
                                        color="orange",
                                        threat_level="Elevated Risk",
                                        tags=["dns", "mx", "rdns", "mismatch"]
                                    ))
                        except:
                            pass
                        break
                except:
                    pass

        targets = []
        for port in SMTP_PORTS:
            use_tls = port == 465
            targets.append((host, port, use_tls))
        if mx_records:
            for _, exchange in mx_records[:2]:
                for port in SMTP_PORTS:
                    use_tls = port == 465
                    targets.append((exchange, port, use_tls))

        seen_servers = set()
        has_starttls = False
        has_strong_tls = False
        has_open_relay = False
        has_vrfy_enabled = False
        has_expn_enabled = False

        for smtp_host, port, use_tls in targets:
            t0 = time.monotonic()
            smtp_sock, reader = await connect_smtp(smtp_host, port, use_tls)
            t_conn = time.monotonic() - t0
            if not smtp_sock:
                continue

            t1 = time.monotonic()
            banner = await recv_response(reader, timeout=5.0)
            t_banner = time.monotonic() - t1

            if banner:
                server_ident = "unknown"
                for name, sigs in SERVER_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in banner.lower():
                            server_ident = name
                            break
                    if server_ident != "unknown":
                        break

                key = f"{smtp_host}:{port}"
                if server_ident not in seen_servers:
                    seen_servers.add(server_ident)
                    findings.append(make_finding(
                        entity=f"{smtp_host}:{port} - {banner[:150]}",
                        ftype="SMTP Banner",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=banner[:500],
                        tags=["smtp", "banner", f"port-{port}"]
                    ))

                findings.append(make_finding(
                    entity=f"Mail server: {server_ident.title()} on {smtp_host}:{port}",
                    type="Mail Server Software",
                    source="MailServerAnalyzer",
                    confidence="High" if server_ident != "unknown" else "Low",
                    color="purple" if server_ident != "unknown" else "slate",
                    threat_level="Informational",
                    raw_data=f"Banner: {banner[:200]}",
                    tags=["mail-server", "software", server_ident]
                ))

                findings.append(make_finding(
                    entity=f"SMTP timing on {smtp_host}:{port}: conn={t_conn*1000:.0f}ms banner={t_banner*1000:.0f}ms",
                    ftype="SMTP Timing",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Connection: {t_conn*1000:.0f}ms | Banner: {t_banner*1000:.0f}ms",
                    tags=["smtp", "timing", f"port-{port}"]
                ))

                t2 = time.monotonic()
                ehlo_resp = await send_command(smtp_sock, "EHLO scanner", reader)
                t_ehlo = time.monotonic() - t2

                if ehlo_resp:
                    findings.append(make_finding(
                        entity=f"EHLO response time on {smtp_host}:{port}: {t_ehlo*1000:.0f}ms",
                        ftype="SMTP EHLO Timing",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=f"EHLO command: {t_ehlo*1000:.0f}ms",
                        tags=["smtp", "timing", "ehlo", f"port-{port}"]
                    ))

                    extensions_found = []
                    for ext, desc in SMTP_EXTENSIONS.items():
                        if ext.lower() in ehlo_resp.lower():
                            extensions_found.append(ext)
                            if ext == "STARTTLS":
                                findings.append(make_finding(
                                    entity=f"STARTTLS supported on {smtp_host}:{port}",
                                    ftype="SMTP STARTTLS Support",
                                    source="MailServerAnalyzer",
                                    confidence="High",
                                    color="emerald",
                                    threat_level="Informational",
                                    raw_data=f"STARTTLS advertised on {smtp_host}:{port}",
                                    tags=["smtp", "starttls", "security"]
                                ))
                            elif ext.startswith("AUTH"):
                                findings.append(make_finding(
                                    entity=f"AUTH method: {ext} on {smtp_host}:{port}",
                                    ftype="SMTP Authentication",
                                    source="MailServerAnalyzer",
                                    confidence="High",
                                    color="orange",
                                    threat_level="Informational",
                                    raw_data=f"Authentication method: {ext}",
                                    tags=["smtp", "auth"]
                                ))

                    if extensions_found:
                        ext_list = ", ".join(extensions_found)
                        findings.append(make_finding(
                            entity=f"{len(extensions_found)} SMTP extensions on {smtp_host}:{port}",
                            type="SMTP Extensions Summary",
                            source="MailServerAnalyzer",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=ext_list[:500],
                            tags=["smtp", "extensions"]
                        ))

                    if not use_tls and port in (25, 587, 2525):
                        ehlo_resp_lower = ehlo_resp.lower()
                        if "starttls" in ehlo_resp_lower:
                            starttls_resp = await send_command(smtp_sock, "STARTTLS", reader)
                            if "ready" in starttls_resp.lower() or "proceed" in starttls_resp.lower():
                                try:
                                    ctx = ssl.create_default_context()
                                    ctx.check_hostname = False
                                    ctx.verify_mode = ssl.CERT_NONE
                                    smtp_sock = ctx.wrap_socket(smtp_sock, server_hostname=smtp_host)

                                    tls_version = smtp_sock.version()
                                    cipher_info = smtp_sock.cipher()
                                    cert = smtp_sock.getpeercert()

                                    if tls_version:
                                        is_strong = "TLSv1.2" in tls_version or "TLSv1.3" in tls_version
                                        if is_strong:
                                            has_strong_tls = True
                                        tls_color = "emerald" if is_strong else "orange"
                                        findings.append(make_finding(
                                            entity=f"{tls_version} on {smtp_host}:{port}",
                                            ftype="STARTTLS Protocol Version",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color=tls_color,
                                            threat_level="Informational",
                                            raw_data=f"TLS version: {tls_version}",
                                            tags=["smtp", "starttls", "tls", f"port-{port}"]
                                        ))

                                    if cipher_info:
                                        cipher_name = cipher_info[0]
                                        cipher_proto = cipher_info[1]
                                        cipher_bits = cipher_info[2]
                                        findings.append(make_finding(
                                            entity=f"Cipher: {cipher_name} ({cipher_bits} bits) on {smtp_host}:{port}",
                                            type="STARTTLS Cipher",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color="slate",
                                            threat_level="Informational",
                                            raw_data=f"Cipher: {cipher_name} | Protocol: {cipher_proto} | Bits: {cipher_bits}",
                                            tags=["smtp", "starttls", "cipher", f"port-{port}"]
                                        ))

                                    if cert:
                                        issuer_parts = cert.get("issuer", [])
                                        subject_parts = cert.get("subject", [])
                                        issuer_str = "; ".join(
                                            f"{k}={v}" for group in issuer_parts
                                            for item in group for k, v in (item,) if isinstance(item, tuple)
                                        ) if issuer_parts else "Unknown"
                                        subject_str = "; ".join(
                                            f"{k}={v}" for group in subject_parts
                                            for item in group for k, v in (item,) if isinstance(item, tuple)
                                        ) if subject_parts else "Unknown"

                                        findings.append(make_finding(
                                            entity=f"Issuer: {issuer_str[:150]} on {smtp_host}:{port}",
                                            ftype="STARTTLS Certificate Issuer",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color="slate",
                                            threat_level="Informational",
                                            raw_data=issuer_str[:500],
                                            tags=["smtp", "starttls", "certificate", f"port-{port}"]
                                        ))
                                        findings.append(make_finding(
                                            entity=f"Subject: {subject_str[:150]} on {smtp_host}:{port}",
                                            ftype="STARTTLS Certificate Subject",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color="slate",
                                            threat_level="Informational",
                                            raw_data=subject_str[:500],
                                            tags=["smtp", "starttls", "certificate", f"port-{port}"]
                                        ))

                                        not_before = cert.get("notBefore", "Unknown")
                                        not_after = cert.get("notAfter", "Unknown")
                                        findings.append(make_finding(
                                            entity=f"Valid: {not_before} to {not_after} on {smtp_host}:{port}",
                                            ftype="STARTTLS Certificate Validity",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color="emerald",
                                            threat_level="Informational",
                                            raw_data=f"Not Before: {not_before} | Not After: {not_after}",
                                            tags=["smtp", "starttls", "certificate", "validity", f"port-{port}"]
                                        ))

                                        san_list = cert.get("subjectAltName", [])
                                        if san_list:
                                            san_hosts = [v for _, v in san_list[:10]]
                                            findings.append(make_finding(
                                                entity=f"SANs: {', '.join(san_hosts)} on {smtp_host}:{port}",
                                                type="STARTTLS Certificate SANs",
                                                source="MailServerAnalyzer",
                                                confidence="High",
                                                color="slate",
                                                threat_level="Informational",
                                                raw_data=", ".join(san_hosts)[:500],
                                                tags=["smtp", "starttls", "certificate", "san", f"port-{port}"]
                                            ))

                                    reader = asyncio.StreamReader(limit=65536)
                                    protocol = asyncio.StreamReaderProtocol(reader)
                                    loop = asyncio.get_event_loop()
                                    await loop.connect_acceptor_socket(lambda: protocol, smtp_sock)

                                    has_starttls = True

                                    ehlo2 = await send_command(smtp_sock, "EHLO scanner", reader)
                                    if ehlo2:
                                        findings.append(make_finding(
                                            entity=f"STARTTLS upgrade successful on {smtp_host}:{port}",
                                            ftype="SMTP STARTTLS Upgrade",
                                            source="MailServerAnalyzer",
                                            confidence="High",
                                            color="emerald",
                                            threat_level="Informational",
                                            raw_data=f"Successfully upgraded to TLS on {smtp_host}:{port}",
                                            tags=["smtp", "starttls", "upgrade"]
                                        ))
                                except Exception:
                                    pass

                vrfy_resp = await send_command(smtp_sock, f"VRFY {TEST_EMAIL}", reader)
                if "252" in vrfy_resp or "250" in vrfy_resp:
                    has_vrfy_enabled = True
                    findings.append(make_finding(
                        entity=f"VRFY enabled on {smtp_host}:{port} - email enumeration risk",
                        ftype="SMTP VRFY Enabled",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=f"VRFY response: {vrfy_resp}",
                        tags=["smtp", "enumeration", "vrfy"]
                    ))

                expn_resp = await send_command(smtp_sock, f"EXPN postmaster", reader)
                if "250" in expn_resp:
                    has_expn_enabled = True
                    findings.append(make_finding(
                        entity=f"EXPN enabled on {smtp_host}:{port}",
                        ftype="SMTP EXPN Enabled",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        raw_data=f"EXPN response: {expn_resp}",
                        tags=["smtp", "enumeration", "expn"]
                    ))

                mail_from_resp = await send_command(smtp_sock, f"MAIL FROM:<test@{host}>", reader)
                rcpt_to_resp = await send_command(smtp_sock, f"RCPT TO:<test@{TEST_EXTERNAL_DOMAIN}>", reader)
                if "250" in mail_from_resp and ("250" in rcpt_to_resp or "251" in rcpt_to_resp):
                    has_open_relay = True
                    findings.append(make_finding(
                        entity=f"OPEN RELAY on {smtp_host}:{port} - accepts mail to external domains",
                        ftype="SMTP Open Relay",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="Critical",
                        raw_data=f"MAIL FROM response: {mail_from_resp} | RCPT TO response: {rcpt_to_resp}",
                        tags=["smtp", "open-relay", "vulnerability", "critical"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"Relay test: {rcpt_to_resp[:100]} on {smtp_host}:{port}",
                        ftype="SMTP Relay Test",
                        source="MailServerAnalyzer",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"RCPT TO external ({TEST_EXTERNAL_DOMAIN}): {rcpt_to_resp}",
                        tags=["smtp", "relay-test"]
                    ))

                quit_resp = await send_command(smtp_sock, "QUIT", reader)
                try:
                    smtp_sock.close()
                except Exception:
                    pass

            else:
                findings.append(make_finding(
                    entity=f"No banner on {smtp_host}:{port}",
                    ftype="SMTP No Banner",
                    source="MailServerAnalyzer",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["smtp", "warning"]
                ))

        bimi_present = any("BIMI Record" in (f.type or "") for f in findings)
        mta_sts_present = any("MTA-STS Record" in (f.type or "") for f in findings)
        dnssec_present = any("DNSSEC" in (f.type or "") for f in findings)
        rdns_ok = any("MX rDNS Record" in (f.type or "") for f in findings)

        score = 0
        max_score = 50
        score_breakdown = []

        if has_starttls:
            score += 3
            score_breakdown.append("STARTTLS: 3")
        else:
            score_breakdown.append("STARTTLS: 0")

        if has_strong_tls:
            score += 2
            score_breakdown.append("TLS 1.2+: 2")
        else:
            score_breakdown.append("TLS 1.2+: 0")

        if not has_open_relay:
            score += 3
            score_breakdown.append("No Open Relay: 3")
        else:
            score_breakdown.append("No Open Relay: 0")

        if not has_vrfy_enabled and not has_expn_enabled:
            score += 2
            score_breakdown.append("VRFY/EXPN Disabled: 2")
        else:
            score_breakdown.append("VRFY/EXPN Disabled: 0")

        if spf_present:
            score += 3
            score_breakdown.append("SPF: 3")
        else:
            score_breakdown.append("SPF: 0")

        if dkim_found_selectors:
            score += 3
            score_breakdown.append("DKIM: 3")
        else:
            score_breakdown.append("DKIM: 0")

        if dmarc_present:
            score += 3
            score_breakdown.append("DMARC: 3")
        else:
            score_breakdown.append("DMARC: 0")

        if tlsa_records:
            score += 2
            score_breakdown.append("DANE/TLSA: 2")
        else:
            score_breakdown.append("DANE/TLSA: 0")

        if bimi_present:
            score += 2
            score_breakdown.append("BIMI: 2")
        else:
            score_breakdown.append("BIMI: 0")

        if mta_sts_present:
            score += 2
            score_breakdown.append("MTA-STS: 2")
        else:
            score_breakdown.append("MTA-STS: 0")

        if dnssec_present:
            score += 2
            score_breakdown.append("DNSSEC: 2")
        else:
            score_breakdown.append("DNSSEC: 0")

        if rdns_ok:
            score += 1
            score_breakdown.append("MX rDNS: 1")
        else:
            score_breakdown.append("MX rDNS: 0")

        score_pct = round((score / max_score) * 100)
        if score_pct >= 80:
            risk_level = "Low Risk"
            risk_color = "emerald"
        elif score_pct >= 50:
            risk_level = "Moderate Risk"
            risk_color = "orange"
        else:
            risk_level = "High Risk"
            risk_color = "red"

        findings.append(make_finding(
            entity=f"Mail Server Security Score: {score}/{max_score} ({score_pct}%) - {risk_level}",
            type="Mail Server Security Score",
            source="MailServerAnalyzer",
            confidence="High",
            color=risk_color,
            threat_level=risk_level,
            raw_data=f"Score: {score}/{max_score} ({score_pct}%) | Breakdown: {' + '.join(score_breakdown)} | {risk_level}",
            tags=["smtp", "security-score", "summary"]
        ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Mail server error: {str(e)[:100]}",
            type="Mail Server Error",
            source="MailServerAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
