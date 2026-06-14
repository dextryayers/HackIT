import asyncio
import socket
import ssl
import re
import httpx
import dns.asyncresolver
from models import IntelligenceFinding

SMTP_PORTS = [25, 465, 587]
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
}

TEST_EMAIL = "test@example.com"
TEST_EXTERNAL_DOMAIN = "example.com"

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
                findings.append(IntelligenceFinding(
                    entity=f"{exchange} (priority {priority})",
                    type="MX Record",
                    source="MailServerAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"MX: {exchange} | Priority: {priority} | Domain: {host}",
                    tags=["dns", "mx", "mail"]
                ))
            findings.append(IntelligenceFinding(
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
            findings.append(IntelligenceFinding(
                entity=f"No MX records for {host}",
                type="MX Record",
                source="MailServerAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"No MX records found - email may not be hosted here",
                tags=["dns", "mx", "warning"]
            ))

        targets = [(host, 25, False), (host, 465, True), (host, 587, False)]
        if mx_records:
            for _, exchange in mx_records[:2]:
                targets.append((exchange, 25, False))
                targets.append((exchange, 465, True))
                targets.append((exchange, 587, False))

        seen_servers = set()
        for smtp_host, port, use_tls in targets:
            smtp_sock, reader = await connect_smtp(smtp_host, port, use_tls)
            if not smtp_sock:
                continue

            banner = await recv_response(reader, timeout=5.0)
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
                    findings.append(IntelligenceFinding(
                        entity=f"{smtp_host}:{port} - {banner[:150]}",
                        type="SMTP Banner",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        raw_data=banner[:500],
                        tags=["smtp", "banner", f"port-{port}"]
                    ))

                findings.append(IntelligenceFinding(
                    entity=f"Mail server: {server_ident.title()} on {smtp_host}:{port}",
                    type="Mail Server Software",
                    source="MailServerAnalyzer",
                    confidence="High" if server_ident != "unknown" else "Low",
                    color="purple" if server_ident != "unknown" else "slate",
                    threat_level="Informational",
                    raw_data=f"Banner: {banner[:200]}",
                    tags=["mail-server", "software", server_ident]
                ))

                ehlo_resp = await send_command(smtp_sock, f"EHLO scanner", reader)
                if ehlo_resp:
                    extensions_found = []
                    for ext, desc in SMTP_EXTENSIONS.items():
                        if ext.lower() in ehlo_resp.lower():
                            extensions_found.append(ext)
                            if ext == "STARTTLS":
                                findings.append(IntelligenceFinding(
                                    entity=f"STARTTLS supported on {smtp_host}:{port}",
                                    type="SMTP STARTTLS Support",
                                    source="MailServerAnalyzer",
                                    confidence="High",
                                    color="emerald",
                                    threat_level="Informational",
                                    raw_data=f"STARTTLS advertised on {smtp_host}:{port}",
                                    tags=["smtp", "starttls", "security"]
                                ))
                            elif ext.startswith("AUTH"):
                                findings.append(IntelligenceFinding(
                                    entity=f"AUTH method: {ext} on {smtp_host}:{port}",
                                    type="SMTP Authentication",
                                    source="MailServerAnalyzer",
                                    confidence="High",
                                    color="orange",
                                    threat_level="Informational",
                                    raw_data=f"Authentication method: {ext}",
                                    tags=["smtp", "auth"]
                                ))

                    if extensions_found:
                        ext_list = ", ".join(extensions_found)
                        findings.append(IntelligenceFinding(
                            entity=f"{len(extensions_found)} SMTP extensions on {smtp_host}:{port}",
                            type="SMTP Extensions Summary",
                            source="MailServerAnalyzer",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=ext_list[:500],
                            tags=["smtp", "extensions"]
                        ))

                    if not use_tls and port == 587:
                        ehlo_resp_lower = ehlo_resp.lower()
                        if "starttls" in ehlo_resp_lower:
                            starttls_resp = await send_command(smtp_sock, "STARTTLS", reader)
                            if "ready" in starttls_resp.lower() or "proceed" in starttls_resp.lower():
                                try:
                                    ctx = ssl.create_default_context()
                                    ctx.check_hostname = False
                                    ctx.verify_mode = ssl.CERT_NONE
                                    smtp_sock = ctx.wrap_socket(smtp_sock, server_hostname=smtp_host)
                                    reader = asyncio.StreamReader(limit=65536)
                                    protocol = asyncio.StreamReaderProtocol(reader)
                                    loop = asyncio.get_event_loop()
                                    await loop.connect_acceptor_socket(lambda: protocol, smtp_sock)
                                    ehlo2 = await send_command(smtp_sock, f"EHLO scanner", reader)
                                    if ehlo2:
                                        findings.append(IntelligenceFinding(
                                            entity=f"STARTTLS upgrade successful on {smtp_host}:{port}",
                                            type="SMTP STARTTLS Upgrade",
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
                    findings.append(IntelligenceFinding(
                        entity=f"VRFY enabled on {smtp_host}:{port} - email enumeration risk",
                        type="SMTP VRFY Enabled",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=f"VRFY response: {vrfy_resp}",
                        tags=["smtp", "enumeration", "vrfy"]
                    ))

                expn_resp = await send_command(smtp_sock, f"EXPN postmaster", reader)
                if "250" in expn_resp:
                    findings.append(IntelligenceFinding(
                        entity=f"EXPN enabled on {smtp_host}:{port}",
                        type="SMTP EXPN Enabled",
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
                    findings.append(IntelligenceFinding(
                        entity=f"OPEN RELAY on {smtp_host}:{port} - accepts mail to external domains",
                        type="SMTP Open Relay",
                        source="MailServerAnalyzer",
                        confidence="High",
                        color="red",
                        threat_level="Critical",
                        raw_data=f"MAIL FROM response: {mail_from_resp} | RCPT TO response: {rcpt_to_resp}",
                        tags=["smtp", "open-relay", "vulnerability", "critical"]
                    ))
                else:
                    findings.append(IntelligenceFinding(
                        entity=f"Relay test: {rcpt_to_resp[:100]} on {smtp_host}:{port}",
                        type="SMTP Relay Test",
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
                findings.append(IntelligenceFinding(
                    entity=f"No banner on {smtp_host}:{port}",
                    type="SMTP No Banner",
                    source="MailServerAnalyzer",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["smtp", "warning"]
                ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Mail server error: {str(e)[:100]}",
            type="Mail Server Error",
            source="MailServerAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
