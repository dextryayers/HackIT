import httpx
import re
import asyncio
import socket
from models import IntelligenceFinding
from urllib.parse import urlparse, urldefrag

COMMON_MAILBOXES = [
    "admin", "info", "contact", "support", "sales", "marketing", "billing",
    "abuse", "postmaster", "webmaster", "noreply", "no-reply", "help",
    "hello", "hi", "team", "careers", "jobs", "hr", "recruitment",
    "press", "media", "pr", "partner", "partners", "business",
    "enquiries", "enquiry", "inquiry", "inquiries", "general",
    "feedback", "complaints", "customerservice", "cs", "service",
    "newsletter", "subscribe", "unsubscribe", "announce",
    "security", "privacy", "legal", "dmca", "copyright",
    "dev", "developer", "developers", "engineering", "tech",
    "it", "it-support", "sysadmin", "operations",
    "ceo", "founder", "director", "manager",
    "test", "testing", "mail", "email", "office",
    "accounts", "accounting", "finance", "payments",
    "shipping", "logistics", "orders", "order",
    "return", "returns", "refund", "refunds",
]

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
MAILTO_REGEX = re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
SOCIAL_PATTERNS = [
    (r"(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in)/[a-zA-Z0-9_-]+", "LinkedIn"),
    (r"(?:https?://)?(?:www\.)?twitter\.com/[a-zA-Z0-9_]+", "Twitter / X"),
    (r"(?:https?://)?(?:www\.)?github\.com/[a-zA-Z0-9_-]+", "GitHub"),
    (r"(?:https?://)?(?:www\.)?facebook\.com/[a-zA-Z0-9.]+", "Facebook"),
    (r"(?:https?://)?(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+", "Instagram"),
    (r"(?:https?://)?(?:www\.)?youtube\.com/@?[a-zA-Z0-9_-]+", "YouTube"),
    (r"(?:https?://)?(?:www\.)?crunchbase\.com/organization/[a-zA-Z0-9_-]+", "Crunchbase"),
    (r"(?:https?://)?(?:www\.)?angel\.co/[a-zA-Z0-9_-]+", "AngelList"),
    (r"(?:https?://)?(?:www\.)?glassdoor\.com/(?:Overview|Reviews)/[a-zA-Z0-9_-]+", "Glassdoor"),
    (r"(?:https?://)?(?:www\.)?producthunt\.com/@?[a-zA-Z0-9_-]+", "Product Hunt"),
]

EMAIL_PATTERN_ANALYSIS = [
    (r"^[a-z]+\.[a-z]+@", "firstname.lastname"),
    (r"^[a-z][a-z]+[a-z]@", "firstinitiallastname"),
    (r"^[a-z]+@", "firstname"),
    (r"^[a-z]{1}\.[a-z]+@", "firstinitial.lastname"),
    (r"^[a-z]+\.[a-z]{1}@", "firstname.lastinitial"),
    (r"^[a-z]{1}[a-z]+@", "firstinitial+lastname"),
    (r"^[a-z]+[0-9]+@", "name+number"),
    (r"^[a-z]+\_[a-z]+@", "firstname_lastname"),
    (r"^[a-z]+\-[a-z]+@", "firstname-lastname"),
]

SMTP_TIMEOUT = 5

async def check_smtp(host: str, email: str) -> dict:
    try:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: socket.create_connection(
            (host, 25), timeout=SMTP_TIMEOUT
        ))
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await loop.create_connection(
            lambda: protocol, host=host, port=25
        )

        def recv_line():
            fut = loop.create_future()
            reader.readuntil(b'\n').add_done_callback(lambda f: fut.set_result(f.result()))
            return fut

        async def send_line(line: bytes):
            transport.write(line + b'\r\n')
            await asyncio.sleep(0.1)

        banner = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        banner_str = banner.decode("utf-8", errors="ignore").strip()

        await send_line(b'EHLO hunterhow.local')
        ehlo_resp = b""
        try:
            while True:
                line = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
                ehlo_resp += line
                if b'250 ' in line:
                    break
        except Exception:
            pass

        await send_line(f'MAIL FROM:<verify@{email.split("@")[1]}>'.encode())
        mailfrom_resp = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        mailfrom_str = mailfrom_resp.decode("utf-8", errors="ignore")

        await send_line(f'RCPT TO:<{email}>'.encode())
        rcpt_resp = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=SMTP_TIMEOUT)
        rcpt_str = rcpt_resp.decode("utf-8", errors="ignore")

        await send_line(b'QUIT')
        transport.close()

        is_valid = rcpt_str.startswith("250") or rcpt_str.startswith("251")
        return {"valid": is_valid, "banner": banner_str[:100], "response": rcpt_str.strip()[:100]}
    except Exception as e:
        return {"valid": None, "banner": "", "response": str(e)[:100]}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    base_url = f"https://{domain}"
    html = ""
    js_content = ""

    try:
        resp = await client.get(base_url, timeout=15.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp.status_code == 200:
            html = resp.text if hasattr(resp, "text") else ""
    except Exception:
        try:
            resp = await client.get(f"http://{domain}", timeout=15.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp.status_code == 200:
                html = resp.text if hasattr(resp, "text") else ""
        except Exception:
            pass

    if not html:
        return findings

    mailto_emails = set()
    for m in MAILTO_REGEX.finditer(html):
        mailto_emails.add(m.group(1).lower())

    for email in mailto_emails:
        if email.endswith("." + domain) or email.endswith(domain):
            findings.append(IntelligenceFinding(
                entity=email,
                type="HunterHOW - Email (mailto: link)",
                source="HunterHOW",
                confidence="High",
                color="emerald",
                status="Found in HTML",
                raw_data=f"Email in mailto: {email}",
                tags=["email", "mailto"]
            ))

    text_emails = set()
    for m in EMAIL_REGEX.finditer(html):
        email = m.group(0).lower()
        if email.endswith("." + domain) or email.endswith(domain):
            text_emails.add(email)

    non_mailto = text_emails - mailto_emails
    for email in list(non_mailto)[:15]:
        findings.append(IntelligenceFinding(
            entity=email,
            type="HunterHOW - Email (in page text)",
            source="HunterHOW",
            confidence="Medium",
            color="cyan",
            status="Found in content",
            raw_data=f"Email in page content: {email}",
            tags=["email", "text"]
        ))

    js_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html)
    for js_src in js_scripts[:10]:
        try:
            js_url = js_src if js_src.startswith("http") else f"{base_url.rstrip('/')}/{js_src.lstrip('/')}"
            js_resp = await client.get(js_url, timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if js_resp.status_code == 200:
                js_content += (js_resp.text or "")
        except Exception:
            pass

    if js_content:
        js_emails = set()
        for m in EMAIL_REGEX.finditer(js_content):
            email = m.group(0).lower()
            if email.endswith("." + domain) or email.endswith(domain):
                js_emails.add(email)
        for email in list(js_emails)[:10]:
            findings.append(IntelligenceFinding(
                entity=email,
                type="HunterHOW - Email (in JavaScript)",
                source="HunterHOW",
                confidence="Medium",
                color="cyan",
                status="Found in JS",
                raw_data=f"Email in JavaScript: {email}",
                tags=["email", "javascript"]
            ))

    all_found_emails = set()
    for f in findings:
        if f.entity and "@" in f.entity:
            all_found_emails.add(f.entity)

    found_mailboxes = set()
    for mailbox in COMMON_MAILBOXES:
        test_email = f"{mailbox}@{domain}"
        if test_email in all_found_emails:
            found_mailboxes.add(mailbox)

    verified_mailboxes = []
    for mailbox in COMMON_MAILBOXES[:20]:
        test_email = f"{mailbox}@{domain}"
        if test_email in all_found_emails:
            verified_mailboxes.append(mailbox)
            continue
        check_html_lower = html.lower()
        if mailbox in check_html_lower:
            verified_mailboxes.append(mailbox)

    for mailbox in verified_mailboxes:
        test_email = f"{mailbox}@{domain}"
        if test_email not in all_found_emails:
            findings.append(IntelligenceFinding(
                entity=test_email,
                type="HunterHOW - Common Mailbox (likely)",
                source="HunterHOW",
                confidence="Medium",
                color="blue",
                status="Probable",
                raw_data=f"Common mailbox pattern: {mailbox}@{domain}",
                tags=["email", "common-mailbox"]
            ))

    if not verified_mailboxes and not all_found_emails:
        for mailbox in ["info", "contact", "admin", "support"]:
            test_email = f"{mailbox}@{domain}"
            findings.append(IntelligenceFinding(
                entity=test_email,
                type="HunterHOW - Common Mailbox (suggested)",
                source="HunterHOW",
                confidence="Low",
                color="slate",
                status="Suggested",
                raw_data=f"Suggested common mailbox: {test_email}",
                tags=["email", "common-mailbox"]
            ))

    all_emails = list(all_found_emails)
    if all_emails:
        for email in all_emails[:3]:
            local_part = email.split("@")[0]
            for pattern, pattern_name in EMAIL_PATTERN_ANALYSIS:
                if re.match(pattern, local_part):
                    findings.append(IntelligenceFinding(
                        entity=f"Email format: {pattern_name} (from {email})",
                        type="HunterHOW - Email Naming Pattern",
                        source="HunterHOW",
                        confidence="High",
                        color="purple",
                        raw_data=f"Pattern: {pattern_name} | Example: {local_part}@{domain}",
                        tags=["email", "pattern"]
                    ))
                    break

        local_parts = [e.split("@")[0] for e in all_emails]
        if len(set(local_parts)) >= 3:
            findings.append(IntelligenceFinding(
                entity=f"{len(set(local_parts))} different local parts found",
                type="HunterHOW - Email Diversity",
                source="HunterHOW",
                confidence="Medium",
                color="slate",
                raw_data=f"Local parts: {', '.join(sorted(set(local_parts))[:10])}",
                tags=["email", "diversity"]
            ))

    smtp_host = None
    import dns.resolver
    loop = asyncio.get_event_loop()
    try:
        mx_records = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        mx_hosts = [(r.preference, str(r.exchange).rstrip('.')) for r in mx_records]
        if mx_hosts:
            mx_hosts.sort()
            smtp_host = mx_hosts[0][1]
            for prio, mx in mx_hosts:
                findings.append(IntelligenceFinding(
                    entity=f"{mx} (priority {prio})",
                    type="HunterHOW - Mail Server (MX)",
                    source="HunterHOW",
                    confidence="High",
                    color="slate",
                    raw_data=f"MX: {mx} | Priority: {prio}",
                    tags=["email", "mx"]
                ))
    except Exception:
        pass

    if all_emails and smtp_host:
        verify_email = list(all_emails)[0]
        smtp_result = await check_smtp(smtp_host, verify_email)

        if smtp_result.get("valid") is True:
            findings.append(IntelligenceFinding(
                entity=f"{verify_email} is VERIFIED (SMTP confirmed)",
                type="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="High",
                color="emerald",
                status="Verified",
                raw_data=f"SMTP verification passed for {verify_email} via {smtp_host}",
                tags=["email", "verified", "smtp"]
            ))
        elif smtp_result.get("valid") is False:
            findings.append(IntelligenceFinding(
                entity=f"{verify_email} REJECTED by mail server",
                type="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="Medium",
                color="red",
                status="Invalid",
                raw_data=f"SMTP rejection for {verify_email}: {smtp_result.get('response', '')}",
                tags=["email", "invalid", "smtp"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"SMTP check inconclusive for {verify_email}",
                type="HunterHOW - Email Verification",
                source="HunterHOW",
                confidence="Low",
                color="orange",
                status="Unknown",
                raw_data=f"SMTP result: {smtp_result.get('response', '')}",
                tags=["email", "smtp"]
            ))

        banner = smtp_result.get("banner", "")
        if banner:
            banner_lower = banner.lower()
            if "catch" in banner_lower or "catch-all" in banner_lower:
                findings.append(IntelligenceFinding(
                    entity=f"Catch-all detected: {banner[:100]}",
                    type="HunterHOW - Catch-All Detection",
                    source="HunterHOW",
                    confidence="Medium",
                    color="orange",
                    raw_data=f"Banner suggests catch-all: {banner[:200]}",
                    tags=["email", "catch-all"]
                ))

            banner_provider = "Unknown"
            for name, patterns in [
                ("Google Workspace", ["google", "gmail"]),
                ("Microsoft 365", ["outlook", "microsoft", "office365"]),
                ("ProtonMail", ["protonmail"]),
                ("Zoho", ["zoho"]),
                ("Fastmail", ["fastmail", "messagingengine"]),
                ("Yandex", ["yandex"]),
                ("Mailgun", ["mailgun"]),
                ("Cpanel/Exim", ["exim", "cpanel"]),
                ("Postfix", ["postfix"]),
                ("Sendmail", ["sendmail"]),
            ]:
                if any(p in banner_lower for p in patterns):
                    banner_provider = name
                    break

            if banner_provider != "Unknown":
                findings.append(IntelligenceFinding(
                    entity=f"Mail server: {banner_provider}",
                    type="HunterHOW - Mail Server Provider",
                    source="HunterHOW",
                    confidence="High",
                    color="blue",
                    raw_data=f"SMTP banner: {banner[:200]}",
                    tags=["email", "provider"]
                ))
    elif smtp_host and not all_emails:
        catch_all_test = f"catchalltest{abs(hash(domain)) % 10000}@{domain}"
        smtp_result = await check_smtp(smtp_host, catch_all_test)
        if smtp_result.get("valid") is True:
            findings.append(IntelligenceFinding(
                entity=f"Server accepts ALL email at {domain} (Catch-All)",
                type="HunterHOW - Catch-All Detected",
                source="HunterHOW",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                raw_data=f"Catch-all confirmed via SMTP test",
                tags=["email", "catch-all"]
            ))

    for pattern, platform in SOCIAL_PATTERNS:
        social_matches = re.findall(pattern, html, re.IGNORECASE)
        for sm in social_matches[:3]:
            findings.append(IntelligenceFinding(
                entity=sm[:200],
                type=f"HOW - {platform} Profile",
                source="HunterHOW",
                confidence="High",
                color="purple" if "linkedin" in platform.lower() else "slate",
                raw_data=sm[:500],
                tags=["social", platform.lower().replace(" ", "-").replace("/", "")]
            ))

    findings.append(IntelligenceFinding(
        entity=f"Total emails found: {len(all_found_emails)}",
        type="HunterHOW - Summary",
        source="HunterHOW",
        confidence="High" if all_found_emails else "Medium",
        color="emerald" if all_found_emails else "slate",
        threat_level="Informational",
        raw_data=f"Emails discovered: {len(all_found_emails)} | From mailto: {len(mailto_emails)} | From text: {len(text_emails)} | Mailboxes suggested: {len(verified_mailboxes)}",
        tags=["email", "summary"]
    ))

    return findings
