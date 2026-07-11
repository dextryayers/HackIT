import asyncio
import dns.resolver
import socket
import re
import time
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

MX_SOFTWARE_SIGNATURES = {
    "Postfix": ["postfix", "ESMTP Postfix"],
    "Exim": ["exim", "ESMTP Exim"],
    "Sendmail": ["sendmail", "ESMTP Sendmail"],
    "Microsoft Exchange": ["microsoft", "exchange", "outlook.com", "hotmail.com"],
    "Google Workspace": ["google", "gmail", "googlemail", "aspmx.l.google.com"],
    "Office 365": ["outlook", "office365", "protection.outlook.com"],
    "Zoho": ["zoho", "zohomail"],
    "ProtonMail": ["protonmail"],
    "Mailgun": ["mailgun"],
    "SendGrid": ["sendgrid"],
    "Amazon SES": ["amazonses", "aws"],
    "Cloudflare": ["cloudflare"],
    "Rackspace": ["rackspace", "emailsrvr"],
    "Yandex": ["yandex"],
    "FastMail": ["fastmail", "messagingengine"],
    "Titan": ["titan", "titanemail"],
    "MXRoute": ["mxroute"],
    "Namecheap": ["namecheap", "privateemail"],
    "GoDaddy": ["godaddy", "secureserver"],
}

async def get_mx(domain: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
        records = []
        for r in answers:
            records.append((r.preference, str(r.exchange).rstrip('.')))
        return sorted(records, key=lambda x: x[0])
    except:
        return []

async def resolve_a(host: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, 25, socket.AF_INET))
        return list(set(a[4][0] for a in answers))
    except:
        return []

async def get_smtp_banner(host: str, port: int = 25, timeout_sec: int = 5):
    loop = asyncio.get_event_loop()
    try:
        ips = await resolve_a(host)
        if not ips:
            return "", ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        sock.connect((ips[0], port))
        banner = ""
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            pass
        sock.sendall(b"EHLO mx-check.local\r\n")
        try:
            ehlo_resp = sock.recv(4096).decode('utf-8', errors='ignore').strip()
        except:
            ehlo_resp = ""
        sock.close()
        return banner, ehlo_resp
    except:
        return "", ""

async def check_starttls(host: str, port: int = 25):
    try:
        ips = await resolve_a(host)
        if not ips:
            return False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ips[0], port))
        sock.recv(1024)
        sock.sendall(b"EHLO tls-check.local\r\n")
        resp = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()
        return 'STARTTLS' in resp
    except:
        return False

async def get_ptr(ip: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve_address(ip))
        return [str(a) for a in answers]
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    mx_records = await get_mx(domain)
    if not mx_records:
        findings.append(make_finding(
            entity=f"No MX records for {domain}",
            ftype="MX Record Missing",
            source="DNS MX Analyzer",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="No MX",
            raw_data="Domain has no mail exchange records - email delivery impossible",
            tags=["mx", "missing"]
        ))
        return findings

    for pref, mx_host in mx_records:
        findings.append(make_finding(
            entity=f"[{pref}] {mx_host}",
            ftype="MX Record",
            source="DNS MX Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Active",
            raw_data=f"Priority: {pref} | Host: {mx_host}",
            tags=["mx", f"priority-{pref}"]
        ))

        ips = await resolve_a(mx_host)
        if ips:
            loc_str = ", ".join(ips)
            for ip in ips:
                findings.append(make_finding(
                    entity=f"{mx_host} -> {ip}",
                    ftype="MX IP Resolution",
                    source="DNS MX Analyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    resolution=ip,
                    status="Resolved",
                    tags=["mx", "ip"]
                ))

                ptrs = await get_ptr(ip)
                if ptrs:
                    findings.append(make_finding(
                        entity=f"rDNS: {ip} -> {', '.join(ptrs)}",
                        type="MX rDNS (PTR) Check",
                        source="DNS MX Analyzer",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="PTR Found",
                        resolution=ip,
                        raw_data=f"IP: {ip} | PTR: {', '.join(ptrs)}",
                        tags=["mx", "ptr", "rdns"]
                    ))
                    for ptr in ptrs:
                        ptr_clean = ptr.rstrip('.')
                        if mx_host.lower() not in ptr_clean.lower():
                            findings.append(make_finding(
                                entity=f"rDNS mismatch: {mx_host} vs {ptr_clean}",
                                ftype="MX rDNS Inconsistency",
                                source="DNS MX Analyzer",
                                confidence="Medium",
                                color="orange",
                                threat_level="Standard Target",
                                status="Mismatch",
                                tags=["mx", "rdns", "inconsistency"]
                            ))
                else:
                    findings.append(make_finding(
                        entity=f"No PTR record for {ip}",
                        ftype="MX rDNS Missing",
                        source="DNS MX Analyzer",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="No PTR",
                        resolution=ip,
                        tags=["mx", "rdns", "missing"]
                    ))

        banner, ehlo = await get_smtp_banner(mx_host)
        if banner:
            detected_software = "Unknown"
            for sw, sigs in MX_SOFTWARE_SIGNATURES.items():
                if any(s.lower() in banner.lower() or s.lower() in ehlo.lower() for s in sigs):
                    detected_software = sw
                    break
            findings.append(make_finding(
                entity=f"{mx_host}: {detected_software}",
                ftype="MX Software Detection",
                source="DNS MX Analyzer",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Banner: {banner[:200]} | EHLO: {ehlo[:200]}",
                tags=["mx", "software", detected_software.lower().replace(" ", "-")]
            ))

        tls = await check_starttls(mx_host)
        findings.append(make_finding(
            entity=f"{mx_host}: STARTTLS {'supported' if tls else 'NOT supported'}",
            ftype="MX TLS Support",
            source="DNS MX Analyzer",
            confidence="High",
            color="emerald" if tls else "red",
            threat_level="Informational" if tls else "Elevated Risk",
            status="STARTTLS" if tls else "No STARTTLS",
            tags=["mx", "tls", "starttls"]
        ))

    priorities = [pref for pref, _ in mx_records]
    if len(set(priorities)) > 1:
        sorted_prio = sorted(set(priorities))
        findings.append(make_finding(
            entity=f"MX priorities: {', '.join(map(str, sorted_prio))}",
            type="MX Priority Analysis",
            source="DNS MX Analyzer",
            confidence="High",
            color="slate",
            threat_level="Informational",
            status="Analyzed",
            raw_data=f"Priorities found: {sorted_prio} | Primary: {sorted_prio[0]} | Secondary: {sorted_prio[1] if len(sorted_prio) > 1 else 'None'}",
            tags=["mx", "priority"]
        ))
    else:
        findings.append(make_finding(
            entity=f"All MX servers have same priority ({priorities[0]}) - no failover order",
            type="MX Failover Analysis",
            source="DNS MX Analyzer",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="No Priority Differentiation",
            tags=["mx", "failover"]
        ))

    if len(mx_records) > 1:
        findings.append(make_finding(
            entity=f"{len(mx_records)} MX servers provide redundancy",
            type="MX Redundancy Check",
            source="DNS MX Analyzer",
            confidence="High",
            color="green",
            threat_level="Informational",
            status="Redundant",
            tags=["mx", "redundancy"]
        ))
        lowest_prio = min(pref for pref, _ in mx_records)
        backup = [mx for pref, mx in mx_records if pref > lowest_prio]
        if backup:
            findings.append(make_finding(
                entity=f"Backup MX servers: {', '.join(backup)}",
                type="MX Backup Detection",
                source="DNS MX Analyzer",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Backup Available",
                tags=["mx", "backup"]
            ))
    else:
        findings.append(make_finding(
            entity=f"Single MX server - no redundancy",
            ftype="MX Single Point of Failure",
            source="DNS MX Analyzer",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="Single MX",
            tags=["mx", "spof"]
        ))

    hostnames_only = [mx for _, mx in mx_records]
    ips_all = []
    for mx in hostnames_only:
        ips_all.extend(await resolve_a(mx))
    unique_ips = list(set(ips_all))
    if len(unique_ips) < len(hostnames_only):
        findings.append(make_finding(
            entity=f"MX servers share {len(unique_ips)} unique IP(s) across {len(hostnames_only)} hosts",
            type="MX IP Diversity",
            source="DNS MX Analyzer",
            confidence="High",
            color="orange" if len(unique_ips) < 2 else "green",
            threat_level="Standard Target" if len(unique_ips) < 2 else "Informational",
            status=f"{len(unique_ips)} Unique IPs",
            tags=["mx", "diversity"]
        ))

    findings.append(make_finding(
        entity=f"Analyzed {len(mx_records)} MX servers for {domain}",
        type="MX Analysis Summary",
        source="DNS MX Analyzer",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["mx", "summary"]
    ))

    return findings
