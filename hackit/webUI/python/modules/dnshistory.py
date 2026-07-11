import httpx
import asyncio
import socket
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

DNSTWISTER_BASE = "https://dnstwister.report/api"
VIEWDNS_BASE = "https://viewdns.info"
SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"
WHOISXML_BASE = "https://www.whoisxmlapi.com"

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "date", "men", "loan", "download", "review"}

COMMON_RBLS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dbl.spamhaus.org", "Spamhaus DBL"),
]


async def _check_dns_blacklist(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    for rbl_host, rbl_name in COMMON_RBLS:
        try:
            query = f"{domain}.{rbl_host}"
            try:
                await asyncio.get_event_loop().run_in_executor(None, lambda: resolve_ip(query))
                findings.append(make_finding(
                    entity=f"Listed on {rbl_name}",
                    ftype="DNSBL Blacklist Hit",
                    source="DNSHistory (RBL)",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Blacklisted",
                    raw_data=f"Domain {domain} found on {rbl_name} RBL",
                    tags=["dnsbl", "blacklist", "spam"]
                ))
            except socket.gaierror:
                pass
        except Exception:
            pass
    if findings:
        findings.append(make_finding(
            entity=f"Domain listed on {len(findings)} DNSBL(s)",
            type="DNSBL Summary",
            source="DNSHistory (RBL)",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Flagged",
            raw_data=f"DNSBL hits: {len(findings)}",
            tags=["dnsbl", "blacklist", "summary"]
        ))
    else:
        findings.append(make_finding(
            entity="Not listed on any tested DNSBL",
            ftype="DNSBL Clean",
            source="DNSHistory (RBL)",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            raw_data="Domain not found on common DNSBLs",
            tags=["dnsbl", "clean"]
        ))
    return findings


async def _check_dnssec(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        doh_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=DS",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if doh_resp.status_code == 200:
            ds_data = doh_resp.json()
            ds_answers = ds_data.get("Answer", [])
            ds_records = [a for a in ds_answers if a.get("type") == 43]
            if ds_records:
                for rec in ds_records[:5]:
                    findings.append(make_finding(
                        entity=rec.get("data", "")[:200],
                        type="DNSSEC - DS Record",
                        source="DNSHistory (Google DoH)",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="DNSSEC Signed",
                        raw_data=f"DS Record: {rec.get('data', '')}",
                        tags=["dnssec", "ds-record"]
                    ))
                findings.append(make_finding(
                    entity="DNSSEC is ENABLED (DS records found)",
                    type="DNSSEC Status",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Secure",
                    raw_data=f"{len(ds_records)} DS records found",
                    tags=["dnssec", "secure"]
                ))
            else:
                findings.append(make_finding(
                    entity="DNSSEC is DISABLED (no DS records)",
                    type="DNSSEC Status",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="No DNSSEC",
                    raw_data="No DS records - domain is not DNSSEC signed",
                    tags=["dnssec", "insecure"]
                ))
    except Exception:
        pass
    return findings


async def _check_caa(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        caa_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=CAA",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if caa_resp.status_code == 200:
            caa_data = caa_resp.json()
            caa_answers = caa_data.get("Answer", [])
            caa_records = [a for a in caa_answers if a.get("type") == 257]
            if caa_records:
                for rec in caa_records[:5]:
                    findings.append(make_finding(
                        entity=rec.get("data", "")[:200],
                        type="CAA Record",
                        source="DNSHistory (Google DoH)",
                        confidence="High",
                        color="slate",
                        status="Configured",
                        raw_data=f"CAA: {rec.get('data', '')}",
                        tags=["dns", "caa"]
                    ))
            else:
                findings.append(make_finding(
                    entity="No CAA record configured",
                    ftype="CAA Record Status",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Missing",
                    raw_data="No Certificate Authority Authorization record",
                    tags=["dns", "caa", "missing"]
                ))
    except Exception:
        pass
    return findings


async def _check_https_service(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://{domain}",
            timeout=12.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp is None:
            raise httpx.ConnectError("Connection failed")
        final_url = str(resp.url)
        chain_len = len(resp.history)
        status = resp.status_code
        server = resp.headers.get("server", "")
        ctype = resp.headers.get("content-type", "")
        cf_ray = resp.headers.get("cf-ray", "")
        powered_by = resp.headers.get("x-powered-by", "")

        findings.append(make_finding(
            entity=f"HTTPS {status} ({final_url})",
            type="HTTPS Service Check",
            source="DNSHistory (HTTP Probe)",
            confidence="High",
            color="emerald" if status < 400 else "red",
            status="Online" if status < 400 else "Error",
            resolution=f"Chain: {chain_len} redirects",
            raw_data=f"Status: {status}, Server: {server}, Type: {ctype}",
            tags=["https", "probe"]
        ))
        if server:
            findings.append(make_finding(
                entity=server[:200],
                ftype="Web Server Header",
                source="DNSHistory (HTTP Probe)",
                confidence="High",
                color="slate",
                raw_data=f"Server: {server}",
                tags=["server", "fingerprint"]
            ))
        if cf_ray:
            findings.append(make_finding(
                entity="Cloudflare detected (cf-ray header)",
                type="CDN Detection",
                source="DNSHistory (HTTP Probe)",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                raw_data=f"Cloudflare Ray ID present",
                tags=["cdn", "cloudflare"]
            ))
        if powered_by:
            findings.append(make_finding(
                entity=powered_by[:200],
                ftype="X-Powered-By Header",
                source="DNSHistory (HTTP Probe)",
                confidence="High",
                color="slate",
                raw_data=f"X-Powered-By: {powered_by}",
                tags=["technology", "fingerprint"]
            ))
    except httpx.ConnectError:
        findings.append(make_finding(
            entity="HTTPS connection FAILED",
            ftype="HTTPS Service Check",
            source="DNSHistory (HTTP Probe)",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="Offline",
            raw_data="Could not establish HTTPS connection",
            tags=["https", "offline"]
        ))
    except Exception:
        pass
    return findings


async def _check_dns_history_securitytrails(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    urls_to_try = [
        f"https://api.securitytrails.com/v1/domain/{domain}/dns",
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
    ]
    for url in urls_to_try:
        try:
            resp = await safe_fetch(client, 
                url, timeout=12.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if "subdomains" in data:
                    subs = data["subdomains"]
                    findings.append(make_finding(
                        entity=f"{len(subs)} subdomains from SecurityTrails",
                        type="SecurityTrails - Subdomain Count",
                        source="DNSHistory (SecurityTrails)",
                        confidence="High",
                        color="blue",
                        raw_data=f"Subdomains: {len(subs)}",
                        tags=["securitytrails", "subdomain-count"]
                    ))
                    for sub in subs[:10]:
                        findings.append(make_finding(
                            entity=f"{sub}.{domain}",
                            ftype="SecurityTrails - Historic Subdomain",
                            source="DNSHistory (SecurityTrails)",
                            confidence="High",
                            color="emerald",
                            status="Historical",
                            raw_data=f"Subdomain: {sub}.{domain}",
                            tags=["securitytrails", "subdomain", "historical"]
                        ))
                if "a" in data or "A" in data:
                    a_records = data.get("a", data.get("A", []))
                    if isinstance(a_records, list):
                        findings.append(make_finding(
                            entity=f"{len(a_records)} A records in SecurityTrails",
                            type="SecurityTrails - A Record History",
                            source="DNSHistory (SecurityTrails)",
                            confidence="High",
                            color="slate",
                            raw_data=f"A records: {a_records[:5]}",
                            tags=["securitytrails", "a-record", "history"]
                        ))
                break
        except Exception:
            continue
    return findings


async def _check_ip_reputation(domain: str, current_ips: set, client: httpx.AsyncClient) -> list:
    findings = []
    for ip in current_ips:
        try:
            resp = await safe_fetch(client, 
                f"https://ipapi.co/{ip}/json/",
                timeout=10.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                org = data.get("org", "")
                country = data.get("country_name", "")
                asn = data.get("asn", "")
                if org:
                    findings.append(make_finding(
                        entity=org[:200],
                        ftype="IP Organization",
                        source="DNSHistory (IP Geolocation)",
                        confidence="High",
                        color="slate",
                        resolution=ip,
                        raw_data=f"ORG: {org}, Country: {country}",
                        tags=["ip-geo", "organization"]
                    ))
                if "cloud" in org.lower() or "aws" in org.lower() or "google" in org.lower() or "azure" in org.lower() or "cloudflare" in org.lower():
                    findings.append(make_finding(
                        entity=f"Hosted on cloud provider: {org}",
                        ftype="Cloud Provider Detection",
                        source="DNSHistory (IP Geolocation)",
                        confidence="High",
                        color="orange",
                        raw_data=f"IP {ip} belongs to {org}",
                        tags=["cloud", "hosting"]
                    ))
                break
        except Exception:
            continue
    return findings


async def _check_dns_timeline(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        doh_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if doh_resp.status_code == 200:
            doh_data = doh_resp.json()
            answers = doh_data.get("Answer", [])
            current_ips = set()
            ttl_values = []
            for ans in answers:
                if ans.get("type") == 1:
                    ip_val = ans.get("data", "")
                    if ip_val:
                        current_ips.add(ip_val)
                        ttl_values.append(ans.get("TTL", 0))
            if ttl_values:
                avg_ttl = sum(ttl_values) / len(ttl_values)
                findings.append(make_finding(
                    entity=f"Average TTL: {avg_ttl:.0f}s (low={min(ttl_values)}, high={max(ttl_values)})",
                    type="DNS Timeline - TTL Analysis",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="slate",
                    raw_data=f"TTL values: {ttl_values}",
                    tags=["dns", "ttl", "timeline"]
                ))
                if avg_ttl < 300:
                    findings.append(make_finding(
                        entity="Low TTL (<5 min) suggests dynamic DNS or fast-flux",
                        type="DNS Timeline - Fast Flux Detection",
                        source="DNSHistory (Google DoH)",
                        confidence="Medium",
                        color="red",
                        threat_level="Elevated Risk",
                        raw_data=f"Average TTL: {avg_ttl:.0f}s",
                        tags=["fast-flux", "dynamic-dns"]
                    ))
    except Exception:
        pass
    return findings


async def _check_dns_records_bulk(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    record_types_to_check = [
        ("HINFO", 13, "HINFO Record (OS/CPU info)"),
        ("RP", 17, "RP Record (Responsible Person)"),
        ("LOC", 29, "LOC Record (Location)"),
        ("NAPTR", 35, "NAPTR Record"),
        ("SRV", 33, "SRV Record (Service)"),
    ]
    for rtype_name, rtype_num, desc in record_types_to_check:
        try:
            resp = await safe_fetch(client, 
                f"https://dns.google/resolve?name={domain}&type={rtype_name}",
                timeout=10.0,
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                matching = [a for a in answers if a.get("type") == rtype_num]
                if matching:
                    for ans in matching[:3]:
                        findings.append(make_finding(
                            entity=ans.get("data", "")[:200],
                            type=desc,
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"{rtype_name}: {ans.get('data', '')}",
                            tags=["dns", rtype_name.lower()]
                        ))
        except Exception:
            pass
    return findings


async def _check_viewdns_history(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://viewdns.info/iphistory/?domain={domain}",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            ip_dates = re.findall(r'>(\d+\.\d+\.\d+\.\d+)</td><td>(\d{4}-\d{2}-\d{2})', resp.text)
            ip_dates_unique = list(set(ip_dates))
            if ip_dates_unique:
                findings.append(make_finding(
                    entity=f"{len(ip_dates_unique)} historical IP changes from ViewDNS",
                    type="ViewDNS - IP History Summary",
                    source="DNSHistory (ViewDNS)",
                    confidence="Medium",
                    color="blue",
                    raw_data=f"Historical IPs found: {len(ip_dates_unique)}",
                    tags=["viewdns", "ip-history"]
                ))
                ip_count = {}
                for ip, dt in ip_dates_unique[:30]:
                    ip_count[ip] = ip_count.get(ip, 0) + 1
                for ip, cnt in sorted(ip_count.items(), key=lambda x: -x[1])[:5]:
                    findings.append(make_finding(
                        entity=ip,
                        ftype="ViewDNS - Historical IP",
                        source="DNSHistory (ViewDNS)",
                        confidence="Medium",
                        color="slate",
                        status="Historical",
                        raw_data=f"IP {ip} seen {cnt} times in history",
                        tags=["viewdns", "ip", "historical"]
                    ))
                if len(ip_count) >= 5:
                    findings.append(make_finding(
                        entity=f"IP changed {len(ip_count)} times - high volatility",
                        type="ViewDNS - IP Volatility",
                        source="DNSHistory (ViewDNS)",
                        confidence="Medium",
                        color="orange",
                        threat_level="Standard Target",
                        raw_data=f"Unique IPs over time: {len(ip_count)}",
                        tags=["ip-volatility", "viewdns"]
                    ))
    except Exception:
        pass
    return findings


async def _check_dnssec_and_security(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=DNSKEY",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            answers = data.get("Answer", [])
            dnskey_records = [a for a in answers if a.get("type") == 48]
            rrsig_records = [a for a in answers if a.get("type") == 46]
            if dnskey_records:
                findings.append(make_finding(
                    entity=f"{len(dnskey_records)} DNSKEY records found",
                    type="DNSSEC - DNSKEY Records",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="emerald",
                    status="DNSSEC Enabled",
                    raw_data=f"DNSKEY count: {len(dnskey_records)}",
                    tags=["dnssec", "dnskey"]
                ))
            if rrsig_records:
                findings.append(make_finding(
                    entity=f"{len(rrsig_records)} RRSIG records - zone is signed",
                    type="DNSSEC - RRSIG Present",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="emerald",
                    status="Signed Zone",
                    raw_data=f"RRSIG count: {len(rrsig_records)}",
                    tags=["dnssec", "rrsig"]
                ))
    except Exception:
        pass
    return findings


async def _check_certificate_chain(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        import ssl as ssl_mod
        loop = asyncio.get_event_loop()
        def check_cert():
            try:
                ctx = ssl_mod.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(8)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    cipher = s.cipher()
                    proto = s.version()
                    return {"cert": cert, "cipher": cipher, "protocol": proto}
            except:
                return None
        result = await loop.run_in_executor(None, check_cert)
        if result:
            cert = result.get("cert", {})
            if cert.get("subject"):
                cn = ""
                for item in cert.get("subject", []):
                    for key, val in item:
                        if key == "commonName":
                            cn = val
                if cn:
                    findings.append(make_finding(
                        entity=cn[:200],
                        ftype="SSL Certificate Subject CN",
                        source="DNSHistory (SSL Check)",
                        confidence="High",
                        color="slate",
                        raw_data=f"Common Name: {cn}",
                        tags=["ssl", "subject-cn"]
                    ))
            cipher_info = result.get("cipher", ())
            if cipher_info:
                cipher_name = cipher_info[0]
                proto = result.get("protocol", "")
                findings.append(make_finding(
                    entity=f"{proto} / {cipher_name}",
                    ftype="SSL Cipher & Protocol",
                    source="DNSHistory (SSL Check)",
                    confidence="High",
                    color="emerald",
                    raw_data=f"Protocol: {proto}, Cipher: {cipher_name}",
                    tags=["ssl", "cipher", "protocol"]
                ))
    except Exception:
        pass
    return findings


async def _check_email_security_extended(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        import dns.resolver
        loop = asyncio.get_event_loop()

        mx_records = []
        try:
            answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
            mx_records = [str(r.exchange).rstrip('.') for r in answers]
        except:
            pass

        if mx_records:
            mx_hosters = set()
            for mx in mx_records:
                mx_lower = mx.lower()
                if "google" in mx_lower or "googlemail" in mx_lower:
                    mx_hosters.add("Google Workspace (Gmail)")
                elif "outlook" in mx_lower or "protection.outlook" in mx_lower or "microsoft" in mx_lower:
                    mx_hosters.add("Microsoft 365 (Exchange Online)")
                elif "zoho" in mx_lower:
                    mx_hosters.add("Zoho Mail")
                elif "protonmail" in mx_lower or "proton" in mx_lower:
                    mx_hosters.add("ProtonMail")
                elif "yandex" in mx_lower:
                    mx_hosters.add("Yandex Mail")
                elif "mailgun" in mx_lower:
                    mx_hosters.add("Mailgun")
                elif "sendgrid" in mx_lower or "sendgrid" in mx_lower:
                    mx_hosters.add("SendGrid")
                elif "fastmail" in mx_lower:
                    mx_hosters.add("FastMail")
                elif "rackspace" in mx_lower:
                    mx_hosters.add("Rackspace Email")
                elif "icloud" in mx_lower or "apple" in mx_lower:
                    mx_hosters.add("Apple iCloud")
                else:
                    mx_hosters.add("Custom/Other")

            for h in sorted(mx_hosters):
                findings.append(make_finding(
                    entity=h,
                    ftype="Email Hosting Provider",
                    source="DNSHistory (MX Analysis)",
                    confidence="High",
                    color="slate",
                    raw_data=f"MX indicates: {h}",
                    tags=["email", "hosting", "mx-analysis"]
                ))

            findings.append(make_finding(
                entity=f"MX servers: {', '.join(mx_records[:3])}",
                type="Mail Server (MX Records)",
                source="DNSHistory",
                confidence="High",
                color="blue",
                raw_data=f"MX: {mx_records}",
                tags=["email", "mx"]
            ))
        else:
            findings.append(make_finding(
                entity="No MX records - domain cannot receive email",
                ftype="Missing MX Records",
                source="DNSHistory",
                confidence="High",
                color="orange",
                threat_level="Standard Target",
                status="No Email",
                raw_data="No MX records configured",
                tags=["email", "mx", "missing"]
            ))
    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    raw_target = target.strip().lower()
    if "://" in raw_target:
        domain = urlparse(raw_target).netloc
    else:
        domain = raw_target

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))

    if is_ip:
        try:
            host = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.gethostbyaddr(domain)
            )
            findings.append(make_finding(
                entity=host[0],
                ftype="Reverse DNS (PTR)",
                source="DNSHistory",
                confidence="High",
                color="blue",
                status="Active",
                resolution=f"PTR for {domain}",
                raw_data=f"Hostname: {host[0]}",
                tags=["dns", "ptr"]
            ))
        except Exception:
            pass
        try:
            crt_resp = await safe_fetch(client, 
                f"https://crt.sh/?q={domain}&output=json",
                timeout=15.0,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            )
            if crt_resp.status_code == 200:
                certs = crt_resp.json()
                if isinstance(certs, list):
                    seen = set()
                    for cert in certs[:80]:
                        name = cert.get("name_value", "")
                        if name and name not in seen:
                            seen.add(name)
                            findings.append(make_finding(
                                entity=name[:200],
                                ftype="Domain Associated with IP (crt.sh)",
                                source="DNSHistory",
                                confidence="High",
                                color="blue",
                                status="Historical",
                                resolution=cert.get("not_before", "")[:10],
                                raw_data=f"Cert valid {cert.get('not_before','')[:10]} to {cert.get('not_after','')[:10]}"
                            ))
        except Exception:
            pass
        return findings

    loop = asyncio.get_event_loop()

    try:
        whois_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/whois/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if whois_resp.status_code == 200 and "error" not in whois_resp.text.lower()[:50]:
            whois_text = whois_resp.text
            creation_date = None
            expiry_date = None
            registrars = []
            name_servers = []
            org = None
            admin_email = None
            tech_email = None
            for line in whois_text.split("\n"):
                if "Creation Date" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    creation_date = val[:20]
                elif "Registry Expiry Date" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    expiry_date = val[:20]
                elif "Registrar" in line and ":" in line:
                    r = line.split(":", 1)[1].strip()
                    if r and r not in registrars:
                        registrars.append(r)
                elif "Name Server" in line and ":" in line:
                    ns = line.split(":", 1)[1].strip()
                    if ns:
                        name_servers.append(ns)
                elif "Registrant Organization" in line and ":" in line:
                    org = line.split(":", 1)[1].strip()
                elif "Admin Email" in line and ":" in line:
                    admin_email = line.split(":", 1)[1].strip()
                elif "Tech Email" in line and ":" in line:
                    tech_email = line.split(":", 1)[1].strip()

            if creation_date:
                try:
                    created_dt = datetime.strptime(creation_date[:10], "%Y-%m-%d")
                    age_days = (datetime.now() - created_dt).days
                    age_years = age_days / 365.25
                    age_label = f"{age_years:.1f} years"
                    if age_years < 1:
                        age_label = f"{age_days} days"
                    findings.append(make_finding(
                        entity=f"Domain age: {age_label} (created {creation_date[:10]})",
                        type="DNS History - Domain Age",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="emerald" if age_years > 3 else "orange",
                        status="Active",
                        resolution=creation_date[:10],
                        raw_data=f"Created: {creation_date}, Age: {age_label}",
                        tags=["domain-age", "whois"]
                    ))
                    if age_days < 30:
                        findings.append(make_finding(
                            entity="Domain is VERY NEW (<30 days) - HIGH RISK",
                            type="DNS History - New Domain Alert",
                            source="DNSHistory (WHOIS)",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Newly Registered",
                            raw_data=f"Domain age: {age_days} days",
                            tags=["new-domain", "risk"]
                        ))
                    elif age_days < 365:
                        findings.append(make_finding(
                            entity="Domain is less than 1 year old",
                            ftype="DNS History - Domain Age Risk",
                            source="DNSHistory (WHOIS)",
                            confidence="High",
                            color="orange",
                            threat_level="Elevated Risk",
                            status="Relatively New",
                            raw_data=f"Domain age: {age_days} days",
                            tags=["domain-age", "risk"]
                        ))
                except Exception:
                    pass

            if expiry_date:
                findings.append(make_finding(
                    entity=f"Domain expires: {expiry_date[:10]}",
                    ftype="DNS History - Domain Expiry",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="red" if "202" not in expiry_date[:7] else "emerald",
                    status="Active" if "202" in expiry_date[:7] else "Expiring",
                    raw_data=f"Expiry: {expiry_date[:10]}"
                ))
                try:
                    exp_dt = datetime.strptime(expiry_date[:10], "%Y-%m-%d")
                    days_until_expiry = (exp_dt - datetime.now()).days
                    if days_until_expiry < 30:
                        findings.append(make_finding(
                            entity=f"Domain EXPIRES SOON ({days_until_expiry} days)",
                            type="DNS History - Imminent Expiry",
                            source="DNSHistory (WHOIS)",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Expiring Soon",
                            raw_data=f"Days until expiry: {days_until_expiry}",
                            tags=["expiry", "risk"]
                        ))
                except Exception:
                    pass

            if registrars:
                for registrar in registrars[:2]:
                    findings.append(make_finding(
                        entity=registrar[:200],
                        ftype="DNS History - Registrar",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="slate",
                        raw_data=f"Registrar: {registrar}"
                    ))

            if org:
                findings.append(make_finding(
                    entity=org[:200],
                    ftype="DNS History - Registrant Organization",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="slate",
                    raw_data=f"Organization: {org}"
                ))

            if admin_email:
                findings.append(make_finding(
                    entity=admin_email[:200],
                    ftype="DNS History - Admin Email",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="orange",
                    raw_data=f"Admin Email: {admin_email}"
                ))

            if tech_email:
                findings.append(make_finding(
                    entity=tech_email[:200],
                    ftype="DNS History - Tech Email",
                    source="DNSHistory (WHOIS)",
                    confidence="High",
                    color="orange",
                    raw_data=f"Tech Email: {tech_email}"
                ))

            if name_servers:
                ns_providers = set()
                for ns in name_servers[:5]:
                    findings.append(make_finding(
                        entity=ns[:200],
                        ftype="DNS History - Nameserver",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="blue",
                        raw_data=f"Nameserver: {ns}"
                    ))
                    ns_lower = ns.lower()
                    if "awsdns" in ns_lower:
                        ns_providers.add("AWS Route53")
                    elif "cloudflare" in ns_lower or "ns.cloudflare" in ns_lower:
                        ns_providers.add("Cloudflare DNS")
                    elif "googledomains" in ns_lower or "ns-." in ns_lower:
                        ns_providers.add("Google Cloud DNS")
                    elif "azure" in ns_lower or "azure" in ns_lower:
                        ns_providers.add("Azure DNS")
                    elif "dnsmadeeasy" in ns_lower:
                        ns_providers.add("DNS Made Easy")
                    elif "ns1.com" in ns_lower:
                        ns_providers.add("NS1")
                    elif "ultradns" in ns_lower:
                        ns_providers.add("UltraDNS (Neustar)")
                    elif "akamai" in ns_lower:
                        ns_providers.add("Akamai DNS")
                    elif "registrar-servers" in ns_lower:
                        ns_providers.add("Namecheap (registrar DNS)")
                    elif "domaincontrol" in ns_lower:
                        ns_providers.add("GoDaddy DNS")
                    else:
                        ns_providers.add("Custom/Unknown DNS")
                for prov in sorted(ns_providers):
                    findings.append(make_finding(
                        entity=f"Nameserver Provider: {prov}",
                        ftype="DNS History - NS Provider",
                        source="DNSHistory (WHOIS)",
                        confidence="High",
                        color="purple",
                        raw_data=f"Detected provider: {prov}",
                        tags=["nameserver", "provider", "dns-hosting"]
                    ))
    except Exception:
        pass

    try:
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        crt_resp = await safe_fetch(client, crt_url, timeout=20.0, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if crt_resp.status_code == 200:
            certs = crt_resp.json()
            if isinstance(certs, list) and certs:
                name_data = {}
                for cert in certs[:300]:
                    name_val = cert.get("name_value", "").strip()
                    if not name_val or "*" in name_val:
                        continue
                    nb = cert.get("not_before", "")[:10]
                    na = cert.get("not_after", "")[:10]
                    for single_name in name_val.split("\n"):
                        single_name = single_name.strip().lower()
                        if not single_name or single_name == domain or "*" in single_name:
                            continue
                        if not single_name.endswith("." + domain):
                            continue
                        if single_name not in name_data:
                            name_data[single_name] = {"first": nb, "last": na, "count": 0}
                        if nb and (nb < name_data[single_name]["first"] or not name_data[single_name]["first"]):
                            name_data[single_name]["first"] = nb
                        if na and (na > name_data[single_name]["last"] or not name_data[single_name]["last"]):
                            name_data[single_name]["last"] = na
                        name_data[single_name]["count"] += 1

                for name, data in sorted(name_data.items(), key=lambda x: x[1]["first"])[:40]:
                    findings.append(make_finding(
                        entity=name[:200],
                        ftype="DNS History - Historic Subdomain (CT Log)",
                        source="DNSHistory (crt.sh)",
                        confidence="High",
                        color="emerald",
                        status="Historical",
                        resolution=f"First seen: {data['first']}",
                        raw_data=f"First: {data['first']}, Last: {data['last']}, Certs: {data['count']}",
                        tags=["dns-history", "subdomain", "certificate-transparency"]
                    ))

                findings.append(make_finding(
                    entity=f"{len(name_data)} unique subdomains found in CT logs",
                    type="DNS History - CT Log Summary",
                    source="DNSHistory (crt.sh)",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Total historic subdomains: {len(name_data)}",
                    tags=["summary"]
                ))

                earliest_date = None
                for data in name_data.values():
                    if data["first"] and (earliest_date is None or data["first"] < earliest_date):
                        earliest_date = data["first"]
                if earliest_date:
                    findings.append(make_finding(
                        entity=f"Earliest SSL cert: {earliest_date}",
                        ftype="DNS History - SSL Timeline Start",
                        source="DNSHistory (crt.sh)",
                        confidence="High",
                        color="slate",
                        raw_data=f"First certificate logged: {earliest_date}"
                    ))
    except Exception:
        pass

    try:
        ht_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if ht_resp.status_code == 200 and "error" not in ht_resp.text.lower()[:50]:
            lines = ht_resp.text.strip().split("\n")
            sub_ip_map = {}
            for line in lines:
                if "," in line:
                    parts = line.split(",", 1)
                    sub = parts[0].strip().lower()
                    ip = parts[1].strip()
                    if sub not in sub_ip_map:
                        sub_ip_map[sub] = set()
                    sub_ip_map[sub].add(ip)

            for sub, ips in list(sub_ip_map.items())[:30]:
                ip_list = ", ".join(sorted(ips)[:3])
                extra = f" and {len(ips)-3} more" if len(ips) > 3 else ""
                findings.append(make_finding(
                    entity=sub[:200],
                    ftype="DNS History - Current Subdomain",
                    source="DNSHistory (HackerTarget)",
                    confidence="High",
                    color="cyan",
                    status="Active",
                    resolution=ip_list[:100],
                    raw_data=f"Subdomain: {sub} -> {ip_list}{extra}",
                    tags=["subdomain", "active"]
                ))

            findings.append(make_finding(
                entity=f"{len(sub_ip_map)} active subdomains from passive DNS",
                type="DNS History - Subdomain Summary",
                source="DNSHistory (HackerTarget)",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"Total current subdomains: {len(sub_ip_map)}",
                tags=["summary"]
            ))

            all_ips = set()
            for ips in sub_ip_map.values():
                all_ips.update(ips)
            if len(all_ips) >= 5:
                findings.append(make_finding(
                    entity=f"{len(all_ips)} unique IPs across {len(sub_ip_map)} subdomains",
                    type="DNS History - IP Diversity",
                    source="DNSHistory",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"IPs: {', '.join(sorted(all_ips)[:10])}",
                    tags=["fast-flux", "ip-diversity"]
                ))
    except Exception:
        pass

    try:
        rev_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/reverseip/?q={domain}",
            timeout=12.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if rev_resp.status_code == 200 and "error" not in rev_resp.text.lower()[:50]:
            lines = rev_resp.text.strip().split("\n")
            rev_hosts = []
            for line in lines:
                if "," in line:
                    host_part = line.split(",")[0].strip()
                    if host_part and host_part != domain:
                        rev_hosts.append(host_part)
            for host in rev_hosts[:15]:
                findings.append(make_finding(
                    entity=host[:200],
                    ftype="DNS History - Co-hosted Domain (Reverse IP)",
                    source="DNSHistory (HackerTarget)",
                    confidence="Medium",
                    color="purple",
                    raw_data=f"Co-hosted domain: {host}",
                    tags=["reverse-ip", "co-hosting"]
                ))
    except Exception:
        pass

    try:
        doh_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if doh_resp.status_code == 200:
            doh_data = doh_resp.json()
            answers = doh_data.get("Answer", [])
            current_ips = set()
            for ans in answers:
                if ans.get("type") == 1:
                    ip_val = ans.get("data", "")
                    if ip_val:
                        current_ips.add(ip_val)

            for ip_val in sorted(current_ips):
                findings.append(make_finding(
                    entity=ip_val,
                    ftype="DNS History - Current A Record",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="emerald",
                    status="Active",
                    resolution=f"A record for {domain}",
                    raw_data=f"{domain} -> {ip_val}",
                    tags=["dns", "a-record"]
                ))

            if len(current_ips) > 2:
                findings.append(make_finding(
                    entity=f"{len(current_ips)} A records: {', '.join(sorted(current_ips))}",
                    type="DNS History - Multiple A Records",
                    source="DNSHistory (Google DoH)",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    raw_data=f"Multiple IPs: {', '.join(sorted(current_ips))}",
                    tags=["load-balancing", "multi-ip"]
                ))
    except Exception:
        pass

    try:
        mx_doh = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=MX",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if mx_doh.status_code == 200:
            mx_data = mx_doh.json()
            mx_answers = mx_data.get("Answer", [])
            for ans in mx_answers:
                if ans.get("type") == 15:
                    mx_val = ans.get("data", "")
                    if mx_val:
                        findings.append(make_finding(
                            entity=mx_val[:200],
                            ftype="DNS History - MX Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"MX: {mx_val}",
                            tags=["dns", "mx"]
                        ))
    except Exception:
        pass

    try:
        ns_doh = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=NS",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if ns_doh.status_code == 200:
            ns_data = ns_doh.json()
            ns_answers = ns_data.get("Answer", [])
            for ans in ns_answers:
                if ans.get("type") == 2:
                    ns_val = ans.get("data", "")
                    if ns_val:
                        findings.append(make_finding(
                            entity=ns_val[:200],
                            ftype="DNS History - NS Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="blue",
                            raw_data=f"NS: {ns_val}",
                            tags=["dns", "nameserver"]
                        ))
    except Exception:
        pass

    try:
        aaaa_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=AAAA",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if aaaa_resp.status_code == 200:
            aaaa_data = aaaa_resp.json()
            aaaa_answers = aaaa_data.get("Answer", [])
            for ans in aaaa_answers:
                if ans.get("type") == 28:
                    aaaa_val = ans.get("data", "")
                    if aaaa_val:
                        findings.append(make_finding(
                            entity=aaaa_val[:200],
                            ftype="DNS History - AAAA Record (IPv6)",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="emerald",
                            status="Active",
                            raw_data=f"AAAA: {aaaa_val}",
                            tags=["dns", "aaaa", "ipv6"]
                        ))
    except Exception:
        pass

    try:
        txt_doh = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=TXT",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if txt_doh.status_code == 200:
            txt_data = txt_doh.json()
            txt_answers = txt_data.get("Answer", [])
            for ans in txt_answers:
                if ans.get("type") == 16:
                    txt_val = ans.get("data", "")
                    if txt_val and txt_val.startswith("v=") and len(txt_val) > 10:
                        findings.append(make_finding(
                            entity=txt_val[:200],
                            ftype="DNS History - TXT Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"TXT: {txt_val[:500]}",
                            tags=["dns", "txt"]
                        ))
    except Exception:
        pass

    try:
        cname_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=CNAME",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if cname_resp.status_code == 200:
            cname_data = cname_resp.json()
            cname_answers = cname_data.get("Answer", [])
            for ans in cname_answers:
                if ans.get("type") == 5:
                    cname_val = ans.get("data", "")
                    if cname_val:
                        findings.append(make_finding(
                            entity=cname_val[:200],
                            ftype="DNS History - CNAME Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="purple",
                            resolution=f"CNAME target",
                            raw_data=f"CNAME: {cname_val}",
                            tags=["dns", "cname"]
                        ))
    except Exception:
        pass

    try:
        soa_resp = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=SOA",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if soa_resp.status_code == 200:
            soa_data = soa_resp.json()
            soa_answers = soa_data.get("Answer", [])
            for ans in soa_answers:
                if ans.get("type") == 6:
                    soa_val = ans.get("data", "")
                    if soa_val:
                        findings.append(make_finding(
                            entity=soa_val[:200],
                            ftype="DNS History - SOA Record",
                            source="DNSHistory (Google DoH)",
                            confidence="High",
                            color="slate",
                            raw_data=f"SOA: {soa_val[:500]}",
                            tags=["dns", "soa"]
                        ))
    except Exception:
        pass

    dnstwister_url = f"https://dnstwister.report/api/fuzz/{domain}"
    try:
        dw_resp = await safe_fetch(client, dnstwister_url, timeout=15.0, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if dw_resp.status_code == 200:
            dw_data = dw_resp.json() if isinstance(dw_resp.text, str) and dw_resp.text.startswith("{") else {}
            if isinstance(dw_data, dict):
                fuzzy = dw_data.get("fuzzy", [])
                if isinstance(fuzzy, list):
                    registered = [f for f in fuzzy if isinstance(f, dict) and f.get("domain") and f.get("registered")]
                    for fuzz_item in registered[:10]:
                        fuzz_domain = fuzz_item.get("domain", "")
                        fuzz_ip = fuzz_item.get("ip", "")
                        if fuzz_domain:
                            findings.append(make_finding(
                                entity=fuzz_domain[:200],
                                ftype="DNS History - Typosquatting Variant",
                                source="DNSHistory (DNSTwister)",
                                confidence="Medium",
                                color="red",
                                threat_level="Elevated Risk",
                                resolution=fuzz_ip[:50] if fuzz_ip else "",
                                raw_data=f"Registered typosquat: {fuzz_domain} -> {fuzz_ip}",
                                tags=["typosquatting", "dns-twister"]
                            ))
    except Exception:
        pass

    try:
        rt_resp = await safe_fetch(client, 
            f"https://api.hackertarget.com/zonetransfer/?q={domain}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if rt_resp.status_code == 200:
            zt_text = rt_resp.text.strip()
            if zt_text and "error" not in zt_text.lower()[:50] and "fail" not in zt_text.lower()[:50]:
                zt_lines = [l.strip() for l in zt_text.split("\n") if l.strip()]
                for zl in zt_lines[:20]:
                    findings.append(make_finding(
                        entity=zl[:200],
                        ftype="DNS History - Zone Transfer Data",
                        source="DNSHistory (HackerTarget)",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        raw_data=f"Zone transfer: {zl[:500]}",
                        tags=["zone-transfer"]
                    ))
                findings.append(make_finding(
                    entity=f"Zone transfer VULNERABLE - {len(zt_lines)} records leaked",
                    type="DNS History - Zone Transfer Risk",
                    source="DNSHistory (HackerTarget)",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["zone-transfer", "critical"]
                ))
    except Exception:
        pass

    dnsbl_findings = await _check_dns_blacklist(domain, client)
    findings.extend(dnsbl_findings)

    dnssec_findings = await _check_dnssec(domain, client)
    findings.extend(dnssec_findings)

    caa_findings = await _check_caa(domain, client)
    findings.extend(caa_findings)

    https_findings = await _check_https_service(domain, client)
    findings.extend(https_findings)

    st_findings = await _check_dns_history_securitytrails(domain, client)
    findings.extend(st_findings)

    timeline_findings = await _check_dns_timeline(domain, client)
    findings.extend(timeline_findings)

    rare_findings = await _check_dns_records_bulk(domain, client)
    findings.extend(rare_findings)

    viewdns_findings = await _check_viewdns_history(domain, client)
    findings.extend(viewdns_findings)

    dnskey_findings = await _check_dnssec_and_security(domain, client)
    findings.extend(dnskey_findings)

    cert_findings = await _check_certificate_chain(domain, client)
    findings.extend(cert_findings)

    email_findings = await _check_email_security_extended(domain, client)
    findings.extend(email_findings)

    try:
        current_ips_in_doh = set()
        doh_check = await safe_fetch(client, 
            f"https://dns.google/resolve?name={domain}&type=A",
            timeout=10.0,
            headers={"Accept": "application/json"}
        )
        if doh_check.status_code == 200:
            for ans in doh_check.json().get("Answer", []):
                if ans.get("type") == 1:
                    current_ips_in_doh.add(ans.get("data", ""))
        ip_rep_findings = await _check_ip_reputation(domain, current_ips_in_doh, client)
        findings.extend(ip_rep_findings)
    except Exception:
        pass

    return findings
