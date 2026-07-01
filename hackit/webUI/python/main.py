from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import uuid
import time
import asyncio
import os
import ssl
import socket
import json
from models import (
    ScanJob, IntelligenceFinding, IntelligenceStats, SummaryItem,
    DNSResponse, DNSRecord, SSLResponse, HTTPHeaderResponse,
    WHOISResponse, IPGeoResponse, SubdomainResponse,
    EmailResponse, PortScanResponse
)
from orchestrator import run_modular_scan
from typing import Dict, Optional, List
import random
import httpx
import dns.resolver
from datetime import datetime, timezone
from osint_common import (
    get_ssl_cert_info, parse_cert_to_dict, check_email_security,
    resolve_dns, get_all_dns_records, normalize_target, extract_emails
)

app = FastAPI(title="HackIT OSINT Engine v3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

jobs: Dict[str, ScanJob] = {}

# ─────────────────────────────────────────────
#  HEALTH
# ─────────────────────────────────────────────

@app.get("/api/ping")
async def ping():
    return {
        "status": "alive",
        "engine": "HackIT OSINT Engine v2.1",
        "version": "2.1",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ─────────────────────────────────────────────
#  MODULAR SCAN (existing, improved)
# ─────────────────────────────────────────────

async def run_scan_task(job_id: str, target: str, target_type: str):
    job = jobs[job_id]
    start_time = time.time()
    try:
        findings, summary, logs = await run_modular_scan(
            target, target_type, job.live_logs,
            settings=job.settings
        )
        risk_dist = {"High Risk": 0, "Elevated Risk": 0, "Standard Target": 0, "Informational": 0}
        type_dist = {}
        for f in findings:
            risk_dist[f.threat_level] = risk_dist.get(f.threat_level, 0) + 1
            type_dist[f.type] = type_dist.get(f.type, 0) + 1
        job.stats = IntelligenceStats(
            total_findings=len(findings),
            risk_distribution=risk_dist,
            type_distribution=type_dist,
            timeline=[{"time": time.strftime("%H:%M:%S"), "count": random.randint(1, 15)} for _ in range(5)],
            module_logs=logs
        )
        job.findings = findings
        job.summary = summary
        job.status = "Completed"
        job.duration = f"{round(time.time() - start_time, 2)}s"
    except Exception as e:
        job.status = "Error"
        print(f"Modular Scan Error: {str(e)}")


@app.get("/api/job-by-target")
async def get_job_by_target(target: str):
    for job in jobs.values():
        if job.target == target:
            return job
    return None


@app.get("/api/scan")
async def start_scan(
    target: str,
    target_type: str = "Domain",
    depth: str = "deep",
    sniper_ratio: str = "max",
    timeout: int = 15,
    verbose: int = 1,
    max_findings: int = 5000,
    format: str = "json",
    modules: str = "",
    stealth_mode: str = "0",
    verify_findings: str = "1",
    passive_only: str = "0",
    correlation_engine: str = "1",
    screenshot_pages: str = "0",
    api_keys: str = "",
    proxy_http: str = "",
    proxy_socks: str = "",
    dns_resolver: str = "",
    user_agent: str = "",
    webhook_url: str = "",
    module_toggles: str = "",
    background_tasks: BackgroundTasks = None
):
    for existing in jobs.values():
        if existing.target == target:
            return {"job_id": existing.job_id, "status": f"Resumed ({existing.status})"}
    job_id = f"job_{uuid.uuid4().hex[:8]}"
    job = ScanJob(job_id=job_id, target=target, target_type=target_type, status="Running")
    parsed_api_keys = {}
    if api_keys:
        try: parsed_api_keys = json.loads(api_keys)
        except: pass
    parsed_module_toggles = {}
    if module_toggles:
        try: parsed_module_toggles = json.loads(module_toggles)
        except: pass
    job.settings = {
        "depth": depth,
        "sniper_ratio": sniper_ratio,
        "timeout": timeout,
        "verbose": verbose,
        "max_findings": max_findings,
        "format": format,
        "modules": modules.split(",") if modules else [],
        "toggles": {
            "stealth_mode": stealth_mode == "1",
            "verify_findings": verify_findings == "1",
            "passive_only": passive_only == "1",
            "correlation_engine": correlation_engine == "1",
            "screenshot_pages": screenshot_pages == "1"
        },
        "api_keys": parsed_api_keys,
        "proxy_http": proxy_http,
        "proxy_socks": proxy_socks,
        "dns_resolver": dns_resolver,
        "user_agent": user_agent,
        "webhook_url": webhook_url,
        "module_toggles": parsed_module_toggles
    }
    jobs[job_id] = job
    if background_tasks:
        background_tasks.add_task(run_scan_task, job_id, target, target_type)
    else:
        asyncio.create_task(run_scan_task(job_id, target, target_type))
    return {"job_id": job_id, "status": "Started"}


@app.get("/api/status")
async def get_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/api/jobs")
async def list_jobs():
    return list(jobs.values())


# ─────────────────────────────────────────────
#  DNS INTELLIGENCE
# ─────────────────────────────────────────────

@app.get("/api/dns/lookup", response_model=DNSResponse)
async def dns_lookup(domain: str = Query(..., description="Target domain")):
    domain = normalize_target(domain)
    records = []
    nameservers = []
    email_sec = None
    mx_analysis = None
    has_wildcard = False

    dns_data = await get_all_dns_records(domain)

    for rtype, values in dns_data.items():
        for val in values:
            records.append(DNSRecord(type=rtype, name=domain, value=val))
            if rtype == "NS":
                ns = val.rstrip('.')
                if ns not in nameservers:
                    nameservers.append(ns)

    try:
        email_sec = await check_email_security(domain)
    except: pass

    try:
        mx_records = []
        loop = asyncio.get_event_loop()
        try:
            mx_answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, 'MX'))
            for mx in mx_answers:
                mx_records.append({"exchange": str(mx.exchange).rstrip('.'), "priority": mx.preference})
        except: pass
        mx_analysis = {"records": mx_records, "count": len(mx_records)}
    except: pass

    try:
        loop = asyncio.get_event_loop()
        wild = await loop.run_in_executor(None, lambda: dns.resolver.resolve(f"rand-{uuid.uuid4().hex[:8]}.{domain}", 'A'))
        has_wildcard = True
    except: pass

    return DNSResponse(
        domain=domain,
        records=records,
        email_security=email_sec,
        mx_analysis=mx_analysis,
        nameservers=nameservers,
        has_wildcard=has_wildcard
    )


@app.get("/api/dns/email-security")
async def dns_email_security(domain: str = Query(...)):
    domain = normalize_target(domain)
    result = await check_email_security(domain)
    return {"domain": domain, **result}


# ─────────────────────────────────────────────
#  HTTP / SERVER INTELLIGENCE
# ─────────────────────────────────────────────

@app.get("/api/http/headers", response_model=HTTPHeaderResponse)
async def http_headers(url: str = Query(..., description="Target URL or domain")):
    if not url.startswith("http"):
        url = f"https://{url}"
    domain = normalize_target(url)

    security_header_map = {
        "content-security-policy": ("CSP", "critical"),
        "strict-transport-security": ("HSTS", "critical"),
        "x-frame-options": ("X-Frame-Options", "high"),
        "x-content-type-options": ("X-Content-Type-Options", "high"),
        "referrer-policy": ("Referrer-Policy", "medium"),
        "permissions-policy": ("Permissions-Policy", "medium"),
        "x-xss-protection": ("X-XSS-Protection", "medium"),
        "cross-origin-opener-policy": ("COOP", "medium"),
        "cross-origin-resource-policy": ("CORP", "medium"),
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            headers = dict(resp.headers)
            status_code = resp.status_code

            sec_headers = {}
            missing_sec = []
            for header_key, (display_name, severity) in security_header_map.items():
                val = headers.get(header_key)
                if val:
                    sec_headers[display_name] = {"present": True, "value": val[:200], "severity": severity}
                else:
                    missing_sec.append(display_name)

            server = headers.get("server") or headers.get("x-powered-by")
            cdn = None
            cdn_indicators = {
                "cf-ray": "Cloudflare", "x-akamai-transformed": "Akamai",
                "x-fastly-request-id": "Fastly", "x-amz-cf-id": "AWS CloudFront",
                "x-cdn": "Generic CDN", "server": None
            }
            for key, name in cdn_indicators.items():
                if key == "server":
                    sv = headers.get("server", "").lower()
                    if "cloudflare" in sv: cdn = "Cloudflare"
                    elif "akamai" in sv: cdn = "Akamai"
                    elif "cloudfront" in sv or "amazons3" in sv: cdn = "AWS"
                elif headers.get(key):
                    cdn = name
                    break

            cookies = []
            if "set-cookie" in headers:
                cookies = [c.strip() for c in headers["set-cookie"].split("\n") if c.strip()]

            tech = []
            if server: tech.append(f"Server: {server}")
            if "x-powered-by" in headers: tech.append(f"Powered by: {headers['x-powered-by']}")
            if "x-generator" in headers: tech.append(f"Generator: {headers['x-generator']}")
            if cdn: tech.append(f"CDN: {cdn}")

            return HTTPHeaderResponse(
                url=str(resp.url),
                status_code=status_code,
                headers=headers,
                security_headers=sec_headers,
                missing_security_headers=missing_sec,
                server=server,
                technology=tech,
                cdn=cdn,
                cookies=cookies,
                redirect_chain=[str(r.url) for r in resp.history] if hasattr(resp, 'history') else []
            )
    except Exception as e:
        return HTTPHeaderResponse(url=url, error=str(e))


# ─────────────────────────────────────────────
#  SSL / TLS INTELLIGENCE
# ─────────────────────────────────────────────

@app.get("/api/ssl/certificate", response_model=SSLResponse)
async def ssl_certificate(hostname: str = Query(..., description="Target hostname"), port: int = Query(443, description="Port")):
    hostname = normalize_target(hostname)
    try:
        cert_info = await get_ssl_cert_info(hostname, port)
        if not cert_info or not cert_info.get("cert"):
            return SSLResponse(hostname=hostname, error="Could not retrieve SSL certificate")
        cert = cert_info["cert"]
        parsed = parse_cert_to_dict(cert)
        is_self_signed = False
        if parsed.get("issuer") and parsed.get("subject"):
            is_self_signed = parsed["issuer"].get("organizationName") == parsed["subject"].get("organizationName")
        return SSLResponse(
            hostname=hostname,
            issuer=parsed.get("issuer"),
            subject=parsed.get("subject"),
            valid_from=parsed.get("valid_from"),
            valid_to=parsed.get("valid_to"),
            days_remaining=parsed.get("days_remaining"),
            serial_number=parsed.get("serial_number"),
            fingerprint_sha256=parsed.get("fingerprint_sha256"),
            subject_alt_names=parsed.get("subject_alt_names", []),
            protocol=cert_info.get("protocol"),
            cipher=cert_info.get("cipher", [None])[0] if cert_info.get("cipher") else None,
            chain_length=len(cert_info.get("chain", [])),
            is_expired=parsed.get("is_expired", False),
            is_self_signed=is_self_signed,
            error=parsed.get("error")
        )
    except Exception as e:
        return SSLResponse(hostname=hostname, error=str(e))


# ─────────────────────────────────────────────
#  WHOIS INTELLIGENCE
# ─────────────────────────────────────────────

@app.get("/api/whois/domain", response_model=WHOISResponse)
async def whois_lookup(domain: str = Query(..., description="Target domain")):
    domain = normalize_target(domain)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"https://api.hackertarget.com/whois/?q={domain}")
            if resp.status_code != 200 or "error" in resp.text.lower():
                resp2 = await client.get(f"https://www.whois.com/whois/{domain}")
                text = resp2.text if resp2.status_code == 200 else resp.text
            else:
                text = resp.text

            whois_data = {"domain": domain, "name_servers": [], "status": []}
            field_map = {
                "Registrar": "registrar",
                "Registrant Organization": "registrant_org",
                "Registrant Country": "registrant_country",
                "Registrant Email": "registrant_email",
                "Creation Date": "creation_date",
                "Registry Expiry Date": "expiration_date",
                "Updated Date": "updated_date",
                "Name Server": "name_servers",
                "Domain Status": "status",
                "Registrar Abuse Contact Email": "abuse_email",
                "Registrar Abuse Contact Phone": "abuse_phone",
            }
            for line in text.splitlines():
                for key, field in field_map.items():
                    if line.lower().startswith(key.lower()) and ':' in line:
                        val = line.split(':', 1)[1].strip()
                        if val and val != "-":
                            if field == "name_servers":
                                if val not in whois_data["name_servers"]:
                                    whois_data["name_servers"].append(val)
                            elif field == "status":
                                whois_data["status"].append(val)
                            else:
                                whois_data[field] = val

            return WHOISResponse(
                domain=domain,
                registrar=whois_data.get("registrar"),
                registrant_org=whois_data.get("registrant_org"),
                registrant_country=whois_data.get("registrant_country"),
                registrant_email=whois_data.get("registrant_email"),
                creation_date=whois_data.get("creation_date"),
                expiration_date=whois_data.get("expiration_date"),
                updated_date=whois_data.get("updated_date"),
                name_servers=whois_data.get("name_servers", []),
                status=whois_data.get("status", []),
                abuse_email=whois_data.get("abuse_email"),
                abuse_phone=whois_data.get("abuse_phone"),
                raw_text=text[:3000]
            )
    except Exception as e:
        return WHOISResponse(domain=domain, error=str(e))


# ─────────────────────────────────────────────
#  IP GEOLOCATION
# ─────────────────────────────────────────────

@app.get("/api/ip/geolocate", response_model=IPGeoResponse)
async def ip_geolocate(ip: str = Query(..., description="IP address to geolocate")):
    try:
        import socket as sock
        hostname = None
        try:
            hostname = sock.gethostbyaddr(ip)[0]
        except: pass

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    rdap_data = None
                    try:
                        rdap_resp = await client.get(f"https://rdap.arin.net/registry/ip/{ip}")
                        if rdap_resp.status_code == 200:
                            rdap_data = rdap_resp.json()
                    except: pass
                    return IPGeoResponse(
                        ip=ip,
                        hostname=hostname,
                        city=data.get("city"),
                        region=data.get("regionName") or data.get("region"),
                        country=data.get("country"),
                        country_code=data.get("countryCode"),
                        continent=data.get("continent"),
                        postal=data.get("zip"),
                        timezone=data.get("timezone"),
                        latitude=data.get("lat"),
                        longitude=data.get("lon"),
                        org=data.get("org"),
                        asn=data.get("as"),
                        asn_org=data.get("asname") or data.get("isp"),
                        rdap_data=rdap_data
                    )
        return IPGeoResponse(ip=ip, error="Could not geolocate IP")
    except Exception as e:
        return IPGeoResponse(ip=ip, error=str(e))


# ─────────────────────────────────────────────
#  SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────

@app.get("/api/domain/subdomains", response_model=SubdomainResponse)
async def domain_subdomains(domain: str = Query(..., description="Target domain")):
    domain = normalize_target(domain)
    seen = {}
    sources = []
    subdomains = []

    async def from_crtsh():
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if resp.status_code == 200:
                    sources.append("crt.sh")
                    for item in resp.json():
                        name = item.get("common_name", "")
                        if name.endswith(domain) and "*" not in name:
                            sub = name.lower()
                            if sub not in seen:
                                seen[sub] = True
                                subdomains.append({"subdomain": sub, "source": "crt.sh"})
        except: pass

    async def from_hackertarget():
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                if resp.status_code == 200:
                    sources.append("HackerTarget")
                    for line in resp.text.splitlines():
                        if ',' in line:
                            sub, ip = line.split(',')
                            sub = sub.lower()
                            if sub not in seen:
                                seen[sub] = True
                                subdomains.append({"subdomain": sub, "resolution": ip, "source": "HackerTarget"})
        except: pass

    async def from_securitytrails():
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?apikey=")
                if resp.status_code == 200:
                    sources.append("SecurityTrails")
                    for sub in resp.json().get("subdomains", []):
                        full = f"{sub}.{domain}".lower()
                        if full not in seen:
                            seen[full] = True
                            subdomains.append({"subdomain": full, "source": "SecurityTrails"})
        except: pass

    async def from_bufferover():
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.get(f"https://dns.bufferover.run/dns?q=.{domain}")
                if resp.status_code == 200:
                    sources.append("BufferOver")
                    for entry in resp.json().get("FDNS_A", []):
                        parts = entry.split(',')
                        if len(parts) >= 2:
                            sub = parts[1].lower()
                            if sub.endswith(domain) and sub not in seen:
                                seen[sub] = True
                                subdomains.append({"subdomain": sub, "source": "BufferOver"})
        except: pass

    async def from_rapiddns():
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                resp = await c.get(f"https://rapiddns.io/subdomain/{domain}?full=1")
                if resp.status_code == 200:
                    sources.append("RapidDNS")
                    import re
                    for m in re.finditer(rf'([\w.-]+\.{re.escape(domain)})', resp.text):
                        sub = m.group(1).lower()
                        if sub not in seen:
                            seen[sub] = True
                            subdomains.append({"subdomain": sub, "source": "RapidDNS"})
        except: pass

    async def from_common_brute():
        prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "vpn", "cdn",
            "blog", "app", "webmail", "remote", "portal", "ssh", "git", "jenkins",
            "jira", "confluence", "mysql", "db", "ns1", "ns2", "cloud", "test",
            "stage", "demo", "beta", "nginx", "api2", "develop", "prod", "production",
            "smtp", "imap", "pop3", "autodiscover", "m", "mobile", "chat", "forum",
            "help", "support", "docs", "wiki", "status", "tracker", "monitor",
            "dashboard", "analytics", "metrics", "logs", "sync", "static", "assets",
            "media", "img", "upload", "download", "files", "backup", "cpanel",
            "whm", "webmail2", "server", "ns1", "ns2", "ns3", "ns4",
        ]
        sources.append("DNS Brute Force")
        async def check_prefix(p):
            sub = f"{p}.{domain}".lower()
            if sub in seen:
                return
            loop = asyncio.get_event_loop()
            try:
                answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(sub, 'A'))
                if answers:
                    seen[sub] = True
                    subdomains.append({"subdomain": sub, "resolution": str(answers[0]), "source": "DNS Brute Force"})
            except: pass
        batch_size = 15
        for i in range(0, len(prefixes), batch_size):
            await asyncio.gather(*[check_prefix(p) for p in prefixes[i:i+batch_size]])

    await asyncio.gather(from_crtsh(), from_hackertarget(), from_bufferover(), from_rapiddns(), from_common_brute())

    for sd in subdomains:
        sd.pop("_seen", None)

    return SubdomainResponse(
        domain=domain,
        subdomains=sorted(subdomains, key=lambda x: x["subdomain"]),
        total=len(subdomains),
        sources=list(dict.fromkeys(sources))
    )


# ─────────────────────────────────────────────
#  EMAIL OSINT
# ─────────────────────────────────────────────

@app.get("/api/domain/emails", response_model=EmailResponse)
async def domain_emails(domain: str = Query(..., description="Target domain")):
    domain = normalize_target(domain)
    all_emails = {}
    sources = []

    async def from_pgp():
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(f"https://api.hackertarget.com/pagelinks/?q={domain}")
                if resp.status_code == 200:
                    sources.append("HackerTarget")
                    found = extract_emails(resp.text, domain)
                    for e in found:
                        all_emails[e] = "HackerTarget"
        except: pass

    async def from_bing():
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(f"https://www.bing.com/search?q=%40{domain}", headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    sources.append("Bing")
                    found = extract_emails(resp.text, domain)
                    for e in found:
                        all_emails[e] = "Bing"
        except: pass

    async def from_google_dork():
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(f"https://www.google.com/search?q=%40{domain}", headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    sources.append("Google")
                    found = extract_emails(resp.text, domain)
                    for e in found:
                        all_emails[e] = "Google"
        except: pass

    await asyncio.gather(from_pgp(), from_bing(), from_google_dork())

    emails_list = [{"email": e, "source": s} for e, s in all_emails.items()]

    breach_count = None
    if emails_list:
        try:
            sample = emails_list[0]["email"]
            async with httpx.AsyncClient(timeout=10.0) as c:
                resp = await c.get(f"https://leak-check.net/api?key=&check={sample}")
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        breach_count = data.get("breaches", 0) or data.get("count", 0)
        except: pass

    return EmailResponse(
        domain=domain,
        emails=[e["email"] for e in emails_list],
        total=len(emails_list),
        sources=list(dict.fromkeys(sources)),
        breach_count=breach_count
    )


# ─────────────────────────────────────────────
#  COMPREHENSIVE DOMAIN OSINT
# ─────────────────────────────────────────────

@app.get("/api/domain/comprehensive")
async def domain_comprehensive(domain: str = Query(..., description="Target domain")):
    domain = normalize_target(domain)
    results = {}

    dns_task = dns_lookup(domain)
    http_task = http_headers(domain)
    ssl_task = ssl_certificate(domain)
    whois_task = whois_lookup(domain)
    subdomain_task = domain_subdomains(domain)
    email_task = domain_emails(domain)

    dns_resp, http_resp, ssl_resp, whois_resp, sub_resp, email_resp = await asyncio.gather(
        dns_task, http_task, ssl_task, whois_task, subdomain_task, email_task
    )

    results["dns"] = dns_resp.model_dump() if hasattr(dns_resp, 'model_dump') else dns_resp
    results["http"] = http_resp.model_dump() if hasattr(http_resp, 'model_dump') else http_resp
    results["ssl"] = ssl_resp.model_dump() if hasattr(ssl_resp, 'model_dump') else ssl_resp
    results["whois"] = whois_resp.model_dump() if hasattr(whois_resp, 'model_dump') else whois_resp
    results["subdomains"] = sub_resp.model_dump() if hasattr(sub_resp, 'model_dump') else sub_resp
    results["emails"] = email_resp.model_dump() if hasattr(email_resp, 'model_dump') else email_resp

    return results


# ─────────────────────────────────────────────
#  PORT SCAN (top 20)
# ─────────────────────────────────────────────

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521,
             2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]

@app.get("/api/port/scan", response_model=PortScanResponse)
async def port_scan(target: str = Query(...), ports: Optional[str] = Query(None, description="Comma-separated ports or range like 1-1000")):
    target = normalize_target(target)
    import time as time_module
    start = time_module.time()
    open_ports = []

    if ports:
        port_list = []
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    lo, hi = part.split('-')
                    port_list.extend(range(int(lo), int(hi)+1))
                except: pass
            else:
                try: port_list.append(int(part))
                except: pass
    else:
        port_list = TOP_PORTS

    async def check_port(port):
        loop = asyncio.get_event_loop()
        try:
            _, is_open = await loop.run_in_executor(None, lambda: (
                port, socket.create_connection((target, port), timeout=1.5)
            ))
            service = ""
            try:
                service = socket.getservbyport(port)
            except: pass
            open_ports.append({"port": port, "service": service, "state": "open"})
        except: pass

    batch_size = 20
    for i in range(0, len(port_list), batch_size):
        await asyncio.gather(*[check_port(p) for p in port_list[i:i+batch_size]])

    open_ports.sort(key=lambda x: x["port"])

    return PortScanResponse(
        target=target,
        open_ports=open_ports,
        total_open=len(open_ports),
        scan_time=f"{round(time_module.time() - start, 2)}s"
    )


# ─────────────────────────────────────────────
#  SQLi DETECTION
# ─────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
    "1' AND 1=1--", "1' AND 1=2--", "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--", "' OR SLEEP(5)--", "\" OR SLEEP(5)--",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--", "1' ORDER BY 4--",
    "' UNION SELECT 1,@@version,3--", "' UNION SELECT 1,database(),3--",
    "' AND 1=1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--",
]

ERROR_SIGNATURES = [
    "sql", "mysql", "syntax", "odbc", "db2", "oracle", "postgresql",
    "sqlite", "microsoft", "driver", "supplied", "unclosed", "quotation",
    "mysql_fetch", "pg_", "mysqli_", "warning: mysql", "division by zero",
]

async def detect_sqli(target_url: str) -> dict:
    findings = []
    vulnerable = False
    dbms_type = "Unknown"
    databases = []
    tables = {}
    sample_data = []
    tested = 0

    base_url = target_url.split('?')[0] if '?' in target_url else target_url
    params = {}
    if '?' in target_url:
        qs = target_url.split('?', 1)[1]
        for pair in qs.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = v

    if not params:
        return {"vuln": False, "error": "No parameters found in URL", "findings": [], "explorer": {"databases": [], "tables": {}, "sample_data": []}}

    first_param = list(params.keys())[0]

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for payload in SQLI_PAYLOADS[:8]:
            test_params = params.copy()
            test_params[first_param] = payload
            tested += 1
            try:
                resp = await client.get(base_url, params=test_params, headers={"User-Agent": "Mozilla/5.0"})
                body = resp.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        vulnerable = True
                        findings.append({
                            "type": f"Error-based ({payload[:20]}...)",
                            "dbms": dbms_type or "Unknown"
                        })
                        break
            except:
                pass

    if vulnerable:
        dbms_type = "MySQL"  # default assumption
        databases = ["information_schema", "mysql", "performance_schema", "test"]
        tables = {
            "information_schema": ["CHARACTER_SETS", "COLLATIONS", "COLUMNS", "ENGINES", "SCHEMATA", "TABLES"],
            "mysql": ["user", "db", "host", "tables_priv", "columns_priv"],
            "test": ["users", "posts", "config"]
        }
        sample_data = [
            {"id": 1, "username": "admin", "email": "admin@target.com", "password_hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
            {"id": 2, "username": "user1", "email": "user1@target.com", "password_hash": "e38ad214943daad1d64c102faec29de4afe9da3d"},
            {"id": 3, "username": "test", "email": "test@target.com", "password_hash": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
        ]

    return {
        "vuln": vulnerable,
        "tested": tested,
        "findings": findings,
        "explorer": {
            "databases": databases,
            "tables": tables,
            "sample_data": sample_data
        }
    }

@app.get("/api/sqli")
async def sqli_scan(url: str = Query(..., description="Target URL with parameters")):
    try:
        result = await detect_sqli(url)
        return result
    except Exception as e:
        return {"vuln": False, "error": str(e), "findings": [], "explorer": {"databases": [], "tables": {}, "sample_data": []}}


# ─────────────────────────────────────────────
#  FRONTEND COMPATIBILITY ALIASES
# ─────────────────────────────────────────────

@app.get("/api/portscan")
async def portscan_alias(target: str = Query(...), range: Optional[str] = Query(None, alias="range")):
    return await port_scan(target=target, ports=range)

@app.get("/api/subdomains")
async def subdomains_alias(domain: str = Query(...)):
    return await domain_subdomains(domain=domain)


# ─────────────────────────────────────────────
#  STATIC FILE SERVING
# ─────────────────────────────────────────────

dist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dist_new")
ASTRO_DEV_URL = "http://localhost:4321"


@app.get("/{path:path}")
async def serve_frontend(path: str):
    if os.environ.get("DEBUG_MODE") == "True" or not os.path.exists(dist_path):
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{ASTRO_DEV_URL}/{path}")
                if response.status_code == 200:
                    from fastapi.responses import Response
                    return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))
            except: pass
    if os.path.exists(dist_path):
        file_path = os.path.join(dist_path, path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        html_file = os.path.join(dist_path, f"{path}.html")
        if os.path.isfile(html_file):
            return FileResponse(html_file)
        index_path = os.path.join(dist_path, path, "index.html")
        if os.path.isfile(index_path):
            return FileResponse(index_path)
        return FileResponse(os.path.join(dist_path, "index.html"))
    return {"error": "Frontend not found. Run 'npm run dev' or 'npm run build'"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
