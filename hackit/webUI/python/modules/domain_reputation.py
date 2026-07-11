import httpx
import asyncio
import socket
import re
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

BL_CHECKERS = [
    ("Spamhaus ZEN", "zen.spamhaus.org", lambda ip: ip),
    ("Spamhaus DBL", "dbl.spamhaus.org", lambda d: d),
    ("Spamhaus XBL", "xbl.spamhaus.org", lambda ip: ip),
    ("SURBL Multi", "multi.surbl.org", lambda d: d),
    ("URIBL Black", "black.uribl.com", lambda d: d),
    ("URIBL Grey", "grey.uribl.com", lambda d: d),
    ("URIBL Red", "red.uribl.com", lambda d: d),
    ("Barracuda BRBL", "b.barracudacentral.org", lambda ip: ip),
    ("Invaluement", "dnsbl.invaluement.com", lambda d: d),
    ("SORBS DNSBL", "dnsbl.sorbs.net", lambda ip: ip),
    ("CBL Abuseat", "cbl.abuseat.org", lambda ip: ip),
    ("NJABL", "dnsbl.njabl.org", lambda ip: ip),
    ("AHBL", "dnsbl.ahbl.org", lambda ip: ip),
    ("DroneBL", "drone.abuse.ch", lambda ip: ip),
    ("TorDNSBL", "dnsbl.dronebl.org", lambda ip: ip),
    ("ViriBL", "virib.dnsbl.bit.nl", lambda ip: ip),
    ("BlockList.de", "dnsbl.blocklist.de", lambda ip: ip),
    ("SWINOG", "dnsbl.swinog.ch", lambda ip: ip),
    ("RU DNSBL", "dnsbl.dnsbl.net", lambda ip: ip),
    ("WPBL", "dnsbl.wpbl.info", lambda ip: ip),
    ("IX.DNSBL", "dnsbl.ix.dnsbl.manitu.net", lambda ip: ip),
    ("UCEPROTECT", "dnsbl-1.uceprotect.net", lambda ip: ip),
]

async def resolve_to_ips(domain: str):
    loop = asyncio.get_event_loop()
    try:
        ais = await loop.run_in_executor(None, lambda: socket.getaddrinfo(domain, 80, family=socket.AF_INET))
        return list(set(a[4][0] for a in ais))
    except:
        return []

async def check_dnsbl(ip_or_domain: str, dnsbl_host: str, query_func):
    loop = asyncio.get_event_loop()
    try:
        query = query_func(ip_or_domain)
        if not query:
            return False
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', query):
            reversed_ip = ".".join(reversed(query.split('.')))
            fqdn = f"{reversed_ip}.{dnsbl_host}"
        else:
            fqdn = f"{query}.{dnsbl_host}"
        await loop.run_in_executor(None, lambda: socket.getaddrinfo(fqdn, 80, family=socket.AF_INET))
        return True
    except:
        return False

async def query_otx(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/reputation",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def query_urlhaus(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=15.0, method="POST")
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def query_phishtank(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://checkurl.phishtank.com/checkurl/index.php?url={domain}&format=json",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def query_ibm_xforce(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://api.xforce.ibmcloud.com/api/url/{domain}",
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def query_cisco_talos(domain: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F{domain}&query_type=domain",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            return resp.json()
    except: pass
    return {}

async def query_abuseipdb(ip: str, client: httpx.AsyncClient):
    try:
        resp = await safe_fetch(client, 
            f"https://www.abuseipdb.com/check/{ip}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            text = resp.text
            score = 0
            m = re.search(r'is a ([A-Za-z]+)\s*threat', text, re.IGNORECASE)
            if m:
                return {"threat": m.group(1), "category": "abuseipdb"}
    except: pass
    return {}

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    ips = await resolve_to_ips(domain)
    blacklist_hits = 0
    blacklist_details = []

    for ip in ips[:3]:
        for bl_name, bl_host, query_func in BL_CHECKERS:
            try:
                listed = await check_dnsbl(ip if 'ip' in query_func.__code__.co_varnames[:1] else domain, bl_host, query_func)
                if listed:
                    blacklist_hits += 1
                    blacklist_details.append(bl_name)
                    findings.append(make_finding(
                        entity=f"LISTED on {bl_name}",
                        ftype="Blacklist Hit",
                        source="Domain Reputation",
                        confidence="High",
                        color="red",
                        threat_level="Elevated Risk",
                        status="Blacklisted",
                        resolution=ip,
                        raw_data=f"{domain}/{ip} found on {bl_host}",
                        tags=["blacklist", "reputation", bl_name.lower().replace(" ", "-")]
                    ))
            except:
                pass

    if blacklist_hits == 0:
        findings.append(make_finding(
            entity=f"Domain NOT listed on any tested blacklist (clean)",
            type="Blacklist Status",
            source="Domain Reputation",
            confidence="Medium",
            color="green",
            threat_level="Informational",
            status="Clean",
            resolution=domain,
            raw_data=f"Tested {len(BL_CHECKERS)} blacklists, zero hits",
            tags=["blacklist", "clean"]
        ))
    else:
        findings.append(make_finding(
            entity=f"Listed on {blacklist_hits}/{len(BL_CHECKERS)} blacklists: {', '.join(blacklist_details[:8])}",
            type="Blacklist Summary",
            source="Domain Reputation",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status=f"{blacklist_hits} Hits",
            tags=["blacklist", "summary"]
        ))

    otx = await query_otx(domain, client)
    if otx:
        pulses = otx.get("pulse_info", {}).get("pulses", [])
        if pulses:
            findings.append(make_finding(
                entity=f"AlienVault OTX: {len(pulses)} associated pulses",
                type="Threat Intelligence (OTX)",
                source="AlienVault OTX",
                confidence="Medium",
                color="orange",
                threat_level="Standard Target",
                status="OTX Hits",
                resolution=domain,
                tags=["otx", "threat-intel"]
            ))

    urlhaus = await query_urlhaus(domain, client)
    if urlhaus and urlhaus.get("query_status") == "ok":
        findings.append(make_finding(
            entity=f"URLhaus: {urlhaus.get('url_count', 0)} malicious URLs, status={urlhaus.get('threat', '')}",
            type="Threat Intelligence (URLhaus)",
            source="URLhaus",
            confidence="High",
            color="red" if urlhaus.get("threat") == "malware" else "orange",
            threat_level="Elevated Risk",
            status="Malicious" if urlhaus.get("threat") == "malware" else "Suspicious",
            resolution=domain,
            tags=["urlhaus", "malware"]
        ))

    phishtank = await query_phishtank(domain, client)
    if phishtank and phishtank.get("results", {}).get("in_phish_tank") == True:
        findings.append(make_finding(
            entity=f"PhishTank: domain verified as phishing",
            ftype="Threat Intelligence (PhishTank)",
            source="PhishTank",
            confidence="High",
            color="red",
            threat_level="High Risk",
            status="Phishing",
            resolution=domain,
            tags=["phishtank", "phishing"]
        ))

    ibm = await query_ibm_xforce(domain, client)
    if ibm:
        score = ibm.get("score", 0)
        cats = ibm.get("categoryDescriptions", [])
        if score > 0 or cats:
            findings.append(make_finding(
                entity=f"IBM X-Force: score={score}, categories={', '.join(cats[:3])}",
                type="Threat Intelligence (X-Force)",
                source="IBM X-Force",
                confidence="Medium",
                color="orange" if score > 3 else "slate",
                threat_level="Elevated Risk" if score > 3 else "Informational",
                status=f"Score {score}",
                resolution=domain,
                tags=["ibm-xforce", "reputation"]
            ))

    talos = await query_cisco_talos(domain, client)
    if talos:
        talos_score = talos.get("score", 0) if isinstance(talos, dict) else 0
        talos_category = talos.get("category", talos.get("classification", "")) if isinstance(talos, dict) else ""
        if talos_score or talos_category:
            findings.append(make_finding(
                entity=f"Cisco Talos: score={talos_score}, category={talos_category}",
                ftype="Threat Intelligence (Talos)",
                source="Cisco Talos",
                confidence="Medium",
                color="orange" if talos_score > 0 else "slate",
                threat_level="Standard Target" if talos_score > 0 else "Informational",
                status="Suspicious" if talos_score > 0 else "Unknown",
                resolution=domain,
                tags=["talos", "reputation"]
            ))

    for ip in ips[:3]:
        ab = await query_abuseipdb(ip, client)
        if ab:
            findings.append(make_finding(
                entity=f"AbuseIPDB: {ab.get('threat', '')} threat for {ip}",
                type="IP Reputation (AbuseIPDB)",
                source="AbuseIPDB",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                status="Reported",
                resolution=ip,
                tags=["abuseipdb", "ip-reputation"]
            ))

    reputation_score = 100 - (blacklist_hits * 5)
    if reputation_score < 0: reputation_score = 0
    rep_color = "green" if reputation_score >= 80 else "orange" if reputation_score >= 50 else "red"
    rep_threat = "Informational" if reputation_score >= 80 else "Standard Target" if reputation_score >= 50 else "Elevated Risk"
    findings.append(make_finding(
        entity=f"Reputation Score: {reputation_score}/100 ({'Low Risk' if reputation_score >= 80 else 'Medium Risk' if reputation_score >= 50 else 'High Risk'})",
        type="Domain Reputation Score",
        source="Domain Reputation",
        confidence="Medium",
        color=rep_color,
        threat_level=rep_threat,
        status=f"Score {reputation_score}",
        raw_data=f"Score: {reputation_score} | Blacklists: {blacklist_hits}/{len(BL_CHECKERS)} | IPs: {', '.join(ips[:3])}",
        tags=["reputation", "score"]
    ))

    findings.append(make_finding(
        entity=f"Reputation analysis complete for {domain}",
        ftype="Reputation Summary",
        source="Domain Reputation",
        confidence="High",
        color="blue",
        threat_level="Informational",
        status="Complete",
        tags=["reputation", "summary"]
    ))

    return findings
