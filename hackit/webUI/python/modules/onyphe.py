import httpx
import json
import re
from models import IntelligenceFinding

ONYPHE_BASE = "https://www.onyphe.io/api/v2"
ONYPHE_KEY = ""
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

DATASCAN_TYPES = {
    "ip": {"endpoint": "/simple/ip/{target}", "description": "IP Information"},
    "domain": {"endpoint": "/summary/domain/{target}", "description": "Domain Summary"},
    "synscan": {"endpoint": "/simple/synscan/{target}", "description": "SYN Scan Data"},
    "datascan": {"endpoint": "/simple/datascan/{target}", "description": "Service Data Scan"},
    "pastries": {"endpoint": "/simple/pastries/{target}", "description": "Paste/Leak Search"},
    "ports": {"endpoint": "/simple/ports/{target}", "description": "Open Ports"},
    "vulnerabilities": {"endpoint": "/simple/vulnerabilities/{target}", "description": "Vulnerability Scan"},
    "threatlist": {"endpoint": "/simple/threatlist/{target}", "description": "Threat List Check"},
    "geoloc": {"endpoint": "/simple/geoloc/{target}", "description": "Geolocation Data"},
    "whois": {"endpoint": "/simple/whois/{target}", "description": "WHOIS Lookup"},
    "inetnum": {"endpoint": "/simple/inetnum/{target}", "description": "IP Network Info"},
    "resolver": {"endpoint": "/simple/resolver/{target}", "description": "DNS Resolver Check"},
    "forward": {"endpoint": "/simple/forward/{target}", "description": "Forward DNS"},
    "reverse": {"endpoint": "/simple/reverse/{target}", "description": "Reverse DNS"},
}

THREAT_CLASSIFICATIONS = {
    "malware": {"type": "Malware", "severity": "Critical", "color": "red"},
    "botnet": {"type": "Botnet C2", "severity": "Critical", "color": "red"},
    "phishing": {"type": "Phishing", "severity": "Critical", "color": "red"},
    "scanner": {"type": "Scanner", "severity": "Medium", "color": "orange"},
    "attack": {"type": "Attack Source", "severity": "High", "color": "red"},
    "spam": {"type": "Spam Source", "severity": "Medium", "color": "orange"},
    "cve": {"type": "Vulnerable", "severity": "Critical", "color": "red"},
    "exploit": {"type": "Exploited", "severity": "Critical", "color": "red"},
    "paste": {"type": "Paste Leak", "severity": "High", "color": "red"},
    "suspicious": {"type": "Suspicious Activity", "severity": "High", "color": "orange"},
    "ddos": {"type": "DDoS Target", "severity": "Critical", "color": "red"},
    "proxy": {"type": "Proxy/VPN", "severity": "Medium", "color": "orange"},
    "tor": {"type": "Tor Exit Node", "severity": "Medium", "color": "orange"},
}

SERVICE_THREAT_MAP = {
    "ssh": {"severity": "Medium", "color": "orange", "description": "SSH Service"},
    "ftp": {"severity": "High", "color": "red", "description": "FTP Service"},
    "telnet": {"severity": "High", "color": "red", "description": "Telnet Service"},
    "rdp": {"severity": "High", "color": "red", "description": "RDP Service"},
    "mysql": {"severity": "High", "color": "orange", "description": "MySQL Service"},
    "mongodb": {"severity": "Critical", "color": "red", "description": "MongoDB Service"},
    "redis": {"severity": "Critical", "color": "red", "description": "Redis Service"},
    "elasticsearch": {"severity": "Critical", "color": "red", "description": "Elasticsearch Service"},
    "memcached": {"severity": "High", "color": "red", "description": "Memcached Service"},
    "http": {"severity": "Low", "color": "slate", "description": "HTTP Service"},
    "https": {"severity": "Low", "color": "slate", "description": "HTTPS Service"},
    "smtp": {"severity": "Medium", "color": "orange", "description": "SMTP Service"},
    "dns": {"severity": "Medium", "color": "orange", "description": "DNS Service"},
    "vnc": {"severity": "High", "color": "red", "description": "VNC Service"},
    "smb": {"severity": "High", "color": "red", "description": "SMB Service"},
    "nfs": {"severity": "High", "color": "red", "description": "NFS Service"},
}

VULN_SEVERITY_MAP = {
    "critical": ("Critical", "red"),
    "high": ("High Risk", "red"),
    "medium": ("Elevated Risk", "orange"),
    "low": ("Informational", "slate"),
}

def classify_threat(result: dict) -> dict:
    categories = result.get("category", result.get("threat", "")).lower()
    for keyword, classification in THREAT_CLASSIFICATIONS.items():
        if keyword in categories:
            return classification
    return {"type": "Unknown", "severity": "Informational", "color": "slate"}

def assess_risk_level(results: list) -> tuple:
    risk_counts = {"Critical": 0, "High Risk": 0, "Elevated Risk": 0, "Informational": 0}
    for r in results:
        sev = r.get("severity", "Informational")
        if sev in risk_counts:
            risk_counts[sev] += 1
    if risk_counts["Critical"] > 0:
        return "Critical Risk", risk_counts
    if risk_counts["High Risk"] > 0:
        return "High Risk", risk_counts
    if risk_counts["Elevated Risk"] > 0:
        return "Elevated Risk", risk_counts
    return "Informational", risk_counts

async def query_onyphe(target: str, scan_type: str, config: dict, client: httpx.AsyncClient) -> list:
    results = []
    endpoint = config["endpoint"].format(target=target)
    url = f"{ONYPHE_BASE}{endpoint}"
    headers = {
        "User-Agent": UA,
        "Accept": "application/json",
        "X-API-Key": ONYPHE_KEY,
    }
    try:
        resp = await client.get(url, timeout=20.0, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("results", [data]) if isinstance(data, dict) else data
            results.append({
                "scan_type": scan_type,
                "type": "summary",
                "total": data.get("count", data.get("total", len(items))),
                "description": config["description"],
            })
            for item in (items if isinstance(items, list) else [items]):
                if isinstance(item, dict):
                    item["_scan_type"] = scan_type
                    results.append({"scan_type": scan_type, "type": "item", "data": item})
    except Exception as e:
        results.append({"scan_type": scan_type, "type": "error", "message": str(e)[:100]})
    return results

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    ip_target = domain
    try:
        import socket
        ip_target = socket.gethostbyname(domain)
    except Exception:
        pass

    all_results = []
    for scan_type, config in DATASCAN_TYPES.items():
        results = await query_onyphe(ip_target if scan_type not in ("domain", "whois", "forward", "reverse", "resolver") else domain, scan_type, config, client)
        all_results.extend(results)

    seen_ips = set()
    seen_pastes = set()
    scanned_types = set()
    threat_summary = {"Malware": 0, "Botnet": 0, "Scanner": 0, "Phishing": 0, "Paste": 0, "Other": 0}

    for result in all_results:
        if result["type"] == "summary":
            scanned_types.add(result["scan_type"])
            findings.append(IntelligenceFinding(
                entity=f"Onyphe {result['description']}: {result['total']} results",
                type=f"Onyphe: {result['scan_type'].title()} Summary",
                source="Onyphe",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Completed",
                raw_data=f"Scan type: {result['scan_type']}, Total: {result['total']}",
                tags=[f"onyphe-{result['scan_type']}", "summary"],
            ))

        if result["type"] == "error":
            findings.append(IntelligenceFinding(
                entity=f"Onyphe {result['scan_type']} error: {result['message']}",
                type="Onyphe: Scan Error",
                source="Onyphe",
                confidence="Low",
                color="red",
                threat_level="Informational",
                tags=["error"],
            ))

        if result["type"] != "item":
            continue

        item = result["data"]
        scan_type = result["scan_type"]
        if not isinstance(item, dict):
            continue

        ip = item.get("ip", item.get("address", ""))
        port = item.get("port", item.get("port_number", 0))
        service_proto = item.get("protocol", item.get("service", item.get("transport", "")))
        category = item.get("category", item.get("type", ""))
        threat = item.get("threat", item.get("threat_type", ""))
        country = item.get("country", item.get("country_code", ""))
        city = item.get("city", "")
        org = item.get("org", item.get("organization", ""))
        asn = item.get("asn", "")

        # Track threat types for summary
        cat_lower = category.lower()
        for threat_key in threat_summary:
            if threat_key.lower() in cat_lower:
                threat_summary[threat_key] += 1
                break
        else:
            if threat:
                threat_summary["Other"] += 1

        dedup_key = f"{ip}:{port}"
        if dedup_key in seen_ips:
            continue
        seen_ips.add(dedup_key)

        if scan_type == "vulnerabilities":
            vuln_id = item.get("cve", item.get("vuln_id", item.get("id", "")))
            vuln_sev = item.get("severity", item.get("cvss_score", "")).lower()
            sev_info = VULN_SEVERITY_MAP.get(vuln_sev, ("High Risk", "red"))
            entity = f"{vuln_id}" if vuln_id else f"Vulnerability on {ip}:{port}"
            findings.append(IntelligenceFinding(
                entity=entity[:200],
                type=f"Onyphe: Vulnerability ({sev_info[0]})",
                source="Onyphe",
                confidence="High",
                color=sev_info[1],
                threat_level=sev_info[0],
                resolution=ip,
                raw_data=json.dumps(item)[:1000],
                tags=["vulnerability", "onyphe-vuln"],
            ))
            continue

        if scan_type == "pastries":
            paste_id = item.get("id", item.get("paste_id", item.get("@id", "")))
            title = item.get("title", item.get("subject", ""))
            paste_date = item.get("date", item.get("timestamp", ""))
            paste_source = item.get("source", item.get("origin", ""))
            dedup_paste = paste_id or title
            if dedup_paste and dedup_paste not in seen_pastes:
                seen_pastes.add(dedup_paste)
                entity = f"Paste: {title[:80]}" if title else f"Paste ID: {paste_id[:16]}"
                if paste_date:
                    entity += f" ({paste_date})"
                findings.append(IntelligenceFinding(
                    entity=entity[:200],
                    type="Onyphe: Pastrie/Paste Leak",
                    source="Onyphe",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Leaked",
                    raw_data=json.dumps(item)[:1000],
                    tags=["paste-leak", "onyphe-pastrie"],
                ))
            continue

        if scan_type == "threatlist":
            classification = classify_threat(item)
            entity = f"{ip} flagged as {classification['type']}"
            if threat:
                entity += f" ({threat})"
            findings.append(IntelligenceFinding(
                entity=entity[:200],
                type=f"Onyphe: {classification['type']}",
                source="Onyphe",
                confidence="High",
                color=classification["color"],
                threat_level=classification["severity"],
                resolution=ip,
                raw_data=json.dumps(item)[:1000],
                tags=["threatlist", "onyphe-threat"],
            ))
            continue

        if scan_type == "synscan" or scan_type == "ports":
            open_ports = item.get("ports", item.get("open_ports", ""))
            if open_ports:
                findings.append(IntelligenceFinding(
                    entity=f"{ip}: Open ports: {open_ports}",
                    type="Onyphe: Port Scan",
                    source="Onyphe",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    resolution=ip,
                    raw_data=json.dumps(item)[:1000],
                    tags=["port-scan"],
                ))
            continue

        if scan_type == "whois":
            org_name = item.get("org", item.get("organization", ""))
            abuse_email = item.get("abuse_email", "")
            if org_name or abuse_email:
                findings.append(IntelligenceFinding(
                    entity=f"WHOIS: {org_name or domain}",
                    type="Onyphe: WHOIS",
                    source="Onyphe",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    raw_data=json.dumps(item)[:1000],
                    tags=["whois"],
                ))
            continue

        if scan_type == "resolver" or scan_type == "forward" or scan_type == "reverse":
            hostname = item.get("hostname", item.get("forward", item.get("reverse", "")))
            if hostname:
                findings.append(IntelligenceFinding(
                    entity=f"DNS: {hostname}",
                    type="Onyphe: DNS Resolution",
                    source="Onyphe",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=json.dumps(item)[:500],
                    tags=["dns"],
                ))
            continue

        if port:
            service_name = service_proto.lower() if service_proto else ""
            threat_info = SERVICE_THREAT_MAP.get(service_name, {"severity": "Medium", "color": "orange", "description": "Network Service"})
            entity = f"{ip}:{port}"
            if service_name:
                entity += f" ({service_name})"
            if country:
                entity += f" [{country}]"
            findings.append(IntelligenceFinding(
                entity=entity[:200],
                type=f"Onyphe: {threat_info['description']}",
                source="Onyphe",
                confidence="High",
                color=threat_info["color"],
                threat_level=threat_info["severity"],
                resolution=ip,
                raw_data=json.dumps(item)[:1000],
                tags=[f"port-{port}", f"service-{service_name}" if service_name else "service"],
            ))

        # Geolocation/ASN info
        if any([country, city, org, asn]):
            loc_parts = []
            if city:
                loc_parts.append(city)
            if country:
                loc_parts.append(country)
            if asn:
                loc_parts.append(f"AS{asn}")
            if org:
                loc_parts.append(f"({org})")
            loc_str = " ".join(loc_parts)
            findings.append(IntelligenceFinding(
                entity=loc_str[:200],
                type="Onyphe: Geolocation/ASN",
                source="Onyphe",
                confidence="High",
                color="slate",
                threat_level="Informational",
                resolution=ip,
                raw_data=f"Location for {ip}: {loc_str}",
                tags=["geolocation"],
            ))

        if category and scan_type not in ("pastries", "threatlist", "vulnerabilities", "synscan", "ports", "whois", "ip", "domain"):
            classification = classify_threat(item)
            findings.append(IntelligenceFinding(
                entity=f"{ip}:{port} categorized as {category}",
                type=f"Onyphe: {classification['type']}",
                source="Onyphe",
                confidence="Medium",
                color=classification["color"],
                threat_level=classification["severity"],
                resolution=ip,
                raw_data=json.dumps(item)[:1000],
                tags=["category", f"onyphe-{scan_type}"],
            ))

    # Threat intelligence summary
    if any(threat_summary.values()):
        threat_parts = [f"{k}: {v}" for k, v in threat_summary.items() if v > 0]
        findings.append(IntelligenceFinding(
            entity=f"Threat intelligence: {', '.join(threat_parts)}",
            type="Onyphe: Threat Intelligence Summary",
            source="Onyphe",
            confidence="High",
            color="red" if threat_summary.get("Malware", 0) or threat_summary.get("Botnet", 0) else "orange",
            threat_level="High Risk" if threat_summary.get("Malware", 0) or threat_summary.get("Botnet", 0) else "Elevated Risk",
            raw_data=json.dumps(threat_summary),
            tags=["threat-intel"],
        ))

    scan_type_names = [s for s in scanned_types]
    if scan_type_names:
        all_items = [r for r in all_results if r["type"] == "item"]
        risk_level, risk_counts = assess_risk_level(
            [r["data"] for r in all_items if isinstance(r.get("data"), dict)]
        )
        risk_color = "red" if "Critical" in risk_level else "orange"
        findings.append(IntelligenceFinding(
            entity=f"Onyphe scan complete: {len(scanned_types)} scans, {len(all_items)} items, risk: {risk_level}",
            type="Onyphe: Complete Scan Summary",
            source="Onyphe",
            confidence="High",
            color=risk_color,
            threat_level=risk_level,
            status="Completed",
            raw_data=json.dumps({"scans": list(scanned_types), "total_items": len(all_items), "risk": risk_level, "counts": risk_counts}),
            tags=["scan-complete", "onyphe-summary"],
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No Onyphe results found for {target}",
            type="Onyphe: Empty",
            source="Onyphe",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="No Results",
            tags=["empty"],
        ))

    return findings
