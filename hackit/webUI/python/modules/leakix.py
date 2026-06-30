import httpx
import json
from collections import Counter
from models import IntelligenceFinding

LEAKIX_BASE = "https://leakix.net"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

LEAK_CLASSIFICATIONS = {
    "open_database": {"type": "Open Database", "severity": "Critical", "color": "red"},
    "credential_leak": {"type": "Credential Leak", "severity": "Critical", "color": "red"},
    "information_disclosure": {"type": "Info Disclosure", "severity": "High", "color": "red"},
    "misconfiguration": {"type": "Misconfiguration", "severity": "High", "color": "orange"},
    "exposed_service": {"type": "Exposed Service", "severity": "Medium", "color": "orange"},
    "vulnerability": {"type": "Vulnerability", "severity": "Critical", "color": "red"},
    "data_breach": {"type": "Data Breach", "severity": "Critical", "color": "red"},
    "code_repository": {"type": "Code Repository Leak", "severity": "High", "color": "red"},
    "cloud_asset": {"type": "Cloud Asset Exposure", "severity": "Critical", "color": "red"},
    "api_key_leak": {"type": "API Key Leak", "severity": "Critical", "color": "red"},
}

SERVICE_SPECIFIC_RISKS = {
    "MONGODB": {"risk": "Critical", "desc": "Database tanpa autentikasi"},
    "ELASTICSEARCH": {"risk": "Critical", "desc": "Database terbuka untuk publik"},
    "REDIS": {"risk": "Critical", "desc": "Cache store tanpa autentikasi"},
    "MYSQL": {"risk": "High", "desc": "Database MySQL terbuka"},
    "MEMCACHED": {"risk": "High", "desc": "Cache store rentan DDoS amplifikasi"},
    "FTP": {"risk": "High", "desc": "FTP anonymous atau kredensial lemah"},
    "SMTP": {"risk": "Medium", "desc": "SMTP open relay"},
    "HTTP": {"risk": "Low", "desc": "Web server standar"},
    "HTTPS": {"risk": "Low", "desc": "Web server dengan SSL"},
}

def classify_leak_event(event: dict) -> dict:
    leak_str = json.dumps(event).lower()
    if "mongodb" in leak_str or "27017" in leak_str:
        return {"type": "Open MongoDB", "severity": "Critical", "color": "red", "category": "database"}
    if "elasticsearch" in leak_str or "9200" in leak_str:
        return {"type": "Open Elasticsearch", "severity": "Critical", "color": "red", "category": "database"}
    if "redis" in leak_str or "6379" in leak_str:
        return {"type": "Open Redis", "severity": "Critical", "color": "red", "category": "database"}
    if "mysql" in leak_str or "3306" in leak_str:
        return {"type": "Open MySQL", "severity": "Critical", "color": "red", "category": "database"}
    if "memcached" in leak_str or "11211" in leak_str:
        return {"type": "Open Memcached", "severity": "High", "color": "red", "category": "cache"}
    if "ftp" in leak_str:
        return {"type": "Open FTP", "severity": "High", "color": "red", "category": "service"}
    if "smtp" in leak_str:
        return {"type": "Open SMTP", "severity": "Medium", "color": "orange", "category": "service"}
    if "password" in leak_str or "credential" in leak_str:
        return {"type": "Credential Leak", "severity": "Critical", "color": "red", "category": "credentials"}
    if "cve-" in leak_str or "vuln" in leak_str:
        return {"type": "Vulnerability", "severity": "Critical", "color": "red", "category": "vulnerability"}
    if "leak" in leak_str or "breach" in leak_str:
        return {"type": "Data Leak", "severity": "High", "color": "red", "category": "leak"}
    if "api" in leak_str and ("key" in leak_str or "token" in leak_str):
        return {"type": "API Key Leak", "severity": "Critical", "color": "red", "category": "credentials"}
    if "git" in leak_str or "github" in leak_str or "repository" in leak_str:
        return {"type": "Code Repository Leak", "severity": "High", "color": "red", "category": "code"}
    if "aws" in leak_str or "s3" in leak_str or "cloud" in leak_str:
        return {"type": "Cloud Asset Exposure", "severity": "Critical", "color": "red", "category": "cloud"}
    return {"type": "Exposed Service", "severity": "Medium", "color": "orange", "category": "service"}

def extract_service_from_event(event: dict) -> str:
    port = event.get("port", 0)
    service = event.get("service", event.get("_service", ""))
    if service:
        return service.upper()
    port_map = {21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP", 443: "HTTPS", 3306: "MYSQL",
                3389: "RDP", 5432: "POSTGRESQL", 6379: "REDIS", 8080: "HTTP", 8443: "HTTPS",
                9200: "ELASTICSEARCH", 11211: "MEMCACHED", 27017: "MONGODB", 27018: "MONGODB",
                1433: "MSSQL", 1521: "ORACLE", 5900: "VNC", 23: "TELNET", 110: "POP3",
                993: "IMAPS", 995: "POP3S"}
    return port_map.get(int(port), f"PORT_{port}")

def score_severity_distribution(events: list) -> dict:
    sev_counts = Counter()
    for ev in events:
        classification = classify_leak_event(ev)
        sev_counts[classification["severity"]] += 1
    return dict(sev_counts)

def analyze_time_patterns(events: list) -> list:
    timeline = []
    for ev in events:
        timestamp = ev.get("timestamp", ev.get("time", ev.get("date", "")))
        if timestamp:
            timeline.append({"time": timestamp[:10], "ip": ev.get("ip", ""), "event": ev.get("event", "")})
    timeline.sort(key=lambda x: x["time"])
    return timeline

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        resp = await client.get(
            f"{LEAKIX_BASE}/api/domain/{domain}",
            timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
        all_events = []
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                all_events = data
            elif isinstance(data, dict) and "events" in data:
                all_events = data["events"]

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"LeakIX API error: {str(e)[:100]}",
            type="LeakIX Error",
            source="LeakIX",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"],
        ))
        return findings

    seen_ips = set()
    affected_services = Counter()
    leak_types = Counter()
    data_classification = Counter()
    timeline_events = []
    service_risk_counts = Counter()

    for event in all_events:
        if not isinstance(event, dict):
            continue

        ip = event.get("ip", "")
        port = event.get("port", 0)
        event_name = event.get("event", event.get("title", event.get("name", "")))
        service = extract_service_from_event(event)
        classification = classify_leak_event(event)
        leak_type_label = classification["type"]
        severity = classification["severity"]
        color = classification["color"]
        category = classification["category"]

        dedup_key = f"{ip}:{port}:{event_name}"
        if dedup_key in seen_ips:
            continue
        seen_ips.add(dedup_key)

        affected_services[service] += 1
        leak_types[leak_type_label] += 1
        data_classification[category] += 1

        event_ts = event.get("timestamp", event.get("time", event.get("date", "")))
        if event_ts:
            timeline_events.append({"time": str(event_ts)[:10], "event": event_name, "type": leak_type_label})

        entity = f"{ip}:{port}/{service} - {event_name} [{leak_type_label}]"
        raw = json.dumps(event)[:1000]
        tags = [f"service-{service.lower()}", category, "domain-event"]
        if severity in ("Critical", "High"):
            tags.append("high-severity")

        findings.append(IntelligenceFinding(
            entity=entity[:200],
            type=f"LeakIX: {leak_type_label}",
            source="LeakIX",
            confidence="High",
            color=color,
            threat_level=severity if severity in ("Critical", "High Risk") else "Elevated Risk",
            status="Active",
            resolution=ip,
            raw_data=raw,
            tags=tags,
        ))

        if event.get("description", ""):
            findings.append(IntelligenceFinding(
                entity=f"Details: {event['description'][:200]}",
                type=f"LeakIX: {leak_type_label} Details",
                source="LeakIX",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=event["description"][:1000],
                tags=["details"],
            ))

        # Service-specific risk analysis
        if service in SERVICE_SPECIFIC_RISKS:
            risk_info = SERVICE_SPECIFIC_RISKS[service]
            service_risk_counts[service] += 1
            findings.append(IntelligenceFinding(
                entity=f"{service} risk analysis: {risk_info['desc']}",
                type=f"LeakIX: {service} Risk Analysis",
                source="LeakIX",
                confidence="High",
                color="red" if risk_info["risk"] in ("Critical", "High") else "orange",
                threat_level=risk_info["risk"],
                resolution=ip,
                raw_data=f"Service {service} teridentifikasi dengan risiko {risk_info['risk']}: {risk_info['desc']}",
                tags=[f"service-{service.lower()}", "risk-analysis"],
            ))

        # Extract exposed credentials count if available
        cred_count = event.get("credential_count", event.get("count", 0))
        if isinstance(cred_count, int) and cred_count > 0:
            findings.append(IntelligenceFinding(
                entity=f"{cred_count} credentials exposed on {ip}:{port}",
                type="LeakIX: Credential Count",
                source="LeakIX",
                confidence="Medium",
                color="red",
                threat_level="Critical",
                resolution=ip,
                raw_data=f"{cred_count} credentials ditemukan pada {entity}",
                tags=["credentials", "exposed"],
            ))

        # CVSS/CVE details
        cvss = event.get("cvss", event.get("cvss_score", None))
        if cvss is not None:
            findings.append(IntelligenceFinding(
                entity=f"CVSS: {cvss} for {event_name}",
                type="LeakIX: CVSS Score",
                source="LeakIX",
                confidence="High",
                color="red" if float(cvss) >= 7 else "orange",
                threat_level="Critical" if float(cvss) >= 9 else ("High" if float(cvss) >= 7 else "Medium"),
                resolution=ip,
                raw_data=f"CVSS score: {cvss}",
                tags=["cvss"],
            ))

    for service, count in affected_services.most_common():
        findings.append(IntelligenceFinding(
            entity=f"{service}: {count} leak events on {domain}",
            type="LeakIX: Affected Service",
            source="LeakIX",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            raw_data=f"Service {service} associated with {count} leak events on {domain}",
            tags=[f"service-{service.lower()}", "affected-service"],
        ))

    for lt, count in leak_types.most_common():
        sev_info = LEAK_CLASSIFICATIONS.get(lt.lower().replace(" ", "_"), {})
        sev = sev_info.get("severity", "Medium")
        lcolor = sev_info.get("color", "orange")
        findings.append(IntelligenceFinding(
            entity=f"{lt}: {count} occurrences",
            type="LeakIX: Leak Type Aggregation",
            source="LeakIX",
            confidence="Medium",
            color=lcolor,
            threat_level=sev if sev in ("Critical", "High") else "Elevated Risk",
            raw_data=f"Leak type {lt} appeared {count} times",
            tags=[f"leak-type-{lt.lower().replace(' ', '-')}"],
        ))

    for cat, count in data_classification.most_common():
        findings.append(IntelligenceFinding(
            entity=f"{cat}: {count} events",
            type="LeakIX: Data Classification",
            source="LeakIX",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            raw_data=f"Classification {cat}: {count} events",
            tags=[f"classification-{cat}"],
        ))

    if timeline_events:
        timeline_events.sort(key=lambda x: x["time"])
        for te in timeline_events[:15]:
            findings.append(IntelligenceFinding(
                entity=f"{te['time']}: {te['event']} ({te['type']})",
                type="LeakIX: Timeline",
                source="LeakIX",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=f"{te['time']} - {te['event']} - Type: {te['type']}",
                tags=["timeline"],
            ))

    if all_events:
        sev_dist = score_severity_distribution(all_events)
        crit_count = sev_dist.get("Critical", 0)
        high_count = sev_dist.get("High", 0)
        mid_count = sev_dist.get("Medium", 0)
        total = len(all_events)
        overall = "Critical" if crit_count > 0 else ("High Risk" if high_count > 0 else ("Elevated Risk" if mid_count > 0 else "Informational"))
        ips = set(e.get("ip", "") for e in all_events if e.get("ip"))
        raw_stats = json.dumps({"total": total, "severity_distribution": sev_dist, "unique_ips": len(ips), "services": dict(affected_services)})

        findings.append(IntelligenceFinding(
            entity=f"LeakIX domain intelligence: {total} events, {len(ips)} IPs, {len(affected_services)} services (C:{crit_count} H:{high_count} M:{mid_count})",
            type="LeakIX: Domain Intelligence Summary",
            source="LeakIX",
            confidence="High",
            color="red" if crit_count > 0 else "orange",
            threat_level=overall,
            status="Analyzed",
            raw_data=raw_stats[:1000],
            tags=["domain-intelligence", "summary"],
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No domain events found for {domain}",
            type="LeakIX: No Events",
            source="LeakIX",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            tags=["clean"],
        ))

    return findings
