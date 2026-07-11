import httpx
import json
import re
from module_common import safe_fetch, make_finding
LEAKIX_BASE = "https://leakix.net"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

SERVICE_QUERIES = {
    "HTTP": {"protocol": "http", "ports": [80, 443, 8080, 8443], "severity": "Medium", "color": "orange"},
    "HTTPS": {"protocol": "https", "ports": [443, 8443], "severity": "Medium", "color": "orange"},
    "SMTP": {"protocol": "smtp", "ports": [25, 465, 587, 2525], "severity": "Medium", "color": "orange"},
    "FTP": {"protocol": "ftp", "ports": [21], "severity": "High", "color": "red"},
    "MYSQL": {"protocol": "mysql", "ports": [3306], "severity": "Critical", "color": "red"},
    "MONGODB": {"protocol": "mongodb", "ports": [27017, 27018], "severity": "Critical", "color": "red"},
    "ELASTICSEARCH": {"protocol": "elasticsearch", "ports": [9200, 9300], "severity": "Critical", "color": "red"},
    "REDIS": {"protocol": "redis", "ports": [6379], "severity": "Critical", "color": "red"},
    "MEMCACHED": {"protocol": "memcached", "ports": [11211], "severity": "High", "color": "red"},
    "POSTGRESQL": {"protocol": "postgresql", "ports": [5432], "severity": "Critical", "color": "red"},
    "SSH": {"protocol": "ssh", "ports": [22], "severity": "Medium", "color": "orange"},
    "RDP": {"protocol": "rdp", "ports": [3389], "severity": "High", "color": "red"},
    "TELNET": {"protocol": "telnet", "ports": [23], "severity": "High", "color": "red"},
    "VNC": {"protocol": "vnc", "ports": [5900, 5800], "severity": "High", "color": "red"},
    "SMB": {"protocol": "smb", "ports": [445, 139], "severity": "High", "color": "red"},
    "DNS": {"protocol": "dns", "ports": [53], "severity": "Medium", "color": "orange"},
    "MSSQL": {"protocol": "mssql", "ports": [1433], "severity": "Critical", "color": "red"},
    "ORACLEDB": {"protocol": "oracle", "ports": [1521], "severity": "High", "color": "red"},
    "DOCKER": {"protocol": "docker", "ports": [2375, 2376], "severity": "Critical", "color": "red"},
    "KIBANA": {"protocol": "kibana", "ports": [5601], "severity": "Medium", "color": "orange"},
}

LEAK_TYPES = {
    "open_database": {"type": "Open Database", "severity": "Critical", "color": "red"},
    "credential_leak": {"type": "Credential Leak", "severity": "Critical", "color": "red"},
    "information_disclosure": {"type": "Info Disclosure", "severity": "High", "color": "red"},
    "misconfiguration": {"type": "Misconfiguration", "severity": "High", "color": "orange"},
    "vulnerability": {"type": "Vulnerability", "severity": "Critical", "color": "red"},
    "exposed_service": {"type": "Exposed Service", "severity": "High", "color": "orange"},
    "api_key_leak": {"type": "API Key Leak", "severity": "Critical", "color": "red"},
    "code_leak": {"type": "Code Leak", "severity": "High", "color": "red"},
}

RESPONSE_PATTERNS = {
    r"password|passwd|pwd|secret|credential": "Credential Exposure",
    r"mongodb|27017|no auth|unauthorized": "Open MongoDB",
    r"elasticsearch|9200|cluster_name|indices": "Open Elasticsearch",
    r"redis|6379|keyspace|\-server": "Open Redis",
    r"mysql|3306|sql error|database error": "MySQL Exposure",
    r"ftp|anonymous|login successful": "FTP Exposure",
    r"smtp|helo|ehlo|mail from": "SMTP/Banner",
    r"cve-\d{4}-\d+|vulnerability|exploit": "Vulnerability Mention",
    r"api.?key|api.?secret|token|auth.?key": "API Key Exposure",
    r"admin|root|administrator": "Privileged Access",
    r"aws|s3\.amazonaws|amazonaws\.com": "AWS Exposure",
    r"-----BEGIN.*PRIVATE KEY-----": "Private Key Exposure",
    r"git:|github|gitlab|bitbucket": "Code Repository Leak",
}

def detect_leak_type(entry: dict) -> dict:
    leak_str = json.dumps(entry).lower()
    if any(w in leak_str for w in ["mongodb", "27017", "no auth", "unauthorized"]):
        return {"type": "Open MongoDB", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["elasticsearch", "9200", "cluster_name"]):
        return {"type": "Open Elasticsearch", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["redis", "6379", "keyspace"]):
        return {"type": "Open Redis", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["mysql", "3306", "sql"]):
        return {"type": "Open MySQL", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["memcached", "11211"]):
        return {"type": "Open Memcached", "severity": "High", "color": "red"}
    if any(w in leak_str for w in ["ftp", "anonymous", "login"]):
        return {"type": "Open FTP", "severity": "High", "color": "red"}
    if any(w in leak_str for w in ["smtp", "25/tcp", "mail"]):
        return {"type": "Open SMTP", "severity": "Medium", "color": "orange"}
    if any(w in leak_str for w in ["password", "passwd", "credential", "login:", "pwd"]):
        return {"type": "Credential Leak", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["vuln", "cve", "exploit"]):
        return {"type": "Vulnerability", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["leak", "breach", "exposed"]):
        return {"type": "Data Leak", "severity": "High", "color": "red"}
    if any(w in leak_str for w in ["api", "key", "token", "secret"]):
        return {"type": "API Key Leak", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["docker", "2375", "2376", "container"]):
        return {"type": "Open Docker API", "severity": "Critical", "color": "red"}
    if any(w in leak_str for w in ["ssh", "22/tcp", "openssh"]):
        return {"type": "SSH Exposure", "severity": "Medium", "color": "orange"}
    if any(w in leak_str for w in ["rdp", "3389", "terminal"]):
        return {"type": "RDP Exposure", "severity": "High", "color": "red"}
    return {"type": "Exposed Service", "severity": "Medium", "color": "orange"}

def match_response_patterns(entry: dict) -> list:
    matches = []
    entry_str = json.dumps(entry)
    for pattern, label in RESPONSE_PATTERNS.items():
        if re.search(pattern, entry_str, re.IGNORECASE):
            matches.append(label)
    return matches

def score_severity(entries: list) -> tuple:
    critical = 0
    high = 0
    medium = 0
    total = len(entries)
    for e in entries:
        sev = detect_leak_type(e).get("severity", "Low")
        if sev == "Critical":
            critical += 1
        elif sev == "High":
            high += 1
        elif sev == "Medium":
            medium += 1
    if critical > 0:
        return "Critical", critical, high, medium
    elif high > 0:
        return "High Risk", critical, high, medium
    elif medium > 0:
        return "Elevated Risk", critical, high, medium
    return "Informational", critical, high, medium

async def search_service(target: str, service: str, config: dict, client: httpx.AsyncClient) -> list:
    results = []
    protocol = config["protocol"]
    try:
        url = f"{LEAKIX_BASE}/search?q={protocol}:{target}&scope=leak"
        resp = await safe_fetch(client, 
            url, timeout=15.0,
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
        if resp.status_code == 200 and resp.text.strip().startswith(("[")):
            data = resp.json()
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        entry["_service"] = service
                        entry["_protocol"] = protocol
                        results.append(entry)
    except Exception:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    all_leaks = []
    service_counts = {}

    for service, config in SERVICE_QUERIES.items():
        leaks = await search_service(domain, service, config, client)
        all_leaks.extend(leaks)
        if leaks:
            service_counts[service] = len(leaks)

    seen_events = set()
    leak_type_counter = {}
    pattern_matches = []

    for leak in all_leaks:
        event = leak.get("event", "")
        ip = leak.get("ip", "")
        port = leak.get("port", 0)
        leak_service = leak.get("_service", "Unknown")
        protocol = leak.get("_protocol", "")
        title = leak.get("title", "")
        description = leak.get("description", "")
        count = leak.get("count", 0)
        leak_type = leak.get("type", "")
        severity_val = leak.get("severity", "")

        dedup_key = f"{ip}:{port}:{event}"
        if dedup_key in seen_events:
            continue
        seen_events.add(dedup_key)

        detected = detect_leak_type(leak)
        leak_label = detected["type"] if not leak_type else leak_type
        sev = detected["severity"] if not severity_val else severity_val
        color = detected["color"]

        # Response pattern matching
        patterns_found = match_response_patterns(leak)
        if patterns_found:
            pattern_matches.append({"leak_label": leak_label, "patterns": patterns_found, "ip": ip, "port": port})

        entity = f"{leak_label}"
        if event:
            entity = f"{event} ({leak_label})"
        if ip:
            entity += f" @ {ip}"
        if port:
            entity += f":{port}"

        raw = json.dumps(leak)[:1000]
        tags = ["leak", leak_service.lower().replace(" ", "-")]
        if "credential" in leak_label.lower() or "password" in raw.lower():
            tags.append("credential-leak")
        if "open" in leak_label.lower() or "unauthorized" in raw.lower():
            tags.append("open-access")
        if "api" in leak_label.lower():
            tags.append("api-key")

        findings.append(make_finding(
            entity=entity[:200],
            ftype=f"LeakIX: {leak_service}",
            source="LeakIX Scanner",
            confidence="High",
            color=color,
            threat_level=sev if sev in ("Critical", "High Risk") else "Elevated Risk",
            status="Confirmed",
            resolution=ip if ip else None,
            raw_data=raw,
            tags=tags,
        ))

        if description:
            findings.append(make_finding(
                entity=f"{leak_label} details: {description[:200]}",
                ftype=f"LeakIX: {leak_service} Description",
                source="LeakIX Scanner",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=description[:1000],
                tags=["description"],
            ))

        if count > 0:
            findings.append(make_finding(
                entity=f"{leak_label} impact: {count} records",
                ftype="LeakIX: Breach Impact",
                source="LeakIX Scanner",
                confidence="Medium",
                color="red",
                threat_level="High Risk",
                raw_data=f"{count} records affected in {event or leak_label}",
                tags=["impact"],
            ))

        # Track leak types for classification summary
        if leak_label not in leak_type_counter:
            leak_type_counter[leak_label] = 0
        leak_type_counter[leak_label] += 1

    # Pattern match summaries
    if pattern_matches:
        all_patterns = set()
        for pm in pattern_matches:
            for p in pm["patterns"]:
                all_patterns.add(p)
        findings.append(make_finding(
            entity=f"Response pattern matches: {', '.join(sorted(all_patterns)[:10])}",
            ftype="LeakIX: Response Pattern Analysis",
            source="LeakIX Scanner",
            confidence="Medium",
            color="orange",
            threat_level="Informational",
            raw_data=f"Patterns detected: {all_patterns}",
            tags=["pattern-analysis"],
        ))

    # Leak type classification breakdown
    for lt, lcount in sorted(leak_type_counter.items(), key=lambda x: -x[1])[:10]:
        findings.append(make_finding(
            entity=f"{lt}: {lcount} occurrence(s)",
            ftype="LeakIX: Leak Type Classification",
            source="LeakIX Scanner",
            confidence="Medium",
            color="red" if "Critical" in lt else "orange",
            threat_level="Elevated Risk",
            raw_data=f"Leak type '{lt}' ditemukan {lcount} kali",
            tags=["leak-classification"],
        ))

    for service, count in sorted(service_counts.items()):
        config = SERVICE_QUERIES.get(service, {})
        sev = config.get("severity", "Medium")
        color = config.get("color", "orange")
        findings.append(make_finding(
            entity=f"{service}: {count} leaks detected on {domain}",
            ftype=f"LeakIX: {service} Summary",
            source="LeakIX Scanner",
            confidence="High",
            color=color,
            threat_level=sev if sev in ("Critical", "High") else "Elevated Risk",
            status="Analyzed",
            raw_data=f"Service {service} on {domain}: {count} leaks found",
            tags=[f"service-{service.lower()}", "summary"],
        ))

    if all_leaks:
        overall_sev, crit, high, med = score_severity(all_leaks)
        color = "red" if crit > 0 else ("orange" if high > 0 else "slate")
        findings.append(make_finding(
            entity=f"LeakIX scan summary: {len(all_leaks)} total leaks | {crit} critical, {high} high, {med} medium across {len(service_counts)} services",
            ftype="LeakIX: Scan Summary",
            source="LeakIX Scanner",
            confidence="High",
            color=color,
            threat_level=overall_sev,
            status="Completed",
            raw_data=f"Total entries: {len(all_leaks)}, Services affected: {list(service_counts.keys())}, Severity: {overall_sev}",
            tags=["scan-summary"],
        ))
    else:
        findings.append(make_finding(
            entity=f"No leaks found for {domain} on LeakIX",
            ftype="LeakIX: Clear",
            source="LeakIX Scanner",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Scanned",
            tags=["clear"],
        ))

    return findings
