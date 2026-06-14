import httpx
import re
import socket
import asyncio
from models import IntelligenceFinding
from urllib.parse import urlparse

TM_API = "https://api.threatminer.org/v2"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

TM_ENDPOINTS = {
    "subdomains": ("domain.php", {"q": "{target}", "rt": "2"}, "Subdomain", "emerald"),
    "related_hosts": ("domain.php", {"q": "{target}", "rt": "5"}, "Related Host", "slate"),
    "whois": ("domain.php", {"q": "{target}", "rt": "4"}, "WHOIS Record", "slate"),
    "email": ("domain.php", {"q": "{target}", "rt": "6"}, "Email Association", "orange"),
    "pdns": ("domain.php", {"q": "{target}", "rt": "3"}, "Passive DNS", "blue"),
    "samples": ("domain.php", {"q": "{target}", "rt": "8"}, "Sample Hash", "purple"),
    "reports": ("domain.php", {"q": "{target}", "rt": "9"}, "Threat Report", "red"),
    "av_detections": ("domain.php", {"q": "{target}", "rt": "10"}, "AV Detection", "orange"),
}

THREAT_CATEGORIES = {
    "malware": ("Malware", 3),
    "trojan": ("Trojan", 3),
    "ransomware": ("Ransomware", 4),
    "worm": ("Worm", 3),
    "backdoor": ("Backdoor", 4),
    "botnet": ("Botnet/C2", 4),
    "c2": ("C2 Server", 4),
    "phishing": ("Phishing URL", 3),
    "spam": ("Spam Source", 2),
    "exploit": ("Exploit Kit", 3),
    "ddos": ("DDoS Target", 2),
    "scanner": ("Scanner Activity", 1),
    "suspicious": ("Suspicious", 2),
    "malicious": ("Malicious", 3),
    "attack": ("Attack Infrastructure", 3),
    "proxy": ("Proxy/VPN", 1),
    "tor": ("Tor Exit Node", 1),
    "cnc": ("C&C Server", 4),
    "payload": ("Malicious Payload", 3),
    "dropper": ("Dropper", 4),
}

SAMPLE_HASH_PATTERNS = {
    "MD5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "SHA1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "SHA256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
}

async def _tm_get(endpoint: str, params: dict, client: httpx.AsyncClient) -> dict | None:
    try:
        url = f"{TM_API}/{endpoint}"
        resp = await client.get(url, params=params, timeout=15.0,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None

async def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def _compute_threat_score(findings_count: int, weighted_hits: dict) -> int:
    score = 0
    for category, weight in weighted_hits.items():
        score += weight * weighted_hits[category]
    score += findings_count
    return min(score, 100)

def _classify_threat(text: str) -> list[tuple[str, str, int]]:
    results = []
    text_lower = text.lower()
    for keyword, (label, weight) in THREAT_CATEGORIES.items():
        if keyword in text_lower:
            results.append((keyword, label, weight))
    return results

def _extract_ips(text: str) -> list[str]:
    return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))

def _extract_hashes(text: str) -> dict[str, list[str]]:
    found = {}
    for hash_type, pattern in SAMPLE_HASH_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            found[hash_type] = matches[:10]
    return found

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    domain = domain.strip().lower()

    if not domain or "." not in domain:
        findings.append(IntelligenceFinding(
            entity=f"Invalid target: {target}",
            type="ThreatMiner Error",
            source="ThreatMiner",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Invalid",
            tags=["error"]
        ))
        return findings

    is_ip_target = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    weighted_hits = {}
    total_results = 0
    seen_entities = set()

    for ep_name, (endpoint, params_orig, ftype_base, color) in TM_ENDPOINTS.items():
        params = {k: v.replace("{target}", domain) for k, v in params_orig.items()}
        data = await _tm_get(endpoint, params, client)
        if not data or not isinstance(data, dict):
            continue

        results_list = data.get("results", [])
        if not isinstance(results_list, list):
            continue

        status_code = data.get("status_code", data.get("status", ""))
        status_msg = data.get("status_message", data.get("message", ""))

        if status_code and str(status_code) not in ("200", "0"):
            continue

        total_results += len(results_list)

        for result in results_list[:20]:
            if isinstance(result, dict):
                if ep_name == "subdomains":
                    subdomain = result.get("domain", result.get("subdomain", result.get("hostname", "")))
                    ip = result.get("ip", result.get("address", ""))
                    if subdomain:
                        entity_key = f"sub:{subdomain}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        resolution = ip or (await _resolve_ip(subdomain)) or ""
                        findings.append(IntelligenceFinding(
                            entity=subdomain[:200],
                            type=f"ThreatMiner {ftype_base}",
                            source="ThreatMiner",
                            confidence="High",
                            color=color,
                            threat_level="Informational",
                            status="Resolved" if resolution else "Unresolved",
                            resolution=resolution,
                            raw_data=f"Subdomain: {subdomain} -> {resolution}",
                            tags=["subdomain", domain.replace('.', '_')]
                        ))

                elif ep_name == "related_hosts":
                    ip = result.get("ip", result.get("address", result.get("host", "")))
                    if ip:
                        entity_key = f"ip:{ip}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        findings.append(IntelligenceFinding(
                            entity=ip[:200],
                            type=f"ThreatMiner {ftype_base}",
                            source="ThreatMiner",
                            confidence="High",
                            color=color,
                            threat_level="Informational",
                            status="Related",
                            raw_data=f"Related host: {ip}",
                            tags=["related_host", "ip", domain.replace('.', '_')]
                        ))

                elif ep_name == "whois":
                    for whois_key in ["registrar", "creation_date", "expiration_date", "registrant_name",
                                       "registrant_organization", "registrant_email", "registrant_country",
                                       "name_servers", "admin_email", "tech_email", "abuse_email"]:
                        val = result.get(whois_key, result.get(whois_key.replace("_", " "), ""))
                        if val:
                            val_str = str(val)[:200] if isinstance(val, str) else str(val)
                            entity_key = f"whois_{whois_key}:{val_str}"
                            if entity_key in seen_entities:
                                continue
                            seen_entities.add(entity_key)
                            findings.append(IntelligenceFinding(
                                entity=val_str,
                                type=f"ThreatMiner WHOIS {whois_key.replace('_', ' ').title()}",
                                source="ThreatMiner",
                                confidence="High",
                                color=color,
                                threat_level="Informational",
                                status="Confirmed",
                                raw_data=f"WHOIS {whois_key}: {val_str}",
                                tags=["whois", whois_key, domain.replace('.', '_')]
                            ))

                elif ep_name == "email":
                    email = result.get("email", result.get("address", "")) if isinstance(result, dict) else str(result)
                    if email and '@' in str(email):
                        entity_key = f"email:{email}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        findings.append(IntelligenceFinding(
                            entity=str(email)[:200],
                            type=f"ThreatMiner {ftype_base}",
                            source="ThreatMiner",
                            confidence="Medium",
                            color=color,
                            threat_level="Elevated Risk",
                            status="Extracted",
                            raw_data=f"Email from samples: {email}",
                            tags=["email", "pii", domain.replace('.', '_')]
                        ))

                elif ep_name == "pdns":
                    pdns_host = result.get("hostname", result.get("domain", result.get("host", "")))
                    pdns_ip = result.get("ip", result.get("address", ""))
                    pdns_type = result.get("type", result.get("record_type", ""))
                    pdns_first = result.get("first_seen", result.get("first", ""))
                    pdns_last = result.get("last_seen", result.get("last", ""))
                    if pdns_host:
                        entity_key = f"pdns:{pdns_host}:{pdns_ip}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        findings.append(IntelligenceFinding(
                            entity=str(pdns_host)[:200],
                            type=f"ThreatMiner PDNS ({pdns_type})",
                            source="ThreatMiner",
                            confidence="High",
                            color=color,
                            threat_level="Informational",
                            status="Historical",
                            resolution=str(pdns_ip)[:100] if pdns_ip else "",
                            raw_data=f"PDNS: {pdns_host} ({pdns_type}) -> {pdns_ip or 'N/A'} [{pdns_first} - {pdns_last}]",
                            tags=["pdns", pdns_type.lower() if pdns_type else "dns", domain.replace('.', '_')]
                        ))

                elif ep_name == "samples":
                    sample_hash = result.get("hash", result.get("md5", result.get("sha1", result.get("sha256", ""))))
                    sample_filename = result.get("filename", result.get("file", ""))
                    sample_type = result.get("type", result.get("file_type", ""))
                    sample_size = result.get("size", "")
                    if sample_hash:
                        entity_key = f"sample:{sample_hash}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        threats = _classify_threat(str(result))
                        for keyword, label, weight in threats[:3]:
                            weighted_hits[label] = max(weighted_hits.get(label, 0), weight)
                        hash_type = "SHA256" if len(sample_hash) == 64 else ("SHA1" if len(sample_hash) == 40 else "MD5")
                        findings.append(IntelligenceFinding(
                            entity=sample_hash[:200],
                            type=f"ThreatMiner Sample ({hash_type})",
                            source="ThreatMiner",
                            confidence="High",
                            color="red" if threats else "purple",
                            threat_level="Suspicious" if threats else "Informational",
                            status="Analyzed",
                            raw_data=f"Sample: {sample_hash} ({sample_filename or 'unnamed'}, {sample_type or 'unknown type'}, {sample_size or 'unknown size'})",
                            tags=["sample_hash", hash_type.lower(), domain.replace('.', '_')] +
                                 ([kw for kw, _, _ in threats[:3]] if threats else [])
                        ))

                elif ep_name == "reports":
                    report_title = result.get("title", result.get("name", str(result)[:100]))
                    report_url = result.get("url", result.get("link", ""))
                    report_date = result.get("date", result.get("published", ""))
                    if report_title:
                        entity_key = f"report:{report_title}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        threats = _classify_threat(str(result))
                        for keyword, label, weight in threats[:3]:
                            weighted_hits[label] = max(weighted_hits.get(label, 0), weight)
                        findings.append(IntelligenceFinding(
                            entity=str(report_title)[:200],
                            type="ThreatMiner Threat Report",
                            source="ThreatMiner",
                            confidence="Medium",
                            color="red",
                            threat_level="Suspicious",
                            status="Referenced",
                            raw_data=f"Report: {report_title} ({report_date}) [{report_url}]",
                            tags=["report", "threat_report"] +
                                 ([kw for kw, _, _ in threats[:3]] if threats else [])
                        ))

                elif ep_name == "av_detections":
                    av_name = result.get("av", result.get("vendor", ""))
                    detection = result.get("detection", result.get("signature", result.get("result", "")))
                    if av_name and detection:
                        entity_key = f"av:{av_name}:{detection}"
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)
                        weighted_hits["Malware"] = max(weighted_hits.get("Malware", 0), 3)
                        findings.append(IntelligenceFinding(
                            entity=f"{av_name}: {str(detection)[:150]}",
                            type="ThreatMiner AV Detection",
                            source="ThreatMiner",
                            confidence="High",
                            color="red",
                            threat_level="High Risk",
                            status="Detected",
                            raw_data=f"AV Detection: {av_name} flagged as {detection}",
                            tags=["av_detection", "malware", av_name.lower(), domain.replace('.', '_')]
                        ))

            elif isinstance(result, str):
                entity_key = f"str:{result[:100]}"
                if entity_key in seen_entities:
                    continue
                seen_entities.add(entity_key)
                threats = _classify_threat(result)
                for keyword, label, weight in threats:
                    weighted_hits[label] = max(weighted_hits.get(label, 0), weight)
                findings.append(IntelligenceFinding(
                    entity=result[:200],
                    type=f"ThreatMiner Raw Result",
                    source="ThreatMiner",
                    confidence="Low",
                    color="red" if threats else "slate",
                    threat_level="Suspicious" if threats else "Informational",
                    status="Raw",
                    raw_data=f"Raw result from {ep_name}: {result[:300]}",
                    tags=[ep_name] + ([kw for kw, _, _ in threats] if threats else [])
                ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No ThreatMiner results found for {domain}",
            type="ThreatMiner Summary",
            source="ThreatMiner",
            confidence="Low",
            color="emerald",
            threat_level="Informational",
            status="Clean",
            tags=["clean", domain.replace('.', '_')]
        ))
        return findings

    threat_score = _compute_threat_score(len(findings), weighted_hits)
    risk_level = "Informational"
    if threat_score >= 60:
        risk_level = "Critical"
    elif threat_score >= 40:
        risk_level = "High Risk"
    elif threat_score >= 20:
        risk_level = "Elevated Risk"
    elif threat_score >= 5:
        risk_level = "Standard Target"

    findings.append(IntelligenceFinding(
        entity=f"ThreatMiner scan: {total_results} total results, {len(findings)} findings, threat score: {threat_score}/100",
        type="ThreatMiner Summary",
        source="ThreatMiner",
        confidence="High",
        color="red" if threat_score >= 40 else ("orange" if threat_score >= 20 else "purple"),
        threat_level=risk_level,
        status="Scored",
        raw_data=f"Threat score: {threat_score}/100. Categories: {', '.join(weighted_hits.keys()) if weighted_hits else 'none'}",
        tags=["summary", "threat_score", str(threat_score), domain.replace('.', '_')] +
             list(weighted_hits.keys()) if weighted_hits else []
    ))

    return findings
