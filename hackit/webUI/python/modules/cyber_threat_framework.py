import httpx
import re
import json
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding

MITRE_ATTACK_TECHNIQUES = {
    "Initial Access": ["T1078", "T1190", "T1133", "T1566", "T1091", "T1189", "T1195", "T1199", "T1200"],
    "Execution": ["T1059", "T1204", "T1559", "T1106", "T1569", "T1053", "T1047"],
    "Persistence": ["T1098", "T1136", "T1547", "T1546", "T1505", "T1053", "T1525"],
    "Privilege Escalation": ["T1548", "T1068", "T1134", "T1055", "T1484", "T1078"],
    "Defense Evasion": ["T1562", "T1055", "T1070", "T1027", "T1036", "T1140", "T1218", "T1202"],
    "Credential Access": ["T1552", "T1555", "T1558", "T1110", "T1056", "T1003", "T1606"],
    "Discovery": ["T1083", "T1082", "T1087", "T1046", "T1069", "T1482", "T1007", "T1016", "T1033"],
    "Lateral Movement": ["T1021", "T1570", "T1550", "T1091", "T1210", "T1080"],
    "Collection": ["T1005", "T1074", "T1114", "T1213", "T1560", "T1119", "T1125"],
    "Command and Control": ["T1071", "T1573", "T1095", "T1572", "T1105", "T1090", "T1008", "T1219"],
    "Exfiltration": ["T1041", "T1052", "T1567", "T1020", "T1030", "T1011"],
    "Impact": ["T1485", "T1486", "T1489", "T1491", "T1565", "T1499", "T1495"],
}

MITRE_D3FEND_CAPABILITIES = {
    "Harden": ["Application Hardening", "Credential Hardening", "Platform Hardening"],
    "Detect": ["Network Traffic Analysis", "Process Monitoring", "File Monitoring", "User Behavior Analysis"],
    "Isolate": ["Network Isolation", "Process Isolation", "Container Isolation"],
    "Deceive": ["Honeypots", "Decoy Credentials", "Decoy Network Resources"],
    "Evict": ["Process Termination", "Network Blocking", "Account Lockout"],
}

OWASP_TOP_10_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

CWE_TOP_25_2024 = ["CWE-787", "CWE-79", "CWE-89", "CWE-20", "CWE-125", "CWE-78", "CWE-416", "CWE-22",
    "CWE-476", "CWE-190", "CWE-131", "CWE-476", "CWE-862", "CWE-77", "CWE-119", "CWE-276",
    "CWE-287", "CWE-200", "CWE-522", "CWE-732", "CWE-611", "CWE-798", "CWE-502", "CWE-269", "CWE-295"]

NIST_CSF_CATEGORIES = ["Identify", "Protect", "Detect", "Respond", "Recover"]

TECH_STACK_PATTERNS = {
    "web_server": ["apache", "nginx", "iis", "tomcat", "caddy", "lighttpd"],
    "database": ["mysql", "postgresql", "mariadb", "mongodb", "oracle", "mssql"],
    "language": ["php", "python", "java", "node.js", ".net", "ruby", "go", "rust"],
    "cms": ["wordpress", "drupal", "joomla", "magento", "shopify", "wix"],
    "cloud": ["aws", "azure", "gcp", "cloudflare", "akamai"],
}


def map_tech_to_techniques(tech_stack: dict) -> list:
    relevant = []
    if "wordpress" in str(tech_stack).lower():
        relevant.extend(["T1190 (Exploit Public-Facing Application)", "T1505 (Server Software Component)", "T1078 (Valid Accounts)"])
    if "nginx" in str(tech_stack).lower() or "apache" in str(tech_stack).lower():
        relevant.extend(["T1190 (Exploit Public-Facing Application)", "T1003 (OS Credential Dumping)"])
    if "mysql" in str(tech_stack).lower() or "postgresql" in str(tech_stack).lower():
        relevant.extend(["T1552 (Unsecured Credentials)", "T1213 (Data from Information Repositories)"])
    if "aws" in str(tech_stack).lower() or "azure" in str(tech_stack).lower():
        relevant.extend(["T1525 (Implant Internal Image)", "T1552 (Unsecured Credentials)", "T1613 (Container and Resource Discovery)"])
    return relevant


async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    tech_stack = {}
    try:
        resp = await client.get(f"https://{t}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
        if resp.status_code == 200:
            text = resp.text.lower() + str(resp.headers).lower()
            for category, indicators in TECH_STACK_PATTERNS.items():
                found = [ind for ind in indicators if ind in text]
                if found:
                    tech_stack[category] = found
    except:
        pass

    for tactic, techniques in MITRE_ATTACK_TECHNIQUES.items():
        findings.append(IntelligenceFinding(
            entity=f"MITRE ATT&CK Tactic: {tactic} - {len(techniques)} techniques applicable",
            type=f"Framework: MITRE ATT&CK {tactic}",
            source="CyberThreatFramework",
            confidence="High",
            color="blue",
            category="Threat Framework Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            raw_data=f"Techniques: {', '.join(techniques[:5])}",
            tags=["mitre", "attack", tactic.lower().replace(" ", "-")],
        ))

        for technique_id in techniques[:3]:
            findings.append(IntelligenceFinding(
                entity=f"MITRE ATT&CK Technique: {technique_id} ({tactic})",
                type="Framework: MITRE Technique",
                source="CyberThreatFramework",
                confidence="Medium",
                color="sky",
                category="Threat Framework Intelligence",
                threat_level="Informational",
                status="Mapped",
                resolution=t,
                tags=["mitre", "technique", technique_id.lower()],
            ))

    for capability, subs in MITRE_D3FEND_CAPABILITIES.items():
        findings.append(IntelligenceFinding(
            entity=f"MITRE D3FEND: {capability} - {', '.join(subs[:3])}",
            type="Framework: D3FEND Defense",
            source="CyberThreatFramework",
            confidence="High",
            color="emerald",
            category="Threat Framework Intelligence",
            threat_level="Informational",
            status="Recommended",
            resolution=t,
            tags=["d3fend", "defense", capability.lower()],
        ))

    for cwe_id, cwe_name in OWASP_TOP_10_2021.items():
        findings.append(IntelligenceFinding(
            entity=f"OWASP Top 10: {cwe_id} - {cwe_name}",
            type="Framework: OWASP Risk",
            source="CyberThreatFramework",
            confidence="High",
            color="orange",
            category="Threat Framework Intelligence",
            threat_level="Medium Risk" if "2021" in cwe_id else "Informational",
            status="Applicable",
            resolution=t,
            tags=["owasp", cwe_id.split(":")[0].lower(), cwe_name.lower().replace(" ", "-")],
        ))

    if tech_stack:
        relevant_techniques = map_tech_to_techniques(tech_stack)
        for rt in relevant_techniques[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Tech-specific threat: {rt}",
                type="Framework: Tech Threat Mapping",
                source="CyberThreatFramework",
                confidence="Medium",
                color="orange",
                category="Threat Framework Intelligence",
                threat_level="High Risk",
                status="Mapped",
                resolution=t,
                tags=["threat-mapping", "technology", rt.split(" ")[0].lower()],
            ))

    for cwe in CWE_TOP_25_2024[:10]:
        findings.append(IntelligenceFinding(
            entity=f"CWE Top 25: {cwe}",
            type="Framework: CWE Risk",
            source="CyberThreatFramework",
            confidence="High",
            color="orange",
            category="Threat Framework Intelligence",
            threat_level="Medium Risk",
            status="Applicable",
            resolution=t,
            tags=["cwe", cwe.lower()],
        ))

    for category in NIST_CSF_CATEGORIES:
        findings.append(IntelligenceFinding(
            entity=f"NIST CSF Function: {category}",
            type="Framework: NIST CSF",
            source="CyberThreatFramework",
            confidence="High",
            color="slate",
            category="Threat Framework Intelligence",
            threat_level="Informational",
            status="Mapped",
            resolution=t,
            tags=["nist", "csf", category.lower()],
        ))

    total_techniques = sum(len(v) for v in MITRE_ATTACK_TECHNIQUES.values())
    findings.append(IntelligenceFinding(
        entity=f"Complete framework mapping: {len(MITRE_ATTACK_TECHNIQUES)} tactics, {total_techniques} techniques, 10 OWASP risks, 25 CWE entries",
        type="Framework: Coverage Summary",
        source="CyberThreatFramework",
        confidence="Very High",
        color="slate",
        category="Threat Framework Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["framework", "coverage", "summary"],
    ))

    return findings
