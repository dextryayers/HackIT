import json
import re
import sys
from typing import Any, Dict, List

# Comprehensive CVE database with version ranges
CVE_DATABASE = {
    "ssh": [
        {"id": "CVE-2024-6387", "severity": "Critical", "description": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server (glibc-based, < 9.8)", "affected": {"max_version": "9.8p1"}},
        {"id": "CVE-2023-38408", "severity": "High", "description": "Remote code execution in OpenSSH agent forwarding (< 9.3p2)", "affected": {"max_version": "9.3p2"}},
        {"id": "CVE-2023-51385", "severity": "Medium", "description": "OpenSSH ProxyCommand injection via user-supplied SSH command", "affected": {"max_version": "9.6"}},
        {"id": "CVE-2021-41617", "severity": "Medium", "description": "Privilege escalation in OpenSSH via authorized_keys command=", "affected": {"max_version": "8.8"}},
        {"id": "CVE-2020-14145", "severity": "Medium", "description": "OpenSSH Keystroke Obfuscation Bypass via Man-in-the-Middle", "affected": {"max_version": "8.4"}},
    ],
    "ftp": [
        {"id": "CVE-2020-9273", "severity": "Critical", "description": "ProFTPD use-after-free in main processing loop (< 1.3.7b)"},
        {"id": "CVE-2021-3121", "severity": "High", "description": "ProFTPD directory traversal via mod_copy (< 1.3.7e)"},
        {"id": "CVE-2023-51785", "severity": "High", "description": "vsftpd: buffer overflow in parse_conf()"},
    ],
    "http": [
        {"id": "CVE-2021-44228", "severity": "Critical", "description": "Log4Shell: Remote Code Execution in Log4j 2 (< 2.15.0)"},
        {"id": "CVE-2024-24919", "severity": "Critical", "description": "Check Point Security Gateway Information Disclosure"},
        {"id": "CVE-2023-44487", "severity": "High", "description": "HTTP/2 Rapid Reset Attack (DoS)"},
        {"id": "CVE-2022-22965", "severity": "Critical", "description": "Spring4Shell: Remote Code Execution in Spring (JDK 9+)"},
        {"id": "CVE-2024-0204", "severity": "Critical", "description": "GoAnywhere MFT Auth Bypass"},
    ],
    "nginx": [
        {"id": "CVE-2024-24989", "severity": "Medium", "description": "Nginx HTTP/3 QUIC memory leak (< 1.25.3)"},
        {"id": "CVE-2023-44487", "severity": "High", "description": "HTTP/2 Rapid Reset Attack (affects Nginx)"},
        {"id": "CVE-2021-23017", "severity": "Medium", "description": "Nginx DNS resolver vulnerability"},
    ],
    "apache": [
        {"id": "CVE-2023-25690", "severity": "High", "description": "Apache HTTP Server HTTP Request Smuggling (< 2.4.56)"},
        {"id": "CVE-2021-44790", "severity": "Critical", "description": "Apache HTTP Server mod_lua buffer overflow (< 2.4.52)"},
        {"id": "CVE-2022-31813", "severity": "Medium", "description": "Apache HTTP Server mod_proxy request splitting"},
    ],
    "mysql": [
        {"id": "CVE-2023-21963", "severity": "High", "description": "MySQL Server Optimizer subquery vulnerability"},
        {"id": "CVE-2021-2421", "severity": "Medium", "description": "MySQL Server input validation in GIS"},
        {"id": "CVE-2024-21163", "severity": "Medium", "description": "MySQL Server DDL vulnerability"},
    ],
    "mariadb": [
        {"id": "CVE-2023-22084", "severity": "High", "description": "MariaDB Server memory corruption"},
        {"id": "CVE-2024-21096", "severity": "Medium", "description": "MariaDB Server privilege escalation"},
    ],
    "redis": [
        {"id": "CVE-2022-0543", "severity": "Critical", "description": "Redis Lua sandbox escape (Debian/Ubuntu, < 7.0.15)"},
        {"id": "CVE-2023-41056", "severity": "Medium", "description": "Redis integer overflow in string resize (< 7.0.15, 7.2.4)"},
        {"id": "CVE-2024-31449", "severity": "High", "description": "Redis Lua library arbitrary code execution"},
    ],
    "postgresql": [
        {"id": "CVE-2023-2454", "severity": "High", "description": "PostgreSQL search_path privilege escalation (< 15.3, 14.8)"},
        {"id": "CVE-2024-4317", "severity": "Medium", "description": "PostgreSQL memory leak in logical decoding (< 16.3, 15.7)"},
        {"id": "CVE-2024-0985", "severity": "Medium", "description": "PostgreSQL MERGE/REFRESH privilege escalation"},
    ],
    "mongodb": [
        {"id": "CVE-2021-32037", "severity": "High", "description": "MongoDB Server privilege escalation (< 5.0.5, 4.4.11)"},
        {"id": "CVE-2023-46237", "severity": "Medium", "description": "MongoDB Server DoS via crafted payloads"},
    ],
    "docker": [
        {"id": "CVE-2024-21626", "severity": "High", "description": "Docker runC container escape (< 1.1.12)"},
        {"id": "CVE-2019-13139", "severity": "Medium", "description": "Docker command injection via malicious image"},
    ],
    "elasticsearch": [
        {"id": "CVE-2023-31418", "severity": "High", "description": "Elasticsearch code execution via snapshot API"},
        {"id": "CVE-2021-44228", "severity": "Critical", "description": "Log4Shell: Remote Code Execution in Log4j (affects Elasticsearch < 7.16.2)"},
    ],
    "tomcat": [
        {"id": "CVE-2023-46589", "severity": "Medium", "description": "Tomcat request smuggling via HTTP/2 (< 9.0.84)"},
        {"id": "CVE-2024-21733", "severity": "High", "description": "Tomcat DoS via HTTP/2 frame handling"},
    ],
    "smtp": [
        {"id": "CVE-2023-51766", "severity": "High", "description": "Exim remote code execution (< 4.97.1)"},
        {"id": "CVE-2024-39929", "severity": "Medium", "description": "Exim DNS resolver vulnerability"},
    ],
}

def _extract_version(service: str, banner: str) -> str:
    svc = service.lower()
    ban = banner.lower()
    patterns = {
        "openssh": r"openssh[_-]([\d.]+p?\d*)",
        "ssh": r"openssh[_-]([\d.]+p?\d*)",
        "nginx": r"nginx/([\d.]+)",
        "apache": r"apache/([\d.]+)",
        "mysql": r"mysql[_-]?([\d.]+)",
        "mariadb": r"mariadb[_-]?([\d.]+)",
        "redis": r"redis[_-]?([\d.]+)",
        "postgresql": r"postgresql[_-]?([\d.]+)",
        "postgres": r"postgresql[_-]?([\d.]+)",
        "mongodb": r"mongodb[_-]?([\d.]+)",
        "proftpd": r"proftpd[_-]?([\d.]+)",
        "vsftpd": r"vsftpd[_-]?([\d.]+)",
        "pure-ftpd": r"pure-?ftpd[_-]?([\d.]+)",
        "tomcat": r"tomcat/([\d.]+)",
        "elasticsearch": r"elasticsearch[_-]?([\d.]+)",
        "docker": r"docker[_-]?([\d.]+)",
        "exim": r"exim[_-]?([\d.]+)",
        "smtp": r"exim[_-]?([\d.]+)",
    }
    for name, pat in patterns.items():
        if name in svc or (svc == "" and name in ban):
            m = re.search(pat, ban)
            if m:
                return m.group(1)
    return ""

def _version_in_range(version: str, affected: dict) -> bool:
    if not version or not affected:
        return False
    max_ver = affected.get("max_version", "")
    if not max_ver:
        return True
    # Simple comparison: version < max_version → affected
    try:
        return version < max_ver
    except:
        return False

def enrich_results(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    total_risk_score: float = 0
    vulnerabilities_found: int = 0
    
    results: List[Dict[str, Any]] = scan_data.get("results", [])
    if not results:
        scan_data["intelligence"] = {
            "total_risk_score": 0,
            "vulnerabilities_count": 0,
            "summary": "No open ports found."
        }
        return scan_data

    for result in results:
        status = result.get("status", "").lower()
        if status != "open":
            continue

        service = result.get("service", "").lower()
        banner = result.get("banner", "").lower()
        version = result.get("version", "")
        
        if not version:
            version = _extract_version(service, banner)
            if version:
                result["version"] = version

        matched_cves = []
        
        for svc_key, cves in CVE_DATABASE.items():
            if svc_key not in service and svc_key not in banner:
                continue
            for cve in cves:
                affected = cve.get("affected", {})
                if not affected or _version_in_range(version, affected):
                    if not any(c["id"] == cve["id"] for c in matched_cves):
                        matched_cves.append(cve)

        result["cves"] = matched_cves
        
        risk_score = 0
        for cve in matched_cves:
            sev = cve.get("severity", "Low")
            risk_score += {"Critical": 40, "High": 25, "Medium": 10, "Low": 5}.get(sev, 5)
        
        result["risk_score"] = float(min(risk_score, 100))
        if matched_cves:
            total_risk_score += result["risk_score"]
        vulnerabilities_found += len(matched_cves)

    open_count = sum(1 for r in results if r.get("status", "").lower() == "open")
    avg_risk: float = total_risk_score / open_count if open_count else 0.0
    
    if avg_risk > 70:
        summary = "CRITICAL: High risk services detected. Immediate action required."
    elif avg_risk > 40:
        summary = "WARNING: Potential vulnerabilities detected. Review results."
    elif avg_risk > 10:
        summary = "INFO: Minor vulnerabilities or exposed services found."
    else:
        summary = "System looks secure."

    scan_data["intelligence"] = {
        "total_risk_score": round(avg_risk, 2),
        "vulnerabilities_count": vulnerabilities_found,
        "summary": summary,
    }
    return scan_data

def generate_summary(score, count):
    if score > 100:
        return "Critical: Multiple high-severity vulnerabilities detected."
    elif score > 50:
        return "High: Several vulnerabilities found, immediate action recommended."
    elif count > 0:
        return "Medium: Some vulnerabilities detected."
    else:
        return "Low: No known vulnerabilities detected for identified services."

if __name__ == "__main__":
    try:
        input_data = sys.stdin.read()
        if not input_data:
            sys.exit(0)
        data = json.loads(input_data)
        enriched_data = enrich_results(data)
        print(json.dumps(enriched_data, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
