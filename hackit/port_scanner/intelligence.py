import json
import sys

# Simple CVE mapping for demonstration
# In a real scenario, this would query a local database or API
CVE_DATABASE = {
    "ssh": [
        {"id": "CVE-2024-6387", "severity": "Critical", "description": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH's server"},
        {"id": "CVE-2023-38408", "severity": "High", "description": "Remote code execution in OpenSSH agent forwarding"},
        {"id": "CVE-2021-41617", "severity": "Medium", "description": "Privilege escalation in OpenSSH via authorized_keys"}
    ],
    "ftp": [
        {"id": "CVE-2021-3121", "severity": "High", "description": "ProFTPD directory traversal"},
        {"id": "CVE-2020-9273", "severity": "Critical", "description": "ProFTPD use-after-free vulnerability"}
    ],
    "http": [
        {"id": "CVE-2021-44228", "severity": "Critical", "description": "Log4Shell: Remote Code Execution in Log4j"},
        {"id": "CVE-2023-44487", "severity": "High", "description": "HTTP/2 Rapid Reset Attack (DoS)"},
        {"id": "CVE-2024-24919", "severity": "Critical", "description": "Check Point Security Gateway Information Disclosure"}
    ],
    "mysql": [
        {"id": "CVE-2021-2421", "severity": "Medium", "description": "MySQL Server vulnerabilities"},
        {"id": "CVE-2023-21963", "severity": "High", "description": "MySQL Server vulnerability in Optimizer"}
    ],
    "redis": [
        {"id": "CVE-2022-0543", "severity": "Critical", "description": "Redis Lua sandbox escape (Debian/Ubuntu specific)"},
        {"id": "CVE-2023-41056", "severity": "Medium", "description": "Redis integer overflow in string resize"}
    ],
    "postgresql": [
        {"id": "CVE-2023-2454", "severity": "High", "description": "PostgreSQL search_path vulnerability"},
        {"id": "CVE-2024-4317", "severity": "Medium", "description": "PostgreSQL memory leak in logic decoding"}
    ],
    "mongodb": [
        {"id": "CVE-2021-32037", "severity": "High", "description": "MongoDB Server privilege escalation"},
        {"id": "CVE-2023-46237", "severity": "Medium", "description": "MongoDB Server Denial of Service"}
    ]
}

def enrich_results(scan_data):
    total_risk_score = 0
    vulnerabilities_found = 0
    
    results = scan_data.get("results", [])
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
            result["cves"] = []
            result["risk_score"] = 0
            continue

        service = result.get("service", "").lower()
        banner = result.get("banner", "").lower()
        version = result.get("version", "")
        
        # If version is missing, try to extract it from banner
        if not version and banner:
            # Simple extraction patterns
            if "openssh" in banner:
                match = re.search(r"openssh[_-]([0-9.p1-]+)", banner)
                if match: version = f"OpenSSH {match.group(1)}"
            elif "nginx" in banner:
                match = re.search(r"nginx/([0-9.]+)", banner)
                if match: version = f"Nginx {match.group(1)}"
            elif "apache" in banner:
                match = re.search(r"apache/([0-9.]+)", banner)
                if match: version = f"Apache {match.group(1)}"
            
            result["version"] = version

        matched_cves = []
        
        # Check by service name
        for svc, cves in CVE_DATABASE.items():
            if svc in service:
                matched_cves.extend(cves)
        
        # Check banner for version-specific matches (simplified)
        if "openssh 8.5" in banner or "openssh 8.6" in banner or "openssh 8.7" in banner or "openssh 8.8" in banner or "openssh 8.9" in banner or "openssh 9.0" in banner or "openssh 9.1" in banner or "openssh 9.2" in banner or "openssh 9.3" in banner or "openssh 9.4" in banner or "openssh 9.5" in banner or "openssh 9.6" in banner or "openssh 9.7" in banner:
            if not any(c["id"] == "CVE-2024-6387" for c in matched_cves):
                matched_cves.append(CVE_DATABASE["ssh"][0]) # regreSSHion

        result["cves"] = matched_cves
        
        risk_score = 0
        for cve in matched_cves:
            severity = cve.get("severity", "Low")
            if severity == "Critical":
                risk_score += 40
            elif severity == "High":
                risk_score += 25
            elif severity == "Medium":
                risk_score += 10
            elif severity == "Low":
                risk_score += 5
        
        # Cap risk score per port
        result["risk_score"] = min(risk_score, 100)
        total_risk_score += result["risk_score"]
        vulnerabilities_found += len(matched_cves)

    # Global intelligence
    avg_risk = total_risk_score / len(results) if results else 0
    
    summary = "System looks secure."
    if avg_risk > 70:
        summary = "CRITICAL: High risk services detected. Immediate action required."
    elif avg_risk > 40:
        summary = "WARNING: Potential vulnerabilities detected. Review results."
    elif avg_risk > 10:
        summary = "INFO: Minor vulnerabilities or exposed services found."

    scan_data["intelligence"] = {
        "total_risk_score": round(avg_risk, 2),
        "vulnerabilities_count": vulnerabilities_found,
        "summary": summary
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
    # Expecting JSON input from stdin
    try:
        input_data = sys.stdin.read()
        if not input_data:
            sys.exit(0)
            
        data = json.loads(input_data)
        enriched_data = enrich_results(data)
        print(json.dumps(enriched_data, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
