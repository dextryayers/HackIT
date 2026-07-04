import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Callable

from .state import PentestState, Finding, Phase, persist_state
from .tools import GoBridge


def _run_parallel(workers: List[Callable], max_workers: int = 5) -> List[Any]:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(w): w for w in workers}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                results.append({"error": str(e)})
    return results


def recon_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    bridge = GoBridge()

    updates = {"phase": Phase.RECON.value}

    def do_portscan():
        r = bridge.run_worker(portscan=target)
        return ("ports", r[0].get("data", []) if r and r[0].get("success") else [])

    def do_subdomain():
        r = bridge.run_worker(subdomain=target)
        return ("subdomains", r[0].get("data", []) if r and r[0].get("success") else [])

    def do_tech():
        r = bridge.run_worker(tech=f"{target}:443")
        return ("tech", r[0].get("data", {}) if r and r[0].get("success") else {})

    def do_waf():
        r = bridge.run_worker(waf=f"{target}:443")
        return ("waf", r[0].get("data", {}) if r and r[0].get("success") else {})

    def do_headers():
        r = bridge.run_worker(headers=f"https://{target}")
        return ("headers", r[0].get("data", []) if r and r[0].get("success") else [])

    def do_fuzz():
        r = bridge.run_worker(fuzz=f"https://{target}")
        return ("fuzz", r[0].get("data", []) if r and r[0].get("success") else [])

    scan_data = {}
    for key, data in _run_parallel([do_portscan, do_subdomain, do_tech, do_waf, do_headers, do_fuzz], max_workers=6):
        if isinstance(key, str) and isinstance(data, (dict, list)):
            scan_data[key] = data

    findings = []
    has_web = False
    ports = scan_data.get("ports", [])
    if isinstance(ports, list):
        for p in ports:
            if isinstance(p, dict):
                port_num = p.get("Port", 0)
                if port_num in (80, 443, 8080, 8443):
                    has_web = True

    updates["scan_data"] = scan_data
    updates["findings"] = findings

    persist_state(dict(state, **updates))
    return updates


def recon_router(state: PentestState) -> str:
    scan_data = state.get("scan_data", {})
    ports = scan_data.get("ports", [])

    has_web = False
    if isinstance(ports, list):
        for p in ports:
            if isinstance(p, dict) and p.get("Port") in (80, 443, 8080, 8443):
                has_web = True

    if has_web:
        return "js"   # js comes before analyze
    elif len(ports) > 0:
        return "correlate"
    else:
        return "report"


def js_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    bridge = GoBridge()
    updates = {"phase": Phase.JS.value}

    js_result = bridge.run_worker(js=f"https://{target}")
    if js_result and js_result[0].get("success"):
        js_data = js_result[0].get("data", {})
        updates["scan_data"] = {**state.get("scan_data", {}), "js_analysis": js_data}

        if isinstance(js_data, dict):
            secrets = js_data.get("secrets", [])
            existing = list(state.get("findings", []))
            for s in secrets:
                existing.append(Finding(
                    id=f"JS-SECRET-{len(existing)}", type="js_secret",
                    severity=s.get("severity", "high"),
                    target=target, description=f"Secret exposure: {s.get('type', 'unknown')}",
                    evidence=s.get("value", ""), remediation="Rotate exposed secrets"
                ).to_dict())
            updates["findings"] = existing

    persist_state(dict(state, **updates), suffix="_js")
    return updates


def param_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    bridge = GoBridge()
    updates = {"phase": Phase.PARAM.value}

    param_result = bridge.run_worker(param=f"https://{target}")
    if param_result and param_result[0].get("success"):
        param_data = param_result[0].get("data", {})
        scan_data = dict(state.get("scan_data", {}))
        scan_data["params"] = param_data
        updates["scan_data"] = scan_data

    persist_state(dict(state, **updates), suffix="_param")
    return updates


def analyze_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    scan_data = state.get("scan_data", {})
    bridge = GoBridge()

    prompt = f"""Analyze this target for pentest:
Target: {target}
Ports: {json.dumps(scan_data.get('ports', []), indent=2)}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2)}
WAF: {json.dumps(scan_data.get('waf', {}), indent=2)}
Subdomains: {json.dumps(scan_data.get('subdomains', []), indent=2)}
Headers: {json.dumps(scan_data.get('headers', []), indent=2)}
Discovered paths: {json.dumps(scan_data.get('fuzz', []), indent=2)}
JS Analysis: {json.dumps(scan_data.get('js_analysis', {}), indent=2)}
Parameters: {json.dumps(scan_data.get('params', {}), indent=2)}

Identify attack surface, potential vulnerabilities, and entry points. List specific vulnerability types to test."""

    analysis = bridge.ai_chat(prompt, mode="analyze")

    result = {
        "analysis": analysis,
        "messages": state.get("messages", []) + [{"role": "analyze", "content": analysis}],
    }
    persist_state(dict(state, **result), suffix="_analyze")
    return result


def plan_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    analysis = state.get("analysis", "")
    scan_data = state.get("scan_data", {})
    bridge = GoBridge()

    prompt = f"""Based on this analysis, create an exploitation plan:

Target: {target}
Analysis: {analysis}

Ports: {json.dumps(scan_data.get('ports', []), indent=2)}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2)}

Create a prioritized attack plan with:
1. SQL Injection testing points
2. XSS testing points
3. SSRF entry points
4. Open redirect parameters
5. 403 bypass targets
6. Subdomain takeover candidates
7. SSL/TLS issues
Sort by criticality (Critical → High → Medium → Low)."""

    plan = bridge.ai_chat(prompt, mode="attack")

    result = {
        "attack_plan": plan,
        "messages": state.get("messages", []) + [{"role": "plan", "content": plan}],
    }
    persist_state(dict(state, **result), suffix="_plan")
    return result


def _process_module_results(findings, find_count, bridge, target, base_url, module, _type, severity, cvss, remediation):
    result = bridge.run_worker(**{module: base_url})
    if result and result[0].get("success"):
        data = result[0].get("data", [])
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("vulnerable", item.get("Vulnerable", False)):
                    findings.append(Finding(
                        id=f"{_type.upper()}-{find_count[0]}", type=_type, severity=severity,
                        target=base_url,
                        description=str(item.get("evidence", item.get("Evidence", ""))),
                        evidence=str(item), remediation=remediation, cvss=cvss
                    ).to_dict())
                    find_count[0] += 1
    return findings


def execute_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    existing_findings = state.get("findings", [])
    bridge = GoBridge()

    findings = list(existing_findings)
    base_url = f"https://{target}"
    find_count = [len(findings)]

    module_configs = [
        ("sqli", "sqli", "critical", 9.1, "Use parameterized queries"),
        ("xss", "xss", "high", 6.1, "Implement CSP and output encoding"),
        ("ssrf", "ssrf", "high", 8.2, "Validate and sanitize URLs"),
        ("redirect", "open_redirect", "medium", 4.3, "Use allowlist for redirect URLs"),
        ("bypass403", "bypass403", "medium", 5.0, "Review access control rules"),
        ("cors", "cors", "medium", 6.5, "Implement proper CORS origin validation"),
        ("csrf", "csrf", "medium", 5.0, "Add anti-CSRF tokens to all forms"),
        ("lfi", "lfi", "high", 7.5, "Validate and sanitize file paths"),
        ("ssti", "ssti", "critical", 9.0, "Use safe template rendering"),
        ("xxe", "xxe", "high", 7.3, "Disable external entity processing"),
        ("cmd", "cmd_injection", "critical", 9.5, "Never pass user input to shell commands"),
    ]

    def make_worker(mod, _type, sev, cvss, rem):
        def worker():
            nonlocal findings, find_count
            return _process_module_results(findings, find_count, bridge, target, base_url, mod, _type, sev, cvss, rem)
        return worker

    workers = [make_worker(m, t, s, c, r) for m, t, s, c, r in module_configs]
    _run_parallel(workers, max_workers=6)

    ssl_result = bridge.run_worker(ssl=f"{target}:443")
    if ssl_result and ssl_result[0].get("success"):
        ssl_data = ssl_result[0].get("data", {})
        if isinstance(ssl_data, dict) and ssl_data.get("Issues"):
            findings.append(Finding(
                id=f"SSL-{find_count[0]}", type="ssl", severity="medium",
                target=f"{target}:443", description=str(ssl_data.get("Issues", "")),
                evidence=str(ssl_data), remediation="Update SSL/TLS configuration",
                cvss=5.8
            ).to_dict())
            find_count[0] += 1

    result = {"findings": findings, "phase": Phase.EXECUTE.value}
    persist_state(dict(state, **result), suffix="_execute")
    return result


def correlate_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    findings = state.get("findings", [])
    scan_data = state.get("scan_data", {})
    bridge = GoBridge()

    prompt = f"""Correlate these pentest findings into attack chains:

Target: {target}
Ports: {json.dumps(scan_data.get('ports', []), indent=2)}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2)}

Findings: {json.dumps(findings, indent=2)}

1. Build attack chains combining multiple vulnerabilities
2. Calculate overall risk score (0-10)
3. Identify critical path exploitation
4. Prioritize findings by exploitability and impact"""

    correlation = bridge.ai_chat(prompt, mode="correlate")

    risk_score = 0.0
    for f in findings:
        cvss = f.get("cvss", 0)
        if cvss:
            risk_score = max(risk_score, cvss)
    if risk_score == 0.0 and findings:
        risk_score = 5.0

    result = {
        "risk_score": risk_score,
        "messages": state.get("messages", []) + [{"role": "correlate", "content": correlation}],
    }
    persist_state(dict(state, **result), suffix="_correlate")
    return result


def report_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    findings = state.get("findings", [])
    risk_score = state.get("risk_score", 0.0)
    scan_data = state.get("scan_data", {})
    analysis = state.get("analysis", "")
    attack_plan = state.get("attack_plan", "")
    bridge = GoBridge()

    prompt = f"""Generate a professional pentest report:

Target: {target}
Risk Score: {risk_score}/10
Analysis: {analysis[:2000]}
Attack Plan: {attack_plan[:2000]}
Findings: {json.dumps(findings, indent=2)}
Ports: {json.dumps(scan_data.get('ports', []), indent=2)}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2)}

Format with:
1. Executive Summary
2. Methodology
3. Key Findings (sorted by severity)
4. Attack Chains
5. Risk Assessment
6. Remediation Recommendations
7. Conclusion"""

    report = bridge.ai_chat(prompt, mode="report")

    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "go", "reports", "pentest")
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    report_path = os.path.join(reports_dir, f"{safe_target}_{timestamp}.md")
    with open(report_path, "w") as f:
        f.write(f"# Pentest Report: {target}\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Risk Score:** {risk_score}/10\n")
        f.write(f"**Findings:** {len(findings)}\n\n")
        f.write("---\n\n")
        f.write(report)

    result = {
        "report_path": report_path,
        "phase": Phase.DONE.value,
        "messages": state.get("messages", []) + [{"role": "report", "content": report}],
    }
    persist_state(dict(state, **result), suffix="_report")
    return result
