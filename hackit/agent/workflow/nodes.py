"""Autonomous pentest pipeline nodes.

Every node returns a partial ``PentestState`` update.  Nodes are deliberately
defensive: a missing binary, offline provider or unreachable target must never
abort the whole pipeline.  All observations are persisted between phases so a
run can be audited or resumed.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable, Dict, List, Tuple
from urllib.parse import parse_qs, parse_qsl, urlencode, urljoin, urlparse

from .state import Finding, PentestState, Phase, persist_state, target_slug
from .tools import GoBridge
from ..textutils import strip_control

WEB_PORTS = (80, 443, 8000, 8080, 8443, 8888, 3000, 5000)

PAYLOAD_TYPES = ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi", "open_redirect"]

SEVERITY_BY_TYPE = {
    "sqli": ("critical", 9.1, "Use parameterised queries and least-privilege DB accounts"),
    "cmd_injection": ("critical", 9.5, "Never pass user input to a shell"),
    "cmdi": ("critical", 9.5, "Never pass user input to a shell"),
    "ssti": ("critical", 9.0, "Use sandboxed templates and never render user input as code"),
    "lfi": ("high", 7.5, "Validate file paths against an allowlist"),
    "xxe": ("high", 7.3, "Disable external entity processing"),
    "ssrf": ("high", 8.2, "Validate outbound URLs and block link-local ranges"),
    "xss": ("high", 6.1, "Apply context-aware output encoding and a strict CSP"),
    "js_secret": ("high", 7.0, "Rotate exposed secrets and remove them from bundles"),
    "credential_exposure": ("high", 7.4, "Force password resets and enable MFA"),
    "open_redirect": ("medium", 4.3, "Use an allowlist for redirect destinations"),
    "cors": ("medium", 6.5, "Validate Origin and never combine wildcard with credentials"),
    "csrf": ("medium", 5.0, "Add anti-CSRF tokens to state-changing requests"),
    "ssl": ("medium", 5.8, "Update TLS configuration and certificate hygiene"),
    "osint_exposure": ("info", 2.0, "Review public exposure and remove stale accounts"),
    "probe": ("high", 7.0, "Reproduce manually and apply input validation"),
}


def _run_parallel(workers: List[Callable], max_workers: int = 5) -> List[Any]:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(w): w for w in workers}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"error": str(exc)})
    return results


def _finding(findings: List[Dict[str, Any]], ftype: str, target: str,
             description: str, evidence: str, severity: str = "",
             cvss: float | None = None, remediation: str = "") -> None:
    sev, score, rem = SEVERITY_BY_TYPE.get(ftype, ("info", 0.0, "Review manually"))
    findings.append(Finding(
        id=f"{ftype.upper()}-{uuid.uuid4().hex[:8]}",
        type=ftype,
        severity=severity or sev,
        target=strip_control(str(target)),
        description=strip_control(str(description)),
        evidence=strip_control(str(evidence))[:4000],
        remediation=strip_control(str(remediation)) or rem,
        cvss=cvss if cvss is not None else score,
    ).to_dict())


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _module_payload(result: List[Dict[str, Any]]) -> Any:
    if not result:
        return None
    first = result[0] if isinstance(result[0], dict) else {}
    if first.get("success") is False:
        return None
    return first.get("data")


def _target_parts(state: PentestState) -> Tuple[str, str, int, str]:
    """Normalise a target into ``(host, scheme, port, base_url)``.

    Users may pass ``example.com``, ``https://example.com/app`` or
    ``http://127.0.0.1:8080``.  Every node needs the host for port/tech scans
    and the full base URL for HTTP modules; the previous code built
    ``https://http://...`` for URL-shaped targets.
    """
    raw = (state.get("target") or "").strip()
    if not raw:
        return "", "https", 443, ""

    has_scheme = "://" in raw
    parsed = urlparse(raw if has_scheme else "//" + raw)
    host = parsed.hostname or raw.split("/")[0].split(":")[0]
    explicit_port = parsed.port

    if has_scheme:
        scheme = (parsed.scheme or "https").lower()
        port = explicit_port or (443 if scheme == "https" else 80)
    elif explicit_port:
        port = explicit_port
        scheme = "https" if port in (443, 8443) else "http"
    else:
        scheme = "https"
        port = 443

    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    base = f"{scheme}://{host_part}"
    if explicit_port:
        base += f":{explicit_port}"
    if has_scheme:
        path = parsed.path or ""
        if path and path != "/":
            base += path
        if parsed.query:
            base += "?" + parsed.query
    return host, scheme, port, base


def _is_private_host(host: str) -> bool:
    """Return True for loopback, RFC1918, link-local and local-only names.

    OSINT providers enumerate public usernames/domains.  Running them against
    ``127.0.0.1`` or ``*.local`` wastes minutes on doomed lookups and can leak
    internal names to third parties.
    """
    host = (host or "").strip().strip("[]").lower()
    if not host:
        return True
    if host in ("localhost", "localhost.localdomain") or host.endswith((".local", ".internal", ".lan", ".home")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def _scan_base_url(base_url: str) -> str:
    """Base URL for path-based scanners: strip query and fragment.

    The probe phase needs the query string to discover parameters, but path
    scanners must not append ``/.git/config`` after ``?id=1``.
    """
    return (base_url or "").split("#", 1)[0].split("?", 1)[0]


def _target_has_web(state: PentestState) -> bool:
    scan_data = state.get("scan_data") or {}
    if "has_web" in scan_data:
        return bool(scan_data.get("has_web"))
    for port in _as_list(scan_data.get("ports")):
        if not isinstance(port, dict):
            continue
        number = port.get("port", port.get("Port", 0))
        try:
            if int(number) in WEB_PORTS:
                return True
        except (TypeError, ValueError):
            continue
    host, _scheme, _port, _base = _target_parts(state)
    raw = (state.get("target") or "").strip()
    if "://" in raw:
        return bool(host)
    return "." in raw or ":" in raw or host in ("localhost", "127.0.0.1", "::1")


# ---------------------------------------------------------------------------
# Phase 1-2: reconnaissance and OSINT
# ---------------------------------------------------------------------------


def recon_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    host, scheme, port, base_url = _target_parts(state)
    scan_base = _scan_base_url(base_url)
    bridge = GoBridge()
    updates: Dict[str, Any] = {"phase": Phase.RECON.value}

    def do_portscan():
        data = _module_payload(bridge.run_worker(portscan=host or target))
        return ("ports", data if isinstance(data, list) else [])

    def do_subdomain():
        # Public OSINT cannot enumerate subdomains of an IP address or a
        # single-label host; querying it only returns the target itself.
        if _is_ip(host) or "." not in (host or ""):
            return ("subdomains", [])
        data = _module_payload(bridge.run_worker(subdomain=host or target))
        return ("subdomains", data if isinstance(data, list) else [])

    def do_tech():
        data = _module_payload(bridge.run_worker(tech=f"{host}:{port}"))
        return ("tech", data if isinstance(data, dict) else {})

    def do_waf():
        data = _module_payload(bridge.run_worker(waf=f"{host}:{port}"))
        return ("waf", data if isinstance(data, dict) else {})

    def do_headers():
        data = _module_payload(bridge.run_worker(headers=base_url))
        return ("headers", data if isinstance(data, list) else [])

    def do_fuzz():
        data = _module_payload(bridge.run_worker(fuzz=scan_base))
        return ("fuzz", data if isinstance(data, list) else [])

    scan_data: Dict[str, Any] = {}
    for item in _run_parallel(
        [do_portscan, do_subdomain, do_tech, do_waf, do_headers, do_fuzz],
        max_workers=6,
    ):
        if isinstance(item, tuple) and len(item) == 2:
            scan_data[item[0]] = item[1]

    has_web = _target_has_web({**state, "scan_data": scan_data})
    scan_data["web_url"] = base_url
    scan_data["host"] = host
    scan_data["scheme"] = scheme
    scan_data["port"] = port
    scan_data["has_web"] = has_web

    findings = list(state.get("findings", []))
    # Only verified fuzzer hits become findings.  A bare HTTP 200 is not
    # evidence on catch-all servers and SPA fallbacks, so the Go fuzzer
    # compares every path with a random baseline and a file signature.
    for entry in _as_list(scan_data.get("fuzz")):
        if not isinstance(entry, dict):
            continue
        verified = entry.get("Verified", entry.get("verified", False))
        status = entry.get("StatusCode", entry.get("status_code", 0))
        path = entry.get("Path", entry.get("path", ""))
        evidence = str(entry.get("Evidence", entry.get("evidence", "")) or "")
        if not verified or not path or not evidence:
            continue
        _finding(
            findings, "misconfig", f"{scan_base.rstrip('/')}/{str(path).lstrip('/')}",
            f"Sensitive path accessible: {path}",
            f"HTTP {status} for {path} — {evidence}",
            severity="medium", cvss=5.3,
            remediation="Remove the exposed resource or restrict access",
        )

    updates["scan_data"] = scan_data
    updates["findings"] = findings
    persist_state(dict(state, **updates))
    return updates


def recon_router(state: PentestState) -> str:
    """Recon always feeds passive OSINT before active web enumeration."""
    return "osint"


def osint_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    host, _scheme, _port, _base = _target_parts(state)
    updates: Dict[str, Any] = {"phase": Phase.OSINT.value}
    scan_data = dict(state.get("scan_data", {}))
    findings = list(state.get("findings", []))
    osint: Dict[str, Any] = {}

    if _is_private_host(host):
        osint = {"skipped": "private or loopback target"}
        scan_data["osint"] = osint
        updates["scan_data"] = scan_data
        updates["osint_data"] = osint
        updates["findings"] = findings
        persist_state(dict(state, **updates), suffix="_osint")
        return updates

    try:
        from hackit.osint.core import run_full_scan

        raw = run_full_scan(
            host,
            timeout=6,
            workers=16,
            verbose=False,
            check_domain=True,
            check_phone=False,
            deep=False,
        )
        profiles = _as_list(raw.get("profiles"))
        hits = [p for p in profiles if isinstance(p, dict) and p.get("status") == "hit"]
        email = raw.get("email") or {}
        domain = raw.get("domain") or {}
        analysis = raw.get("analysis") or {}
        correlation = raw.get("correlation") or {}

        osint = {
            "summary": raw.get("summary", {}),
            "analysis": analysis,
            "correlation": correlation,
            "email": email,
            "domain": domain,
            "profiles_hit": hits[:100],
            "trace_leads": _as_list(raw.get("trace_leads"))[:30],
        }

        if hits:
            platforms = ", ".join(str(p.get("platform", "?")) for p in hits[:12])
            _finding(
                findings, "osint_exposure", target,
                f"{len(hits)} public profile(s) linked to the target",
                f"Platforms: {platforms}",
                severity="info", cvss=2.0,
                remediation="Review the public footprint and remove stale accounts",
            )
        if email.get("breaches"):
            breaches = email.get("breaches") or []
            _finding(
                findings, "credential_exposure", target,
                f"{len(breaches)} breach record(s) reference the target",
                json.dumps(breaches[:10], default=str),
                severity="high" if len(breaches) >= 3 else "medium",
            )
        if domain.get("registrar"):
            osint["domain_registrar"] = domain.get("registrar")
    except Exception as exc:  # noqa: BLE001 - OSINT must never abort the pipeline
        osint = {"error": str(exc)[:500]}

    scan_data["osint"] = osint
    updates["scan_data"] = scan_data
    updates["osint_data"] = osint
    updates["findings"] = findings
    persist_state(dict(state, **updates), suffix="_osint")
    return updates


def osint_router(state: PentestState) -> str:
    return "js" if _target_has_web(state) else "payload"


# ---------------------------------------------------------------------------
# Phase 3-4: JavaScript and parameter discovery
# ---------------------------------------------------------------------------


def js_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    bridge = GoBridge()
    updates: Dict[str, Any] = {"phase": Phase.JS.value}
    scan_data = dict(state.get("scan_data", {}))
    findings = list(state.get("findings", []))

    if not _target_has_web(state):
        scan_data["js_analysis"] = {"skipped": "no web service detected"}
        updates["scan_data"] = scan_data
        persist_state(dict(state, **updates), suffix="_js")
        return updates

    _host, _scheme, _port, base_url = _target_parts(state)
    result = bridge.run_hative(base_url, ["js"], timeout=180)
    payload = _module_payload(result)
    if payload is None and result and isinstance(result[0], dict):
        payload = result[0].get("data")
    scan_data["js_analysis"] = payload or {}

    if isinstance(payload, dict):
        for secret in _as_list(payload.get("secrets")):
            if not isinstance(secret, dict):
                continue
            _finding(
                findings, "js_secret", target,
                f"Secret exposure: {secret.get('type', 'unknown')}",
                str(secret.get("value", ""))[:1000],
                severity=secret.get("severity", "high"),
            )

    updates["scan_data"] = scan_data
    updates["findings"] = findings
    persist_state(dict(state, **updates), suffix="_js")
    return updates


def param_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    bridge = GoBridge()
    updates: Dict[str, Any] = {"phase": Phase.PARAM.value}
    scan_data = dict(state.get("scan_data", {}))

    if not _target_has_web(state):
        scan_data["params"] = {"skipped": "no web service detected"}
    else:
        _host, _scheme, _port, base_url = _target_parts(state)
        result = bridge.run_hative(base_url, ["param"], timeout=120)
        scan_data["params"] = _module_payload(result) or (result[0].get("data") if result else {})

    updates["scan_data"] = scan_data
    persist_state(dict(state, **updates), suffix="_param")
    return updates


# ---------------------------------------------------------------------------
# Phase 5: AI payload forging
# ---------------------------------------------------------------------------


def _context_blob(state: PentestState) -> str:
    scan_data = state.get("scan_data", {})
    return json.dumps({
        "target": state.get("target"),
        "tech": scan_data.get("tech"),
        "waf": scan_data.get("waf"),
        "ports": scan_data.get("ports"),
        "subdomains": scan_data.get("subdomains"),
        "params": scan_data.get("params"),
        "fuzz": scan_data.get("fuzz"),
        "js": scan_data.get("js_analysis"),
        "osint": scan_data.get("osint", {}).get("analysis") if isinstance(scan_data.get("osint"), dict) else {},
    }, default=str)[:12000]


def _select_payload_types(state: PentestState) -> List[str]:
    blob = _context_blob(state).lower()
    selected: List[str] = []
    keywords = {
        "sqli": ["sql", "mysql", "postgres", "oracle", "mssql", "database"],
        "xss": ["xss", "script", "html", "template", "dom"],
        "ssrf": ["ssrf", "url=", "fetch", "proxy", "redirect"],
        "lfi": ["file", "path", "include", "download", "attachment"],
        "ssti": ["template", "jinja", "twig", "handlebars", "freemarker"],
        "cmdi": ["cmd", "exec", "shell", "system", "ping"],
        "open_redirect": ["redirect", "return", "next", "callback", "continue"],
    }
    for vuln_type, needles in keywords.items():
        if any(needle in blob for needle in needles):
            selected.append(vuln_type)
    for vuln_type in PAYLOAD_TYPES:
        if vuln_type not in selected:
            selected.append(vuln_type)
    return selected[:6]


def payload_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    updates: Dict[str, Any] = {"phase": Phase.PAYLOAD.value}
    types = _select_payload_types(state)

    try:
        from hackit.agent import payloads as forge

        result = forge.generate_multi(
            types,
            context=_context_blob(state),
            count=10,
            use_ai=True,
        )
    except Exception as exc:  # noqa: BLE001
        result = {"error": str(exc)[:500], "results": {}}

    updates["payloads"] = result
    persist_state(dict(state, **updates), suffix="_payload")
    return updates


# ---------------------------------------------------------------------------
# Phase 6-7: AI analysis and attack plan
# ---------------------------------------------------------------------------


def _offline_analysis(state: PentestState) -> str:
    scan_data = state.get("scan_data", {})
    findings = state.get("findings", [])
    base_url = scan_data.get("web_url") or state.get("target") or ""
    endpoints = _endpoint_candidates(state, base_url, limit=12)
    lines = [
        f"Target: {state.get('target')}",
        f"Web endpoint: {base_url}",
        f"Open ports: {len(_as_list(scan_data.get('ports')))}",
        f"Subdomains: {len(_as_list(scan_data.get('subdomains')))}",
        f"Findings so far: {len(findings)}",
        f"Concrete endpoints: {len(endpoints)}",
    ]
    if endpoints:
        lines.append("Endpoints: " + ", ".join(endpoints[:8]))
    parameter_names = _param_names(state)
    if parameter_names:
        lines.append("Parameters: " + ", ".join(parameter_names))
    tech = scan_data.get("tech")
    if tech:
        lines.append(f"Technology: {json.dumps(tech, default=str)[:500]}")
    lines.append("Candidate tests: " + ", ".join(_select_payload_types(state)))
    return "\n".join(lines)


def analyze_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    scan_data = state.get("scan_data", {})
    bridge = GoBridge()

    prompt = f"""Analyze this target for an authorised penetration test.
Target: {target}
Web endpoint: {scan_data.get('web_url') or target}
Ports: {json.dumps(scan_data.get('ports', []), indent=2, default=str)[:4000]}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2, default=str)[:3000]}
WAF: {json.dumps(scan_data.get('waf', {}), indent=2, default=str)[:2000]}
Subdomains: {json.dumps(scan_data.get('subdomains', []), indent=2, default=str)[:3000]}
Headers: {json.dumps(scan_data.get('headers', []), indent=2, default=str)[:2500]}
Discovered paths: {json.dumps(scan_data.get('fuzz', []), indent=2, default=str)[:3000]}
JS analysis: {json.dumps(scan_data.get('js_analysis', {}), indent=2, default=str)[:3000]}
Parameters: {json.dumps(scan_data.get('params', {}), indent=2, default=str)[:3000]}
Concrete endpoints: {json.dumps(_endpoint_candidates(state, scan_data.get('web_url') or target, limit=12), default=str)[:2000]}
Parameter names: {json.dumps(_param_names(state), default=str)[:1000]}
OSINT: {json.dumps(scan_data.get('osint', {}), indent=2, default=str)[:4000]}
Generated payload classes: {list((state.get('payloads') or {}).get('results', {}).keys())}

Identify the attack surface, likely vulnerability classes, entry points and
the three most valuable tests to run next. Be explicit about confidence.
No active verification has run yet: every vulnerability is a hypothesis.
Never describe anything as confirmed; use "candidate" or "hypothesis".
Be concise: answer in at most 120 words.
"""
    analysis = bridge.ai_chat(prompt, mode="analyze")
    analysis_error = ""
    if (not analysis or analysis.startswith("[!]") or len(analysis.strip()) < 80
            or analysis.lstrip().startswith("{")):
        analysis_error = analysis or "empty AI response"
        analysis = _offline_analysis(state)
    analysis = _sanitize_ai_narrative(analysis, False)

    result = {
        "phase": Phase.ANALYZE.value,
        "analysis": analysis,
        "analysis_error": analysis_error,
        "messages": state.get("messages", []) + [{"role": "analyze", "content": analysis}],
    }
    persist_state(dict(state, **result), suffix="_analyze")
    return result


def plan_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    analysis = state.get("analysis", "")
    scan_data = state.get("scan_data", {})
    payloads = (state.get("payloads") or {}).get("results", {})
    bridge = GoBridge()

    prompt = f"""Create a prioritised exploitation plan for an authorised test.

Target: {target}
Web endpoint: {scan_data.get('web_url') or target}
Analysis: {analysis[:4000]}
Ports: {json.dumps(scan_data.get('ports', []), indent=2, default=str)[:2000]}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2, default=str)[:2000]}
Generated payload classes: {list(payloads.keys())}

Return an ordered plan that covers:
1. SQL injection and authentication bypass points
2. XSS and client-side injection points
3. SSRF, URL fetching and cloud metadata paths
4. LFI/path traversal and file upload paths
5. SSTI and command injection candidates
6. Open redirect, 403 bypass and missing security headers
7. SSL/TLS and subdomain takeover issues
Sort by criticality and state the exact endpoint/parameter to test when known.
Be concise: answer in at most 120 words.
"""
    plan = bridge.ai_chat(prompt, mode="attack")
    plan_error = ""
    if (not plan or plan.startswith("[!]") or len(plan.strip()) < 80
            or plan.lstrip().startswith("{")):
        plan_error = plan or "empty AI response"
        plan = _offline_analysis(state)
    plan = _sanitize_ai_narrative(plan, False)

    result = {
        "phase": Phase.PLAN.value,
        "attack_plan": plan,
        "plan_error": plan_error,
        "messages": state.get("messages", []) + [{"role": "plan", "content": plan}],
    }
    persist_state(dict(state, **result), suffix="_plan")
    return result


# ---------------------------------------------------------------------------
# Phase 8: active verification with the Go worker
# ---------------------------------------------------------------------------


def _is_module_finding(module: str, item: Dict[str, Any]) -> bool:
    if item.get("vulnerable") or item.get("Vulnerable"):
        return True
    if module == "xss" and item.get("reflected"):
        return True
    if module in ("ssrf", "redirect", "bypass403") and item.get("success"):
        return True
    if module == "graphql" and item.get("vuln_type"):
        return True
    return False


def _process_module_results(findings, find_count, bridge, target, target_url, module,
                            ftype, severity, cvss, remediation):
    result = bridge.run_worker(**{module: target_url})
    data = _module_payload(result)
    items = [item for item in _as_list(data) if isinstance(item, dict)]
    error = ""
    if result and isinstance(result[0], dict) and result[0].get("success") is False:
        error = str(result[0].get("error") or "module failed")[:300]
    found = 0
    for item in items:
        if not _is_module_finding(module, item):
            continue
        evidence = str(item.get("evidence") or item.get("Evidence") or item)
        _finding(
            findings, ftype, str(item.get("endpoint", target_url)),
            evidence[:500], evidence,
            severity=severity, cvss=cvss, remediation=remediation,
        )
        find_count[0] += 1
        found += 1
    return {
        "module": module,
        "target": target_url,
        "tested": len(items),
        "findings": found,
        "error": error,
    }


def _endpoint_candidates(state: PentestState, base_url: str, limit: int = 8) -> List[str]:
    """Build same-origin endpoints from the fuzzer and JS analysis."""
    scan_data = state.get("scan_data") or {}
    base_url = str(base_url or scan_data.get("web_url") or _target_parts(state)[3] or "")
    if not base_url:
        return []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    directory = parsed.path.rsplit("/", 1)[0] if parsed.path not in ("", "/") else ""
    seen = set()
    candidates: List[str] = []

    def add(value: Any) -> None:
        value = str(value or "").strip()
        if not value:
            return
        if value.startswith("//"):
            value = parsed.scheme + ":" + value
        elif value.startswith("/"):
            value = origin + value
        elif not value.startswith(("http://", "https://")):
            value = urljoin(origin + directory + "/", value)
        candidate = urlparse(value)
        if candidate.netloc.lower() != parsed.netloc.lower():
            return
        clean = candidate._replace(fragment="").geturl()
        if clean not in seen:
            seen.add(clean)
            candidates.append(clean)

    add(base_url)
    for entry in _as_list(scan_data.get("fuzz")):
        if isinstance(entry, dict):
            path = entry.get("Path") or entry.get("path") or entry.get("endpoint") or entry.get("url")
        else:
            path = entry
        if path:
            add(path)
    js_analysis = scan_data.get("js_analysis")
    if isinstance(js_analysis, dict):
        for endpoint in _as_list(js_analysis.get("endpoints")):
            if isinstance(endpoint, str):
                add(endpoint)
    return candidates[:limit]


def _parameter_targets(base_url: str, names: List[str], limit: int = 6) -> List[str]:
    """Create same-origin URLs that exercise each discovered parameter."""
    parsed = urlparse(base_url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    targets: List[str] = []
    for name in names:
        name = str(name or "").strip()
        if not name or name in existing:
            continue
        query = dict(existing)
        query[name] = "1"
        targets.append(parsed._replace(query=urlencode(query)).geturl())
        if len(targets) >= limit:
            break
    return targets


def execute_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    findings = list(state.get("findings", []))
    scan_data = dict(state.get("scan_data", {}))
    bridge = GoBridge()
    updates: Dict[str, Any] = {"phase": Phase.EXECUTE.value}

    host, scheme, port, default_base = _target_parts(state)
    base_url = scan_data.get("web_url") or default_base
    find_count = [len(findings)]

    if not _target_has_web(state):
        updates["findings"] = findings
        persist_state(dict(state, **updates), suffix="_execute")
        return updates

    module_configs = [
        ("sqli", "sqli", "critical", 9.1, "Use parameterised queries"),
        ("xss", "xss", "high", 6.1, "Apply output encoding and CSP"),
        ("ssrf", "ssrf", "high", 8.2, "Validate and sanitise outbound URLs"),
        ("redirect", "open_redirect", "medium", 4.3, "Use an allowlist for redirects"),
        ("bypass403", "bypass403", "medium", 5.0, "Review access-control rules"),
        ("cors", "cors", "medium", 6.5, "Validate CORS origins"),
        ("csrf", "csrf", "medium", 5.0, "Add anti-CSRF tokens"),
        ("lfi", "lfi", "high", 7.5, "Validate file paths"),
        ("ssti", "ssti", "critical", 9.0, "Use sandboxed template rendering"),
        ("xxe", "xxe", "high", 7.3, "Disable external entities"),
        ("cmd", "cmd_injection", "critical", 9.5, "Never pass input to a shell"),
        ("nosqli", "nosqli", "high", 8.0, "Validate query operators"),
        ("ldap", "ldap", "high", 8.0, "Escape LDAP filter input"),
        ("graphql", "graphql", "medium", 5.5, "Disable production introspection"),
    ]

    endpoints = _endpoint_candidates(state, base_url, limit=6)
    parameter_names = _param_names(state)
    parameter_targets = _parameter_targets(base_url, parameter_names, limit=6)
    injection_modules = {
        "sqli", "xss", "ssrf", "redirect", "lfi", "ssti", "cmd", "nosqli",
    }
    path_modules = {"lfi", "bypass403", "xss", "redirect", "cors", "csrf", "graphql"}

    # The base URL gets every module.  Discovered endpoints and parameter
    # URLs get the modules that can actually exercise their input, so the
    # run is deeper without blindly multiplying every scanner.
    tasks: List[Tuple[Tuple[Any, ...], str]] = [
        (config, base_url) for config in module_configs
    ]
    for endpoint in endpoints[1:]:
        relevant = injection_modules if urlparse(endpoint).query else path_modules
        tasks.extend(
            (config, endpoint) for config in module_configs if config[0] in relevant
        )
    for target_url in parameter_targets:
        tasks.extend(
            (config, target_url) for config in module_configs if config[0] in injection_modules
        )
    try:
        task_budget = max(14, int(os.environ.get("HACKIT_MODULE_TASKS", "72")))
    except ValueError:
        task_budget = 72
    tasks = tasks[:task_budget]

    def make_worker(config, target_url):
        mod, ftype, sev, cvss, rem = config
        def worker():
            return _process_module_results(
                findings, find_count, bridge, target, target_url, mod, ftype, sev, cvss, rem
            )
        return worker

    module_results = _run_parallel(
        [make_worker(config, target_url) for config, target_url in tasks],
        max_workers=8,
    )

    attack_log = list(state.get("attack_log") or [])
    for item in module_results:
        if not isinstance(item, dict) or not item.get("module"):
            continue
        attack_log.append({
            "phase": Phase.EXECUTE.value,
            "action": "module",
            "module": item.get("module"),
            "target": item.get("target"),
            "tested": item.get("tested", 0),
            "findings": item.get("findings", 0),
            "error": item.get("error", ""),
        })
    attack_log = attack_log[-240:]

    if scheme == "https" or port in (443, 8443):
        ssl_target = f"{host}:{port}"
        ssl_result = bridge.run_worker(ssl=ssl_target)
        ssl_data = _module_payload(ssl_result)
        attack_log.append({
            "phase": Phase.EXECUTE.value,
            "action": "module",
            "module": "ssl",
            "target": ssl_target,
            "tested": 1 if isinstance(ssl_data, dict) else 0,
            "findings": 0,
            "error": "",
        })
        if isinstance(ssl_data, dict):
            issues = ssl_data.get("Vulnerabilities") or ssl_data.get("vulnerabilities") \
                or ssl_data.get("Issues") or ssl_data.get("issues")
            if issues and issues not in ("", [], {}):
                _finding(
                    findings, "ssl", ssl_target, str(issues)[:1000],
                    json.dumps(ssl_data, default=str)[:3000],
                    severity="medium", cvss=5.8,
                )
                attack_log[-1]["findings"] = 1

    coverage = dict(state.get("coverage") or {})
    coverage["execute_targets"] = sorted({target_url for _config, target_url in tasks})
    coverage["execute_modules"] = sorted({config[0] for config, _url in tasks})
    coverage["execute_tasks"] = len(tasks)
    coverage["execute_tested"] = sum(
        int(item.get("tested", 0)) for item in module_results if isinstance(item, dict)
    )
    coverage["execute_signals"] = sum(
        int(item.get("findings", 0)) for item in module_results if isinstance(item, dict)
    )
    coverage["endpoints"] = endpoints
    coverage["parameters"] = parameter_names
    execute_errors = [
        f"{item.get('module')}@{item.get('target')}: {item.get('error')}"
        for item in module_results
        if isinstance(item, dict) and item.get("error")
    ]
    if execute_errors:
        coverage["execute_errors"] = execute_errors[:12]

    # De-duplicate findings by type + target + evidence prefix.
    deduped = []
    seen = set()
    for item in findings:
        key = (item.get("type"), item.get("target"), str(item.get("evidence", ""))[:200])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    updates["findings"] = deduped
    updates["scan_data"] = scan_data
    updates["coverage"] = coverage
    updates["attack_log"] = attack_log
    persist_state(dict(state, **updates), suffix="_execute")
    return updates


# ---------------------------------------------------------------------------
# Phase 9: AI payload verification
# ---------------------------------------------------------------------------


def _param_names(state: PentestState) -> List[str]:
    params = (state.get("scan_data") or {}).get("params") or {}
    names: List[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("Name")
                    if name and name not in names:
                        names.append(str(name))
                elif isinstance(item, str) and item not in names:
                    names.append(item)
        elif isinstance(value, dict):
            for key in ("url_params", "extracted_from_js", "params", "parameters"):
                if key in value:
                    collect(value[key])

    collect(params)
    target = state.get("target", "")
    if "?" in target:
        for key in parse_qs(urlparse(target).query):
            if key not in names:
                names.append(key)
    return names[:8]


def probe_node(state: PentestState) -> Dict[str, Any]:
    updates: Dict[str, Any] = {"phase": Phase.PROBE.value}
    findings = list(state.get("findings", []))
    scan_data = dict(state.get("scan_data", {}))
    payloads_state = state.get("payloads") or {}
    results = payloads_state.get("results", {}) if isinstance(payloads_state, dict) else {}

    authorized = bool(state.get("authorized")) or os.environ.get(
        "HACKIT_AUTHORIZED", ""
    ).lower() in ("1", "true", "yes", "y")
    if not authorized:
        scan_data["payload_probe"] = {
            "skipped": "active verification requires an authorised run"
        }
        updates["probe_results"] = []
        updates["scan_data"] = scan_data
        updates["findings"] = findings
        persist_state(dict(state, **updates), suffix="_probe")
        return updates

    base_url = scan_data.get("web_url") or _target_parts(state)[3]
    params = _param_names(state) or ["url"]
    probe_targets = _endpoint_candidates(state, base_url, limit=4) or [base_url]
    probe_results: List[Dict[str, Any]] = []
    attack_log = list(state.get("attack_log") or [])
    coverage = dict(state.get("coverage") or {})
    attempted_types: List[str] = []

    try:
        from hackit.agent import payloads as forge

        try:
            budget = max(8, int(os.environ.get("HACKIT_PROBE_BUDGET", "60")))
        except ValueError:
            budget = 60

        for vuln_type, data in results.items():
            if budget <= 0:
                break
            items = data.get("payloads", []) if isinstance(data, dict) else []
            selected = [item.get("payload") for item in items[:3] if item.get("payload")]
            if not selected:
                continue
            attempted_types.append(vuln_type)
            for target_url in probe_targets:
                if budget <= 0:
                    break
                target_params = (params[:3] if target_url == base_url else params[:2]) or ["url"]
                for parameter in target_params:
                    if budget <= 0:
                        break
                    batch_payloads = selected[: (2 if target_url == base_url else 1)]
                    batch_payloads = batch_payloads[:budget]
                    if not batch_payloads:
                        break
                    batch = forge.probe_many(
                        target_url, vuln_type, batch_payloads, parameter=parameter,
                        timeout=8.0, delay=0.1,
                    )
                    budget -= len(batch)
                    probe_results.extend(batch)
                    for item in batch:
                        vulnerable = bool(item.get("vulnerable"))
                        attack_log.append({
                            "phase": Phase.PROBE.value,
                            "action": "payload",
                            "module": vuln_type,
                            "target": target_url,
                            "parameter": parameter,
                            "payload": str(item.get("payload", ""))[:300],
                            "vulnerable": vulnerable,
                            "evidence": str(item.get("evidence", ""))[:500],
                        })
                        if not vulnerable:
                            continue
                        _finding(
                            findings, "probe", item.get("target", target_url),
                            f"{vuln_type} payload produced a differential signal",
                            f"parameter={parameter} payload={item.get('payload')} "
                            f"evidence={item.get('evidence')}",
                            severity=SEVERITY_BY_TYPE.get(vuln_type, ("high", 7.0, ""))[0],
                            cvss=SEVERITY_BY_TYPE.get(vuln_type, ("high", 7.0, ""))[1],
                        )
    except Exception as exc:  # noqa: BLE001
        scan_data["payload_probe_error"] = str(exc)[:500]

    signals = sum(1 for item in probe_results if item.get("vulnerable"))
    scan_data["payload_probe"] = {
        "attempted": len(probe_results),
        "signals": signals,
        "parameters": params,
        "targets": probe_targets,
        "types": attempted_types,
    }
    coverage["probe_attempted"] = len(probe_results)
    coverage["probe_signals"] = signals
    coverage["probe_types"] = attempted_types
    coverage["probe_targets"] = probe_targets
    coverage["probe_parameters"] = params
    updates["probe_results"] = probe_results
    updates["scan_data"] = scan_data
    updates["findings"] = findings
    updates["coverage"] = coverage
    updates["attack_log"] = attack_log[-240:]
    persist_state(dict(state, **updates), suffix="_probe")
    return updates


# ---------------------------------------------------------------------------
# Phase 10-11: correlation and reporting
# ---------------------------------------------------------------------------

UNVERIFIED_EVIDENCE_NOTE = (
    "**Evidence status:** no evidence-backed finding or verified probe hit was "
    "recorded in this run. The narrative below is AI-generated context and may "
    "contain hypotheses; it is not evidence."
)

_NEGATION_RE = re.compile(
    r"\b(?:no|not|none|never|without|cannot|can't|couldn't|isn't|aren't|"
    r"wasn't|weren't|unconfirmed|unverified)\b",
    re.IGNORECASE,
)


def _has_verified_evidence(state: PentestState) -> bool:
    """True when the deterministic layers produced real, reproducible evidence."""
    if any(isinstance(item, dict) for item in (state.get("findings") or [])):
        return True
    return any(
        isinstance(item, dict) and item.get("vulnerable")
        for item in (state.get("probe_results") or [])
    )


def _rewrite_confirmation_chunk(match: "re.Match[str]") -> str:
    chunk = match.group(0)
    lowered = chunk.lower()
    if "confirmed" not in lowered or _NEGATION_RE.search(chunk):
        return chunk
    starts_upper = chunk.lstrip()[:1].isupper()
    chunk = re.sub(
        r"\b(?:is|are|was|were|has been|have been)\s+confirmed\b",
        "remains unverified",
        chunk,
        flags=re.IGNORECASE,
    )
    chunk = re.sub(r"\bwe\s+confirmed\b", "we hypothesised", chunk, flags=re.IGNORECASE)
    chunk = re.sub(r"\bconfirmed\s*:", "Unverified hypothesis:", chunk, flags=re.IGNORECASE)

    def possible(word: "re.Match[str]") -> str:
        original = word.group(0)
        replacement = "possible"
        return replacement.capitalize() if original[:1].isupper() else replacement

    chunk = re.sub(r"\bconfirmed\b", possible, chunk, flags=re.IGNORECASE)
    if starts_upper:
        for index, char in enumerate(chunk):
            if not char.isspace():
                chunk = chunk[:index] + char.upper() + chunk[index + 1:]
                break
    return chunk


def _sanitize_ai_narrative(text: str, has_evidence: bool) -> str:
    """Neutralise confirmation claims that no deterministic evidence supports.

    Local models sometimes describe hypotheses as "confirmed" even when the
    findings and probe lists are empty.  A report must never repeat that as
    fact, so unsupported confirmation language is rewritten deterministically.
    Negative statements ("no vulnerability was confirmed") are preserved.
    """
    cleaned = strip_control(text or "").strip()
    if not cleaned or has_evidence:
        return cleaned

    cleaned = re.sub(r"[^.!?\n]+[.!?]?", _rewrite_confirmation_chunk, cleaned)
    # A narrative must not compete with the deterministic risk score.
    def risk_unverified(match: "re.Match[str]") -> str:
        original = match.group(0)
        replacement = "risk score remains unverified"
        return replacement.capitalize() if original[:1].isupper() else replacement

    cleaned = re.sub(
        r"\brisk\s*(?:score)?\s*(?:(?:of|is)\s*)?[:=]?\s*([1-9]\d*(?:\.\d+)?)\s*/\s*10\b",
        risk_unverified,
        cleaned,
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"\(\s*[1-9]\d*(?:\.\d+)?\s*/\s*10\s*\)",
        "(risk not independently verified)",
        cleaned,
    )
    return cleaned


def correlate_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    findings = state.get("findings", [])
    scan_data = state.get("scan_data", {})
    bridge = GoBridge()

    prompt = f"""Correlate these authorised pentest findings into attack chains.
Target: {target}
Web endpoint: {scan_data.get('web_url') or target}
Ports: {json.dumps(scan_data.get('ports', []), indent=2, default=str)[:2000]}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2, default=str)[:2000]}
OSINT: {json.dumps(scan_data.get('osint', {}), indent=2, default=str)[:2500]}
Findings: {json.dumps(findings, indent=2, default=str)[:6000]}
Probe results: {json.dumps(state.get('probe_results', []), indent=2, default=str)[:4000]}
Coverage: {_coverage_summary(state)}
Active attack log: {json.dumps(state.get('attack_log', []), indent=2, default=str)[:4000]}
Verified findings: {len(findings)}
Verified probe hits: {sum(1 for item in (state.get('probe_results') or []) if isinstance(item, dict) and item.get('vulnerable'))}

1. Build realistic attack chains (only from observed evidence).
2. Calculate an overall risk score from 0 to 10.
3. Identify the critical path and the next best action.
4. Separate confirmed findings from hypotheses.
5. If both verified counts are zero, state that no vulnerability was confirmed
   and use a 0/10 risk score. Never describe a hypothesis as confirmed.
Be concise: answer in at most 80 words.
"""
    correlation = bridge.ai_chat(prompt, mode="correlate")
    correlation_error = ""
    if (not correlation or correlation.startswith("[!]") or len(correlation.strip()) < 40
            or correlation.lstrip().startswith("{")):
        correlation_error = correlation or "empty AI response"
        correlation = f"{len(findings)} finding(s) correlated offline."
    correlation = _sanitize_ai_narrative(
        correlation, _has_verified_evidence(state),
    )

    risk_score = 0.0
    for item in findings:
        try:
            risk_score = max(risk_score, float(item.get("cvss") or 0))
        except (TypeError, ValueError):
            continue
    if risk_score == 0.0 and findings:
        risk_score = 5.0

    result = {
        "phase": Phase.CORRELATE.value,
        "risk_score": risk_score,
        "correlation_error": correlation_error,
        "messages": state.get("messages", []) + [{"role": "correlate", "content": correlation}],
        "analysis": (
            state.get("analysis", "")
            + "\n\n[Correlation]\n" + correlation
            + "\n\n[Coverage]\n" + _coverage_summary(state)
        ).strip(),
    }
    persist_state(dict(state, **result), suffix="_correlate")
    return result


def _coverage_summary(state: PentestState) -> str:
    """Deterministic description of what the active phase actually tested."""
    coverage = state.get("coverage") or {}
    targets = _as_list(coverage.get("execute_targets"))
    modules = _as_list(coverage.get("execute_modules"))
    probe_targets = _as_list(coverage.get("probe_targets"))
    probe_types = _as_list(coverage.get("probe_types"))
    parameters = _as_list(coverage.get("parameters"))
    lines = [
        f"Active mode: {'yes' if state.get('authorized') else 'no'}",
        f"Module tasks: {coverage.get('execute_tasks', 0)} across {len(targets)} target(s)",
        f"Modules exercised: {', '.join(str(item) for item in modules) or 'none'}",
        f"Payload probes: {coverage.get('probe_attempted', 0)} across "
        f"{len(probe_targets)} target(s), {len(probe_types)} type(s)",
        f"Probe signals: {coverage.get('probe_signals', 0)}",
        f"Discovered endpoints: {len(_as_list(coverage.get('endpoints')))}",
        f"Parameters: {', '.join(str(item) for item in parameters[:10]) or 'none'}",
    ]
    errors = _as_list(coverage.get("execute_errors"))
    if errors:
        lines.append(f"Module errors: {len(errors)}")
    return "\n".join(lines)


def _offline_report(state: PentestState) -> str:
    """Build a professional report from evidence when the AI is unavailable."""
    target = state.get("target", "")
    findings = state.get("findings", []) or []
    scan_data = state.get("scan_data", {}) or {}
    risk_score = state.get("risk_score", 0.0)
    analysis = state.get("analysis", "")
    attack_plan = state.get("attack_plan", "")
    has_evidence = _has_verified_evidence(state)
    analysis = _sanitize_ai_narrative(analysis, has_evidence)
    attack_plan = _sanitize_ai_narrative(attack_plan, has_evidence)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(
        findings,
        key=lambda item: severity_order.get(str(item.get("severity", "info")).lower(), 5),
    )
    counts: Dict[str, int] = {}
    for item in ranked:
        severity = str(item.get("severity", "info")).lower()
        counts[severity] = counts.get(severity, 0) + 1

    lines = [
        "## Executive Summary",
        "",
        f"Automated assessment of **{target}** completed with a risk score of "
        f"**{risk_score}/10** and **{len(findings)}** evidence-backed finding(s).",
        "",
    ]
    if counts:
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for severity in ("critical", "high", "medium", "low", "info"):
            if counts.get(severity):
                lines.append(f"| {severity.title()} | {counts[severity]} |")
        lines.append("")
    if not findings:
        lines.extend([
            "No exploitable issue with a reproducible signal was confirmed in this "
            "run. Absence of findings is not proof of security; manual review and "
            "authenticated testing remain recommended.",
            "",
        ])

    lines.extend([
        "## Methodology and Scope",
        "",
        "Phases executed: passive recon, OSINT, JavaScript analysis, parameter "
        "discovery, payload generation, AI-assisted analysis, active verification, "
        "correlation and reporting. Active payload verification was only performed "
        "when explicitly authorised.",
        "",
    ])
    ports = _as_list(scan_data.get("ports"))
    tech = scan_data.get("tech") or {}
    subdomains = _as_list(scan_data.get("subdomains"))
    web_url = scan_data.get("web_url") or target
    lines.append(f"- Web endpoint tested: {web_url}")
    lines.append(f"- Open ports observed: {len(ports)}")
    lines.append(f"- Subdomains observed: {len(subdomains)}")
    if isinstance(tech, dict) and tech:
        lines.append(f"- Technology hints: {json.dumps(tech, default=str)[:500]}")
    lines.append("")
    lines.extend(["## Active Coverage", "", _coverage_summary(state), ""])

    attack_log = _as_list(state.get("attack_log"))
    if attack_log:
        lines.extend([
            "### Attack Log (latest)",
            "",
            "| Phase | Action | Module | Target | Result |",
            "| --- | --- | --- | --- | --- |",
        ])
        for entry in attack_log[-20:]:
            if not isinstance(entry, dict):
                continue
            result_text = (
                f"vulnerable: {entry.get('evidence', '')}"
                if entry.get("vulnerable")
                else f"{entry.get('tested', 0)} tested / {entry.get('findings', 0)} finding(s)"
            )
            lines.append(
                f"| {entry.get('phase', '')} | {entry.get('action', '')} | "
                f"{entry.get('module', '')} | {str(entry.get('target', ''))[:100]} | "
                f"{str(result_text)[:160].replace('|', '\\\\|')} |"
            )
        lines.append("")

    if ranked:
        lines.extend([
            "## Key Findings",
            "",
            "| Severity | CVSS | Finding | Target | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ])
        for item in ranked:
            evidence = str(item.get("evidence", ""))[:180].replace("|", "\\|")
            title = str(item.get("title", item.get("type", "finding")))[:120].replace("|", "\\|")
            target_value = str(item.get("target", target))[:120].replace("|", "\\|")
            lines.append(
                f"| {str(item.get('severity', 'info')).title()} | "
                f"{item.get('cvss', '—')} | {title} | {target_value} | {evidence} |"
            )
        lines.append("")

        lines.extend(["## Remediation Recommendations", ""])
        remediation_seen = set()
        for item in ranked:
            suggestion = str(item.get("remediation", "")).strip()
            if suggestion and suggestion not in remediation_seen:
                remediation_seen.add(suggestion)
                lines.append(f"- {suggestion}")
        if not remediation_seen:
            lines.append("- Review each finding and apply the vendor/OWASP guidance.")
        lines.append("")

    lines.extend(["## AI Analysis (narrative, not evidence)", ""])
    lines.extend([analysis[:4000] or "No AI analysis was available.", ""])
    if attack_plan:
        lines.extend(["## AI Attack Plan (narrative, not evidence)", "", attack_plan[:3000], ""])
    lines.extend([
        "## Conclusion",
        "",
        "This report reflects only the evidence collected during the run. "
        "Hypotheses are explicitly separated from confirmed findings, and no "
        "destructive actions were performed.",
        "",
    ])
    return "\n".join(lines)


def report_node(state: PentestState) -> Dict[str, Any]:
    target = state["target"]
    findings = state.get("findings", [])
    risk_score = state.get("risk_score", 0.0)
    scan_data = state.get("scan_data", {})
    analysis = state.get("analysis", "")
    attack_plan = state.get("attack_plan", "")
    payloads_state = state.get("payloads") or {}
    probe_results = state.get("probe_results", [])
    verified_probe_hits = sum(
        1 for item in probe_results
        if isinstance(item, dict) and item.get("vulnerable")
    )
    bridge = GoBridge()

    prompt = f"""Write a concise executive summary for an authorised pentest report.

Target: {target}
Web endpoint: {scan_data.get('web_url') or target}
Risk Score: {risk_score}/10
Analysis: {analysis[:2500]}
Attack Plan: {attack_plan[:2000]}
Findings: {json.dumps(findings, indent=2, default=str)[:5000]}
Verified findings: {len(findings)}
Verified probe hits: {verified_probe_hits}
OSINT: {json.dumps(scan_data.get('osint', {}), indent=2, default=str)[:2000]}
Payload classes: {list((payloads_state.get('results') or {}).keys())}
Probe results: {json.dumps(probe_results, indent=2, default=str)[:2000]}
Coverage: {_coverage_summary(state)}
Active attack log: {json.dumps(state.get('attack_log', []), indent=2, default=str)[:3000]}
Ports: {json.dumps(scan_data.get('ports', []), indent=2, default=str)[:1500]}
Technologies: {json.dumps(scan_data.get('tech', {}), indent=2, default=str)[:1500]}

Cover the most important evidence, business impact and the next action.
The Findings list and verified probe hits are the ONLY evidence.
If both verified counts are zero, state that no vulnerability was confirmed,
do not assign a nonzero risk score, and never call a hypothesis confirmed.
Otherwise only claim what the evidence supports; mark hypotheses as hypotheses.
Be concise: answer in at most 150 words.
"""
    report = bridge.ai_chat(prompt, mode="report")
    report_error = ""
    if (not report or report.startswith("[!]") or len(report.strip()) < 120
            or report.lstrip().startswith("{")):
        report_error = report or "empty AI response"
        report = ""

    has_evidence = _has_verified_evidence(state)
    structured = _offline_report(state)
    if report:
        report = _sanitize_ai_narrative(report.strip(), has_evidence)
        note = "" if has_evidence else "> " + UNVERIFIED_EVIDENCE_NOTE + "\n\n"
        report = (
            "## AI Analyst Summary (narrative, not evidence)\n\n"
            + note
            + report
            + "\n\n---\n\n"
            + structured
        )
    else:
        report = structured

    reports_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "go", "reports", "pentest",
    )
    os.makedirs(reports_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target_slug(target)
    report_path = os.path.join(reports_dir, f"{safe_target}_{timestamp}.md")
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write(f"# Pentest Report: {target}\n\n")
        handle.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        handle.write(f"**Risk Score:** {risk_score}/10\n")
        handle.write(f"**Findings:** {len(findings)}\n")
        handle.write(f"**Authorized active mode:** {'yes' if state.get('authorized') else 'no'}\n")
        handle.write(f"**Module tasks:** {(state.get('coverage') or {}).get('execute_tasks', 0)}\n")
        handle.write(f"**Payload probes:** {(state.get('coverage') or {}).get('probe_attempted', 0)}\n")
        handle.write(f"**Payload classes:** {', '.join((payloads_state.get('results') or {}).keys()) or 'none'}\n\n")
        handle.write("---\n\n")
        handle.write(report)

    result = {
        "report_path": report_path,
        "report_error": report_error,
        "phase": Phase.DONE.value,
        "messages": state.get("messages", []) + [{"role": "report", "content": report}],
    }
    persist_state(dict(state, **result), suffix="_report")
    return result
