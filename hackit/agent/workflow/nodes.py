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


_CURRENT_PROGRESS = None


def set_progress_callback(cb) -> None:
    global _CURRENT_PROGRESS
    _CURRENT_PROGRESS = cb


def _emit_progress(phase: str, message: str) -> None:
    cb = _CURRENT_PROGRESS
    if cb is None:
        return
    try:
        cb(phase, message)
    except Exception:  # noqa: BLE001
        pass


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
    findings = list(state.get("findings", []))
    _emit_progress("recon", "recon starting")

    def do_portscan():
        data = _module_payload(bridge.run_worker(portscan=host or target, timeout=30))
        return ("ports", data if isinstance(data, list) else [])

    def do_subdomain():
        # Public OSINT cannot enumerate subdomains of an IP address or a
        # single-label host; querying it only returns the target itself.
        if _is_ip(host) or "." not in (host or ""):
            return ("subdomains", [])
        data = _module_payload(bridge.run_worker(subdomain=host or target, timeout=30))
        return ("subdomains", data if isinstance(data, list) else [])

    def do_tech():
        data = _module_payload(bridge.run_worker(tech=f"{host}:{port}", timeout=30))
        return ("tech", data if isinstance(data, dict) else {})

    def do_waf():
        data = _module_payload(bridge.run_worker(waf=f"{host}:{port}", timeout=30))
        return ("waf", data if isinstance(data, dict) else {})

    def do_headers():
        data = _module_payload(bridge.run_worker(headers=base_url, timeout=30))
        return ("headers", data if isinstance(data, list) else [])

    def do_fuzz():
        data = _module_payload(bridge.run_worker(fuzz=scan_base, timeout=30))
        return ("fuzz", data if isinstance(data, list) else [])

    scan_data: Dict[str, Any] = {}
    _emit_progress("recon", "core recon modules starting")
    for item in _run_parallel(
        [do_portscan, do_subdomain, do_tech, do_waf, do_headers, do_fuzz],
        max_workers=6,
    ):
        if isinstance(item, tuple) and len(item) == 2:
            scan_data[item[0]] = item[1]

    # Deep external recon: prefer real tools, fall back to pure Python, dedup.
    try:
        from hackit.agent import external_tools as _ext

        _emit_progress("recon", "external recon starting")
        extra = _ext.aggregate_recon(host or target, base_url)
        _emit_progress("recon", f"external recon done: {len(extra.get('subdomains', []))} subs, {len(extra.get('ports', []))} ports")
        # Merge subdomains (dedup)
        existing_subs = scan_data.get("subdomains")
        if not isinstance(existing_subs, list):
            existing_subs = []
        merged_subs = _ext._dedup_str(list(existing_subs) + list(extra.get("subdomains", [])))
        scan_data["subdomains"] = merged_subs
        # Merge ports (dedup by port number)
        existing_ports = scan_data.get("ports")
        if not isinstance(existing_ports, list):
            existing_ports = []
        port_seen = set()
        merged_ports = []
        for item in list(existing_ports) + list(extra.get("ports", [])):
            if not isinstance(item, dict):
                continue
            port = item.get("port")
            if port in port_seen:
                continue
            port_seen.add(port)
            merged_ports.append(item)
        if merged_ports:
            scan_data["ports"] = merged_ports
        scan_data["external_http"] = extra.get("http_probe", [])
        scan_data["external_endpoints"] = extra.get("endpoints", [])
        scan_data["external_tools"] = extra.get("tools", {})
    except Exception as exc:  # noqa: BLE001 - recon must never abort the pipeline
        scan_data["external_recon_error"] = str(exc)[:300]

    # Asset inventory -> surface every discovered subdomain/port/endpoint as
    # informational findings so the report reflects the full attack surface.
    try:
        for sub in _as_list(scan_data.get("subdomains"))[:200]:
            _finding(
                findings, "asset_discovery", str(sub),
                f"Subdomain discovered: {sub}",
                f"DNS resolution succeeded for {sub}",
                severity="info", cvss=0.0,
                remediation="Review whether this host should be publicly exposed",
            )
        for port_entry in _as_list(scan_data.get("ports"))[:100]:
            if not isinstance(port_entry, dict):
                continue
            port_num = port_entry.get("port", port_entry.get("Port"))
            if port_num is None:
                continue
            _finding(
                findings, "open_port", f"{host}:{port_num}",
                f"Open port {port_num}/tcp detected",
                f"Service: {port_entry.get('service', '')} {port_entry.get('version', '')}".strip(),
                severity="info", cvss=0.0,
                remediation="Close unused ports or restrict access",
            )
        for url in _as_list(scan_data.get("external_endpoints"))[:100]:
            _finding(
                findings, "endpoint_discovered", str(url),
                f"Endpoint discovered: {str(url)[:120]}",
                f"Reached during link/JS crawl",
                severity="info", cvss=0.0,
                remediation="Review endpoint exposure and access control",
            )
    except Exception:
        pass

    # Passive header / configuration analysis -> low-hanging findings.
    try:
        _emit_progress("recon", "header analysis starting")
        from hackit.agent import external_tools as _ext2

        _security_headers = {
            "strict-transport-security": "Missing HSTS header",
            "content-security-policy": "Missing Content-Security-Policy header",
            "x-frame-options": "Missing X-Frame-Options (clickjacking risk)",
            "x-content-type-options": "Missing X-Content-Type-Options (MIME sniffing)",
            "referrer-policy": "Missing Referrer-Policy header",
            "permissions-policy": "Missing Permissions-Policy header",
        }
        urls_to_check = [base_url] + [r.get("url") for r in _as_list(scan_data.get("external_http")) if isinstance(r, dict) and r.get("url")]
        seen_urls = set()
        for url in urls_to_check:
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            if len(seen_urls) > 80:
                break
            headers = {}
            try:
                import urllib.request
                req = urllib.request.Request(url, method="HEAD")
                req.add_header("User-Agent", "HackIt-Recon/1.0")
                with urllib.request.urlopen(req, timeout=6) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except Exception:
                try:
                    import urllib.request
                    req = urllib.request.Request(url, method="GET")
                    req.add_header("User-Agent", "HackIt-Recon/1.0")
                    with urllib.request.urlopen(req, timeout=6) as resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                except Exception:
                    continue
            # Missing security headers
            for hdr, msg in _security_headers.items():
                if hdr not in headers:
                    _finding(
                        findings, "misconfig", url,
                        msg, f"Response from {url} did not include {hdr}",
                        severity="low", cvss=3.1,
                        remediation=f"Add the {hdr} response header",
                    )
            # Server version disclosure
            server = headers.get("server", "")
            if server and any(ch.isdigit() for ch in server):
                _finding(
                    findings, "info_disclosure", url,
                    "Server version disclosed",
                    f"Server header: {server}",
                    severity="info", cvss=2.0,
                    remediation="Hide or genericise the Server header",
                )
            # CORS wildcard
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*":
                _finding(
                    findings, "cors", url,
                    "CORS allows any origin (*)",
                    f"Access-Control-Allow-Origin: {acao}",
                    severity="medium", cvss=5.0,
                    remediation="Restrict CORS to trusted origins",
                )
            # Cache-control on sensitive
            if "cache-control" not in headers and any(k in url.lower() for k in ("login", "admin", "api", "account")):
                _finding(
                    findings, "misconfig", url,
                    "Missing Cache-Control on sensitive endpoint",
                    f"No Cache-Control header on {url}",
                    severity="low", cvss=3.0,
                    remediation="Add Cache-Control: no-store on sensitive responses",
                )
    except Exception as exc:  # noqa: BLE001
        scan_data["header_analysis_error"] = str(exc)[:300]


    has_web = _target_has_web({**state, "scan_data": scan_data})
    scan_data["web_url"] = base_url
    scan_data["host"] = host
    scan_data["scheme"] = scheme
    scan_data["port"] = port
    scan_data["has_web"] = has_web

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
            # The pipeline must never park on a slow model: curated payloads
            # are already loaded, so a short AI budget degrades cleanly.
            timeout=45,
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
    endpoints = _endpoint_candidates(state, base_url, limit=30)
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
    analysis = bridge.ai_chat(prompt, mode="analyze", timeout=90)
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
    plan = bridge.ai_chat(prompt, mode="attack", timeout=90)
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


# Native modules that can emit reflection false positives (for example a JSON
# API echoing the payload).  Their reports are re-checked with the differential
# prober before they become findings.
MODULE_PROBE_TYPES = {
    "xss": "xss",
    "ssrf": "ssrf",
    "ssti": "ssti",
    "lfi": "lfi",
    "sqli": "sqli",
    "cmd": "cmdi",
    "redirect": "open_redirect",
    "xxe": "xxe",
    "nosqli": "nosqli",
    "ldap": "ldap",
}


def _first_query_parameter(url: str) -> str:
    try:
        query = parse_qs(urlparse(str(url or "")).query, keep_blank_values=True)
    except ValueError:
        return ""
    return next(iter(query), "")


def _finding_identity(item: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Collapse duplicate evidence for the same class/path/parameter."""
    parsed = urlparse(str(item.get("target") or ""))
    evidence = str(item.get("evidence") or "")
    match = re.search(r"parameter=([^,\s)]+)", evidence)
    parameter = match.group(1) if match else ""
    return (
        str(item.get("type") or ""),
        parsed.netloc.lower(),
        parsed.path or "/",
        parameter,
    )


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in findings:
        key = _finding_identity(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _process_module_results(findings, find_count, bridge, target, target_url, module,
                            ftype, severity, cvss, remediation):
    result = bridge.run_worker(**{module: target_url})
    data = _module_payload(result)
    items = [item for item in _as_list(data) if isinstance(item, dict)]
    error = ""
    if result and isinstance(result[0], dict) and result[0].get("success") is False:
        error = str(result[0].get("error") or "module failed")[:300]

    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for item in items:
        if not _is_module_finding(module, item):
            continue
        endpoint = str(item.get("endpoint") or target_url)
        parameter = str(item.get("parameter") or _first_query_parameter(endpoint))
        groups.setdefault((endpoint, parameter), []).append(item)

    found = 0
    unverified = 0
    probe_type = MODULE_PROBE_TYPES.get(module)
    for (endpoint, parameter), group in groups.items():
        selected = group[0]
        probe_result: Dict[str, Any] = {}
        if probe_type:
            # Reflection inside JSON/plain text is not executable XSS, and a
            # payload echoed back is not proof of SSTI/LFI/SSRF.  Re-run the
            # candidate through the baseline-differential prober.
            confirmed = None
            try:
                from hackit.agent import payloads as forge

                for candidate in group[:3]:
                    payload = str(candidate.get("payload") or "")
                    if not payload:
                        continue
                    result_item = forge.probe(
                        endpoint, probe_type, payload,
                        parameter=parameter, timeout=8.0,
                    )
                    if result_item.get("vulnerable"):
                        confirmed = (candidate, result_item)
                        break
            except Exception as exc:  # noqa: BLE001
                error = error or f"verification failed: {exc}"[:300]
            if confirmed is None:
                unverified += 1
                continue
            selected, probe_result = confirmed
            evidence = (
                f"{probe_result.get('evidence', '')} "
                f"(parameter={probe_result.get('parameter', '')}, "
                f"payload={str(probe_result.get('payload', ''))[:200]})"
            ).strip()
        else:
            evidence = str(selected.get("evidence") or selected.get("Evidence") or selected)

        _finding(
            findings, ftype, endpoint,
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
        "unverified": unverified,
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

    def add_ext(value: Any) -> None:
        value = str(value or "").strip()
        if not value or not value.startswith(("http://", "https://")):
            return
        candidate = urlparse(value)
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
    # External recon endpoints (subdomains, probed URLs)
    for url in _as_list(scan_data.get("external_endpoints")):
        add_ext(url)
    for item in _as_list(scan_data.get("external_http")):
        if isinstance(item, dict) and item.get("url"):
            add_ext(item.get("url"))
        elif isinstance(item, str):
            add_ext(item)
    # Increase default coverage
    return candidates[: max(limit, 12)]


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
    injection_modules = {
        "sqli", "xss", "ssrf", "redirect", "lfi", "ssti", "cmd",
        "nosqli", "ldap", "xxe",
    }
    path_modules = {"lfi", "bypass403", "xss", "redirect", "cors", "csrf", "graphql"}

    # Exercise parameters on every discovered endpoint, not just the base
    # URL.  The endpoint's own query names drive the module choice.
    parameter_targets: List[str] = []
    seen_parameter_targets = set()
    for endpoint in endpoints:
        for target_url in _parameter_targets(endpoint, parameter_names, limit=3):
            if target_url in seen_parameter_targets:
                continue
            seen_parameter_targets.add(target_url)
            parameter_targets.append(target_url)
            if len(parameter_targets) >= 10:
                break
        if len(parameter_targets) >= 10:
            break

    # The base URL gets every module.  Parameter URLs get only the modules
    # that can exercise their names, so the run is deeper without blindly
    # multiplying every scanner.
    tasks: List[Tuple[Tuple[Any, ...], str]] = []
    seen_tasks = set()

    def add_task(config: Tuple[Any, ...], target_url: str) -> None:
        key = (config[0], target_url)
        if key in seen_tasks:
            return
        seen_tasks.add(key)
        tasks.append((config, target_url))

    for config in module_configs:
        add_task(config, base_url)
    for target_url in parameter_targets:
        names = list(parse_qs(urlparse(target_url).query))
        relevant: set = set()
        for name in names:
            relevant.update(_modules_for_parameter(name))
        if not relevant:
            relevant = set(injection_modules)
        for config in module_configs:
            if config[0] in relevant:
                add_task(config, target_url)
    for endpoint in endpoints[1:]:
        relevant = injection_modules if urlparse(endpoint).query else path_modules
        for config in module_configs:
            if config[0] in relevant:
                add_task(config, endpoint)

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
            "unverified": item.get("unverified", 0),
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
    coverage["execute_unverified"] = sum(
        int(item.get("unverified", 0)) for item in module_results if isinstance(item, dict)
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
    updates["findings"] = _dedupe_findings(findings)
    updates["scan_data"] = scan_data
    updates["coverage"] = coverage
    updates["attack_log"] = attack_log
    persist_state(dict(state, **updates), suffix="_execute")
    return updates


# ---------------------------------------------------------------------------
# Phase 9: AI payload verification
# ---------------------------------------------------------------------------


PREFERRED_PARAMS: Dict[str, List[str]] = {
    "sqli": ["id", "q", "query", "search", "user", "username", "email", "name"],
    "nosqli": ["id", "q", "query", "user", "username", "filter", "search"],
    "xss": ["q", "s", "search", "query", "name", "message", "comment", "callback"],
    "open_redirect": [
        "url", "redirect", "next", "return", "returnurl", "return_url",
        "dest", "destination", "target", "continue", "callback",
    ],
    "ssrf": [
        "url", "uri", "src", "source", "dest", "destination", "target",
        "host", "site", "callback", "webhook",
    ],
    "lfi": ["file", "path", "page", "include", "template", "view", "download", "filename"],
    "ssti": ["name", "template", "q", "message", "content", "page"],
    "cmdi": ["cmd", "command", "exec", "ping", "host", "ip", "query", "q"],
    "xxe": ["xml", "data", "body", "content"],
    "ldap": ["user", "username", "filter", "search", "q"],
}


def _param_order(vuln_type: str, params: List[str]) -> List[str]:
    """Put the most relevant parameter names for this payload class first."""
    preferred = PREFERRED_PARAMS.get(str(vuln_type or "").lower(), [])
    ordered = [name for name in preferred if name in params]
    ordered.extend(name for name in params if name not in ordered)
    return ordered or ["url"]


PARAMETER_MODULES: Dict[str, List[str]] = {
    "url": ["ssrf", "redirect"],
    "uri": ["ssrf", "redirect"],
    "src": ["ssrf"],
    "source": ["ssrf", "lfi"],
    "dest": ["ssrf", "redirect"],
    "destination": ["ssrf", "redirect"],
    "redirect": ["redirect"],
    "next": ["redirect"],
    "return": ["redirect"],
    "returnurl": ["redirect"],
    "return_url": ["redirect"],
    "continue": ["redirect"],
    "id": ["sqli", "nosqli", "xss"],
    "q": ["xss", "ssti", "sqli"],
    "s": ["xss"],
    "search": ["xss", "sqli"],
    "query": ["sqli", "xss"],
    "name": ["xss", "ssti"],
    "message": ["xss", "ssti"],
    "comment": ["xss"],
    "callback": ["xss", "ssrf"],
    "file": ["lfi"],
    "filename": ["lfi"],
    "path": ["lfi"],
    "page": ["lfi", "xss"],
    "include": ["lfi"],
    "template": ["ssti", "lfi"],
    "view": ["lfi"],
    "download": ["lfi"],
    "cmd": ["cmd"],
    "command": ["cmd"],
    "exec": ["cmd"],
    "ping": ["cmd"],
    "host": ["cmd", "ssrf"],
    "ip": ["cmd", "ssrf"],
    "filter": ["nosqli", "ldap"],
    "user": ["sqli", "ldap"],
    "username": ["sqli", "ldap"],
    "xml": ["xxe"],
    "data": ["xxe"],
    "body": ["xxe"],
}

DEFAULT_PARAMETER_MODULES = [
    "sqli", "xss", "ssrf", "redirect", "lfi", "ssti", "cmd", "nosqli",
]


def _modules_for_parameter(name: str) -> List[str]:
    """Pick the modules that can actually exercise a parameter name."""
    return PARAMETER_MODULES.get(str(name or "").lower(), DEFAULT_PARAMETER_MODULES)


def _ordered_probe_targets(vuln_type: str, targets: List[str]) -> List[str]:
    """Put endpoints whose path/query matches the payload class first."""
    hints = {
        "open_redirect": ("redirect", "url", "next", "return", "continue", "dest", "target"),
        "ssrf": ("url", "uri", "src", "dest", "target", "host", "callback"),
        "lfi": ("file", "path", "page", "include", "download", "view"),
        "ssti": ("template", "name", "page"),
        "sqli": ("id", "q", "query", "search"),
        "xss": ("q", "s", "search", "query", "name"),
        "cmdi": ("cmd", "command", "exec", "ping", "host"),
        "xxe": ("xml", "data", "body"),
        "nosqli": ("id", "q", "query", "filter"),
        "ldap": ("user", "username", "filter", "search"),
    }.get(str(vuln_type or "").lower(), ())

    if not hints:
        return list(targets)

    def score(value: str) -> int:
        parsed = urlparse(value)
        query_keys = {key.lower() for key in parse_qs(parsed.query)}
        path = parsed.path.lower()
        for hint in hints:
            if hint in query_keys:
                return 0
            if len(hint) > 1 and hint in path:
                return 0
        return 1

    return sorted(targets, key=score)


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

    # Concrete parameters observed in the target and discovered URLs come
    # first; the generic param-module wordlist follows.  This keeps a long
    # generic list from hiding a real parameter such as ``url``.
    target = state.get("target", "")
    if "?" in target:
        for key in parse_qs(urlparse(target).query):
            if key not in names:
                names.append(key)
    base_url = (state.get("scan_data") or {}).get("web_url") or _target_parts(state)[3]
    for endpoint in _endpoint_candidates(state, base_url, limit=12):
        for key in parse_qs(urlparse(endpoint).query):
            if key not in names:
                names.append(key)
    collect(params)
    return names[:16]


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
    probe_targets = _endpoint_candidates(state, base_url, limit=8) or [base_url]
    probe_results: List[Dict[str, Any]] = []
    attack_log = list(state.get("attack_log") or [])
    coverage = dict(state.get("coverage") or {})
    attempted_types: List[str] = []
    signal_keys = set()

    try:
        from hackit.agent import payloads as forge

        try:
            budget = max(8, int(os.environ.get("HACKIT_PROBE_BUDGET", "60")))
        except ValueError:
            budget = 60

        type_payloads: List[Tuple[str, List[str]]] = []
        for vuln_type, data in results.items():
            items = data.get("payloads", []) if isinstance(data, dict) else []
            selected = [item.get("payload") for item in items[:3] if item.get("payload")]
            if selected:
                type_payloads.append((vuln_type, selected))

        # Breadth first: every payload class gets a fair share of the budget,
        # and each round reaches all discovered targets/parameters before a
        # second payload is tried.  A small budget must not starve later
        # classes just because the first one was listed first.
        for index, (vuln_type, selected) in enumerate(type_payloads):
            if budget <= 0:
                break
            remaining_types = len(type_payloads) - index
            type_budget = max(1, budget // remaining_types)
            ordered_params = _param_order(vuln_type, params)[:3]
            type_targets = _ordered_probe_targets(vuln_type, probe_targets)
            jobs: List[Tuple[str, str, str]] = []
            for payload in selected:
                for target_url in type_targets:
                    # Prefer the parameter that the endpoint actually
                    # exposes (``/item?id=1`` -> id, ``/redirect?url=...``
                    # -> url) before falling back to the global order.
                    target_params: List[str] = []
                    for name in parse_qs(urlparse(target_url).query):
                        if name not in target_params:
                            target_params.append(name)
                    for name in ordered_params:
                        if name not in target_params:
                            target_params.append(name)
                    for parameter in target_params[:3]:
                        jobs.append((target_url, parameter, payload))
            used = 0
            for target_url, parameter, payload in jobs:
                if used >= type_budget or budget <= 0:
                    break
                batch = forge.probe_many(
                    target_url, vuln_type, [payload], parameter=parameter,
                    timeout=8.0, delay=0.1,
                )
                used += len(batch)
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
                    signal_keys.add((vuln_type, urlparse(target_url).path, parameter))
                    _finding(
                        findings, vuln_type, item.get("target", target_url),
                        f"{vuln_type} payload produced a differential signal",
                        f"parameter={parameter} payload={item.get('payload')} "
                        f"evidence={item.get('evidence')}",
                        severity=SEVERITY_BY_TYPE.get(vuln_type, ("high", 7.0, ""))[0],
                        cvss=SEVERITY_BY_TYPE.get(vuln_type, ("high", 7.0, ""))[1],
                    )
            if used:
                attempted_types.append(vuln_type)
    except Exception as exc:  # noqa: BLE001
        scan_data["payload_probe_error"] = str(exc)[:500]

    signals = len(signal_keys)
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
    updates["findings"] = _dedupe_findings(findings)
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
    correlation = bridge.ai_chat(prompt, mode="correlate", timeout=90)
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
        f"Module reports rejected as reflection-only: {coverage.get('execute_unverified', 0)}",
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
            if entry.get("vulnerable"):
                result_text = f"vulnerable: {entry.get('evidence', '')}"
            elif entry.get("action") == "payload":
                result_text = "no differential signal"
            else:
                result_text = (
                    f"{entry.get('tested', 0)} tested / "
                    f"{entry.get('findings', 0)} finding(s)"
                )
                if entry.get("unverified"):
                    result_text += f" / {entry.get('unverified')} reflection-only rejected"
            lines.append(
                f"| {entry.get('phase', '')} | {entry.get('action', '')} | "
                f"{entry.get('module', '')} | {str(entry.get('target', ''))[:100]} | "
                f"{str(result_text)[:160].replace('|', '\\\\|')} |"
            )
        lines.append("")

    ext_tools = scan_data.get("external_tools") or {}
    ext_subs = _as_list(scan_data.get("subdomains"))
    ext_ports = _as_list(scan_data.get("ports"))
    ext_http = _as_list(scan_data.get("external_http"))
    ext_eps = _as_list(scan_data.get("external_endpoints"))
    lines.extend(["## Reconnaissance Summary", ""])
    lines.append(f"- Subdomains discovered: {len(ext_subs)}")
    lines.append(f"- Open ports: {len(ext_ports)}")
    lines.append(f"- HTTP endpoints probed: {len(ext_http)}")
    lines.append(f"- Unique endpoints: {len(ext_eps)}")
    if ext_tools:
        lines.append(f"- External tools available: {', '.join(sorted(ext_tools))}")
    if ext_subs:
        lines.append(f"- Sample subdomains: {', '.join(ext_subs[:15])}")
    if ext_ports:
        port_list = ", ".join(str(p.get('port', p.get('Port', '?'))) for p in ext_ports[:25] if isinstance(p, dict))
        lines.append(f"- Open ports: {port_list}")
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

        # Bug-bounty-style proof of concept per finding.
        lines.extend(["## Proof of Concept", ""])
        for idx, item in enumerate(ranked, 1):
            title = str(item.get("title", item.get("type", "finding")))
            target_value = str(item.get("target", target))
            evidence = str(item.get("evidence", ""))
            lines.append(f"### PoC #{idx} — {title}")
            lines.append("")
            lines.append(f"- **Target:** `{target_value}`")
            lines.append(f"- **Severity:** {str(item.get('severity', 'info')).title()} "
                         f"(CVSS {item.get('cvss', '—')})")
            lines.append("- **Reproduction steps:**")
            lines.append("  1. Send the request below to the target.")
            lines.append("  2. Observe the response/evidence noted.")
            lines.append("  3. Confirm the behaviour is reproducible.")
            if evidence:
                lines.append("")
                lines.append("  **Evidence:**")
                lines.append("  ```")
                lines.append("  " + evidence[:600].replace("\n", "\n  "))
                lines.append("  ```")
            remediation = str(item.get("remediation", "")).strip()
            if remediation:
                lines.append(f"- **Remediation:** {remediation}")
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

Cover the most important evidence, business impact, a short reproduction/PoC for each confirmed finding, and the next action. Format like a real bug-bounty report.
The Findings list and verified probe hits are the ONLY evidence.
If both verified counts are zero, state that no vulnerability was confirmed,
do not assign a nonzero risk score, and never call a hypothesis confirmed.
Otherwise only claim what the evidence supports; mark hypotheses as hypotheses.
Be concise: answer in at most 150 words.
"""
    report = bridge.ai_chat(prompt, mode="report", timeout=90)
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
