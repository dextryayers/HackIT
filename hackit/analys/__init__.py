"""HackIT analys — zero-flag deep analysis for files and targets.

One command, no long flags: ``hackit analys <target>``

  * target is a file  → full native malware triage (Rust malwscan + C fastscan),
    hidden-malware detection (embedded PE, packers, NOP sleds, W+X sections),
    IOC mining and an AI verdict when a model is configured.
  * target is a host  → fast autonomous assessment: recon, port sweep, tech
    fingerprinting, vulnerability probes and an AI assessment. A report is
    always written to reports/analys/.

Interactive prompt when invoked bare: ``hackit analys``
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import click

from hackit.ui import _colored, B_CYAN, B_GREEN, B_RED, B_WHITE, B_YELLOW, DIM, GREEN, RED, YELLOW
from hackit.malware.engine import analyze as _malware_analyze, engine_available, EngineError
from hackit.malware import _render, VERDICT_STYLE

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", "analys")


def _is_file_target(target: str) -> bool:
    return os.path.isfile(target)


def _slug(target: str) -> str:
    safe = target.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_")
    for ch in ':*"<>|':
        safe = safe.replace(ch, "_")
    return safe[:80]


def _ai_verdict(context: str) -> str:
    try:
        from hackit.agent.brain import AIHyperBrain
        brain = AIHyperBrain(engine="native", enable_memory=False, announce=False)
        answer = brain.chat(
            "You are a malware triage analyst. Analyze this triage output and give:\n"
            "1) a one-line verdict, 2) what the sample does, 3) concrete IOCs to pivot on, "
            "4) confidence. Be precise and professional. Do not hedge with disclaimers.\n\n"
            + context[:3500]
        )
        return answer.strip() if isinstance(answer, str) else ""
    except Exception as exc:
        return f"(AI verdict unavailable: {exc})"


def _file_mode(target: str, pure: bool) -> int:
    click.echo(_colored("\n  [ ANALYS ] malware triage — native Rust engine + C fastscan", B_CYAN, bold=True))
    click.echo(_colored(f"  target   {target}", DIM))
    try:
        results = _malware_analyze([target])
    except EngineError as exc:
        click.echo(_colored(f"  [!] {exc}", RED), err=True)
        return 2
    entry = results[0] if results else {"file": target, "error": "no result"}
    _render(entry)

    if not pure and not entry.get("error"):
        click.echo(_colored("\n  [ AI VERDICT ]", B_CYAN))
        ai = _ai_verdict(json.dumps(entry, ensure_ascii=False, default=str))
        for line in (ai or "").splitlines():
            click.echo(f"  {line}")

    verdict = str(entry.get("verdict") or "unknown")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"analys_malware_{_slug(os.path.basename(target))}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(entry, fh, indent=2, ensure_ascii=False)
    click.echo(_colored(f"\n  [ report ] {path}", B_GREEN))
    return {"malicious": 1, "suspicious": 1}.get(verdict, 0)


def _host_mode(target: str, pure: bool) -> int:
    """TOTAL deep scan — seven stages, everything automatic, one shot."""
    host = urlparse(target).hostname or target.split("/")[0]
    raw_base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    base = raw_base
    if not target.startswith(("http://", "https://")):
        import socket

        def _port_open(port: int) -> bool:
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    return True
            except OSError:
                return False

        if _port_open(443):
            base = f"https://{target}"
        elif _port_open(80):
            base = f"http://{target}"
    click.echo(_colored("\n  [ ANALYS ] TOTAL DEEP SCAN — full pipeline, target only", B_CYAN, bold=True))
    click.echo(_colored(f"  target   {base}", DIM))
    click.echo(_colored("  stages   recon → ports(top1000) → headers → JS hunt → probes → backend malware → AI assessment", DIM))

    from hackit.agent.external_tools import aggregate_recon
    from hackit.port_scanner.engine_orchestrator import PortOrchestrator
    from hackit.port_scanner.engine_profiles import get_profile

    report: dict = {"target": base, "mode": "host", "started": datetime.now().isoformat()}

    # ── 1. Reconnaissance ───────────────────────────────────────
    click.echo(_colored("\n  [1/7] Reconnaissance…", B_CYAN))
    recon = aggregate_recon(host, base)
    subs = recon.get("subdomains", [])
    eps = recon.get("endpoints", [])
    tech = recon.get("tech", {}) or {}
    click.echo(f"  subdomains   {len(subs)}")
    click.echo(f"  endpoints    {len(eps)}")
    if tech:
        click.echo(f"  tech         {json.dumps(tech)[:140]}")
    report["recon"] = {"subdomains": subs[:50], "endpoints": eps[:50], "tech": tech}

    # ── 2. Port sweep — top1000, quick profile ──────────────────
    click.echo(_colored("\n  [2/7] Port sweep — top1000, quick profile…", B_CYAN))
    try:
        orch = PortOrchestrator()
        profile = get_profile("quick")
        result = orch.run_scan(host, "top1000", profile, engines=["go"], stages=["tcp_scan", "service_detect"], options={})
        open_ports = [p for p in (result or {}).get("results", []) if str(p.get("status")).lower() == "open"]
        for p in open_ports:
            click.echo(f"  open       {p.get('port')}/tcp  {p.get('service')}  {str(p.get('banner') or '')[:60]}")
        click.echo(f"  open ports   {len(open_ports)} (top1000 scanned)")
        report["ports"] = open_ports
    except Exception as exc:
        click.echo(_colored(f"  [!] port sweep failed: {exc}", YELLOW))
        report["ports_error"] = str(exc)

    # ── 3. Security headers audit ───────────────────────────────
    click.echo(_colored("\n  [3/7] Security headers audit…", B_CYAN))
    header_findings = []
    try:
        import httpx
        client = httpx.Client(timeout=8.0, follow_redirects=True, verify=False)
        resp = client.get(base)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        checks = [
            ("content-security-policy", "CSP", True),
            ("strict-transport-security", "HSTS", True),
            ("x-frame-options", "X-Frame-Options", True),
            ("x-content-type-options", "X-Content-Type-Options", True),
            ("referrer-policy", "Referrer-Policy", True),
            ("permissions-policy", "Permissions-Policy", True),
            ("x-xss-protection", "X-XSS-Protection", False),
        ]
        passed = 0
        for name, label, required in checks:
            if name in headers:
                passed += 1
                click.echo(f"  [pass] {label}")
            else:
                header_findings.append({"header": label, "issue": "missing", "severity": "medium" if required else "low"})
                click.echo(_colored(f"  [FAIL] {label} missing", YELLOW))
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server:
            click.echo(f"  [info] server: {server}")
        if powered:
            click.echo(f"  [info] x-powered-by: {powered}")
        grade = "A" if passed == len(checks) else ("B" if passed >= 5 else ("C" if passed >= 3 else "D"))
        click.echo(_colored(f"  headers grade  {grade}  ({passed}/{len(checks)} hardening headers present)", B_GREEN if grade in ("A", "B") else B_YELLOW))
        report["headers"] = {"grade": grade, "passed": passed, "missing": header_findings, "server": server, "powered_by": powered}
        client.close()
    except Exception as exc:
        click.echo(_colored(f"  [!] headers audit failed: {exc}", YELLOW))
        report["headers_error"] = str(exc)

    # ── 4. JavaScript & secrets hunt ────────────────────────────
    click.echo(_colored("\n  [4/7] JavaScript & secrets hunt…", B_CYAN))
    js_report: dict = {"scripts": 0, "endpoints": [], "secrets": []}
    try:
        import re
        import httpx
        client = httpx.Client(timeout=8.0, follow_redirects=True, verify=False)
        base_resp = client.get(base)
        html = base_resp.text[:50000]
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)[:8]
        endpoint_re = re.compile(r"['\"](/(?:api|v1|v2|graphql|gql|rest|internal|admin|auth)[a-zA-Z0-9_\-/{}.:]{2,120})['\"]")
        secret_re = re.compile(r"(?i)(api[-_]?key|secret|token|password|passwd|auth[-_]?token)['\"\s]*[:=]['\"\s]*([A-Za-z0-9_\-\.=]{8,80})")
        found_endpoints: list = []
        found_secrets: list = []
        for src_attr in script_srcs:
            url = src_attr if src_attr.startswith(("http://", "https://")) else base.rstrip("/") + "/" + src_attr.lstrip("/")
            try:
                js_resp = client.get(url)
            except Exception:
                continue
            body = js_resp.text[:80000]
            js_report["scripts"] += 1
            for m in endpoint_re.findall(body):
                if m not in found_endpoints:
                    found_endpoints.append(m)
            for m in secret_re.finditer(body):
                found_secrets.append({"kind": m.group(1).lower(), "sample": m.group(2)[:24] + "…"})
        # also scan the main page itself
        for m in endpoint_re.findall(html):
            if m not in found_endpoints:
                found_endpoints.append(m)
        js_report["endpoints"] = found_endpoints[:20]
        js_report["secrets"] = found_secrets[:10]
        click.echo(f"  scripts fetched   {js_report['scripts']}")
        click.echo(f"  endpoints found   {len(found_endpoints)}")
        for ep in found_endpoints[:6]:
            click.echo(f"    endpoint    {ep}")
        if found_secrets:
            click.echo(_colored(f"  [WARN] {len(found_secrets)} secret-like token(s) in client-side code — review before exposure", B_YELLOW))
        report["js"] = js_report
        client.close()
    except Exception as exc:
        click.echo(_colored(f"  [!] JS hunt failed: {exc}", YELLOW))
        report["js_error"] = str(exc)

    # ── 5. Vulnerability probes — deep ───────────────────────────
    click.echo(_colored("\n  [5/7] Vulnerability probes — deep matrix…", B_CYAN))
    try:
        from hackit.agent.payloads import CATALOG, probe_many
        catalog = CATALOG or {}
        probe_classes = ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi"]
        findings = []
        params = ["q", "id", "url", "page", "search", "file", "path", "redirect"]
        for cls in probe_classes:
            payloads = [str(p.get("payload", p)) if isinstance(p, dict) else str(p) for p in (catalog.get(cls) or [])[:12]]
            if not payloads:
                continue
            for param in params[:4]:
                rows = probe_many(base, cls, payloads, parameter=param, method="GET", timeout=6.0, delay=0.08)
                hits = [r for r in rows if r.get("vulnerable")]
                for hit in hits:
                    findings.append({"vuln_type": cls, "parameter": param, "payload": hit.get("payload"),
                                     "evidence": str(hit.get("evidence"))[:200],
                                     "severity": "critical" if cls in ("sqli", "cmdi", "ssti", "lfi") else "high"})
        for f in findings:
            click.echo(_colored(f"  [HIGH] {f['vuln_type']} param={f['parameter']}", B_RED, bold=True))
        if not findings:
            click.echo(_colored("  no reflected/error-based findings confirmed (passive baseline clean)", DIM))
        else:
            report.setdefault("findings", []).extend(findings)
        report.setdefault("findings", findings)
    except Exception as exc:
        click.echo(_colored(f"  [!] probe stage error: {exc}", YELLOW))
        report["findings_error"] = str(exc)

    # ── 6. Backend malware sweep — webshell & dropper hunt ───────
    click.echo(_colored("\n  [6/7] Backend malware sweep — webshell & dropper hunt…", B_CYAN))
    webshell_paths = [
        "/", "/info.php", "/shell.php", "/c99.php", "/r57.php", "/uploads/shell.php",
        "/images/shell.php", "/wp-content/uploads/shell.php", "/admin/shell.php",
        "/backup/shell.php", "/assets/shell.php", "/.hidden/shell.php", "/test.php",
    ]
    markers = (
        "eval(base64_decode", "eval(gzinflate", "c99shell", "r57shell",
        "filesman", "<?system", "@eval($", "gzuncompress(base64_decode",
        "passthru($_", "assert($_POST", "shell_exec($_", "FilesMan v",
    )
    backend_hits = []
    try:
        import httpx
        client = httpx.Client(timeout=6.0, follow_redirects=True, verify=False)
        for wp in webshell_paths:
            try:
                resp = client.get(base.rstrip("/") + wp)
            except Exception:
                continue
            body = resp.text[:20000] if resp.text else ""
            found_markers = [m for m in markers if m.lower() in body.lower()]
            if found_markers or (resp.status_code == 200 and ".php" in wp and len(body) > 0 and "php" in resp.headers.get("content-type", "").lower() and ("<?php" in body[:200])):
                backend_hits.append({"path": wp, "markers": found_markers, "status": resp.status_code})
        client.close()
    except Exception as exc:
        click.echo(_colored(f"  [!] backend sweep error: {exc}", YELLOW))
    for hit in backend_hits:
        click.echo(_colored(f"  [CRITICAL] webshell indicator at {base.rstrip('/')}{hit['path']}  markers={','.join(hit['markers']) or 'php script exposed'}", B_RED, bold=True))
    if backend_hits:
        report.setdefault("findings", []).extend([
            {"vuln_type": "webshell", "target": base.rstrip("/") + h["path"], "parameter": "", "payload": None,
             "evidence": f"webshell marker(s): {','.join(h['markers']) or 'php exposed'}", "severity": "critical"}
            for h in backend_hits
        ])
    else:
        click.echo(_colored("  backend clean — no webshell/dropper markers on checked paths", DIM))

    # ── 7. AI assessment — the full picture ──────────────────────
    if not pure:
        click.echo(_colored("\n  [7/7] AI assessment — total picture…", B_CYAN))
        ai = _ai_verdict(json.dumps(report, default=str)[:4000])
        for line in (ai or "").splitlines():
            click.echo(f"  {line}")
        report["ai_assessment"] = ai

    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"analys_total_{_slug(base)}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    findings = report.get("findings", [])
    click.echo(_colored(f"\n  [ report ] {path}", B_GREEN))
    click.echo(_colored(f"  TOTAL: {len(findings)} finding(s) · headers {report.get('headers', {}).get('grade', 'n/a')} · ports {len(report.get('ports', []))} open · js endpoints {len(js_report['endpoints']) if js_report else 0}", B_CYAN))
    return 0


@click.command()
@click.argument("target", required=False)
@click.option("--pure", is_flag=True, help="Skip the AI assessment (offline / no model configured)")
def analys(target: Optional[str], pure: bool):
    """Autonomous deep analysis — files (malware triage) or hosts (full sweep).

    No flags needed: give it a target, it figures out the rest.
    Omit the target and you will be prompted for it.
    """
    if not target:
        if not sys.stdin.isatty():
            target = input("  Input Target: ").strip()
        else:
            target = click.prompt(_colored("  Input Target", B_CYAN, bold=True), default="", show_default=False).strip()
    target = (target or "").strip()
    if not target or target.lower() in ("exit", "quit", "q"):
        click.echo(_colored("  [!] no target — nothing to analyse.", DIM))
        return
    if _is_file_target(target):
        sys.exit(_file_mode(os.path.abspath(target), pure))
    sys.exit(_host_mode(target, pure))
