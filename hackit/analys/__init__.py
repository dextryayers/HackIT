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
    """Fast autonomous assessment — recon, ports, tech, vulns. One shot, no flags."""
    host = urlparse(target).hostname or target.split("/")[0]
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    click.echo(_colored("\n  [ ANALYS ] autonomous deep assessment", B_CYAN, bold=True))
    click.echo(_colored(f"  target   {base}", DIM))
    click.echo(_colored("  engine   recon → ports → tech → vuln probes → AI assessment", DIM))

    from hackit.agent.external_tools import aggregate_recon
    from hackit.port_scanner.engine_orchestrator import PortOrchestrator
    from hackit.port_scanner.engine_profiles import get_profile

    report: dict = {"target": base, "mode": "host", "started": datetime.now().isoformat()}

    click.echo(_colored("\n  [1/4] Reconnaissance…", B_CYAN))
    recon = aggregate_recon(host, base)
    subs = recon.get("subdomains", [])
    eps = recon.get("endpoints", [])
    tech = recon.get("tech", {}) or {}
    click.echo(f"  subdomains   {len(subs)}")
    click.echo(f"  endpoints    {len(eps)}")
    if tech:
        click.echo(f"  tech         {json.dumps(tech)[:140]}")
    report["recon"] = {"subdomains": subs[:50], "endpoints": eps[:50], "tech": tech}

    click.echo(_colored("\n  [2/4] Port sweep (top100, quick profile)…", B_CYAN))
    try:
        orch = PortOrchestrator()
        profile = get_profile("quick")
        result = orch.run_scan(host, "top100", profile, engines=["go"], stages=["tcp_scan", "service_detect"], options={})
        open_ports = [p for p in (result or {}).get("results", []) if str(p.get("status")).lower() == "open"]
        for p in open_ports:
            click.echo(f"  open       {p.get('port')}/tcp  {p.get('service')}  {str(p.get('banner') or '')[:60]}")
        click.echo(f"  open ports   {len(open_ports)}")
        report["ports"] = open_ports
    except Exception as exc:
        click.echo(_colored(f"  [!] port sweep failed: {exc}", YELLOW))
        report["ports_error"] = str(exc)

    click.echo(_colored("\n  [3/4] Vulnerability probes…", B_CYAN))
    try:
        from hackit.agent.payloads import CATALOG, probe_many
        catalog = CATALOG or {}
        probe_classes = ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi"]
        findings = []
        params = ["q", "id", "url", "page", "search"]
        for cls in probe_classes[:4]:
            payloads = [str(p.get("payload", p)) if isinstance(p, dict) else str(p) for p in (catalog.get(cls) or [])[:3]]
            if not payloads:
                continue
            for param in params[:2]:
                rows = probe_many(base, cls, payloads, parameter=param, method="GET", timeout=6.0, delay=0.1)
                hits = [r for r in rows if r.get("vulnerable")]
                for hit in hits:
                    findings.append({"vuln_type": cls, "parameter": param, "payload": hit.get("payload"),
                                     "evidence": str(hit.get("evidence"))[:200]})
        for f in findings:
            click.echo(_colored(f"  [HIGH] {f['vuln_type']} param={f['parameter']}", B_RED, bold=True))
        if not findings:
            click.echo(_colored("  no reflected/error-based findings confirmed (passive baseline clean)", DIM))
        report["findings"] = findings
    except Exception as exc:
        click.echo(_colored(f"  [!] probe stage error: {exc}", YELLOW))
        report["findings_error"] = str(exc)

    if not pure:
        click.echo(_colored("\n  [4/4] AI assessment…", B_CYAN))
        ai = _ai_verdict(json.dumps(report, default=str)[:3500])
        for line in (ai or "").splitlines():
            click.echo(f"  {line}")
        report["ai_assessment"] = ai

    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"analys_host_{_slug(base)}_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    click.echo(_colored(f"\n  [ report ] {path}", B_GREEN))
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
