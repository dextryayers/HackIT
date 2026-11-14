"""hackit stress — authorized resilience testing console.

Measures how your own systems behave under load: HTTP(S) latency and
error rates (Go engine), TCP handshake and plain-HTTP throughput
(C engine). Every non-lab run requires a signed scope file and a matching
approval reference, enforces hard caps, and writes an audit record.

No spoofing, no amplification, no evasion, no persistence. If you do not
own the target or lack written permission, this tool is not for you.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import click

from hackit.stresslab import engines
from hackit.stresslab.scope import (
    HARD_MAX_DURATION_S,
    HARD_MAX_RPS,
    HARD_MAX_WORKERS,
    ScopeError,
    check_run,
    effective_limits,
    load_scope,
)

AUDIT_LOG = Path.home() / ".hackit" / "stresslab" / "audit.log"
AUDIT_MAX_BYTES = 5 * 1024 * 1024

LAB_MAX_RPS = 500
LAB_MAX_WORKERS = 16
LAB_MAX_DURATION_S = 60


def _audit(record: dict) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_MAX_BYTES:
            rotated = AUDIT_LOG.with_suffix(".1.log")
            rotated.write_bytes(AUDIT_LOG.read_bytes()[-AUDIT_MAX_BYTES // 2:])
            AUDIT_LOG.unlink()
        with AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise ScopeError(f"cannot write audit log {AUDIT_LOG}: {exc} — refusing to run unaudited") from exc


def _is_loopback(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_http_target(target: str):
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https"):
        raise ScopeError("http profile needs a full URL, e.g. https://staging.example.internal/health")
    if not parts.hostname:
        raise ScopeError("target URL has no hostname")
    return parts, parts.hostname


def _render_report(report: dict, effective: dict) -> None:
    lat = report.get("latency_ms") or {}
    engine = str(report.get("engine", "?")).upper()
    click.echo(f"  engine        {engine} ({report.get('mode', '?')})")
    click.echo(f"  target        {report.get('target', '?')}")
    click.echo(f"  duration      {float(report.get('duration_s', 0.0)):.1f}s   cap rps {effective['rps']}/s   workers {effective['workers']}")
    click.echo(f"  requests      {report.get('requests', 0)}   ok {report.get('ok', 0)}   errors {report.get('errors', 0)}")
    click.echo(f"  achieved rps  {float(report.get('achieved_rps', 0.0)):.1f}   error rate {float(report.get('error_rate', 0.0)) * 100:.2f}%")
    click.echo(f"  latency ms    p50 {lat.get('p50', 0):.1f}   p90 {lat.get('p90', 0):.1f}   p99 {lat.get('p99', 0):.1f}   max {lat.get('max', 0):.1f}")


def _write_report(path: str, report: dict, meta: dict) -> None:
    payload = {"meta": meta, "result": report}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    click.echo(f"  report        written to {path}")


@click.group()
def stress():
    """Authorized resilience testing for systems you own or may assess in writing.

    Requires a scope file (see scope.example.json) with approval_ref, an
    expiry date and an explicit target allowlist. Lab mode needs no scope but
    loopback-only. Every run is audit-logged.
    """


@stress.command()
def build():
    """Compile the Go and C engines."""
    for label, fn in (("go", engines.build_go), ("c", engines.build_c)):
        try:
            path = fn()
        except engines.EngineError as exc:
            click.echo(f"  [fail] {label}: {exc}", err=True)
            sys.exit(1)
        click.echo(f"  [ok]   {label}: {path}")


@stress.command()
@click.option("--scope", required=True, type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON).")
@click.option("--target", required=True, help="URL for http profile, bare host for tcp profile.")
@click.option("--approval", required=True, help="Approval reference; must match scope approval_ref.")
@click.option("--profile", type=click.Choice(["http", "tcp"]), default="http")
@click.option("--port", default=80, show_default=True, type=int, help="Port for the tcp profile.")
@click.option("--rps", default=50, show_default=True, type=int)
@click.option("--workers", default=10, show_default=True, type=int)
@click.option("--duration", default=10, show_default=True, type=int, help="Seconds, capped by scope and hard limit.")
def check(scope, target, approval, profile, port, rps, workers, duration):
    """Validate scope, target and approval without generating any load."""
    try:
        sc = load_scope(scope)
        host = _resolve_host(target, profile)
        check_run(sc, host, approval)
        limits = effective_limits(sc, rps, workers, duration)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)
    click.echo("  [ok] scope valid")
    click.echo(f"  operator      {sc.operator}")
    click.echo(f"  approval      {sc.approval_ref}   expires {sc.expires.isoformat()}")
    click.echo(f"  allowlist     {', '.join(sc.targets)}")
    click.echo(f"  effective     rps {limits.rps}/s   workers {limits.workers}   duration {limits.duration_s}s (requested {rps}/{workers}/{duration})")


@stress.command()
@click.option("--target", required=True, help="URL (http) or bare host (tcp).")
@click.option("--scope", required=True, type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON).")
@click.option("--approval", required=True, help="Approval reference; must match scope approval_ref.")
@click.option("--profile", type=click.Choice(["http", "tcp"]), default="http", show_default=True)
@click.option("--port", default=80, show_default=True, type=int, help="Port for the tcp profile.")
@click.option("--method", default="GET", show_default=True, help="HTTP method (http profile).")
@click.option("--path", default="/", show_default=True, help="HTTP path (c engine http mode).")
@click.option("--rps", default=50, show_default=True, type=int)
@click.option("--workers", default=10, show_default=True, type=int)
@click.option("--duration", default=10, show_default=True, type=int, help="Seconds; capped by scope and hard limit.")
@click.option("--timeout-ms", default=5000, show_default=True, type=int, help="Per-request timeout (http profile).")
@click.option("--output", type=click.Path(dir_okay=False), help="Write the full JSON report here.")
def run(target, scope, approval, profile, port, method, path, rps, workers, duration, timeout_ms, output):
    """Run an authorized load test. Refuses to touch anything off-scope."""
    try:
        sc = load_scope(scope)
        host = _resolve_host(target, profile)
        check_run(sc, host, approval)
        limits = effective_limits(sc, rps, workers, duration)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    meta = {
        "tool": "hackit stress",
        "operator": sc.operator,
        "approval_ref": sc.approval_ref,
        "scope_expires": sc.expires.isoformat(),
        "profile": profile,
        "target": target,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "effective": {"rps": limits.rps, "workers": limits.workers, "duration_s": limits.duration_s},
    }

    try:
        _audit(meta)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    try:
        if profile == "http":
            url = target if "://" in target else f"http://{target}"
            report = engines.run_go(url, method.upper(), rps=limits.rps, workers=limits.workers,
                                    duration_s=limits.duration_s, timeout_ms=timeout_ms)
        else:
            report = engines.run_c("tcp", host, port, rps=limits.rps, workers=limits.workers,
                                   duration_s=limits.duration_s)
    except engines.EngineError as exc:
        click.echo(f"  [fail] {exc}", err=True)
        sys.exit(1)

    effective = {"rps": limits.rps, "workers": limits.workers}
    click.echo("  stresslab — authorized resilience test")
    _render_report(report, effective)
    if output:
        _write_report(output, report, meta)


@stress.command()
@click.option("--target", required=True, help="Loopback URL (http) or bare loopback host (tcp).")
@click.option("--profile", type=click.Choice(["http", "tcp"]), default="http", show_default=True)
@click.option("--port", default=80, show_default=True, type=int)
@click.option("--path", default="/", show_default=True)
@click.option("--rps", default=20, show_default=True, type=int)
@click.option("--workers", default=4, show_default=True, type=int)
@click.option("--duration", default=5, show_default=True, type=int)
def lab(target, profile, port, path, rps, workers, duration):
    """Loopback-only smoke test. No scope file needed; tight caps apply."""
    rps = min(rps, LAB_MAX_RPS)
    workers = min(workers, LAB_MAX_WORKERS)
    duration = min(duration, LAB_MAX_DURATION_S)
    try:
        host = _resolve_host(target, profile)
        if not _is_loopback(host):
            raise ScopeError("lab mode is loopback-only (localhost / 127.0.0.1 / ::1) — use 'run' with a scope file for anything else")
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    meta = {
        "tool": "hackit stress lab",
        "operator": "local",
        "approval_ref": "lab-loopback",
        "profile": profile,
        "target": target,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "effective": {"rps": rps, "workers": workers, "duration_s": duration},
    }
    try:
        _audit(meta)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    try:
        if profile == "http":
            url = target if "://" in target else f"http://{target}"
            report = engines.run_go(url, "GET", rps=rps, workers=workers, duration_s=duration, timeout_ms=2000)
        else:
            report = engines.run_c("tcp", host, port, rps=rps, workers=workers, duration_s=duration)
    except engines.EngineError as exc:
        click.echo(f"  [fail] {exc}", err=True)
        sys.exit(1)

    click.echo("  stresslab — loopback lab")
    _render_report(report, {"rps": rps, "workers": workers})


def _resolve_host(target: str, profile: str) -> str:
    if profile == "http":
        if "://" not in target:
            target = f"http://{target}"
        parts = urlsplit(target)
        if not parts.hostname:
            raise ScopeError("target has no hostname")
        return parts.hostname
    if "://" in target:
        raise ScopeError("tcp profile takes a bare host, not a URL — pass --port separately")
    return target.rsplit(":", 1)[0] if target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit() else target
