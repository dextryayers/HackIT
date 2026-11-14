"""hackit ddos — authorized resilience testing console.

Measures how systems you own (or may assess under written permission) behave
under load. Go engine for HTTP(S), C11 engine for TCP/plain-HTTP, Python as
the bridge into the main HackIt CLI.

Safety model:
  * Loopback targets run immediately.
  * Remote targets require an explicit authorization confirmation in the
    interactive console, or a signed scope file (--scope + --approval) for
    scripted runs.
  * Hard caps on rate, concurrency and duration; scope files can only lower
    them.
  * No spoofing, no amplification, no evasion, no persistence. HTTPS targets
    are verified against the system trust store.
  * Every run appends a record to ~/.hackit/ddos/audit.log; the run aborts if
    the audit log is not writable.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import click

from hackit.ddos import engines
from hackit.ddos.scope import (
    HARD_MAX_DURATION_S,
    HARD_MAX_RPS,
    HARD_MAX_WORKERS,
    ScopeError,
    check_run,
    effective_limits,
    load_scope,
)

AUDIT_LOG = Path.home() / ".hackit" / "ddos" / "audit.log"
AUDIT_MAX_BYTES = 5 * 1024 * 1024

LAB_MAX_RPS = 500
LAB_MAX_WORKERS = 16
LAB_MAX_DURATION_S = 60

# Interactive defaults — deliberately conservative; formal runs use scope files.
INTERACTIVE_DEFAULT_RPS = 20
INTERACTIVE_DEFAULT_WORKERS = 4
INTERACTIVE_DEFAULT_DURATION_S = 10
INTERACTIVE_MAX_RPS = 1000
INTERACTIVE_MAX_WORKERS = 64
INTERACTIVE_MAX_DURATION_S = 300

AUTH_PHRASE = "yes"


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


def _host_of(target: str) -> str:
    target = target.strip()
    if "://" in target:
        parts = urlsplit(target)
        if parts.hostname:
            return parts.hostname
        raise ScopeError("target URL has no hostname")
    if ":" in target:
        head, tail = target.rsplit(":", 1)
        if tail.isdigit():
            return head
    return target


def _http_url(target: str) -> str:
    target = target.strip()
    return target if "://" in target else f"http://{target}"


def _render_report(report: dict, rps_cap: int, workers: int) -> None:
    lat = report.get("latency_ms") or {}
    engine = str(report.get("engine", "?")).upper()
    click.echo(f"  engine        {engine} ({report.get('mode', '?')})")
    click.echo(f"  target        {report.get('target', '?')}")
    click.echo(f"  duration      {float(report.get('duration_s', 0.0)):.1f}s   cap rps {rps_cap}/s   workers {workers}")
    click.echo(f"  requests      {report.get('requests', 0)}   ok {report.get('ok', 0)}   errors {report.get('errors', 0)}")
    click.echo(f"  achieved rps  {float(report.get('achieved_rps', 0.0)):.1f}   error rate {float(report.get('error_rate', 0.0)) * 100:.2f}%")
    click.echo(f"  latency ms    p50 {lat.get('p50', 0):.1f}   p90 {lat.get('p90', 0):.1f}   p99 {lat.get('p99', 0):.1f}   max {lat.get('max', 0):.1f}")


def _write_report(path: str, report: dict, meta: dict) -> None:
    payload = {"meta": meta, "result": report}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    click.echo(f"  report        written to {path}")


def _run_http(url: str, method: str, rps: int, workers: int, duration_s: int, timeout_ms: int) -> dict:
    return engines.run_go(url, method.upper(), rps=rps, workers=workers,
                          duration_s=duration_s, timeout_ms=timeout_ms)


def _run_tcp(host: str, port: int, rps: int, workers: int, duration_s: int) -> dict:
    return engines.run_c("tcp", host, port, rps=rps, workers=workers, duration_s=duration_s)


def _audit_meta(operator: str, approval_ref: str, profile: str, target: str,
                rps: int, workers: int, duration_s: int, scope_expires: str | None = None) -> dict:
    return {
        "tool": "hackit ddos",
        "operator": operator,
        "approval_ref": approval_ref,
        "scope_expires": scope_expires,
        "profile": profile,
        "target": target,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "effective": {"rps": rps, "workers": workers, "duration_s": duration_s},
    }


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(value, hi))


def _interactive() -> None:
    click.echo("")
    click.echo("  HACKIT / DDOS — authorized resilience console")
    click.echo("  Loopback targets run immediately. Remote targets need your explicit")
    click.echo("  confirmation that you own the system or hold written permission.")
    click.echo("")

    while True:
        raw = click.prompt("  Target domain/IP (empty to quit)", default="", show_default=False).strip()
        if not raw:
            click.echo("  rai cleared — bye.")
            return

        try:
            host = _host_of(raw)
        except ScopeError as exc:
            click.echo(f"  [refused] {exc}")
            continue

        remote = not _is_loopback(host)
        if remote:
            click.echo("")
            click.echo(f"  Target '{host}' is remote. This console sends real load.")
            click.echo("  Type 'yes' only if you own this system or hold written permission.")
            answer = click.prompt("  Authorization confirmed?", default="no", show_default=True).strip().lower()
            if answer != AUTH_PHRASE:
                click.echo("  [refused] authorization not confirmed — nothing was sent.")
                continue

        profile = click.prompt("  Profile [http|tcp]", default="http", show_default=True).strip().lower()
        if profile not in ("http", "tcp"):
            click.echo("  [refused] profile must be http or tcp")
            continue

        port = 80
        path = "/"
        if profile == "tcp":
            port = _clamp(click.prompt("  Port", default=80, show_default=True, type=int), 1, 65535)
        else:
            if "://" in raw:
                path = urlsplit(raw).path or "/"

        duration = _clamp(click.prompt("  Duration (s)", default=INTERACTIVE_DEFAULT_DURATION_S, show_default=True, type=int),
                          1, INTERACTIVE_MAX_DURATION_S)
        rps = _clamp(click.prompt("  Rate cap (rps)", default=INTERACTIVE_DEFAULT_RPS, show_default=True, type=int),
                     1, INTERACTIVE_MAX_RPS)
        workers = _clamp(click.prompt("  Workers", default=INTERACTIVE_DEFAULT_WORKERS, show_default=True, type=int),
                         1, INTERACTIVE_MAX_WORKERS)

        meta = _audit_meta(
            operator="interactive",
            approval_ref="interactive-confirmed" if remote else "lab-loopback",
            profile=profile,
            target=raw,
            rps=rps,
            workers=workers,
            duration_s=duration,
        )
        try:
            _audit(meta)
        except ScopeError as exc:
            click.echo(f"  [refused] {exc}")
            continue

        click.echo("  engines spinning up...")
        try:
            if profile == "http":
                report = _run_http(_http_url(raw), "GET", rps, workers, duration, 3000)
            else:
                report = _run_tcp(host, port, rps, workers, duration)
        except engines.EngineError as exc:
            click.echo(f"  [fail] {exc}")
            continue

        _render_report(report, rps, workers)
        click.echo("")
        again = click.prompt("  Test another target? [y/N]", default="n", show_default=False).strip().lower()
        if again not in ("y", "yes"):
            click.echo("  rail cold — bye.")
            return


@click.group(invoke_without_command=True)
@click.pass_context
def ddos(ctx: click.Context):
    """Authorized resilience testing — enter a target, engines work.

    Loopback runs immediately; remote targets require typing 'yes' to confirm
    you own the system or hold written permission. Scripted runs need a
    scope file (--scope) with a matching --approval. Every run is audited.
    """
    if ctx.invoked_subcommand is None:
        _interactive()


@ddos.command()
def build():
    """Compile the Go and C engines."""
    for label, fn in (("go", engines.build_go), ("c", engines.build_c)):
        try:
            path = fn()
        except engines.EngineError as exc:
            click.echo(f"  [fail] {label}: {exc}", err=True)
            sys.exit(1)
        click.echo(f"  [ok]   {label}: {path}")


@ddos.command()
@click.option("--scope", required=True, type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON).")
@click.option("--target", required=True, help="URL for http profile, bare host for tcp profile.")
@click.option("--approval", required=True, help="Approval reference; must match scope approval_ref.")
@click.option("--profile", type=click.Choice(["http", "tcp"]), default="http")
@click.option("--port", default=80, show_default=True, type=int, help="Port for the tcp profile.")
def check(scope, target, approval, profile, port):
    """Validate scope, target and approval without generating any load."""
    try:
        sc = load_scope(scope)
        host = _host_of(target)
        check_run(sc, host, approval)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)
    click.echo("  [ok] scope valid")
    click.echo(f"  operator      {sc.operator}")
    click.echo(f"  approval      {sc.approval_ref}   expires {sc.expires.isoformat()}")
    click.echo(f"  allowlist     {', '.join(sc.targets)}")
    click.echo(f"  caps          rps <= {sc.max_rps}/s   workers <= {sc.max_workers}   duration <= {sc.max_duration_s}s "
               f"(hard ceilings {HARD_MAX_RPS}/{HARD_MAX_WORKERS}/{HARD_MAX_DURATION_S})")


@ddos.command()
@click.option("--target", required=True, help="URL (http) or bare host (tcp).")
@click.option("--scope", type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON) — required for remote targets.")
@click.option("--approval", help="Approval reference; must match scope approval_ref.")
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
    """Run a scripted load test. Remote targets require --scope and --approval."""
    host = _host_of(target)
    loopback = _is_loopback(host)

    if loopback:
        limits_rps = min(rps, LAB_MAX_RPS)
        limits_workers = min(workers, LAB_MAX_WORKERS)
        limits_duration = min(duration, LAB_MAX_DURATION_S)
        meta = _audit_meta("local", "lab-loopback", profile, target, limits_rps, limits_workers, limits_duration)
    else:
        if not scope or not approval:
            click.echo("  [refused] remote targets require --scope and --approval — loopback works without them.", err=True)
            sys.exit(2)
        try:
            sc = load_scope(scope)
            check_run(sc, host, approval)
            limits = effective_limits(sc, rps, workers, duration)
        except ScopeError as exc:
            click.echo(f"  [refused] {exc}", err=True)
            sys.exit(2)
        limits_rps, limits_workers, limits_duration = limits.rps, limits.workers, limits.duration_s
        meta = _audit_meta(sc.operator, sc.approval_ref, profile, target,
                           limits_rps, limits_workers, limits_duration, sc.expires.isoformat())

    try:
        _audit(meta)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    try:
        if profile == "http":
            report = _run_http(_http_url(target), method, limits_rps, limits_workers, limits_duration, timeout_ms)
        else:
            report = _run_tcp(host, port, limits_rps, limits_workers, limits_duration)
    except engines.EngineError as exc:
        click.echo(f"  [fail] {exc}", err=True)
        sys.exit(1)

    click.echo("  HACKIT / DDOS — authorized resilience test")
    _render_report(report, limits_rps, limits_workers)
    if output:
        _write_report(output, report, meta)


@ddos.command()
@click.option("--target", required=True, help="Loopback URL (http) or bare loopback host (tcp).")
@click.option("--profile", type=click.Choice(["http", "tcp"]), default="http", show_default=True)
@click.option("--port", default=80, show_default=True, type=int)
@click.option("--rps", default=20, show_default=True, type=int)
@click.option("--workers", default=4, show_default=True, type=int)
@click.option("--duration", default=5, show_default=True, type=int)
def lab(target, profile, port, rps, workers, duration):
    """Loopback-only smoke test. No scope file, tight caps."""
    rps = min(rps, LAB_MAX_RPS)
    workers = min(workers, LAB_MAX_WORKERS)
    duration = min(duration, LAB_MAX_DURATION_S)
    host = _host_of(target)
    if not _is_loopback(host):
        click.echo("  [refused] lab mode is loopback-only (localhost / 127.0.0.1 / ::1)", err=True)
        sys.exit(2)

    meta = _audit_meta("local", "lab-loopback", profile, target, rps, workers, duration)
    try:
        _audit(meta)
    except ScopeError as exc:
        click.echo(f"  [refused] {exc}", err=True)
        sys.exit(2)

    try:
        if profile == "http":
            report = _run_http(_http_url(target), "GET", rps, workers, duration, 2000)
        else:
            report = _run_tcp(host, port, rps, workers, duration)
    except engines.EngineError as exc:
        click.echo(f"  [fail] {exc}", err=True)
        sys.exit(1)

    click.echo("  HACKIT / DDOS — loopback lab")
    _render_report(report, rps, workers)
