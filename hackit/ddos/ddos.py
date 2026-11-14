"""hackit ddos — authorized resilience testing console.

Measures how systems you own (or may assess under written permission) behave
under load. Go engine for HTTP(S), C11 engine for TCP/plain-HTTP, Python as
the bridge into the main HackIt CLI.

Safety model:
  * Loopback targets run immediately.
  * Remote targets require an explicit authorization confirmation in the
    interactive console (`hackit ddos console`), or a signed scope file
    (--scope + --approval) for scripted runs.
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
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import click

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

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

console = Console()

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
HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options", "mixed"]

BANNER = [
    "██████╗ ██████╗  ██████╗  ███████╗",
    "██╔══██╗██╔══██╗██╔══██╗ ██╔════╝",
    "██║  ██║██║  ██║██║  ██║ ███████╗",
    "██║  ██║██║  ██║██║  ██║ ╚════██║",
    "██████╔╝██████╔╝██████╔╝ ███████║",
    "╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
]


def _gradient(text: str, start=(0, 200, 255), end=(255, 60, 160)) -> Text:
    out = Text()
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        f = i / n
        r = int(start[0] + (end[0] - start[0]) * f)
        g = int(start[1] + (end[1] - start[1]) * f)
        b = int(start[2] + (end[2] - start[2]) * f)
        out.append(ch, style=f"rgb({r},{g},{b})")
    return out


def _banner() -> Text:
    lines = Text()
    for line in BANNER:
        lines.append_text(_gradient(line))
        lines.append("\n")
    lines.append("\n")
    lines.append("  HACKIT / DDOS", style="bold white")
    lines.append("  —  authorized resilience testing\n", style="dim white")
    lines.append("  scoped · capped · audited", style="dim cyan")
    return lines


def _panel(title: str, renderable, *, border="cyan", padding=(0, 1)) -> Panel:
    return Panel(renderable, title=f"[bold]{title}[/bold]", border_style=border,
                 box=box.ROUNDED, padding=padding)


def _print_help() -> None:
    console.print()
    console.print(_banner())
    console.print()

    commands = Table.grid(padding=(0, 2))
    commands.add_column(style="bold cyan", no_wrap=True)
    commands.add_column(style="white")
    commands.add_row("console", "interactive console — type a target, engines work")
    commands.add_row("run",     "scripted run — scope file + approval for remote targets")
    commands.add_row("lab",     "loopback-only smoke test, no scope needed")
    commands.add_row("check",   "validate scope / target / approval, no load generated")
    commands.add_row("build",   "compile the Go and C engines")
    console.print(_panel("Commands", commands, border="cyan"))

    profiles = Table.grid(padding=(0, 2))
    profiles.add_column(style="bold magenta", no_wrap=True)
    profiles.add_column(style="white")
    profiles.add_row("http", "Go engine — GET · POST · PUT · PATCH · DELETE · HEAD · OPTIONS · mixed")
    profiles.add_row("tcp",  "C engine  — TCP connect handshake rate & latency")
    profiles.add_row("http-raw", "C engine  — plain-HTTP GET against the raw socket path")
    console.print(_panel("Profiles", profiles, border="magenta"))

    options = Table.grid(padding=(0, 2))
    options.add_column(style="bold yellow", no_wrap=True)
    options.add_column(style="white")
    options.add_row("--method",   "HTTP verb, or 'mixed' to rotate verbs per request")
    options.add_row("--body",     "request body for POST/PUT/PATCH (JSON auto-detected)")
    options.add_row("--ramp N",   "linearly ramp 1 → --rps over N seconds (find the knee)")
    options.add_row("--close",    "force Connection: close (handshake stress)")
    options.add_row("-v",         "verbose — resolved target, effective caps, audit path")
    console.print(_panel("Run flags", options, border="yellow"))

    examples = Text("", style="white")
    examples.append("  hackit ddos\n", style="bold green")
    examples.append("  hackit ddos run --target https://staging.example.internal/health \\\n"
                    "      --scope scope.json --approval CHG-1234 --method post \\\n"
                    "      --body '{\"probe\":true}' --rps 100 --workers 16 --duration 30 -v\n", style="green")
    examples.append("  hackit ddos lab --target http://127.0.0.1:8080 --method put --ramp 5\n", style="green")
    console.print(_panel("Examples", examples, border="green"))

    console.print(f"  [dim]caps  interactive {INTERACTIVE_MAX_RPS} rps/{INTERACTIVE_MAX_WORKERS} workers/{INTERACTIVE_MAX_DURATION_S}s  ·  "
                  f"lab {LAB_MAX_RPS}/{LAB_MAX_WORKERS}/{LAB_MAX_DURATION_S}  ·  "
                  f"hard {HARD_MAX_RPS}/{HARD_MAX_WORKERS}/{HARD_MAX_DURATION_S}[/dim]")
    console.print(f"  [dim]audit {AUDIT_LOG}  ·  remote targets always require authorization[/dim]")
    console.print()


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


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(value, hi))


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


class _Dashboard:
    """Live run panel — refreshed from engine progress lines."""

    def __init__(self, *, label: str, target: str, method: str, rps: int,
                 workers: int, duration_s: int, started: float):
        self.label = label
        self.target = target
        self.method = method
        self.rps = rps
        self.workers = workers
        self.duration_s = duration_s
        self.started = started
        self.state = {"elapsed_s": 0.0, "requests": 0, "ok": 0, "errors": 0, "achieved_rps": 0.0}
        self.history: list[float] = []

    def update(self, progress: dict) -> None:
        self.state = {
            "elapsed_s": float(progress.get("elapsed_s", 0.0)),
            "requests": int(progress.get("requests", 0)),
            "ok": int(progress.get("ok", 0)),
            "errors": int(progress.get("errors", 0)),
            "achieved_rps": float(progress.get("achieved_rps", 0.0)),
        }
        self.history.append(self.state["achieved_rps"])
        self.history = self.history[-60:]

    def _bar(self, frac: float, width: int = 34) -> Text:
        frac = max(0.0, min(1.0, frac))
        filled = int(frac * width)
        bar = Text()
        bar.append("━" * filled, style="bold cyan")
        bar.append("─" * (width - filled), style="dim")
        return bar

    def _spark(self, width: int = 34) -> Text:
        if not self.history:
            return Text("·" * width, style="dim")
        peak = max(max(self.history), 1.0)
        ramp = "▁▂▃▄▅▆▇█"
        out = Text()
        step = max(1, len(self.history) // width)
        samples = self.history[::step][-width:]
        for v in samples:
            idx = min(len(ramp) - 1, int(v / peak * (len(ramp) - 1)))
            out.append(ramp[idx], style="cyan")
        return out

    def render(self) -> Panel:
        s = self.state
        frac = s["elapsed_s"] / self.duration_s if self.duration_s else 0.0
        err_rate = (s["errors"] / s["requests"] * 100) if s["requests"] else 0.0

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True)
        grid.add_column()

        grid.add_row("target", Text(self.target, style="bold white"))
        grid.add_row("profile", Text(f"{self.method}  ·  cap {self.rps} rps  ·  {self.workers} workers", style="magenta"))
        grid.add_row("elapsed", Text(f"{s['elapsed_s']:.1f}s / {self.duration_s}s", style="white"))
        grid.add_row("progress", self._bar(frac))
        grid.add_row("throughput", self._spark())
        grid.add_row("sent", Text(f"{s['requests']}", style="bold"))
        grid.add_row("ok / err", Text.assemble((f"{s['ok']}", "green"), (" / ", "dim"), (f"{s['errors']}", "red" if s['errors'] else "green"), (f"  ({err_rate:.2f}%)", "dim")))
        grid.add_row("achieved", Text(f"{s['achieved_rps']:.1f} rps", style="bold cyan"))

        return Panel(grid, title=f"[bold cyan]LIVE — {self.label}[/bold cyan]",
                     border_style="cyan", box=box.ROUNDED, padding=(0, 1))


def _final_report(report: dict, *, label: str, rps_cap: int, workers: int,
                  verbose: bool, meta: dict | None = None) -> None:
    lat = report.get("latency_ms") or {}
    engine = str(report.get("engine", "?")).upper()
    total = int(report.get("requests", 0))
    errors = int(report.get("errors", 0))
    err_rate = float(report.get("error_rate", 0.0)) * 100

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", no_wrap=True)
    grid.add_column()
    grid.add_row("engine", Text(f"{engine} ({report.get('mode', '?')})" + (f"  method {report['method']}" if report.get("method") else ""), style="magenta"))
    grid.add_row("target", Text(str(report.get("target", "?")), style="bold white"))
    grid.add_row("duration", Text(f"{float(report.get('duration_s', 0.0)):.1f}s   cap {rps_cap} rps   {workers} workers", style="white"))
    grid.add_row("requests", Text(f"{total}   ok {report.get('ok', 0)}   errors {errors}", style="white"))
    grid.add_row("achieved", Text(f"{float(report.get('achieved_rps', 0.0)):.1f} rps   error rate {err_rate:.2f}%", style="bold cyan"))

    lat_row = Table.grid(padding=(0, 3))
    for key in ("p50", "p90", "p99", "max"):
        lat_row.add_column(style="white")
    lat_row.add_row(*[Text(f"{k}  {float(lat.get(k, 0.0)):.1f} ms", style="cyan") for k in ("p50", "p90", "p99", "max")])

    body = Group(grid, Text(""), lat_row)
    console.print(Panel(body, title=f"[bold green]RESULT — {label}[/bold green]",
                        border_style="green", box=box.ROUNDED, padding=(0, 1)))

    if verbose and meta:
        details = Table.grid(padding=(0, 2))
        details.add_column(style="dim", no_wrap=True)
        details.add_column(style="white")
        details.add_row("operator", str(meta.get("operator")))
        details.add_row("approval", str(meta.get("approval_ref")))
        if meta.get("scope_expires"):
            details.add_row("scope expires", str(meta.get("scope_expires")))
        details.add_row("started (UTC)", str(meta.get("started_utc")))
        details.add_row("audit log", str(AUDIT_LOG))
        console.print(Panel(details, title="[dim]verbose[/dim]", border_style="dim",
                            box=box.ROUNDED, padding=(0, 1)))


def _run_engine(kind: str, *, on_progress, **kwargs) -> dict:
    if kind == "go":
        return engines.run_go(on_progress=on_progress, **kwargs)
    return engines.run_c(on_progress=on_progress, **kwargs)


def _execute(*, label: str, profile: str, target: str, method: str, body: str,
             port: int, ramp: int, force_close: bool, rps: int, workers: int,
             duration: int, timeout_ms: int, meta: dict, verbose: bool,
             output: str | None, raw_path: str = "/") -> None:
    started = time.monotonic()
    dashboard = _Dashboard(label=label, target=target, method=method.upper() if profile == "http" else f"{profile.upper()}:{port}",
                           rps=rps, workers=workers, duration_s=duration, started=started)

    meta = {**meta, "started_utc": datetime.now(timezone.utc).isoformat()}
    try:
        _audit(meta)
    except ScopeError as exc:
        console.print(f"[bold red]refused[/bold red] — {exc}")
        sys.exit(2)

    if verbose:
        console.print(f"[dim]resolved target[/dim] {_host_of(target)}   [dim]audit[/dim] {AUDIT_LOG}")

    tty = console.is_terminal

    def on_progress(p: dict) -> None:
        dashboard.update(p)
        if not tty:
            s = dashboard.state
            console.print(f"[dim]t={s['elapsed_s']:.1f}s[/dim] sent {s['requests']} · ok {s['ok']} · "
                          f"err {s['errors']} · {s['achieved_rps']:.1f} r/s")

    try:
        if tty:
            with Live(dashboard.render(), console=console, refresh_per_second=10) as live:
                def live_progress(p: dict) -> None:
                    on_progress(p)
                    live.update(dashboard.render())
                if profile == "http":
                    report = _run_engine("go", on_progress=live_progress,
                                         url=_http_url(target), method=method.upper(),
                                         rps=rps, workers=workers, duration_s=duration,
                                         timeout_ms=timeout_ms, body=body,
                                         ramp_s=ramp, force_close=force_close)
                elif profile == "http-raw":
                    report = _run_engine("c", on_progress=live_progress,
                                         mode="http", host=_host_of(target), port=port, path=raw_path,
                                         rps=rps, workers=workers, duration_s=duration)
                else:
                    report = _run_engine("c", on_progress=live_progress,
                                         mode="tcp", host=_host_of(target), port=port,
                                         rps=rps, workers=workers, duration_s=duration)
        else:
            if profile == "http":
                report = _run_engine("go", on_progress=on_progress,
                                     url=_http_url(target), method=method.upper(),
                                     rps=rps, workers=workers, duration_s=duration,
                                     timeout_ms=timeout_ms, body=body,
                                     ramp_s=ramp, force_close=force_close)
            elif profile == "http-raw":
                report = _run_engine("c", on_progress=on_progress,
                                     mode="http", host=_host_of(target), port=port, path=raw_path,
                                     rps=rps, workers=workers, duration_s=duration)
            else:
                report = _run_engine("c", on_progress=on_progress,
                                     mode="tcp", host=_host_of(target), port=port,
                                     rps=rps, workers=workers, duration_s=duration)
    except engines.EngineError as exc:
        console.print(f"[bold red]engine failure[/bold red] — {exc}")
        sys.exit(1)

    _final_report(report, label=label, rps_cap=rps, workers=workers, verbose=verbose, meta=meta)
    if output:
        _write_report(output, report, meta)


def _write_report(path: str, report: dict, meta: dict) -> None:
    payload = {"meta": meta, "result": report}
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    console.print(f"[dim]report written to {path}[/dim]")


@click.group(invoke_without_command=True)
@click.pass_context
def ddos(ctx: click.Context):
    """Authorized resilience testing — scoped, capped, audited.

    Run with no arguments to see the console help. Remote targets always
    require authorization: a signed scope file (run) or a typed confirmation
    (console). Loopback targets run immediately.
    """
    if ctx.invoked_subcommand is None:
        _print_help()


@ddos.command()
def build():
    """Compile the Go and C engines."""
    for label, fn in (("go", engines.build_go), ("c", engines.build_c)):
        try:
            path = fn()
        except engines.EngineError as exc:
            console.print(f"[bold red]fail[/bold red] {label}: {exc}")
            sys.exit(1)
        console.print(f"[green]ok[/green]   {label}: {path}")


@ddos.command()
@click.option("--scope", required=True, type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON).")
@click.option("--target", required=True, help="URL for http profile, bare host for tcp profile.")
@click.option("--approval", required=True, help="Approval reference; must match scope approval_ref.")
@click.option("--profile", type=click.Choice(["http", "http-raw", "tcp"]), default="http")
@click.option("--port", default=80, show_default=True, type=int, help="Port for the tcp profile.")
def check(scope, target, approval, profile, port):
    """Validate scope, target and approval without generating any load."""
    try:
        sc = load_scope(scope)
        host = _host_of(target)
        check_run(sc, host, approval)
    except ScopeError as exc:
        console.print(f"[bold red]refused[/bold red] — {exc}")
        sys.exit(2)
    body = Text()
    body.append(f"operator       {sc.operator}\n")
    body.append(f"approval       {sc.approval_ref}   expires {sc.expires.isoformat()}\n")
    body.append(f"allowlist      {', '.join(sc.targets)}\n")
    body.append(f"caps           rps ≤ {sc.max_rps}/s   workers ≤ {sc.max_workers}   duration ≤ {sc.max_duration_s}s\n")
    body.append(f"hard ceilings  {HARD_MAX_RPS}/{HARD_MAX_WORKERS}/{HARD_MAX_DURATION_S}", style="dim")
    console.print(Panel(body, title="[bold green]scope valid[/bold green]", border_style="green",
                        box=box.ROUNDED, padding=(0, 1)))


@ddos.command()
@click.option("--target", required=True, help="URL (http) or bare host (tcp).")
@click.option("--scope", type=click.Path(exists=True, dir_okay=False), help="Signed scope file (JSON) — required for remote targets.")
@click.option("--approval", help="Approval reference; must match scope approval_ref.")
@click.option("--profile", type=click.Choice(["http", "http-raw", "tcp"]), default="http", show_default=True)
@click.option("--port", default=80, show_default=True, type=int, help="Port for tcp/http-raw profiles.")
@click.option("--method", type=click.Choice(HTTP_METHODS), default="get", show_default=True,
              help="HTTP verb, or 'mixed' to rotate verbs per request.")
@click.option("--body", default="", help="Request body for POST/PUT/PATCH.")
@click.option("--ramp", default=0, show_default=True, type=int, help="Seconds to linearly ramp 1 → --rps.")
@click.option("--close", "force_close", is_flag=True, help="Send Connection: close (handshake stress).")
@click.option("--path", default="/", show_default=True, help="HTTP path (http-raw profile).")
@click.option("--rps", default=50, show_default=True, type=int)
@click.option("--workers", default=10, show_default=True, type=int)
@click.option("--duration", default=10, show_default=True, type=int, help="Seconds; capped by scope and hard limit.")
@click.option("--timeout-ms", default=5000, show_default=True, type=int, help="Per-request timeout (http profile).")
@click.option("--output", type=click.Path(dir_okay=False), help="Write the full JSON report here.")
@click.option("-v", "--verbose", is_flag=True, help="Show resolved target, effective caps and audit path.")
def run(target, scope, approval, profile, port, method, body, ramp, force_close, path,
        rps, workers, duration, timeout_ms, output, verbose):
    """Run a scripted load test. Remote targets require --scope and --approval."""
    host = _host_of(target)
    loopback = _is_loopback(host)

    if loopback:
        eff_rps, eff_workers, eff_duration = min(rps, LAB_MAX_RPS), min(workers, LAB_MAX_WORKERS), min(duration, LAB_MAX_DURATION_S)
        meta = _audit_meta("local", "lab-loopback", profile, target, eff_rps, eff_workers, eff_duration)
    else:
        if not scope or not approval:
            console.print("[bold red]refused[/bold red] — remote targets require --scope and --approval (loopback works without them)")
            sys.exit(2)
        try:
            sc = load_scope(scope)
            check_run(sc, host, approval)
            limits = effective_limits(sc, rps, workers, duration)
        except ScopeError as exc:
            console.print(f"[bold red]refused[/bold red] — {exc}")
            sys.exit(2)
        eff_rps, eff_workers, eff_duration = limits.rps, limits.workers, limits.duration_s
        meta = _audit_meta(sc.operator, sc.approval_ref, profile, target,
                           eff_rps, eff_workers, eff_duration, sc.expires.isoformat())

    _execute(label="scoped run" if not loopback else "loopback", profile=profile, target=target,
             method=method, body=body, port=port, ramp=ramp, force_close=force_close,
             rps=eff_rps, workers=eff_workers, duration=eff_duration, timeout_ms=timeout_ms,
             meta=meta, verbose=verbose, output=output, raw_path=path)


@ddos.command()
@click.option("--target", required=True, help="Loopback URL (http) or bare loopback host (tcp).")
@click.option("--profile", type=click.Choice(["http", "http-raw", "tcp"]), default="http", show_default=True)
@click.option("--port", default=80, show_default=True, type=int)
@click.option("--method", type=click.Choice(HTTP_METHODS), default="get", show_default=True)
@click.option("--body", default="", help="Request body for POST/PUT/PATCH.")
@click.option("--ramp", default=0, show_default=True, type=int)
@click.option("--close", "force_close", is_flag=True)
@click.option("--rps", default=20, show_default=True, type=int)
@click.option("--workers", default=4, show_default=True, type=int)
@click.option("--duration", default=5, show_default=True, type=int)
@click.option("-v", "--verbose", is_flag=True)
def lab(target, profile, port, method, body, ramp, force_close, rps, workers, duration, verbose):
    """Loopback-only smoke test. No scope file, tight caps."""
    host = _host_of(target)
    if not _is_loopback(host):
        console.print("[bold red]refused[/bold red] — lab mode is loopback-only (localhost / 127.0.0.1 / ::1)")
        sys.exit(2)

    eff_rps, eff_workers, eff_duration = min(rps, LAB_MAX_RPS), min(workers, LAB_MAX_WORKERS), min(duration, LAB_MAX_DURATION_S)
    meta = _audit_meta("local", "lab-loopback", profile, target, eff_rps, eff_workers, eff_duration)

    _execute(label="loopback lab", profile=profile, target=target,
             method=method, body=body, port=port, ramp=ramp, force_close=force_close,
             rps=eff_rps, workers=eff_workers, duration=eff_duration, timeout_ms=2000,
             meta=meta, verbose=verbose, output=None)


@ddos.command(name="console")
def ddos_console():
    """Interactive console — enter a target, engines work."""
    from rich.prompt import Prompt

    console.print()
    console.print(_banner())
    console.print("  [dim]Loopback targets run immediately. Remote targets need a typed 'yes'[/dim]")
    console.print("  [dim]confirming you own the system or hold written permission.[/dim]")
    console.print()

    while True:
        raw = Prompt.ask("[bold cyan]target domain/IP[/bold cyan] (empty to quit)", default="", show_default=False).strip()
        if not raw:
            console.print("[dim]rail cleared — bye.[/dim]")
            return

        try:
            host = _host_of(raw)
        except ScopeError as exc:
            console.print(f"[bold red]refused[/bold red] — {exc}")
            continue

        remote = not _is_loopback(host)
        if remote:
            console.print(f"\n  [bold yellow]'{host}' is remote.[/bold yellow] This console sends real load.")
            answer = Prompt.ask("  Type [bold]yes[/bold] to confirm ownership or written permission", default="no").strip().lower()
            if answer != AUTH_PHRASE:
                console.print("[bold red]refused[/bold red] — authorization not confirmed, nothing was sent.\n")
                continue

        profile = Prompt.ask("profile", choices=["http", "http-raw", "tcp"], default="http")
        port = 80
        method = "get"
        body = ""
        ramp = 0
        if profile in ("tcp", "http-raw"):
            port = _clamp(int(Prompt.ask("port", default="80") or "80"), 1, 65535)
        if profile == "http":
            method = Prompt.ask("method", choices=HTTP_METHODS, default="get")
            if method in ("post", "put", "patch"):
                body = Prompt.ask("body (JSON or text, empty for none)", default="")
            ramp = _clamp(int(Prompt.ask("ramp seconds (0 = steady)", default="0") or "0"), 0, INTERACTIVE_MAX_DURATION_S)

        duration = _clamp(int(Prompt.ask("duration (s)", default=str(INTERACTIVE_DEFAULT_DURATION_S)) or INTERACTIVE_DEFAULT_DURATION_S), 1, INTERACTIVE_MAX_DURATION_S)
        rps = _clamp(int(Prompt.ask("rate cap (rps)", default=str(INTERACTIVE_DEFAULT_RPS)) or INTERACTIVE_DEFAULT_RPS), 1, INTERACTIVE_MAX_RPS)
        workers = _clamp(int(Prompt.ask("workers", default=str(INTERACTIVE_DEFAULT_WORKERS)) or INTERACTIVE_DEFAULT_WORKERS), 1, INTERACTIVE_MAX_WORKERS)

        meta = _audit_meta("interactive", "interactive-confirmed" if remote else "lab-loopback",
                           profile, raw, rps, workers, duration)
        _execute(label="interactive", profile=profile, target=raw,
                 method=method, body=body, port=port, ramp=ramp, force_close=False,
                 rps=rps, workers=workers, duration=duration, timeout_ms=3000,
                 meta=meta, verbose=False, output=None)
        console.print()
        again = Prompt.ask("test another target?", choices=["y", "n"], default="n")
        if again != "y":
            console.print("[dim]rail cold — bye.[/dim]")
            return
