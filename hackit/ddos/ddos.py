"""hackit ddos — authorized resilience testing console.

Safety model:
  * Loopback targets run immediately.
  * Remote targets need a typed `yes` (console) or a signed scope file
    (--scope + --approval) for scripted runs.
  * Hard caps on rate, concurrency and duration; scope can only lower them.
  * Every run appends to ~/.hackit/ddos/audit.log; the run aborts if that log
    is not writable.

Engines: Go (HTTP/2, DNS, UDP), C measurement (TCP/HTTP/ICMP), C raw flood
(SYN/ACK/RST/FIN/PSH/XMAS/NULL/UDP/ICMP/HTTP), C slowloris. Profiles can be
comma-separated to run vectors in parallel.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import click
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hackit.ddos import engines
from hackit.ddos.scope import (
    ALL_PROFILES,
    HARD_MAX_DURATION_S,
    HARD_MAX_PPS,
    HARD_MAX_RPS,
    HARD_MAX_WORKERS,
    L4_PROFILES,
    ScopeError,
    check_run,
    effective_limits,
    is_l4,
    load_scope,
)

console = Console()

AUDIT_LOG = Path.home() / ".hackit" / "ddos" / "audit.log"
AUDIT_MAX_BYTES = 5 * 1024 * 1024

LAB_MAX_RPS = 500
LAB_MAX_PPS = 20000
LAB_MAX_WORKERS = 16
LAB_MAX_DURATION_S = 60

INTERACTIVE_DEFAULT_RPS = 20
INTERACTIVE_DEFAULT_PPS = 2000
INTERACTIVE_DEFAULT_WORKERS = 4
INTERACTIVE_DEFAULT_DURATION_S = 10
INTERACTIVE_MAX_RPS = 1000
INTERACTIVE_MAX_PPS = 200000
INTERACTIVE_MAX_WORKERS = 64
INTERACTIVE_MAX_DURATION_S = 300

AUTH_PHRASE = "yes"
HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options", "mixed"]

PROFILE_LABEL = {
    "http": "HTTP", "https": "HTTPS", "http-raw": "HTTP-RAW", "slowloris": "SLOWLORIS",
    "dns": "DNS", "udp": "UDP-ECHO", "ws": "WS", "syn": "SYN", "ack": "ACK",
    "rst": "RST", "fin": "FIN", "psh": "PSH", "xmas": "XMAS", "null": "NULL",
    "udp-flood": "UDP-FLOOD", "icmp-flood": "ICMP-FLOOD",
}

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
        out.append(ch, style="rgb({},{},{})".format(
            int(start[0] + (end[0] - start[0]) * f),
            int(start[1] + (end[1] - start[1]) * f),
            int(start[2] + (end[2] - start[2]) * f)))
    return out


def _banner() -> Text:
    t = Text()
    for line in BANNER:
        t.append_text(_gradient(line))
        t.append("\n")
    t.append("\n")
    t.append("  HACKIT / DDOS", style="bold white")
    t.append("  —  authorized resilience testing\n", style="dim white")
    t.append("  scoped · capped · audited · multi-vector", style="dim cyan")
    return t


def _panel(title: str, renderable, *, border="cyan", padding=(0, 1)) -> Panel:
    return Panel(renderable, title=f"[bold]{title}[/bold]", border_style=border,
                 box=box.ROUNDED, padding=padding)


def _print_help() -> None:
    console.print()
    console.print(_banner())
    console.print()

    cmds = Table.grid(padding=(0, 2))
    cmds.add_column(style="bold cyan", no_wrap=True)
    cmds.add_column(style="white")
    cmds.add_row("console", "interactive console")
    cmds.add_row("run", "scripted run — scope file + approval for remote targets")
    cmds.add_row("lab", "loopback-only smoke test, no scope needed")
    cmds.add_row("check", "validate scope / target / approval, no load")
    cmds.add_row("build", "compile every engine")
    console.print(_panel("Commands", cmds))

    prof = Table.grid(padding=(0, 2))
    prof.add_column(style="bold magenta", no_wrap=True)
    prof.add_column(style="white")
    prof.add_row("http · https", "Go — HTTP/1.1 + HTTP/2 request load")
    prof.add_row("http-raw", "C — plain HTTP, full request/response measurement")
    prof.add_row("slowloris", "C — held sockets, drip-fed headers")
    prof.add_row("syn · ack · rst", "C raw — TCP flag floods (root)")
    prof.add_row("fin · psh · xmas · null", "C raw — TCP flag floods (root)")
    prof.add_row("udp-flood · icmp-flood", "C raw — packet blast (root)")
    prof.add_row("tcp", "C — TCP handshake rate")
    prof.add_row("dns · udp", "Go — DNS query rate / UDP echo throughput")
    prof.add_row("ws", "Python — WebSocket echo")
    console.print(_panel("Profiles (comma-separate to run in parallel)", prof, border="magenta"))

    opt = Table.grid(padding=(0, 2))
    opt.add_column(style="bold yellow", no_wrap=True)
    opt.add_column(style="white")
    opt.add_row("--waf", "per-request identity: header case, XFF/CF IPs, path mutation, cache buster, UA draw")
    opt.add_row("--spoof", "randomise source IP on raw modes (root)")
    opt.add_row("--method / --body", "HTTP verb and body (mixed rotates per request)")
    opt.add_row("--ramp N / --close", "linear ramp 1→rate / Connection: close")
    opt.add_row("--keepalive N", "requests per connection, 0 = never reconnect")
    opt.add_row("--rand-path / --read", "cache buster / read the status line")
    opt.add_row("--sockets / --interval-ms", "slowloris width and drip interval")
    opt.add_row("-v", "resolved target, effective caps, audit path")
    console.print(_panel("Flags", opt, border="yellow"))

    ex = Text("", style="white")
    ex.append("  hackit ddos lab --target http://127.0.0.1:8080 --profile syn,ack,http --waf\n", style="green")
    ex.append("  hackit ddos run --target https://staging.example/health \\\n"
              "      --scope scope.json --approval CHG-1234 --profile http,https \\\n"
              "      --method mixed --waf --rps 500 --workers 64 --duration 120 -v\n", style="green")
    ex.append("  hackit ddos run --target 203.0.113.10 --port 443 --profile syn,ack,rst \\\n"
              "      --scope scope.json --approval CHG-1234 --spoof --rps 200000\n", style="green")
    console.print(_panel("Examples", ex, border="green"))

    console.print(f"  [dim]caps  lab {LAB_MAX_RPS} rps / {LAB_MAX_PPS} pps  ·  "
                  f"hard {HARD_MAX_RPS} rps / {HARD_MAX_PPS} pps / {HARD_MAX_WORKERS} workers / "
                  f"{HARD_MAX_DURATION_S}s[/dim]")
    console.print(f"  [dim]audit {AUDIT_LOG}  ·  remote targets always require authorization[/dim]")
    console.print()


def _audit(record: dict) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        if AUDIT_LOG.exists() and AUDIT_LOG.stat().st_size > AUDIT_MAX_BYTES:
            keep = AUDIT_LOG.read_bytes()[-AUDIT_MAX_BYTES // 2:]
            AUDIT_LOG.with_suffix(".1.log").write_bytes(keep)
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


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(v, hi))


def _ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    from rich.prompt import Prompt
    raw = Prompt.ask(prompt, default=str(default))
    try:
        return _clamp(int(raw or default), lo, hi)
    except ValueError:
        console.print(f"[yellow]bukan angka — pakai {default}[/yellow]")
        return _clamp(default, lo, hi)


def _percentile(vals, p):
    if not vals:
        return 0.0
    idx = p / 100 * (len(vals) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(vals) - 1)
    return vals[lo] * (1 - (idx - lo)) + vals[hi] * (idx - lo)


def _ws_run(url: str, rps: int, workers: int, duration_s: int, on_progress) -> dict:
    try:
        try:
            from websockets.asyncio.client import connect as ws_connect
        except ImportError:
            from websockets import connect as ws_connect
    except ImportError:
        raise engines.EngineError("python package 'websockets' is not installed — pip install websockets")

    total = ok = err = 0
    rtts: list[float] = []
    start = time.monotonic()

    async def main():
        end = start + duration_s
        queue: asyncio.Queue = asyncio.Queue(maxsize=max(1, rps // 10))

        async def feeder():
            while time.monotonic() < end:
                try:
                    queue.put_nowait(1)
                except asyncio.QueueFull:
                    pass
                await asyncio.sleep(1.0 / rps)

        async def mon():
            while time.monotonic() < end:
                el = time.monotonic() - start
                on_progress({"elapsed_s": el, "requests": total, "ok": ok,
                             "errors": err, "achieved_rps": total / el if el else 0.0})
                await asyncio.sleep(0.5)

        async def worker():
            nonlocal total, ok, err
            while time.monotonic() < end:
                try:
                    await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                t0 = time.monotonic()
                try:
                    async with ws_connect(url, open_timeout=3, close_timeout=1) as ws:
                        await ws.send(f"ping-{uuid4().hex[:8]}")
                        try:
                            await asyncio.wait_for(ws.recv(), timeout=2.0)
                            total += 1
                            ok += 1
                            if len(rtts) < 100000:
                                rtts.append((time.monotonic() - t0) * 1000.0)
                        except asyncio.TimeoutError:
                            total += 1
                            err += 1
                except Exception:
                    total += 1
                    err += 1

        await asyncio.gather(feeder(), mon(), *[worker() for _ in range(workers)])

    asyncio.run(main())
    el = time.monotonic() - start
    rtts.sort()
    return {"type": "result", "engine": "python", "mode": "ws", "target": url,
            "method": "WS-TEXT", "duration_s": el, "requests": total, "ok": ok,
            "errors": err, "achieved_rps": total / el if el else 0.0,
            "error_rate": err / total if total else 0.0,
            "latency_ms": {"p50": _percentile(rtts, 50), "p90": _percentile(rtts, 90),
                           "p99": _percentile(rtts, 99), "max": rtts[-1] if rtts else 0.0}}


def _audit_meta(operator: str, approval_ref: str, profiles, target: str,
                rate: int, workers: int, duration_s: int, expires: str | None = None) -> dict:
    return {"tool": "hackit ddos", "operator": operator, "approval_ref": approval_ref,
            "scope_expires": expires, "profiles": list(profiles), "target": target,
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "effective": {"rate": rate, "workers": workers, "duration_s": duration_s}}


class _Dashboard:
    def __init__(self, *, label: str, target: str, profiles, rate: int,
                 workers: int, duration_s: int, started: float):
        self.label = label
        self.target = target
        self.profiles = list(profiles)
        self.rate = rate
        self.workers = workers
        self.duration_s = duration_s
        self.started = started
        self.lock = threading.Lock()
        self.state = {p: {"elapsed_s": 0.0, "requests": 0, "ok": 0, "errors": 0,
                          "achieved_rps": 0.0} for p in self.profiles}
        self.history: list[float] = []

    def update(self, profile: str, progress: dict) -> None:
        with self.lock:
            self.state[profile] = {
                "elapsed_s": float(progress.get("elapsed_s", 0.0)),
                "requests": int(progress.get("requests", 0)),
                "ok": int(progress.get("ok", 0)),
                "errors": int(progress.get("errors", 0)),
                "achieved_rps": float(progress.get("achieved_rps", 0.0)),
            }
            total = sum(s["achieved_rps"] for s in self.state.values())
            self.history.append(total)
            self.history = self.history[-60:]

    def totals(self) -> tuple[int, int, int, float]:
        with self.lock:
            req = sum(s["requests"] for s in self.state.values())
            ok = sum(s["ok"] for s in self.state.values())
            err = sum(s["errors"] for s in self.state.values())
            rps = sum(s["achieved_rps"] for s in self.state.values())
            el = max((s["elapsed_s"] for s in self.state.values()), default=0.0)
        return req, ok, err, rps if rps else 0.0, el

    def _bar(self, frac: float, width: int = 34) -> Text:
        frac = max(0.0, min(1.0, frac))
        filled = int(frac * width)
        t = Text()
        t.append("━" * filled, style="bold cyan")
        t.append("─" * (width - filled), style="dim")
        return t

    def _spark(self, width: int = 34) -> Text:
        if not self.history:
            return Text("·" * width, style="dim")
        peak = max(max(self.history), 1.0)
        ramp = "▁▂▃▄▅▆▇█"
        step = max(1, len(self.history) // width)
        out = Text()
        for v in self.history[::step][-width:]:
            out.append(ramp[min(len(ramp) - 1, int(v / peak * (len(ramp) - 1)))], style="cyan")
        return out

    def render(self) -> Panel:
        req, ok, err, rps, el = self.totals()
        frac = el / self.duration_s if self.duration_s else 0.0
        err_rate = (err / req * 100) if req else 0.0

        g = Table.grid(padding=(0, 2))
        g.add_column(style="dim", no_wrap=True)
        g.add_column()
        g.add_row("target", Text(self.target, style="bold white"))
        g.add_row("vectors", Text(", ".join(self.profiles), style="magenta"))
        g.add_row("elapsed", Text(f"{el:.1f}s / {self.duration_s}s"))
        g.add_row("progress", self._bar(frac))
        g.add_row("throughput", self._spark())
        g.add_row("sent", Text(f"{req}", style="bold"))
        g.add_row("ok / err", Text.assemble((f"{ok}", "green"), (" / ", "dim"),
                                            (f"{err}", "red" if err else "green"),
                                            (f"  ({err_rate:.2f}%)", "dim")))
        g.add_row("achieved", Text(f"{rps:.1f} op/s", style="bold cyan"))

        per = Table.grid(padding=(0, 2))
        per.add_column(style="dim", no_wrap=True)
        per.add_column(justify="right")
        for p in self.profiles:
            s = self.state[p]
            per.add_row(p, Text(f"{s['achieved_rps']:.1f}/s  err {s['errors']}", style="white"))

        return Panel(Group(g, Text(""), per), title=f"[bold cyan]LIVE — {self.label}[/bold cyan]",
                     border_style="cyan", box=box.ROUNDED, padding=(0, 1))


def _final_report(reports: dict, *, label: str, rate_cap: int, workers: int,
                  verbose: bool, meta: dict | None = None) -> None:
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False)
    for col, just in (("vector", "left"), ("req", "right"), ("ok", "right"),
                      ("err", "right"), ("op/s", "right"), ("p50", "right"),
                      ("p99", "right")):
        table.add_column(col, justify=just)

    tot_req = tot_ok = tot_err = 0
    p50s, p99s = [], []
    for name, r in reports.items():
        lat = r.get("latency_ms") or {}
        table.add_row(name, str(r.get("requests", 0)), str(r.get("ok", 0)),
                      str(r.get("errors", 0)), f"{float(r.get('achieved_rps', 0.0)):.1f}",
                      f"{float(lat.get('p50', 0.0)):.1f}ms", f"{float(lat.get('p99', 0.0)):.1f}ms")
        tot_req += int(r.get("requests", 0))
        tot_ok += int(r.get("ok", 0))
        tot_err += int(r.get("errors", 0))
        p50s.append(float(lat.get("p50", 0.0)))
        p99s.append(float(lat.get("p99", 0.0)))

    err_rate = (tot_err / tot_req * 100) if tot_req else 0.0
    head = Table.grid(padding=(0, 2))
    head.add_column(style="dim", no_wrap=True)
    head.add_column()
    head.add_row("target", Text(str(meta.get("target", "?")) if meta else "?", style="bold white"))
    head.add_row("vectors", Text(", ".join(reports), style="magenta"))
    head.add_row("caps", Text(f"{rate_cap}/s   {workers} workers", style="white"))
    head.add_row("totals", Text(f"{tot_req} sent   ok {tot_ok}   err {tot_err}   ({err_rate:.2f}%)",
                                style="white"))
    head.add_row("p50 / p99 worst", Text(f"{max(p50s or [0]):.1f}ms / {max(p99s or [0]):.1f}ms",
                                         style="cyan"))

    console.print(Panel(Group(head, Text(""), table), title=f"[bold green]RESULT — {label}[/bold green]",
                        border_style="green", box=box.ROUNDED, padding=(0, 1)))

    if verbose and meta:
        d = Table.grid(padding=(0, 2))
        d.add_column(style="dim", no_wrap=True)
        d.add_column(style="white")
        d.add_row("operator", str(meta.get("operator")))
        d.add_row("approval", str(meta.get("approval_ref")))
        if meta.get("scope_expires"):
            d.add_row("scope expires", str(meta.get("scope_expires")))
        d.add_row("started (UTC)", str(meta.get("started_utc")))
        d.add_row("audit log", str(AUDIT_LOG))
        console.print(Panel(d, title="[dim]verbose[/dim]", border_style="dim", box=box.ROUNDED))


def _run_one(profile: str, *, target, method, body, port, ramp, force_close, raw_path,
             rate, workers, duration, timeout_ms, dns_name, dns_type, dns_server,
             udp_payload, udp_echo, spoof, keepalive, rand_path, read_reply, size,
             sockets, interval_ms, waf, on_progress) -> dict:
    host = _host_of(target)

    if profile in L4_PROFILES:
        mode = {"udp-flood": "udp", "icmp-flood": "icmp"}.get(profile, profile)
        return engines.run_flood(mode, host, port, rate=rate, threads=workers,
                                 duration_s=duration, size=size, spoof=spoof,
                                 path=raw_path, method=method, keepalive=keepalive,
                                 rand_path=rand_path, read_reply=read_reply,
                                 tls=port == 443, waf=waf, on_progress=on_progress)

    if profile in ("http", "https"):
        return engines.run_go(_http_url(target), method.upper(), rps=rate, workers=workers,
                              duration_s=duration, timeout_ms=timeout_ms, body=body,
                              ramp_s=ramp, force_close=force_close, mode="http",
                              waf=waf, on_progress=on_progress)
    if profile == "http-raw":
        return engines.run_c("http", host, port, rps=rate, workers=workers,
                             duration_s=duration, path=raw_path, method=method,
                             body=body, tls=port == 443, waf=waf, on_progress=on_progress)
    if profile == "slowloris":
        return engines.run_slowloris(host, port, sockets=sockets, threads=workers,
                                     duration_s=duration, interval_ms=interval_ms,
                                     path=raw_path, tls=port == 443, waf=waf,
                                     on_progress=on_progress)
    if profile == "tcp":
        return engines.run_c("tcp", host, port, rps=rate, workers=workers,
                             duration_s=duration, on_progress=on_progress)
    if profile == "dns":
        if not dns_name:
            raise engines.EngineError("dns profile requires --dns-name")
        srv = "" if target.lower() == "system" else target
        return engines.run_go("", "", rps=rate, workers=workers, duration_s=duration,
                              timeout_ms=timeout_ms, ramp_s=ramp, mode="dns",
                              dns_name=dns_name, dns_type=dns_type.upper(),
                              dns_server=srv, waf=waf, on_progress=on_progress)
    if profile == "udp":
        ut = target if ":" in target else f"{target}:{port}"
        return engines.run_go(ut, "", rps=rate, workers=workers, duration_s=duration,
                              timeout_ms=timeout_ms, ramp_s=ramp, mode="udp",
                              udp_payload=udp_payload, udp_echo=udp_echo, waf=waf,
                              on_progress=on_progress)
    if profile == "ws":
        if not target.lower().startswith(("ws://", "wss://")):
            raise engines.EngineError("ws profile needs a ws:// or wss:// URL")
        return _ws_run(target, rate, workers, duration, on_progress)
    raise engines.EngineError(f"unknown profile: {profile}")


def _execute(*, label: str, profiles, target: str, method: str, body: str, port: int,
             ramp: int, force_close: bool, rate: int, workers: int, duration: int,
             timeout_ms: int, meta: dict, verbose: bool, output: str | None,
             raw_path: str = "/", dns_name: str = "", dns_type: str = "A",
             dns_server: str = "", udp_payload: str = "hackit-ddos-probe",
             udp_echo: bool = True, spoof: bool = False, keepalive: int = 1,
             rand_path: bool = False, read_reply: bool = False, size: int = 64,
             sockets: int = 1000, interval_ms: int = 8000, waf: bool = False) -> None:
    profiles = list(profiles)
    started = time.monotonic()
    dash = _Dashboard(label=label, target=target, profiles=profiles, rate=rate,
                      workers=workers, duration_s=duration, started=started)

    meta = {**meta, "started_utc": datetime.now(timezone.utc).isoformat()}
    try:
        _audit(meta)
    except ScopeError as exc:
        console.print(f"[bold red]refused[/bold red] — {exc}")
        sys.exit(2)

    if verbose:
        console.print(f"[dim]resolved[/dim] {_host_of(target)}   [dim]audit[/dim] {AUDIT_LOG}")
        console.print(f"[dim]caps[/dim] {rate}/s   {workers} workers   {duration}s")

    reports: dict[str, dict] = {}
    failures: list[str] = []
    lock = threading.Lock()
    tty = console.is_terminal

    def make_progress(p: str):
        def cb(data: dict) -> None:
            dash.update(p, data)
            if not tty:
                s = dash.state[p]
                console.print(f"[dim]{p} t={s['elapsed_s']:.1f}s[/dim] sent {s['requests']} · "
                              f"ok {s['ok']} · err {s['errors']} · {s['achieved_rps']:.1f}/s")
        return cb

    def run_one(p: str) -> None:
        try:
            r = _run_one(p, target=target, method=method, body=body, port=port, ramp=ramp,
                         force_close=force_close, raw_path=raw_path, rate=rate,
                         workers=max(1, workers // len(profiles)), duration=duration,
                         timeout_ms=timeout_ms, dns_name=dns_name, dns_type=dns_type,
                         dns_server=dns_server, udp_payload=udp_payload, udp_echo=udp_echo,
                         spoof=spoof, keepalive=keepalive, rand_path=rand_path,
                         read_reply=read_reply, size=size, sockets=sockets,
                         interval_ms=interval_ms, waf=waf, on_progress=make_progress(p))
            with lock:
                reports[p] = r
        except engines.EngineError as exc:
            with lock:
                failures.append(f"{p}: {exc}")

    threads = [threading.Thread(target=run_one, args=(p,), daemon=True) for p in profiles]

    if tty:
        with Live(dash.render(), console=console, refresh_per_second=8) as live:
            for t in threads:
                t.start()
            while any(t.is_alive() for t in threads):
                live.update(dash.render())
                time.sleep(0.125)
    else:
        for t in threads:
            t.start()
    for t in threads:
        t.join()

    for f in failures:
        console.print(f"[bold red]vector failed[/bold red] — {f}")
    if not reports:
        sys.exit(1)

    _final_report(reports, label=label, rate_cap=rate, workers=workers,
                  verbose=verbose, meta=meta)

    if output:
        Path(output).write_text(json.dumps({"meta": meta, "results": reports}, indent=2) + "\n",
                                encoding="utf-8")
        console.print(f"[dim]report written to {output}[/dim]")


@click.group(invoke_without_command=True)
@click.pass_context
def ddos(ctx: click.Context):
    """Authorized resilience testing — scoped, capped, audited, multi-vector."""
    if ctx.invoked_subcommand is None:
        _print_help()


@ddos.command()
def build():
    """Compile every engine."""
    for label, fn in (("go", engines.build_go), ("c", engines.build_c),
                      ("flood", engines.build_flood), ("slowloris", engines.build_slowloris)):
        try:
            path = fn()
        except engines.EngineError as exc:
            console.print(f"[bold red]fail[/bold red] {label}: {exc}")
            sys.exit(1)
        console.print(f"[green]ok[/green]   {label}: {path}")


@ddos.command()
@click.option("--scope", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--target", required=True)
@click.option("--approval", required=True)
@click.option("--profile", default="http")
def check(scope, target, approval, profile):
    """Validate scope, target and approval without generating load."""
    try:
        sc = load_scope(scope)
        check_run(sc, _host_of(target), approval)
    except ScopeError as exc:
        console.print(f"[bold red]refused[/bold red] — {exc}")
        sys.exit(2)
    body = Text()
    body.append(f"operator       {sc.operator}\n")
    body.append(f"approval       {sc.approval_ref}   expires {sc.expires.isoformat()}\n")
    body.append(f"allowlist      {', '.join(sc.targets)}\n")
    body.append(f"caps           rps ≤ {sc.max_rps}/s   pps ≤ {sc.max_pps}/s   "
                f"workers ≤ {sc.max_workers}   duration ≤ {sc.max_duration_s}s\n")
    body.append(f"hard ceilings  {HARD_MAX_RPS}/{HARD_MAX_PPS}/{HARD_MAX_WORKERS}/{HARD_MAX_DURATION_S}",
                style="dim")
    console.print(Panel(body, title="[bold green]scope valid[/bold green]", border_style="green",
                        box=box.ROUNDED))


def _profile_opt(default="http"):
    return click.option("--profile", default=default, show_default=True,
                        help="Comma-separated profiles to run in parallel.")


@ddos.command()
@click.option("--target", required=True)
@click.option("--scope", type=click.Path(exists=True, dir_okay=False))
@click.option("--approval")
@_profile_opt()
@click.option("--port", default=80, show_default=True, type=int)
@click.option("--dns-name", default="")
@click.option("--dns-type", type=click.Choice(["A", "AAAA", "MX", "TXT", "NS"]), default="A")
@click.option("--udp-payload", default="hackit-ddos-probe")
@click.option("--udp-no-echo", is_flag=True)
@click.option("--method", type=click.Choice(HTTP_METHODS), default="get", show_default=True)
@click.option("--body", default="")
@click.option("--ramp", default=0, type=int)
@click.option("--close", "force_close", is_flag=True)
@click.option("--path", default="/", show_default=True)
@click.option("--rps", default=50, show_default=True, type=int,
              help="Rate cap: requests/s (L7) or packets/s (L4).")
@click.option("--workers", default=10, show_default=True, type=int)
@click.option("--duration", default=10, show_default=True, type=int)
@click.option("--timeout-ms", default=5000, show_default=True, type=int)
@click.option("--spoof", is_flag=True)
@click.option("--waf", is_flag=True)
@click.option("--keepalive", default=1, show_default=True, type=int)
@click.option("--rand-path", is_flag=True)
@click.option("--read", "read_reply", is_flag=True)
@click.option("--size", default=64, show_default=True, type=int)
@click.option("--sockets", default=1000, show_default=True, type=int)
@click.option("--interval-ms", default=8000, show_default=True, type=int)
@click.option("--output", type=click.Path(dir_okay=False))
@click.option("-v", "--verbose", is_flag=True)
def run(target, scope, approval, profile, port, method, body, ramp, force_close, path,
        rps, workers, duration, timeout_ms, output, verbose, dns_name, dns_type,
        udp_payload, udp_no_echo, spoof, waf, keepalive, rand_path, read_reply,
        size, sockets, interval_ms):
    """Run a scripted load test. Remote targets require --scope and --approval."""
    profiles = [p.strip().lower() for p in profile.split(",") if p.strip()]
    unknown = [p for p in profiles if p not in ALL_PROFILES]
    if unknown:
        console.print(f"[bold red]refused[/bold red] — unknown profile(s): {', '.join(unknown)}")
        sys.exit(2)

    host = _host_of(target)
    loopback = (target.lower() == "system") or _is_loopback(host)

    if "dns" in profiles and not dns_name:
        console.print("[bold red]refused[/bold red] — dns profile requires --dns-name")
        sys.exit(2)

    if loopback:
        cap = LAB_MAX_PPS if any(is_l4(p) for p in profiles) else LAB_MAX_RPS
        rate = min(rps, cap)
        w = min(workers, LAB_MAX_WORKERS)
        dur = min(duration, LAB_MAX_DURATION_S)
        meta = _audit_meta("local", "lab-loopback", profiles, target, rate, w, dur)
    else:
        if not scope or not approval:
            console.print("[bold red]refused[/bold red] — remote targets require --scope and --approval")
            sys.exit(2)
        try:
            sc = load_scope(scope)
            check_run(sc, host, approval)
            lim = effective_limits(sc, profiles, rps, workers, duration)
        except ScopeError as exc:
            console.print(f"[bold red]refused[/bold red] — {exc}")
            sys.exit(2)
        rate, w, dur = lim.rate, lim.workers, lim.duration_s
        meta = _audit_meta(sc.operator, sc.approval_ref, profiles, target, rate, w, dur,
                           sc.expires.isoformat())

    _execute(label="scoped run" if not loopback else "loopback", profiles=profiles,
             target=target, method=method, body=body, port=port, ramp=ramp,
             force_close=force_close, rate=rate, workers=w, duration=dur,
             timeout_ms=timeout_ms, meta=meta, verbose=verbose, output=output,
             raw_path=path, dns_name=dns_name, dns_type=dns_type, dns_server=target,
             udp_payload=udp_payload, udp_echo=not udp_no_echo, spoof=spoof,
             keepalive=keepalive, rand_path=rand_path, read_reply=read_reply,
             size=size, sockets=sockets, interval_ms=interval_ms, waf=waf)


@ddos.command()
@click.option("--target", required=True)
@_profile_opt()
@click.option("--port", default=80, show_default=True, type=int)
@click.option("--dns-name", default="")
@click.option("--dns-type", type=click.Choice(["A", "AAAA", "MX", "TXT", "NS"]), default="A")
@click.option("--udp-payload", default="hackit-ddos-probe")
@click.option("--udp-no-echo", is_flag=True)
@click.option("--method", type=click.Choice(HTTP_METHODS), default="get", show_default=True)
@click.option("--body", default="")
@click.option("--ramp", default=0, type=int)
@click.option("--close", "force_close", is_flag=True)
@click.option("--rps", default=20, show_default=True, type=int)
@click.option("--workers", default=4, show_default=True, type=int)
@click.option("--duration", default=5, show_default=True, type=int)
@click.option("--spoof", is_flag=True)
@click.option("--waf", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def lab(target, profile, port, dns_name, dns_type, udp_payload, udp_no_echo, method,
        body, ramp, force_close, rps, workers, duration, spoof, waf, verbose):
    """Loopback-only smoke test. No scope file, tight caps."""
    profiles = [p.strip().lower() for p in profile.split(",") if p.strip()]
    host = _host_of(target)
    if target.lower() != "system" and not _is_loopback(host):
        console.print("[bold red]refused[/bold red] — lab mode is loopback-only")
        sys.exit(2)
    if "dns" in profiles and not dns_name:
        console.print("[bold red]refused[/bold red] — dns profile requires --dns-name")
        sys.exit(2)

    cap = LAB_MAX_PPS if any(is_l4(p) for p in profiles) else LAB_MAX_RPS
    rate = min(rps, cap)
    w = min(workers, LAB_MAX_WORKERS)
    dur = min(duration, LAB_MAX_DURATION_S)
    meta = _audit_meta("local", "lab-loopback", profiles, target, rate, w, dur)

    _execute(label="loopback lab", profiles=profiles, target=target, method=method,
             body=body, port=port, ramp=ramp, force_close=force_close, rate=rate,
             workers=w, duration=dur, timeout_ms=2000, meta=meta, verbose=verbose,
             output=None, dns_name=dns_name, dns_type=dns_type, dns_server=target,
             udp_payload=udp_payload, udp_echo=not udp_no_echo, spoof=spoof, waf=waf)


@ddos.command(name="console")
def ddos_console():
    """Interactive console — enter a target, engines work."""
    from rich.prompt import Prompt

    console.print()
    console.print(_banner())
    console.print("  [dim]Loopback targets run immediately. Remote targets need a typed 'yes'.[/dim]")
    console.print()

    while True:
        raw = Prompt.ask("[bold cyan]target domain/IP[/bold cyan] (empty to quit)",
                         default="", show_default=False).strip()
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
            console.print(f"\n  [bold yellow]'{host}' is remote.[/bold yellow] Real load.")
            if Prompt.ask("  Type [bold]yes[/bold] to confirm permission",
                          default="no").strip().lower() != AUTH_PHRASE:
                console.print("[bold red]refused[/bold red] — nothing sent.\n")
                continue

        prof_raw = Prompt.ask("profile(s), comma-separated",
                              default="http").strip().lower()
        profiles = [p.strip() for p in prof_raw.split(",") if p.strip() in ALL_PROFILES]
        if not profiles:
            console.print("[bold red]refused[/bold red] — no valid profile")
            continue

        port = 80
        method = "get"
        body = ""
        dns_name = ""
        dns_type = "A"
        if any(is_l4(p) for p in profiles) or "http-raw" in profiles or "slowloris" in profiles:
            port = _ask_int("port", 80 if "slowloris" not in profiles else 80, 1, 65535)
        if "http" in profiles or "http-raw" in profiles:
            method = Prompt.ask("method", choices=HTTP_METHODS, default="get")
            if method in ("post", "put", "patch"):
                body = Prompt.ask("body (empty for none)", default="")
        if "dns" in profiles:
            dns_name = Prompt.ask("dns name", default="localhost")
            dns_type = Prompt.ask("record type", choices=["A", "AAAA", "MX", "TXT", "NS"], default="A")
        if "ws" in profiles and not raw.lower().startswith(("ws://", "wss://")):
            console.print("[bold red]refused[/bold red] — ws target needs ws:// or wss://")
            continue

        use_waf = Prompt.ask("waf bypass", choices=["y", "n"], default="y") == "y"
        use_spoof = False
        if any(is_l4(p) for p in profiles):
            use_spoof = Prompt.ask("spoof source IP (needs root)",
                                   choices=["y", "n"], default="y") == "y"

        dur = _ask_int("duration (s)", INTERACTIVE_DEFAULT_DURATION_S, 1, INTERACTIVE_MAX_DURATION_S)
        cap_hi = INTERACTIVE_MAX_PPS if any(is_l4(p) for p in profiles) else INTERACTIVE_MAX_RPS
        dflt = INTERACTIVE_DEFAULT_PPS if any(is_l4(p) for p in profiles) else INTERACTIVE_DEFAULT_RPS
        rate = _ask_int("rate cap", dflt, 1, cap_hi)
        workers = _ask_int("workers", INTERACTIVE_DEFAULT_WORKERS, 1, INTERACTIVE_MAX_WORKERS)

        meta = _audit_meta("interactive", "interactive-confirmed" if remote else "lab-loopback",
                           profiles, raw, rate, workers, dur)
        _execute(label="interactive", profiles=profiles, target=raw, method=method,
                 body=body, port=port, ramp=0, force_close=False, rate=rate,
                 workers=workers, duration=dur, timeout_ms=3000, meta=meta,
                 verbose=False, output=None, dns_name=dns_name, dns_type=dns_type,
                 dns_server=raw, udp_payload="hackit-ddos-probe", udp_echo=True,
                 spoof=use_spoof, waf=use_waf)
        console.print()
        if Prompt.ask("test another target?", choices=["y", "n"], default="n") != "y":
            console.print("[dim]rail cold — bye.[/dim]")
            return