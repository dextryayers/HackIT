"""themes.py — rotating CLI presentation layer for long-running wireless attacks.

Multiple distinct themes per phase (deauth / capture / eviltwin / crack), picked
per invocation so the operator never sees the same layout twice in a row. Within
one invocation the theme can rotate on a schedule.

Every theme is `theme(state: dict, tick: int) -> Renderable`. Pure presentation.
No engine calls. `LiveOrchestra` wraps a Rich `Live` and rebuilds the panel each
tick from the shared `state` dict the executor updates.
"""
from __future__ import annotations

import math
import random
import time
from typing import Callable, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_console = Console()

# ── Shared glyph + color vocabulary ──────────────────────────────────────
GLYPHS_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
GLYPHS_PULSE = "◓◑◒◔"
GLYPHS_FLOW = "▁▂▃▄▅▆▇█"
GLYPHS_BLOCKS = " ░▒▓█"


def _spin(tick: int) -> str:
    return GLYPHS_SPIN[tick % len(GLYPHS_SPIN)]


def _pulse(tick: int) -> str:
    return GLYPHS_PULSE[tick % len(GLYPHS_PULSE)]


def _human_rate(pps: float) -> str:
    if pps >= 1_000_000:
        return f"{pps/1_000_000:.1f}M pps"
    if pps >= 1_000:
        return f"{pps/1_000:.1f}k pps"
    return f"{pps:.0f} pps"


def _rate_bar(pps: float, width: int = 28, peak: float = 2000.0) -> Text:
    ratio = min(1.0, max(0.0, pps / max(peak, 1.0)))
    filled = int(ratio * width)
    bar = "█" * filled + "░" * (width - filled)
    color = "bright_red" if ratio > 0.75 else "bright_yellow" if ratio > 0.4 else "bright_cyan"
    text = Text()
    text.append(bar, style=f"bold {color}")
    text.append(" ")
    text.append(_human_rate(pps), style="bold white")
    return text


def _channel_strip(active: Optional[int], bands=("2.4", "5")) -> Text:
    text = Text()
    for ch in range(1, 14):
        style = "bold bright_red" if ch == active else "dim"
        text.append(f"{ch:>2}" + (" " if ch != 13 else ""), style=style)
    if "5" in bands:
        text.append("\n")
        for ch in (36, 40, 44, 48, 52, 56, 60, 64, 100, 112, 116, 132, 149, 157, 165):
            style = "bold bright_red" if ch == active else "dim"
            text.append(f"{ch:>3} ", style=style)
    return text


def _fit(text: str, maxlen: int) -> str:
    if len(text) <= maxlen:
        return text
    return text[: maxlen - 1] + "…"


# ════════════════════════════════════════════════════════════════════════
# DEAUTH THEMES
# ════════════════════════════════════════════════════════════════════════
def deauth_theme_radar(state: dict, tick: int) -> Panel:
    bssid = state.get("bssid", "-")
    frames = state.get("frames", 0)
    pps = state.get("pps", 0.0)
    elapsed = state.get("elapsed", 0.0)
    errors = state.get("errors", 0)
    channel = state.get("channel")
    targeted = state.get("station") or "bcast"
    band_mode = state.get("band", "2.4+5")
    reason = state.get("reason", "rot")

    header = Text()
    header.append("◉ ", style="bold bright_red")
    header.append("DEAUTH ACTIVE", style="bold bright_red")
    header.append(f"   {band_mode}", style="dim")
    header.append("   target ", style="dim")
    header.append(_fit(bssid, 18), style="bold white")
    header.append("  <- ", style="dim")
    header.append(_fit(targeted, 18), style="bright_cyan")

    body = Table.grid(expand=True, padding=(0, 2))
    body.add_column(ratio=2)
    body.add_column(ratio=1, justify="right")
    body.add_row(
        Text.from_markup(f"[bold bright_red]{_pulse(tick)}[/] {frames:,} frames"),
        Text.from_markup(f"[dim]{elapsed:.0f}s[/]"),
    )
    body.add_row(_rate_bar(pps), Text.from_markup(f"[dim]err {errors}[/]"))
    body.add_row(
        _channel_strip(channel, band_mode),
        Text.from_markup(f"[bold white]ch[/] {channel or '-'}\n[bold white]rsn[/] {reason}"),
    )
    return Panel(body, title=header, border_style="bold bright_red", padding=(0, 1))


def deauth_theme_minimal(state: dict, tick: int) -> Panel:
    frames = state.get("frames", 0)
    pps = state.get("pps", 0.0)
    elapsed = state.get("elapsed", 0.0)
    channel = state.get("channel", "-")
    bssid = state.get("bssid", "-")

    line = Text()
    line.append(_spin(tick) + " ", style="bold bright_red")
    line.append(f"{frames:>10,} frames", style="bold white")
    line.append("  |  ", style="dim")
    line.append(_human_rate(pps), style="bright_yellow")
    line.append("  |  ", style="dim")
    line.append(f"ch {channel}", style="bright_cyan")
    line.append("  |  ", style="dim")
    line.append(f"{elapsed:>5.0f}s", style="dim")
    line.append("  |  ", style="dim")
    line.append(_fit(bssid, 20), style="bright_white")
    return Panel(Align.left(line), border_style="red", padding=(0, 1), title="deauth")


def deauth_theme_matrix(state: dict, tick: int) -> Panel:
    bssid = state.get("bssid", "-")
    frames = state.get("frames", 0)
    pps = state.get("pps", 0.0)
    errors = state.get("errors", 0)
    channel = state.get("channel", "-")
    elapsed = state.get("elapsed", 0.0)

    bars_row = Text()
    seed = (frames * 31 + tick * 7) & 0xFFFF
    for i in range(40):
        level = ((seed >> (i % 13)) ^ (i * 3)) & 0x7
        bars_row.append(GLYPHS_FLOW[level], style="bright_green")

    stat = Table.grid(expand=True, padding=(0, 2))
    stat.add_column(ratio=1)
    stat.add_column(ratio=1)
    stat.add_row(
        Text.from_markup(f"[bold bright_green]{frames:>10,}[/] frames"),
        Text.from_markup(f"[bold bright_yellow]{_human_rate(pps)}[/]"),
    )
    stat.add_row(
        Text.from_markup(f"[dim]ch[/] [bright_cyan]{channel}[/]"),
        Text.from_markup(f"[dim]errors[/] [red]{errors}[/]"),
    )
    stat.add_row(
        Text.from_markup(f"[dim]elapsed[/] {elapsed:.0f}s"),
        Text.from_markup(f"[dim]target[/] {_fit(bssid, 17)}"),
    )
    body = Group(bars_row, Text(""), stat)
    return Panel(body, title=f"[bold bright_green]{_spin(tick)} DEAUTH FLOW[/]",
                 border_style="bright_green", padding=(0, 1))


def deauth_theme_combat(state: dict, tick: int) -> Panel:
    bssid = state.get("bssid", "-")
    frames = state.get("frames", 0)
    pps = state.get("pps", 0.0)
    channel = state.get("channel", "-")
    station = state.get("station", "bcast")
    elapsed = state.get("elapsed", 0.0)
    targeted = station and station.lower() not in ("ff:ff:ff:ff:ff:ff", "bcast")

    left = Text()
    left.append("TARGET\n", style="bright_red")
    left.append(f"{bssid}\n", style="bold white")
    left.append(f"-> {station}\n", style="bright_cyan")
    left.append(f"type {'unicast' if targeted else 'broadcast'}\n", style="dim")
    left.append(f"ch {channel}\n", style="bright_yellow")

    center = Text()
    center.append(f"{frames:,}", style="bold bright_red")
    center.append(" frames fired\n", style="dim")
    center.append(f"{_human_rate(pps)}\n", style="bold bright_yellow")
    center.append(f"{elapsed:.0f}s uptime", style="dim")

    right = Text()
    right.append("WAVE\n", style="bright_magenta")
    wave = "".join(
        GLYPHS_FLOW[int((math.sin((tick + i) * 0.4) + 1) * 3.5)] for i in range(10)
    )
    right.append(wave + "\n", style="bright_magenta")
    right.append(f"rst {state.get('reason', 'rot')}\n", style="dim")
    right.append(f"err {state.get('errors', 0)}", style="red")

    layout = Table.grid(expand=True, padding=(0, 2))
    layout.add_column(ratio=1)
    layout.add_column(ratio=1, justify="center")
    layout.add_column(ratio=1)
    layout.add_row(left, center, right)
    return Panel(layout, title=f"[bold bright_red]{_spin(tick)} DEAUTH HUD[/]",
                 border_style="bright_red", padding=(0, 1))


DEAUTH_THEMES = {
    "radar": deauth_theme_radar,
    "minimal": deauth_theme_minimal,
    "matrix": deauth_theme_matrix,
    "combat": deauth_theme_combat,
}


# ════════════════════════════════════════════════════════════════════════
# CAPTURE THEMES
# ════════════════════════════════════════════════════════════════════════
def capture_theme_scanner(state: dict, tick: int) -> Panel:
    ssid = state.get("ssid", "<any>")
    bssid = state.get("bssid", "<any>")
    frames = state.get("frames", 0)
    eapol = state.get("eapols", 0)
    pmkid = state.get("pmkid", 0)
    elapsed = state.get("elapsed", 0.0)
    status = state.get("status", "hunting")

    body = Table.grid(expand=True, padding=(0, 2))
    body.add_column(ratio=1)
    body.add_column(ratio=1, justify="right")
    body.add_row(
        Text.from_markup(f"[bold bright_cyan]{_spin(tick)} CAPTURE[/]  [dim]{status}[/]"),
        Text.from_markup(f"[dim]{elapsed:.0f}s[/]"),
    )
    body.add_row(
        Text.from_markup(f"[bold white]SSID[/]  {_fit(ssid, 24)}"),
        Text.from_markup(f"[bold white]BSSID[/]  {_fit(bssid, 20)}"),
    )
    body.add_row(
        Text.from_markup(f"[bright_cyan]frames[/]  {frames:,}"),
        Text.from_markup(f"[bright_yellow]EAPOL[/]  [bold]{eapol}[/]"),
    )
    body.add_row(
        Text.from_markup(f"[bright_magenta]PMKID[/]  {pmkid}"),
        Text.from_markup("[dim]running[/]"),
    )

    stages = ["probe", "auth", "assoc", "4-way #1", "4-way #2", "MIC"]
    line = Text()
    done_set = state.get("stage_done", set())
    for i, s in enumerate(stages):
        has = (eapol >= (i + 1)) or (i in done_set)
        line.append("OK " if has else "-- ", style="bold bright_green" if has else "dim")
        line.append(s, style="white" if has else "dim")
        line.append("  ")

    return Panel(Group(body, Text(""), line),
                 title="[bold bright_cyan]WPA HANDSHAKE CAPTURE[/]",
                 border_style="bright_cyan", padding=(0, 1))


def capture_theme_list(state: dict, tick: int) -> Panel:
    ssid = state.get("ssid", "<any>")
    bssid = state.get("bssid", "<any>")
    frames = state.get("frames", 0)
    eapol = state.get("eapols", 0)
    pmkid = state.get("pmkid", 0)
    elapsed = state.get("elapsed", 0.0)

    events = state.get("events", [])
    stream = Text()
    for ev in events[-6:]:
        ts = ev.get("t", 0.0)
        kind = ev.get("kind", "?")
        detail = ev.get("detail", "")
        style = "bright_green" if ("eapol" in kind.lower() or "pmkid" in kind.lower()) else "dim"
        stream.append(f"  {ts:>6.1f}s  ", style="dim")
        stream.append(f"{kind:>10} ", style=style)
        stream.append(_fit(detail, 30) + "\n", style="white")
    if not events:
        stream.append("  waiting for the first event...\n", style="dim")

    head = Text.from_markup(
        f"[bold bright_yellow]{_pulse(tick)}[/] "
        f"[bold]{_fit(ssid, 20)}[/] -> [dim]{_fit(bssid, 17)}[/] "
        f" [bright_cyan]{frames:,}f[/] [bright_yellow]{eapol}E[/] "
        f"[bright_magenta]{pmkid}P[/] [dim]{elapsed:.0f}s[/]"
    )
    return Panel(Group(head, Text(""), stream),
                 title="[bold bright_yellow]CAPTURE LOG[/]",
                 border_style="bright_yellow", padding=(0, 1))


def capture_theme_waterfall(state: dict, tick: int) -> Panel:
    frames = state.get("frames", 0)
    eapol = state.get("eapols", 0)
    ssid = state.get("ssid", "<any>")
    pps = state.get("pps", 0.0)

    lines = []
    for row in range(8):
        seed = (frames * 13 + row * 97 + tick * 3) & 0xFFFF
        bar = [GLYPHS_BLOCKS[(seed >> (i * 2)) & 0x3] for i in range(40)]
        col = "bright_cyan" if row % 2 == 0 else "cyan"
        lines.append(Text("".join(bar), style=col))
    if eapol > 0:
        lines.append(Text(f"   !! {eapol} EAPOL captured   ", style="bold bright_red"))

    head = Text.from_markup(
        f"[bold bright_cyan]{_spin(tick)}[/] [bold]{_fit(ssid, 24)}[/]  "
        f"[bright_yellow]{frames:,}[/] frames  [bold bright_red]{eapol}[/] EAPOL  "
        f"[dim]{_human_rate(pps)}[/]"
    )
    return Panel(Group(head, Text(""), *lines),
                 title="[bold bright_cyan]CAPTURE WATERFALL[/]",
                 border_style="bright_cyan", padding=(0, 1))


CAPTURE_THEMES = {
    "scanner": capture_theme_scanner,
    "list": capture_theme_list,
    "waterfall": capture_theme_waterfall,
}


# ════════════════════════════════════════════════════════════════════════
# EVILTWIN THEMES
# ════════════════════════════════════════════════════════════════════════
def eviltwin_theme_dashboard(state: dict, tick: int) -> Panel:
    ssids = state.get("ssids", [])
    clients = state.get("clients", [])
    creds = state.get("creds", [])
    beacons = state.get("beacons", 0)
    deauths = state.get("deauths", 0)
    elapsed = state.get("elapsed", 0.0)

    ssid_tbl = Table.grid(padding=(0, 1))
    ssid_tbl.add_column(width=2)
    ssid_tbl.add_column()
    for i, s in enumerate(ssids[:6]):
        marker = "*" if i == 0 else "-"
        style = "bold bright_magenta" if i == 0 else "white"
        ssid_tbl.add_row(Text(marker, style=style), Text(_fit(s, 22), style=style))
    if len(ssids) > 6:
        ssid_tbl.add_row(Text("+", style="dim"), Text(f"{len(ssids) - 6} more", style="dim"))

    cli_tbl = Table.grid(padding=(0, 1))
    cli_tbl.add_column()
    for cli in clients[-5:]:
        cli_tbl.add_row(Text(_fit(cli, 26), style="bright_cyan"))
    if not clients:
        cli_tbl.add_row(Text("no clients", style="dim"))

    cred_tbl = Table.grid(padding=(0, 1))
    cred_tbl.add_column()
    for c in creds[-3:]:
        cred_tbl.add_row(Text.from_markup(
            f"[bold bright_magenta]{_fit(c.get('ssid', '?'), 16)}[/]  "
            f"{_fit(c.get('username', '-'), 12)}  [bold bright_green]{c.get('password', '-')}[/]"
        ))
    if not creds:
        cred_tbl.add_row(Text("waiting for login...", style="dim"))

    cols = Table.grid(expand=True, padding=(0, 2))
    cols.add_column(ratio=1)
    cols.add_column(ratio=1)
    cols.add_row(
        Panel(ssid_tbl, title="SSIDs", border_style="dim", padding=(0, 0)),
        Panel(cli_tbl, title="Clients", border_style="dim", padding=(0, 0)),
    )

    foot = Text.from_markup(
        f"[bold bright_magenta]{_pulse(tick)}[/] "
        f"[dim]beacons[/] [bold]{beacons}[/]   "
        f"[dim]deauths[/] [bold]{deauths}[/]   "
        f"[dim]{elapsed:.0f}s[/]"
    )
    return Panel(
        Group(
            foot, Text(""), cols,
            Panel(cred_tbl, title="Captured Credentials",
                  border_style="bright_green", padding=(0, 0)),
        ),
        title="[bold bright_magenta]EVIL TWIN - CAPTIVE PORTAL[/]",
        border_style="bright_magenta", padding=(0, 1),
    )


def eviltwin_theme_console(state: dict, tick: int) -> Panel:
    ssids = state.get("ssids", [])
    beacons = state.get("beacons", 0)
    deauths = state.get("deauths", 0)
    clients = state.get("clients", [])
    log = state.get("log", [])

    head = Text.from_markup(
        f"[bold bright_magenta]{_spin(tick)}[/] iface [bright_white]{state.get('iface', '')}[/] "
        f"APs {len(ssids)}  clients {len(clients)}"
    )

    stream = Text()
    for row in log[-8:]:
        t = row.get("t", 0.0)
        kind = row.get("kind", "?")
        detail = row.get("detail", "")
        c = {
            "beacon": "bright_magenta", "deauth": "bright_red",
            "client": "bright_cyan", "login": "bright_green",
        }.get(kind, "dim")
        stream.append(f"  {t:>6.1f}s  ", style="dim")
        stream.append(f"{kind:>8} ", style=c)
        stream.append(_fit(detail, 40) + "\n", style="white")

    gauge = _rate_bar(beacons / max(state.get("elapsed", 1.0), 1.0), width=32, peak=500)
    tail = Group(
        Text.from_markup(f"[dim]beacon pps[/] {gauge}  [dim]deauths[/] [bold red]{deauths}[/]"),
        Text(""),
    )
    return Panel(Group(head, Text(""), stream, Text(""), tail),
                 title="[bold bright_magenta]EVIL TWIN - LIVE[/]",
                 border_style="bright_magenta", padding=(0, 1))


EVILTWIN_THEMES = {
    "dashboard": eviltwin_theme_dashboard,
    "console": eviltwin_theme_console,
}


# ════════════════════════════════════════════════════════════════════════
# CRACK THEMES
# ════════════════════════════════════════════════════════════════════════
def crack_theme_classic(state: dict, tick: int) -> Panel:
    ssid = state.get("ssid", "?")
    tested = state.get("tested", 0)
    total = state.get("total", 1) or 1
    rate = state.get("rate", 0.0)
    candidate = state.get("candidate", "")
    found = state.get("found", "")
    pct = tested / total * 100.0
    eta = (total - tested) / rate if rate > 0 else 0.0

    bar_w = 36
    fill = int(min(1.0, pct / 100.0) * bar_w)
    bar = "█" * fill + "░" * (bar_w - fill)
    lines = [
        Text.from_markup(f"[bold bright_green]{_spin(tick)} CRACK[/]  [bold]{ssid}[/]"),
        Text.from_markup(f"[bright_green]{bar}[/] {pct:5.1f}%"),
        Text.from_markup(
            f"[dim]tested[/] {tested:,}/{total:,}   [dim]rate[/] {_human_rate(rate)}   [dim]eta[/] {eta:.0f}s"
        ),
        Text.from_markup(f"[dim]candidate[/] [italic]{_fit(candidate, 34)}[/]"),
    ]
    if found:
        lines.append(Text.from_markup(f"[bold bright_green]KEY -> {found}[/]"))
    return Panel(Group(*lines), title="[bold bright_green]WPA CRACK[/]",
                 border_style="bright_green", padding=(0, 1))


def crack_theme_speedometer(state: dict, tick: int) -> Panel:
    ssid = state.get("ssid", "?")
    tested = state.get("tested", 0)
    total = state.get("total", 1) or 1
    rate = state.get("rate", 0.0)
    candidate = state.get("candidate", "")
    found = state.get("found", "")

    rel = min(1.0, rate / 500_000.0)
    arc = 20
    needle = int(rel * arc)
    left = "[" + "-" * needle
    right = "-" * (arc - needle) + "]"

    head = Text.from_markup(f"[bold bright_cyan]{_pulse(tick)} SPEEDOMETER[/]  [bold]{ssid}[/]")
    speed = Text()
    speed.append(left, style="bright_green")
    speed.append("#", style="bold bright_yellow")
    speed.append(right, style="dim")
    speed.append(f"  {_human_rate(rate)}", style="bold white")

    progress = tested / total * 100.0
    lines = [
        head,
        speed,
        Text.from_markup(
            f"[dim]progress[/] {progress:5.1f}%   "
            f"[dim]tested[/] {tested:,}/{total:,}   "
            f"[dim]candidate[/] [italic]{_fit(candidate, 22)}[/]"
        ),
    ]
    if found:
        lines.append(Text.from_markup(f"[bold bright_green]FOUND -> {found}[/]"))
    return Panel(Group(*lines), title="[bold bright_cyan]HASHCAT ACCELERATOR[/]",
                 border_style="bright_cyan", padding=(0, 1))


def crack_theme_matrix(state: dict, tick: int) -> Panel:
    ssid = state.get("ssid", "?")
    tested = state.get("tested", 0)
    rate = state.get("rate", 0.0)
    candidate = state.get("candidate", "")
    found = state.get("found", "")

    stream = Text()
    seed = (tested // 100 + tick) & 0xFFF
    for i in range(46):
        level = ((seed >> (i % 9)) ^ (i * 7)) & 0x7
        stream.append(GLYPHS_FLOW[level], style="bright_green" if level > 4 else "dim green")

    head = Text.from_markup(
        f"[bold bright_green]{_spin(tick)}[/] CRACK ENGINE  [bold]{ssid}[/]  "
        f"[dim]{tested:,} candidates  {_human_rate(rate)}[/]"
    )
    tail = Text.from_markup(f"[dim]try[/] [italic bright_white]{_fit(candidate, 30)}[/]")
    body = Group(head, Text(""), stream, Text(""), tail)
    if found:
        body = Group(body, Text.from_markup(f"[bold bright_green]KEY -> {found}[/]"))
    return Panel(body, title="[bold bright_green]BRUTE FORCE[/]",
                 border_style="bright_green", padding=(0, 1))


CRACK_THEMES = {
    "classic": crack_theme_classic,
    "speedometer": crack_theme_speedometer,
    "matrix": crack_theme_matrix,
}


# ════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════
PHASE_THEMES = {
    "deauth": DEAUTH_THEMES,
    "capture": CAPTURE_THEMES,
    "eviltwin": EVILTWIN_THEMES,
    "crack": CRACK_THEMES,
}

RECENT_CHOICES: dict[str, str] = {}


def pick_theme(phase: str, prefer: Optional[str] = None) -> tuple[str, Callable]:
    pool = PHASE_THEMES.get(phase)
    if not pool:
        raise ValueError(f"unknown phase {phase!r}")
    if prefer and prefer in pool:
        RECENT_CHOICES[phase] = prefer
        return prefer, pool[prefer]
    last = RECENT_CHOICES.get(phase)
    candidates = [n for n in pool.keys() if n != last]
    if not candidates:
        candidates = list(pool.keys())
    name = random.choice(candidates)
    RECENT_CHOICES[phase] = name
    return name, pool[name]


class LiveOrchestra:
    """A Rich `Live` whose renderer changes themes on an interval."""

    def __init__(
        self,
        phase: str,
        state: Optional[dict] = None,
        theme: Optional[str] = None,
        rotate_every: float = 0.0,
        refresh: float = 8.0,
    ):
        self.phase = phase
        self.state = state if state is not None else {}
        self._theme, self._renderer = pick_theme(phase, theme)
        self._theme_pool = list(PHASE_THEMES[phase].items())
        self._rotate_every = rotate_every
        self._last_rotate = time.time()
        self._refresh = refresh
        self._tick = 0
        self._live: Optional[Live] = None

    @property
    def theme(self) -> str:
        return self._theme

    def _render(self):
        self._tick += 1
        try:
            return self._renderer(self.state, self._tick)
        except Exception:
            return Text(f"{_spin(self._tick)} {self.phase} running...")

    def __enter__(self):
        self._live = Live(
            self._render(),
            console=_console,
            refresh_per_second=self._refresh,
            transient=True,
        )
        self._live.__enter__()
        return self

    def refresh(self):
        if not self._live:
            return
        if self._rotate_every > 0 and time.time() - self._last_rotate >= self._rotate_every:
            self._last_rotate = time.time()
            options = [n for n, _ in self._theme_pool if n != self._theme]
            if options:
                self._theme = random.choice(options)
                self._renderer = dict(self._theme_pool)[self._theme]
        self._live.update(self._render())

    def print_exit(self, message: str = ""):
        if self._live:
            self._live.stop()
            self._live = None
        if message:
            _console.print(message)

    def __exit__(self, *exc):
        if self._live:
            self._live.__exit__(*exc)
            self._live = None


# One-shot phase banner
_BANNER_STYLES = (
    "bright_cyan", "bright_red", "bright_magenta", "bright_green",
    "bright_yellow", "bright_blue",
)
_BANNER_CHOICES = {}


def phase_banner(phase: str, detail: str = "", accent: Optional[str] = None) -> None:
    if accent is None:
        last = _BANNER_CHOICES.get(phase)
        pool = [c for c in _BANNER_STYLES if c != last]
        if not pool:
            pool = list(_BANNER_STYLES)
        accent = random.choice(pool)
        _BANNER_CHOICES[phase] = accent

    width = 66
    title_line = Text()
    title_line.append("=" * 3 + " ", style=accent)
    title_line.append(phase.upper(), style=f"bold {accent}")
    title_line.append(" " + "=" * max(0, width - 4 - len(phase)), style=accent)
    _console.print()
    _console.print(title_line)
    if detail:
        _console.print(Text.from_markup(f"  [dim]{detail}[/]"))
    _console.print()


def summary_panel(lines: list[tuple[str, str]], title: str, accent: str = "bright_green") -> Panel:
    """Reusable post-run summary, single-column key:value list."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim")
    grid.add_column(style="bold white")
    for k, v in lines:
        grid.add_row(k, v)
    return Panel(grid, title=f"[bold {accent}]{title}[/]", border_style=accent, padding=(0, 1))
