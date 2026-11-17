"""Attack-phase rendering.

Every phase gets a different layout so the operator can tell at a glance which
stage they are looking at:

* capture   — packet counter, EAPOL tracker, nonce/mic checklist
* deauth    — frame rate gauge, channel map, reason-code strip
* eviltwin  — SSID roster, client roster, credential feed
* crack     — keyspace progress, rate, ETA, candidate stream

Rendering never blocks the attack: each function is pure presentation and is
called from the coordinator's worker thread.
"""

from __future__ import annotations

import time
from typing import Optional

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

_console = Console()

ACCENT_CAPTURE = "cyan"
ACCENT_DEAUTH = "red"
ACCENT_TWIN = "magenta"
ACCENT_CRACK = "green"

_GLYPHS = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


def _spin(idx: int) -> str:
    return _GLYPHS[idx % len(_GLYPHS)]


# --------------------------------------------------------------------------- #
# Capture
# --------------------------------------------------------------------------- #


def capture_panel(stats: dict, ssid: str, bssid: str, step: int = 0) -> Panel:
    """Live panel for the handshake capture phase."""
    frames = stats.get("packets", 0)
    hs = stats.get("handshakes", 0)
    pmkid = stats.get("pmkids", 0)
    elapsed = stats.get("elapsed", 0.0)

    spinner = _spin(step)

    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=2)
    grid.add_column(justify="right", ratio=1)

    grid.add_row(
        Text.from_markup(f"[bold {ACCENT_CAPTURE}]{spinner}[/] [!] capturing on target"),
        Text.from_markup(f"[dim]{elapsed:.1f}s[/]"),
    )

    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim")
    body.add_column(style="bold white")
    body.add_row("SSID", ssid or "[dim]any[/]")
    body.add_row("BSSID", bssid or "[dim]any[/]")
    body.add_row("Frames", f"[bold {ACCENT_CAPTURE}]{frames}[/]")
    body.add_row("EAPOL", f"[bold yellow]{hs}[/] handshake(s)")
    body.add_row("PMKID", f"[bold magenta]{pmkid}[/]")

    header = Text(f"CAPTURE  {stats.get('status', 'running')}", style=f"bold {ACCENT_CAPTURE}")
    return Panel(
        Group(grid, Text(""), body),
        title=header,
        border_style=ACCENT_CAPTURE,
        padding=(0, 1),
    )


# --------------------------------------------------------------------------- #
# Deauth
# --------------------------------------------------------------------------- #


def _channel_grid(active: Optional[int], bands: tuple[str, ...]) -> Text:
    text = Text()
    for ch in range(1, 14):
        style = f"bold {ACCENT_DEAUTH}" if ch == active else "dim"
        text.append(f"{ch:>2} ", style=style)
    if "5" in bands:
        text.append("\n")
        for ch in (36, 40, 44, 48, 52, 60, 100, 116, 132, 149, 157, 165):
            style = f"bold {ACCENT_DEAUTH}" if ch == active else "dim"
            text.append(f"{ch:>3} ", style=style)
    return text


def _rate_gauge(pps: float) -> Text:
    width = 30
    filled = int(min(1.0, pps / 2000.0) * width)
    bar = "█" * filled + "░" * (width - filled)
    color = "red" if pps > 800 else ("yellow" if pps > 300 else "cyan")
    text = Text()
    text.append(bar, style=f"bold {color}")
    text.append(f"  {pps:.0f} pps", style="bold white")
    return text


def deauth_panel(stats: dict, bssid: str, step: int = 0) -> Panel:
    frames = stats.get("frames", 0)
    errors = stats.get("errors", 0)
    pps = stats.get("pps", 0.0) or (
        frames / stats["elapsed"] if stats.get("elapsed") else 0.0
    )
    channel = stats.get("channel")
    reason = stats.get("reason", 7)
    bands = stats.get("bands", ("2.4", "5"))

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column()
    grid.add_column(justify="right")

    grid.add_row(
        Text.from_markup(f"[bold {ACCENT_DEAUTH}]{_spin(step)} DEAUTH[/] → {bssid}"),
        Text.from_markup(f"[dim]{stats.get('elapsed', 0):.0f}s[/]"),
    )
    grid.add_row(_rate_gauge(pps), Text.from_markup(f"[dim]errors {errors}[/]"))
    grid.add_row(Text(""), Text(""))
    grid.add_row(_channel_grid(channel, bands), Text.from_markup(
        f"[bold white]ch[/] {channel or '-'}   [bold white]reason[/] {reason}"
    ))

    return Panel(grid, border_style=ACCENT_DEAUTH, padding=(0, 1))


# --------------------------------------------------------------------------- #
# Evil twin
# --------------------------------------------------------------------------- #


def eviltwin_panel(state: dict, step: int = 0) -> Panel:
    ssids = state.get("ssids", [])
    clients = state.get("clients", [])
    creds = state.get("credentials", [])
    beacons = state.get("beacons", 0)
    deauths = state.get("deauths", 0)

    roster = Table.grid(padding=(0, 1))
    roster.add_column()
    for i, ssid in enumerate(ssids[:4]):
        marker = "◆" if i == 0 else "◇"
        roster.add_row(Text.from_markup(f"[bold {ACCENT_TWIN}]{marker}[/] {ssid}"))
    if len(ssids) > 4:
        roster.add_row(Text.from_markup(f"[dim]… {len(ssids) - 4} more[/]"))

    client_txt = Text()
    client_txt.append(f"{len(clients)} client(s)", style="bold white")
    if clients:
        client_txt.append("\n" + "\n".join(clients[:3]), style="dim")
        if len(clients) > 3:
            client_txt.append(f"\n+{len(clients) - 3}", style="dim")

    cred_txt = Text()
    if creds:
        for entry in creds[-3:]:
            cred_txt.append(
                f"  {entry.get('ssid', '?')}  {entry.get('username', '-')}  "
                f"[bold]{entry.get('password', '-')}[/]\n",
                style="bold green",
            )
    else:
        cred_txt.append("waiting for login…", style="dim")

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(roster, title="SSIDs", border_style="dim", padding=(0, 0)),
        Panel(client_txt, title="Clients", border_style="dim", padding=(0, 0)),
    )

    footer = Text.from_markup(
        f"[dim]beacons[/] [bold]{beacons}[/]   [dim]deauths[/] [bold]{deauths}[/]"
    )
    cred_panel = Panel(cred_txt, title="Captured", border_style="green", padding=(0, 0))

    return Panel(
        Group(Text.from_markup(f"[bold {ACCENT_TWIN}]{_spin(step)} EVIL TWIN[/] {state.get('iface', '')}"),
              Text(""), grid, footer, cred_panel),
        border_style=ACCENT_TWIN,
        padding=(0, 1),
    )


# --------------------------------------------------------------------------- #
# Crack
# --------------------------------------------------------------------------- #


def crack_progress(tested: int, total: int, rate: float, candidate: str,
                   ssid: str, found: str = "") -> Panel:
    pct = (tested / total * 100.0) if total else 0.0
    eta = (total - tested) / rate if rate > 0 else 0.0

    progress = Progress(
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=34, complete_style="green", finished_style="bold green"),
        TextColumn("[bold]{task.percentage:>5.1f}%"),
        TextColumn("[dim]{task.fields[rate]}"),
        TimeElapsedColumn(),
    )
    task = progress.add_task(
        f"{ssid}", total=total or 1, completed=tested,
        rate=f"{rate:.0f} p/s" if rate else "…",
    )

    lines = [progress]
    lines.append(Text.from_markup(f"[dim]candidate [/] [italic]{candidate}[/]"))
    if eta:
        lines.append(Text.from_markup(f"[dim]eta[/] [bold]{eta:.0f}s[/]"))
    if found:
        lines.append(Text.from_markup(f"[bold green]KEY → {found}[/]"))

    return Panel(Group(*lines), title=f"CRACK {ssid}", border_style=ACCENT_CRACK, padding=(0, 1))


# --------------------------------------------------------------------------- #
# Live helper
# --------------------------------------------------------------------------- #


class LiveView:
    """Context manager that redraws a panel builder on a fixed cadence."""

    def __init__(self, builder, refresh: float = 8.0):
        self._builder = builder
        self._refresh = refresh
        self._step = 0

    def __enter__(self):
        self._live = Live(
            self._builder(0),
            console=_console, refresh_per_second=self._refresh,
            transient=True,
        )
        self._live.__enter__()
        return self

    def update(self, *args, **kwargs) -> None:
        self._step += 1
        try:
            self._live.update(self._builder(self._step, *args, **kwargs))
        except TypeError:
            self._live.update(self._builder(self._step))

    def __exit__(self, *exc):
        self._live.__exit__(*exc)


def banner_phase(phase: str, detail: str, color: str) -> None:
    """One-shot phase banner shown once before a long operation starts."""
    title = Text()
    title.append("━" * 3 + " ", style=color)
    title.append(phase.upper(), style=f"bold {color}")
    title.append(" " + "━" * (60 - len(phase)), style=color)
    _console.print()
    _console.print(title)
    if detail:
        _console.print(Text.from_markup(f"  [dim]{detail}[/]"))
    _console.print()
