import os, sys, time, math, threading
from datetime import datetime
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.bar import Bar
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.align import Align
from rich.syntax import Syntax
from rich.tree import Tree
from rich.markdown import Markdown

console = Console()

SIGNAL_BARS = "▁▂▃▄▅▆▇█"


class UIRenderer:

    # ── Core output ────────────────────────────────────────────

    @staticmethod
    def print_info(msg: str):
        console.print(f"[bold cyan][*][/bold cyan] {msg}")

    @staticmethod
    def print_success(msg: str):
        console.print(f"[bold green][+][/bold green] {msg}")

    @staticmethod
    def print_warning(msg: str):
        console.print(f"[bold yellow][!][/bold yellow] {msg}")

    @staticmethod
    def print_error(msg: str):
        console.print(f"[bold red][-][/bold red] {msg}")

    @staticmethod
    def print_debug(msg: str):
        console.print(f"[dim][#] {msg}[/dim]")

    @staticmethod
    def print_raw(msg: str):
        console.print(msg)

    @staticmethod
    def print_status(msg: str):
        console.print(f"[bold cyan]EvilTwin[/bold cyan] {msg}")

    # ── Progress / Spinner ─────────────────────────────────────

    @staticmethod
    def spinner(message: str = "Working..."):
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold yellow]{task.description}"),
            console=console,
        )

    @staticmethod
    def task_progress():
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40, complete_style="green", finished_style="green"),
            TextColumn("[bold yellow]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )

    # ── AP / Network Tables ────────────────────────────────────

    @staticmethod
    def create_ap_table(title: str = "Access Points in Range"):
        table = Table(title=f"[bold cyan]{title}[/bold cyan]",
                      title_style="bold", border_style="cyan",
                      header_style="bold white")
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("SSID", style="white", min_width=20)
        table.add_column("BSSID", style="cyan", no_wrap=True)
        table.add_column("Ch", justify="center", style="yellow", width=4)
        table.add_column("Signal", style="green", width=12)
        table.add_column("Bar", width=8)
        table.add_column("Vendor", style="magenta", min_width=14)
        table.add_column("Crypto", style="red")
        table.add_column("WPS", style="blue")
        return table

    @staticmethod
    def fill_ap_row(i: int, ap: dict) -> list:
        ssid = ap.get("ssid", "<hidden>")
        bssid = ap.get("bssid", "?")
        ch = str(ap.get("channel", "?"))
        signal_str = str(ap.get("signal", "?"))
        dbm = DataParser.signal_to_dbm(signal_str) if has_dbm else -100
        bar = UIRenderer.signal_bar(dbm)
        vendor = ap.get("vendor", UIRenderer._oui_lookup(bssid))
        crypto = ap.get("encrypt", ap.get("security", "?"))
        wps = "YES" if ap.get("wps", "").lower() == "yes" else "—"
        return [str(i), ssid, bssid, ch, f"{dbm} dBm", bar, vendor, crypto, wps]

    @staticmethod
    def signal_bar(dbm: int) -> str:
        if dbm >= -50:
            return "[bold green]████████[/bold green]"
        elif dbm >= -60:
            return "[green]███████░[/green]"
        elif dbm >= -70:
            return "[yellow]█████░░░[/yellow]"
        elif dbm >= -80:
            return "[bold yellow]███░░░░░[/bold yellow]"
        else:
            return "[red]█░░░░░░░[/red]"

    @staticmethod
    def signal_ascii_bars(dbm: int, length: int = 10) -> str:
        levels = max(0, min(length, (dbm + 100) // 10))
        filled = SIGNAL_BARS[-1] * levels if levels > 0 else ""
        empty = "░" * (length - levels)
        return filled + empty

    # ── Client table ───────────────────────────────────────────

    @staticmethod
    def create_client_table():
        table = Table(title="[bold cyan]Connected Clients[/bold cyan]",
                      border_style="green")
        table.add_column("Station MAC", style="cyan", no_wrap=True)
        table.add_column("BSSID", style="yellow")
        table.add_column("Signal", style="green", width=12)
        table.add_column("Bar", width=8)
        table.add_column("Probes", style="magenta")
        table.add_column("Last Seen", style="dim")
        return table

    @staticmethod
    def fill_client_row(station: str, bssid: str, dbm: int, probes: str = "", last_seen: str = ""):
        return [station, bssid, f"{dbm} dBm", UIRenderer.signal_bar(dbm), probes, last_seen]

    # ── Target / Capture table ─────────────────────────────────

    @staticmethod
    def create_target_table():
        table = Table(title="[bold cyan]Captured Frame Telemetry (Live)[/bold cyan]",
                      border_style="blue")
        table.add_column("BSSID", justify="center", style="cyan", no_wrap=True)
        table.add_column("Event Type", style="magenta")
        table.add_column("Details", style="bold yellow")
        table.add_column("Size", justify="right", style="green")
        return table

    # ── Spectrum / Channel visualization ───────────────────────

    @staticmethod
    def render_spectrum(channels: list[dict]) -> Panel:
        lines = []
        lines.append("[bold cyan]2.4 GHz Band[/bold cyan]")
        lines.append("")

        for ch in channels:
            if ch.get("band", "").startswith("2.4"):
                num = ch.get("number", 0)
                freq = ch.get("frequency", 0)
                rssi = ch.get("rssi", -100)
                apc = ch.get("ap_count", ch.get("APCount", 0))
                util = ch.get("utilization", ch.get("Utilization", 0))
                bar = UIRenderer.signal_ascii_bars(rssi)
                util_bar = "█" * int(util * 20) + "░" * (20 - int(util * 20))
                lines.append(
                    f"  Ch {num:>3} | {freq} MHz | "
                    f"[bold]{'█'*max(0, min(10,(rssi+100)//10))}{'░'*max(0,10-min(10,(rssi+100)//10))}[/bold] | "
                    f"RSSI: {rssi:>3} dBm | APs: {apc:>2} | Util: [{util_bar}] {util*100:>5.1f}%"
                )

        lines.append("")
        lines.append("[bold yellow]5 GHz Band[/bold yellow]")
        lines.append("")

        for ch in channels:
            if ch.get("band", "").startswith("5"):
                num = ch.get("number", 0)
                freq = ch.get("frequency", 0)
                rssi = ch.get("rssi", -100)
                apc = ch.get("ap_count", ch.get("APCount", 0))
                util = ch.get("utilization", ch.get("Utilization", 0))
                bar = UIRenderer.signal_ascii_bars(rssi)
                util_bar = "█" * int(util * 20) + "░" * (20 - int(util * 20))
                lines.append(
                    f"  Ch {num:>3} | {freq} MHz | "
                    f"{bar} | "
                    f"RSSI: {rssi:>3} dBm | APs: {apc:>2} | Util: [{util_bar}] {util*100:>5.1f}%"
                )

        return Panel("\n".join(lines), title="[bold cyan]Spectrum Analysis[/bold cyan]",
                     border_style="green")

    # ── Crack progress ─────────────────────────────────────────

    @staticmethod
    def render_crack_progress(tested: int, total: int, rate: float, current_pass: str,
                              elapsed: float, status: str = "Cracking..."):
        pct = (tested / total * 100) if total > 0 else 0
        bar_len = 40
        filled = int(bar_len * tested / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        eta = (total - tested) / rate if rate > 0 else 0

        grid = Table.grid(padding=(0, 1))
        grid.add_column()
        grid.add_column(justify="right")

        grid.add_row("[bold cyan]Status[/bold cyan]", f"[bold yellow]{status}[/bold yellow]")
        grid.add_row("[bold cyan]Progress[/bold cyan]", f"[green]{bar}[/green] {pct:.1f}%")
        grid.add_row("[bold cyan]Tested[/bold cyan]", f"[white]{tested:,}[/white] / [white]{total:,}[/white]")
        grid.add_row("[bold cyan]Rate[/bold cyan]", f"[green]{rate:,.0f}[/green] p/s")
        grid.add_row("[bold cyan]Current[/bold cyan]", f"[yellow]{current_pass}[/yellow]")
        grid.add_row("[bold cyan]Elapsed[/bold cyan]", f"[cyan]{elapsed:.1f}s[/cyan]")
        if eta > 0 and eta < 1e6:
            grid.add_row("[bold cyan]ETA[/bold cyan]", f"[magenta]{eta:.0f}s[/magenta]")

        return Panel(grid, title="[bold magenta]WPA Cracking[/bold magenta]",
                     border_style="magenta")

    # ── Vendor OUI lookup ──────────────────────────────────────

    @staticmethod
    def _oui_lookup(mac: str) -> str:
        from .oui_db import _oui_lookup as _oui
        return _oui(mac)

    # ── Dashboard builder ──────────────────────────────────────

    @staticmethod
    def build_dashboard(iface: str, mode: str, aps: list, clients: list,
                        packets: int, handshakes: int, uptime: float) -> Panel:
        uptime_str = f"{uptime:.0f}s" if uptime < 60 else f"{uptime/60:.1f}m"
        grid = Table.grid(padding=(1, 2))
        grid.add_column(justify="left", style="bold cyan")
        grid.add_column(justify="right")

        grid.add_row("Interface", f"[green]{iface}[/green]")
        grid.add_row("Mode", f"[yellow]{mode}[/yellow]")
        grid.add_row("APs Seen", f"[white]{len(aps)}[/white]")
        grid.add_row("Clients", f"[white]{len(clients)}[/white]")
        grid.add_row("Packets", f"[white]{packets:,}[/white]")
        grid.add_row("Handshakes", f"[bold green]{handshakes}[/bold green]")
        grid.add_row("Uptime", f"[dim]{uptime_str}[/dim]")

        return Panel(grid, title=f"[bold cyan]HackIT Wireless Dashboard — {iface}[/bold cyan]",
                     border_style="cyan")

    # ── Help system ────────────────────────────────────────────

    @staticmethod
    def render_help_category(title: str, items: list[tuple[str, str, str]]) -> Panel:
        table = Table(box=None, show_header=False, padding=(0, 2))
        table.add_column("Command", style="bold cyan", no_wrap=False, overflow="fold")
        table.add_column("Description", style="white", no_wrap=False)
        table.add_column("Example", style="dim", no_wrap=False, overflow="fold")
        for cmd, desc, example in items:
            table.add_row(cmd, desc, example)
        return Panel(
            table,
            title=f"[bold yellow]{title}[/bold yellow]",
            border_style="cyan",
            expand=True,
        )

    # ── Packet forge visualization ─────────────────────────────

    @staticmethod
    def render_packet_structure(frame_type: str, fields: dict) -> Panel:
        tree = Tree(f"[bold cyan]802.11 {frame_type} Frame[/bold cyan]")
        for k, v in fields.items():
            tree.add(f"[white]{k}:[/white] [green]{v}[/green]")
        return Panel(tree, title="[bold]Packet Structure[/bold]", border_style="blue")


# Import at bottom to avoid circular import
from .data_parser import DataParser

has_dbm = True
