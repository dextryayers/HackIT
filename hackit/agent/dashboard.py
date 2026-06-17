#!/usr/bin/env python3
""" Real-time HackIT Swarm Dashboard using rich TUI """

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich import box
except ImportError:
    print("[!] rich library required. Install: pip install rich")
    sys.exit(1)

console = Console()

class SwarmDashboard:
    def __init__(self, target, scope):
        self.target = target
        self.scope = scope
        self.state = {
            "session_id": "initializing...",
            "start_time": time.time(),
            "target": {"primary_domain": target},
            "recon_data": {"subdomains": [], "asn": "", "cloud_infra": ""},
            "discovered_services": [],
            "vulnerabilities": [],
            "logs": [],
            "context_data": {},
        }
        self.current_agent = "Initializing..."
        self.agent_idx = 0
        self.total_agents = 28
        self.latest_logs = []
        self.running = True
        self.last_state_mtime = 0

    def find_latest_state(self):
        dash_dir = Path(__file__).parent / "go" / "reports" / "dashboard"
        if not dash_dir.exists():
            return None
        jsons = list(dash_dir.glob("*.json"))
        if not jsons:
            return None
        return max(jsons, key=lambda p: p.stat().st_mtime)

    def read_state(self):
        state_file = self.find_latest_state()
        if not state_file:
            return
        try:
            mtime = state_file.stat().st_mtime
            if mtime <= self.last_state_mtime:
                return
            self.last_state_mtime = mtime
            with open(state_file) as f:
                data = json.load(f)
                self.state = data
                self.agent_idx = len(self.state.get("logs", []))
        except (json.JSONDecodeError, OSError):
            pass

    def poll_state(self):
        while self.running:
            self.read_state()
            time.sleep(0.5)

    def make_layout(self):
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="logs", ratio=2),
            Layout(name="stats", ratio=1),
        )
        layout["stats"].split_column(
            Layout(name="counts"),
            Layout(name="vulns"),
            Layout(name="progress"),
        )
        return layout

    def render_header(self):
        elapsed = time.time() - self.state.get("start_time", time.time())
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        session = self.state.get("session_id", "N/A")
        target = self.state.get("target", {}).get("primary_domain", self.target)
        return Panel(
            Text.from_markup(
                f"[bold cyan]HACKIT SWARM DASHBOARD[/]  "
                f"[dim]Session:[/] [yellow]{session}[/]  "
                f"[dim]Target:[/] [bold]{target}[/] [dim]({self.scope})[/]  "
                f"[dim]Elapsed:[/] [green]{elapsed_str}[/]"
            ),
            style="bold white on black",
        )

    def render_logs(self):
        logs = self.state.get("logs", [])
        recent = logs[-15:] if logs else []
        lines = []
        for log in recent:
            agent = log.get("agent", "")[:35]
            action = log.get("action", "")
            msg = log.get("message", "")[:60]
            level = log.get("level", "info")
            style = {"ok": "green", "warn": "yellow", "error": "red", "info": "dim"}.get(level, "dim")
            lines.append(f"[{style}]{agent}[/] [{action}] {msg}")
        if not lines:
            lines = ["[dim]Waiting for swarm output...[/]"]
        return Panel(
            Text.from_markup("\n".join(lines[-12:])),
            title="[bold]Live Log Feed[/]",
            border_style="blue",
        )

    def render_counts(self):
        services = len(self.state.get("discovered_services", []))
        subdomains = len(self.state.get("recon_data", {}).get("subdomains", []))
        vulns = len(self.state.get("vulnerabilities", []))
        logs = len(self.state.get("logs", []))

        table = Table.grid(padding=(0, 1))
        table.add_column()
        table.add_column()
        table.add_row("[bold]Subdomains[/]", f"[cyan]{subdomains}[/]")
        table.add_row("[bold]Services[/]", f"[green]{services}[/]")
        table.add_row("[bold]Vulnerabilities[/]", f"[red]{vulns}[/]")
        table.add_row("[bold]Log Events[/]", f"[dim]{logs}[/]")
        return Panel(table, title="[bold]Counts[/]", border_style="green")

    def render_vulns(self):
        vulns = self.state.get("vulnerabilities", [])
        if not vulns:
            return Panel("[dim]No vulnerabilities found yet[/]", title="[bold]Vulnerabilities[/]", border_style="red")

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Sev", style="bold", width=8)
        table.add_column("Name", width=35)
        table.add_column("CVSS", width=5)

        for v in vulns[-6:]:
            sev = v.get("severity", "?")
            sev_style = {"Critical": "red", "High": "yellow", "Medium": "blue", "Low": "dim"}.get(sev, "dim")
            table.add_row(
                f"[{sev_style}]{sev}[/]",
                v.get("name", "")[:34],
                str(v.get("cvss", 0)),
            )
        return Panel(table, title=f"[bold]Vulns ({len(vulns)})[/]", border_style="red")

    def render_progress(self):
        total = self.total_agents
        current = self.agent_idx
        if current > total:
            current = total
        pct = (current / total) * 100 if total > 0 else 0

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        task = progress.add_task(
            f"[cyan]Agent {current}/{total}[/]",
            total=total,
            completed=current,
        )
        progress.update(task, completed=current)

        agent_name = self.current_agent[:50]
        return Panel(
            Group(progress, Text(f"[bold cyan]>>[/] {agent_name}")),
            title="[bold]Progress[/]",
            border_style="cyan",
        )

    def run(self):
        layout = self.make_layout()
        poll_thread = threading.Thread(target=self.poll_state, daemon=True)
        poll_thread.start()

        with Live(layout, refresh_per_second=4, screen=True) as live:
            while self.running:
                layout["header"].update(self.render_header())
                layout["logs"].update(self.render_logs())
                layout["counts"].update(self.render_counts())
                layout["vulns"].update(self.render_vulns())
                layout["progress"].update(self.render_progress())
                time.sleep(0.25)


def main():
    if len(sys.argv) < 2:
        print("Usage: dashboard.py <target> [scope]")
        sys.exit(1)

    target = sys.argv[1]
    scope = sys.argv[2] if len(sys.argv) > 2 else "passive"

    base_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(base_dir, "go", "ai_engine")

    if not os.path.exists(engine_path):
        print(f"[!] AI engine not found at {engine_path}")
        sys.exit(1)

    dashboard = SwarmDashboard(target, scope)

    try:
        engine_proc = subprocess.Popen(
            [engine_path, "--swarm", target, "--swarm-scope", scope],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dashboard.run()
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.running = False
        engine_proc.terminate()
        engine_proc.wait(timeout=5)


if __name__ == "__main__":
    main()
