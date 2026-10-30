#!/usr/bin/env python3
""" Real-time HackIT Swarm Dashboard using rich TUI """

import datetime
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict

try:
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.markup import escape
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
        # The swarm writes relative to its working directory, which may be the
        # repository root, the agent/go directory, or a user's shell cwd.
        candidates = [
            Path.cwd() / "reports" / "dashboard",
            Path(__file__).resolve().parent / "go" / "reports" / "dashboard",
            Path.home() / ".hackit" / "reports" / "dashboard",
        ]
        jsons = []
        for dash_dir in candidates:
            if dash_dir.exists():
                jsons.extend(dash_dir.glob("*.json"))
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
                if not isinstance(data, dict):
                    return
                self.state = self._sanitize_state(data)
                logs = self.state.get("logs") or []
                agents = {str(log.get("agent", "")) for log in logs if isinstance(log, dict)}
                self.agent_idx = len([agent for agent in agents if agent])
                if logs:
                    self.current_agent = str(logs[-1].get("agent") or self.current_agent)
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            pass

    @staticmethod
    def _sanitize_state(data: Dict[str, Any]) -> Dict[str, Any]:
        """Coerce null/!list fields emitted by the Go engine.

        The engine writes ``discovered_services: null`` until the first agent
        reports; every renderer assumed a list and crashed on ``len(None)``.
        """
        list_fields = (
            "discovered_services", "vulnerabilities", "logs",
            "findings", "subdomains", "ports",
        )
        for field in list_fields:
            if not isinstance(data.get(field), list):
                data[field] = []
        dict_fields = ("recon_data", "context_data", "target")
        for field in dict_fields:
            if not isinstance(data.get(field), dict):
                data[field] = {}
        if not isinstance(data["recon_data"].get("subdomains"), list):
            data["recon_data"]["subdomains"] = []
        return data

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

    def _start_timestamp(self):
        value = self.state.get("start_time")
        if isinstance(value, str):
            try:
                return datetime.datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                return time.time()
        if isinstance(value, (int, float)):
            return float(value)
        return time.time()

    def render_header(self):
        elapsed = max(0.0, time.time() - self._start_timestamp())
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        session = escape(str(self.state.get("session_id", "N/A")))
        target_data = self.state.get("target", {})
        if isinstance(target_data, dict):
            target = target_data.get("primary_domain", self.target)
        else:
            target = target_data or self.target
        return Panel(
            Text.from_markup(
                f"[bold cyan]HACKIT SWARM DASHBOARD[/]  "
                f"[dim]Session:[/] [yellow]{session}[/]  "
                f"[dim]Target:[/] [bold]{escape(str(target))}[/] [dim]({escape(str(self.scope))})[/]  "
                f"[dim]Elapsed:[/] [green]{elapsed_str}[/]"
            ),
            style="bold white on black",
        )

    def render_logs(self):
        logs = self.state.get("logs", [])
        recent = logs[-15:] if logs else []
        lines = []
        for log in recent:
            if not isinstance(log, dict):
                continue
            agent = escape(str(log.get("agent", ""))[:35])
            action = escape(str(log.get("action", "")))
            msg = escape(str(log.get("message", ""))[:60])
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
        services = len(self.state.get("discovered_services") or [])
        recon = self.state.get("recon_data") or {}
        subdomains = len(recon.get("subdomains") or []) if isinstance(recon, dict) else 0
        vulns = len(self.state.get("vulnerabilities") or [])
        logs = len(self.state.get("logs") or [])

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
            if not isinstance(v, dict):
                continue
            sev = str(v.get("severity", "?"))
            sev_style = {"Critical": "red", "High": "yellow", "Medium": "blue", "Low": "dim"}.get(sev, "dim")
            table.add_row(
                f"[{sev_style}]{escape(sev)}[/]",
                escape(str(v.get("name", ""))[:34]),
                escape(str(v.get("cvss", 0))),
            )
        return Panel(table, title=f"[bold]Vulns ({len(vulns)})[/]", border_style="red")

    def render_progress(self):
        total = self.total_agents
        current = self.agent_idx
        if not current:
            agents = {
                str(log.get("agent", ""))
                for log in (self.state.get("logs") or [])
                if isinstance(log, dict) and log.get("agent")
            }
            current = len(agents)
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

        agent_name = escape(self.current_agent[:50])
        return Panel(
            Group(progress, Text.from_markup(f"[bold cyan]>>[/] {agent_name}")),
            title="[bold]Progress[/]",
            border_style="cyan",
        )

    def run(self, process=None):
        layout = self.make_layout()
        poll_thread = threading.Thread(target=self.poll_state, daemon=True)
        poll_thread.start()

        with Live(layout, refresh_per_second=4, screen=True) as live:
            while self.running:
                if process is not None and process.poll() is not None:
                    # Render one final frame before the engine exits.
                    self.read_state()
                    break
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
    engine_proc = None

    try:
        engine_proc = subprocess.Popen(
            [engine_path, "--swarm", target, "--swarm-scope", scope],
            cwd=os.path.join(base_dir, "go"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dashboard.run(process=engine_proc)
        code = engine_proc.poll()
        if code not in (0, None):
            console.print(f"[red][!] Swarm engine exited with code {code}[/]")
        elif code is None:
            console.print("[yellow][*] Swarm still running; dashboard closed.[/]")
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.running = False
        if engine_proc is not None and engine_proc.poll() is None:
            engine_proc.terminate()
            try:
                engine_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                engine_proc.kill()


if __name__ == "__main__":
    main()
