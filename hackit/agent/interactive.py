"""Modern terminal UI for HackIt Agent.

The interface is built on Rich (rendering) and prompt_toolkit (input,
completion, persistent history) with a plain ``input()`` fallback for dumb
terminals.  Both Chat and Autopilot share the same engine so every AI provider
and Ollama get the same streaming, memory and payload-forging behaviour.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory
    _HAS_PT = True
except ImportError:  # pragma: no cover
    _HAS_PT = False

from hackit.ui import GREEN, RED, YELLOW, DIM, B_CYAN, MAGENTA, RESET, BOLD, _colored

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "go", "reports")

AUTOPILOT_COMMANDS = {
    "set-target": "Lock target domain/IP",
    "target": "Show current target",
    "all": "Full comprehensive scan",
    "scan": "Run hative modules",
    "portscan": "Run port scan on target",
    "subdomainenum": "Enumerate subdomains",
    "dirfuzz": "Directory/file fuzzing",
    "techdetect": "Detect web technologies",
    "sqli": "SQL injection test",
    "xss": "XSS vulnerability test",
    "ssrf": "SSRF test",
    "rce": "Remote code execution test",
    "bypass403": "403 bypass techniques",
    "cve": "CVE lookup/search",
    "js": "JavaScript analysis",
    "header": "HTTP header audit",
    "ssl": "SSL/TLS analysis",
    "redirect": "Open redirect finder",
    "params": "Parameter discovery",
    "waf": "WAF detection",
    "takeover": "Subdomain takeover check",
    "deep": "Deep vulnerability analysis",
    "report": "Generate pentest report",
    "payload": "Forge payloads for a vulnerability class",
    "probe": "Send generated payloads to a target",
    "auto": "Run the full autonomous pipeline",
    "osint": "Run OSINT profile discovery",
    "status": "Provider / model connectivity",
    "model": "Switch model",
    "provider": "Switch provider",
    "memory": "Show memory statistics",
    "forget": "Clear conversation memory",
    "export": "Export conversation [filename]",
    "import": "Import conversation [filename]",
    "help": "Show all commands",
    "clear": "Clear screen",
    "exit": "Exit autopilot",
    "quit": "Exit autopilot",
}

CHAT_COMMANDS = {
    "code": "Generate code with explanation",
    "debug": "Debug code or errors",
    "explain": "Explain complex topics simply",
    "translate": "Translate text between languages",
    "write": "Write creative content",
    "summarize": "Summarize long text concisely",
    "math": "Solve math problems step by step",
    "research": "Deep research on any topic",
    "review": "Review code for bugs",
    "refactor": "Refactor code with best practices",
    "test": "Generate unit tests for code",
    "diagram": "Create Mermaid diagrams",
    "learn": "Teach me step by step",
    "quick": "Quick concise answer",
    "detail": "Detailed comprehensive answer",
    "plan": "Create a step-by-step plan",
    "compare": "Compare and contrast items",
    "analyze": "Deep analysis of data/input",
    "payload": "Forge payloads for a vulnerability class",
    "probe": "Send generated payloads to a target",
    "auto": "Run the autonomous pentest pipeline",
    "osint": "Run OSINT profile discovery",
    "scan": "Run full hative security scan",
    "status": "Provider / model connectivity",
    "model": "Switch model",
    "provider": "Switch provider",
    "models": "List available models",
    "memory": "Show memory statistics",
    "facts": "Show remembered facts",
    "forget": "Clear conversation memory",
    "save": "Save memory to a file",
    "load": "Load memory from a file",
    "retry": "Retry the previous prompt",
    "target": "Set/show the active target",
    "export": "Export conversation [filename]",
    "import": "Import conversation [filename]",
    "clear": "Clear screen and conversation",
    "help": "Show all commands",
    "exit": "Exit chat",
    "quit": "Exit chat",
}

AUTOPILOT_BANNER = r"""
    █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
   ███████║██║   ██║   ██║   ██║   ██║██████╔╝██║██║     ██║   ██║   ██║
   ██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║
   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║
   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝
                      AUTONOMOUS PENTEST AI ENGINE
"""

CHAT_BANNER = r"""
    ██████╗██╗  ██╗ █████╗ ████████╗
   ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
   ██║     ███████║███████║   ██║
   ██║     ██╔══██║██╔══██║   ██║
   ╚██████╗██║  ██║██║  ██║   ██║
    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
                    GENERAL AI CHAT ENGINE
"""


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value or "")


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def _console() -> "Console":
    if _HAS_RICH:
        return Console(highlight=False, soft_wrap=True)
    raise RuntimeError("rich is required for this UI")


class _SlashCompleter(Completer if _HAS_PT else object):  # type: ignore[misc]
    def __init__(self, commands: Dict[str, str], payload_types: Optional[List[str]] = None):
        self.commands = commands
        self.payload_types = payload_types or []

    def get_completions(self, document, complete_event):  # noqa: ANN001
        text = document.text
        if not text.startswith("/"):
            return
        body = text[1:]
        if " " in body:
            head, _, tail = body.partition(" ")
            if head in ("payload", "probe"):
                for item in self.payload_types:
                    if item.startswith(tail.split()[0] if tail else ""):
                        yield Completion(item, start_position=-len(tail))
            return
        for command, description in sorted(self.commands.items()):
            if command.startswith(body):
                yield Completion(
                    f"/{command} ",
                    start_position=-len(text),
                    display=f"/{command}",
                    meta=description,
                )


class AgentUI:
    """Shared base for ChatUI and AutopilotUI."""

    mode_name = "CHAT"
    banner = CHAT_BANNER
    commands: Dict[str, str] = CHAT_COMMANDS

    def __init__(self, target: str = ""):
        self.console = _console()
        self.target = target
        self.running = True
        self.last_prompt = ""
        self.brain = None
        self._print_banner()

    # ------------------------------------------------------------------
    # Presentation
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        self.console.clear()
        banner = Text(self.banner.strip("\n"), style="bold cyan")
        self.console.print(banner)
        self.console.print(
            Panel(
                Text.from_markup(
                    "[bold]HackIt Agent[/bold]  [dim]v2.2[/dim]\n"
                    "[dim]AI chat · autonomous pentest · payload forge · OSINT[/dim]\n\n"
                    f"[green]/help[/green] commands   [green]Tab[/green] autocomplete   "
                    "[green]↑↓[/green] history   [green]Ctrl+C[/green] cancel"
                ),
                border_style="cyan",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )

    def _status_panel(self) -> None:
        brain = self.brain
        if not brain:
            return
        model = brain.model or "(auto)"
        backend = brain.memory.backend if brain.memory else "off"
        memory_count = brain.memory.stats()["messages"] if brain.memory else 0
        rows = [
            ("Engine", brain.engine),
            ("Provider", brain.provider or "none"),
            ("Model", model),
            ("Memory", f"{backend} · {memory_count} msg"),
            ("Target", self.target or "—"),
        ]
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim", no_wrap=True)
        table.add_column(style="bold")
        for name, value in rows:
            table.add_row(name, str(value))
        self.console.print(Panel(table, title="[bold cyan]SESSION[/bold cyan]", border_style="cyan", box=box.ROUNDED))

    def _toolbar(self) -> str:
        if not self.brain:
            return " provider=… model=… "
        memory = self.brain.memory.stats()["messages"] if self.brain.memory else 0
        target = f" · target={self.target}" if self.target else ""
        return f" provider={self.brain.provider or 'none'} · model={self.brain.model or 'auto'} · mem={memory}{target} "

    def _bottom_toolbar(self):
        if _HAS_PT:
            return HTML(f"<style bg='#1f2937' fg='#9ca3af'> {self._toolbar()} </style>")
        return self._toolbar()

    # ------------------------------------------------------------------
    # Input
    # ------------------------------------------------------------------

    def _make_session(self) -> Optional[Any]:
        if not _HAS_PT or not sys.stdin.isatty():
            return None
        history_file = os.path.join(os.path.expanduser("~"), f".hackit_{self.mode_name.lower()}_history")
        try:
            from . import payloads

            completer = _SlashCompleter(self.commands, payloads.catalog_types())
            return PromptSession(
                history=FileHistory(history_file),
                completer=completer,
                complete_while_typing=True,
                bottom_toolbar=self._bottom_toolbar,
                enable_history_search=True,
                multiline=False,
            )
        except Exception:
            return None

    def _read_input(self, session: Optional[Any]) -> str:
        prompt = HTML(f"<b><style fg='#22d3ee'>{self.mode_name.lower()}</style></b> <style fg='#f59e0b'>›</style> ")
        if session is not None:
            return session.prompt(prompt)
        return input(_colored(f"{self.mode_name.lower()} › ", B_CYAN))

    # ------------------------------------------------------------------
    # AI exchange
    # ------------------------------------------------------------------

    def _ask_ai(self, prompt: str, system_extra: str = "") -> str:
        assert self.brain is not None
        self.last_prompt = prompt
        self.console.print(
            f"[dim]{_timestamp()}[/dim] [bold cyan]you[/bold cyan] {prompt}"
        )
        self.console.print("[bold green]hackit[/bold green] ", end="")

        started = time.time()
        token_count = 0
        rendered: List[str] = []

        def on_token(event: Dict[str, Any]) -> None:
            nonlocal token_count
            token = event.get("token", "")
            if not token:
                return
            token_count += len(token)
            rendered.append(token)
            sys.stdout.write(token)
            sys.stdout.flush()

        try:
            if system_extra:
                result = self.brain.stream_chat(prompt, on_token=on_token)
            else:
                result = self.brain.stream_chat(prompt, on_token=on_token)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Cancelled.[/yellow]")
            return ""
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"\n[red]UI error: {exc}[/red]")
            return ""

        if not rendered:
            sys.stdout.write(result)
        sys.stdout.write("\n")
        sys.stdout.flush()

        elapsed = time.time() - started
        if result and result.strip().startswith("[!]"):
            self.console.print(f"[red]{_strip_ansi(result.strip())}[/red]")
        else:
            self.console.print(
                f"[dim]{_timestamp()} · {elapsed:.1f}s · ~{max(1, token_count // 4)} tok[/dim]"
            )
        return result

    # ------------------------------------------------------------------
    # Built-in commands
    # ------------------------------------------------------------------

    def _print_help(self) -> None:
        table = Table(title=f"{self.mode_name} COMMANDS", box=box.SIMPLE, show_lines=False)
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        for command, description in sorted(self.commands.items()):
            table.add_row(f"/{command}", description)
        table.add_row("/<mode> <text>", "Run an AI analysis mode (e.g. /risk target)")
        table.add_row("<text>", "Chat naturally with the AI")
        self.console.print(table)

    def _cmd_status(self) -> None:
        if not self.brain:
            return
        self.console.print("[dim]Probing providers…[/dim]")
        statuses = self.brain.health()
        if not statuses:
            self.console.print("[yellow]No provider keys configured. Run `agent setting`.[/yellow]")
            return
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Provider", style="cyan")
        table.add_column("State")
        table.add_column("Latency")
        table.add_column("Models")
        table.add_column("Detail")
        for status in statuses:
            color = {"ready": "green", "configured": "blue", "unreachable": "red",
                     "offline": "red", "not-configured": "dim"}.get(status.state, "white")
            table.add_row(
                status.label,
                f"[{color}]{status.state}[/{color}]",
                f"{status.latency_ms} ms" if status.latency_ms else "—",
                str(len(status.models)) if status.models else "—",
                status.error or status.detail or "—",
            )
        self.console.print(table)

    def _cmd_provider(self, argument: str) -> None:
        from . import providers

        if not argument:
            self.console.print("[dim]Usage: /provider <" + "|".join(providers.PROVIDERS) + ">[/dim]")
            return
        provider = providers.normalize_provider(argument)
        if self.brain and self.brain.set_provider(provider):
            self._persist_provider(provider)
            self.console.print(f"[green]Provider switched to {provider}.[/green]")
            self.console.print(f"[dim]Model: {self.brain.model or 'auto'}[/dim]")
        else:
            self.console.print(f"[red]Provider {provider} has no usable key.[/red]")

    def _persist_provider(self, provider: str) -> None:
        try:
            from hackit.config import load_config, save_config

            cfg = load_config()
            cfg["ai_provider"] = provider
            save_config(cfg)
        except Exception:
            pass

    def _cmd_model(self, argument: str) -> None:
        if not self.brain:
            return
        if argument:
            self.brain.model = argument.strip()
            try:
                from hackit.config import load_config, save_config

                cfg = load_config()
                cfg.setdefault("ai_models", {})[self.brain.provider] = self.brain.model
                save_config(cfg)
            except Exception:
                pass
            self.console.print(f"[green]Model set to {self.brain.model}.[/green]")
            return
        self.console.print(f"[dim]Current model: {self.brain.model or 'auto'}[/dim]")
        self.console.print("[dim]Usage: /model <model-id>[/dim]")

    def _cmd_models(self) -> None:
        if not self.brain:
            return
        items = self.brain.list_models(include_remote=True)
        table = Table(title=f"MODELS · {self.brain.provider}", box=box.SIMPLE)
        table.add_column("#", style="dim", width=4)
        table.add_column("Model", style="cyan")
        table.add_column("Tier")
        table.add_column("Description", style="dim")
        for index, (model, tier, description) in enumerate(items, 1):
            table.add_row(str(index), model, tier, description)
        self.console.print(table)

    def _cmd_payload(self, argument: str) -> None:
        from . import payloads

        if not self.brain:
            return
        if not argument:
            self.console.print("[dim]Usage: /payload <type> [context] [--probe URL --param name][/dim]")
            self.console.print(f"[dim]Types: {', '.join(payloads.catalog_types())}[/dim]")
            return

        target_url = ""
        parameter = ""
        method = "GET"
        tokens = argument.split()
        keep: List[str] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token == "--probe" and index + 1 < len(tokens):
                target_url = tokens[index + 1]
                index += 2
                continue
            if token == "--param" and index + 1 < len(tokens):
                parameter = tokens[index + 1]
                index += 2
                continue
            if token == "--method" and index + 1 < len(tokens):
                method = tokens[index + 1].upper()
                index += 2
                continue
            keep.append(token)
            index += 1
        if not keep:
            self.console.print("[red]Missing vulnerability type.[/red]")
            return
        vuln_type = keep[0]
        context = " ".join(keep[1:]) or (self.target or "")

        with self.console.status(f"[cyan]Forging {vuln_type} payloads…[/cyan]"):
            result = self.brain.generate_payloads(vuln_type, context=context, count=12)

        table = Table(title=f"PAYLOAD FORGE · {result.get('type')}", box=box.SIMPLE_HEAVY)
        table.add_column("#", width=4, style="dim")
        table.add_column("Payload", style="cyan", overflow="fold")
        table.add_column("Technique")
        table.add_column("Notes", style="dim")
        for index, item in enumerate(result.get("payloads", []), 1):
            table.add_row(str(index), item.get("payload", ""), item.get("technique", ""), item.get("notes", ""))
        self.console.print(table)
        if result.get("ai_error"):
            self.console.print(f"[yellow]AI note: {result['ai_error']}[/yellow]")

        os.makedirs(os.path.join(REPORTS_DIR, "payloads"), exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR, "payloads", f"{result.get('type')}_{stamp}.json")
        try:
            payloads.save({"results": {result.get("type", vuln_type): result}}, path)
            self.console.print(f"[dim]Saved: {path}[/dim]")
        except Exception:
            pass

        if target_url:
            self._probe(target_url, vuln_type, [item["payload"] for item in result.get("payloads", [])],
                        parameter, method)

    def _probe(self, target_url: str, vuln_type: str, payload_list: List[str],
               parameter: str = "", method: str = "GET") -> None:
        from . import payloads

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        threshold = 1 if os.environ.get("HACKIT_AUTHORIZED", "").lower() in ("1", "true", "yes") else 0
        if not threshold:
            self.console.print(
                "[yellow]Probing disabled: set HACKIT_AUTHORIZED=1 to confirm you are authorised to test this target.[/yellow]"
            )
            return

        self.console.print(f"[dim]Probing {len(payload_list)} payload(s) against {target_url}…[/dim]")
        results: List[Dict[str, Any]] = []

        def on_result(item: Dict[str, Any]) -> None:
            results.append(item)
            if item.get("vulnerable"):
                self.console.print(f"[red]![/red] {item['payload']} -> {item['evidence']}")
            else:
                self.console.print(f"[dim]· {item['payload']} -> {item['evidence']}[/dim]")

        payloads.probe_many(
            target_url, vuln_type, payload_list, parameter=parameter,
            method=method, on_result=on_result,
        )
        self.console.print(f"[bold]{payloads.summarize_probe(results)}[/bold]")

    def _cmd_memory(self) -> None:
        if not self.brain or not self.brain.memory:
            self.console.print("[dim]Memory disabled.[/dim]")
            return
        stats = self.brain.memory.stats()
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim")
        table.add_column(style="bold")
        for key, value in stats.items():
            table.add_row(key, str(value))
        self.console.print(Panel(table, title="MEMORY", border_style="magenta", box=box.ROUNDED))

    def _cmd_facts(self) -> None:
        if not self.brain or not self.brain.memory:
            return
        facts = self.brain.memory._facts  # noqa: SLF001 - intentional read-only view
        if not facts:
            self.console.print("[dim]No long-term facts yet.[/dim]")
            return
        for fact in facts:
            self.console.print(f"[cyan]·[/cyan] {fact}")

    def _cmd_save(self, path: str) -> None:
        if not self.brain or not self.brain.memory:
            return
        if not path:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = f"hackit_memory_{stamp}.json"
        try:
            self.brain.memory.export(path)
            self.console.print(f"[green]Memory saved to {path}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Save failed: {exc}[/red]")

    def _cmd_load(self, path: str) -> None:
        if not self.brain or not self.brain.memory:
            return
        try:
            count = self.brain.memory.import_file(path)
            self.console.print(f"[green]Imported {count} messages from {path}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Load failed: {exc}[/red]")

    def _cmd_scan(self, argument: str) -> None:
        if not self.target:
            self.console.print("[yellow]Set a target first: /target <host> or /set-target <host>[/yellow]")
            return
        if not self.brain:
            return
        modules = [item for item in argument.split() if item]
        self.console.print(f"[dim]Scanning {self.target} with hative…[/dim]")

        def on_progress(event: Dict[str, Any]) -> None:
            kind = event.get("event", "")
            message = event.get("message", "")
            if kind == "start":
                self.console.print(f"[cyan]▶[/cyan] [dim]{message}[/dim]")
            elif kind == "done":
                self.console.print(f"[green]✓[/green] {message}")
            elif kind == "error":
                self.console.print(f"[red]✗[/red] {message}")
            elif kind == "complete":
                self.console.print(f"[bold green]{message}[/bold green]")

        results = self.brain.stream_hative(self.target, on_progress=on_progress, modules=modules or None)
        if not results:
            self.console.print("[yellow]No results.[/yellow]")
            return
        findings = 0
        for item in results:
            data = item.get("data") if isinstance(item, dict) else None
            if isinstance(data, list):
                findings += len(data)
        self.console.print(f"[green]Scan complete: {len(results)} module(s), {findings} finding(s).[/green]")

    def _cmd_osint(self, query: str) -> None:
        if not query:
            query = self.target
        if not query:
            self.console.print("[yellow]Usage: /osint <username|email|domain>[/yellow]")
            return
        self.console.print(f"[dim]Running OSINT for {query} (this can take a minute)…[/dim]")
        try:
            from hackit.osint.core import run_full_scan

            def on_step(phase: str, message: str) -> None:
                self.console.print(f"[cyan]{phase}[/cyan] [dim]{message}[/dim]")

            data = run_full_scan(
                query, timeout=8, workers=24, verbose=False,
                check_phone=True, check_domain=True,
                on_step=on_step,
            )
            profiles = data.get("profiles", [])
            hits = data.get("summary", {}).get("hits", 0)
            confidence = data.get("analysis", {}).get("confidence_score", 0)
            self.console.print(
                f"[green]OSINT complete:[/green] {len(profiles)} checked · {hits} hit(s) · confidence {confidence}/100"
            )
            os.makedirs(os.path.join(REPORTS_DIR, "osint"), exist_ok=True)
            path = os.path.join(REPORTS_DIR, "osint", f"{query.replace('/', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, default=str)
            self.console.print(f"[dim]Saved: {path}[/dim]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]OSINT failed: {exc}[/red]")

    def _cmd_auto(self, target: str) -> None:
        target = target or self.target
        if not target:
            self.console.print("[yellow]Usage: /auto <target>[/yellow]")
            return
        self.target = target
        self.console.print(f"[bold cyan]Autonomous pipeline[/bold cyan] [dim]target={target}[/dim]")
        try:
            from .workflow import run_pentest

            def progress(phase: str, message: str) -> None:
                self.console.print(f"[cyan]▸ {phase}[/cyan] [dim]{message}[/dim]")

            state = run_pentest(target, scope="active_stealth", progress=progress)
            findings = state.get("findings", []) if isinstance(state, dict) else []
            report_path = state.get("report_path") if isinstance(state, dict) else ""
            self.console.print(f"[green]Pipeline complete: {len(findings)} finding(s).[/green]")
            if report_path:
                self.console.print(f"[dim]Report: {report_path}[/dim]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Pipeline failed: {exc}[/red]")
            if os.environ.get("HACKIT_DEBUG"):
                self.console.print(traceback.format_exc())

    def _cmd_export(self, path: str) -> None:
        if not path:
            path = f"hackit_conversation_{time.strftime('%Y%m%d_%H%M%S')}.md"
        if not self.brain or not self.brain.memory:
            return
        try:
            entries = self.brain.memory.snapshot()
            lines = [f"# HackIt {self.mode_name} Conversation", "", f"**Exported:** {datetime.datetime.now().isoformat()}", ""]
            for entry in entries:
                if entry.get("role") == "banner":
                    continue
                label = {"user": "User", "assistant": "Assistant", "system": "System"}.get(entry.get("role"), "Entry")
                lines.append(f"## {label}\n\n{entry.get('content', '')}\n")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines))
            self.console.print(f"[green]Conversation exported to {path}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Export failed: {exc}[/red]")

    def _cmd_import(self, path: str) -> None:
        if not self.brain or not self.brain.memory:
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()
            count = 0
            for section in content.split("## "):
                if section.startswith("User"):
                    body = section.split("\n\n", 1)[-1].strip()
                    if body:
                        self.brain.memory.add_user(body)
                        count += 1
                elif section.startswith("Assistant"):
                    body = section.split("\n\n", 1)[-1].strip()
                    if body:
                        self.brain.memory.add_assistant(body)
                        count += 1
            self.brain.memory.save()
            self.console.print(f"[green]Imported {count} message(s) from {path}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Import failed: {exc}[/red]")

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, raw: str) -> bool:
        """Handle one input line. Returns False to exit."""
        text = raw.strip()
        if not text:
            return True
        if not text.startswith("/"):
            self._ask_ai(text)
            return True

        head, _, rest = text[1:].partition(" ")
        head = head.lower()
        rest = rest.strip()

        if head in ("exit", "quit", "q", "bye"):
            return False
        if head in ("help", "?"):
            self._print_help()
            return True
        if head == "clear":
            self.console.clear()
            self._print_banner()
            if self.brain and self.brain.memory:
                self.brain.memory.clear()
            self.console.print("[dim]Screen and conversation cleared.[/dim]")
            return True
        if head == "status":
            self._cmd_status()
            return True
        if head == "provider":
            self._cmd_provider(rest)
            return True
        if head == "model":
            self._cmd_model(rest)
            return True
        if head == "models":
            self._cmd_models()
            return True
        if head == "memory":
            self._cmd_memory()
            return True
        if head == "facts":
            self._cmd_facts()
            return True
        if head == "forget":
            if self.brain and self.brain.memory:
                self.brain.memory.clear()
                self.console.print("[green]Conversation memory cleared.[/green]")
            return True
        if head == "save":
            self._cmd_save(rest)
            return True
        if head == "load":
            self._cmd_load(rest)
            return True
        if head == "payload":
            self._cmd_payload(rest)
            return True
        if head == "probe":
            self._cmd_probe_command(rest)
            return True
        if head == "scan":
            self._cmd_scan(rest)
            return True
        if head == "osint":
            self._cmd_osint(rest)
            return True
        if head == "auto":
            self._cmd_auto(rest)
            return True
        if head == "target":
            self.target = rest or self.target
            self.console.print(f"[cyan]Target:[/cyan] {self.target or '—'}")
            return True
        if head in ("set-target", "set_target"):
            self.target = rest
            self.console.print(f"[cyan]Target locked:[/cyan] {self.target}")
            return True
        if head == "export":
            self._cmd_export(rest)
            return True
        if head == "import":
            self._cmd_import(rest)
            return True
        if head == "retry":
            if self.last_prompt:
                self._ask_ai(self.last_prompt)
            else:
                self.console.print("[dim]Nothing to retry.[/dim]")
            return True

        # Domain-specific aliases: /scan modules, /portscan, /sqli ... all
        # forward to hative with the relevant module.
        module_aliases = {
            "all": "", "portscan": "portscan", "subdomainenum": "subdomain",
            "dirfuzz": "fuzz", "techdetect": "tech", "sqli": "sqli", "xss": "xss",
            "ssrf": "ssrf", "rce": "cmd", "bypass403": "bypass403", "js": "js",
            "header": "headers", "ssl": "ssl", "redirect": "redirect",
            "params": "param", "waf": "waf", "takeover": "takeover",
        }
        if head in module_aliases:
            if not self.target:
                self.console.print("[yellow]Set a target first: /target <host>[/yellow]")
                return True
            module = module_aliases[head]
            self._cmd_scan(module)
            return True

        # Unknown slash command -> send to the AI as a mode command.
        self._ask_ai(text)
        return True

    def _cmd_probe_command(self, rest: str) -> None:
        if not rest:
            self.console.print("[dim]Usage: /probe <type> <url> [--param name] [--method GET][/dim]")
            return
        parts = rest.split()
        if len(parts) < 2:
            self.console.print("[dim]Usage: /probe <type> <url> [--param name] [--method GET][/dim]")
            return
        vuln_type, target_url = parts[0], parts[1]
        parameter = ""
        method = "GET"
        index = 2
        while index < len(parts):
            if parts[index] == "--param" and index + 1 < len(parts):
                parameter = parts[index + 1]
                index += 2
                continue
            if parts[index] == "--method" and index + 1 < len(parts):
                method = parts[index + 1].upper()
                index += 2
                continue
            index += 1
        if not self.brain:
            return
        result = self.brain.generate_payloads(vuln_type, context=target_url, count=10, use_ai=False)
        self._probe(target_url, vuln_type, [item["payload"] for item in result.get("payloads", [])], parameter, method)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        from .brain import AIHyperBrain

        session = self._make_session()
        try:
            self.brain = AIHyperBrain(engine="chat" if self.mode_name == "CHAT" else "native", target=self.target)
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Failed to initialise agent: {exc}[/red]")
            return

        self._status_panel()
        self.console.print("[dim]Type /help for commands. Ctrl+C cancels the current request.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                self.console.print("\n[dim]Interrupted. Type /exit to quit.[/dim]")
                continue
            except EOFError:
                break
            if raw is None:
                continue
            if not self._dispatch(raw):
                break

        self.console.print(f"\n[green]Session closed.[/green] [dim]{self.mode_name} agent offline.[/dim]\n")


class ChatUI(AgentUI):
    mode_name = "CHAT"
    banner = CHAT_BANNER
    commands = CHAT_COMMANDS

    def __init__(self, target: str = ""):
        super().__init__(target=target)


class AutopilotUI(AgentUI):
    mode_name = "AUTOPILOT"
    banner = AUTOPILOT_BANNER
    commands = AUTOPILOT_COMMANDS

    def __init__(self, target: str = ""):
        super().__init__(target=target)

    def run(self) -> None:
        from .brain import AIHyperBrain

        session = self._make_session()
        try:
            self.brain = AIHyperBrain(engine="native", target=self.target)
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]Failed to initialise autopilot: {exc}[/red]")
            return

        self._status_panel()
        if self.target:
            self.console.print(f"[cyan]Target:[/cyan] {self.target}")
        else:
            self.console.print("[yellow]No target set. Use /set-target <host> or /auto <host>.[/yellow]")
        self.console.print("[dim]Type /help for commands. Ctrl+C cancels the current request.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                self.console.print("\n[dim]Interrupted. Type /exit to quit.[/dim]")
                continue
            except EOFError:
                break
            if raw is None:
                continue
            if not self._dispatch(raw):
                break

        self.console.print(f"\n[green]Session closed.[/green] [dim]AUTOPILOT offline.[/dim]\n")


# Backwards-compatible helper used by other modules.
def _clear_screen() -> None:
    console = Console()
    console.clear()
