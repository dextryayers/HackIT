"""Modern terminal UI for HackIt Agent.

The interface is built on Rich (rendering) and prompt_toolkit (input,
completion, persistent history) with a plain ``input()`` fallback for dumb
terminals.  Both Chat and Autopilot share the same engine so every AI provider
and Ollama get the same streaming, memory and payload-forging behaviour.
"""

from __future__ import annotations

import contextlib
import datetime
import html
import json
import os
import re
import sys
import time
import traceback
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.markup import escape
    from rich import box
    _HAS_RICH = True
except ImportError:  # pragma: no cover
    _HAS_RICH = False

    def escape(value: Any) -> str:  # type: ignore[misc]
        return str(value)

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.shortcuts import CompleteStyle
    _HAS_PT = True
except ImportError:  # pragma: no cover
    _HAS_PT = False

from hackit.ui import GREEN, RED, YELLOW, DIM, B_CYAN, MAGENTA, RESET, BOLD, _colored
from .textutils import strip_control

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


class _ReasoningSplitter:
    """Split streaming model output into reasoning and answer segments.

    Local reasoning models (Qwen, Nemotron, DeepSeek distills, ...) emit
    ``<think>...</think>`` blocks as ordinary content.  The splitter is
    incremental and safe across arbitrary chunk boundaries, so the UI can
    render reasoning in a dedicated pane and keep the final answer clean.
    """

    _OPEN = re.compile(r"<(think|thinking|reasoning)>", re.IGNORECASE)
    _CLOSE = re.compile(r"</(think|thinking|reasoning)>", re.IGNORECASE)
    _OPEN_TAGS = ("<think>", "<thinking>", "<reasoning>")
    _CLOSE_TAGS = ("</think>", "</thinking>", "</reasoning>")

    def __init__(self) -> None:
        self.buffer = ""
        self.in_think = False

    @staticmethod
    def _partial_hold(buffer: str, tags: Tuple[str, ...]) -> int:
        hold = 0
        for tag in tags:
            for index in range(1, len(tag)):
                if buffer.endswith(tag[:index]):
                    hold = max(hold, index)
        return hold

    def feed(self, text: str) -> List[Tuple[str, str]]:
        """Return a list of ``(kind, text)`` events; kind is thinking/answer."""
        self.buffer += text or ""
        events: List[Tuple[str, str]] = []

        while self.buffer:
            if self.in_think:
                match = self._CLOSE.search(self.buffer)
                if not match:
                    hold = self._partial_hold(self.buffer, self._CLOSE_TAGS)
                    if hold:
                        if len(self.buffer) > hold:
                            events.append(("thinking", self.buffer[:-hold]))
                        self.buffer = self.buffer[-hold:]
                    else:
                        events.append(("thinking", self.buffer))
                        self.buffer = ""
                    break
                if match.start() > 0:
                    events.append(("thinking", self.buffer[:match.start()]))
                self.buffer = self.buffer[match.end():]
                self.in_think = False
                continue

            match = self._OPEN.search(self.buffer)
            if match:
                if match.start() > 0:
                    events.append(("answer", self.buffer[:match.start()]))
                self.buffer = self.buffer[match.end():]
                self.in_think = True
                continue

            hold = self._partial_hold(self.buffer, self._OPEN_TAGS)
            if hold:
                if len(self.buffer) > hold:
                    events.append(("answer", self.buffer[:-hold]))
                self.buffer = self.buffer[-hold:]
                break
            events.append(("answer", self.buffer))
            self.buffer = ""

        return events

    def flush(self) -> List[Tuple[str, str]]:
        if not self.buffer:
            return []
        kind = "thinking" if self.in_think else "answer"
        tail, self.buffer = self.buffer, ""
        return [(kind, tail)]


def _console() -> "Console":
    if _HAS_RICH:
        return Console(highlight=False, soft_wrap=True)
    raise RuntimeError("rich is required for this UI")


PARAMETERLESS_COMMANDS = {
    "help", "clear", "status", "memory", "facts", "forget", "models",
    "exit", "quit", "retry", "target", "save", "export",
}


class _SlashCompleter(Completer if _HAS_PT else object):  # type: ignore[misc]
    """Command palette with descriptions and payload-type completion."""

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
                prefix = tail.split()[0] if tail else ""
                for item in self.payload_types:
                    if item.startswith(prefix):
                        yield Completion(
                            item,
                            start_position=-len(prefix),
                            display=item,
                            display_meta="payload type",
                            style="class:palette.arg",
                            selected_style="class:palette.arg.selected",
                        )
            return
        for command, description in sorted(self.commands.items()):
            if command.startswith(body):
                yield Completion(
                    f"/{command} ",
                    start_position=-len(text),
                    display=f"/{command}",
                    display_meta=description,
                    style="class:palette.command",
                    selected_style="class:palette.command.selected",
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
        self.tui = False
        self._print_banner()

    # ------------------------------------------------------------------
    # Output abstraction (inline now, full-screen TUI in tui.py)
    # ------------------------------------------------------------------

    def print(self, *args: Any, **kwargs: Any) -> None:
        self.console.print(*args, **kwargs)

    @contextlib.contextmanager
    def status_context(self, message: str) -> Iterator[Any]:
        with self.console.status(message) as status:
            yield status

    def clear_view(self) -> None:
        self.console.clear()

    # ------------------------------------------------------------------
    # Structured long-running operations (scan / OSINT / pentest)
    # ------------------------------------------------------------------

    def begin_operation(self, title: str, target: str = "") -> None:
        label = escape(str(title))
        if target:
            self.print(
                f"[bold cyan]{label}[/bold cyan] [dim]· target {escape(str(target))}[/dim]"
            )
        else:
            self.print(f"[bold cyan]{label}[/bold cyan]")

    def operation_event(
        self,
        phase: str,
        message: str = "",
        status: str = "run",
        pct: Optional[int] = None,
        module: str = "",
    ) -> None:
        label = escape(str(module or phase or "task"))
        detail = escape(str(message or ""))
        suffix = f" [dim]{pct:>3}%[/dim]" if isinstance(pct, int) and pct > 0 else ""
        if status == "error":
            self.print(f"[red]✗[/red] [bold]{label}[/bold] {detail}{suffix}")
        elif status == "done":
            self.print(f"[green]✓[/green] [bold]{label}[/bold] [dim]{detail}[/dim]{suffix}")
        elif status == "complete":
            self.print(f"[bold green]{detail or label}[/bold green]")
        elif status == "log":
            self.print(f"[dim]· {detail or label}[/dim]")
        else:
            self.print(f"[cyan]▶[/cyan] [bold]{label}[/bold] [dim]{detail}[/dim]{suffix}")

    def end_operation(
        self,
        summary: str,
        table: Optional[Any] = None,
        status: str = "ok",
    ) -> None:
        color = {"ok": "green", "error": "red", "cancelled": "yellow"}.get(status, "green")
        self.print(f"[bold {color}]{escape(str(summary))}[/bold {color}]")
        if table is not None:
            self.print(table)


    # ------------------------------------------------------------------
    # Presentation
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        self.clear_view()
        banner = Text(self.banner.strip("\n"), style="bold cyan")
        self.print(banner)
        self.print(
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
            table.add_row(name, Text(str(value)))
        self.print(Panel(table, title="[bold cyan]SESSION[/bold cyan]", border_style="cyan", box=box.ROUNDED))

    def _toolbar(self) -> str:
        if not self.brain:
            return " provider=… model=… "
        memory = self.brain.memory.stats()["messages"] if self.brain.memory else 0
        target = f" · target={self.target}" if self.target else ""
        return f" provider={self.brain.provider or 'none'} · model={self.brain.model or 'auto'} · mem={memory}{target} "

    def _bottom_toolbar(self):
        if _HAS_PT:
            return HTML(
                f"<style bg='#1f2937' fg='#9ca3af'> "
                f"{html.escape(self._toolbar(), quote=False)} </style>"
            )
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
            try:
                from .tui import TUI_STYLE, build_key_bindings

                key_bindings = build_key_bindings(None, tui=False)
                style = TUI_STYLE
            except Exception:
                key_bindings = None
                style = None
            return PromptSession(
                history=FileHistory(history_file),
                completer=completer,
                complete_while_typing=True,
                # READLINE_LIKE only prints matches on Tab; COLUMN renders the
                # palette dropdown as the user types a slash command.
                complete_style=CompleteStyle.COLUMN,
                bottom_toolbar=self._bottom_toolbar,
                enable_history_search=True,
                multiline=False,
                key_bindings=key_bindings,
                style=style,
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
        return self._ask_ai_inline(prompt, system_extra)

    def _ask_ai_inline(self, prompt: str, system_extra: str = "") -> str:
        assert self.brain is not None
        self.last_prompt = prompt
        self.print(
            f"[dim]{_timestamp()}[/dim] [bold cyan]you[/bold cyan] {escape(prompt)}"
        )
        self.print(f"[bold green]hackit[/bold green] [dim]{_timestamp()}[/dim]")

        started = time.time()
        token_count = 0
        rendered: List[str] = []
        thinking_parts: List[str] = []
        answer_parts: List[str] = []
        splitter = _ReasoningSplitter()
        state = {"thinking_started": False, "answer_started": False}

        def emit(kind: str, text: str) -> None:
            nonlocal token_count
            text = strip_control(text)
            if not text:
                return
            token_count += len(text)
            rendered.append(text)
            if kind == "thinking":
                thinking_parts.append(text)
                if not state["thinking_started"]:
                    state["thinking_started"] = True
                    sys.stdout.write(f"\n{DIM}  thinking  {RESET}\n{DIM}")
                sys.stdout.write(text)
            else:
                answer_parts.append(text)
                if not state["answer_started"]:
                    if state["thinking_started"]:
                        sys.stdout.write(f"{RESET}\n\n")
                    sys.stdout.write(f"{BOLD}{GREEN}  response{RESET}\n")
                    state["answer_started"] = True
                sys.stdout.write(text)
            sys.stdout.flush()

        def process_events(events: List[Tuple[str, str]]) -> None:
            for kind, text in events:
                emit(kind, text)

        def on_token(event: Dict[str, Any]) -> None:
            token = event.get("token", "")
            if token:
                process_events(splitter.feed(token))

        try:
            result = self.brain.stream_chat(prompt, on_token=on_token)
        except KeyboardInterrupt:
            self.print("\n[yellow]Cancelled.[/yellow]")
            return ""
        except Exception as exc:  # noqa: BLE001
            self.print(f"\n[red]UI error: {escape(str(exc))}[/red]")
            return ""

        process_events(splitter.flush())
        if not rendered and result:
            # Non-streaming fallback: route through the splitter as well so a
            # reasoning trace can never leak into the terminal unlabelled.
            fallback = _ReasoningSplitter()
            process_events(fallback.feed(result))
            process_events(fallback.flush())
        if state["thinking_started"] or state["answer_started"]:
            sys.stdout.write(RESET + "\n")
            sys.stdout.flush()

        elapsed = time.time() - started
        if result and result.strip().startswith("[!]"):
            message = _strip_ansi(result.strip())
            if message not in "".join(rendered):
                self.print(f"[red]{escape(message)}[/red]")
        elif not state["answer_started"]:
            self.print("[yellow]Model returned reasoning but no final answer.[/yellow]")
        else:
            self.print(
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
        self.print(table)

    def _cmd_status(self) -> None:
        if not self.brain:
            return
        self.print("[dim]Probing providers…[/dim]")
        statuses = self.brain.health()
        if not statuses:
            self.print("[yellow]No provider keys configured. Run `agent setting`.[/yellow]")
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
                Text(str(status.error or status.detail or "—")),
            )
        self.print(table)

    def _cmd_provider(self, argument: str) -> None:
        from . import providers

        if not argument:
            self.print("[dim]Usage: /provider <" + "|".join(providers.PROVIDERS) + ">[/dim]")
            return
        provider = providers.normalize_provider(argument)
        if self.brain and self.brain.set_provider(provider):
            self._persist_provider(provider)
            self.print(f"[green]Provider switched to {escape(str(provider))}.[/green]")
            self.print(f"[dim]Model: {escape(str(self.brain.model or 'auto'))}[/dim]")
        else:
            self.print(f"[red]Provider {escape(str(provider))} has no usable key.[/red]")

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
            self.print(f"[green]Model set to {escape(str(self.brain.model))}.[/green]")
            return
        self.print(f"[dim]Current model: {escape(str(self.brain.model or 'auto'))}[/dim]")
        self.print("[dim]Usage: /model <model-id>[/dim]")

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
            table.add_row(
                str(index), Text(str(model)), Text(str(tier)), Text(str(description)),
            )
        self.print(table)

    def _cmd_payload(self, argument: str) -> None:
        from . import payloads

        if not self.brain:
            return
        if not argument:
            self.print("[dim]Usage: /payload <type> [context] [--probe URL --param name][/dim]")
            self.print(f"[dim]Types: {', '.join(payloads.catalog_types())}[/dim]")
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
            self.print("[red]Missing vulnerability type.[/red]")
            return
        vuln_type = keep[0]
        context = " ".join(keep[1:]) or (self.target or "")

        with self.status_context(f"[cyan]Forging {vuln_type} payloads…[/cyan]"):
            result = self.brain.generate_payloads(vuln_type, context=context, count=12)

        table = Table(title=f"PAYLOAD FORGE · {result.get('type')}", box=box.SIMPLE_HEAVY)
        table.add_column("#", width=4, style="dim")
        table.add_column("Payload", style="cyan", overflow="fold")
        table.add_column("Technique")
        table.add_column("Notes", style="dim")
        for index, item in enumerate(result.get("payloads", []), 1):
            table.add_row(
                str(index),
                Text(str(item.get("payload", ""))),
                Text(str(item.get("technique", ""))),
                Text(str(item.get("notes", ""))),
            )
        self.print(table)
        if result.get("ai_error"):
            self.print(f"[yellow]AI note: {escape(str(result['ai_error']))}[/yellow]")

        os.makedirs(os.path.join(REPORTS_DIR, "payloads"), exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(REPORTS_DIR, "payloads", f"{result.get('type')}_{stamp}.json")
        try:
            payloads.save({"results": {result.get("type", vuln_type): result}}, path)
            self.print(f"[dim]Saved: {escape(str(path))}[/dim]")
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
            self.print(
                "[yellow]Probing disabled: set HACKIT_AUTHORIZED=1 to confirm you are authorised to test this target.[/yellow]"
            )
            return

        self.print(f"[dim]Probing {len(payload_list)} payload(s) against {escape(str(target_url))}…[/dim]")
        results: List[Dict[str, Any]] = []

        def on_result(item: Dict[str, Any]) -> None:
            results.append(item)
            if item.get("vulnerable"):
                self.print(
                    f"[red]![/red] {escape(str(item['payload']))} -> {escape(str(item['evidence']))}"
                )
            else:
                self.print(
                    f"[dim]· {escape(str(item['payload']))} -> {escape(str(item['evidence']))}[/dim]"
                )

        payloads.probe_many(
            target_url, vuln_type, payload_list, parameter=parameter,
            method=method, on_result=on_result,
        )
        self.print(f"[bold]{escape(payloads.summarize_probe(results))}[/bold]")

    def _cmd_memory(self) -> None:
        if not self.brain or not self.brain.memory:
            self.print("[dim]Memory disabled.[/dim]")
            return
        stats = self.brain.memory.stats()
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim")
        table.add_column(style="bold")
        for key, value in stats.items():
            table.add_row(str(key), Text(str(value)))
        self.print(Panel(table, title="MEMORY", border_style="magenta", box=box.ROUNDED))

    def _cmd_facts(self) -> None:
        if not self.brain or not self.brain.memory:
            return
        facts = self.brain.memory._facts  # noqa: SLF001 - intentional read-only view
        if not facts:
            self.print("[dim]No long-term facts yet.[/dim]")
            return
        for fact in facts:
            self.print(f"[cyan]·[/cyan] {escape(str(fact))}")

    def _cmd_save(self, path: str) -> None:
        if not self.brain or not self.brain.memory:
            return
        if not path:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = f"hackit_memory_{stamp}.json"
        try:
            self.brain.memory.export(path)
            self.print(f"[green]Memory saved to {escape(str(path))}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Save failed: {escape(str(exc))}[/red]")

    def _cmd_load(self, path: str) -> None:
        if not self.brain or not self.brain.memory:
            return
        try:
            count = self.brain.memory.import_file(path)
            self.print(f"[green]Imported {count} messages from {escape(str(path))}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Load failed: {escape(str(exc))}[/red]")

    def _cmd_scan(self, argument: str) -> None:
        tokens = [item for item in argument.split() if item]
        known_modules = {
            "all", "portscan", "subdomain", "ssl", "headers", "tech", "waf",
            "fuzz", "js", "param", "cors", "csrf", "xxe", "sqli", "xss",
            "ssrf", "redirect", "lfi", "ssti", "cmd", "nosqli", "ldap",
            "graphql", "bypass403", "takeover", "jwt",
        }
        if tokens and tokens[0].lower() not in known_modules:
            # `/scan https://host/path sqli` and `/scan example.com` both work.
            self.target = tokens[0]
            tokens = tokens[1:]
        if not self.target:
            self.print("[yellow]Set a target first: /target <host> or /set-target <host>[/yellow]")
            return
        if not self.brain:
            return
        modules = tokens
        self.begin_operation("SCAN", str(self.target))

        def on_progress(event: Dict[str, Any]) -> None:
            kind = str(event.get("event", ""))
            status = {
                "start": "run", "retry": "run", "done": "done",
                "error": "error", "complete": "complete", "log": "log",
            }.get(kind, "run")
            self.operation_event(
                phase=str(event.get("module") or "scan"),
                message=str(event.get("message", "")),
                status=status,
                pct=event.get("pct") if isinstance(event.get("pct"), int) else None,
                module=str(event.get("module") or ""),
            )

        results = self.brain.stream_hative(self.target, on_progress=on_progress, modules=modules or None)
        cancelled = bool(getattr(self.brain, "cancelled", False))
        if not results:
            self.end_operation(
                "Scan cancelled." if cancelled else "Scan completed with no results.",
                status="cancelled" if cancelled else "error",
            )
            return

        def count_findings(data: Any) -> int:
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in ("findings", "results", "vulnerabilities", "issues"):
                    value = data.get(key)
                    if isinstance(value, list):
                        return len(value)
                return 1 if data else 0
            return 0

        findings = 0
        table = Table(
            title="SCAN RESULTS",
            box=box.SIMPLE_HEAVY,
            title_justify="left",
            pad_edge=False,
        )
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Findings", justify="right")
        table.add_column("Time", justify="right", style="dim")
        table.add_column("Note", style="dim", overflow="fold")
        for item in results:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            count = count_findings(data)
            findings += count
            error = str(item.get("error") or "")
            success = bool(item.get("success")) and not error
            status_text = Text("ok" if success else "error", style=GREEN if success else RED)
            elapsed = item.get("elapsed_seconds")
            elapsed_text = f"{float(elapsed):.1f}s" if isinstance(elapsed, (int, float)) else "—"
            table.add_row(
                Text(str(item.get("module") or "module")),
                status_text,
                Text(str(count)),
                elapsed_text,
                Text(error[:160]),
            )
        self.end_operation(
            f"Scan complete · {len(results)} module(s) · {findings} finding(s)",
            table,
        )


    def _cmd_osint(self, query: str) -> None:
        if not query:
            query = self.target
        if not query:
            self.print("[yellow]Usage: /osint <username|email|domain>[/yellow]")
            return
        self.begin_operation("OSINT", str(query))
        try:
            from hackit.osint.core import run_full_scan

            def on_step(phase: str, message: str) -> None:
                phase = str(phase).lower()
                message = str(message)
                if phase == "tick":
                    # ``platform [status]|checked|total`` – keep one live row
                    # instead of appending a new line for every probe.
                    label = message
                    pct = None
                    parts = message.split("|")
                    if len(parts) >= 3:
                        label = parts[0]
                        try:
                            checked, total = int(parts[1]), int(parts[2])
                            pct = int(checked / max(1, total) * 100)
                            label = f"{label} · {checked}/{total}"
                        except ValueError:
                            pass
                    self.operation_event(
                        "sweep", label, status="run", pct=pct, module="sweep",
                    )
                elif phase in ("warn", "note"):
                    self.operation_event(phase, message, status="log")
                else:
                    self.operation_event(phase, message, status="run")

            data = run_full_scan(
                query, timeout=8, workers=24, verbose=False,
                check_phone=True, check_domain=True,
                on_step=on_step,
            )
            profiles = data.get("profiles", [])
            hits = data.get("summary", {}).get("hits", 0)
            possible = data.get("summary", {}).get("possible", 0)
            confidence = data.get("analysis", {}).get("confidence_score", 0)

            table = None
            visible = [
                item for item in profiles
                if isinstance(item, dict) and str(item.get("status", "")).lower() in ("hit", "possible")
            ]
            if visible:
                table = Table(
                    title="OSINT SIGNALS",
                    box=box.SIMPLE_HEAVY,
                    title_justify="left",
                    pad_edge=False,
                )
                table.add_column("Platform", style="cyan", no_wrap=True)
                table.add_column("Handle", no_wrap=True)
                table.add_column("Status", no_wrap=True)
                table.add_column("Confidence", no_wrap=True)
                table.add_column("URL", style="dim", overflow="fold")
                for item in visible[:20]:
                    status = str(item.get("status", "")).lower()
                    table.add_row(
                        Text(str(item.get("platform", ""))),
                        Text(str(item.get("handle", ""))),
                        Text(status, style=GREEN if status == "hit" else "#f59e0b"),
                        Text(str(item.get("confidence", ""))),
                        Text(str(item.get("url", ""))),
                    )
                if len(visible) > 20:
                    table.caption = f"{len(visible) - 20} more signal(s) in the JSON report"
                    table.caption_justify = "left"

            self.end_operation(
                f"OSINT complete · {len(profiles)} checked · {hits} hit(s) · "
                f"{possible} possible · confidence {confidence}/100",
                table,
            )
            os.makedirs(os.path.join(REPORTS_DIR, "osint"), exist_ok=True)
            path = os.path.join(REPORTS_DIR, "osint", f"{query.replace('/', '_')}_{time.strftime('%Y%m%d_%H%M%S')}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, default=str)
            self.print(f"[dim]Saved: {escape(str(path))}[/dim]")
        except Exception as exc:  # noqa: BLE001
            self.end_operation(f"OSINT failed: {exc}", status="error")


    def _cmd_auto(self, target: str) -> None:
        target = target or self.target
        if not target:
            self.print("[yellow]Usage: /auto <target>[/yellow]")
            return
        self.target = target
        self.begin_operation("AUTONOMOUS PENTEST", str(target))
        try:
            from .workflow import NODE_SEQUENCE, run_pentest

            phase_order = [name for name, _node in NODE_SEQUENCE]
            phase_total = max(1, len(phase_order))

            def progress(phase: str, message: str) -> None:
                phase = str(phase)
                message = str(message)
                status = "run"
                pct = None
                if phase in phase_order:
                    index = phase_order.index(phase)
                    starting = message.startswith("starting ")
                    if not starting:
                        status = "done"
                    pct = int((index + (0 if starting else 1)) / phase_total * 100)
                elif phase == "workflow":
                    status = "log"
                elif message.startswith("error:"):
                    status = "error"
                self.operation_event(phase, message, status=status, pct=pct)

            cancel_event = None
            if self.brain is not None:
                self.brain.reset_cancel()
                cancel_event = self.brain.cancel_event

            state = run_pentest(
                target, scope="active_stealth", progress=progress,
                cancel_event=cancel_event,
            )
            cancelled = bool(
                (state.get("cancelled") if isinstance(state, dict) else False)
                or getattr(self.brain, "cancelled", False)
            )
            if cancelled:
                self.end_operation(
                    "Pipeline cancelled. Running tool processes were stopped.",
                    status="cancelled",
                )
                return
            findings = state.get("findings", []) if isinstance(state, dict) else []
            report_path = state.get("report_path") if isinstance(state, dict) else ""
            risk = state.get("risk_score", 0.0) if isinstance(state, dict) else 0.0

            table = None
            if findings:
                order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                ranked = sorted(
                    findings,
                    key=lambda item: order.get(str(item.get("severity", "info")).lower(), 5),
                )
                table = Table(
                    title="FINDINGS",
                    box=box.SIMPLE_HEAVY,
                    title_justify="left",
                    pad_edge=False,
                )
                table.add_column("Severity", no_wrap=True)
                table.add_column("CVSS", justify="right", no_wrap=True)
                table.add_column("Type", style="cyan", no_wrap=True)
                table.add_column("Target", overflow="fold")
                table.add_column("Evidence", style="dim", overflow="fold")
                colors = {
                    "critical": "#fb7185", "high": "#f59e0b", "medium": "#facc15",
                    "low": "#34d399", "info": "#94a3b8",
                }
                for item in ranked[:30]:
                    severity = str(item.get("severity", "info")).lower()
                    cvss = item.get("cvss")
                    table.add_row(
                        Text(severity, style=f"bold {colors.get(severity, '#94a3b8')}"),
                        Text(str(cvss if cvss is not None else "—")),
                        Text(str(item.get("type", ""))),
                        Text(str(item.get("target", ""))),
                        Text(str(item.get("evidence", ""))[:220]),
                    )
                if len(ranked) > 30:
                    table.caption = f"{len(ranked) - 30} more finding(s) in the report"
                    table.caption_justify = "left"

            self.end_operation(
                f"Pipeline complete · {len(findings)} finding(s) · risk {risk}/10",
                table,
            )
            if report_path:
                self.print(f"[dim]Report: {escape(str(report_path))}[/dim]")
        except Exception as exc:  # noqa: BLE001
            self.end_operation(f"Pipeline failed: {exc}", status="error")
            if os.environ.get("HACKIT_DEBUG"):
                self.print(traceback.format_exc())


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
            self.print(f"[green]Conversation exported to {escape(str(path))}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Export failed: {escape(str(exc))}[/red]")

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
            self.print(f"[green]Imported {count} message(s) from {escape(str(path))}[/green]")
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Import failed: {escape(str(exc))}[/red]")

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
            self.clear_view()
            self._print_banner()
            if self.brain and self.brain.memory:
                self.brain.memory.clear()
            self.print("[dim]Screen and conversation cleared.[/dim]")
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
                self.print("[green]Conversation memory cleared.[/green]")
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
            self.print(f"[cyan]Target:[/cyan] {escape(str(self.target or '—'))}")
            return True
        if head in ("set-target", "set_target"):
            self.target = rest
            self.print(f"[cyan]Target locked:[/cyan] {escape(str(self.target))}")
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
                self.print("[dim]Nothing to retry.[/dim]")
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
                self.print("[yellow]Set a target first: /target <host>[/yellow]")
                return True
            module = module_aliases[head]
            self._cmd_scan(module)
            return True

        # Unknown slash command -> send to the AI as a mode command.
        self._ask_ai(text)
        return True

    def _cmd_probe_command(self, rest: str) -> None:
        if not rest:
            self.print("[dim]Usage: /probe <type> <url> [--param name] [--method GET][/dim]")
            return
        parts = rest.split()
        if len(parts) < 2:
            self.print("[dim]Usage: /probe <type> <url> [--param name] [--method GET][/dim]")
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
            self.print(f"[red]Failed to initialise agent: {escape(str(exc))}[/red]")
            return

        self._status_panel()
        self.print("[dim]Type /help for commands. Ctrl+C cancels the current request.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                self.print("\n[dim]Interrupted. Type /exit to quit.[/dim]")
                continue
            except EOFError:
                break
            if raw is None:
                continue
            if not self._dispatch(raw):
                break

        self.print(f"\n[green]Session closed.[/green] [dim]{self.mode_name} agent offline.[/dim]\n")


class ChatUI(AgentUI):
    mode_name = "CHAT"
    banner = CHAT_BANNER
    commands = CHAT_COMMANDS

    def __init__(self, target: str = ""):
        super().__init__(target=target)

    def run(self) -> None:
        from .tui import can_use_tui

        if can_use_tui():
            from .tui import ChatTUI

            ChatTUI(target=self.target).run()
            return
        super().run()


class AutopilotUI(AgentUI):
    mode_name = "AUTOPILOT"
    banner = AUTOPILOT_BANNER
    commands = AUTOPILOT_COMMANDS

    def __init__(self, target: str = ""):
        super().__init__(target=target)

    def run(self) -> None:
        from .tui import can_use_tui

        if can_use_tui():
            from .tui import AutopilotTUI

            AutopilotTUI(target=self.target).run()
            return

        from .brain import AIHyperBrain

        session = self._make_session()
        try:
            self.brain = AIHyperBrain(engine="native", target=self.target)
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Failed to initialise autopilot: {escape(str(exc))}[/red]")
            return

        self._status_panel()
        if self.target:
            self.print(f"[cyan]Target:[/cyan] {escape(str(self.target))}")
        else:
            self.print("[yellow]No target set. Use /set-target <host> or /auto <host>.[/yellow]")
        self.print("[dim]Type /help for commands. Ctrl+C cancels the current request.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                self.print("\n[dim]Interrupted. Type /exit to quit.[/dim]")
                continue
            except EOFError:
                break
            if raw is None:
                continue
            if not self._dispatch(raw):
                break

        self.print(f"\n[green]Session closed.[/green] [dim]AUTOPILOT offline.[/dim]\n")


def create_ui(mode: str, target: str = "") -> AgentUI:
    """Create the best UI available for this terminal.

    The full-screen renderer is selected before construction so the inline
    banner is never painted on terminals that immediately switch to the
    alternate screen.
    """
    if mode == "autopilot":
        from .tui import AutopilotTUI, can_use_tui

        if can_use_tui():
            return AutopilotTUI(target=target)
        return AutopilotUI(target=target)

    from .tui import ChatTUI, can_use_tui

    if can_use_tui():
        return ChatTUI(target=target)
    return ChatUI(target=target)


# Backwards-compatible helper used by other modules.
def _clear_screen() -> None:
    console = Console()
    console.clear()
