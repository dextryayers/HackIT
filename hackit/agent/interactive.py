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
    "set-target": "Lock target domain/IP (auto-runs autopilot)",
    "target": "Show current target",
    "autopilot": "Run full autonomous pentest (target optional)",
    "recon": "Full recon: ports, subdomains, dir fuzz, JS crawl, tech, WAF",
    "full": "Full pentest pipeline (alias for /autopilot)",
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
    "autopilot": "Run full autonomous pentest (target optional)",
    "progress": "Show/hide live progress",
    "hide": "Hide progress output",
    "show": "Show buffered progress",
    "osint": "Run OSINT profile discovery",
    "status": "Provider / model connectivity",
    "model": "Switch model (arrow-key picker)",
    "select": "Central model select (chat, /halo, autopilot, auto)",
    "provider": "Switch provider",
    "usage": "Live token usage (session + all-time)",
    "tokens": "Live token usage (alias)",
    "memory": "Show memory statistics",
    "forget": "Clear conversation memory",
    "export": "Export conversation [filename]",
    "import": "Import conversation [filename]",
    "help": "Show all commands",
    "clear": "Clear screen",
    "doctor": "Deep provider diagnostics",
    "setting": "Configure AI providers, keys and models",
    "models": "List available models",
    "guide": "Full slash-command reference",
    "reset": "Reset AI keys / provider / models",
    "exit": "Exit autopilot",
    "quit": "Exit autopilot",
}

CHAT_COMMANDS = {
    "recon": "Full recon: ports, subdomains, dir fuzz, JS crawl, tech, WAF",
    "full": "Full pentest pipeline (alias for /autopilot)",
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
    "auto": "Run the full autonomous pipeline",
    "autopilot": "Run full autonomous pentest (target optional)",
    "progress": "Show/hide live progress",
    "hide": "Hide progress output",
    "show": "Show buffered progress",
    "osint": "Run OSINT profile discovery",
    "scan": "Run full hative security scan",
    "status": "Provider / model connectivity",
    "model": "Switch model (arrow-key picker)",
    "select": "Central model select (chat, /halo, autopilot, auto)",
    "provider": "Switch provider",
    "models": "List available models",
    "usage": "Live token usage (session + all-time)",
    "tokens": "Live token usage (alias)",
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
    "doctor": "Deep provider diagnostics",
    "setting": "Configure AI providers, keys and models",
    "guide": "Full slash-command reference",
    "reset": "Reset AI keys / provider / models",
    "exit": "Exit chat",
    "quit": "Exit chat",
}

# Merge the 40+ specialized AI modes so they are discoverable in the
# "/" palette and autocomplete, and routed to the AI engine.
try:
    from .commands import COMMAND_MODES as _AI_MODES
except Exception:  # pragma: no cover - defensive
    _AI_MODES = {}
for _name, _desc in _AI_MODES.items():
    if _name not in CHAT_COMMANDS:
        CHAT_COMMANDS[_name] = _desc
    if _name not in AUTOPILOT_COMMANDS:
        AUTOPILOT_COMMANDS[_name] = _desc
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
    "usage", "tokens", "progress", "hide", "show", "exit", "quit",
    "retry", "target", "save", "export",
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
        # Autopilot visibility + background run state.
        self._progress_hidden = False
        self._autopilot_running = False
        self._autopilot_thread = None
        self._autopilot_cancel = None
        self._autopilot_state = None
        self._autopilot_phase = ""
        self._autopilot_lock = __import__("threading").Lock()
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
        # Hidden mode buffers phase chatter but always shows findings,
        # errors and completion. Buffered events replay on /show.
        if self._progress_hidden:
            if status not in ("error", "complete"):
                if not hasattr(self, "_hidden_buffer"):
                    self._hidden_buffer = []
                self._hidden_buffer.append(
                    (phase, message, status, pct, module)
                )
                if len(self._hidden_buffer) > 500:
                    self._hidden_buffer = self._hidden_buffer[-500:]
                return
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
    # Progress visibility (hide / show)
    # ------------------------------------------------------------------

    def set_progress_hidden(self, hidden: bool) -> List[Tuple[str, str, str, Any, str]]:
        """Toggle progress visibility. Returns buffered events when showing."""
        self._progress_hidden = bool(hidden)
        if hidden:
            self.print("[dim]Progress hidden. Running phases are buffered — /show to replay.[/dim]")
            return []
        buffered = getattr(self, "_hidden_buffer", []) or []
        if hasattr(self, "_hidden_buffer"):
            self._hidden_buffer = []
        else:
            buffered = []
        if buffered:
            self.print(f"[dim]Progress visible — replaying {len(buffered)} buffered event(s).[/dim]")
        else:
            self.print("[dim]Progress visible.[/dim]")
        return buffered

    def is_progress_hidden(self) -> bool:
        return bool(getattr(self, "_progress_hidden", False))

    def _replay_buffered(self, events: List[Tuple[str, str, str, Any, str]]) -> None:
        if not events:
            return
        # Temporarily force visibility so replay actually renders.
        self._progress_hidden = False
        for phase, message, status, pct, module in events:
            self.operation_event(phase, message, status=status, pct=pct, module=module)

    def _cmd_progress(self, argument: str) -> None:
        arg = (argument or "").strip().lower()
        if arg in ("hide", "hidden", "off"):
            self.set_progress_hidden(True)
        elif arg in ("show", "visible", "on", "unhide"):
            buffered = self.set_progress_hidden(False)
            self._replay_buffered(buffered)
        elif arg == "status":
            hidden = self.is_progress_hidden()
            buffered_count = len(getattr(self, "_hidden_buffer", []) or [])
            autopilot = "running" if self._autopilot_running else "idle"
            self.print(
                f"[dim]Progress: {'hidden' if hidden else 'visible'} "
                f"· buffered: {buffered_count} · autopilot: {autopilot} "
                f"· phase: {escape(str(self._autopilot_phase or '—'))}[/dim]"
            )
        else:
            buffered = self.set_progress_hidden(not self._progress_hidden)
            self._replay_buffered(buffered)

    # ------------------------------------------------------------------
    # Autopilot background runner
    # ------------------------------------------------------------------

    def _autopilot_start(self, target: str) -> bool:
        """Start the full pipeline in a background thread. Returns False if busy."""
        import threading

        target = (target or self.target or "").strip()
        if not target:
            self.print("[yellow]Usage: /autopilot <target>  (or /set-target first)[/yellow]")
            return False
        with self._autopilot_lock:
            if self._autopilot_running:
                self.print("[yellow]Autopilot already running — /autopilot stop to cancel.[/yellow]")
                return False
            self._autopilot_running = True
            self._autopilot_phase = "recon"
            self._autopilot_state = None
            cancel = threading.Event()
            if self.brain is not None and hasattr(self.brain, "cancel_event"):
                cancel = self.brain.cancel_event
                self.brain.reset_cancel()
            self._autopilot_cancel = cancel
            self.target = target

        self.begin_operation("AUTONOMOUS PENTEST", str(target))
        self.print(
            "[dim]AI is running the full pipeline: recon → osint → js → params → "
            "payload → analyse → plan → execute → probe → correlate → report. "
            "/progress hide to silence the chatter. Ctrl+C / /autopilot stop to cancel.[/dim]"
        )

        def _runner() -> None:
            try:
                from .workflow import run_pentest, NODE_SEQUENCE

                phase_order = [name for name, _node in NODE_SEQUENCE]
                phase_total = max(1, len(phase_order))

                def _progress(phase: str, message: str) -> None:
                    phase = str(phase)
                    message = str(message)
                    self._autopilot_phase = phase
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

                state = run_pentest(
                    target, scope="active_stealth", progress=_progress,
                    cancel_event=cancel, authorized=True,
                )
                with self._autopilot_lock:
                    self._autopilot_state = state
                    self._autopilot_running = False
                    self._autopilot_phase = "done"
                cancelled = bool(
                    (state.get("cancelled") if isinstance(state, dict) else False)
                ) or (self.brain is not None and getattr(self.brain, "cancelled", False))
                if cancelled:
                    self.end_operation(
                        "Autopilot cancelled. Running tool processes were stopped.",
                        status="cancelled",
                    )
                    return
                self._render_autopilot_result(state)
            except Exception as exc:  # noqa: BLE001
                with self._autopilot_lock:
                    self._autopilot_running = False
                    self._autopilot_phase = "error"
                    self._autopilot_state = {"error": str(exc)}
                self.end_operation(f"Autopilot failed: {exc}", status="error")
                if os.environ.get("HACKIT_DEBUG"):
                    self.print(traceback.format_exc())

        self._autopilot_thread = threading.Thread(target=_runner, daemon=True, name="autopilot")
        self._autopilot_thread.start()
        return True

    def _render_autopilot_result(self, state: Any) -> None:
        if not isinstance(state, dict):
            self.end_operation("Autopilot finished with no state.", status="error")
            return
        findings = state.get("findings", []) or []
        report_path = state.get("report_path") or ""
        risk = state.get("risk_score", 0.0)
        coverage = state.get("coverage", {}) or {}
        attack_log = state.get("attack_log", []) or []
        analysis = state.get("analysis", "") or ""

        if coverage:
            coverage_table = Table(
                title="ACTIVE COVERAGE",
                box=box.SIMPLE_HEAVY,
                title_justify="left",
                pad_edge=False,
            )
            coverage_table.add_column("Metric", style="dim", no_wrap=True)
            coverage_table.add_column("Value", overflow="fold")
            modules = ", ".join(str(item) for item in coverage.get("execute_modules", [])) or "—"
            targets = coverage.get("execute_targets", []) or []
            probe_targets = coverage.get("probe_targets", []) or []
            probe_types = coverage.get("probe_types", []) or []
            parameters = coverage.get("parameters", []) or []
            coverage_table.add_row("authorized", "yes" if state.get("authorized") else "no")
            coverage_table.add_row("module tasks", f"{coverage.get('execute_tasks', 0)} across {len(targets)} target(s)")
            coverage_table.add_row("modules", modules)
            coverage_table.add_row("endpoints", f"{len(coverage.get('endpoints', []) or [])} discovered")
            coverage_table.add_row("parameters", ", ".join(str(item) for item in parameters[:12]) or "—")
            coverage_table.add_row("payload probes", f"{coverage.get('probe_attempted', 0)} across {len(probe_targets)} target(s), {len(probe_types)} type(s)")
            coverage_table.add_row("probe signals", str(coverage.get("probe_signals", 0)))
            coverage_table.add_row("attack log", f"{len(attack_log)} action(s)")
            self.print(coverage_table)

        if analysis:
            excerpt = strip_control(str(analysis)).strip()
            if len(excerpt) > 1800:
                excerpt = "…\n" + excerpt[-1800:]
            self.print(
                Panel(
                    Text(excerpt, style="#e2e8f0"),
                    title=Text(" ANALYSIS ", style="bold #22d3ee"),
                    title_align="left",
                    border_style="#1e293b",
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )

        table = None
        if findings:
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            ranked = sorted(findings, key=lambda item: order.get(str(item.get("severity", "info")).lower(), 5))
            table = Table(
                title="FINDINGS", box=box.SIMPLE_HEAVY, title_justify="left", pad_edge=False,
            )
            table.add_column("Severity", no_wrap=True)
            table.add_column("CVSS", justify="right", no_wrap=True)
            table.add_column("Type", style="cyan", no_wrap=True)
            table.add_column("Target", overflow="fold")
            table.add_column("Evidence", style="dim", overflow="fold")
            colors = {"critical": "#fb7185", "high": "#f59e0b", "medium": "#facc15", "low": "#34d399", "info": "#94a3b8"}
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
            f"Autopilot complete · {len(findings)} finding(s) · risk {risk}/10 · "
            f"{coverage.get('execute_tasks', 0)} module task(s) · "
            f"{coverage.get('probe_attempted', 0)} payload probe(s) · "
            f"{coverage.get('probe_signals', 0)} probe signal(s)",
            table,
        )
        if report_path:
            self.print(f"[dim]Report: {escape(str(report_path))}[/dim]")

    def _autopilot_stop(self) -> bool:
        with self._autopilot_lock:
            if not self._autopilot_running:
                self.print("[dim]Autopilot is not running.[/dim]")
                return False
            cancel = self._autopilot_cancel
        if cancel is not None:
            cancel.set()
        if self.brain is not None and hasattr(self.brain, "cancel_stream"):
            try:
                self.brain.cancel_stream()
            except Exception:
                pass
        self.print("[yellow]Autopilot cancellation requested.[/yellow]")
        return True

    def _cmd_autopilot(self, argument: str) -> None:
        arg = (argument or "").strip()
        low = arg.lower()
        if low == "stop":
            self._autopilot_stop()
            return
        if low == "status":
            running = "running" if self._autopilot_running else "idle"
            self.print(
                f"[dim]Autopilot: {running} · phase: {escape(str(self._autopilot_phase or '—'))} "
                f"· target: {escape(str(self.target or '—'))} · "
                f"progress: {'hidden' if self._progress_hidden else 'visible'}[/dim]"
            )
            return
        target = arg or self.target
        if not target:
            self.print("[yellow]Target belum terkunci.[/yellow]")
            self.print("[dim]Ketik [green]/set-target example.com[/green] untuk mengunci dan langsung menjalankan autopilot. Atau [green]/autopilot example.com[/green].[/dim]")
            self.print("[dim]Setelah target terkunci, serangan pentest berjalan otomatis. AI tetap bisa diajak ngobrol — sebutkan tugasnya (recon, port scan, subdomain, js crawl, dir brute force, sqli…), tool asli akan jalan.[/dim]")
            return
        # /autopilot with no target in autopilot mode reuses the locked target.
        self._autopilot_start(target)


    # ------------------------------------------------------------------
    # Presentation
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        self.clear_view()
        banner = Text(self.banner.strip("\n"), style="bold cyan")
        self.print(banner)
        if self.mode_name == "AUTOPILOT":
            pipeline = "recon → osint → js → params → payload → analyse → plan → execute → probe → correlate → report"
            self.print(
                Panel(
                    Text.from_markup(
                        "[bold]HackIt Autopilot[/bold]  [dim]v2.2 · high-precision cyber expert[/dim]\n"
                        f"[dim]{pipeline}[/dim]\n\n"
                        "[green]/set-target example.com[/green] kunci target → autopilot jalan otomatis\n"
                        "[green]/recon example.com[/green]   ports · subdomain · dir fuzz · JS crawl · tech · WAF\n"
                        "[green]/autopilot[/green]  pipeline penuh   [green]/progress hide[/green]  sembunyikan progress\n"
                        "[green]/help[/green] commands   [green]Tab[/green] autocomplete   [green]Ctrl+C[/green] cancel"
                    ),
                    border_style="cyan",
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )
            return
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
        usage = brain.usage_summary() if hasattr(brain, "usage_summary") else {}
        usage_text = brain.usage_text() if hasattr(brain, "usage_text") else "~0 tokens"
        rows = [
            ("Engine", brain.engine),
            ("Provider", brain.provider or "none"),
            ("Model", model),
            ("Tokens", usage_text),
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
        usage = ""
        if hasattr(self.brain, "usage_summary"):
            s = self.brain.usage_summary()
            usage = f" · tok ~{s['total']:,} ({s['turns']}t)"
        return f" provider={self.brain.provider or 'none'} · model={self.brain.model or 'auto'} · mem={memory}{usage}{target} "

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
            if not token:
                return
            kind = str(event.get("kind") or "")
            if kind in ("thinking", "answer"):
                process_events([(kind, token)])
            else:
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
            live = self.brain.usage_summary() if hasattr(self.brain, "usage_summary") else {}
            session = f" · session ~{live.get('total', token_count // 4):,} tok" if live.get("total") else ""
            self.print(
                f"[dim]{_timestamp()} · {elapsed:.1f}s · ~{max(1, token_count // 4)} tok this turn{session}[/dim]"
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
            self.print("[dim]After switching, run /select to pick the model for the new provider.[/dim]")
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

    def _cmd_select(self, argument: str) -> None:
        """Central model selection shared by chat, /halo, autopilot and auto.

        Opens the arrow-key picker when the active provider exposes more than
        one model, otherwise it shows the current choice and (when no model was
        chosen yet) the default that will be used. A model id may also be
        passed directly: ``/select <model-id>``.
        """
        if not self.brain:
            return
        provider = self.brain.provider or "gemini"
        current = self.brain.model or "auto"
        items = self.brain.model_choices(include_remote=True)

        # Direct form: /select <model-id>
        if argument:
            model_id = argument.strip()
            if not model_id:
                return
            if self.brain.switch_model(model_id):
                self.print(f"[green]Model set to {escape(str(self.brain.model))} for {escape(str(provider))}.[/green]")
                self.print("[dim]Applies to chat, /halo, autopilot and auto.[/dim]")
            else:
                self.print(f"[red]Invalid model id: {escape(model_id)}[/red]")
            return

        if not items:
            self.print(f"[dim]Current model: {escape(str(current))} ({escape(str(provider))})[/dim]")
            self.print("[dim]No models discovered. Usage: /select <model-id>[/dim]")
            return

        if len(items) == 1:
            only = items[0][0]
            self.print(f"[dim]Only one model available for {escape(str(provider))}: {escape(str(only))}[/dim]")
            if self.brain.switch_model(only):
                self.print(f"[green]Model set to {escape(str(only))}.[/green]")
            return

        # >1 model: open the picker. The active model is highlighted.
        try:
            from . import _dropdown_select
        except Exception:  # pragma: no cover - defensive
            _dropdown_select = None  # type: ignore[assignment]
        if _dropdown_select is None:
            self.print("[dim]Usage: /select <model-id>[/dim]")
            return
        ids = [item[0] for item in items]
        chosen = _dropdown_select(provider, items, ids)
        if not chosen:
            self.print("[dim]Model unchanged.[/dim]")
            return
        if self.brain.switch_model(chosen):
            self.print(f"[green]Model set to {escape(chosen)} for {escape(str(provider))}.[/green]")
            self.print("[dim]Applies to chat, /halo, autopilot and auto.[/dim]")
        else:
            self.print(f"[red]Could not switch to {escape(chosen)}.[/red]")

    def _cmd_usage(self) -> None:
        """Show live token usage for this session and all past sessions."""
        if not self.brain:
            return
        try:
            from .usage import session_totals, format_total
        except Exception:  # pragma: no cover
            self.print("[dim]Token tracking unavailable.[/dim]")
            return
        live = self.brain.usage_summary() if hasattr(self.brain, "usage_summary") else {}
        history = session_totals()
        table = Table(title="TOKEN USAGE", box=box.SIMPLE)
        table.add_column("Scope", style="dim")
        table.add_column("Tokens", style="cyan")
        table.add_column("Turns", style="white")
        table.add_column("Detail", style="dim")
        table.add_row(
            "This session",
            f"~{live.get('total', 0):,}",
            str(live.get("turns", 0)),
            f"prompt ~{live.get('prompt', 0):,} · completion ~{live.get('completion', 0):,} · reasoning ~{live.get('reasoning', 0):,}",
        )
        table.add_row(
            "All time",
            f"~{history['total']:,}",
            str(history["turns"]),
            f"{history['entries']} session(s) persisted",
        )
        self.print(table)
        self.print(f"[dim]Model: {escape(str(self.brain.provider or 'none'))} · {escape(str(self.brain.model or 'auto'))}[/dim]")
        self.print("[dim]Estimated at ~4 characters/token. Usage is written to ~/.hackit/token_usage.json each turn.[/dim]")

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

        # No argument: open the arrow-key selector so a provider that exposes
        # more than one model can be switched without typing the id.
        items = self.brain.list_models(include_remote=True)
        if not items:
            self.print(f"[dim]Current model: {escape(str(self.brain.model or 'auto'))}[/dim]")
            self.print("[dim]No models discovered. Usage: /model <model-id>[/dim]")
            return
        try:
            from . import _dropdown_select
        except Exception:  # pragma: no cover - defensive
            _dropdown_select = None  # type: ignore[assignment]
        if _dropdown_select is None:
            self.print("[dim]Usage: /model <model-id>[/dim]")
            return
        chosen = _dropdown_select(self.brain.provider, items, [i[0] for i in items])
        if not chosen:
            self.print("[dim]Model unchanged.[/dim]")
            return
        self.brain.model = chosen
        try:
            from hackit.config import load_config, save_config

            cfg = load_config()
            cfg.setdefault("ai_models", {})[self.brain.provider] = chosen
            save_config(cfg)
        except Exception:
            pass
        self.print(f"[green]Model set to {escape(chosen)}.[/green]")

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


    def _cmd_recon(self, argument: str) -> None:
        """Full recon stack in one call: ports, subdomains, dir fuzz, JS crawl, tech, WAF, headers.

        Runs the hative modules sequentially with live progress and an
        aggregated summary, so the operator does not have to call each tool
        separately. Results stay evidence-first: only verified hits promote.
        """
        tokens = [item for item in (argument or "").split() if item]
        modules = ("portscan", "subdomain", "fuzz", "js", "tech", "waf", "headers", "param")
        if tokens and tokens[0].lower() not in {m.lower() for m in modules}:
            self.target = tokens[0]
            tokens = tokens[1:]
        if tokens:
            # "/recon <target> portscan js" → only those modules.
            wanted = [t.lower() for t in tokens]
            modules = tuple(m for m in modules if m.lower() in wanted) or modules
        if not self.target:
            self.print("[yellow]Set a target first: /set-target <host> atau /recon <host>[/yellow]")
            return
        if not self.brain:
            return
        self.begin_operation("RECON", str(self.target))
        self.operation_event("recon", f"recon lengkap dimulai: {', '.join(modules)}", status="run", pct=0)

        def _progress(event: Dict[str, Any]) -> None:
            kind = str(event.get("event", ""))
            status = {"start": "run", "retry": "run", "done": "done", "error": "error", "complete": "complete", "log": "log"}.get(kind, "run")
            self.operation_event(
                phase=str(event.get("module") or "recon"),
                message=str(event.get("message", "")),
                status=status,
                pct=event.get("pct") if isinstance(event.get("pct"), int) else None,
                module=str(event.get("module") or ""),
            )

        results = self.brain.stream_hative(self.target, on_progress=_progress, modules=list(modules))
        cancelled = bool(getattr(self.brain, "cancelled", False))
        if not results:
            self.end_operation(
                "Recon cancelled." if cancelled else "Recon completed with no results.",
                status="cancelled" if cancelled else "error",
            )
            return

        def _count(data: Any) -> int:
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in ("findings", "results", "vulnerabilities", "issues", "ports", "subdomains", "paths", "endpoints"):
                    value = data.get(key)
                    if isinstance(value, list):
                        return len(value)
                return 1 if data else 0
            return 0

        total = 0
        table = Table(title="RECON RESULTS", box=box.SIMPLE_HEAVY, title_justify="left", pad_edge=False)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Count", justify="right")
        table.add_column("Time", justify="right", style="dim")
        for item in results:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            count = _count(data)
            total += count
            error = str(item.get("error") or "")
            success = bool(item.get("success")) and not error
            status_text = Text("ok" if success else "error", style=GREEN if success else RED)
            elapsed = item.get("elapsed_seconds")
            elapsed_text = f"{float(elapsed):.1f}s" if isinstance(elapsed, (int, float)) else "—"
            table.add_row(Text(str(item.get("module") or "module")), status_text, Text(str(count)), elapsed_text, )
            if error:
                table.add_column("Note", style="dim") if len(table.columns) == 4 else None
            # Append error inline via caption if any module failed.
        failures = [str(x.get("module")) for x in results if isinstance(x, dict) and x.get("error")]
        if failures:
            table.caption = f"modules gagal: {', '.join(failures)} — sisa recon tetap jalan"
            table.caption_justify = "left"
        self.end_operation(
            f"Recon lengkap · {len(results)} module(s) · {total} item(s) · target {self.target}",
            table,
        )
        # Surface the most useful recon output as plain lines for quick scan.
        for item in results:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            module = str(item.get("module") or "")
            if isinstance(data, list) and data:
                sample = ", ".join(str(x)[:60] for x in data[:5])
                if sample:
                    self.print(f"[dim]{module}: {escape(sample[:220])}[/dim]")

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
        self.print(
            Panel(
                Text.from_markup(
                    "[bold]ACTIVE MODE[/bold]\n"
                    "Autopilot will run attack modules against discovered endpoints "
                    "and verify generated payloads with differential probes.\n"
                    "[yellow]Only test targets you own or have explicit written "
                    "permission to test.[/yellow]"
                ),
                title=Text(" AUTHORIZED ", style="bold #020617 on #f59e0b"),
                border_style="#f59e0b",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )
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
                cancel_event=cancel_event, authorized=True,
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
            coverage = state.get("coverage", {}) if isinstance(state, dict) else {}
            attack_log = state.get("attack_log", []) if isinstance(state, dict) else []
            analysis = state.get("analysis", "") if isinstance(state, dict) else ""

            if coverage:
                coverage_table = Table(
                    title="ACTIVE COVERAGE",
                    box=box.SIMPLE_HEAVY,
                    title_justify="left",
                    pad_edge=False,
                )
                coverage_table.add_column("Metric", style="dim", no_wrap=True)
                coverage_table.add_column("Value", overflow="fold")
                modules = ", ".join(str(item) for item in coverage.get("execute_modules", [])) or "—"
                targets = coverage.get("execute_targets", []) or []
                probe_targets = coverage.get("probe_targets", []) or []
                probe_types = coverage.get("probe_types", []) or []
                parameters = coverage.get("parameters", []) or []
                coverage_table.add_row("authorized", "yes" if state.get("authorized") else "no")
                coverage_table.add_row(
                    "module tasks",
                    f"{coverage.get('execute_tasks', 0)} across {len(targets)} target(s)",
                )
                coverage_table.add_row("modules", modules)
                coverage_table.add_row(
                    "endpoints",
                    f"{len(coverage.get('endpoints', []) or [])} discovered",
                )
                coverage_table.add_row(
                    "parameters",
                    ", ".join(str(item) for item in parameters[:12]) or "—",
                )
                coverage_table.add_row(
                    "payload probes",
                    f"{coverage.get('probe_attempted', 0)} across "
                    f"{len(probe_targets)} target(s), {len(probe_types)} type(s)",
                )
                coverage_table.add_row("probe signals", str(coverage.get("probe_signals", 0)))
                coverage_table.add_row("attack log", f"{len(attack_log)} action(s)")
                self.print(coverage_table)

            if analysis:
                excerpt = strip_control(str(analysis)).strip()
                if len(excerpt) > 1800:
                    excerpt = "…\n" + excerpt[-1800:]
                self.print(
                    Panel(
                        Text(excerpt, style="#e2e8f0"),
                        title=Text(" ANALYSIS ", style="bold #22d3ee"),
                        title_align="left",
                        border_style="#1e293b",
                        box=box.ROUNDED,
                        padding=(0, 1),
                    )
                )

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
                f"Pipeline complete · {len(findings)} finding(s) · risk {risk}/10 · "
                f"{coverage.get('execute_tasks', 0)} module task(s) · "
                f"{coverage.get('probe_attempted', 0)} payload probe(s) · "
                f"{coverage.get('probe_signals', 0)} probe signal(s)",
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
    # Natural-language cyber intent routing (autopilot)
    # ------------------------------------------------------------------

    # Keyword groups that map a natural-language request to the real tool.
    # The AI stays conversational, but a pentest intent always executes
    # deterministically instead of being left as chat text.
    _CYBER_INTENTS = [
        # Combined / full pipelines first (longest needles win).
        (("full pentest", "pentest penuh", "uji lengkap", "serang penuh", "autopilot penuh", "pentest lengkap", "uji semua"), "all"),
        (("recon lengkap", "recon penuh", "pindai semua", "semua recon", "full recon"), "recon"),
        (("recon", "pindai", "mapping", "pemetaan"), "recon"),
        (("subdomain", "sub domain", "sub-domain", "enum subdomain", "cari subdomain"), "subdomainenum"),
        (("port scan", "portscan", "pindai port", "cek port", "scan port", "pindai port"), "portscan"),
        (("dir brute", "dir fuzz", "brute force direktori", "dorking", "cari direktori", "brute force", "fuzz direktori"), "dirfuzz"),
        (("js crawl", "javascript", "crawl js", "analisis js", "endpoints js", "crawl javascript"), "js"),
        (("tech", "teknologi", "fingerprint teknologi", "waf", "deteksi waf", "cek teknologi"), "techdetect"),
        (("serang", "pen test", "pentest", "uji celah", "uji keamanan"), "all"),
        (("sqli", "sql injection", "cari sql", "uji sql", "injeksi sql"), "sqli"),
        (("xss", "cross site", "uji xss", "injeksi xss"), "xss"),
        (("ssrf", "uji ssrf"), "ssrf"),
        (("param", "parameter", "param discovery", "cari parameter", "temuan parameter"), "params"),
        (("osint", "profil", "jejaring", "sosial"), "osint"),
    ]

    def _maybe_cyber_intent(self, text: str) -> bool:
        """Route natural pentest requests to the real scanner. Returns True if handled."""
        if self.mode_name != "AUTOPILOT":
            return False
        lowered = (text or "").strip().lower()
        if not lowered:
            return False
        # Pure questions / chat stay with the AI even if they mention a tool.
        if lowered.startswith(("apa ", "bagaimana", "kenapa", "jelaskan", "explain", "what ", "how ", "tutorial", "cara ")) and "scan" not in lowered and "cari" not in lowered:
            return False
        module = ""
        for needles, mod in self._CYBER_INTENTS:
            if any(needle in lowered for needle in needles):
                module = mod
                break
        if not module:
            return False
        # Extract a target mention (domain, IP, or URL) when present.
        candidate = self._extract_target_hint(text) or self.target
        if not candidate:
            self.print("[yellow]Sebutkan targetnya dulu, misal: 'port scan example.com'.[/yellow]")
            return True
        self.target = candidate
        if module == "all":
            self._autopilot_start(candidate)
            return True
        if module == "recon":
            self._cmd_recon(candidate)
            return True
        if module == "osint":
            self._cmd_osint(candidate)
            return True
        self._cmd_scan(module)
        return True

    @staticmethod
    def _extract_target_hint(text: str) -> str:
        import re as _re
        tokens = [item.strip() for item in (text or "").replace(",", " ").split() if item.strip()]
        for token in tokens:
            cleaned = token.strip("<>[](){}")
            if cleaned.startswith(("http://", "https://")):
                return cleaned
        for token in tokens:
            cleaned = token.strip("<>[](){}")
            if _re.match(r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", cleaned):
                return cleaned
            if _re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$", cleaned):
                return cleaned
        return ""

    # ------------------------------------------------------------------
    # Bare set / go-words (no slash needed, like normal AI chat)
    # ------------------------------------------------------------------

    # "Mulai" words: any of these alone means "start the full pipeline".
    _GO_WORDS = {
        "lanjut", "lanjutkan", "mulai", "gass", "gas", "gaspol",
        "jalan", "jalanin", "jalankan", "start", "go", "run",
        "attack", "serang", "hajar", "sikat", "tempur",
        "eksekusi", "execute", "continue", "lanjutkan serang",
        "mulai menyerang", "lanjut menyerang", "gas serangan",
        "mulai pentest", "mulai serangan",
    }

    def _handle_bare_set(self, text: str) -> bool:
        """Recognise `set <target>` / `set target <target>` without a slash.

        Both forms appear in the wild (users paste `set https://x` or
        `set target https://x`).  In Autopilot the locked target starts
        the full pipeline immediately; in Chat it only locks.
        """
        parts = (text or "").strip().split()
        if not parts:
            return False
        if parts[0].lower() not in ("set", "set-target", "set_target"):
            return False
        rest_tokens = parts[1:]
        if rest_tokens and rest_tokens[0].lower() == "target":
            rest_tokens = rest_tokens[1:]
        target = " ".join(rest_tokens).strip()
        if not target:
            self.print("[yellow]Usage: set <target>  contoh: set https://example.com[/yellow]")
            return True
        # Never treat a second command word as a target.
        if target.lower() in ("--no-run",):
            self.print("[yellow]Usage: set <target>  contoh: set https://example.com[/yellow]")
            return True
        no_run = target.endswith("--no-run")
        if no_run:
            target = target[: -len("--no-run")].strip()
        self.target = target
        self.print(f"[cyan]Target locked:[/cyan] {escape(str(self.target))}")
        if self.mode_name == "AUTOPILOT" and not no_run:
            self.print("[dim]Autopilot starting — full pentest pipeline (recon → report).[/dim]")
            try:
                import threading

                threading.Timer(0.6, lambda: self._autopilot_start(self.target)).start()
            except Exception:
                self._autopilot_start(self.target)
        return True

    def _handle_bare_go(self, text: str) -> bool:
        """Recognise `lanjut` / `mulai` / `gass` … as “start the full attack”.

        Only fires when the whole message is a go-word (or a short phrase
        built from go-words).  Anything longer stays with the AI.
        """
        cleaned = (text or "").strip().lower().strip(" .!?.")
        if cleaned not in self._GO_WORDS:
            # Also accept "<go-word>" + optional target in one line.
            if cleaned.startswith(tuple(w + " " for w in self._GO_WORDS if " " not in w)):
                candidate = self._extract_target_hint(text)
                if candidate:
                    self.target = candidate
                    self._autopilot_start(candidate)
                    return True
            return False
        if self._autopilot_running:
            self.print("[dim]Autopilot sudah jalan — tunggu fase selesai.[/dim]")
            return True
        if not self.target:
            self.print("[yellow]Target belum diset.[/yellow]")
            self.print("[dim]Ketik [green]set https://example.com[/green] dulu, atau [green]/set-target example.com[/green]. Setelah target terkunci, kata mulai akan langsung menyerang.[/dim]")
            return True
        self.print("[dim]Autopilot starting — full pentest pipeline (recon → osint → js → params → payload → analyse → plan → execute → probe → correlate → report).[/dim]")
        self._autopilot_start(self.target)
        return True

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, raw: str) -> bool:
        """Handle one input line. Returns False to exit."""
        text = raw.strip()
        if not text:
            return True
        if not text.startswith("/"):
            # A bare word that names a real command must execute it.  Before
            # this, `doctor` and `auto` were shipped to the model as prompts.
            head = text.split(None, 1)[0].lower()
            if head in self.commands:
                text = "/" + text
            elif self._handle_bare_set(text):
                return True
            elif self._handle_bare_go(text):
                return True
            elif self._maybe_cyber_intent(text):
                return True
            else:
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
        if head == "doctor":
            self._run_agent_action("doctor", rest)
            return True
        if head == "setting":
            self._run_agent_action("setting", rest)
            return True
        if head == "guide":
            self._run_agent_action("guide", rest)
            return True
        if head == "reset":
            self._run_agent_action("reset", rest)
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
        if head == "select":
            self._cmd_select(rest)
            return True
        if head in ("usage", "tokens"):
            self._cmd_usage()
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
        if head == "recon":
            self._cmd_recon(rest)
            return True
        if head == "full":
            self._cmd_autopilot(rest or self.target or "")
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
        if head == "autopilot":
            self._cmd_autopilot(rest)
            return True
        if head == "progress":
            self._cmd_progress(rest)
            return True
        if head == "hide":
            self._cmd_progress("hide")
            return True
        if head == "show":
            self._cmd_progress("show")
            return True
        if head == "target":
            self.target = rest or self.target
            self.print(f"[cyan]Target:[/cyan] {escape(str(self.target or '—'))}")
            return True
        if head in ("set-target", "set_target"):
            self.target = rest
            self.print(f"[cyan]Target locked:[/cyan] {escape(str(self.target))}")
            # Autopilot contract: once the target is locked the AI runs the
            # full pipeline by itself.  /set-target --no-run opts out once.
            if self.mode_name == "AUTOPILOT" and self.target and "--no-run" not in rest:
                # Re-parse without the flag so it is never treated as target.
                self.target = rest.replace("--no-run", "").strip()
                self.print("[dim]Autopilot starting — full pentest pipeline (recon → report).[/dim]")
                # Small delay so the lock message lands before progress.
                try:
                    import threading

                    threading.Timer(0.6, lambda: self._autopilot_start(self.target)).start()
                except Exception:
                    self._autopilot_start(self.target)
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

    def _run_agent_action(self, name: str, rest: str = "") -> None:
        """Run a Click subcommand of the ``agent`` group from inside the UI."""
        try:
            from . import _dispatch_agent_action

            _dispatch_agent_action(name, rest)
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]{escape(str(exc))}[/red]")

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
            if self.mode_name == "AUTOPILOT" and self.brain is not None:
                expert = (
                    "You are an elite, high-precision cybersecurity expert and penetration tester "
                    "running inside HackIt Autopilot. "
                    "You can chat conversationally, but your default is action: when the operator "
                    "asks for recon, subdomain enumeration, port scanning, JavaScript crawling, "
                    "directory brute-force, parameter discovery, or any pentest module, route it to "
                    "the real tools (/scan, /portscan, /subdomainenum, /dirfuzz, /js, /params, /sqli, "
                    "or the full /autopilot pipeline) instead of describing it. "
                    "Every claim about a vulnerability must come from deterministic tool output "
                    "(hative/worker modules, differential probes, baseline comparisons) — never "
                    "hypothesise a finding. Be precise, technical and evidence-first. "
                    "Only test targets the operator owns or is authorised to test."
                )
                base = getattr(self.brain, "system_prompt", "") or ""
                self.brain.system_prompt = (base + "\n" + expert).strip()
        except Exception as exc:  # noqa: BLE001
            self.print(f"[red]Failed to initialise agent: {escape(str(exc))}[/red]")
            return

        self._status_panel()
        self.print("[dim]Type /help for commands. Ctrl+C cancels the current request.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                if getattr(self, "_autopilot_running", False):
                    self._autopilot_stop()
                    self.print("\n[yellow]Autopilot cancelled. Type /exit to quit.[/yellow]")
                    continue
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

            ui = AutopilotTUI(target=self.target)
            ui._autopilot_auto_run = bool(getattr(self, "_autopilot_auto_run", False))
            ui.run()
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
            if getattr(self, "_autopilot_auto_run", False):
                self.print("[dim]Autopilot auto-starting full pentest pipeline…[/dim]")
                try:
                    import threading

                    threading.Timer(0.8, lambda: self._autopilot_start(self.target)).start()
                except Exception:
                    self._autopilot_start(self.target)
        else:
            self.print("[yellow]No target set. Use /set-target <host> (autopilot then runs automatically) or /autopilot <host>.[/yellow]")
        self.print("[dim]Type /help for commands. /progress hide hides phases. Ctrl+C cancels.[/dim]\n")

        while self.running:
            try:
                raw = self._read_input(session)
            except KeyboardInterrupt:
                if getattr(self, "_autopilot_running", False):
                    self._autopilot_stop()
                    self.print("\n[yellow]Autopilot cancelled. Type /exit to quit.[/yellow]")
                    continue
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
