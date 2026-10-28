"""Full-screen OpenCode-style terminal UI for HackIt Agent.

The renderer is deliberately separated from the command controller in
:mod:`hackit.agent.interactive`.  ChatUI/AutopilotUI keep all of their command
semantics and fall back to the inline renderer on dumb terminals; this module
only owns presentation, input, streaming composition and the command palette.

Design rules
------------
* One accent colour per mode, neutral greys everywhere else.
* Reasoning and final answers live in separate panels, never mixed.
* Tool and attack progress is rendered as structured state, not log spam.
* The composer is a real framed message box with a navigable palette.
"""

from __future__ import annotations

import contextlib
import html
import io
import os
import re
import shutil
import sys
import threading
import time
import traceback
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from rich import box
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from prompt_toolkit import Application
from prompt_toolkit.application import get_app
from prompt_toolkit.data_structures import Point
from prompt_toolkit.filters import Condition, has_completions
from prompt_toolkit.formatted_text import ANSI, FormattedText, HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import (
    ConditionalContainer,
    Float,
    FloatContainer,
    FormattedTextControl,
    HSplit,
    Layout,
    VSplit,
    Window,
)
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Frame, TextArea

from .interactive import (
    AgentUI,
    PARAMETERLESS_COMMANDS,
    _ReasoningSplitter,
    _SlashCompleter,
    _strip_ansi,
    _timestamp,
)
from .textutils import strip_control

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

CYAN = "#22d3ee"
BLUE = "#38bdf8"
AMBER = "#f59e0b"
GREEN = "#34d399"
RED = "#fb7185"
SLATE = "#94a3b8"
SLATE_DIM = "#64748b"
INK = "#020617"
PANEL = "#0b1220"
RULE = "#1e293b"
TEXT = "#e2e8f0"

TUI_STYLE = Style.from_dict(
    {
        "header": f"bg:{PANEL} {TEXT}",
        "header.brand": f"bg:{PANEL} bold {CYAN}",
        "header.mode": f"bg:{CYAN} {INK} bold",
        "header.dim": f"bg:{PANEL} {SLATE_DIM}",
        "header.label": f"bg:{PANEL} {SLATE_DIM}",
        "header.value": f"bg:{PANEL} {TEXT}",
        "rule": f"bg:{INK} {RULE}",
        "transcript": f"bg:{INK} {TEXT}",
        "sidebar": f"bg:{PANEL} {TEXT}",
        "sidebar.title": f"bg:{PANEL} bold {CYAN}",
        "sidebar.label": f"bg:{PANEL} {SLATE_DIM}",
        "sidebar.value": f"bg:{PANEL} {TEXT}",
        "sidebar.rule": f"bg:{PANEL} {RULE}",
        "sidebar.key": f"bg:{PANEL} {AMBER}",
        "sidebar.muted": f"bg:{PANEL} {SLATE_DIM}",
        "composer": f"bg:{PANEL} {TEXT}",
        "composer.prompt": f"bg:{PANEL} bold {CYAN}",
        "composer.frame": f"bg:{PANEL} {RULE}",
        "composer.frame.label": f"bg:{PANEL} {CYAN}",
        "composer.frame.border": f"bg:{PANEL} {RULE}",
        "status": f"bg:{PANEL} {SLATE_DIM}",
        "status.key": f"bg:{PANEL} {CYAN}",
        "status.value": f"bg:{PANEL} {SLATE}",
        "status.busy": f"bg:{PANEL} bold {AMBER}",
        "status.ok": f"bg:{PANEL} bold {GREEN}",
        "status.error": f"bg:{PANEL} bold {RED}",
        "palette.command": f"bg:{PANEL} {TEXT}",
        "palette.command.selected": f"bg:{CYAN} {INK} bold",
        "palette.arg": f"bg:{PANEL} {TEXT}",
        "palette.arg.selected": f"bg:{AMBER} {INK} bold",
        "palette.frame": f"bg:{PANEL} {RULE}",
        "palette.frame.border": f"bg:{PANEL} {RULE}",
        "palette.frame.label": f"bg:{PANEL} bold {CYAN}",
        "completion-menu": f"bg:{PANEL} {TEXT}",
        "completion-menu.completion": f"bg:{PANEL} {TEXT}",
        "completion-menu.completion.current": f"bg:{CYAN} {INK} bold",
        "completion-menu.meta.completion": f"bg:{INK} {SLATE_DIM}",
        "completion-menu.meta.completion.current": f"bg:{CYAN} {INK}",
        "scrollbar.background": f"bg:{RULE}",
        "scrollbar.button": f"bg:{SLATE_DIM}",
    }
)

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def can_use_tui() -> bool:
    """Return True when a full-screen prompt_toolkit UI is safe to start."""
    if os.environ.get("HACKIT_INLINE", "").lower() in ("1", "true", "yes", "on"):
        return False
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return False
    if os.environ.get("TERM", "") in ("", "dumb"):
        return False
    try:
        import prompt_toolkit  # noqa: F401
        import rich  # noqa: F401
    except ImportError:
        return False
    columns, rows = shutil.get_terminal_size((80, 24))
    return columns >= 72 and rows >= 18


def _truncate(value: str, limit: int) -> str:
    value = str(value or "")
    if limit <= 1:
        return value[:limit]
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _plain_markup(value: str) -> str:
    value = _strip_ansi(str(value or ""))
    value = re.sub(r"\[[^\]]*\]", "", value)
    return value.strip()


class _TuiStatus:
    """Small status handle compatible with ``console.status(...)`` usage."""

    def __init__(self, ui: "TuiMixin", message: str):
        self.ui = ui
        self.message = _plain_markup(message)

    def update(self, message: str) -> None:
        self.message = _plain_markup(message)
        self.ui._status_message = self.message or "working"
        self.ui._invalidate()


# ---------------------------------------------------------------------------
# Key bindings shared by the TUI and the inline prompt
# ---------------------------------------------------------------------------


def build_key_bindings(ui: Optional["TuiMixin"] = None, tui: bool = True) -> KeyBindings:
    kb = KeyBindings()

    @kb.add("up", filter=has_completions, eager=True)
    def _complete_up(event) -> None:  # noqa: ANN001
        event.current_buffer.complete_previous()

    @kb.add("down", filter=has_completions, eager=True)
    def _complete_down(event) -> None:  # noqa: ANN001
        event.current_buffer.complete_next()

    @kb.add("tab", filter=has_completions, eager=True)
    def _complete_tab(event) -> None:  # noqa: ANN001
        event.current_buffer.complete_next()

    @kb.add("enter", filter=has_completions, eager=True)
    def _complete_enter(event) -> None:  # noqa: ANN001
        buffer = event.current_buffer
        state = buffer.complete_state
        if state is None or not state.completions:
            buffer.validate_and_handle()
            return
        completion = state.current_completion
        if completion is None:
            # The first Enter accepts the first match without forcing the
            # user to press Down first.
            completion = state.completions[0]
        buffer.apply_completion(completion)
        text = buffer.text.strip()
        head = ""
        if text.startswith("/"):
            head = text[1:].split(" ", 1)[0].lower()
        if text.startswith("/") and " " not in text and head in PARAMETERLESS_COMMANDS:
            buffer.validate_and_handle()

    @kb.add("escape", filter=has_completions, eager=True)
    def _close_palette(event) -> None:  # noqa: ANN001
        event.current_buffer.complete_state = None

    @kb.add("c-space", eager=True)
    def _force_complete(event) -> None:  # noqa: ANN001
        event.current_buffer.start_completion(select_first=True)

    @kb.add(
        "/",
        filter=Condition(lambda: get_app().current_buffer.text == ""),
        eager=True,
    )
    def _open_palette(event) -> None:  # noqa: ANN001
        buffer = event.current_buffer
        buffer.insert_text("/")
        # List the palette with no preview. Arrow keys choose a row; Enter
        # accepts the highlighted (or first) command.
        buffer.start_completion(select_first=False)

    @kb.add("c-p", eager=True)
    def _palette_shortcut(event) -> None:  # noqa: ANN001
        buffer = event.current_buffer
        if not buffer.text:
            buffer.insert_text("/")
            buffer.start_completion(select_first=False)

    if tui and ui is not None:
        @kb.add("c-c", eager=True)
        def _ctrl_c(event) -> None:  # noqa: ANN001
            ui._handle_ctrl_c()

        @kb.add("c-d", eager=True)
        def _ctrl_d(event) -> None:  # noqa: ANN001
            ui._exit()

        @kb.add("c-l", eager=True)
        def _ctrl_l(event) -> None:  # noqa: ANN001
            ui._handle_clear_shortcut()

        @kb.add("pageup", eager=True)
        def _page_up(event) -> None:  # noqa: ANN001
            ui._scroll_transcript(-8)

        @kb.add("pagedown", eager=True)
        def _page_down(event) -> None:  # noqa: ANN001
            ui._scroll_transcript(8)

    return kb


# ---------------------------------------------------------------------------
# Full-screen renderer
# ---------------------------------------------------------------------------


class TuiMixin:
    """Full-screen renderer mixed into ChatUI / AutopilotUI."""

    accent = CYAN

    def __init__(self, *args: Any, **kwargs: Any):
        self.app: Optional[Application] = None
        self.busy = False
        self._closed = False
        self._render_lock = threading.RLock()
        self._block_renderers: List[Callable[[Console], None]] = []
        self._frozen_ansi = ""
        self._frozen_width = 0
        self._live_renderers: List[Callable[[Console], None]] = []
        self._live_ansi = ""
        self._last_live_render = 0.0
        self._status_message = "ready"
        self._spinner_index = 0
        self._session_tokens = 0
        self._started_at = time.time()
        self._transcript_window: Optional[Window] = None
        self._input: Optional[TextArea] = None
        self._header_control: Optional[FormattedTextControl] = None
        self._sidebar_control: Optional[FormattedTextControl] = None
        self._status_control: Optional[FormattedTextControl] = None
        self._follow_output = True
        self._manual_y = 0
        self._welcome_shown = False
        self._cancel_requested = False
        self._operation: Optional[Dict[str, Any]] = None
        super().__init__(*args, **kwargs)
        self.tui = True
        self.accent = getattr(self, "accent", CYAN)

    # -- lifecycle -------------------------------------------------------

    def _print_banner(self) -> None:
        """Draw the welcome panel inside the TUI; suppress the inline banner."""
        if getattr(self, "app", None) is not None:
            self._tui_welcome(force=True)

    def run(self) -> None:
        from .brain import AIHyperBrain

        try:
            self.brain = AIHyperBrain(
                engine="chat" if self.mode_name == "CHAT" else "native",
                target=self.target,
                announce=False,
            )
        except Exception as exc:  # noqa: BLE001
            self.brain = None
            self._boot_error = str(exc)
        else:
            self._boot_error = ""

        self.app = Application(
            layout=self._build_layout(),
            key_bindings=build_key_bindings(self, tui=True),
            style=TUI_STYLE,
            full_screen=True,
            mouse_support=False,
            refresh_interval=0.1,
        )
        self._tui_welcome()
        self._start_spinner()
        try:
            self.app.run()
        except KeyboardInterrupt:
            pass
        except Exception as exc:  # noqa: BLE001
            self._closed = True
            self.console.print(f"[red]TUI error: {escape(str(exc))}[/red]")
            if os.environ.get("HACKIT_DEBUG"):
                self.console.print(traceback.format_exc())
            return
        finally:
            self._closed = True
        self.console.print(
            f"\n[green]Session closed.[/green] [dim]{self.mode_name} agent offline.[/dim]\n"
        )

    def _start_spinner(self) -> None:
        def spin() -> None:
            while not self._closed:
                time.sleep(0.1)
                if self.busy:
                    self._spinner_index = (self._spinner_index + 1) % len(SPINNER)
                    self._invalidate()

        threading.Thread(target=spin, daemon=True).start()

    def _exit(self) -> None:
        self.running = False
        if self.app is not None:
            self.app.exit()

    def _handle_ctrl_c(self) -> None:
        if self.busy:
            self._cancel_requested = True
            if self.brain is not None and hasattr(self.brain, "cancel_stream"):
                try:
                    self.brain.cancel_stream()
                except Exception:
                    pass
            self._status_message = "cancelling…"
            self._invalidate()
            return
        if self._input is not None and self._input.text.strip():
            self._input.text = ""
            self._invalidate()
            return
        self._exit()

    def _handle_clear_shortcut(self) -> None:
        self.clear_view()
        self._tui_welcome(force=True)

    # -- layout ----------------------------------------------------------

    def _sidebar_enabled(self) -> bool:
        columns, _ = shutil.get_terminal_size((100, 30))
        return columns >= 110

    def _content_width(self) -> int:
        columns, _ = shutil.get_terminal_size((100, 30))
        sidebar = 34 if self._sidebar_enabled() else 0
        return max(40, columns - sidebar - 2)

    def _build_layout(self) -> Layout:
        from . import payloads

        self._header_control = FormattedTextControl(self._header_text)
        header = Window(
            self._header_control,
            height=1,
            style="class:header",
            dont_extend_height=True,
        )

        self._transcript_window = Window(
            FormattedTextControl(
                self._transcript_text,
                show_cursor=False,
                get_cursor_position=self._transcript_cursor,
            ),
            wrap_lines=True,
            style="class:transcript",
            always_hide_cursor=True,
        )

        self._sidebar_control = FormattedTextControl(self._sidebar_text)
        sidebar = ConditionalContainer(
            content=Window(
                self._sidebar_control,
                width=32,
                style="class:sidebar",
                wrap_lines=True,
            ),
            filter=Condition(self._sidebar_enabled),
        )

        self._input = TextArea(
            multiline=False,
            prompt=HTML(
                "<b><style fg='#22d3ee'>you</style></b> "
                "<style fg='#f59e0b'>›</style> "
            ),
            completer=_SlashCompleter(self.commands, payloads.catalog_types()),
            complete_while_typing=True,
            accept_handler=self._accept_input,
            history=FileHistory(
                os.path.join(os.path.expanduser("~"), f".hackit_{self.mode_name.lower()}_history")
            ),
            style="class:composer",
            height=1,
            dont_extend_height=True,
            wrap_lines=True,
            name="composer",
        )

        composer = Frame(
            self._input,
            title=HTML("<style fg='#22d3ee'> MESSAGE </style>"),
            style="class:composer.frame",
            height=3,
        )

        self._status_control = FormattedTextControl(self._status_text)
        status = Window(
            self._status_control,
            height=1,
            style="class:status",
            dont_extend_height=True,
        )

        body = VSplit(
            [
                self._transcript_window,
                Window(width=1, char="│", style="class:rule"),
                sidebar,
            ]
        )
        root = HSplit(
            [
                header,
                Window(height=1, char="─", style="class:rule"),
                body,
                Window(height=1, char="─", style="class:rule"),
                composer,
                status,
            ]
        )
        floats = [
            Float(
                bottom=5,
                left=2,
                width=82,
                content=ConditionalContainer(
                    content=Frame(
                        CompletionsMenu(
                            max_height=12,
                            scroll_offset=1,
                            display_arrows=True,
                        ),
                        title=HTML("<style fg='#22d3ee'> COMMANDS </style>"),
                        style="class:palette.frame",
                    ),
                    filter=has_completions,
                ),
            )
        ]
        return Layout(
            FloatContainer(content=root, floats=floats),
            focused_element=self._input,
        )

    def _tui_welcome(self, force: bool = False) -> None:
        if self._welcome_shown and not force:
            return
        self._welcome_shown = True
        if self._boot_error:
            self.print(
                Panel(
                    Text(
                        f"Agent initialisation failed:\n{self._boot_error}",
                        style=RED,
                    ),
                    title=Text(" ERROR ", style=f"bold {RED}"),
                    border_style=RED,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
            return

        is_auto = self.mode_name == "AUTOPILOT"
        title = "AUTOPILOT" if is_auto else "CHAT"
        subtitle = (
            "Autonomous recon · OSINT · scan · payload · analysis · attack · report"
            if is_auto
            else "General AI copilot with a security toolchain"
        )
        body = Text()
        body.append(title, style=f"bold {self.accent}")
        body.append("  ·  HackIt Agent v2.2\n", style=SLATE_DIM)
        body.append(subtitle + "\n\n", style=TEXT)
        if self.brain is not None:
            body.append("provider  ", style=SLATE_DIM)
            body.append(str(self.brain.provider or "none"), style=f"bold {TEXT}")
            body.append("    model  ", style=SLATE_DIM)
            body.append(str(self.brain.model or "auto"), style=TEXT)
            body.append("\n", style=TEXT)
        body.append("target    ", style=SLATE_DIM)
        body.append(self.target or "not set", style=AMBER if not self.target else TEXT)
        body.append("\n\n", style=TEXT)
        body.append("Type a message", style=f"bold {self.accent}")
        body.append(" or press ", style=SLATE_DIM)
        body.append("/", style=f"bold {AMBER}")
        body.append(" for the command palette. ", style=SLATE_DIM)
        body.append("Ctrl+P", style=f"bold {AMBER}")
        body.append(" also opens it.", style=SLATE_DIM)
        self.print(
            Panel(
                body,
                title=Text(f" {title} ", style=f"bold {INK} on {self.accent}"),
                border_style=self.accent,
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
        if is_auto and not self.target:
            self.print(
                Text(
                    "No target locked. Use /target <host> or /set-target <host> before active tests.",
                    style=AMBER,
                )
            )

    # -- chrome ----------------------------------------------------------

    def _header_text(self) -> FormattedText:
        brain = self.brain
        provider = str(brain.provider) if brain and brain.provider else "none"
        model = str(brain.model) if brain and brain.model else "auto"
        target = self.target or "no target"
        columns, _ = shutil.get_terminal_size((100, 30))
        budget = max(10, columns // 4)
        model = _truncate(model, budget)
        target = _truncate(target, budget)
        mode = self.mode_name
        mode_style = f"bg:{AMBER} {INK} bold" if mode == "AUTOPILOT" else f"bg:{CYAN} {INK} bold"
        return FormattedText(
            [
                (f"bg:{PANEL} bold {CYAN}", " HACKIT "),
                (mode_style, f" {mode} "),
                (f"bg:{PANEL} {SLATE_DIM}", "   provider "),
                (f"bg:{PANEL} {TEXT}", provider),
                (f"bg:{PANEL} {SLATE_DIM}", "  ·  model "),
                (f"bg:{PANEL} {TEXT}", model),
                (f"bg:{PANEL} {SLATE_DIM}", "  ·  target "),
                (f"bg:{PANEL} {AMBER if not self.target else TEXT}", target),
                (f"bg:{PANEL} {SLATE_DIM}", " "),
            ]
        )

    def _sidebar_text(self) -> FormattedText:
        brain = self.brain
        provider = str(brain.provider) if brain and brain.provider else "none"
        model = str(brain.model) if brain and brain.model else "auto"
        backend = "off"
        messages = 0
        if brain is not None and brain.memory is not None:
            backend = brain.memory.backend
            messages = brain.memory.stats().get("messages", 0)
        try:
            from .workflow import workflow_engine

            workflow = workflow_engine()
        except Exception:
            workflow = "builtin"
        elapsed = int(time.time() - self._started_at)
        elapsed_text = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        status = self._status_message
        fragments: List[Tuple[str, str]] = [
            (f"bg:{PANEL} bold {self.accent}", " SESSION\n"),
            (f"bg:{PANEL} {RULE}", " " + "─" * 27 + "\n"),
        ]

        def row(label: str, value: str) -> None:
            fragments.append((f"bg:{PANEL} {SLATE_DIM}", f" {label:<9}"))
            fragments.append((f"bg:{PANEL} {TEXT}", f"{_truncate(value, 20)}\n"))

        row("engine", str(getattr(brain, "engine", "—") if brain else "—"))
        row("provider", provider)
        row("model", model)
        row("memory", f"{backend} · {messages} msg")
        row("target", self.target or "—")
        row("workflow", workflow)
        fragments.extend(
            [
                (f"bg:{PANEL} {RULE}", " " + "─" * 27 + "\n"),
                (f"bg:{PANEL} {SLATE_DIM}", " STATE\n"),
                (f"bg:{PANEL} {SLATE_DIM}", " status   "),
                (
                    f"bg:{PANEL} bold {AMBER if self.busy else GREEN}",
                    f"{_truncate(status, 18)}\n",
                ),
                (f"bg:{PANEL} {SLATE_DIM}", " elapsed  "),
                (f"bg:{PANEL} {TEXT}", f"{elapsed_text}\n"),
                (f"bg:{PANEL} {SLATE_DIM}", " tokens   "),
                (f"bg:{PANEL} {TEXT}", f"~{self._session_tokens}\n"),
                (f"bg:{PANEL} {RULE}", " " + "─" * 27 + "\n"),
                (f"bg:{PANEL} {SLATE_DIM}", " KEYS\n"),
                (f"bg:{PANEL} {AMBER}", " /        "),
                (f"bg:{PANEL} {SLATE}", "command palette\n"),
                (f"bg:{PANEL} {AMBER}", " ↑ ↓      "),
                (f"bg:{PANEL} {SLATE}", "select command\n"),
                (f"bg:{PANEL} {AMBER}", " Tab      "),
                (f"bg:{PANEL} {SLATE}", "complete\n"),
                (f"bg:{PANEL} {AMBER}", " Enter    "),
                (f"bg:{PANEL} {SLATE}", "run / accept\n"),
                (f"bg:{PANEL} {AMBER}", " PgUp/Dn  "),
                (f"bg:{PANEL} {SLATE}", "scroll chat\n"),
                (f"bg:{PANEL} {AMBER}", " Ctrl+C   "),
                (f"bg:{PANEL} {SLATE}", "cancel / exit\n"),
                (f"bg:{PANEL} {AMBER}", " Ctrl+D   "),
                (f"bg:{PANEL} {SLATE}", "quit\n"),
            ]
        )
        return FormattedText(fragments)

    def _status_text(self) -> FormattedText:
        if self.busy:
            spinner = SPINNER[self._spinner_index % len(SPINNER)]
            return FormattedText(
                [
                    (f"bg:{PANEL} bold {AMBER}", f" {spinner} "),
                    (f"bg:{PANEL} {AMBER}", f"{_truncate(self._status_message, 42)} "),
                    (f"bg:{PANEL} {SLATE_DIM}", "  Ctrl+C cancel"),
                ]
            )
        return FormattedText(
            [
                (f"bg:{PANEL} bold {GREEN}", " ● "),
                (f"bg:{PANEL} {SLATE}", "ready "),
                (f"bg:{PANEL} {RULE}", "│ "),
                (f"bg:{PANEL} {CYAN}", "/ "),
                (f"bg:{PANEL} {SLATE}", "commands  "),
                (f"bg:{PANEL} {CYAN}", "Ctrl+P "),
                (f"bg:{PANEL} {SLATE}", "palette  "),
                (f"bg:{PANEL} {CYAN}", "↑↓ "),
                (f"bg:{PANEL} {SLATE}", "select  "),
                (f"bg:{PANEL} {CYAN}", "Enter "),
                (f"bg:{PANEL} {SLATE}", "run  "),
                (f"bg:{PANEL} {CYAN}", "Ctrl+C "),
                (f"bg:{PANEL} {SLATE}", "exit"),
            ]
        )

    # -- structured operations ------------------------------------------

    def _operation_counts(self) -> Tuple[int, int, int]:
        operation = self._operation or {}
        rows = operation.get("rows", {})
        done = sum(1 for row in rows.values() if row.get("status") == "done")
        errors = sum(1 for row in rows.values() if row.get("status") == "error")
        running = sum(1 for row in rows.values() if row.get("status") == "run")
        return done, errors, running

    def _operation_panel(self) -> Panel:
        operation = self._operation or {}
        title = str(operation.get("title") or "OPERATION")
        target = str(operation.get("target") or "")
        elapsed = int(time.time() - float(operation.get("started", time.time())))
        elapsed_text = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
        done, errors, running = self._operation_counts()
        pct = int(operation.get("pct") or 0)
        pct = max(0, min(100, pct))

        header = Text()
        header.append(f"{len(operation.get('rows', {}))} task(s)", style=TEXT)
        header.append("  ·  ", style=RULE)
        header.append(f"{done} done", style=GREEN)
        if running:
            header.append("  ·  ", style=RULE)
            header.append(f"{running} running", style=AMBER)
        if errors:
            header.append("  ·  ", style=RULE)
            header.append(f"{errors} failed", style=RED)
        header.append("  ·  ", style=RULE)
        header.append(elapsed_text, style=SLATE)
        header.append("  ·  ", style=RULE)
        header.append(f"{pct}%", style=f"bold {self.accent}")

        width = max(16, min(60, self._content_width() - 10))
        filled = int(width * pct / 100)
        bar = Text()
        bar.append("█" * filled, style=self.accent)
        bar.append("░" * (width - filled), style=RULE)
        bar.append(f"  {pct:>3}%", style=SLATE_DIM)

        table = Table(
            box=None,
            show_header=False,
            padding=(0, 1),
            expand=True,
        )
        table.add_column(width=2, no_wrap=True)
        table.add_column(style="bold", no_wrap=True, width=16)
        table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)
        table.add_column(justify="right", width=5, no_wrap=True)

        rows = list(operation.get("rows", {}).values())
        visible = rows[-11:]
        if len(rows) > len(visible):
            table.add_row(
                Text("·", style=SLATE_DIM),
                Text(f"+{len(rows) - len(visible)} earlier", style=SLATE_DIM),
                Text(""),
                Text(""),
            )
        for row in visible:
            status = str(row.get("status") or "run")
            module = _truncate(str(row.get("module") or row.get("phase") or "task"), 16)
            message = _truncate(str(row.get("message") or ""), max(20, self._content_width() - 44))
            pct_text = f"{row['pct']}%" if isinstance(row.get("pct"), int) and row["pct"] > 0 else ""
            if status == "done":
                icon, style = "✓", GREEN
            elif status == "error":
                icon, style = "✗", RED
            elif status == "retry":
                icon, style = "↻", AMBER
            elif status == "complete":
                icon, style = "★", self.accent
            elif status == "log":
                icon, style = "·", SLATE_DIM
            else:
                icon, style = SPINNER[self._spinner_index % len(SPINNER)], self.accent
            table.add_row(
                Text(icon, style=style),
                Text(module, style=TEXT if status != "error" else RED),
                Text(message, style=SLATE),
                Text(pct_text, style=SLATE_DIM),
            )

        body = Group(header, Text(""), bar, Text(""), table)
        return Panel(
            body,
            title=Text(f" {title} ", style=f"bold {INK} on {self.accent}"),
            title_align="left",
            border_style=self.accent,
            box=box.ROUNDED,
            padding=(0, 1),
        )

    def begin_operation(self, title: str, target: str = "") -> None:
        self._operation = {
            "title": str(title or "OPERATION").upper(),
            "target": str(target or ""),
            "started": time.time(),
            "rows": {},
            "pct": 0,
        }
        self._status_message = f"{str(title).lower()} · {target}" if target else str(title).lower()
        self._set_live([self._operation_panel()], force=True)
        self._invalidate()

    def operation_event(
        self,
        phase: str,
        message: str = "",
        status: str = "run",
        pct: Optional[int] = None,
        module: str = "",
    ) -> None:
        operation = self._operation
        if operation is None:
            return
        key = str(module or phase or "task")
        rows = operation.setdefault("rows", {})
        row = rows.get(key, {})
        row.update({
            "module": key,
            "message": strip_control(str(message or ""))[:300],
            "status": status,
            "updated": time.time(),
        })
        if isinstance(pct, int):
            row["pct"] = max(0, min(100, pct))
            operation["pct"] = max(int(operation.get("pct") or 0), max(0, min(100, pct)))
        rows[key] = row
        self._status_message = f"{operation.get('title', 'operation').lower()} · {key}"
        self._set_live([self._operation_panel()])

    def end_operation(
        self,
        summary: str,
        table: Optional[Any] = None,
        status: str = "ok",
    ) -> None:
        operation = self._operation or {}
        elapsed = int(time.time() - float(operation.get("started", time.time())))
        done, errors, running = self._operation_counts()
        color = {"ok": GREEN, "error": RED, "cancelled": AMBER}.get(status, GREEN)
        label = {"ok": " COMPLETE ", "error": " FAILED ", "cancelled": " CANCELLED "}.get(
            status, " COMPLETE "
        )
        title = str(operation.get("title") or "OPERATION")
        target = str(operation.get("target") or "")
        stats = Text()
        stats.append(f"{done} done", style=GREEN)
        if errors:
            stats.append("  ·  ", style=RULE)
            stats.append(f"{errors} failed", style=RED)
        if running:
            stats.append("  ·  ", style=RULE)
            stats.append(f"{running} unfinished", style=AMBER)
        stats.append("  ·  ", style=RULE)
        stats.append(f"{elapsed // 60:02d}:{elapsed % 60:02d}", style=SLATE)
        body = Group(stats, Text(""), Text(str(summary), style=f"bold {color}"))
        self._clear_live()
        self.print(
            Panel(
                body,
                title=Text(label, style=f"bold {INK} on {color}"),
                title_align="left",
                subtitle=Text(f" {title} · {target} " if target else f" {title} ", style=SLATE_DIM),
                subtitle_align="right",
                border_style=color,
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )
        if table is not None:
            self.print(table)
        self._operation = None
        self._status_message = "ready"
        self._invalidate()

    # -- transcript rendering -------------------------------------------

    def _render_to_ansi(self, renderers: List[Callable[[Console], None]], width: int) -> str:
        buffer = io.StringIO()
        console = Console(
            file=buffer,
            force_terminal=True,
            color_system="truecolor",
            width=max(20, int(width)),
            highlight=False,
            soft_wrap=True,
            legacy_windows=False,
        )
        for render in renderers:
            render(console)
        return buffer.getvalue()

    def _ensure_width(self) -> int:
        width = self._content_width()
        if width != self._frozen_width:
            with self._render_lock:
                self._frozen_ansi = self._render_to_ansi(self._block_renderers, width)
                self._frozen_width = width
                if self._live_renderers:
                    self._live_ansi = self._render_to_ansi(self._live_renderers, width)
        return width

    def print(self, *args: Any, **kwargs: Any) -> None:
        render = lambda console: console.print(*args, **kwargs)  # noqa: E731
        with self._render_lock:
            width = self._ensure_width()
            self._block_renderers.append(render)
            self._frozen_ansi += self._render_to_ansi([render], width)
        self._invalidate()

    def _set_live(self, renderables: List[Any], force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_live_render < 0.065:
            return
        self._last_live_render = now
        renderers = [
            (lambda console, item=item: console.print(item)) for item in renderables if item is not None
        ]
        with self._render_lock:
            self._live_renderers = renderers
            self._live_ansi = (
                self._render_to_ansi(renderers, self._content_width()) if renderers else ""
            )
        self._invalidate()

    def _clear_live(self) -> None:
        with self._render_lock:
            self._live_renderers = []
            self._live_ansi = ""
        self._invalidate()

    def _transcript_text(self) -> ANSI:
        with self._render_lock:
            value = self._frozen_ansi + self._live_ansi
        return ANSI(value)

    def _transcript_cursor(self) -> Point:
        with self._render_lock:
            value = self._frozen_ansi + self._live_ansi
        total = value.count("\n")
        y = total if self._follow_output else max(0, min(self._manual_y, total))
        return Point(x=0, y=y)

    def _scroll_transcript(self, delta: int) -> None:
        with self._render_lock:
            value = self._frozen_ansi + self._live_ansi
        total = value.count("\n")
        if self._follow_output:
            self._manual_y = max(0, total - 4)
            self._follow_output = False
        self._manual_y = max(0, min(self._manual_y + delta, total))
        if self._manual_y >= total:
            self._follow_output = True
        self._invalidate()

    def _invalidate(self) -> None:
        app = self.app
        if app is None:
            return
        try:
            loop = getattr(app, "loop", None)
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(app.invalidate)
            else:
                app.invalidate()
        except Exception:
            pass

    @contextlib.contextmanager
    def status_context(self, message: str) -> Iterator[_TuiStatus]:
        previous = self._status_message
        status = _TuiStatus(self, message)
        self._status_message = status.message or "working"
        self._invalidate()
        try:
            yield status
        finally:
            self._status_message = previous or "ready"
            self._invalidate()

    def clear_view(self) -> None:
        with self._render_lock:
            self._block_renderers = []
            self._frozen_ansi = ""
            self._frozen_width = 0
            self._live_renderers = []
            self._live_ansi = ""
        self._follow_output = True
        self._manual_y = 0
        self._invalidate()

    # -- input -----------------------------------------------------------

    def _accept_input(self, buffer: Any) -> bool:
        text = buffer.text.strip()
        if not text:
            return False
        if self.busy:
            self.print(
                Panel(
                    Text("A request is already running. Press Ctrl+C to cancel it.", style=AMBER),
                    title=Text(" BUSY ", style=f"bold {AMBER}"),
                    border_style=AMBER,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
            return True
        self.busy = True
        self._status_message = "working"
        self._invalidate()
        threading.Thread(target=self._run_turn, args=(text,), daemon=True).start()
        return False

    def _run_turn(self, text: str) -> None:
        self._cancel_requested = False
        try:
            if not self._dispatch(text):
                self._exit()
                return
        except KeyboardInterrupt:
            self.print(Text("Cancelled.", style=AMBER))
        except Exception as exc:  # noqa: BLE001
            self.print(
                Panel(
                    Text(f"{type(exc).__name__}: {exc}", style=RED),
                    title=Text(" INTERNAL ERROR ", style=f"bold {RED}"),
                    border_style=RED,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
            if os.environ.get("HACKIT_DEBUG"):
                self.print(Text(traceback.format_exc(), style=SLATE_DIM))
        finally:
            self.busy = False
            self._status_message = "ready"
            self._invalidate()

    # -- AI exchange -----------------------------------------------------

    def _ask_ai(self, prompt: str, system_extra: str = "") -> str:
        assert self.brain is not None
        self.last_prompt = prompt
        self._cancel_requested = False
        self._status_message = "thinking"
        self._invalidate()

        self.print(
            Panel(
                Text(prompt, style=TEXT),
                title=Text(" YOU ", style=f"bold {SLATE}"),
                title_align="left",
                border_style=RULE,
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

        started = time.time()
        thinking = ""
        answer = ""
        token_count = 0
        splitter = _ReasoningSplitter()
        last_render = [0.0]

        def render_live(force: bool = False) -> None:
            now = time.monotonic()
            if not force and now - last_render[0] < 0.065:
                return
            last_render[0] = now
            blocks: List[Any] = []
            if thinking:
                blocks.append(
                    Panel(
                        Text(thinking, style=f"italic {SLATE}"),
                        title=Text(" THINKING ", style=f"bold {SLATE_DIM}"),
                        title_align="left",
                        border_style=SLATE_DIM,
                        box=box.ROUNDED,
                        padding=(0, 1),
                    )
                )
            if answer:
                blocks.append(
                    Panel(
                        Text(answer, style=TEXT),
                        title=Text(" HACKIT ", style=f"bold {self.accent}"),
                        title_align="left",
                        border_style=self.accent,
                        box=box.ROUNDED,
                        padding=(0, 1),
                    )
                )
            if not blocks:
                blocks.append(Text("…", style=SLATE_DIM))
            self._set_live(blocks, force=force)

        def consume(events: List[Tuple[str, str]]) -> None:
            nonlocal thinking, answer, token_count
            for kind, text in events:
                text = strip_control(text)
                if not text:
                    continue
                token_count += len(text)
                if kind == "thinking":
                    thinking += text
                    self._status_message = "thinking"
                else:
                    answer += text
                    self._status_message = "responding"
            render_live()

        def on_token(event: Dict[str, Any]) -> None:
            token = event.get("token", "")
            if token:
                consume(splitter.feed(token))

        try:
            result = self.brain.stream_chat(prompt, on_token=on_token)
        except KeyboardInterrupt:
            self._clear_live()
            self.print(Text("Cancelled.", style=AMBER))
            self._status_message = "cancelled"
            return ""
        except Exception as exc:  # noqa: BLE001
            self._clear_live()
            if self._cancel_requested or getattr(self.brain, "cancelled", False):
                self.print(Text("Cancelled.", style=AMBER))
                self._status_message = "cancelled"
                return ""
            self.print(
                Panel(
                    Text(f"UI error: {exc}", style=RED),
                    title=Text(" ERROR ", style=f"bold {RED}"),
                    border_style=RED,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
            self._status_message = "error"
            return ""

        if self._cancel_requested or getattr(self.brain, "cancelled", False):
            self._clear_live()
            self.print(
                Panel(
                    Text("Generation cancelled. Partial output was discarded.", style=AMBER),
                    title=Text(" CANCELLED ", style=f"bold {AMBER}"),
                    title_align="left",
                    border_style=AMBER,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
            self._status_message = "cancelled"
            return ""

        consume(splitter.flush())
        if not answer and result:
            answer = strip_control(result)
        if not thinking and not answer:
            self._clear_live()
            self.print(Text("Model returned no final answer.", style=AMBER))
            self._status_message = "empty"
            return result or ""

        render_live(force=True)
        self._clear_live()
        if thinking:
            self.print(
                Panel(
                    Text(thinking, style=f"italic {SLATE}"),
                    title=Text(" THINKING ", style=f"bold {SLATE_DIM}"),
                    title_align="left",
                    border_style=SLATE_DIM,
                    box=box.ROUNDED,
                    padding=(0, 1),
                )
            )
        if answer:
            if answer.strip().startswith("[!]"):
                self.print(
                    Panel(
                        Text(_strip_ansi(answer), style=RED),
                        title=Text(" ERROR ", style=f"bold {RED}"),
                        border_style=RED,
                        box=box.ROUNDED,
                        padding=(0, 1),
                    )
                )
            else:
                self.print(
                    Panel(
                        Markdown(answer),
                        title=Text(" HACKIT ", style=f"bold {self.accent}"),
                        title_align="left",
                        border_style=self.accent,
                        box=box.ROUNDED,
                        padding=(0, 1),
                    )
                )
        elapsed = time.time() - started
        self._session_tokens += max(1, token_count // 4)
        self.print(
            Text(
                f"{_timestamp()}  ·  {elapsed:.1f}s  ·  ~{max(1, token_count // 4)} tokens",
                style=SLATE_DIM,
            )
        )
        self._status_message = "ready"
        return result


# ---------------------------------------------------------------------------
# Concrete full-screen classes
# ---------------------------------------------------------------------------


def _tui_classes():
    from .interactive import AutopilotUI, ChatUI

    class ChatTUI(TuiMixin, ChatUI):
        accent = CYAN

    class AutopilotTUI(TuiMixin, AutopilotUI):
        accent = AMBER

    return ChatTUI, AutopilotTUI


ChatTUI, AutopilotTUI = _tui_classes()
