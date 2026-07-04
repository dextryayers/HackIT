import sys
import os
import time
import shutil
import termios
import tty
import fcntl
import select
import subprocess as _sp
import re
import textwrap
import json
import datetime
from hackit.ui import GREEN, RED, YELLOW, DIM, B_CYAN, MAGENTA, RESET, BOLD, CYAN, WHITE, B_GREEN, B_YELLOW, B_BLUE, B_MAGENTA, _colored

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import ANSI
    from prompt_toolkit.completion import Completer, Completion
    _HAS_PT = True
except ImportError:
    _HAS_PT = False

try:
    from pygments import highlight as _pyg_highlight
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.formatters import TerminalFormatter
    _HAS_PYGMENTS = True
except ImportError:
    _HAS_PYGMENTS = False

_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_HACKIT_WATERMARK = f"\n{DIM}────────────────────{RESET}\n{DIM}  HackIT AI v2.1{RESET}\n"

AUTOPILOT_COMMANDS = {
    "set-target":    "Lock target domain/IP",
    "target":        "Show current target",
    "all":           "Full comprehensive scan",
    "portscan":      "Run port scan on target",
    "subdomainenum": "Enumerate subdomains",
    "dirfuzz":       "Directory/file fuzzing",
    "techdetect":    "Detect web technologies",
    "sqli":          "SQL injection test",
    "xss":           "XSS vulnerability test",
    "ssrf":          "SSRF test",
    "rce":           "Remote code execution test",
    "bypass403":     "403 bypass techniques",
    "cve":           "CVE lookup/search",
    "js":            "JavaScript analysis",
    "header":        "HTTP header audit",
    "ssl":           "SSL/TLS analysis",
    "redirect":      "Open redirect finder",
    "params":        "Parameter discovery",
    "waf":           "WAF detection",
    "takeover":      "Subdomain takeover check",
    "deep":          "Deep vulnerability analysis",
    "report":        "Generate pentest report",
    "export":        "Export conversation [filename]",
    "import":        "Import conversation [filename]",
    "help":          "Show all commands",
    "clear":         "Clear screen",
    "exit":          "Exit autopilot",
    "quit":          "Exit autopilot",
}

CHAT_COMMANDS = {
    "code":       "Generate code with explanation",
    "debug":      "Debug code or errors",
    "explain":    "Explain complex topics simply",
    "translate":  "Translate text between languages",
    "write":      "Write creative content",
    "summarize":  "Summarize long text concisely",
    "math":       "Solve math problems step by step",
    "research":   "Deep research on any topic",
    "review":     "Review code for bugs",
    "refactor":   "Refactor code with best practices",
    "test":       "Generate unit tests for code",
    "diagram":    "Create Mermaid diagrams",
    "learn":      "Teach me step by step",
    "quick":      "Quick concise answer",
    "detail":     "Detailed comprehensive answer",
    "plan":       "Create a step-by-step plan",
    "compare":    "Compare and contrast items",
    "analyze":    "Deep analysis of data/input",
    "export":     "Export conversation [filename]",
    "import":     "Import conversation [filename]",
    "clear":      "Clear conversation",
    "help":       "Show all commands",
    "exit":       "Exit chat mode",
    "quit":       "Exit chat mode",
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


def _clear_screen():
    _sp.run(['clear' if os.name == 'posix' else 'cls'], shell=True)


def _get_term_size():
    return shutil.get_terminal_size()


def _vis_len(s):
    return len(_ANSI_RE.sub('', s))


def _wrap_text(text, width):
    if not text:
        return ['']
    return textwrap.wrap(text, width=width, replace_whitespace=False)


def _loading_animation(mode_name, theme_color):
    steps = [
        ("SYS", "Initializing terminal interface", 5),
        ("CORE", "Loading engine kernel", 6),
        ("MEM", "Allocating buffer zones", 4),
        ("NET", "Establishing secure channel", 5),
        ("READY", "System is ready", 3),
    ]
    chars = ['\u25e2', '\u25e3', '\u25e4', '\u25e5']
    for tag, msg, dur in steps:
        for _ in range(dur):
            c = chars[int(time.time() * 4) % 4]
            sys.stdout.write(f"\r  {theme_color}{c}{RESET} {DIM}[{theme_color}{tag}{DIM}]{RESET} {msg}  ")
            sys.stdout.flush()
            time.sleep(0.07)
    sys.stdout.write(f"\r  {GREEN}\u2713{RESET}  {DIM}{mode_name} initialized{RESET}{' ' * 28}\n")
    sys.stdout.flush()
    time.sleep(0.2)


def _transition_to(mode_name, theme_color, banner_art):
    _clear_screen()
    cols = _get_term_size().columns
    bar_len = min(cols - 20, 36)
    for pct in range(0, 101, 5):
        filled = int(bar_len * pct / 100)
        bar = f"{theme_color}{chr(9608) * filled}{DIM}{chr(9617) * (bar_len - filled)}{RESET}"
        sys.stdout.write(f"\r  {DIM}\u25b6{RESET} {theme_color}{mode_name}{RESET} {bar} {theme_color}{pct}%{RESET} ")
        sys.stdout.flush()
        time.sleep(0.012)
    sys.stdout.write(f"\r{' ' * cols}\r")
    sys.stdout.flush()
    time.sleep(0.1)
    _clear_screen()
    lines = banner_art.strip('\n').split('\n')
    for l in lines:
        sys.stdout.write(f"  {theme_color}{l}{RESET}\n")
    sys.stdout.flush()
    print()
    print(f"  {DIM}{chr(9556)}{chr(9552) * 50}{chr(9559)}{RESET}")
    print(f"  {DIM}{chr(9553)}{RESET}  {theme_color}Type /help{RESET} for commands  |  {BOLD}Tab{RESET} autocomplete  |  {BOLD}\u2191\u2193{RESET} history  {DIM}{chr(9553)}{RESET}")
    print(f"  {DIM}{chr(9562)}{chr(9552) * 50}{chr(9565)}{RESET}")
    print()
    time.sleep(0.2)


class TermUI:
    def __init__(self, mode_name, theme_color, banner_art):
        self.mode_name = mode_name
        self.theme = theme_color
        self.banner_art = banner_art
        self.messages = []
        self.target = ""
        self.running = True
        self.suggestions = []
        self.sel_idx = 0
        self.history = []
        self.hist_idx = -1
        self.scroll_offset = 0
        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)
        sz = _get_term_size()
        self.cols = sz.columns
        self.rows = sz.lines
        self._setup_sigwinch()

    def _setup_sigwinch(self):
        import signal as _sig
        def _resize(signum, frame):
            sz = _get_term_size()
            self.cols = sz.columns
            self.rows = sz.lines
        _sig.signal(_sig.SIGWINCH, _resize)

    def transition_in(self):
        _transition_to(self.mode_name, self.theme, self.banner_art)
        self.messages = []
        for line in self.banner_art.strip('\n').split('\n'):
            self.messages.append(("banner", line, self.theme))

    def _read_key(self):
        ch = os.read(self.fd, 1)
        if not ch:
            return 'ESC'
        ch = chr(ch[0])

        if ch == '\x1b':
            fl = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            fcntl.fcntl(self.fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            seq = ''
            try:
                more = os.read(self.fd, 4)
                seq = more.decode('utf-8', errors='replace') if more else ''
            except (BlockingIOError, OSError):
                seq = ''
            fcntl.fcntl(self.fd, fcntl.F_SETFL, fl)

            if seq == '[A': return 'UP'
            if seq == '[B': return 'DOWN'
            if seq == '[C': return 'RIGHT'
            if seq == '[D': return 'LEFT'
            if seq == '[5~': return 'PGUP'
            if seq == '[6~': return 'PGDN'
            if seq == '[H': return 'HOME'
            if seq == '[F': return 'END'
            if seq == '[Z': return 'SHIFT_TAB'
            return 'ESC'

        if ch in ('\r', '\n'): return 'ENTER'
        if ch in ('\x7f', '\x08'): return 'BACKSPACE'
        if ch == '\x03': return 'CTRLC'
        if ch == '\t': return 'TAB'
        return ch

    def _highlight_code(self, code, lang=""):
        if not _HAS_PYGMENTS or not code.strip():
            return code
        try:
            if lang:
                lexer = get_lexer_by_name(lang, stripall=True)
            else:
                lexer = guess_lexer(code)
            return _pyg_highlight(code, lexer, TerminalFormatter()).rstrip('\n')
        except Exception:
            return code

    def _render_msg(self, role, content, color, width):
        lines = []
        if role == "banner":
            lines.append(f"  {color}{content}{RESET}")
            return lines
        prefix_v = "\u25bc" if role != "assistant" else "\u25c9"
        role_clean = role.upper() if role in ("user", "system") else role.title()
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        lines.append(f" {DIM}[{ts}]{RESET} {color}{prefix_v}{RESET} {BOLD}{color}{role_clean}{RESET}")
        if content:
            in_code = False
            code_lang = ""
            code_buf = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith('```'):
                    if in_code:
                        code_text = '\n'.join(code_buf)
                        highlighted = self._highlight_code(code_text, code_lang)
                        for hl_line in highlighted.split('\n'):
                            for wl in _wrap_text(hl_line, width - 4):
                                lines.append(f"   {wl}")
                        code_buf = []
                        code_lang = ""
                    else:
                        code_lang = stripped[3:].strip().split()[0] if len(stripped) > 3 else ""
                    in_code = not in_code
                    continue
                if in_code:
                    code_buf.append(line)
                else:
                    for wl in _wrap_text(line, width - 2):
                        lines.append(f"  {wl}")
            if code_buf:
                code_text = '\n'.join(code_buf)
                highlighted = self._highlight_code(code_text, code_lang)
                for hl_line in highlighted.split('\n'):
                    for wl in _wrap_text(hl_line, width - 4):
                        lines.append(f"   {wl}")
        lines.append("")
        return lines

    def _all_rendered_lines(self, width):
        all_lines = []
        for role, content, color in self.messages:
            ml = self._render_msg(role, content, color, width)
            all_lines.extend(ml)
        return all_lines

    def _redraw_messages(self):
        width = self.cols - 2
        if width < 20:
            width = 20
        msg_area = self.rows - 4

        all_lines = self._all_rendered_lines(width)
        max_display = msg_area
        total = len(all_lines)

        if total > max_display:
            self.scroll_offset = min(self.scroll_offset, total - max_display)
            start = total - max_display - self.scroll_offset
            end = total - self.scroll_offset
            if start < 0:
                start = 0
                self.scroll_offset = max(0, total - max_display)
                end = total
            display_lines = all_lines[start:end]
            if len(display_lines) > max_display:
                display_lines = display_lines[:max_display]
        else:
            self.scroll_offset = 0
            display_lines = all_lines

        out_parts = [f"\033[1;0H"]
        for i, line in enumerate(display_lines):
            y = 1 + i
            if y > msg_area:
                break
            vis = line[:self.cols - 1] if _vis_len(line) > self.cols - 1 else line
            out_parts.append(f"\033[{y};0H\033[K{vis}")
        for y in range(1 + len(display_lines), msg_area + 1):
            out_parts.append(f"\033[{y};0H\033[K")
        sys.stdout.write(''.join(out_parts))
        sys.stdout.flush()

    def _add_message(self, role, content, color):
        self.messages.append((role, content, color))
        self._redraw_messages()

    def _thinking(self, active=True):
        if active:
            import threading
            self._thinking_active = True
            self._thinking_msg = f"{DIM}\u23f3 HackIT AI is thinking{RESET}"
            self.messages.append(("", self._thinking_msg, DIM))
            self._redraw_messages()
            self._draw_input_bar("", 0)

            def _animate():
                chars = ["\u25e2", "\u25e3", "\u25e4", "\u25e5"]
                dots = 0
                while getattr(self, '_thinking_active', False):
                    c = chars[int(time.time() * 4) % 4]
                    dots = (dots % 3) + 1
                    msg = f"{DIM}{c} HackIT AI is thinking{'.' * dots}{RESET}"
                    for i in range(len(self.messages) - 1, -1, -1):
                        if "\u23f3 HackIT AI is thinking" in str(self.messages[i]) or \
                           "\u25e2 HackIT AI is thinking" in str(self.messages[i]) or \
                           "\u25e3 HackIT AI is thinking" in str(self.messages[i]) or \
                           "\u25e4 HackIT AI is thinking" in str(self.messages[i]) or \
                           "\u25e5 HackIT AI is thinking" in str(self.messages[i]):
                            self.messages[i] = ("", msg, DIM)
                            break
                    self._redraw_messages()
                    self._draw_input_bar("", 0)
                    time.sleep(0.15)

            t = threading.Thread(target=_animate, daemon=True)
            t.start()
        else:
            self._thinking_active = False
            time.sleep(0.05)
            for i in range(len(self.messages) - 1, -1, -1):
                if "HackIT AI is thinking" in str(self.messages[i]):
                    self.messages.pop(i)
                    break
            self._redraw_messages()
            self._draw_input_bar("", 0)

    def _draw_input_bar(self, input_text, cursor):
        bar_y = self.rows
        box_w = self.cols - 2
        if box_w < 20:
            box_w = 20

        hint = " /help" if not self.suggestions else " [Tab]"
        prompt = "> "
        max_w = box_w - len(prompt) - len(hint) - 4
        if max_w < 8:
            max_w = 8

        offset = 0
        if cursor > max_w:
            offset = cursor - max_w
        display = input_text[offset:offset + max_w]
        vis_cursor = min(cursor - offset, max_w)

        top = f"\033[{bar_y-2};0H\033[K  {DIM}|{'=' * (box_w - 2)}|{RESET}"
        middle = f"\033[{bar_y-1};0H\033[K  {DIM}|{RESET} {self.theme}{prompt}{RESET}{WHITE}{display}{RESET}{DIM}{hint}{RESET}{' ' * max(1, box_w - len(prompt) - len(display) - len(hint) - 4)}{DIM}|{RESET}"
        bottom = f"\033[{bar_y};0H\033[K  {DIM}|{'=' * (box_w - 2)}|{RESET}"

        sys.stdout.write(top)
        sys.stdout.write(middle)
        sys.stdout.write(bottom)

        abs_cursor = 4 + len(prompt) + vis_cursor
        sys.stdout.write(f"\033[{bar_y-1};{abs_cursor}H")
        sys.stdout.flush()

    def _draw_suggestions(self, suggestions, sel_idx):
        if not suggestions:
            return
        max_show = min(len(suggestions), 8)
        start_y = self.rows - 3 - max_show
        out_parts = []
        for i in range(max_show):
            y = start_y + i
            if y < 1:
                continue
            s = suggestions[i]
            cmd = s.split('\u2014')[0].strip() if '\u2014' in s else s
            desc = s.split('\u2014')[-1].strip() if '\u2014' in s else ''
            if i == sel_idx:
                out_parts.append(f"\033[{y};0H\033[K  {self.theme}\u25b8{RESET} {BOLD}{WHITE}/{cmd}{RESET}  {DIM}{desc}{RESET}")
            else:
                out_parts.append(f"\033[{y};0H\033[K   {DIM}/{cmd}{RESET}  {DIM}{desc}{RESET}")
        if out_parts:
            sys.stdout.write(''.join(out_parts))
            sys.stdout.flush()

    def _clear_suggestions(self, count):
        if count <= 0:
            return
        out_parts = []
        for i in range(count):
            y = self.rows - 3 - i - 1
            if y >= 1:
                out_parts.append(f"\033[{y};0H\033[K")
        if out_parts:
            sys.stdout.write(''.join(out_parts))
            sys.stdout.flush()

    def _rich_input(self, commands_dict):
        if not _HAS_PT:
            return self.get_input(commands_dict)

        history_path = os.path.join(os.path.expanduser("~"), ".hackit_pt_history")
        try:
            session = PromptSession(
                history=FileHistory(history_path),
                auto_suggest=AutoSuggestFromHistory(),
                enable_history_search=True,
                multiline=False,
            )

            class CmdCompleter(Completer):
                def __init__(self, cmds):
                    self.cmds = cmds
                def get_completions(self, document, complete_event):
                    text = document.text
                    if text.startswith('/'):
                        partial = text[1:].lower()
                        for cmd, desc in self.cmds.items():
                            if cmd.startswith(partial):
                                display = f"/{cmd}  — {desc}"
                                yield Completion(f"/{cmd} ", start_position=-len(text), display=display)

            prompt_text = ANSI(f"\033[2K\r  {self.theme}\u25b8{RESET} ")
            try:
                result = session.prompt(
                    prompt_text,
                    completer=CmdCompleter(commands_dict),
                    complete_while_typing=True,
                    vi_mode=False,
                )
                result = result.strip()
                if not result:
                    return ""
                if result.startswith('//'):
                    return result[1:]
                return result
            except (EOFError, KeyboardInterrupt):
                return "/exit"
        except Exception:
            return self.get_input(commands_dict)

    def _autocomplete_best(self, input_text, commands_dict):
        if not input_text.startswith('/') or input_text.startswith('//'):
            return input_text, len(input_text)
        partial = input_text[1:].lower()
        matches = [cmd for cmd in commands_dict if cmd.startswith(partial)]
        if not matches:
            return input_text, len(input_text)
        if len(matches) == 1:
            return '/' + matches[0] + ' ', len(matches[0]) + 2
        common = os.path.commonprefix(matches)
        if len(common) > len(partial):
            return '/' + common, len(common) + 1
        return input_text, len(input_text)

    def get_input(self, commands_dict):
        self.suggestions = []
        self.sel_idx = 0
        input_text = ""
        cursor = 0
        need_redraw = False

        self._redraw_messages()
        self._draw_input_bar(input_text, cursor)

        while self.running:
            k = self._read_key()

            old_suggestions = list(self.suggestions)
            old_sel = self.sel_idx

            if k == 'ENTER':
                if self.suggestions and self.suggestions[0]:
                    sel = self.suggestions[self.sel_idx]
                    cmd = sel.split('\u2014')[0].strip() if '\u2014' in sel else sel
                    input_text = '/' + cmd + ' '
                    cursor = len(input_text)
                    self._clear_suggestions(len(self.suggestions))
                    self.suggestions = []
                    self._draw_input_bar(input_text, cursor)
                    continue
                break

            elif k == 'BACKSPACE':
                if cursor > 0:
                    input_text = input_text[:cursor - 1] + input_text[cursor:]
                    cursor -= 1
                    need_redraw = True

            elif k == 'CTRLC':
                self._clear_suggestions(len(self.suggestions))
                return '/exit'

            elif k == 'TAB':
                new_text, new_cursor = self._autocomplete_best(input_text, commands_dict)
                if new_text != input_text:
                    input_text = new_text
                    cursor = new_cursor
                    need_redraw = True
                    self._clear_suggestions(len(self.suggestions))
                    self.suggestions = []

            elif k == 'SHIFT_TAB':
                if self.suggestions:
                    self.sel_idx = (self.sel_idx - 1) % len(self.suggestions)

            elif k == 'UP':
                if self.suggestions:
                    self.sel_idx = (self.sel_idx - 1) % len(self.suggestions)
                elif self.history:
                    self.hist_idx = min(self.hist_idx + 1, len(self.history) - 1)
                    idx = -(self.hist_idx + 1)
                    input_text = self.history[idx] if idx < 0 else self.history[0]
                    cursor = len(input_text)

            elif k == 'DOWN':
                if self.suggestions:
                    self.sel_idx = (self.sel_idx + 1) % len(self.suggestions)
                elif self.hist_idx >= 0:
                    self.hist_idx -= 1
                    if self.hist_idx >= 0:
                        input_text = self.history[-(self.hist_idx + 1)]
                    else:
                        input_text = ""
                    cursor = len(input_text)

            elif k == 'LEFT':
                if cursor > 0:
                    cursor -= 1

            elif k == 'RIGHT':
                if cursor < len(input_text):
                    cursor += 1

            elif k == 'HOME':
                cursor = 0

            elif k == 'END':
                cursor = len(input_text)

            elif k == 'PGUP':
                self.scroll_offset = min(self.scroll_offset + 5, 5000)
                self._redraw_messages()
                self._draw_input_bar(input_text, cursor)
                continue

            elif k == 'PGDN':
                self.scroll_offset = max(self.scroll_offset - 5, 0)
                self._redraw_messages()
                self._draw_input_bar(input_text, cursor)
                continue

            elif len(k) == 1:
                input_text = input_text[:cursor] + k + input_text[cursor:]
                cursor += 1
                need_redraw = True

            else:
                continue

            if need_redraw and input_text.startswith('/') and not input_text.startswith('//'):
                partial = input_text[1:].lower()
                self.suggestions = [f"{cmd} \u2014 {desc}"
                                    for cmd, desc in commands_dict.items()
                                    if cmd.startswith(partial)][:10]
                self.sel_idx = 0
            elif need_redraw:
                self.suggestions = []
                self.sel_idx = 0

            if self.suggestions != old_suggestions or self.sel_idx != old_sel:
                self._clear_suggestions(len(old_suggestions) if old_suggestions else 0)
                self._draw_suggestions(self.suggestions, self.sel_idx)

            self._draw_input_bar(input_text, cursor)
            need_redraw = False

        result = input_text.strip()
        self._clear_suggestions(len(self.suggestions))
        self.suggestions = []
        self._draw_input_bar("", 0)
        if result:
            if not self.history or self.history[-1] != result:
                self.history.append(result)
            self.hist_idx = -1
        return result

    def run(self):
        pass

    def close(self):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)
        sys.stdout.write(f"\033[{self.rows};0H\033[J")
        sys.stdout.flush()


    def _export_conversation(self, filepath=""):
        if not filepath:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"hackit_conversation_{ts}.md"
        md_lines = [f"# HackIT AI Conversation\n", f"**Exported:** {datetime.datetime.now().isoformat()}\n", f"**Mode:** {self.mode_name}\n\n---\n"]
        for role, content, color in self.messages:
            if role == "banner":
                continue
            prefix = "**User**" if role == "user" else "**System**" if role == "system" else "**Assistant**"
            md_lines.append(f"\n### {prefix}\n\n{content}\n")
        md_lines.append("\n---\n*Generated by HackIT AI v2.1*\n")
        try:
            with open(filepath, 'w') as f:
                f.write('\n'.join(md_lines))
            return f"Conversation exported to {filepath}"
        except Exception as e:
            return f"Export failed: {e}"

    def _import_conversation(self, filepath):
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            sections = content.split('### ')
            count = 0
            for sec in sections:
                if sec.startswith('**User**'):
                    text = sec.split('\n\n', 1)[-1].strip()
                    self._add_message("user", text, self.theme)
                    count += 1
                elif sec.startswith('**Assistant**'):
                    text = sec.split('\n\n', 1)[-1].strip()
                    if text and not text.startswith('*Generated by'):
                        self._add_message("assistant", text, GREEN if self.mode_name == "AUTOPILOT" else CYAN)
                        count += 1
            return f"Imported {count} messages from {filepath}"
        except Exception as e:
            return f"Import failed: {e}"

class AutopilotUI(TermUI):
    def __init__(self):
        super().__init__("AUTOPILOT", B_GREEN, AUTOPILOT_BANNER)
        self.brain = None

    def _run_hative(self, modules=None):
        if not self.target:
            self._add_message("system", "Set target first with /set-target", YELLOW)
            return
        self._add_message("system", f"Launching hative scan on {self.target}...", self.theme)
        from hackit.agent.brain import AIHyperBrain
        brain = AIHyperBrain(engine="native")

        def on_progress(evt):
            event = evt.get("event", "")
            mod = evt.get("module", "")
            msg = evt.get("message", "")
            pct = evt.get("pct", 0)
            eta = evt.get("eta_seconds", 0)
            if event == "start":
                self._add_message("", f"  [{B_GREEN}\u25b6{RESET}] {msg}", DIM)
            elif event == "done":
                eta_str = f" (ETA: {eta}s)" if eta else ""
                self._add_message("", f"  [{GREEN}\u2713{RESET}] {msg}{eta_str}", GREEN)
            elif event == "error":
                self._add_message("", f"  [{RED}\u2717{RESET}] {msg}", RED)
            elif event == "interrupted":
                self._add_message("", f"  [{YELLOW}\u26a0{RESET}] {msg}", YELLOW)
            elif event == "complete":
                self._add_message("system", f"Scan complete: {msg}", GREEN)

        results = brain.stream_hative(self.target, on_progress=on_progress, modules=modules)
        if not results:
            self._add_message("system", "No results from hative", RED)
            return
        if isinstance(results, list) and len(results) > 0:
            if "error" in results[0]:
                self._add_message("system", f"Hative error: {results[0]['error']}", RED)
                return

            vuln_count = 0
            total_count = len(results)
            for r in results:
                data = r.get("data")
                if isinstance(data, list):
                    vuln_count += len(data)

            self._add_message("system",
                f"Scan complete: {total_count} modules, {vuln_count} findings", GREEN)

    def run(self):
        self.transition_in()
        from hackit.agent.brain import AIHyperBrain
        self.brain = AIHyperBrain(engine="native")
        use_pt = _HAS_PT and os.isatty(self.fd)
        try:
            if not use_pt:
                tty.setraw(self.fd)
            self._add_message("system", "Autopilot ready. Set target with /set-target", DIM)
            while self.running:
                cmd = self._rich_input(AUTOPILOT_COMMANDS) if use_pt else self.get_input(AUTOPILOT_COMMANDS)
                if not cmd:
                    continue
                if cmd in ('/exit', '/quit', 'exit', 'quit'):
                    self._add_message("system", "Shutting down autopilot...", RED)
                    break
                if cmd == '/clear':
                    self.messages = []
                    _clear_screen()
                    self.transition_in()
                    continue
                if cmd.startswith('/set-target '):
                    self.target = cmd[12:].strip()
                    self._add_message("system", f"Target locked: {self.target}", YELLOW)
                    continue
                if cmd == '/target':
                    if self.target:
                        self._add_message("system", f"Current target: {self.target}", YELLOW)
                    else:
                        self._add_message("system", "No target set. Use /set-target <domain|ip>", YELLOW)
                    continue
                if cmd == '/all':
                    self._add_message("user", "Running full comprehensive scan via hative...", self.theme)
                    self._run_hative()
                    continue
                if cmd == '/js':
                    self._add_message("user", "Running JS analysis...", self.theme)
                    self._run_hative(modules=["js"])
                    continue
                if cmd == '/params':
                    self._add_message("user", "Running param discovery...", self.theme)
                    self._run_hative(modules=["param"])
                    continue
                if cmd.startswith('/export '):
                    fp = cmd[8:].strip()
                    result = self._export_conversation(fp)
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd == '/export':
                    result = self._export_conversation()
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd.startswith('/import '):
                    fp = cmd[8:].strip()
                    result = self._import_conversation(fp)
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd == '/help':
                    self._add_message("system", "COMMANDS", self.theme)
                    for c, d in AUTOPILOT_COMMANDS.items():
                        self._add_message("", f"/{c:<15} {d}", self.theme)
                    continue
                if cmd.startswith('/'):
                    self._add_message("user", cmd, self.theme)
                    if self.target:
                        full_cmd = f"{cmd} target={self.target}"
                        self._thinking(True)
                        resp = self.brain._invoke_engine(full_cmd)
                        self._thinking(False)
                        resp = resp.replace('[!] AI Error:', '').replace('[!] Engine Error:', '').strip()
                        if not resp:
                            resp = "No response from engine"
                        self._add_message("assistant", resp + _HACKIT_WATERMARK, GREEN)
                    else:
                        self._add_message("assistant", "Set target first with /set-target", YELLOW)
                    continue
                self._add_message("user", cmd, self.theme)
                self._thinking(True)
                resp = self.brain._invoke_engine(cmd)
                self._thinking(False)
                resp = resp.replace('[!] AI Error:', '').replace('[!] Engine Error:', '').strip()
                if not resp:
                    resp = "No response from engine"
                self._add_message("assistant", resp + _HACKIT_WATERMARK, GREEN)
        except Exception as e:
            self._add_message("system", f"Error: {e}", RED)
        finally:
            self.close()


class ChatUI(TermUI):
    def __init__(self):
        super().__init__("CHAT", B_CYAN, CHAT_BANNER)
        self.brain = None

    def run(self):
        self.transition_in()
        from hackit.agent.brain import AIHyperBrain
        self.brain = AIHyperBrain(engine="chat")
        use_pt = _HAS_PT and os.isatty(self.fd)
        try:
            if not use_pt:
                tty.setraw(self.fd)
            self._add_message("system", "Chat mode active. Ask me anything!", DIM)
            while self.running:
                cmd = self._rich_input(CHAT_COMMANDS) if use_pt else self.get_input(CHAT_COMMANDS)
                if not cmd:
                    continue
                if cmd in ('/exit', '/quit', 'exit', 'quit'):
                    self._add_message("system", "Exiting chat mode...", RED)
                    break
                if cmd == '/clear':
                    self.messages = []
                    _clear_screen()
                    self.transition_in()
                    continue
                if cmd.startswith('/export '):
                    fp = cmd[8:].strip()
                    result = self._export_conversation(fp)
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd == '/export':
                    result = self._export_conversation()
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd.startswith('/import '):
                    fp = cmd[8:].strip()
                    result = self._import_conversation(fp)
                    self._add_message("system", result, YELLOW)
                    continue
                if cmd == '/help':
                    self._add_message("system", "COMMANDS", self.theme)
                    for c, d in CHAT_COMMANDS.items():
                        self._add_message("", f"/{c:<12} {d}", self.theme)
                    self._add_message("", "Any other text: Send to AI", DIM)
                    continue
                self._add_message("user", cmd, self.theme)
                self._thinking(True)
                resp = self.brain._invoke_engine(cmd)
                self._thinking(False)
                resp = resp.replace('[!] AI Error:', '').replace('[!] Engine Error:', '').strip()
                if not resp:
                    resp = "No response from engine"
                self._add_message("assistant", resp + _HACKIT_WATERMARK, CYAN)
        except Exception as e:
            self._add_message("system", f"Error: {e}", RED)
        finally:
            self.close()
