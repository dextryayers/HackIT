"""KeyStrike — multi-protocol brute force front end.

The CLI is a thin, honest wrapper: it collects targets and candidates, hands
them to the Rust engine, and renders what the engine reports. Progress and
credentials are printed the moment the engine emits them, not after the run
finishes.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Dict, List, Optional

import click
from hackit.ui import (
    _colored, B_CYAN, B_GREEN, B_MAGENTA, B_BLUE, B_WHITE, B_YELLOW,
    B_RED, WHITE, YELLOW, DIM, GREEN, RED, BLUE, CYAN, MAGENTA,
    BG_BLUE, BG_CYAN, BG_GREEN, BG_MAGENTA, BG_B_RED, BG_B_BLUE,
    BG_B_GREEN, BG_B_CYAN, BG_B_MAGENTA, BG_B_YELLOW, RESET,
)
from hackit.bruteforcer.engine import (
    EngineError,
    PROTOCOLS,
    USERLESS,
    build_engine,
    default_passwords,
    default_users,
    detect_service,
    engine_available,
    get_default_port,
    get_protocol_name,
    list_protocols,
    list_wordlists,
    load_wordlist,
    probe_port,
    run_bruteforce,
)

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))

ART = [
    "██╗  ██╗███████╗██╗   ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗",
    "██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝",
    "█████╔╝ █████╗   ╚████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  ",
    "██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  ",
    "██║  ██╗███████╗   ██║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗",
    "╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝",
]

ART_W = len(ART[0])
IW = ART_W


def _box_w() -> int:
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    return min(cols - 4, ART_W + 4)


def _draw_box(title: str, w: Optional[int] = None) -> int:
    if w is None:
        w = _box_w()
    print(_colored(f"  ╔{'═' * IW}╗", CYAN))
    if title:
        print(_colored(f"  ║{title:^{IW}}║", CYAN))
        print(_colored(f"  ║{'─' * IW}║", CYAN))
    return w


def _draw_box_end(w: Optional[int] = None) -> None:
    print(_colored(f"  ╚{'═' * IW}╝", CYAN))


def _box_line(text: str, color: str = DIM) -> None:
    """One padded line inside a drawn box."""
    body = text.ljust(IW - 4)[: IW - 4]
    print(f"  {_colored('║', CYAN)}  {_colored(body, color)}  {_colored('║', CYAN)}")


def _draw_banner() -> None:
    os.system("clear")
    print(_colored(f"  ╔{'═' * IW}╗", B_RED))
    for line in ART:
        print(f"  {_colored('║', B_RED)}{_colored(line, BLUE)}{_colored('║', B_RED)}")
    sub = "Multi-Protocol Brute Force Attack System"
    print(f"  {_colored('║', B_RED)}{_colored(sub.center(IW), B_CYAN)}{_colored('║', B_RED)}")
    print(_colored(f"  ╚{'═' * IW}╝", B_RED))
    print()


def _proto_entry(i: int, name: str, port: int) -> str:
    label = get_protocol_name(name)
    return f"{_colored(f'[{i:02d}]', B_CYAN)} {_colored(f'{label:11s}', B_WHITE)} {_colored(f':{port}', DIM)}"


def _entry_vis(i: int, name: str, port: int) -> str:
    return f"[{i:02d}] {get_protocol_name(name):11s} :{port}"


def _draw_protos(w: Optional[int] = None) -> None:
    _draw_box(" PROTOCOLS ", w)
    half = (len(PROTOCOLS) + 1) // 2
    left = PROTOCOLS[:half]
    right = PROTOCOLS[half:]

    for i in range(max(len(left), len(right))):
        inner_vis = ""
        if i < len(left):
            inner_vis += "  " + _entry_vis(i + 1, left[i][0], left[i][1]) + "     "
        else:
            inner_vis += " " * 27
        if i < len(right):
            inner_vis += _entry_vis(half + i + 1, right[i][0], right[i][1])
        padding = IW - len(inner_vis)

        inner_col = ""
        if i < len(left):
            inner_col += "  " + _proto_entry(i + 1, left[i][0], left[i][1]) + "     "
        else:
            inner_col += " " * 27
        if i < len(right):
            inner_col += _proto_entry(half + i + 1, right[i][0], right[i][1])
        inner_col += " " * padding

        print(f"  {_colored('║', CYAN)}{inner_col}{_colored('║', CYAN)}")
    _draw_box_end(w)
    print()


def _loading(text: str, duration: float = 1.5) -> None:
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r  {_colored(frames[i % len(frames)], B_CYAN)} {_colored(text, DIM)}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r  {_colored('✔', B_GREEN)} {_colored(text, DIM)}" + " " * 10 + "\n")


# ─────────────────────────── live renderer ───────────────────────────
class LiveReporter:
    """Renders engine events as they arrive.

    Progress redraws a single terminal line; a credential hit prints a permanent
    line above it so nothing scrolls away. Every number shown comes from the
    engine — none of it is estimated here.
    """

    def __init__(self, label: str, target: str, port: int, quiet: bool = False):
        self.label = label
        self.target = target
        self.port = port
        self.quiet = quiet
        self.found: List[Dict[str, object]] = []
        self.started = time.time()
        self._last_len = 0
        self._interactive = sys.stdout.isatty() and not quiet

    def _clear_line(self) -> None:
        if not self._interactive or not self._last_len:
            return
        sys.stdout.write("\r" + " " * self._last_len + "\r")
        self._last_len = 0

    def _bar(self, fraction: float, width: int = 28) -> str:
        fraction = max(0.0, min(1.0, fraction))
        filled = int(round(fraction * width))
        return "█" * filled + "░" * (width - filled)

    def handle(self, event: Dict[str, object]) -> None:
        status = event.get("status")

        if status == "progress":
            if self.quiet:
                return
            attempted = int(event.get("attempted", 0) or 0)
            total = int(event.get("total", 0) or 0)
            speed = float(event.get("speed", 0.0) or 0.0)
            eta = float(event.get("eta", 0.0) or 0.0)
            hits = int(event.get("found", 0) or 0)
            fraction = (attempted / total) if total else 0.0

            if self._interactive:
                line = (
                    f"  {_colored('▸', B_CYAN)} {self._bar(fraction)} "
                    f"{fraction * 100:5.1f}%  "
                    f"{_colored(f'{attempted}/{total}', B_WHITE)}  "
                    f"{_colored(f'{speed:.0f}/s', B_GREEN)}  "
                    f"eta {_colored(f'{eta:.0f}s', DIM)}  "
                    f"hits {_colored(str(hits), B_YELLOW)}"
                )
                self._clear_line()
                sys.stdout.write(line)
                sys.stdout.flush()
                self._last_len = _visible_len(line)
            elif attempted and attempted % 500 == 0:
                click.echo(
                    f"  [*] {attempted}/{total} ({fraction * 100:.1f}%) "
                    f"{speed:.0f}/s eta {eta:.0f}s hits {hits}"
                )

        elif status == "found":
            self._clear_line()
            user = event.get("username", "")
            password = event.get("password", "")
            hit = {
                "username": user,
                "password": password,
                "protocol": event.get("protocol", self.label),
                "target": event.get("target", self.target),
                "port": event.get("port", self.port),
            }
            self.found.append(hit)
            who = f"{user}:{password}" if user else str(password)
            click.echo(f"  {_colored('[+]', B_GREEN)} {_colored(who, B_GREEN)}")

        elif status == "error":
            self._clear_line()
            click.echo(f"  {_colored('[!]', RED)} {_colored(str(event.get('message', '')), RED)}")

    def close(self) -> None:
        self._clear_line()


def _visible_len(text: str) -> int:
    """Length of a rendered line with ANSI escapes removed."""
    out = 0
    i = 0
    while i < len(text):
        if text[i] == "\x1b":
            while i < len(text) and text[i] not in "mK":
                i += 1
            i += 1
            continue
        out += 1
        i += 1
    return out


def _require_engine() -> bool:
    if engine_available():
        return True
    click.echo(_colored(f"  [!] engine binary missing: {ENGINE_DIR}/rust_engine/target/release/keystrike", RED))
    click.echo(_colored("      build it with: cargo build --release", DIM))
    return False


def _collect_wordlist(inline: Optional[str], path: Optional[str], fallback: str) -> List[str]:
    """Resolve a candidate source into a list. `path` wins over `inline`."""
    if path:
        return load_wordlist(path)
    if inline:
        return [inline]
    return load_wordlist(fallback)


@click.group(invoke_without_command=True)
@click.pass_context
def bruter(ctx):
    if ctx.invoked_subcommand is None:
        _keyconsole()


@bruter.command(name="list-protocols")
def list_protocols_cmd():
    _draw_protos()


@bruter.command(name="wordlists")
def wordlists_cmd():
    _draw_box(" BUILT-IN WORDLISTS ")
    for name, path in list_wordlists().items():
        try:
            count = len(load_wordlist(path))
        except OSError:
            count = 0
        _box_line(f"{name:12s} {count:5d} entries  {path}", B_WHITE)
    _draw_box_end()
    click.echo()


@bruter.command(name="build")
def build_cmd():
    click.echo(_colored("  [*] building the Rust engine...", DIM))
    ok, output = build_engine()
    if ok:
        click.echo(_colored("  [+] build finished", B_GREEN))
    else:
        click.echo(_colored("  [!] build failed", RED))
        click.echo(output)
        sys.exit(1)


def _printable(text: str) -> str:
    """Collapse binary banner bytes into something a terminal can render."""
    out = []
    for ch in text:
        code = ord(ch)
        if code == 9 or code == 10 or code == 13:
            out.append(" ")
        elif 32 <= code < 127:
            out.append(ch)
        elif code >= 160:
            out.append(ch)
        else:
            out.append(".")
    collapsed = " ".join("".join(out).split())
    return collapsed[:60]


@bruter.command(name="detect")
@click.option("--target", "-t", required=True, help="Target host or IP")
@click.option("--port", "-p", type=int, multiple=True, help="Port to probe (repeatable)")
@click.option("--timeout", type=float, default=3.0, help="Probe timeout in seconds")
def detect_cmd(target: str, port, timeout: float):
    """Identify the service on a port from what it actually says."""
    ports = list(port) or [22, 21, 23, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379]
    _draw_box(f" SERVICE DETECTION — {target} ")
    for p in ports:
        info = detect_service(target, p, timeout)
        proto = info.get("protocol")
        banner = _printable(str(info.get("banner") or ""))
        if proto:
            _box_line(f"{p:5d}  {get_protocol_name(str(proto)):12s} {banner}", B_GREEN)
        elif banner:
            _box_line(f"{p:5d}  {'unknown':12s} {banner}", YELLOW)
        else:
            _box_line(f"{p:5d}  {'closed':12s} {_printable(str(info.get('detail', '')))}", DIM)
    _draw_box_end()
    click.echo()


@bruter.command()
@click.option("--protocol", "-P", required=True, help="Protocol name, or 'all' to auto-detect")
@click.option("--target", "-t", required=True, help="Target host or IP")
@click.option("--port", "-p", type=int, default=0, help="Port (0 = protocol default)")
@click.option("--user", "-u", help="Single username")
@click.option("--userlist", "-U", help="Username list file or built-in name")
@click.option("--pass", "-w", "passwd", help="Single password")
@click.option("--passlist", "-W", help="Password list file or built-in name")
@click.option("--combo-file", "-C", help="user:pass file (replaces -u/-U/-w/-W)")
@click.option("--extra", "-e", default="", help="Extra candidates: n=null, s=same as login, r=reversed login")
@click.option("--threads", "-T", type=int, default=16, show_default=True)
@click.option("--timeout", type=int, default=10, show_default=True)
@click.option("--stop-on-first", "-f", is_flag=True, help="Stop after the first valid credential")
@click.option("--retries", type=int, default=1, show_default=True, help="Retries on transport errors")
@click.option("--rate", type=float, default=0.0, show_default=True, help="Attempts per second cap (0 = unlimited)")
@click.option("--wait", type=float, default=0.0, show_default=True, help="Seconds to sleep before each attempt")
@click.option("--resume", type=click.Path(), help="Resume cursor file (read on start, written every 5 s)")
@click.option("--max-blocking", type=int, help="Max OS threads for blocking protocol work")
@click.option("--expand-words", is_flag=True, help="Expand the password list (case, digits, suffixes)")
@click.option("--check", is_flag=True, help="Probe reachability first and exit if the port is closed")
@click.option("--http-path", default="", help="HTTP request path")
@click.option("--http-method", default="GET", help="HTTP form method: GET or POST")
@click.option("--http-body", default="", help="HTTP form body template with ^USER^ and ^PASS^")
@click.option("--http-fail", default="", help="Text present only on a failed login")
@click.option("--http-success", default="", help="Text present only on a successful login")
@click.option("--http-header", "http_headers", multiple=True, help="Extra HTTP header, repeatable")
@click.option("--http-tls", is_flag=True, help="Force https")
@click.option("--http-force-basic", is_flag=True, help="Send Basic credentials even without a 401")
@click.option("--verbose", "-v", is_flag=True, help="Per-attempt chatter")
@click.option("--quiet", "-q", is_flag=True, help="Only print credentials and the summary")
def scan(protocol, target, port, user, userlist, passwd, passlist, combo_file, extra,
         threads, timeout, stop_on_first, retries, rate, wait, resume, max_blocking,
         expand_words, check, http_path, http_method, http_body, http_fail, http_success,
         http_headers, http_tls, http_force_basic, verbose, quiet):
    """Brute-force one service."""
    if not _require_engine():
        return

    http = None
    if http_path or http_body or http_fail or http_success or http_headers or http_tls or http_force_basic:
        http = {
            "path": http_path,
            "method": http_method,
            "body": http_body,
            "fail": http_fail,
            "success": http_success,
            "headers": list(http_headers),
            "tls": http_tls,
            "force_basic": http_force_basic,
        }

    if protocol.lower() == "all":
        _scan_all(target, port, threads, timeout, stop_on_first, quiet,
                  user, userlist, passwd, passlist, combo_file, http)
        return

    _scan_one(
        protocol=protocol,
        target=target,
        port=port,
        user=user,
        userlist=userlist,
        passwd=passwd,
        passlist=passlist,
        combo_file=combo_file,
        extra=extra,
        threads=threads,
        timeout=timeout,
        stop_on_first=stop_on_first,
        retries=retries,
        rate=rate,
        wait=wait,
        resume=resume,
        max_blocking=max_blocking,
        expand_words=expand_words,
        check=check,
        http=http,
        verbose=verbose,
        quiet=quiet,
    )


def _scan_one(protocol: str, target: str, port: int, user, userlist, passwd, passlist,
              combo_file, extra, threads, timeout, stop_on_first, retries, rate, wait,
              resume, max_blocking, expand_words, check, http, verbose, quiet) -> Optional[Dict]:
    proto = protocol.lower()
    label = get_protocol_name(proto)
    effective_port = port or get_default_port(proto)

    # Inline values become one-element lists; file paths are passed straight
    # through so a million-line list is never copied into memory here. A
    # built-in wordlist name is resolved to its lines up front.
    users = [user] if user else None
    passwords = [passwd] if passwd is not None else None

    userlist_path = None
    if userlist:
        if os.path.isfile(userlist):
            userlist_path = userlist
        else:
            users = load_wordlist(userlist)
            userlist_path = None

    passlist_path = None
    if passlist:
        if os.path.isfile(passlist):
            passlist_path = passlist
        else:
            passwords = load_wordlist(passlist)
            passlist_path = None

    if not quiet:
        click.echo(_colored(f"\n  [*] {label} on {target}:{effective_port}", B_CYAN))

    reporter = LiveReporter(proto, target, effective_port, quiet=quiet)

    try:
        result = run_bruteforce(
            target,
            effective_port,
            proto,
            users=users,
            passwords=passwords,
            threads=threads,
            timeout=timeout,
            userlist=userlist_path,
            passlist=passlist_path,
            combo_file=combo_file,
            extra=extra,
            stop_on_first=stop_on_first,
            retries=retries,
            rate=rate,
            wait=wait,
            resume=resume,
            max_blocking=max_blocking,
            expand_words=expand_words,
            check=check,
            verbose=verbose,
            http=http,
            on_event=reporter.handle,
        )
    except EngineError as exc:
        reporter.close()
        click.echo(_colored(f"  [!] {exc}", RED))
        return None
    except KeyboardInterrupt:
        reporter.close()
        click.echo(_colored("\n  [*] interrupted", DIM))
        return None
    finally:
        reporter.close()

    _render_summary(result, label, quiet)
    return result


def _render_summary(result: Dict, label: str, quiet: bool) -> None:
    found = result.get("found", [])
    attempts = result.get("total_attempts", 0)
    combos = result.get("total_combos", 0)
    elapsed = float(result.get("elapsed", 0.0) or 0.0)
    speed = result.get("speed") or f"{result.get('speed_raw', 0.0):.0f}/s"
    errors = result.get("transport_errors", 0)

    _draw_box(f" RESULTS — {label} ")
    _box_line(
        f"Attempts: {attempts}/{combos}  |  Time: {elapsed:.1f}s  |  Speed: {speed}  |  Errors: {errors}"
    )
    _box_line(f"Found: {len(found)}", B_GREEN if found else RED)
    if result.get("stopped_early"):
        _box_line("stopped early on first hit", YELLOW)
    _draw_box_end()

    if found:
        click.echo()
        _draw_box(f" CREDENTIALS — {len(found)} ")
        for cred in found:
            who = f"{cred.get('username', '')}:{cred.get('password', '')}"
            _box_line(who, B_GREEN)
        _draw_box_end()
    elif not quiet:
        click.echo(f"  {_colored('[-] no valid credentials', DIM)}")
    click.echo()


def _scan_all(target: str, port: int, threads: int, timeout: int, stop_on_first: bool,
              quiet: bool, user, userlist, passwd, passlist, combo_file, http) -> None:
    """Detect the service, then attack what was detected.

    Detection reads the real greeting. If nothing identifies itself, every
    protocol default port is probed and only open ports are attempted — no
    guessing, no fabricated protocols in the result table.
    """
    detected: Optional[str] = None
    detected_port = port

    if port:
        info = detect_service(target, port, min(timeout, 5))
        detected = info.get("protocol")  # type: ignore[assignment]
    else:
        for name, default_port in PROTOCOLS:
            if not probe_port(target, default_port, 1.5):
                continue
            info = detect_service(target, default_port, min(timeout, 5))
            proto = info.get("protocol")
            if proto and proto == name:
                detected = proto
                detected_port = default_port
                break

    if detected:
        click.echo(_colored(
            f"  [*] detected {get_protocol_name(str(detected))} on {target}:{detected_port}",
            B_GREEN,
        ))
        _scan_one(
            protocol=str(detected), target=target, port=detected_port,
            user=user, userlist=userlist, passwd=passwd, passlist=passlist,
            combo_file=combo_file, extra="", threads=threads, timeout=timeout,
            stop_on_first=stop_on_first, retries=1, rate=0.0, wait=0.0,
            resume=None, max_blocking=None, expand_words=False, check=False,
            http=http, verbose=False, quiet=quiet,
        )
        return

    click.echo(_colored("  [!] no service identified its protocol", YELLOW))
    click.echo(_colored("      open ports were probed; pass -P explicitly to force one", DIM))


# ─────────────────────────── interactive console ───────────────────────────
def _ask(prompt: str, default: str = "") -> str:
    raw = input(_colored(prompt, B_CYAN)).strip()
    return raw or default


def _ask_int(prompt: str, default: int) -> int:
    raw = _ask(prompt, str(default))
    try:
        return int(raw)
    except ValueError:
        return default


def _choose_candidates(kind: str, builtin: str) -> List[str]:
    """Prompt for a username or password source. Returns a list."""
    print()
    click.echo(_colored(f"  [ {kind} Options ]", B_WHITE))
    click.echo(_colored(f"  1. Single {kind.lower()}", DIM))
    click.echo(_colored(f"  2. File path", DIM))
    click.echo(_colored(f"  3. Built-in list ({builtin})", DIM))
    choice = _ask(f"  Choice [1-3]: ", "3")

    if choice == "1":
        value = _ask(f"  {kind}: ")
        return [value] if value else []
    if choice == "2":
        path = _ask("  Path: ")
        try:
            return load_wordlist(path)
        except (FileNotFoundError, OSError) as exc:
            click.echo(_colored(f"  [!] {exc}", RED))
            return []
    try:
        return load_wordlist(builtin)
    except (FileNotFoundError, OSError) as exc:
        click.echo(_colored(f"  [!] {exc}", RED))
        return []


def _run_attack_loop(w: int) -> None:
    while True:
        try:
            sel = input(_colored(f"  Select Protocol [1-{len(PROTOCOLS)}] or 'q': ", B_GREEN)).strip()
            if sel.lower() in ("q", "quit", "exit", "back"):
                click.echo(_colored("\n  [*] Exiting KeyStrike. Goodbye!", DIM))
                break

            try:
                idx = int(sel) - 1
                if idx < 0 or idx >= len(PROTOCOLS):
                    click.echo(_colored(f"  [!] Choose 1-{len(PROTOCOLS)}", RED))
                    continue
            except ValueError:
                click.echo(_colored("  [!] Enter a number or 'q'", RED))
                continue

            proto_name, default_port_val = PROTOCOLS[idx]
            proto_label = get_protocol_name(proto_name)

            print()
            _draw_box(f" TARGET — {proto_label} ({proto_name}) ")
            print()

            target = _ask("  Target IP/Host: ")
            if not target:
                click.echo(_colored("  [!] target required", RED))
                continue

            port = _ask_int(f"  Port [{default_port_val}]: ", default_port_val)

            users: List[str] = []
            if proto_name not in USERLESS:
                users = _choose_candidates("Username", "users")
                if not users:
                    click.echo(_colored("  [!] no usernames", RED))
                    continue

            passwords = _choose_candidates("Password", "passwords")
            if not passwords:
                click.echo(_colored("  [!] no passwords", RED))
                continue

            threads = _ask_int("  Threads [16]: ", 16)
            timeout = _ask_int("  Per-attempt timeout [10]: ", 10)

            print()
            click.echo(_colored("  [ Options ]", B_WHITE))
            click.echo(_colored("  1. Stop on first hit (default)", DIM))
            click.echo(_colored("  2. Keep going, collect every valid credential", DIM))
            mode = _ask("  Choice [1-2]: ", "1")
            stop_on_first = mode != "2"

            extra = _ask("  Extra candidates (-e nsr) []: ", "")

            combo = len(users) * len(passwords) if users else len(passwords)
            print()
            _draw_box(" ATTACK SUMMARY ")
            _box_line(f"Target: {target}:{port} | {proto_label}", B_WHITE)
            _box_line(
                f"Users: {len(users) or '-'} | Passwords: {len(passwords)} | Combos: {combo}"
            )
            _box_line(f"Threads: {threads} | Timeout: {timeout}s | Stop on first: {stop_on_first}")
            _draw_box_end()
            print()

            confirm = _ask("  Start attack? [Y/n]: ", "y").lower()
            if confirm in ("n", "no"):
                click.echo(_colored("  [*] attack cancelled", DIM))
                continue

            print()
            _scan_one(
                protocol=proto_name,
                target=target,
                port=port,
                user=None,
                userlist=None,
                passwd=None,
                passlist=None,
                combo_file=None,
                extra=extra,
                threads=threads,
                timeout=timeout,
                stop_on_first=stop_on_first,
                retries=1,
                rate=0.0,
                wait=0.0,
                resume=None,
                max_blocking=None,
                expand_words=False,
                check=False,
                http=None,
                verbose=False,
                quiet=False,
            )

        except (EOFError, KeyboardInterrupt):
            print()
            click.echo(_colored("\n  [*] Exiting KeyStrike. Goodbye!", DIM))
            break


def _keyconsole() -> None:
    if engine_available():
        _loading("Loading KeyStrike engine...", 0.3)
        _loading("Registering protocol modules...", 0.3)
        _loading("KeyStrike ready", 0.3)
    else:
        click.echo(_colored("  [!] engine not built — run: hackit bruter build", RED))

    _draw_banner()
    _draw_protos()
    _run_attack_loop(_box_w())
