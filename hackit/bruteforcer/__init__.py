import os
import sys
import time
from datetime import datetime

import click
from hackit.ui import (
    _colored, B_CYAN, B_GREEN, B_MAGENTA, B_BLUE, B_WHITE, B_YELLOW,
    B_RED, WHITE, YELLOW, DIM, GREEN, RED, BLUE, CYAN, MAGENTA,
    BG_BLUE, BG_CYAN, BG_GREEN, BG_MAGENTA, BG_B_RED, BG_B_BLUE,
    BG_B_GREEN, BG_B_CYAN, BG_B_MAGENTA, BG_B_YELLOW, RESET,
)
from hackit.bruteforcer.engine import (
    get_protocol_name, get_default_port, run_bruteforce,
)

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))

PROTOCOLS = [
    ("ftp", 21), ("ssh", 22), ("telnet", 23), ("smtp", 25),
    ("http", 80), ("https", 443), ("pop3", 110), ("imap", 143),
    ("ldap", 389), ("mysql", 3306), ("rdp", 3389), ("postgresql", 5432),
    ("redis", 6379), ("smb", 445), ("snmp", 161), ("vnc", 5900),
    ("mssql", 1433), ("mqtt", 1883),
]

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


def _box_w():
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    return min(cols - 4, ART_W + 4)


def _draw_box(title, w=None):
    if w is None:
        w = _box_w()
    b = _colored(f"  ╔{'═' * IW}╗", CYAN)
    print(b)
    if title:
        print(_colored(f"  ║{title:^{IW}}║", CYAN))
        print(_colored(f"  ║{'─' * IW}║", CYAN))
    return w


def _draw_box_end(w=None):
    print(_colored(f"  ╚{'═' * IW}╝", CYAN))


def _draw_banner():
    os.system('clear')
    print(_colored(f"  ╔{'═' * IW}╗", B_RED))
    for line in ART:
        print(f"  {_colored('║', B_RED)}{_colored(line, BLUE)}{_colored('║', B_RED)}")
    sub = "Multi-Protocol Brute Force Attack System"
    print(f"  {_colored('║', B_RED)}{_colored(sub.center(IW), B_CYAN)}{_colored('║', B_RED)}")
    print(_colored(f"  ╚{'═' * IW}╝", B_RED))
    print()


def _loading(text, duration=1.5):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r  {_colored(frames[i % len(frames)], B_CYAN)} {_colored(text, DIM)}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r  {_colored('✔', B_GREEN)} {_colored(text, DIM)}" + " " * 10 + "\n")


def _proto_entry(i, name, port):
    label = get_protocol_name(name)
    return f"{_colored(f'[{i:02d}]', B_CYAN)} {_colored(f'{label:11s}', B_WHITE)} {_colored(f':{port}', DIM)}"


def _entry_vis(i, name, port):
    return f"[{i:02d}] {get_protocol_name(name):11s} :{port}"


def _draw_protos(w):
    _draw_box(" PROTOCOLS ", w)
    half = (len(PROTOCOLS) + 1) // 2
    left = PROTOCOLS[:half]
    right = PROTOCOLS[half:]

    for i in range(max(len(left), len(right))):
        inner_vis = ""
        if i < len(left):
            idx = i + 1
            inner_vis += "  " + _entry_vis(idx, left[i][0], left[i][1]) + "     "
        else:
            inner_vis += " " * 27
        if i < len(right):
            idx = half + i + 1
            inner_vis += _entry_vis(idx, right[i][0], right[i][1])

        padding = IW - len(inner_vis)

        inner_col = ""
        if i < len(left):
            idx = i + 1
            inner_col += "  " + _proto_entry(idx, left[i][0], left[i][1]) + "     "
        else:
            inner_col += " " * 27
        if i < len(right):
            idx = half + i + 1
            inner_col += _proto_entry(idx, right[i][0], right[i][1])
        inner_col += " " * padding

        print(f"  {_colored('║', CYAN)}{inner_col}{_colored('║', CYAN)}")
    _draw_box_end(w)
    print()


@click.group(invoke_without_command=True)
@click.pass_context
def bruter(ctx):
    if ctx.invoked_subcommand is None:
        _keyconsole()


@bruter.command()
def list_protocols_cmd():
    w = _box_w()
    _draw_protos(w)


@bruter.command()
@click.option('--protocol', '-P', required=True, help='Protocol')
@click.option('--target', '-t', required=True, help='Target')
@click.option('--port', '-p', type=int, default=0, help='Port')
@click.option('--user', '-u', help='Username')
@click.option('--userlist', '-U', help='Username list file')
@click.option('--pass', '-w', 'passwd', help='Password')
@click.option('--passlist', '-W', help='Password list file')
@click.option('--threads', '-T', type=int, default=16)
@click.option('--timeout', type=int, default=10)
def scan(protocol, target, port, user, userlist, passwd, passlist, threads, timeout):
    if not target:
        click.echo(_colored("  [!] --target required", RED))
        return

    users = [user] if user else []
    if userlist and os.path.exists(userlist):
        with open(userlist) as f:
            users = [l.strip() for l in f if l.strip()]
    passwords = [passwd] if passwd else []
    if passlist and os.path.exists(passlist):
        with open(passlist) as f:
            passwords = [l.strip() for l in f if l.strip()]

    if not users:
        users = ["root", "admin", "user"]
    if not passwords:
        passwords = ["admin", "123456", "password", "root"]

    click.echo(_colored(f"\n  [*] Starting {protocol.upper()} on {target}:{port or get_default_port(protocol)}", B_CYAN))
    click.echo(_colored(f"  [*] {len(users)} users x {len(passwords)} passwords = {len(users)*len(passwords)} combos", DIM))

    result = run_bruteforce(target, port, protocol, users, passwords, threads, timeout)

    if result.get("status") == "error":
        click.echo(_colored(f"  [!] {result.get('message', 'Unknown error')}", RED))
        return

    w = _box_w()
    _draw_box(f" RESULTS — {protocol.upper()} on {target} ", w)
    for line in [
        f"Total attempts: {result.get('total_attempts', '?')}",
        f"Elapsed: {result.get('elapsed', 0):.1f}s  |  Speed: {result.get('speed', '?')}",
    ]:
        print(f"  ║  {_colored(line.ljust(IW - 4), DIM)}  ║")
    _draw_box_end(w)

    found = result.get("found", [])
    if found:
        click.echo()
        _draw_box(f" CREDENTIALS FOUND: {len(found)} ", w)
        for cred in found:
            u = cred.get("username", "")
            p = cred.get("password", "")
            print(f"  ║  {_colored(f'[+] {u} : {p}'.ljust(IW - 4), B_GREEN)}  ║")
        _draw_box_end(w)
    else:
        click.echo(f"  {_colored('[-] No valid credentials found', RED)}")
    click.echo()


def _run_attack_loop(w):
    while True:
        try:
            sel = input(_colored("  Select Protocol [1-18] or 'q': ", B_GREEN)).strip()
            if sel.lower() in ('q', 'quit', 'exit', 'back'):
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
            _draw_box(f" TARGET — {proto_label} ({proto_name}) ", w)
            print()

            target = input(_colored("  Target IP/Host: ", B_CYAN)).strip()
            if not target:
                click.echo(_colored("  [!] Target required", RED))
                continue

            p_input = input(_colored(f"  Port [{default_port_val}]: ", B_CYAN)).strip()
            port = int(p_input) if p_input else default_port_val

            print()
            click.echo(_colored("  [ User Options ]", B_WHITE))
            click.echo(_colored("  1. Single username", DIM))
            click.echo(_colored("  2. Username list file", DIM))
            click.echo(_colored("  3. Default list (root, admin, user)", DIM))
            uc = input(_colored("  Choice [1-3]: ", B_GREEN)).strip() or "3"

            users = []
            if uc == "1":
                u = input(_colored("  Username: ", B_CYAN)).strip()
                users = [u] if u else ["admin"]
            elif uc == "2":
                path = input(_colored("  Path to userlist: ", B_CYAN)).strip()
                if os.path.exists(path):
                    with open(path) as f:
                        users = [l.strip() for l in f if l.strip()]
                else:
                    click.echo(_colored("  [!] Not found, using defaults", YELLOW))
                    users = ["root", "admin", "user"]
            else:
                users = ["root", "admin", "user", "administrator", "test"]

            print()
            click.echo(_colored("  [ Password Options ]", B_WHITE))
            click.echo(_colored("  1. Single password", DIM))
            click.echo(_colored("  2. Password list file", DIM))
            click.echo(_colored("  3. Default list", DIM))
            pc = input(_colored("  Choice [1-3]: ", B_GREEN)).strip() or "3"

            passwords = []
            if pc == "1":
                p = input(_colored("  Password: ", B_CYAN)).strip()
                passwords = [p] if p else ["password"]
            elif pc == "2":
                path = input(_colored("  Path to passlist: ", B_CYAN)).strip()
                if os.path.exists(path):
                    with open(path) as f:
                        passwords = [l.strip() for l in f if l.strip()]
                else:
                    click.echo(_colored("  [!] Not found, using defaults", YELLOW))
                    passwords = ["admin", "123456", "password", "root", "12345"]
            else:
                passwords = ["admin", "123456", "password", "root", "12345", "toor", "qwerty"]

            t_input = input(_colored("  Threads [16]: ", B_CYAN)).strip()
            threads = int(t_input) if t_input else 16

            combo = len(users) * len(passwords)
            print()
            _draw_box(" ATTACK SUMMARY ", w)
            print(f"  ║  {_colored(f'Target: {target}:{port} | {proto_label}'.ljust(IW - 4), B_WHITE)}  ║")
            print(f"  ║  {_colored(f'Users: {len(users)} | Passwords: {len(passwords)} | Combos: {combo}'.ljust(IW - 4), DIM)}  ║")
            _draw_box_end(w)
            print()

            confirm = input(_colored("  Start attack? [Y/n]: ", B_YELLOW)).strip().lower()
            if confirm in ('n', 'no'):
                click.echo(_colored("  [*] Attack cancelled.", DIM))
                continue

            print()
            click.echo(_colored(f"  [*] Launching {proto_label} on {target}:{port}...", B_CYAN))
            print()

            result = run_bruteforce(target, port, proto_name, users, passwords, threads,
                                    prefer_rust=proto_name != "rdp")

            print()
            if result.get("status") == "error":
                click.echo(_colored(f"  [!] {result.get('message', 'Error')}", RED))
            else:
                total = result.get("total_attempts", combo)
                elapsed = result.get("elapsed", 0)
                speed = result.get("speed", "?")
                found = result.get("found", [])

                _draw_box(f" RESULTS — {proto_label} ", w)
                info = f"Attempts: {total}  |  Time: {elapsed:.1f}s  |  Speed: {speed}  |  Found: {len(found)}"
                print(f"  ║  {_colored(info.ljust(IW - 4), DIM)}  ║")
                if found:
                    for cred in found:
                        u = cred.get("username", "")
                        p = cred.get("password", "")
                        print(f"  ║  {_colored(f'[+] {u} : {p}'.ljust(IW - 4), B_GREEN)}  ║")
                else:
                    print(f"  ║  {_colored('No valid credentials found'.ljust(IW - 4), RED)}  ║")
                _draw_box_end(w)

                hydra_out = result.get("hydra_output", "")
                if hydra_out:
                    print()
                    click.echo(_colored("  [ Hydra log ]", DIM))
                    for hl in hydra_out.split('\n'):
                        if hl.strip():
                            click.echo(_colored(f"  {hl.strip()}", DIM))
                print()

        except (EOFError, KeyboardInterrupt):
            print()
            click.echo(_colored("\n  [*] Exiting KeyStrike. Goodbye!", DIM))
            break


def _keyconsole():
    _loading("Initializing KeyStrike engine...", 0.3)
    _loading("Loading protocol modules...", 0.3)
    _loading("Connecting to system tools (Hydra)...", 0.3)
    _loading("KeyStrike ready", 0.3)

    _draw_banner()
    w = _box_w()
    _draw_protos(w)
    _run_attack_loop(w)
