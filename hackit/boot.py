#!/usr/bin/env python3
"""
HackIt boot entry point.

Runs the original HackIt welcome/boot animation (hex loader, module self-test,
system info panel) before the Click CLI takes over. This is what `python3
main.py` used to do; the console_script entry point lives here so a bare
`hackit` shows the same boot sequence.

The animation is skipped when:
  * stdout is not a TTY (piped / redirected)
  * HACKIT_NO_BANNER is set
  * --no-banner or --json is in argv
  * any subcommand or flag is passed (bare `hackit` only)
"""
import os
import sys
import time
import platform
import re

# ── Typing Animation ───────────────────────────────────────────────────────────

def _typer(text, delay=0.015, end='\n'):
    parts = re.split(r'(\x1b\[[0-9;]*m)', text)
    for part in parts:
        if not part:
            continue
        if part.startswith('\x1b['):
            sys.stdout.write(part)
            sys.stdout.flush()
        else:
            for ch in part:
                sys.stdout.write(ch)
                sys.stdout.flush()
                time.sleep(delay)
    sys.stdout.write(end)
    sys.stdout.flush()

C = {
    'g': '\033[92m', 'r': '\033[91m', 'c': '\033[96m',
    'y': '\033[93m', 'm': '\033[95m', 'b': '\033[94m',
    'w': '\033[97m', 'd': '\033[2m', 'n': '\033[0m',
    'gb': '\033[92;1m', 'rb': '\033[91;1m', 'cb': '\033[96;1m',
    'yb': '\033[93;1m', 'mb': '\033[95;1m', 'bb': '\033[94;1m',
    'wb': '\033[97;1m',
}
def _(tag, text=''):
    c = C.get(tag, '')
    return f'{c}{text}{C["n"]}' if text else c

def _gradient(text, colors, delay=0.003, end='\n'):
    n = len(text)
    for i, ch in enumerate(text):
        idx = int(i / max(n - 1, 1) * (len(colors) - 1))
        sys.stdout.write(colors[idx] + ch + C['n'])
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)
    sys.stdout.flush()

def _progress_bar(current, total, width=26, color='cb'):
    filled = int(current / total * width)
    bar = '█' * filled + '░' * (width - filled)
    pct = int(current / total * 100)
    return f"{_(color, bar)} {_(color, f'{pct:3d}%')}"

def _pulse(tag, text, cycles=1, delay=0.06):
    """Pulse text dim↔bright."""
    dim = _('d', text)
    bright = _(tag, text)
    for c in range(cycles):
        sys.stdout.write(f'\r  {dim}')
        sys.stdout.flush()
        time.sleep(delay)
        sys.stdout.write(f'\r  {bright}')
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write('\n')
    sys.stdout.flush()

def welcome_animation():
    os.system('clear' if os.name == 'posix' else 'cls')

    # ── HACKIT ASCII art logo ──
    logo_art = [
        "    ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗",
        "    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝",
        "    ███████║███████║██║     █████╔╝ ██║   ██║   ",
        "    ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║   ",
        "    ██║  ██║██║  ██║╚██████╗██║  ██║██║   ██║   ",
        "    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ",
    ]
    for line in logo_art:
        _typer(f"{_('w', line)}", delay=0.0015)

    # ── Tagline badge ──
    _typer(f"  {_('d', '┌' + '─'*50 + '┐')}", 0.003)
    inner = f"  {_('rb', 'HACKIT')} {_('d', 'v2.1.0 •')} {_('wb', 'PENTEST FRAMEWORK')}"
    pad = 50 - sum(len(s) for s in ['  HACKIT', ' ', 'v2.1.0 •', ' ', 'PENTEST FRAMEWORK', '  '])
    _typer(f"  {_('d', '│')}{inner}{' ' * pad}{_('d', '  │')}", 0.003)
    _typer(f"  {_('d', '└' + '─'*50 + '┘')}", 0.003)
    _typer("")

    # ── Animated hex-loader ──
    hex_frames = ['◐', '◓', '◑', '◒']
    for i in range(20):
        frame = hex_frames[i % 4]
        blk = i % 8
        col = ['r', 'y', 'g', 'c', 'b', 'm'][blk % 6]
        sys.stdout.write(f"\r  {_('d', '⟫ ')}{_(col, frame)}{_('d', ' ⟪')}  {_(col, 'INITIALIZING')}{_('d', '.' * (i % 4 + 1))}{' ' * (3 - i % 4)}")
        sys.stdout.flush()
        time.sleep(0.06 + (0.04 if i > 12 else 0))
    sys.stdout.write(f"\r  {_('g', '✓')} {_('d', 'Engine live')}                        \n")
    sys.stdout.flush()

    # ── Module loader ──
    module_groups = [
        ("RECON", 'c', ["OSINT", "Port Scanner", "Subdomain", "Tech Hunter", "Network Scan"]),
        ("WEB", 'g', ["Web Fuzzer", "Dir Finder", "JS Hunter", "Header Audit", "403 Bypass"]),
        ("INJECTION", 'r', ["SQLi Engine", "XSS Engine", "RCE Exploit", "Open Redirect"]),
        ("VULN", 'm', ["CVE Scanner", "Atomix Engine", "NSE Scripts", "SSL Analyzer"]),
        ("WIRELESS", 'y', ["Deauth Attack", "Beacon Flood", "Evil Twin", "WPA Cracker", "Packet Inject"]),
        ("RESILIENCE", 'rb', ["Stress Lab", "ARP Spoof", "Anonymity Engine"]),
        ("AI", 'bb', ["AI Agent", "Swarm Scanner", "Autopilot Hunter"]),
        ("TOOLS", 'wb', ["Web UI", "Config Manager", "Console Shell"]),
    ]

    all_modules = []
    for cat_name, cat_color, mods in module_groups:
        for m in mods:
            all_modules.append((m, cat_name, cat_color))

    total = len(all_modules)
    for i, (name, cat, color) in enumerate(all_modules):
        bar = _progress_bar(i + 1, total, color=color)
        print(f"  {_(color, '◆')} {_('w', f'{name:20s}')} {_('d', f'{cat:>10s}')}  {bar}", end='')
        time.sleep(0.045)
        sys.stdout.write('\n')
        sys.stdout.flush()
    _pulse('g', f'✓  {total} modules  —  all systems nominal', cycles=2)

    time.sleep(0.15)

    # ── System info panel ──
    _typer("")
    W = 42
    _typer(f"  {_('d', '┌' + '─'*W + '┐')}", 0.003)
    rows = [
        ('OS', f'{platform.system()} {platform.release()}'),
        ('HOST', platform.node()),
        ('PYTHON', platform.python_version()),
        ('ARCH', platform.machine()),
        ('MODS', str(total)),
    ]
    for label, val in rows:
        inner = f"  {_('w', label)}   {_('c', val)}"
        pad = W - sum(len(s) for s in ['  ', label, '   ', val, '  '])
        _typer(f"  {_('d', '│')}{inner}{' ' * pad}{_('d', '  │')}", 0.003)
    _typer(f"  {_('d', '└' + '─'*W + '┘')}", 0.003)

    time.sleep(0.25)

    # ── Welcome message ──
    _typer("")
    _typer(f"  {_('rb', '▶')}  {_('wb', 'Welcome back')} {_('d', '—')} {_('gb', platform.node())} {_('d', 'is online')}", 0.035)
    _typer(f"  {_('rb', '▶')}  {_('d', 'Type')} {_('yb', ' help ')} {_('d', 'for command list')}  {_('d', '•')}  {_('yb', f'{total}')} {_('d', 'modules ready')}", 0.02)

    time.sleep(0.5)
    os.system('clear' if os.name == 'posix' else 'cls')


def cli_entry():
    no_banner = os.environ.get('HACKIT_NO_BANNER')
    if no_banner:
        from hackit.cli import cli
        cli()
        return

    # Honour the explicit --no-banner flag argv-wise before importing the CLI.
    argv = [a for a in sys.argv[1:] if a not in ('--no-banner',)]
    if len(argv) < len(sys.argv[1:]):
        os.environ['HACKIT_NO_BANNER'] = '1'
        from hackit.cli import cli
        cli()
        return

    if len(sys.argv) <= 1 and sys.stdout.isatty() and os.environ.get('TERM') != 'dumb':
        welcome_animation()

    from hackit.cli import cli
    cli()
