#!/usr/bin/env python3
"""
HackIt main entry point
"""
import sys
import time
import os
import platform

# ── Typing Animation ───────────────────────────────────────────────────────────
import re

def _typer(text, delay=0.015, end='\n'):
    # Split text into segments: ANSI codes vs visible chars
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

def welcome_animation():
    os.system('clear' if os.name == 'posix' else 'cls')

    logo_lines = [
        _('cb', f'╔{"═"*50}╗'),
        _('cb', f'║  {_("rb","HACKIT")} {_("gb","FRAMEWORK")}  {_("yb","V2.1.0")}{" "*24}║'),
        _('cb', f'╚{"═"*50}╝'),
    ]
    for line in logo_lines:
        _typer(f'  {line}', 0.003)

    _typer("")
    _typer(f"  {_('d', 'Initializing system...')}", 0.02)

    modules = [
        ("DDoS Engine", 'g'), ("Port Scanner", 'g'), ("Web Fuzzer", 'g'),
        ("SSL Analyzer", 'g'), ("SQLi Scanner", 'g'), ("XSS Engine", 'g'),
        ("OSINT Module", 'g'), ("Atomix Engine", 'g'), ("CVE Database", 'g'),
        ("Wireless Suite", 'g'), ("Web UI Server", 'g'),
    ]
    for name, color in modules:
        time.sleep(0.06)
        print(f"  {_('d', f'[{_(color, chr(10003))}]')} {_('w', name)}")

    time.sleep(0.15)
    _typer("")
    _typer(f"  {_('cb', '>>')}  {_('w', 'Welcome back, ')}{_('gb', 'Operator')}{_('w', '.')}", 0.05)
    _typer(f"  {_('cb', '>>')}  {_('y', platform.node())}{_('d', '  •  ')}{_('y', f'{platform.system()} {platform.release()}')}", 0.03)
    time.sleep(0.4)

    os.system('clear' if os.name == 'posix' else 'cls')


def cli_entry():
    import os
    no_banner = os.environ.get('HACKIT_NO_BANNER')
    if no_banner:
        from hackit.cli import cli
        cli()
        return

    # Strip --no-banner from argv if present
    argv = [a for a in sys.argv[1:] if a not in ('--no-banner',)]
    if len(argv) < len(sys.argv[1:]):
        os.environ['HACKIT_NO_BANNER'] = '1'
        from hackit.cli import cli
        cli()
        return

    # Only show welcome animation when no subcommand
    if len(sys.argv) <= 1:
        welcome_animation()
        # banner asli dari cli() akan tampil setelah ini

    from hackit.cli import cli
    cli()


if __name__ == '__main__':
    cli_entry()
