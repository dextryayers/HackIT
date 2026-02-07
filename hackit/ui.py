"""
User interface helpers for HackIt CLI

Provides a stylized ASCII banner and status boxes for a nicer startup UX.
"""
from datetime import datetime
import os

# ANSI colors
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
DIM = CSI + "2m"
RED = CSI + "31m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
BLUE = CSI + "34m"
MAGENTA = CSI + "35m"
CYAN = CSI + "36m"
WHITE = CSI + "37m"


def _colored(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def display_banner():
    """Print a stylized startup banner and status boxes.

    Banner is suppressed if environment variable `HACKIT_NO_BANNER` is set.
    """
    if os.environ.get('HACKIT_NO_BANNER'):
        return

    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')

    # Improved large title
    title = r"""
  _    _    _  _____  _   _  _____ __   __ _____
 | |  | |  | ||  __ \| \ | ||  ___|\ \ / /  ___|
 | |  | |  | || |  \/|  \| || |__   \ V /\ `--.
 | |/\| |/\| || | __ | . ` ||  __|   \ /  `--. \
 \  /\  /\  / | |_\ \| |\  || |___   | | /\__/ /
  \/  \/  \/   \____/\_| \_/\____/   \_/ \____/ 
"""

    print(_colored(title, MAGENTA))
    print(_colored('  PENETRATION TESTING FRAMEWORK', CYAN) + '   ' + _colored(f'[{now}]', DIM))
    print(_colored('  By: AniippID', YELLOW))
    print()

    # System status box
    print(_colored('┌' + '─' * 70 + '┐', BLUE))
    print(_colored('│', BLUE) + ' System Status'.ljust(70) + _colored('│', BLUE))
    print(_colored('├' + '─' * 70 + '┤', BLUE))
    print(_colored('│', BLUE) + f' Exploit Engine : ' + _colored('ONLINE', GREEN) + ' ' * 44 + _colored('│', BLUE))
    print(_colored('│', BLUE) + f' Scanner Array   : ' + _colored('ONLINE', GREEN) + ' ' * 44 + _colored('│', BLUE))
    print(_colored('│', BLUE) + f' CVE Database    : ' + _colored('SYNCED', GREEN) + ' ' * 45 + _colored('│', BLUE))
    print(_colored('│', BLUE) + f' Neural Core     : ' + _colored('OPERATIONAL', GREEN) + ' ' * 41 + _colored('│', BLUE))
    print(_colored('└' + '─' * 70 + '┘', BLUE))
    print()

    # Phases
    print(_colored('[PHASE 1] ', YELLOW) + _colored('Initializing attack sequence...', WHITE))
    print(_colored('[✓] Mission ID: 8 | Status: ', CYAN) + _colored('ACTIVE', GREEN))
    print()

    print(_colored('[PHASE 2] ', YELLOW) + _colored('Network reconnaissance in progress...', WHITE))
    print(_colored('─' * 40, DIM))
    print()

    # Footer note
    print(_colored('⚠ FOR AUTHORIZED OPS & TRAINING ONLY', RED) + ' ' + _colored('|', DIM) + ' ' + _colored('By: AniippID', MAGENTA))
    print()


if __name__ == '__main__':
    display_banner()
