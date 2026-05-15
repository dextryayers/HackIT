"""
User interface helpers for HackIt CLI

Provides a stylized ASCII banner and status boxes for a nicer startup UX.
"""
import os
import sys
import platform
import random
import socket
import json
import textwrap
import urllib.request
from datetime import datetime

# Force UTF-8 output on Windows to support box-drawing chars
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass

try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    pass

# ANSI colors
CSI = "\x1b["
RESET = CSI + "0m"
BOLD = CSI + "1m"
DIM = CSI + "2m"
ITALIC = CSI + "3m"
UNDERLINE = CSI + "4m"
BLINK = CSI + "5m"
REVERSE = CSI + "7m"
HIDDEN = CSI + "8m"

# Standard Colors
RED = CSI + "31m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
BLUE = CSI + "34m"
MAGENTA = CSI + "35m"
PURPLE = MAGENTA
CYAN = CSI + "36m"
WHITE = CSI + "37m"

# Bright Colors
B_RED = CSI + "91m"
B_GREEN = CSI + "92m"
B_YELLOW = CSI + "93m"
B_BLUE = CSI + "94m"
B_MAGENTA = CSI + "95m"
B_CYAN = CSI + "96m"
B_WHITE = CSI + "97m"

# Background Colors
BG_BLACK = CSI + "40m"
BG_RED = CSI + "41m"
BG_GREEN = CSI + "42m"
BG_YELLOW = CSI + "43m"
BG_BLUE = CSI + "44m"
BG_MAGENTA = CSI + "45m"
BG_CYAN = CSI + "46m"
BG_WHITE = CSI + "47m"

# Bright Background Colors
BG_B_BLACK = CSI + "100m"
BG_B_RED = CSI + "101m"
BG_B_GREEN = CSI + "102m"
BG_B_YELLOW = CSI + "103m"
BG_B_BLUE = CSI + "104m"
BG_B_MAGENTA = CSI + "105m"
BG_B_CYAN = CSI + "106m"
BG_B_WHITE = CSI + "107m"

# Collection of banners (Global)
BANNERS = [
    r"""
  _    _    _  _____  _   _  _____ __   __ _____
 | |  | |  | ||  __ \| \ | ||  ___|\\ \\ / /  ___|
 | |  | |  | || |  \/|  \| || |__   \ V /\ `--.
 | |/\| |/\| || | __ | . ` ||  __|   \ /  `--. \
 \  /\  /\  / | |_\ \| |\  || |___   | | /\__/ /
  \/  \/  \/   \____/\_| \_/\____/   \_/ \____/ 
""",
    r"""
    __  __            __   _ __ 
   / / / /___ _____  / /__(_) /_
  / /_/ / __ `/ ___/ //_/ / __/
 / __  / /_/ / /__/ ,< / / /_   
/_/ /_/\__,_/\___/_/|_/_/\__/   
""",
    r"""
[ H A C K I T ]
>> SYSTEM_OVERRIDE...
>> ACCESS_GRANTED
""",
    r"""
  _   _   ___   _____  _   __ _____  _____ 
 | | | | / _ \ /  __ \| | / /|_   _||_   _|
 | |_| |/ /_\ \| /  \/| |/ /   | |    | |  
 |  _  ||  _  || |    |    \   | |    | |  
 | | | || | | || \__/\| |\  \ _| |_   | |  
 \_| |_/\_| |_/ \____/\_| \_/ \___/   \_/  
""",
    r"""
:::    :::     :::      ::::::::  :::    ::: ::::::::::: ::::::::::: 
:+:    :+:   :+: :+:   :+:    :+: :+:   :+:      :+:         :+:     
+:+    +:+  +:+   +:+  +:+        +:+  +:+       +:+         +:+     
+#++:++#++ +#++:++#++: +#+        +#++:++        +#+         +#+     
+#+    +#+ +#+     +#+ +#+        +#+  +#+       +#+         +#+     
#+#    #+# #+#     #+# #+#    #+# #+#   #+#      #+#         #+#     
###    ### ###     ###  ########  ###    ### ###########     ###     
""",
    r"""
  _    _          _____ _  _______ _______ 
 | |  | |   /\   / ____| |/ /_   _|__   __|
 | |__| |  /  \ | |    | ' /  | |    | |   
 |  __  | / /\ \| |    |  <   | |    | |   
 | |  | |/ ____ \ |____| . \ _| |_   | |   
 |_|  |_/_/    \_\_____|_|\_\_____|  |_|   
""",
    r"""
 .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |  ____  ____  | || |      __      | || |     _______  | || |  ___  ____   | || |     _____    | || |  _________   | |
| | |_   ||   _| | || |     /  \     | || |    |_   __ \ | || | |_  ||_  _|  | || |    |_   _|   | || | |  _   _  |  | |
| |   | |__| |   | || |    / /\ \    | || |      | |__) | | || |   | |_/ /    | || |      | |     | || | |_/ | | \_|  | |
| |   |  __  |   | || |   / ____ \   | || |      |  __ /  | || |   |  __'.    | || |      | |     | || |     | |      | |
| |  _| |  | |_  | || | _/ /    \ \_ | || |     _| |  \ \_ | || |  _| |  \ \_  | || |     _| |_    | || |    _| |_     | |
| | |____||____| | || ||____|  |____|| || |    |____| |___|| || | |____||____| | || |    |_____|   | || |   |_____|    | |
| |              | || |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------' 
""",
    r"""
  )      )            (     
 /(   ( /(   (        )\ )  
(()\\  )\\())  )\\ )    (()/(  
 ((_)((_)\\  (()/( (   /(_)) 
 _((_)_((_)  /(_)))\\ (_))   
| || | \\/ / (_)) ((_)|_ _|  
| __ |>  <  / -_)(_-< | |   
|_||_/_/\_\\ \\___|/__/|___|  
""",
]

# Specific Art for Tools
TOOL_ART = {
    "PORT SCANNER": r"""
    ____             __     _____                                  
   / __ \____  _____/ /_   / ___/_________ _____  ____  ___  _____ 
  / /_/ / __ \/ ___/ __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/ 
 / ____/ /_/ / /  / /_    ___/ / /__/ /_/ / / / / / / /  __/ /     
/_/    \____/_/   \__/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/      
    """,
    "SQLI SCANNER & EXPLOITER": r"""
   __________  __    _       _____                                         
  / ___/ __ \/ /   (_)     / ___/_________ _____  ____  ___  _____       
  \__ \/ / / / /   / /      \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/       
 ___/ / /_/ / /___/ /      ___/ / /__/ /_/ / / / / / / /  __/ /           
/____/\___\_\____/_/      /____/\___/\__,_/_/ /_/_/ /_/\___/_/            
                                                                          
    [ DATABASE INJECTION & EXTRACTION ]
""",
    "XSS SCANNER": r"""
   _  __ _____ _____    _____                                  
  | |/ // ___// ___/   / ___/_________ _____  ____  ___  _____ 
  |   / \__ \ \__ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/ 
 /   | ___/ /___/ /   ___/ / /__/ /_/ / / / / / / /  __/ /     
/_/|_|/____//____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/      
""",
    "IP RANGE SCANNER": r"""
    ____  ___   __   __      __                     __      _____                                  
   /  _/ / _ \  \ \ / /___  / /________ _________  / /__   / ___/_________ _____  ____  ___  _____ 
   / /  / ___/   \ V / __ \/ __/ __/ _ `/ __/ __/ / __/    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/ 
 _/ /  / /        | / /_/ / /_/_/ / /_/ /__/ /_  /_/      ___/ / /__/ /_/ / / / / / / /  __/ /     
/___/ /_/         |_\____/\__/_/  \__,_/\__/\__/(_)      /____/\___/\__,_/_/ /_/_/ /_/\___/_/      
""",
    "SUBDOMAIN SCANNER": r"""
   _____       __         __                     _         _____                                  
  / ___/__  __/ /_  ____/ /___  ____ ___  ____ _(_)___    / ___/_________ _____  ____  ___  _____ 
  \__ \/ / / / __ \/ __  / __ \/ __ `__ \/ __ `/ / __ \   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/ 
 ___/ / /_/ / /_/ / /_/ / /_/ / / / / / / /_/ / / / / /  ___/ / /__/ /_/ / / / / / / /  __/ /     
/____/\__,_/_.___/\__,_/\____/_/ /_/ /_/\__,_/_/_/ /_/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/      
""",
    "TECH HUNTER": r"""
  _______        _       _    _             _            
 |__   __|      | |     | |  | |           | |           
    | | ___  ___| |__   | |__| |_   _ _ __ | |_ ___ _ __ 
    | |/ _ \/ __| '_ \  |  __  | | | | '_ \| __/ _ \ '__|
    | |  __/ (__| | | | | |  | | |_| | | | | ||  __/ |   
    |_|\___|\\___|_| |_| |_|  |_|\__,_|_| |_|\__\___|_|   
""",
    "WEB FUZZER": r"""
  _       __     __    ______                         
 | |     / /__  / /_  / ____/__  __________  _____    
 | | /| / / _ \/ __ \/ /_  / _ \/ ___/ _ \/ ___/    
 | |/ |/ /  __/ /_/ / __/ /  __/ /  /  __/ /        
 |__/|__/\___/_.___/_/    \___/_/   \___/_/         
""",
    "HEADER AUDITOR": r"""
     __  __               __              ___             ___ __            
    / / / /__  ____ _____/ /__  _____    /   | __  ______/ (_) /_____  _____
   / /_/ / _ \/ __ `/ __  / _ \/ ___/   / /| |/ / / / __  / / __/ __ \/ ___/
  / __  /  __/ /_/ / /_/ /  __/ /      / ___ / /_/ / /_/ / / /_/ /_/ / /    
 /_/ /_/\___/\__,_/\__,_/\___/_/      /_/  |_\__,_/\__,_/_/\__/\____/_/     
""",
    "REDIRECT FINDER": r"""
     ____           ___                __     ______(_)___  ____/ /__  _____
    / __ \___  ____/ (_)_________     / /_   / ____/ / __ \/ __  / _ \/ ___/
   / /_/ / _ \/ __  / / ___/ ___/    / __/  / /_  / / / / / /_/ /  __/ /    
  / _, _/  __/ /_/ / / /  / /__     / /_   / __/ / / / / / /_/ / \___/_/     
 /_/ |_|\___/\__,_/_/_/   \___/    \__/   /_/   /_/_/ /_/\__,_/\___(_)      
""",
    "CVE CHECKER": r"""
   ______     __  ______    ________              __            
  / ____/    /  |/  /   |  / ____/ /_  ___  _____/ /_____  _____
 / / ______ / /|_/ / /| | / /   / __ \/ _ \/ ___/ //_/ _ \/ ___/
/ /_/ /___// /  / / ___ |/ /___/ / / /  __/ /__/ ,< /  __/ /    
\____/    /_/  /_/_/  |_|\____/_/ /_/\___/\___/_/|_|\___/_/     
""",
    "SSL/TLS ANALYZER": r"""
   _____ _____ __       ________    _____    ___                __                     
  / ___// ___// /      /_  __/ /   / ___/   /   |  ____  ____ _/ /_  ______  ___  _____
  \__ \ \__ \/ /        / / / /    \__ \   / /| | / __ \/ __ `/ / / / /_  / / _ \/ ___/
 ___/ /___/ / /___     / / / /___ ___/ /  / ___ |/ / / / /_/ / / /_/ / / /_/  __/ /    
/____//____/_____/    /_/ /_____//____/  /_/  |_/_/ /_/\__,_/_/\__, / /___/\___/_/     
                                                              /____/                   
""",
    "AI AGENT": r"""
           .----------.
          /          / \
         /          /   \
        /__________/     \
        |          |     |
        |  O    O  |     |
        |    __    |     |   [ HackIt AI v2.1 ]
        |   |__|   |     |   [ Status: ONLINE ]
        |__________|    /
         \          \  /
          \__________\/
""",
    "JS HUNTER": r"""
      _  _____   _   _ _   _ _   _ _____ _____ _____ 
     | |/ ____| | | | | | | | \ | |_   _|  ___|  __ \
     | | (___   | |_| | | | |  \| | | | | |__ | |__) |
 _   | |\___ \  |  _  | | | | . ` | | | |  __||  _  / 
| |__| |____) | | | | | |_| | |\  |_| |_| |___| | \ \ 
 \____/|_____/  |_| |_|\___/|_| \_|_____|_____|_|  \_\
"""
}

# Alias mapping for tool names to keys
TOOL_ALIASES = {
    "SSL CHECK": "SSL/TLS ANALYZER",
    "SSL": "SSL/TLS ANALYZER",
    "CVE": "CVE CHECKER",
    "REDIRECT": "REDIRECT FINDER",
    "IPS": "IP RANGE SCANNER",
    "IP SCANNER": "IP RANGE SCANNER",
    "PORTS": "PORT SCANNER",
    "SQLI": "SQLI SCANNER & EXPLOITER",
    "XSS": "XSS SCANNER",
    "SUBDOMAINS": "SUBDOMAIN SCANNER",
    "TECH": "TECH HUNTER",
    "HEADERS": "HEADER AUDITOR",
    "DIRS": "WEB FUZZER",
    "FUZZ": "WEB FUZZER"
}

THEME_COLORS = [CYAN, MAGENTA, GREEN, BLUE, B_CYAN, B_MAGENTA, B_GREEN, B_BLUE]

QUOTES = [
    "The quieter you become, the more you are able to hear.  -- Kali Linux",
    "Security is not a product, but a process.  -- Bruce Schneier",
    "There is no patch for human stupidity.  -- Kevin Mitnick",
    "In God we trust. All others we monitor.  -- NSA",
    "Trust, but verify.  -- Ronald Reagan",
    "Hacking is not a crime, it's a skill.",
    "Knowledge is the only weapon that never runs out.",
    "Think like an attacker, defend like a fortress.",
    "Exploiting the impossible.",
    "The best defense is a good offense.",
    "Penetration testing: break it before they do.",
    "Every system has a vulnerability. Find it first.",
    "Privacy is not a crime. Surveillance is.",
    "Root access obtained. The game begins.",
    "In cybersecurity, curiosity is your greatest tool.",
]


def _colored(text: str, color: str, bold: bool = False) -> str:
    if bold:
        return f"{color}{BOLD}{text}{RESET}"
    return f"{color}{text}{RESET}"


def get_ip_info():
    """Fetch public IP and Geo location with multi-layered fallback for maximum accuracy."""
    providers = [
        ("http://ip-api.com/json/?fields=status,country,city,query", lambda d: (d.get('query'), f"{d.get('city')}, {d.get('country')}")),
        ("https://ipinfo.io/json", lambda d: (d.get('ip'), f"{d.get('city')}, {d.get('country')}")),
        ("https://ipapi.co/json/", lambda d: (d.get('ip'), f"{d.get('city')}, {d.get('country_name')}")),
        ("https://freeipapi.com/api/json", lambda d: (d.get('ipAddress'), f"{d.get('cityName')}, {d.get('countryName')}")),
    ]

    for url, parser in providers:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.loads(response.read().decode())
                ip, geo = parser(data)
                if ip and geo and 'None' not in geo and '?' not in geo:
                    # Clean up geo string
                    geo = geo.replace(', None', '').replace('Unknown, ', '')
                    return {'ip': ip, 'geo': geo}
        except Exception:
            continue

    return {'ip': 'Offline/VPN', 'geo': 'Unknown Location'}


# ─────────────────────────────────────────────────────────────────────────────
def display_banner():
    """Print a premium startup banner. Suppressed if HACKIT_NO_BANNER is set."""
    if os.environ.get('HACKIT_NO_BANNER'):
        return

    import re as _re
    _strip = _re.compile(r'\x1b\[[0-9;]*m')

    def vlen(s: str) -> int:
        """Return the VISIBLE character count (strips all ANSI codes)."""
        return len(_strip.sub('', s))

    def pad_to(s: str, width: int, fill: str = ' ') -> str:
        """Right-pad string `s` so its VISIBLE length equals `width`."""
        return s + fill * max(width - vlen(s), 0)

    def trunc_plain(s: str, maxlen: int) -> str:
        """Truncate a plain (no-ANSI) string to maxlen chars."""
        return s[:maxlen - 1] + '.' if len(s) > maxlen else s

    # ── Theme ────────────────────────────────────────────────────────────────
    now     = datetime.now()
    banner  = random.choice(BANNERS)
    mc      = random.choice([CYAN, B_CYAN, MAGENTA, B_MAGENTA, GREEN, B_GREEN])
    ac      = random.choice([YELLOW, B_YELLOW, WHITE, B_WHITE])
    quote   = random.choice(QUOTES)

    # ── Box geometry ─────────────────────────────────────────────────────────
    W      = 72
    INDENT = '  '
    IN_BAR = INDENT + _colored('║', mc)   # left border piece (Double Line)

    def hline(lc: str, rc: str, char='═'):
        print(INDENT + _colored(lc + char * W + rc, mc))

    def row(content: str):
        print(IN_BAR + pad_to(content, W) + _colored('║', mc))

    # ── Two-column cell helper ───────────────────────────────────────────────
    CELL_W = W // 2
    KW     = 13
    VW     = CELL_W - 1 - KW - 4

    def cell(key: str, val: str, vc=B_CYAN) -> str:
        val_plain = trunc_plain(val, VW)
        k   = _colored(f' {key:<{KW}}', DIM)
        sep = _colored(' » ', ac) # Stylized separator
        v   = _colored(f'{val_plain:<{VW}}', vc, bold=True)
        return k + sep + v

    def two_col(lk, lv, lc, rk, rv, rc):
        left  = cell(lk, lv, lc)
        right = cell(rk, rv, rc)
        mid   = _colored('║', DIM) # Internal divider
        row(left + mid + right)

    # ── Fetch live data ───────────────────────────────────────────────────────
    net   = get_ip_info()
    host  = socket.gethostname()
    py_v  = platform.python_version()
    os_n  = platform.system()
    pid   = os.getpid()
    dstr  = now.strftime('%Y-%m-%d')
    tstr  = now.strftime('%H:%M:%S')

    # ── Print Random Banner Art ───────────────────────────────────────────────
    print()
    print(_colored(banner, mc, bold=True))

    # ── Box top (Heavy Double Line) ──────────────────────────────────────────
    hline('╔', '╗')

    # ── Header row ────────────────────────────────────────────────────────────
    h_t1 = ' █ HACKIT OS █'
    h_t2 = f'   V2.1.0   |   SESSION: {pid:<5}'
    h_t3 = ' [ ANALYST MODE ] '
    h_vis = len(h_t1) + len(h_t2) + len(h_t3)
    h_pad = ' ' * (W - h_vis)
    header_str = (
        _colored(h_t1, mc, bold=True)
        + _colored(h_t2, ac, bold=True)
        + _colored(h_t3, DIM)
        + h_pad
    )
    row(header_str)
    hline('╠', '╣')

    # ── Made In Indonesia Row (Hardened Branding) ─────────────────────────────
    # Standardized branding row using the core row() padding engine for perfect alignment.
    f_logo = f" {RED}{BG_WHITE}▀▀▀{RESET} " 
    f_text = _colored('MADE IN INDONESIA', WHITE, bold=True)
    f_desc = _colored(' | ADVANCED SECURITY INTELLIGENCE ECOSYSTEM', DIM)
    row(f_logo + f_text + f_desc)
    hline('╠', '╣')

    # ── Info grid ────────────────────────────────────────────────────────────
    two_col('Public IP',  net['ip'],                     B_CYAN,
            'Hostname',   host,                           B_CYAN)
    two_col('Location',   net['geo'],                    B_CYAN,
            'OS / Python', f'{os_n} Py{py_v[:4]}',       B_CYAN)
    two_col('Date',        dstr,                          YELLOW,
            'Time',        tstr,                          YELLOW)
    hline('╠', '╣')

    # ── Engine Health / Tech Stack ──────────────────────────────────────────
    s_t1 = ' TECH STACK '
    s_bar = _colored('[', DIM) + _colored('■' * 5, B_GREEN) + _colored(']', DIM)
    s_t2 = ' 100% | ENGINES: Go, Rust, C++, Py, Ruby '
    s_vis = len(s_t1) + 7 + len(s_t2)
    s_pad = ' ' * (W - s_vis)
    status_str = (
        _colored(s_t1, mc, bold=True)
        + s_bar
        + _colored(s_t2, DIM)
        + s_pad
    )
    row(status_str)
    hline('╠', '╣')

    # ── Quote row ─────────────────────────────────────────────────────────────
    q_plain = trunc_plain(quote, W - 6)
    q_str   = _colored('  " ', ac, bold=True) + _colored(q_plain, DIM)
    row(q_str)

    hline('╠', '╣')

    # ── Footer row ────────────────────────────────────────────────────────────
    f_left  = '  [!] AUTHORIZED ACCESS ONLY'
    f_right = 'HACKIT SEC-SUITE  '
    f_pad   = W - len(f_left) - len(f_right)
    footer  = (
        _colored(f_left, B_RED, bold=True)
        + ' ' * max(f_pad, 1)
        + _colored(f_right, DIM)
    )
    row(footer)
    hline('╚', '╝')
    print()
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────────────────
def display_tool_banner(tool_name: str, force: bool = False):
    """Print a premium tool-specific banner."""
    if os.environ.get('HACKIT_NO_BANNER') and not force:
        return

    import re as _re
    _strip = _re.compile(r'\x1b\[[0-9;]*m')

    color  = random.choice([CYAN, B_CYAN, MAGENTA, B_MAGENTA, GREEN, B_GREEN])
    accent = random.choice([YELLOW, B_YELLOW, WHITE])
    W      = 62

    key = tool_name.upper()
    if key in TOOL_ALIASES:
        key = TOOL_ALIASES[key]

    print()
    if key in TOOL_ART:
        print(_colored(TOOL_ART[key], color, bold=True))
    else:
        title     = f'  {tool_name.upper()}  '
        pad_left  = max((W - len(title)) // 2, 0)
        pad_right = max(W - len(title) - pad_left, 0)
        print(_colored('  +' + '=' * W + '+', color))
        print(
            _colored('  |', color)
            + ' ' * pad_left
            + _colored(title, accent, bold=True)
            + ' ' * pad_right
            + _colored('|', color)
        )
        print(_colored('  +' + '=' * W + '+', color))

    now    = datetime.now().strftime('%H:%M:%S')
    left_t = '  [+] MODULE ACTIVE'
    right_t = f'{now}  '
    pad    = max(W + 4 - len(left_t) - len(right_t), 1)
    print(
        _colored(left_t, color, bold=True)
        + ' ' * pad
        + _colored(right_t, DIM)
    )
    print(_colored('  ' + '-' * (W + 2), DIM))
    print()
    sys.stdout.flush()


class TablePrinter:
    """Helper to print neat ASCII tables"""
    def __init__(self, columns, max_col_width=30):
        self.columns = columns
        self.first_row = True
        self.target_width = max(max_col_width, 20)
        self.widths = {c: max(len(c) + 4, self.target_width) for c in columns}

    def _print_border(self, left, mid, right, fill):
        parts = [fill * self.widths[c] for c in self.columns]
        print(f"        {left}{mid.join(parts)}{right}")

    def _print_row(self, row_data, bold=False):
        row_lines = []
        max_height = 1

        for i, col in enumerate(self.columns):
            val = str(row_data[i]) if i < len(row_data) else ""
            val = ''.join(c if ord(c) >= 32 else ' ' for c in val)
            val = val.replace(':::', ' ')

            width = self.widths[col]
            lines = textwrap.wrap(val, width - 2)
            if not lines:
                lines = [""]

            row_lines.append(lines)
            max_height = max(max_height, len(lines))

        for h in range(max_height):
            parts = []
            for i, col in enumerate(self.columns):
                lines = row_lines[i]
                cell_line = lines[h] if h < len(lines) else ""
                padding = self.widths[col] - len(cell_line)
                parts.append(cell_line + " " * padding)

            content = "│".join(parts)
            color = GREEN if not bold else WHITE

            if bold:
                content = f"{BOLD}{content}{RESET}"
            else:
                content = f"{color}{content}{RESET}"

            print(f"        │{content}│")

    def print_header(self):
        self._print_border("┌", "┬", "┐", "─")
        self._print_row(self.columns, bold=True)
        self._print_border("├", "┼", "┤", "─")

    def print_row(self, row):
        if not self.first_row:
            self._print_border("├", "┼", "┤", "─")
        self._print_row(row)
        self.first_row = False

    def print_footer(self):
        self._print_border("└", "┴", "┘", "─")


if __name__ == '__main__':
    display_banner()
