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
import re
import shutil
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import click

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
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
    ███████║███████║██║     █████╔╝ ██║   ██║   
    ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║   
    ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║   
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   
          [!] ADVANCED INTELLIGENCE ECOSYSTEM [!]
          [!]   AUTHORIZED PENETRATION ONLY   [!]
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
    ╔═════════════════════════════════════════════════════════╗ 
    ║ ░▒▓█  ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗ █▓▒░ ║
    ║ ░▒▓█  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝ █▓▒░ ║
    ║ ░▒▓█  ███████║███████║██║     █████╔╝ ██║   ██║    █▓▒░ ║
    ║ ░▒▓█  ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║    █▓▒░ ║
    ║ ░▒▓█  ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║    █▓▒░ ║
    ║ ░▒▓█  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝    █▓▒░ ║
    ╠═════════════════════════════════════════════════════════╣
    ║         HackIT Security Framework Toolkit  v2.1         ║
    ║        >>> Offensive · Defensive · Forensics <<<        ║
    ╚═════════════════════════════════════════════════════════╝
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
╔══════════════════════════════════════════════════════╗
║                                                      ║
║                 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄                      ║ 
║              ▄█                  █▄                  ║
║             ██   ◉    ▄▄▄▄▄   ◉   ██                 ║
║             ██        █   █       ██                 ║
║             ██        ▀▀▀▀▀       ██                 ║
║              ▀█    ╔═════════╗   █▀                  ║
║                ▀▄  ║ ▄▄▄▄▄▄ ║ ▄▀                     ║
║                  ▀ ╚═════════╝ ▀                     ║
║                     ███████████                      ║
║                     ▀▀▀▀▀▀▀▀▀▀▀                      ║
║                                                      ║
║             HACKIT AI AGENT  v2.1                    ║
║           Autonomous Swarm  •  28 Agents             ║
║                    BY: AniipID                       ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
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


_ip_cache = None

def get_ip_info():
    """Fetch public IP and Geo location with multi-layered fallback for maximum accuracy."""
    global _ip_cache
    if _ip_cache is not None:
        return _ip_cache
    providers = [
        ("http://ip-api.com/json/?fields=status,country,city,query", lambda d: (d.get('query'), f"{d.get('city')}, {d.get('country')}")),
        ("https://ipinfo.io/json", lambda d: (d.get('ip'), f"{d.get('city')}, {d.get('country')}")),
        ("https://ipapi.co/json/", lambda d: (d.get('ip'), f"{d.get('city')}, {d.get('country_name')}")),
        ("https://freeipapi.com/api/json", lambda d: (d.get('ipAddress'), f"{d.get('cityName')}, {d.get('countryName')}")),
    ]

    for url, parser in providers:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                data = json.loads(response.read().decode())
                ip, geo = parser(data)
                if ip and geo and 'None' not in geo and '?' not in geo:
                    geo = geo.replace(', None', '').replace('Unknown, ', '')
                    _ip_cache = {'ip': ip, 'geo': geo}
                    return _ip_cache
        except Exception:
            continue

    _ip_cache = {'ip': 'Offline/VPN', 'geo': 'Unknown Location'}
    return _ip_cache


def detect_wifi_adapter():
    """Detect the active Wi-Fi adapter name. Returns name or 'N/A'."""
    try:
        import subprocess
        result = subprocess.run(
            ['iwgetid'], capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            line = result.stdout.strip()
            if line:
                return line.split()[0].rstrip(':')
    except Exception:
        pass

    try:
        for iface in os.listdir('/sys/class/net'):
            wireless_dir = f'/sys/class/net/{iface}/wireless'
            if os.path.exists(wireless_dir):
                return iface
    except Exception:
        pass

    try:
        import subprocess
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'DEVICE,TYPE', 'device', 'status'],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.strip().split('\n'):
            if ':wifi' in line or ':wireless' in line:
                return line.split(':')[0]
    except Exception:
        pass

    return 'N/A'


def check_adapter_status(iface):
    """Check if a Wi-Fi adapter is connected/online/offline."""
    if iface == 'N/A':
        return 'N/A'

    try:
        import subprocess
        result = subprocess.run(
            ['iwgetid', iface, '-r'], capture_output=True, text=True, timeout=3
        )
        ssid = result.stdout.strip()
        if ssid:
            return 'CONNECT' + ' ' + ssid[:20]
    except Exception:
        pass

    try:
        state_path = f'/sys/class/net/{iface}/operstate'
        if os.path.exists(state_path):
            with open(state_path) as f:
                state = f.read().strip()
            if state == 'up':
                return 'ONLINE'
            return state.upper()
    except Exception:
        pass

    try:
        import subprocess
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'DEVICE,STATE', 'device', 'status'],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.strip().split('\n'):
            parts = line.split(':')
            if parts[0] == iface and len(parts) > 1:
                state = parts[1].upper()
                return state
    except Exception:
        pass

    return 'OFFLINE'


# ── Theme-to-color mappings for creative terminal themes ──────────────────
THEME_COLORSETS = {
    'kali':       {'main': B_BLUE,   'accent': B_CYAN,    'dim': DIM,     'status': B_GREEN},
    'cyberpunk':  {'main': B_CYAN,   'accent': B_MAGENTA, 'dim': DIM,     'status': B_GREEN},
    'minimalist': {'main': B_WHITE,  'accent': DIM,       'dim': DIM,     'status': B_GREEN},
    'retro':      {'main': B_GREEN,  'accent': GREEN,     'dim': DIM,     'status': B_GREEN},
    'gacor':      {'main': B_MAGENTA,'accent': B_CYAN,    'dim': DIM,     'status': B_GREEN},
    'powerline':  {'main': B_BLUE,   'accent': YELLOW,    'dim': DIM,     'status': B_GREEN},
    'modern':     {'main': B_CYAN,   'accent': B_GREEN,   'dim': DIM,     'status': B_GREEN},
    'pill':       {'main': B_BLUE,   'accent': B_GREEN,   'dim': DIM,     'status': B_GREEN},
    'nexus':      {'main': B_CYAN,   'accent': B_BLUE,    'dim': DIM,     'status': B_GREEN},
    'zinc':       {'main': B_GREEN,  'accent': WHITE,     'dim': DIM,     'status': B_GREEN},
    'vault':      {'main': B_WHITE,  'accent': B_CYAN,    'dim': DIM,     'status': B_GREEN},
    'storm':      {'main': B_YELLOW, 'accent': B_MAGENTA, 'dim': DIM,     'status': B_GREEN},
    'drift':      {'main': B_CYAN,   'accent': B_MAGENTA, 'dim': DIM,     'status': B_GREEN},
    'pulse':      {'main': B_GREEN,  'accent': B_BLUE,    'dim': DIM,     'status': B_GREEN},
    'slash':      {'main': B_RED,    'accent': WHITE,     'dim': DIM,     'status': B_GREEN},
}


def get_theme_colors():
    """Return color set for the active theme."""
    try:
        from hackit.config import load_config
        theme = load_config().get('theme', 'kali')
    except Exception:
        theme = 'kali'
    return THEME_COLORSETS.get(theme, THEME_COLORSETS['kali'])


# ─────────────────────────────────────────────────────────────────────────────
def display_banner(force=False):
    """Print a premium startup banner. Suppressed if HACKIT_NO_BANNER is set unless forced."""
    if os.environ.get('HACKIT_NO_BANNER') and not force:
        return
    
    # If forced, we definitely want output
    if force:
        pass 

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
    tc      = get_theme_colors()
    mc      = tc['main']
    ac      = tc['accent']
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
    w_iface = detect_wifi_adapter()
    w_status = check_adapter_status(w_iface)

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

    # ── Wi-Fi Adapter ──────────────────────────────────────────────────────
    if w_iface != 'N/A':
        w_color = B_GREEN if w_status != 'OFFLINE' else B_RED
    else:
        w_color = DIM
    two_col('Adapter',  w_iface,  w_color,
            'Status',   w_status, w_color)
    hline('╠', '╣')

    # ── Engine Health / Tech Stack ──────────────────────────────────────────
    s_t1 = ' TECH STACK '
    s_bar = _colored('[', DIM) + _colored('■' * 5, tc['status']) + _colored(']', DIM)
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


# ─────────────────────────────────────────────────────────────────────────────
# Modern CLI help renderer
# ─────────────────────────────────────────────────────────────────────────────
# Click's default help always prints an "Options" block and a flat command
# list.  HackIt is a large framework, so help is rendered as a themed
# dashboard: header, usage, grouped commands, readable flags and a short
# "what next" footer.  The global options block is intentionally hidden on
# the main help screen.

_HELP_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_HELP_ROOT: Optional[click.Command] = None
_HELP_VERSION = "2.1.0"
_HELP_INSTALLED = False


# Compact, action-oriented copy for the help dashboard.  Docstrings stay
# available for detailed command pages; these descriptions keep the list tidy.
_HELP_DESCRIPTIONS: Dict[Tuple[str, ...], str] = {
    # Platform commands
    ("agent",): "AI-assisted security operations with autonomous hunting and swarm execution",
    ("banner",): "Render the HackIt startup banner",
    ("bruter",): "Authentication brute-force framework for multiple protocols",
    ("config",): "Configure themes, identity, colors and terminal prompt",
    ("console",): "Launch the interactive HackIt framework console",
    ("ddos",): "Authorized network stress-testing and resilience console",
    ("dirfinder",): "Discover hidden directories and files with a high-speed engine",
    ("examples",): "Show copy-ready usage examples for every tool",
    ("fetch",): "Inspect host hardware, operating system and network details",
    ("guide",): "Open the complete beginner command guide",
    ("help",): "Display help for any command or module",
    ("help-tools",): "Show a concise reference for the most-used tools",
    ("osint",): "Discover public footprints across 800+ platforms",
    ("ports",): "High-speed TCP port discovery and service analysis",
    ("recon",): "Subdomain, IP range, technology and OSINT reconnaissance",
    ("run",): "Launch the unified web dashboard (Astro + Python)",
    ("ssl",): "Analyze TLS certificates, ciphers and protocol configuration",
    ("util",): "Defensive utilities and vulnerability intelligence",
    ("vuln",): "Detect and validate web application vulnerabilities",
    ("web",): "Audit, fuzz and analyze web applications and APIs",
    ("whoami",): "Show the current user, device and platform identity",
    ("wireless",): "Wireless audit, monitoring and handshake capture console",

    # Web module
    ("web", "headers"): "Audit HTTP security headers and browser protection policies",
    ("web", "tech"): "Fingerprint servers, CMS platforms, frameworks and libraries",
    ("web", "fuzz"): "High-performance fuzzing suite for paths, parameters and discovery",
    ("web", "403bypass"): "Bypass HTTP 403 restrictions with a large payload and technique set",
    ("web", "js"): "Extract endpoints, secrets and API keys from JavaScript assets",
    ("web", "params"): "Discover hidden parameters and test them for reflection",
    ("web", "fuzz", "fast"): "Run high-speed path and parameter fuzzing",
    ("web", "fuzz", "spider"): "Harvest endpoints and parameters with a hybrid crawler",

    # Vulnerability module
    ("vuln", "xss"): "Detect reflected and stored cross-site scripting vulnerabilities",
    ("vuln", "sqli"): "SQL injection testing and database enumeration framework",
    ("vuln", "sqli", "scan"): "Run a full SQL injection assessment with DBMS fingerprinting",
    ("vuln", "sqli", "dbs"): "List databases after injection is confirmed",
    ("vuln", "sqli", "tables"): "List tables from the current database",
    ("vuln", "sqli", "columns"): "List columns for a selected database table",
    ("vuln", "sqli", "schema"): "Show table definitions and column types",
    ("vuln", "sqli", "rows"): "Count rows per table",
    ("vuln", "sqli", "dump"): "Extract rows and credentials from a database table",
    ("vuln", "sqli", "search"): "Search table and column names by keyword",
    ("vuln", "sqli", "sql"): "Run a scalar SQL query through the injection",
    ("vuln", "sqli", "extract"): "Extract data using blind, time-based or inference techniques",
    ("vuln", "sqli", "crawl"): "Crawl schema, row counts, and table data",
    ("vuln", "sqli", "readfile"): "Read files from the database server through SQL injection",
    ("vuln", "sqli", "exec"): "Execute operating-system commands through SQL injection",
    ("vuln", "sqli", "report"): "Generate a structured report from SQL injection findings",
    ("vuln", "sqli", "gui"): "Launch the graphical SQL injection testing interface",
    ("vuln", "rce"): "Detect and validate remote command execution vulnerabilities",
    ("vuln", "redirect"): "Identify open redirect vulnerabilities in URL parameters",
    ("vuln", "atomix"): "Run Nuclei-compatible YAML templates for modern vulnerability scanning",

    # Reconnaissance module
    ("recon", "subdomains"): "Enumerate subdomains with passive and active discovery",
    ("recon", "ips"): "Discover live hosts and open services across IP ranges",
    ("recon", "tech-hunter"): "Fingerprint web technologies, servers and frameworks",
    ("recon", "osint"): "Scan public footprints across social and developer platforms",

    # SSL, utilities and port scanning
    ("ssl", "check"): "Audit TLS certificates, ciphers and protocol configuration",
    ("util", "cve"): "Look up CVEs and vulnerability intelligence by software version",
    ("ports", "scan"): "Execute high-speed TCP scans with multiple strategies and profiles",

    # Brute-force module
    ("bruter", "scan"): "Brute-force logins across FTP, SSH, HTTP and other protocols",
    ("bruter", "list-protocols"): "List supported brute-force protocols and default ports",

    # AI agent
    ("agent", "chat"): "Start an interactive session with the HackIt AI assistant",
    ("agent", "autopilot"): "Run the autonomous AI bug-hunting workflow",
    ("agent", "swarm"): "Launch the 28-node autonomous reconnaissance swarm",
    ("agent", "dashboard"): "Open the real-time swarm monitoring dashboard",
    ("agent", "setting"): "Configure the AI provider, API key and model",
    ("agent", "status"): "Check AI provider configuration and connectivity",
    ("agent", "guide"): "Show the AI agent usage guide",
    ("agent", "help"): "Show AI agent commands and slash-command reference",
    ("agent", "clear"): "Clear the AI conversation history",
    ("agent", "reset"): "Reset AI configuration, keys, models or history",
}

_HELP_ROOT_CATEGORIES: List[Tuple[str, List[str]]] = [
    ("RECON & DISCOVERY", ["recon", "ports", "dirfinder", "osint"]),
    ("WEB & APPLICATION SECURITY", ["web", "vuln", "ssl", "util"]),
    ("OFFENSIVE OPERATIONS", ["bruter", "ddos", "wireless", "agent"]),
    ("WORKSPACE", ["run", "console", "config", "fetch", "whoami"]),
    ("HELP & INFORMATION", ["guide", "examples", "help-tools", "banner", "help"]),
]

_HELP_GROUP_ORDER: Dict[Tuple[str, ...], List[str]] = {
    ("web",): ["headers", "tech", "fuzz", "403bypass", "js", "params"],
    ("vuln",): ["xss", "sqli", "rce", "redirect", "atomix"],
    ("recon",): ["subdomains", "ips", "tech-hunter", "osint"],
    ("ssl",): ["check"],
    ("util",): ["cve"],
    ("ports",): ["scan"],
    ("bruter",): ["scan", "list-protocols"],
    ("agent",): [
        "chat", "autopilot", "swarm", "dashboard",
        "setting", "status", "guide", "help", "clear", "reset",
    ],
    ("web", "fuzz"): ["fast", "spider"],
    ("vuln", "sqli"): [
        "scan", "dbs", "tables", "columns", "schema", "rows", "dump",
        "search", "sql", "extract", "crawl", "readfile", "exec",
        "report", "gui",
    ],
}


def _help_vlen(text: str) -> int:
    """Visible length of a string, ignoring ANSI escape sequences."""
    return len(_HELP_ANSI_RE.sub("", str(text)))


def _help_truncate(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if _help_vlen(text) <= limit:
        return text
    plain = _HELP_ANSI_RE.sub("", text)
    if limit <= 1:
        return "…"[:limit]
    return plain[: limit - 1].rstrip() + "…"


def _help_pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _help_vlen(text))


class _HelpPalette:
    def __init__(self) -> None:
        try:
            theme = get_theme_colors()
        except Exception:
            theme = {}
        self.main = theme.get("main", B_CYAN)
        self.accent = theme.get("accent", B_GREEN)
        self.status = theme.get("status", B_GREEN)
        self.text = B_WHITE
        self.muted = DIM
        self.warn = B_YELLOW
        self.danger = B_RED


def _help_style(text: str, colour: Optional[str] = None, bold: bool = False) -> str:
    if not colour:
        return text
    if bold:
        return f"{colour}{BOLD}{text}{RESET}"
    return f"{colour}{text}{RESET}"


class _HelpScreen:
    """Line-oriented renderer with ANSI-aware alignment."""

    def __init__(self) -> None:
        try:
            columns = shutil.get_terminal_size((96, 24)).columns
        except Exception:
            columns = 96
        self.width = max(42, min(max(columns - 2, 42), 96))
        self.palette = _HelpPalette()
        self.lines: List[str] = []

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def rule(self, title: str) -> None:
        prefix = _help_style("◆ ", self.palette.accent) + _help_style(
            title.upper(), self.palette.main, bold=True
        )
        remaining = max(2, self.width - 2 - _help_vlen(prefix) - 1)
        if self.lines and self.lines[-1].strip():
            self.add("")
        self.add("  " + prefix + " " + _help_style("─" * remaining, self.palette.muted))

    def box(self, rows: Sequence[Tuple[str, Optional[str], bool]]) -> None:
        box_width = self.width - 4
        content_width = box_width - 2
        self.add("  " + _help_style("╭" + "─" * box_width + "╮", self.palette.main))
        for text, colour, bold in rows:
            chunks = textwrap.wrap(str(text), content_width) or [""]
            for chunk in chunks:
                content = _help_style(chunk, colour, bold)
                self.add(
                    "  "
                    + _help_style("│", self.palette.main)
                    + " "
                    + content
                    + " " * max(0, content_width - _help_vlen(chunk))
                    + " "
                    + _help_style("│", self.palette.main)
                )
        self.add("  " + _help_style("╰" + "─" * box_width + "╯", self.palette.main))

    def tool_header(self, path: Sequence[str], description: str) -> None:
        """Compact header used by module and command help pages."""
        bar = _help_style("▌", self.palette.accent)
        title = (
            _help_style("HACKIT", self.palette.muted)
            + _help_style("  /  ", self.palette.muted)
            + _help_style("  /  ".join(part.upper() for part in path), self.palette.main, bold=True)
        )
        self.add(bar + " " + _help_truncate(title, self.width - 4))
        width = max(20, self.width - 4)
        for line in textwrap.wrap(description or "Command reference", width=width):
            self.add(bar + " " + _help_style(line, self.palette.text))
        self.add("")

    def label(self, text: str) -> None:
        """Small section label for the compact tool help layout."""
        if self.lines and self.lines[-1].strip():
            self.add("")
        self.add(
            "  "
            + _help_style("▸ ", self.palette.accent)
            + _help_style(text, self.palette.main, bold=True)
        )

    def command_list(
        self,
        commands: Dict[str, click.Command],
        path: Tuple[str, ...],
        order: Optional[Sequence[str]] = None,
    ) -> None:
        names = [name for name in (order or []) if name in commands]
        names.extend(sorted(name for name in commands if name not in names))
        entries = [
            (name, commands[name])
            for name in names
            if not getattr(commands[name], "hidden", False)
        ]
        if not entries:
            return

        name_width = min(max(_help_vlen(name) for name, _ in entries) + 2, 19)
        for name, command in entries:
            description = _help_describe(path + (name,), command)
            shown_name = _help_truncate(name, name_width - 2)
            prefix = "    " + _help_style(
                _help_pad(shown_name, name_width), self.palette.accent, bold=True
            )
            if not description:
                self.add(prefix)
                continue

            available = max(20, self.width - 4 - name_width)
            chunks = textwrap.wrap(description, width=available) or [""]
            self.add(prefix + _help_style(chunks[0], self.palette.muted))
            for extra in chunks[1:]:
                self.add(" " * (4 + name_width) + _help_style(extra, self.palette.muted))

    def flags(self, records: Sequence[Tuple[str, str, bool]]) -> None:
        if not records:
            return
        decl_width = min(max(_help_vlen(record[0]) for record in records), 32)
        for decl, help_text, required in records:
            marker = _help_style(" *", self.palette.danger, bold=True) if required else ""
            pretty_decl = _help_style(decl, self.palette.accent) + marker
            help_text = (help_text or "").strip()

            if not help_text:
                self.add("    " + pretty_decl)
                continue

            help_width = self.width - 4 - decl_width - 2
            if decl_width <= 30 and help_width >= 26:
                chunks = textwrap.wrap(help_text, width=help_width) or [""]
                self.add(
                    "    "
                    + _help_pad(pretty_decl, decl_width + _help_vlen(marker))
                    + "  "
                    + _help_style(chunks[0], self.palette.muted)
                )
                indent = " " * (4 + decl_width + 2 + _help_vlen(marker))
                for extra in chunks[1:]:
                    self.add(indent + _help_style(extra, self.palette.muted))
            else:
                self.add("    " + pretty_decl)
                for line in textwrap.wrap(help_text, width=max(20, self.width - 8)):
                    self.add("        " + _help_style(line, self.palette.muted))

    def footer(self, tips: Sequence[str], warning: str = "") -> None:
        self.add("")
        tip_width = max(20, self.width - 6)
        for tip in tips:
            chunks = textwrap.wrap(tip, width=tip_width) or [""]
            for index, line in enumerate(chunks):
                prefix = (
                    _help_style("[i] ", self.palette.accent) if index == 0 else "    "
                )
                self.add("  " + prefix + _help_style(line, self.palette.muted))
        if warning:
            self.add("")
            width = max(20, self.width - 6)
            for index, line in enumerate(textwrap.wrap(warning, width=width)):
                prefix = _help_style("[!] ", self.palette.warn) if index == 0 else "    "
                self.add("  " + prefix + _help_style(line, self.palette.warn))

    def render(self) -> str:
        while self.lines and not self.lines[0].strip():
            self.lines.pop(0)
        while self.lines and not self.lines[-1].strip():
            self.lines.pop()
        return "\n".join(self.lines)


def _help_find_path(
    node: Optional[click.Command],
    target: click.Command,
    prefix: Tuple[str, ...] = (),
) -> Optional[Tuple[str, ...]]:
    if node is None:
        return None
    for name, child in getattr(node, "commands", {}).items():
        if child is target:
            return prefix + (name,)
        if isinstance(child, click.Group):
            found = _help_find_path(child, target, prefix + (name,))
            if found:
                return found
    return None


def _help_command_path(command: click.Command, ctx: click.Context) -> List[str]:
    """Return a display path such as ``["web", "headers"]``.

    Contexts created by the interactive console do not always have a complete
    parent chain, so fall back to a recursive search of the root command.
    """
    parts: List[str] = []
    node: Optional[click.Context] = ctx
    while node is not None:
        if node.info_name:
            parts.append(node.info_name)
        node = node.parent
    parts.reverse()

    if parts:
        first = parts[0]
        if first in ("main.py", "__main__.py", "cli"):
            parts = parts[1:]
        elif first != "hackit" and (
            _HELP_ROOT is None or first not in getattr(_HELP_ROOT, "commands", {})
        ):
            parts = parts[1:]

    if command is _HELP_ROOT:
        return []

    root_commands = getattr(_HELP_ROOT, "commands", {}) if _HELP_ROOT is not None else {}
    if parts and parts[0] in root_commands:
        return parts

    found = _help_find_path(_HELP_ROOT, command) if _HELP_ROOT is not None else None
    return list(found or [])


def _help_describe(path: Tuple[str, ...], command: click.Command) -> str:
    override = _HELP_DESCRIPTIONS.get(tuple(path))
    if override:
        return override
    text = command.get_short_help_str(limit=120) or ""
    text = " ".join(text.split())
    return text.rstrip(".")


def _help_usage_line(
    command: click.Command,
    ctx: click.Context,
    path: Sequence[str],
    is_root: bool,
    is_group: bool,
) -> str:
    if is_root:
        return "hackit <command> [arguments]"
    prefix = "hackit " + " ".join(path)
    if is_group:
        return prefix + " <command> [arguments]"
    try:
        pieces = command.collect_usage_pieces(ctx)
    except Exception:
        pieces = []
    if not pieces:
        return prefix
    return prefix + " " + " ".join(pieces)


def _help_option_records(
    command: click.Command, ctx: click.Context
) -> List[Tuple[str, str, bool]]:
    records: List[Tuple[str, str, bool]] = []
    for param in getattr(command, "params", []):
        if not isinstance(param, click.Option) or getattr(param, "hidden", False):
            continue
        # Help/version are already implied by the help screen.
        if param.name in ("help", "version"):
            continue
        try:
            record = param.get_help_record(ctx)
        except Exception:
            record = None
        if not record:
            continue
        decl, help_text = record
        help_text = re.sub(r"\s*\[required\]\s*$", "", help_text or "", flags=re.I)
        records.append((decl, help_text.strip(), bool(getattr(param, "required", False))))
    return records


def render_modern_help(command: click.Command, ctx: click.Context) -> str:
    """Render a complete, themed help screen for any Click command."""
    screen = _HelpScreen()
    palette = screen.palette
    is_root = command is _HELP_ROOT
    is_group = isinstance(command, click.Group)
    path = _help_command_path(command, ctx)

    if is_root:
        screen.box(
            [
                ("◆ HACKIT  ·  v" + _HELP_VERSION, palette.main, True),
                ("Hexa-Engine Penetration Testing Framework", palette.text, True),
                (
                    "Reconnaissance, web security, exploitation, automation and reporting in one framework.",
                    palette.text,
                    False,
                ),
                (
                    "Authorized testing only. Use only on systems you own or have permission to assess.",
                    palette.warn,
                    False,
                ),
                ("Reconnaissance  ·  Web Security  ·  Exploitation  ·  Automation  ·  Reporting", palette.muted, False),
            ]
        )
        screen.rule("USAGE")
    else:
        # Module and command pages use their own compact layout: a vertical
        # accent bar, short labels and no dashboard box.
        screen.tool_header(path, _help_describe(tuple(path), command) or "Command reference")
        screen.label("Usage")

    usage = _help_usage_line(command, ctx, path, is_root, is_group)
    screen.add("    " + _help_style(usage, palette.text, bold=True))

    if is_root:
        commands = getattr(command, "commands", {})
        known: set = set()
        for title, names in _HELP_ROOT_CATEGORIES:
            selected = {name: commands[name] for name in names if name in commands}
            if not selected:
                continue
            known.update(selected)
            screen.rule(title)
            screen.command_list(selected, (), [name for name in names if name in selected])
        leftovers = {name: cmd for name, cmd in commands.items() if name not in known}
        if leftovers:
            screen.rule("OTHER COMMANDS")
            screen.command_list(leftovers, ())

        screen.footer(
            ["hackit help <command>   ·   hackit guide   ·   hackit examples"],
        )
    elif is_group:
        screen.label("Commands")
        screen.command_list(
            getattr(command, "commands", {}),
            tuple(path),
            _HELP_GROUP_ORDER.get(tuple(path)),
        )
        back = "hackit help " + " ".join(path)
        screen.footer(
            [f"hackit help {(' '.join(path) + ' <command>').strip()}   ·   {back}"],
        )
    else:
        records = _help_option_records(command, ctx)
        if records:
            screen.label("Flags")
            screen.flags(records)
            if any(required for _, _, required in records):
                screen.add("")
                screen.add("    " + _help_style("* required", palette.muted))

        if path:
            parent = "hackit help " + " ".join(path[:-1]) if len(path) > 1 else "hackit help"
            screen.footer(
                [f"{parent}   ·   hackit guide   ·   hackit examples"],
            )
        else:
            screen.footer(["hackit guide   ·   hackit examples"])

    return screen.render()


def render_unknown_topic(topic: str, candidates: Iterable[str]) -> str:
    """Small, friendly error block used by the ``help`` command."""
    palette = _HelpPalette()
    names = sorted(candidates)
    import difflib

    matches = difflib.get_close_matches(topic, names, n=4, cutoff=0.45)
    lines = [
        "",
        "  "
        + _help_style("[!] ", palette.warn)
        + _help_style(f"Unknown help topic: {topic}", palette.warn),
    ]
    if matches:
        lines.append(
            "  "
            + _help_style("[i] ", palette.accent)
            + _help_style("Did you mean: " + ", ".join(matches), palette.muted)
        )
    if names:
        lines.append(
            "  "
            + _help_style("[i] ", palette.accent)
            + _help_style("Available: " + ", ".join(names), palette.muted)
        )
    lines.append(
        "  "
        + _help_style("[i] ", palette.accent)
        + _help_style("Run 'hackit help' to see the full command dashboard.", palette.muted)
    )
    lines.append("")
    return "\n".join(lines)


def install_modern_help(root: click.Command, version: str = "2.1.0") -> None:
    """Install the HackIt help renderer for every Click command in this process."""
    global _HELP_ROOT, _HELP_VERSION, _HELP_INSTALLED

    _HELP_ROOT = root
    _HELP_VERSION = version
    if _HELP_INSTALLED:
        return

    original_get_help = click.Command.get_help

    def _modern_get_help(self: click.Command, ctx: click.Context) -> str:
        try:
            return render_modern_help(self, ctx)
        except Exception:
            # Never break a command just because the cosmetic layer failed.
            return original_get_help(self, ctx)

    click.Command.get_help = _modern_get_help  # type: ignore[assignment]
    _HELP_INSTALLED = True


if __name__ == '__main__':
    display_banner()
