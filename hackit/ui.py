"""
User interface helpers for HackIt CLI

Provides a stylized ASCII banner and status boxes for a nicer startup UX.
"""
import os
import sys
import random
import socket
import json
import textwrap
import urllib.request
from datetime import datetime
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
PURPLE = MAGENTA # Alias for PURPLE
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

# Collection of banners (Global)
BANNERS = [
    # Banner 1: Standard Block
    r"""
  _    _    _  _____  _   _  _____ __   __ _____
 | |  | |  | ||  __ \| \ | ||  ___|\ \ / /  ___|
 | |  | |  | || |  \/|  \| || |__   \ V /\ `--.
 | |/\| |/\| || | __ | . ` ||  __|   \ /  `--. \
 \  /\  /\  / | |_\ \| |\  || |___   | | /\__/ /
  \/  \/  \/   \____/\_| \_/\____/   \_/ \____/ 
""",
    # Banner 2: Slant
    r"""
    __  __            __   _ __ 
   / / / /___ _____  / /__(_) /_
  / /_/ / __ `/ ___/ //_/ / __/
 / __  / /_/ / /__/ ,< / / /_   
/_/ /_/\__,_/\___/_/|_/_/\__/   
""",
    # Banner 3: Cyber
    r"""
[ H A C K I T ]
>> SYSTEM_OVERRIDE...
>> ACCESS_GRANTED
""",
    # Banner 4: Big
    r"""
  _   _   ___   _____  _   __ _____  _____ 
 | | | | / _ \ /  __ \| | / /|_   _||_   _|
 | |_| |/ /_\ \| /  \/| |/ /   | |    | |  
 |  _  ||  _  || |    |    \   | |    | |  
 | | | || | | || \__/\| |\  \ _| |_   | |  
 \_| |_/\_| |_/ \____/\_| \_/ \___/   \_/  
""",
    # Banner 5: Dots
    r"""
:::    :::     :::      ::::::::  :::    ::: ::::::::::: ::::::::::: 
:+:    :+:   :+: :+:   :+:    :+: :+:   :+:      :+:         :+:     
+:+    +:+  +:+   +:+  +:+        +:+  +:+       +:+         +:+     
+#++:++#++ +#++:++#++: +#+        +#++:++        +#+         +#+     
+#+    +#+ +#+     +#+ +#+        +#+  +#+       +#+         +#+     
#+#    #+# #+#     #+# #+#    #+# #+#   #+#      #+#         #+#     
###    ### ###     ###  ########  ###    ### ###########     ###     
""",
    # Banner 6: ANSI Shadow
    r"""
██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
███████║███████║██║     █████╔╝ ██║   ██║   
██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║   
██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   
""",
    # Banner 7: Bloody
    r"""
db   db  .d8b.   .o88b. db   dD d888888b d888888b 
88   88 d8' `8b d8P  Y8 88 ,8P'   `88'   `~~88~~' 
88ooo88 88ooo88 8P      88,8P      88       88    
88~~~88 88~~~88 8b      88`8b      88       88    
88   88 88   88 Y8b  d8 88 `88.   .88.      88    
YP   YP YP   YP  `Y88P' YP   YD Y888888P    YP    
""",
    # Banner 8: 3D
    r"""
  )      )            (     
 /(   ( /(   (        )\ )  
(()\  )\())  )\ )    (()/(  
 ((_)((_)\  (()/( (   /(_)) 
 _((_)_((_)  /(_)))\ (_))   
| || | \/ / (_)) ((_)|_ _|  
| __ |>  <  / -_)(_-< | |   
|_||_/_/\_\ \___|/__/|___|  
""",
    # Banner 9: Isometric
    r"""
      ___           ___           ___           ___           ___           ___     
     /\__\         /\  \         /\  \         /\__\         /\  \         /\  \    
    /:/  /        /::\  \       /::\  \       /:/  /         \:\  \        \:\  \   
   /:/__/        /:/\:\  \     /:/\:\  \     /:/__/           \:\  \        \:\  \  
  /::\  \ ___   /::\~\:\  \   /:/  \:\  \   /::\__\____       /::\  \       /::\  \ 
 /:/\:\  /\__\ /:/\:\ \:\__\ /:/__/ \:\__\ /:/\:::::\__\     /:/\:\__\      \/\:\__\
 \/__\:\/:/  / \/__\:\/:/  / \:\  \  \/__/ \/_|:|~~|~       /:/  \/__/       ~~/__/ 
      \::/  /       \::/  /   \:\  \          |:|  |       /:/  /                  
      /:/  /        /:/  /     \:\  \         |:|  |       \/__/                   
     /:/  /        /:/  /       \:\__\        |:|  |                               
     \/__/         \/__/         \/__/         \|__|                               
""",
    # Banner 10: Nmap-Inspired (Gacor Edition)
    r"""
    N   N  M   M   A   PPPP 
    NN  N  MM MM  A A  P   P
    N N N  M M M AAAAA PPPP 
    N  NN  M   M A   A P    
    N   N  M   M A   A P    
    [ H A C K I T - M O D ]
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
    |_|\___|\___|_| |_| |_|  |_|\__,_|_| |_|\__\___|_|   
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
    "The quieter you become, the more you are able to hear.",
    "Security is not a product, but a process.",
    "There is no patch for human stupidity.",
    "Data is the new oil.",
    "Trust, but verify.",
    "Everything is a file.",
    "Hacking is an art.",
    "Knowledge is power.",
    "We do what we must because we can.",
    "It's not a bug, it's a feature.",
    "Exploiting the impossible.",
    "Access Granted.",
    "Think like a hacker, act like a professional.",
    "In cybersecurity, the only safe system is a powered-off one.",
    "Your data is your life. Protect it."
]

def _colored(text: str, color: str, bold: bool = False) -> str:
    if bold:
        return f"{color}{BOLD}{text}{RESET}"
    return f"{color}{text}{RESET}"


def get_ip_info():
    """Fetch public IP and Geo location with fallback"""
    # 1. Try ip-api.com (Best for Geo)
    try:
        # User requested accuracy for ip-api
        with urllib.request.urlopen("http://ip-api.com/json/?fields=status,message,country,city,query,isp", timeout=5) as url:
            data = json.loads(url.read().decode())
            if data.get('status') == 'success':
                return {
                    'ip': data.get('query', 'Unknown'),
                    'geo': f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
                }
    except Exception:
        pass

    # 2. Try ipinfo.io (Very accurate)
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=5) as url:
            data = json.loads(url.read().decode())
            return {
                'ip': data.get('ip', 'Unknown'),
                'geo': f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
            }
    except Exception:
        pass

    # 3. Fallback to ipify (IP only)
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as url:
            data = json.loads(url.read().decode())
            return {
                'ip': data.get('ip', 'Unknown'),
                'geo': 'Unknown (Fallback)'
            }
    except Exception:
        pass

    return {'ip': 'Unavailable', 'geo': 'Unavailable'}


def display_banner():
    """Print a stylized startup banner and status boxes with random elements.

    Banner is suppressed if environment variable `HACKIT_NO_BANNER` is set.
    """
    if os.environ.get('HACKIT_NO_BANNER'):
        return

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Random selections
    banner = random.choice(BANNERS)
    main_color = random.choice(THEME_COLORS)
    secondary_color = random.choice([c for c in THEME_COLORS if c != main_color])
    quote = random.choice(QUOTES)
    mission_id = os.getpid()

    # Print Banner
    print(_colored(banner, main_color, bold=True))
    
    # Subtitle
    print(_colored('  PENETRATION TESTING FRAMEWORK', secondary_color) + '   ' + _colored(f'[{now}]', DIM))
    print(_colored('  By: AniippID', main_color))
    print()

    # Gather System Info
    hostname = socket.gethostname()
    net_info = get_ip_info()

    # Dynamic System Status Box (Modern Rounded)
    box_width = 64
    border_color = secondary_color
    
    # Top Border
    print(_colored('╭──', border_color) + _colored(' SYSTEM STATUS ', main_color, bold=True) + _colored('─' * (box_width - 15), border_color) + _colored('╮', border_color))
    
    status_items = [
        ("User IP", net_info['ip'], B_CYAN),
        ("Geo Location", net_info['geo'], B_CYAN),
        ("Website", "haniipp.space", B_YELLOW),
        ("Device Name", hostname, B_CYAN),
        ("Exploit Engine", "ONLINE", B_GREEN)
    ]
    
    for name, status, color in status_items:
        # Calculate label and value parts
        label_part = f"  {name:<15}"
        value_part = f": {color}{status}{RESET}"
        
        # Calculate visible length (without ANSI)
        visible_len = 2 + 15 + 2 + len(status)
        padding = box_width - visible_len + 2
        
        line = _colored('│', border_color) + label_part + value_part + ' ' * padding + _colored('│', border_color)
        print(line)

    # Bottom Border
    print(_colored('╰' + '─' * (box_width + 2) + '╯', border_color))
    print()

    # Info Line with style
    session_info = f"[+] Session: {mission_id} | User: anonim | {now}"
    print(_colored(session_info, secondary_color))
    print(_colored(f'[!] "{quote}"', B_WHITE, bold=True))
    print()
    
    # Footer
    print(_colored('─' * (box_width + 4), DIM))
    print(_colored('⚠ AUTHORIZED USE ONLY', B_RED, bold=True) + ' ' + _colored('|', DIM) + ' ' + _colored('HackIt v2.0', main_color))
    print()
    sys.stdout.flush()


def display_tool_banner(tool_name: str):
    """Print a specific banner for a tool with random colors"""
    if os.environ.get('HACKIT_NO_BANNER'):
        return
        
    color = random.choice(THEME_COLORS)
    
    # Resolve aliases
    key = tool_name.upper()
    if key in TOOL_ALIASES:
        key = TOOL_ALIASES[key]

    # Check if we have specific art for this tool
    if key in TOOL_ART:
        print()
        print(_colored(TOOL_ART[key], color, bold=True))
        print(_colored('  > AniippID', DIM))
        print()
        return

    # Modern Tool Header
    width = 60
    title = f" {tool_name.upper()} "
    padding = (width - len(title)) // 2
    
    print()
    print(_colored('╔' + '═' * width + '╗', color))
    print(_colored('║', color) + ' ' * padding + _colored(title, WHITE, bold=True) + ' ' * (width - len(title) - padding) + _colored('║', color))
    print(_colored('╚' + '═' * width + '╝', color))
    print(_colored('  > MODULE LOADED: SUCCESS', DIM))
    print()
    sys.stdout.flush()


class TablePrinter:
    """Helper to print neat ASCII tables"""
    def __init__(self, columns, max_col_width=30):
        self.columns = columns
        self.first_row = True
        # Ensure sufficient width for readability but avoid terminal overflow (min 20)
        self.target_width = max(max_col_width, 20)
        # Default widths: use target_width to allow wrapping space
        self.widths = {c: max(len(c) + 4, self.target_width) for c in columns}

    def _print_border(self, left, mid, right, fill):
        parts = [fill * self.widths[c] for c in self.columns]
        print(f"        {left}{mid.join(parts)}{right}")

    def _print_row(self, row_data, bold=False):
        # Prepare wrapped lines for each cell
        row_lines = []
        max_height = 1
        
        for i, col in enumerate(self.columns):
            val = str(row_data[i]) if i < len(row_data) else ""
            
            # Aggressive sanitization
            # 1. Strip ANSI codes from data (if any leaked)
            # 2. Replace control characters
            # 3. Replace delimiters if they leaked
            val = ''.join(c if ord(c) >= 32 else ' ' for c in val)
            val = val.replace(':::', ' ') # Safety
            
            width = self.widths[col]
            # Wrap text to fit column width (minus 2 for padding)
            lines = textwrap.wrap(val, width - 2)
            if not lines: lines = [""]
            
            row_lines.append(lines)
            max_height = max(max_height, len(lines))
            
        # Print each physical line of the row
        for h in range(max_height):
            parts = []
            for i, col in enumerate(self.columns):
                lines = row_lines[i]
                if h < len(lines):
                    cell_line = lines[h]
                else:
                    cell_line = ""
                
                # Padding
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
        # Top border
        self._print_border("┌", "┬", "┐", "─")
        # Header row
        self._print_row(self.columns, bold=True)
        # Separator
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
