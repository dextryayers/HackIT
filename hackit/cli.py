#!/usr/bin/env python3
"""
HackIt - Security Testing CLI Tool Suite
Main CLI interface combining all tools
"""
import click
import sys
import os

from hackit.header_audit import check as check_headers
from hackit.dir_finder import dirfinder as expert_dir_finder
from hackit.subdomain import enumerate as scan_subdomains
from hackit.network_scanner import scan_range
from hackit.tech_hunter import detect as detect_tech
from hackit.ssl_tool import scan_ssl as analyze_ssl
from hackit.web_fuzzer import fuzzer as industrial_fuzzer

from hackit.params import fuzz_params
from hackit.xss import scan_xss
from hackit.sqli import test_sqli
from hackit.redirect import find_redirects
from hackit.js import analyze_js
from hackit.cve import check_cve
from hackit.osint import osint as osint_console
from hackit.agent import agent
from hackit.ddos import ddos as ddos_attack
from hackit.ui import display_banner, _colored, YELLOW, GREEN, B_GREEN, B_CYAN, B_WHITE, DIM, RED, MAGENTA, BLUE, CYAN, B_MAGENTA, B_RED, B_BLUE, B_YELLOW, WHITE, BG_BLUE, BG_CYAN, BG_MAGENTA
from hackit.config import load_config, save_config, set_theme, DEFAULT_CONFIG, VALID_THEMES, VALID_ACCENTS, VALID_BORDERS, VALID_PROMPTS, VALID_MASKING_LEVELS, MASKING_PROFILES, CONFIG_PATH, apply_masking_level, get_masking_info

import re as _re
import json
import shutil
import time
import textwrap
from datetime import datetime
from typing import Dict, Any, Optional

_strip_ansi = _re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

ACCENT_MAP = {
    'cyan': CYAN, 'magenta': MAGENTA, 'green': GREEN,
    'blue': BLUE, 'red': RED, 'yellow': YELLOW, 'white': B_WHITE,
}

BORDER_MAP = {
    'double':  {'tl':'╔','tr':'╗','bl':'╚','br':'╝','h':'═','v':'║'},
    'single':  {'tl':'┌','tr':'┐','bl':'└','br':'┘','h':'─','v':'│'},
    'rounded': {'tl':'╭','tr':'╮','bl':'╰','br':'╯','h':'─','v':'│'},
    'block':   {'tl':'█','tr':'█','bl':'█','br':'█','h':'█','v':'█'},
    'ascii':   {'tl':'+','tr':'+','bl':'+','br':'+','h':'-','v':'|'},
    'none':    {'tl':' ','tr':' ','bl':' ','br':' ','h':' ','v':' '},
}

PROMPT_MAP = {
    'arrow': '└─$', 'hash': '#', 'dollar': '$',
    'lambda': 'λ', 'skull': '☠', 'none': '',
}

def _vis_len(text):
    return len(_strip_ansi.sub('', str(text)))

def _truncate_ansi(text, max_vis):
    if _vis_len(text) <= max_vis:
        return text
    count = 0
    result = []
    i = 0
    while i < len(text) and count < max_vis:
        if text[i] == '\x1b':
            j = text.index('m', i) + 1 if 'm' in text[i:] else len(text)
            result.append(text[i:j])
            i = j
        else:
            result.append(text[i])
            count += 1
            i += 1
    return ''.join(result)

def _bx(line, box_w, ac, bc):
    visible = _vis_len(line)
    pad = max(0, box_w - visible)
    return f"  {_colored(bc['v'], ac)} {line}{' '*pad} {_colored(bc['v'], ac)}"

def _get_theme_preview(theme, user, host, ctx, ac):
    previews = {
        'kali':       f"{_colored('┌──(', DIM)}{_colored(user, ac)}{_colored('㉿', DIM)}{_colored(host, ac)}{_colored(')-[', DIM)}{_colored('10:00', DIM)}{_colored(']-[', DIM)}{_colored(ctx, B_MAGENTA)}{_colored(']', DIM)} {_colored('└─$', ac)}",
        'cyberpunk':  f"{_colored(user, B_CYAN)}{_colored(' ❯❯ ', B_MAGENTA)}{_colored(f'[{ctx}]', B_GREEN)}",
        'minimalist': f"{_colored(f'hackit({ctx}) > ', DIM)}",
        'retro':      f"{_colored(f'{user}@{host}:{ctx}$ ', B_GREEN)}",
        'gacor':      f"{_colored('🔥 ', YELLOW)}{_colored(f'[{user}@{host}]', B_MAGENTA)}{_colored(f' ⚙️  {ctx}', CYAN)}{_colored(' 🚀 ', B_GREEN)}",
        'powerline':  f"{_colored(f' {user} ', BG_BLUE+WHITE)}{_colored(f' {ctx} ', BG_CYAN+WHITE)}{_colored(f' 10:00 ', BG_MAGENTA+WHITE)} {_colored('❯', DIM)}",
        'modern':     f"{_colored(f'{user} ', B_CYAN)}{_colored('❯ ', B_MAGENTA)}{_colored(ctx, B_GREEN)}{_colored(' ❯ ', B_MAGENTA)}",
        'pill':       f"{_colored(f'({user}) ', BG_BLUE+WHITE)}{_colored(f'({ctx}) ', B_GREEN)} {_colored('➜', DIM)}",
        'nexus':      f"{_colored('❯❯', B_CYAN)} {_colored(f'[{user}]', B_BLUE)} {_colored(f'[{ctx}]', B_CYAN)} {_colored('>>', B_BLUE)}",
        'zinc':       f"{_colored(f'[{user}@HackIT]', B_GREEN)} {_colored('➜', WHITE)} {_colored(ctx, B_GREEN)} {_colored('➜', WHITE)}",
        'vault':      f"{_colored('[[', B_WHITE)} {_colored(f'{user}@HackIT', CYAN)} {_colored(']]', B_WHITE)} {_colored('[[', B_WHITE)} {_colored(ctx, CYAN)} {_colored(']]', B_WHITE)} {_colored('$', B_WHITE)}",
        'storm':      f"{_colored('[⚡', B_YELLOW)} {_colored(user, B_MAGENTA)} {_colored('⚡]', B_YELLOW)} {_colored(f'[{ctx}]', B_MAGENTA)} {_colored('#', B_YELLOW)}",
        'drift':      f"{_colored(f'[{user}@hackit:', CYAN)}{_colored(ctx, MAGENTA)}{_colored(']', CYAN)} {_colored('➤', B_WHITE)}",
        'pulse':      f"{_colored(f'[{user}]', B_GREEN)} {_colored('←', B_BLUE)} {_colored(f'[{ctx}]', B_GREEN)} {_colored('->', B_BLUE)} {_colored('$', B_GREEN)}",
        'slash':      f"{_colored('//', B_RED)} {_colored(user, WHITE)} {_colored('//', B_RED)} {_colored(ctx, WHITE)} {_colored('//', B_RED)} {_colored('#', WHITE)}",
    }
    return previews.get(theme, f"{_colored(user, ac)}{_colored('@', DIM)}{_colored(host, ac)} {_colored(PROMPT_MAP.get('arrow', '└─$'), B_GREEN)} {_colored('command', DIM)}")

CONFIG_PROMPT = f"{_colored('[', B_CYAN)}{_colored('config', B_WHITE)}{_colored(' ⚙️ ', YELLOW)}{_colored('HackIT', B_CYAN)}{_colored(']', B_CYAN)} {_colored('>>', B_GREEN)} "

def _show_loading_bar(stage, msg, pct, box_w, color):
    spinner = ['◢', '◣', '◤', '◥']
    sp = spinner[pct % 4]
    filled = '▓' * (pct * box_w // 100)
    empty  = '░' * (box_w - len(filled))
    bar = filled + empty
    cols = shutil.get_terminal_size().columns
    line = f"  {_colored(sp, color)} {_colored(stage, color)}  {_colored(msg, DIM)}  [{_colored(bar, DIM)}]  {_colored(f'{pct:>3}%', YELLOW)}"
    sys.stdout.write(f"\r{line}{' ' * max(0, cols - len(line))}")
    sys.stdout.flush()

def _config_entry_animation(cfg):
    os.system('clear' if os.name == 'posix' else 'cls')
    cols = shutil.get_terminal_size().columns
    box_w = min(cols - 8, 56)
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)

    stages = [
        ("INIT",    "Loading configuration module",   CYAN,    8),
        ("READ",    f"Reading config file",            BLUE,    6),
        ("VALIDATE","Validating config schema",        MAGENTA, 5),
        ("THEME",   f"Applying {cfg.get('theme','vault').upper()} theme",  GREEN,   6),
        ("READY",   "Configuration shell ready",       GREEN,   5),
    ]
    total = sum(s[3] for s in stages)
    step = 1
    for name, msg, color, steps in stages:
        for s in range(steps):
            pct = int((step / total) * 100)
            _show_loading_bar(name, msg, pct, box_w, color)
            time.sleep(0.06 + (0.03 if name == "READY" else 0.0))
            step += 1
    sys.stdout.write('\r' + ' ' * cols + '\r')
    sys.stdout.flush()
    time.sleep(0.15)

def _config_box_top(cfg, box_w):
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])
    print(f"  {_colored(bc['tl'], ac)}{_colored(bc['h']*box_w, ac)}{_colored(bc['tr'], ac)}")

def _config_box_bot(cfg, box_w):
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])
    print(f"  {_colored(bc['bl'], ac)}{_colored(bc['h']*box_w, ac)}{_colored(bc['br'], ac)}")

def _config_box_line(text, cfg, box_w):
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])
    visible = _vis_len(text)
    avail = box_w - 2
    if visible > avail:
        text = _truncate_ansi(text, avail)
        visible = avail
    pad = max(0, avail - visible)
    return f"  {_colored(bc['v'], ac)} {text}{' '*pad} {_colored(bc['v'], ac)}"

def _config_box_sep(cfg, box_w):
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])
    print(_config_box_line(f"{_colored(bc['h']*box_w, DIM)}", cfg, box_w))

def _show_config_shell_banner(cfg):
    cols = shutil.get_terminal_size().columns
    box_w = min(cols - 8, 56)
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])

    cmds_grid = [
        ("list",    "show full config"),
        ("get",     "show one key"),
        ("set",     "change a value"),
        ("theme",   "switch theme"),
        ("accent",  "set accent color"),
        ("border",  "set border style"),
        ("prompt",  "set prompt style"),
        ("masking", "set anonymity lvl"),
        ("user",    "set username"),
        ("host",    "set hostname"),
        ("reset",   "factory defaults"),
        ("export",  "save config"),
        ("import",  "load config"),
        ("help",    "command reference"),
        ("back",    "exit config shell"),
    ]
    half = (len(cmds_grid) + 1) // 2
    left = cmds_grid[:half]
    right = cmds_grid[half:]

    col_w = (box_w - 4) // 2

    print()
    _config_box_top(cfg, box_w)
    print(_config_box_line(f"  {_colored('⚙', B_WHITE)}  {_colored('C O N F I G U R A T I O N   S H E L L', B_WHITE)}", cfg, box_w))
    print(_config_box_line(f"  {_colored('Manage all HackIT preferences', DIM)}", cfg, box_w))
    _config_box_sep(cfg, box_w)
    for i in range(max(len(left), len(right))):
        lcmd, ldesc = left[i] if i < len(left) else ("", "")
        rcmd, rdesc = right[i] if i < len(right) else ("", "")
        lpart = f"{_colored('▶', GREEN)} {_colored(f'{lcmd}:', B_CYAN)} {_colored(ldesc, DIM)}" if lcmd else ""
        rpart = f"{_colored('▶', GREEN)} {_colored(f'{rcmd}:', B_CYAN)} {_colored(rdesc, DIM)}" if rcmd else ""
        lvis = _vis_len(lpart)
        need = col_w - lvis + 2
        if need < 2: need = 2
        line = f"{lpart}{' ' * need}{rpart}"
        print(_config_box_line(line, cfg, box_w))
    _config_box_bot(cfg, box_w)

def _show_config_display(cfg):
    cols = shutil.get_terminal_size().columns
    box_w = min(cols - 8, 56)
    ac = ACCENT_MAP.get(cfg.get('accent', 'cyan'), CYAN)
    bc = BORDER_MAP.get(cfg.get('border', 'double'), BORDER_MAP['double'])

    label_w = 14
    val_start = label_w + 5
    val_w = box_w - val_start - 2

    def _row(label, value, vcolor):
        ls = _colored(label.ljust(label_w), B_WHITE)
        vs = _colored(str(value)[:val_w].ljust(val_w), vcolor)
        return _config_box_line(f"{ls} {_colored('»', DIM)}  {vs}", cfg, box_w)

    print()
    _config_box_top(cfg, box_w)
    print(_config_box_line(f"  {_colored('H A C K I T   C O N F I G U R A T I O N', B_WHITE)}", cfg, box_w))
    _config_box_sep(cfg, box_w)

    for label, key, color in [
        ("Theme",  'theme',  YELLOW),
        ("User",   'user',   ac),
        ("Host",   'hostname', ac),
        ("Accent", 'accent', GREEN),
        ("Border", 'border', GREEN),
        ("Prompt", 'prompt', GREEN),
    ]:
        print(_row(label, cfg.get(key, '').upper() if isinstance(cfg.get(key, ''), str) else str(cfg.get(key, '')), color))

    _config_box_sep(cfg, box_w)

    for label, key in [
        ("Timeout",      'timeout'),
        ("Max Threads",  'max_threads'),
        ("Stealth Mode", 'stealth_mode'),
        ("Verify SSL",   'verify_ssl'),
        ("Output Format",'output_format'),
        ("Auto Report",  'auto_save_reports'),
    ]:
        print(_row(label, str(cfg.get(key, '')), DIM))

    _config_box_sep(cfg, box_w)

    minfo = get_masking_info(cfg)
    level_upper = minfo['level'].upper()
    level_color = {
        'none': RED, 'basic': YELLOW, 'medium': CYAN,
        'advanced': MAGENTA, 'expert': B_RED, 'paranoid': B_MAGENTA,
    }.get(minfo['level'], DIM)
    print(_row("Masking Level", f"{minfo['icon']}  {level_upper}", level_color))
    feat_count = minfo['feature_count']
    total_feat = minfo['total_features']
    if feat_count > 0:
        bar_filled = '█' * (feat_count * 6 // total_feat + 1)
        bar_empty  = '░' * max(0, 6 - (feat_count * 6 // total_feat + 1))
        print(_row("Active Layers", f"{bar_filled}{bar_empty}  {feat_count}/{total_feat}", GREEN))
    else:
        print(_row("Active Layers", '○  none', RED))

    delay_min, delay_max = minfo['delay_range']
    if delay_max > 0:
        print(_row("Delay Range", f"{delay_min}s — {delay_max}s / req", YELLOW))
    p_depth = minfo['proxy_depth']
    if p_depth > 0:
        print(_row("Proxy Chain", f"{p_depth}-hop chain", CYAN))
    ip_freq = minfo['ip_rotate_freq']
    if ip_freq > 0:
        print(_row("IP Rotate", f"every {ip_freq} requests", MAGENTA))

    cats = minfo['categories']
    if cats:
        cat_abbr = {"Network": "NET", "Headers": "HDR", "Privacy": "PRIV", "Evasion": "EVADE"}
        cat_labels = []
        for cn in ["Network", "Headers", "Privacy", "Evasion"]:
            if cn in cats:
                cat_labels.append(cat_abbr.get(cn, cn))
        print(_row("Categories", ' · '.join(cat_labels), GREEN))

    prov = cfg.get('ai_provider', '')
    if prov:
        model = cfg.get('ai_models', {}).get(prov, 'auto')
        _config_box_sep(cfg, box_w)
        print(_row("AI Provider", prov.upper(), MAGENTA))
        print(_row("AI Model", model, MAGENTA))

    _config_box_sep(cfg, box_w)

    preview = _get_theme_preview(cfg['theme'], cfg['user'], cfg['hostname'], 'config', ac)
    print(_config_box_line(f"{_colored('Prompt Preview', B_WHITE)} {_colored('»', DIM)}  {preview}", cfg, box_w))
    _config_box_bot(cfg, box_w)
    print()

def _show_config_help(cfg):
    cols = shutil.get_terminal_size().columns
    box_w = min(cols - 8, 56)

    cmds = [
        ("list",         "Display full configuration"),
        ("show",         "Alias for list"),
        ("get <key>",    "Show value of a single key"),
        ("set <k> <v>",  "Set a config key to a value"),
        ("theme <name>", "Switch terminal visual theme"),
        ("accent <c>",   "Set accent color"),
        ("border <s>",   "Set border style"),
        ("prompt <s>",   "Set prompt symbol"),
        ("masking <lvl>","Set masking anonymity level"),
        ("user <name>",  "Set display username"),
        ("host <name>",  "Set display hostname"),
        ("reset",        "Restore factory defaults"),
        ("export <f>",   "Export config to JSON file"),
        ("import <f>",   "Import config from JSON file"),
        ("help",         "Show this command reference"),
        ("back / exit",  "Exit configuration shell"),
    ]

    print()
    _config_box_top(cfg, box_w)
    print(_config_box_line(f"  {_colored('C O N F I G   S H E L L   C O M M A N D S', B_WHITE)}", cfg, box_w))
    _config_box_sep(cfg, box_w)
    for cmd, desc in cmds:
        print(_config_box_line(f"  {_colored(cmd.ljust(18), B_GREEN)}  {_colored(desc, DIM)}", cfg, box_w))
    _config_box_sep(cfg, box_w)
    cont_pad = ' ' * 12
    for label, items in [
        ("Themes",   ', '.join(VALID_THEMES)),
        ("Accents",  ', '.join(VALID_ACCENTS)),
        ("Borders",  ', '.join(VALID_BORDERS)),
        ("Prompts",  ', '.join(VALID_PROMPTS)),
        ("Masking",  ', '.join(VALID_MASKING_LEVELS)),
    ]:
        wrapped = textwrap.wrap(items, width=box_w - 16) if len(items) > box_w - 16 else [items]
        for idx, chunk in enumerate(wrapped):
            prefix = f"  {_colored(label.ljust(8), B_WHITE)}  " if idx == 0 else f"  {cont_pad}"
            print(_config_box_line(f"{prefix}{_colored(chunk, DIM)}", cfg, box_w))
    _config_box_bot(cfg, box_w)
    print()

def _save_and_confirm(cfg, msg):
    if save_config(cfg):
        print(f"  {_colored('✔', GREEN)}  {_colored(msg, DIM)}")
    else:
        print(f"  {_colored('✘', RED)}  {_colored('Failed to save configuration!', RED)}")

def _interactive_config_shell():
    try:
        import readline
    except ImportError:
        readline = None

    cfg = load_config()
    hist_file = os.path.join(os.path.expanduser("~"), ".hackit_config_history")
    if readline:
        try:
            if os.path.exists(hist_file):
                readline.read_history_file(hist_file)
            readline.set_history_length(500)
            def _completer(text, state):
                cmds = ['list','show','get','set','theme','accent','border','prompt','masking','user','host','reset','export','import','help','back','exit','quit','clear']
                opts = [c for c in cmds if c.startswith(text)]
                return opts[state] if state < len(opts) else None
            readline.set_completer(_completer)
            if hasattr(readline, '__doc__') and readline.__doc__ and 'libedit' in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:
            pass

    _config_entry_animation(cfg)
    _show_config_shell_banner(cfg)
    print(f"  {_colored('[*] Type', DIM)} {_colored('help', B_GREEN)} {_colored('for commands or', DIM)} {_colored('back', B_GREEN)} {_colored('to exit', DIM)}")
    print()

    while True:
        try:
            line = input(CONFIG_PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ('exit', 'quit', 'back', 'q'):
            print(f"  {_colored('[*] Exiting configuration shell.', DIM)}")
            break

        if cmd in ('help', '?'):
            _show_config_help(cfg)
            continue

        if cmd in ('list', 'show'):
            _show_config_display(cfg)
            continue

        if cmd == 'get':
            if not args:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('get <key>', B_GREEN)} {_colored('<key>', DIM)}")
                continue
            key = args[0]
            if key in cfg:
                val = cfg[key]
                if isinstance(val, dict):
                    print(f"  {_colored(key, B_WHITE)} {_colored('»', DIM)}")
                    for k, v in val.items():
                        print(f"    {_colored(k, CYAN)} {_colored(':', DIM)} {_colored(str(v)[:200], WHITE)}")
                else:
                    print(f"  {_colored(key, B_WHITE)} {_colored('»', DIM)}  {_colored(str(val), CYAN)}")
            else:
                print(f"  {_colored('Key not found:', RED)} {_colored(key, B_YELLOW)}")
            continue

        if cmd == 'set':
            if len(args) < 2:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('set <key> <value>', B_GREEN)}")
                continue
            key = args[0]
            value_str = ' '.join(args[1:])
            value = value_str
            if key == 'masking_level':
                if value_str.lower() not in VALID_MASKING_LEVELS:
                    print(f"  {_colored('Invalid masking level:', RED)} {value_str}")
                    print(f"  {_colored('Valid:', DIM)} {', '.join(VALID_MASKING_LEVELS)}")
                    continue
                cfg = apply_masking_level(cfg, value_str.lower())
                _save_and_confirm(cfg, f"Masking level set to {cfg['masking_level'].upper()} ({len([v for v in MASKING_PROFILES[cfg['masking_level']].values() if v])} layers active)")
                continue
            if key in ('timeout', 'ai_timeout', 'ai_temperature', 'request_delay_min', 'request_delay_max'):
                try: value = float(value_str)
                except: print(f"  {_colored('Invalid number:', RED)} {value_str}"); continue
            elif key in ('max_threads', 'history_size', 'ai_max_tokens', 'proxy_chain_depth', 'ip_rotation_freq'):
                try: value = int(value_str)
                except: print(f"  {_colored('Invalid integer:', RED)} {value_str}"); continue
            elif key in ('stealth_mode', 'verify_ssl', 'auto_save_reports', 'notifications_enabled', 'auto_update_check', 'randomize_ua', 'randomize_fingerprint', 'proxy_rotation', 'dns_leak_protection', 'timing_jitter', 'header_randomization', 'request_padding', 'tor_enabled', 'mac_spoofing', 'tls_fingerprint', 'ip_rotation', 'dns_over_https', 'tor_stream_isolation', 'cache_busting', 'referer_spoofing', 'session_isolation', 'adaptive_delays', 'http2_disable', 'packet_fragmentation', 'decoy_traffic', 'notifications_enabled', 'auto_update_check'):
                value = value_str.lower() in ('true', '1', 'yes', 'on')
            cfg[key] = value
            _save_and_confirm(cfg, f"Set {key} = {value_str}")
            continue

        if cmd == 'theme':
            if not args or args[0].lower() not in VALID_THEMES:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('theme <name>', B_GREEN)}")
                print(f"  {_colored('Options:', DIM)} {', '.join(VALID_THEMES)}")
                continue
            cfg['theme'] = args[0].lower()
            _save_and_confirm(cfg, f"Theme changed to {cfg['theme'].upper()}")

        elif cmd == 'accent':
            if not args or args[0].lower() not in VALID_ACCENTS:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('accent <color>', B_GREEN)}")
                print(f"  {_colored('Options:', DIM)} {', '.join(VALID_ACCENTS)}")
                continue
            cfg['accent'] = args[0].lower()
            _save_and_confirm(cfg, f"Accent set to {cfg['accent'].upper()}")

        elif cmd == 'border':
            if not args or args[0].lower() not in VALID_BORDERS:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('border <style>', B_GREEN)}")
                print(f"  {_colored('Options:', DIM)} {', '.join(VALID_BORDERS)}")
                continue
            cfg['border'] = args[0].lower()
            _save_and_confirm(cfg, f"Border set to {cfg['border'].upper()}")

        elif cmd == 'prompt':
            if not args or args[0].lower() not in VALID_PROMPTS:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('prompt <style>', B_GREEN)}")
                print(f"  {_colored('Options:', DIM)} {', '.join(VALID_PROMPTS)}")
                continue
            cfg['prompt'] = args[0].lower()
            _save_and_confirm(cfg, f"Prompt set to {cfg['prompt'].upper()}")

        elif cmd == 'masking':
            if not args or args[0].lower() not in VALID_MASKING_LEVELS:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('masking <level>', B_GREEN)}")
                print(f"  {_colored('Levels:', DIM)}")
                for lvl in VALID_MASKING_LEVELS:
                    prof = MASKING_PROFILES[lvl]
                    bool_cnt = len([k for k in prof if isinstance(prof[k], bool) and prof[k]])
                    delay = prof.get('request_delay_max', 0)
                    chain = prof.get('proxy_chain_depth', 0)
                    icon = {'none':'○','basic':'◶','medium':'◑','advanced':'◐','expert':'●','paranoid':'★'}.get(lvl, '○')
                    extra = []
                    if delay > 0: extra.append(f"delay ≤{delay}s")
                    if chain > 0: extra.append(f"chain {chain}")
                    info = f" ({bool_cnt} layers)" + (f" — {', '.join(extra)}" if extra else "")
                    print(f"    {_colored(icon, B_CYAN)}  {_colored(f'{lvl:12s}', B_WHITE)} {_colored(info, DIM)}")
                continue
            cfg = apply_masking_level(cfg, args[0].lower())
            minfo = get_masking_info(cfg)
            cat_list = ', '.join(minfo['categories'].keys())
            _save_and_confirm(cfg, f"Masking {cfg['masking_level'].upper()} ({minfo['feature_count']} layers: {cat_list})")
            continue

        elif cmd in ('user', 'username'):
            if not args:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('user <name>', B_GREEN)}")
                continue
            cfg['user'] = ' '.join(args)
            _save_and_confirm(cfg, f"Username set to {cfg['user']}")

        elif cmd in ('host', 'hostname'):
            if not args:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('host <name>', B_GREEN)}")
                continue
            cfg['hostname'] = ' '.join(args)
            _save_and_confirm(cfg, f"Hostname set to {cfg['hostname']}")

        elif cmd == 'reset':
            print(f"  {_colored('⚠', B_YELLOW)}  {_colored('Reset all settings to factory defaults?', YELLOW)}")
            try:
                confirm = input(f"  {_colored('Confirm', YELLOW)} {_colored('(y/N):', DIM)} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print(); continue
            if confirm in ('y', 'yes'):
                from hackit.config import reset_to_defaults
                cfg = reset_to_defaults()
                if cfg:
                    print(f"  {_colored('✔', GREEN)}  {_colored('All settings restored to factory defaults', DIM)}")
                else:
                    print(f"  {_colored('✘', RED)}  {_colored('Reset failed', RED)}")
            else:
                print(f"  {_colored('Reset cancelled.', DIM)}")

        elif cmd == 'export':
            export_path = ' '.join(args) if args else os.path.join(os.path.expanduser("~"), f"hackit_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            try:
                parent = os.path.dirname(export_path)
                if parent: os.makedirs(parent, exist_ok=True)
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, indent=4, ensure_ascii=False)
                print(f"  {_colored('✔', GREEN)}  {_colored('Config exported to:', DIM)} {_colored(export_path, CYAN)}")
            except Exception as e:
                print(f"  {_colored('✘', RED)}  {_colored(f'Export failed: {e}', RED)}")

        elif cmd == 'import':
            if not args:
                print(f"  {_colored('Usage:', YELLOW)} {_colored('import <filepath>', B_GREEN)}")
                continue
            import_path = ' '.join(args)
            if not os.path.exists(import_path):
                print(f"  {_colored('File not found:', RED)} {import_path}")
                continue
            try:
                with open(import_path, 'r', encoding='utf-8') as f:
                    imported = json.load(f)
                for k, v in imported.items():
                    if k in SCHEMA or k == 'ai_keys':
                        cfg[k] = v
                _save_and_confirm(cfg, f"Config imported from {import_path}")
            except Exception as e:
                print(f"  {_colored('✘', RED)}  {_colored(f'Import failed: {e}', RED)}")

        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            _show_config_shell_banner(cfg)
            print(f"  {_colored('[*] Screen cleared.', DIM)}")

        else:
            print(f"  {_colored('Unknown command:', RED)} {_colored(cmd, B_YELLOW)}")
            print(f"  {_colored('Type', DIM)} {_colored('help', B_GREEN)} {_colored('for available commands', DIM)}")

    if readline:
        try:
            readline.write_history_file(hist_file)
        except Exception:
            pass


@click.group(invoke_without_command=True)
@click.version_option(version='2.1.0', prog_name='HackIt')
@click.option('--proxy', default=None, help='[HACKIT] Proxy URL for tools (e.g., http://127.0.0.1:8080)')
@click.option('--no-verify', is_flag=True, help='[HACKIT] Disable SSL certificate verification globally')
@click.option('--no-banner', is_flag=True, help='[HACKIT] Disable startup banner')
@click.option('--verbose', is_flag=True, help='[HACKIT] Enable verbose logging (DEBUG)')
@click.pass_context
def cli(ctx, proxy, no_verify, no_banner, verbose):
    """
    🚀 HackIt - Hexa-Engine Penetration Testing Framework 🚀


    
    A professional-grade security suite for research and vulnerability assessment.
    Combines Go, Rust, C, Python, Ruby, and Lua for unmatched speed and precision.

    ⚠️ AUTHORIZED USE ONLY.

    Usage: hackit [options]
    """
    # Export chosen global settings to environment so modules can read them.
    if proxy:
        os.environ['HACKIT_PROXY'] = proxy
    # HACKIT_VERIFY: '1' or '0'
    os.environ['HACKIT_VERIFY'] = '0' if no_verify else '1'
    if no_banner:
        os.environ['HACKIT_NO_BANNER'] = '1'
    # Set global logging verbosity
    import logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    # Display a fancy banner on startup
    try:
        display_banner()
    except Exception:
        # don't fail CLI on banner errors
        pass

    # If no subcommand was provided, enter console automatically
    if ctx.invoked_subcommand is None:
        from hackit.console import start_console
        start_console(cli)
        return


# Top-level commands
cli.add_command(expert_dir_finder, name='dirfinder')

# Port Scanning
@cli.group()
def ports():
    """Port scanning tools (Nmap-Inspired Penta-Engine)"""
    pass

from hackit.port_scanner import scan_ports as nmap_scan
ports.add_command(nmap_scan, name='scan')


# HTTP/Web Tools
@cli.group()
def web():
    """Web scanning and analysis tools"""
    pass

web.add_command(check_headers, name='headers')
web.add_command(detect_tech, name='tech')
web.add_command(industrial_fuzzer, name='fuzz')
web.add_command(analyze_js, name='js')
web.add_command(fuzz_params, name='params')

import importlib
run_bypass_cli = importlib.import_module("hackit.403bypass").run_bypass_cli
web.add_command(run_bypass_cli, name='403bypass')


# Vulnerability Scanners
@cli.group()
def vuln():
    """Vulnerability scanning tools"""
    pass

vuln.add_command(scan_xss, name='xss')
vuln.add_command(test_sqli, name='sqli')
vuln.add_command(find_redirects, name='redirect')

from hackit.rce_modul import rce_command
vuln.add_command(rce_command, name='rce')

from hackit.atomix import atomix_command
vuln.add_command(atomix_command, name='atomix')


# Recon Tools
@cli.group()
def recon():
    """Reconnaissance tools"""
    pass

recon.add_command(scan_subdomains, name='subdomains')
recon.add_command(scan_range, name='ips')
recon.add_command(detect_tech, name='tech-hunter')
recon.add_command(osint_console, name='osint')
cli.add_command(osint_console, name='osint')


# SSL/TLS Tools
@cli.group()
def ssl():
    """SSL/TLS analysis tools"""
    pass

ssl.add_command(analyze_ssl, name='check')


# DDoS Tools
cli.add_command(ddos_attack, name='ddos')

# BruteForce Tools
from hackit.bruteforcer import bruter as bruter_cmd
cli.add_command(bruter_cmd, name='bruter')

# Utility Tools
@cli.group()
def util():
    """Utility and analysis tools"""
    pass

util.add_command(check_cve, name='cve')
cli.add_command(agent, name='agent')

# Wireless Tools
@cli.command()
def wireless():
    """Launch the Interactive Wireless Penetration Console"""
    from hackit.wireless.console import start_wireless_console
    start_wireless_console()

@cli.command()
def whoami():
    """Display the current system user info"""
    import getpass
    import platform
    user = getpass.getuser()
    system = platform.system()
    node = platform.node()
    click.echo(_colored("\n  [ USER IDENTITY ]", B_CYAN))
    click.echo(f"  • User     : " + _colored(user, B_GREEN))
    click.echo(f"  • Device   : " + _colored(node, B_GREEN))
    click.echo(f"  • Platform : " + _colored(system, YELLOW))
    click.echo()

@cli.command()
def banner():
    """Display the main HackIt banner"""
    from hackit.ui import display_banner
    # We clear the environment flag temporarily to ensure it prints
    old_flag = os.environ.get('HACKIT_NO_BANNER')
    if 'HACKIT_NO_BANNER' in os.environ:
        del os.environ['HACKIT_NO_BANNER']
    
    display_banner(force=True)
    
    # Restore the flag if it was there
    if old_flag:
        os.environ['HACKIT_NO_BANNER'] = old_flag


# Example usage command
@cli.command()
def examples():
    """Show usage examples"""
    examples_text = """
    EXAMPLES:
    • Ports:    $ hackit ports scan -p 80,443 --targets example.com
    • Recon:    $ hackit recon subdomains -d target.com
    • OSINT:    $ hackit recon osint
    • Web:      $ hackit web headers --url https://example.com
    • Web UI:   $ hackit run                 # Launch web dashboard
    • Web UI:   $ hackit run --dev           # Dev mode with live-reload
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --dbs
    • Vuln:     $ hackit vuln sqli --url "http://site.com?id=1" --dump-all
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" scan
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" crawl --mode full
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" extract --technique blind
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" dump mydb users
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" readfile --file /etc/passwd
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" exec --cmd "id"
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" network --target 10.0.0.1
    • Vuln:     $ hackit vuln sqli -u "http://site.com?id=1" bypass --user admin
    • Vuln:     $ hackit vuln rce -u "http://site.com?cmd=ls" --detect
    • Vuln:     $ hackit vuln rce -u "http://site.com?cmd=ls" -c "whoami" --exploit
    • Vuln:     $ hackit vuln atomix -u "https://example.com"
    • Vuln:     $ hackit vuln atomix -u "https://example.com" --severity critical
    • CVE:      $ hackit util cve --software apache --version 2.4.49
    • Wireless: $ hackit wireless sniff -i wlan0 --monitor
    • DDoS:     $ hackit ddos
    """
    click.echo(examples_text)


@cli.command()
@click.option('--theme', type=click.Choice(VALID_THEMES), help='Change terminal theme')
@click.option('--user', help='Change display username')
@click.option('--host', help='Change display hostname')
@click.option('--accent', type=click.Choice(VALID_ACCENTS), help='Set accent color')
@click.option('--border', type=click.Choice(VALID_BORDERS), help='Set border character style')
@click.option('--prompt', type=click.Choice(VALID_PROMPTS), help='Set prompt style')
@click.option('--reset', is_flag=True, help='Reset to factory defaults')
@click.pass_context
def config(ctx, theme, user, host, accent, border, prompt, reset):
    """Configure HackIT terminal CLI theme (15 modes)"""
    if any([theme, user, host, accent, border, prompt, reset]):
        cfg = load_config()
        changed = False

        if reset:
            cfg = DEFAULT_CONFIG.copy()
            save_config(cfg)
            click.echo(_colored("  [+] All settings reset to factory defaults.", B_GREEN))
            return

        if theme:
            cfg["theme"] = theme
            click.echo(_colored(f"  [+] Theme changed to: {theme.upper()}", B_GREEN))
            changed = True

        if user:
            cfg["user"] = user
            click.echo(_colored(f"  [+] Username changed to: {user}", B_CYAN))
            changed = True

        if host:
            cfg["hostname"] = host
            click.echo(_colored(f"  [+] Hostname changed to: {host}", B_CYAN))
            changed = True

        if accent:
            cfg["accent"] = accent
            click.echo(_colored(f"  [+] Accent color set to: {accent.upper()}", B_GREEN))
            changed = True

        if border:
            cfg["border"] = border
            click.echo(_colored(f"  [+] Border style set to: {border.upper()}", B_GREEN))
            changed = True

        if prompt:
            cfg["prompt"] = prompt
            click.echo(_colored(f"  [+] Prompt style set to: {prompt.upper()}", B_GREEN))
            changed = True

        if changed:
            save_config(cfg)
            click.echo(_colored("  [*] Configuration updated.", DIM))
        return

    _interactive_config_shell()


@cli.command()
def help_tools():
    """Show detailed tool information"""
    tools_text = """
    QUICK REFERENCE:
    • run           - Launch web UI dashboard (Astro + Python)
    • ports scan    - Async TCP port scanner
    • dirfinder     - Expert directory finder
    • web headers   - Security header audit
    • web tech      - Tech stack detection
    • web dirs      - Recursive directory bruteforce
    • web fuzz      - Parameter reflection fuzzer
    • web js        - JavaScript endpoint analysis
    • vuln xss      - Reflected XSS scanner (Go + Python engines)
    • vuln sqli     - SQLi scanner (997 payloads, 16 DBMS)
    • vuln redirect - Open redirect finder
    • vuln atomix   - Nuclei-style YAML template scanner
    • recon subs    - Subdomain bruteforcer
    • recon osint   - Interactive public footprint scanner
    • ssl check     - TLS/SSL certificate audit
    • util cve      - Vulnerability lookup
    • wireless sniff- Monitor mode sniffing & PCAP
    • wireless crack- High-speed dictionary attack
    • ddos         - DDoS stress testing (SYN/UDP/ACK/RST/ICMP/DNS/NTP)
    """
    click.echo(tools_text)


@cli.command()
@click.pass_context
def console(ctx):
    """Launch interactive HackIt console"""
    from hackit.console import start_console
    start_console(cli)


@cli.command()
@click.option('--dev', is_flag=True, help='Start Astro dev server (live-reload) instead of static build')
@click.option('--port', default=8080, type=int, help='Port for the web UI (default: 8080)')
@click.option('--no-open', is_flag=True, help="Don't auto-open browser")
def run(dev, port, no_open):
    """Launch the HackIT Unified Intelligence Web UI Dashboard (Astro + Python)

    Starts the full web interface on localhost with the Python/FastAPI backend
    and the Astro frontend (static build or dev server).

    Examples:

      hackit run                    # Production mode (static build)

      hackit run --dev              # Development mode (live-reload)

      hackit run --port 3000        # Custom port

    """
    import subprocess
    import os
    import sys
    import time
    import webbrowser
    from hackit.ui import B_GREEN, B_CYAN, B_YELLOW, RED, DIM
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    webui_dir = os.path.join(root_dir, 'webUI')
    webui_main = os.path.join(webui_dir, 'main.py')
    dist_dir = os.path.join(webui_dir, 'dist')
    src_dir = os.path.join(webui_dir, 'src')
    python_dir = os.path.join(webui_dir, 'python')
    
    click.echo(_colored(f"\n  {'='*54}", B_CYAN))
    click.echo(_colored(f"  >>>  HACKIT UNIFIED INTELLIGENCE WEB UI  <<<", B_CYAN))
    click.echo(_colored(f"  {'='*54}", B_CYAN))
    click.echo()
    
    if not os.path.exists(webui_main):
        click.echo(_colored(f"  [!] NOT FOUND: {webui_main}", RED))
        click.echo(_colored(f"  [!] Run this command from the HackIT root directory.", RED))
        return

    # ── 1. Check environment & install deps ──
    node_ok = False
    npm_ok = False
    try:
        subprocess.run(['node', '--version'], capture_output=True, check=True)
        node_ok = True
        subprocess.run(['npm', '--version'], capture_output=True, check=True)
        npm_ok = True
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    if not node_ok or not npm_ok:
        click.echo(_colored("  [!] Node.js/npm not found. Install Node.js to build the frontend.", B_YELLOW))
        click.echo(_colored("  [*] Attempting to start backend-only (API at /api)...", DIM))

    # ── 2. Install npm deps if missing ──
    astro_process = None
    node_modules_dir = os.path.join(webui_dir, 'node_modules')
    if node_ok and npm_ok and not os.path.exists(node_modules_dir):
        click.echo(_colored("  [*] Installing npm dependencies (npm install)...", B_YELLOW))
        try:
            result = subprocess.run(
                ['npm', 'install'],
                cwd=webui_dir,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                click.echo(_colored("  [+] npm install successful.", B_GREEN))
            else:
                click.echo(_colored(f"  [!] npm install warnings:\n{result.stderr[:300]}", B_YELLOW))
        except subprocess.TimeoutExpired:
            click.echo(_colored("  [!] npm install timed out.", RED))
        except Exception as e:
            click.echo(_colored(f"  [!] npm install failed: {e}", RED))

    # ── 3. Build or start Astro dev server ──
    if node_ok and npm_ok:
        if dev:
            click.echo(_colored("  [*] Starting Astro dev server (live-reload)...", B_GREEN))
            astro_process = subprocess.Popen(
                ['npm', 'run', 'dev', '--', '--port', str(port)],
                cwd=webui_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            click.echo(_colored(f"  [+] Astro dev server starting on http://localhost:{port}", B_CYAN))
        else:
            needs_build = not os.path.exists(dist_dir)
            if not needs_build and os.path.exists(src_dir):
                dist_index = os.path.join(dist_dir, 'index.html')
                if os.path.exists(dist_index):
                    dist_mtime = os.path.getmtime(dist_index)
                    for root, dirs, files in os.walk(src_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            if os.path.getmtime(fp) > dist_mtime:
                                needs_build = True
                                break
                        if needs_build:
                            break

            if needs_build:
                click.echo(_colored("  [*] Building Astro frontend (npm run build)...", B_YELLOW))
                try:
                    result = subprocess.run(
                        ['npm', 'run', 'build'],
                        cwd=webui_dir,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if result.returncode == 0:
                        click.echo(_colored("  [+] Frontend build successful.", B_GREEN))
                    else:
                        click.echo(_colored(f"  [!] Build failed:\n{result.stderr[:500]}", RED))
                        click.echo(_colored(f"  [!] Build stdout:\n{result.stdout[:500]}", B_YELLOW))
                except subprocess.TimeoutExpired:
                    click.echo(_colored("  [!] Frontend build timed out.", RED))
            else:
                click.echo(_colored("  [*] Frontend build is up to date.", DIM))
    else:
        click.echo(_colored("  [*] Skipping frontend build (Node.js not available).", DIM))

    # ── 3. Install Python dependencies ──
    req_file = os.path.join(python_dir, 'requirements.txt')
    if os.path.exists(req_file):
        click.echo(_colored("  [*] Checking Python dependencies...", DIM))
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '-q', '-r', req_file],
                cwd=python_dir, capture_output=True, timeout=60,
            )
        except Exception:
            pass

    # ── 4. Start Python backend ──
    click.echo(_colored(f"\n  [+] Starting Python backend on http://localhost:{port}", B_GREEN))
    click.echo(_colored(f"  [+] API endpoint: http://localhost:{port}/api", B_CYAN))
    click.echo()

    backend_env = os.environ.copy()
    if dev:
        backend_env['DEBUG_MODE'] = 'True'
    else:
        backend_env.pop('DEBUG_MODE', None)

    try:
        backend = subprocess.Popen(
            [sys.executable, 'main.py'],
            cwd=python_dir,
            env=backend_env,
        )

        # Wait for backend to start
        for i in range(10):
            time.sleep(0.5)
            if backend.poll() is not None:
                break
            try:
                import httpx
                r = httpx.get(f'http://localhost:{port}/api/ping', timeout=2)
                if r.status_code == 200:
                    click.echo(_colored(f"  [+] Backend is ready! Open your browser to:", B_GREEN))
                    click.echo(_colored(f"      http://localhost:{port}", B_CYAN))
                    click.echo()
                    if not no_open:
                        webbrowser.open(f'http://localhost:{port}')
                    break
            except Exception:
                continue

        click.echo(_colored("  [*] Press Ctrl+C to stop all services.", DIM))
        click.echo(_colored(f"  {'─'*54}", DIM))
        click.echo()

        backend.wait()

    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Shutting down services...", B_YELLOW))
    finally:
        if astro_process and astro_process.poll() is None:
            astro_process.terminate()
            try:
                astro_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                astro_process.kill()
        if backend and backend.poll() is None:
            backend.terminate()
            try:
                backend.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend.kill()
        click.echo(_colored("  [+] All services stopped. Goodbye!", B_GREEN))



if __name__ == '__main__':
    cli()
