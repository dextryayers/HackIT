"""
╔═══════════════════════════════════════════════════════════════════╗
║  HackIT PortStorm v3.0 — Polyglot Ultra-Power Scanner            ║
║  Engines: Go · Rust · C · C++ · Lua                               ║
╚═══════════════════════════════════════════════════════════════════╝
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import click
import json
import os
import random
import sys
import time as _time
import re as _re
from datetime import datetime
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, BLUE, CYAN, PURPLE, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM
from .go_bridge import get_engine
from .targets import parse_targets, parse_ports
from hackit.subdomain.go_bridge import get_engine as get_sub_engine

# ─────────────────────────────────────────────────────────────────
# UTILITY HELPERS
# ─────────────────────────────────────────────────────────────────

def pad_v(text, width, fill=' '):
    """Pad text to visible width, ignoring ANSI codes."""
    ansi_escape = _re.compile(r'\x1b\[[0-9;]*m')
    visible_len = len(ansi_escape.sub('', str(text)))
    return str(text) + (fill * max(0, width - visible_len))

def trunc_v(text, max_len):
    """Truncate text based on visible length."""
    ansi_escape = _re.compile(r'\x1b\[[0-9;]*m')
    visible_text = ansi_escape.sub('', str(text))
    if len(visible_text) <= max_len:
        return text
    return visible_text[:max_len-3] + "..."

def _vis_len(text):
    ansi_escape = _re.compile(r'\x1b\[[0-9;]*m')
    return len(ansi_escape.sub('', str(text)))

# ─────────────────────────────────────────────────────────────────
# PREMIUM BANNER
# ─────────────────────────────────────────────────────────────────

def print_portstorm_banner():
    """Print the ultra-premium HackIT PortStorm banner."""
    W  = '\x1b[0m'
    B  = '\x1b[1m'
    C  = '\x1b[38;5;51m'    # Electric Cyan
    M  = '\x1b[38;5;201m'   # Neon Magenta
    G  = '\x1b[38;5;46m'    # Matrix Green
    Y  = '\x1b[38;5;226m'   # Vivid Yellow
    R  = '\x1b[38;5;196m'   # Bright Red
    P  = '\x1b[38;5;141m'   # Soft Purple
    DM = '\x1b[2m'           # Dim
    BW = '\x1b[1;97m'       # Bold White
    BC = '\x1b[1;36m'       # Bold Cyan

    banner = f"""
{C}{B}  ██████╗  ██████╗ ██████╗ ████████╗███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗{W}
{C}{B}  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║{W}
{C}{B}  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║{W}
{P}{B}  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║{W}
{M}{B}  ██║     ╚██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║{W}
{M}{B}  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝{W}
"""
    subtitle = f"  {DM}┌{'─'*70}┐{W}"
    engine_line = f"  {DM}│{W}  {G}Engines:{W} {BW}Go{W} {DM}·{W} {R}Rust{W} {DM}·{W} {Y}C{W} {DM}·{W} {M}C++{W} {DM}·{W} {C}Lua{W}  {DM}│ {Y}Ultra-Power Polyglot Engine v3.0{W}"
    tag_line    = f"  {DM}│{W}  {P}Modes:{W} SYN·TCP·UDP·ACK·FIN·XMAS·NULL·IDLE·WINDOW·MAIMON·SWEEP  {DM}│{W}"
    sep_line    = f"  {DM}└{'─'*70}┘{W}"

    sys.stdout.write(banner)
    sys.stdout.write(subtitle + "\n")
    sys.stdout.write(engine_line + "\n")
    sys.stdout.write(tag_line + "\n")
    sys.stdout.write(sep_line + "\n\n")
    sys.stdout.flush()


# ─────────────────────────────────────────────────────────────────
# SERVICE DATABASE (expanded to 200+ ports)
# ─────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    # FTP Family
    20: 'FTP-DATA', 21: 'FTP', 989: 'FTPS-DATA', 990: 'FTPS',
    # SSH / Telnet
    22: 'SSH', 23: 'TELNET', 2222: 'SSH-ALT', 2223: 'SSH-ALT2',
    # SMTP Family
    25: 'SMTP', 465: 'SMTPS', 587: 'SMTP-MSA', 2525: 'SMTP-ALT',
    # DNS
    53: 'DNS',
    # HTTP(S)
    80: 'HTTP', 81: 'HTTP-ALT', 443: 'HTTPS', 8000: 'HTTP-DEV',
    8080: 'HTTP-PROXY', 8081: 'HTTP-ALT', 8443: 'HTTPS-ALT',
    8888: 'HTTP-ALT', 8008: 'HTTP-ALT', 9443: 'HTTPS-ALT',
    # Mail
    43: 'WHOIS', 110: 'POP3', 111: 'RPCBIND', 143: 'IMAP',
    993: 'IMAPS', 995: 'POP3S',
    # Network Services
    88: 'KERBEROS', 123: 'NTP', 161: 'SNMP', 162: 'SNMPTRAP',
    179: 'BGP', 389: 'LDAP', 445: 'SMB', 514: 'SYSLOG',
    515: 'LPD', 548: 'AFP', 631: 'IPP', 636: 'LDAPS',
    873: 'RSYNC', 902: 'VMware', 1080: 'SOCKS', 1194: 'OPENVPN',
    # Windows Services
    135: 'MSRPC', 137: 'NETBIOS-NS', 138: 'NETBIOS-DGM',
    139: 'NETBIOS-SSN', 445: 'SMB', 3389: 'RDP', 5985: 'WINRM',
    5986: 'WINRM-SSL', 49152: 'MS-RPC-DYN',
    # Databases
    1433: 'MSSQL', 1434: 'MSSQL-MON', 1521: 'ORACLE',
    2483: 'ORACLE-SSL', 3306: 'MYSQL', 5432: 'POSTGRES',
    6379: 'REDIS', 7001: 'CASSANDRA', 8020: 'HADOOP-NAMENODE',
    9042: 'CASSANDRA-CQL', 9200: 'ELASTICSEARCH',
    9300: 'ELASTICSEARCH-T', 11211: 'MEMCACHED',
    27017: 'MONGODB', 27018: 'MONGODB-SHARD', 28015: 'RETHINKDB',
    50000: 'DB2',
    # Message Queues
    5672: 'AMQP', 5671: 'AMQPS', 61613: 'STOMP', 61614: 'STOMPS',
    61616: 'ACTIVEMQ', 15672: 'RABBITMQ-MGMT',
    # Containers / Cloud
    2375: 'DOCKER', 2376: 'DOCKER-SSL', 2377: 'DOCKER-SWARM',
    4243: 'DOCKER-API', 6443: 'K8S-API', 8001: 'K8S-PROXY',
    10250: 'K8S-KUBELET', 10255: 'K8S-READ-ONLY',
    2379: 'ETCD', 2380: 'ETCD-PEER',
    # VPN / Proxy
    500: 'ISAKMP', 1701: 'L2TP', 4500: 'IPSEC', 4444: 'METERPRETER',
    # Remote / Management
    5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2', 6001: 'X11',
    # Web Apps
    3000: 'DEV-SERVER', 4000: 'DEV-SERVER', 5000: 'FLASK/UPNP',
    8500: 'CONSUL', 8200: 'VAULT', 8300: 'CONSUL-SERVER',
    9090: 'PROMETHEUS', 3100: 'LOKI', 9093: 'ALERTMANAGER',
    # Dev
    4200: 'ANGULAR', 5173: 'VITE', 3001: 'NODE-ALT',
    # Misc
    7: 'ECHO', 9: 'DISCARD', 13: 'DAYTIME', 17: 'QOTD',
    19: 'CHARGEN', 79: 'FINGER', 113: 'IDENT', 119: 'NNTP',
    194: 'IRC', 220: 'IMAP3', 443: 'HTTPS', 543: 'KLOGIN',
    544: 'KSHELL', 749: 'KERBEROS-ADM', 750: 'KERBEROS-IV',
    1812: 'RADIUS', 1813: 'RADIUS-ACC', 2049: 'NFS',
    4369: 'EPMD/RABBITMQ', 5060: 'SIP', 5061: 'SIPS',
    6000: 'X11', 6660: 'IRC-ALT', 6667: 'IRC', 7000: 'AFS',
    8009: 'AJP', 8069: 'ODOO', 8888: 'JUPYTER',
}

# Top 100 port list (nmap-style)
TOP_100_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
    8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465,
    548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000,
    32768, 1027, 1028, 1029, 1030, 8081, 2001, 8082, 6000, 9000, 6443,
    6379, 27017, 3000, 5432, 5672, 11211, 4369, 1521, 1433, 7001, 50000,
    9200, 4567, 7070, 7080, 7443, 8009, 8091, 8161, 8500, 9042, 9090,
    9100, 9200, 9300, 9418, 9999, 11211, 14265, 27017, 28017, 50030,
    50050, 50060, 50070, 50090, 60000, 60010, 60020, 60030, 2375, 2376,
    2377, 4243, 8001, 10250, 10255, 2379, 2380, 5000, 6001, 8200, 8300
]

# ─────────────────────────────────────────────────────────────────
# QUICK FALLBACK SCANNER (pure Python, no Go required)
# ─────────────────────────────────────────────────────────────────

def fast_port_scan(target, port_range="1-1024", workers=200, timeout=1.5):
    """High-performance pure-Python fallback scanner."""
    try:
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
        elif ',' in port_range:
            ports = [int(p) for p in port_range.split(',')]
            start_port, end_port = min(ports), max(ports)
        else:
            start_port = end_port = int(port_range)
    except Exception:
        start_port, end_port = 1, 1024

    results = []
    lock = threading.Lock()

    PROBES = {
        21: b"SYST\r\n",
        22: b"",
        25: b"HELO hackit.local\r\n",
        80: b"GET / HTTP/1.0\r\n\r\n",
        110: b"CAPA\r\n",
        143: b"A1 CAPABILITY\r\n",
        443: b"",
        3306: b"",
        6379: b"INFO\r\n",
        5432: bytes([0,0,0,8,4,210,22,47]),
        27017: bytes([0x3f,0x00,0x00,0x00,0x01,0x00,0x00,0x00]),
        11211: b"stats\r\n",
    }

    def grab_banner(s, port, target_host):
        import ssl
        try:
            s.settimeout(max(timeout, 2.0))
            
            # Deep SSL/TLS Probe
            if port in (443, 8443, 9443, 2083, 2087, 2096, 7443) or str(port).endswith('443'):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ss = ctx.wrap_socket(s, server_hostname=target_host)
                    cert = ss.getpeercert(binary_form=False)
                    cn = ""
                    if cert and 'subject' in cert:
                        for item in cert['subject']:
                            if item[0][0] == 'commonName':
                                cn = item[0][1]
                    
                    req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n"
                    ss.send(req.encode())
                    banner = ss.recv(4096).decode(errors='replace')
                    
                    for line in banner.split('\n'):
                        ll = line.lower()
                        if ll.startswith('server:') or ll.startswith('x-powered-by:'):
                            return f"[SSL: {cn}] {line.strip()}"
                    
                    if banner.upper().startswith("HTTP/"):
                        first_line = banner.split('\n')[0].strip()
                        return f"[SSL: {cn}] {first_line}"
                    
                    return f"[SSL: {cn}]" if cn else "(SSL connected)"
                except Exception:
                    return "(SSL Handshake failed)"

            # Pre-read for greeting protocols (FTP, SSH, SMTP, POP3, IMAP)
            if port in (21, 22, 25, 110, 143, 587, 3306, 5432):
                s.settimeout(0.5)
                try:
                    greet = s.recv(1024).decode(errors='ignore').strip()
                    if greet:
                        return greet.split('\n')[0].strip()
                except socket.timeout:
                    pass
                s.settimeout(max(timeout, 2.0))

            # Active Probing
            probe = b""
            if port in (80, 8080, 8000, 8888, 5000):
                probe = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: curl/8.7.1\r\nConnection: close\r\n\r\n".encode()
            else:
                probe = PROBES.get(port, b"")

            if probe:
                s.send(probe)

            banner = b""
            try:
                for _ in range(2):
                    chunk = s.recv(4096)
                    if not chunk: break
                    banner += chunk
                    if b"\n" in chunk: break
            except socket.timeout:
                pass

            if not banner and not probe:
                s.send(b"\r\n\r\n")
                try:
                    banner = s.recv(1024)
                except:
                    pass

            if not banner:
                return ""

            b_str = banner.decode(errors='replace').strip()
            
            if "HTTP/" in b_str.upper():
                svrs = [ln.strip() for ln in b_str.split('\n') if ln.lower().startswith('server:') or ln.lower().startswith('x-powered-by:')]
                if svrs: return " | ".join(svrs)
                return b_str.split('\n')[0].strip()

            for line in b_str.split('\n'):
                line = line.strip()
                if len(line) > 3 and any(c.isalnum() for c in line):
                    return line
            return b_str[:80]
        except Exception:
            return ""

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'UNKNOWN')
                banner = grab_banner(s, port, target)
                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "version": banner,
                        "banner": banner,
                        "status": "open",
                        "col": "green"
                    })
            s.close()
        except Exception:
            pass

    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(scan_port, ports)
    return sorted(results, key=lambda x: x['port'])


# ─────────────────────────────────────────────────────────────────
# RISK SCORING ENGINE
# ─────────────────────────────────────────────────────────────────

HIGH_RISK_PORTS = {
    21, 23, 445, 3389, 5900, 4444, 1080, 6667, 5985, 5986,
    2375, 2376, 6443, 10250, 27017, 6379, 9200, 11211,
    1433, 3306, 5432, 50000, 1521, 9042,
}

MEDIUM_RISK_PORTS = {
    22, 25, 80, 8080, 8000, 8888, 3000, 5000, 8443,
    110, 143, 161, 162, 179, 389, 636, 873, 1194,
    2049, 4369, 5060, 7001, 9090, 15672, 28015,
}

def get_risk(port, service, banner):
    """Calculate risk score for a port."""
    score = 0
    reasons = []

    if port in HIGH_RISK_PORTS:
        score += 40
        reasons.append("high-risk port")
    elif port in MEDIUM_RISK_PORTS:
        score += 20
        reasons.append("medium-risk port")

    banner_l = (banner or "").lower()
    if any(k in banner_l for k in ['openssh 5', 'openssh 6', 'openssh 7.2', 'apache/2.2', 'nginx/1.0', 'nginx/1.2']):
        score += 30
        reasons.append("outdated/vulnerable version")
    if any(k in banner_l for k in ['anonymous', 'guest', 'default', 'test']):
        score += 25
        reasons.append("anonymous/default credentials hint")
    if 'docker' in banner_l or port in (2375, 2376):
        score += 35
        reasons.append("exposed container runtime")

    if score >= 60:
        level = _colored("CRITICAL", B_RED, bold=True)
    elif score >= 40:
        level = _colored("HIGH", RED, bold=True)
    elif score >= 20:
        level = _colored("MEDIUM", YELLOW, bold=True)
    else:
        level = _colored("LOW", GREEN)

    return score, level, reasons


# ─────────────────────────────────────────────────────────────────
# SCAN RESULT OUTPUT ENGINE
# ─────────────────────────────────────────────────────────────────

def render_port_table(open_results, show_risk=False):
    """Render a premium port results table with perfect alignment."""
    if not open_results:
        click.echo(_colored("\n  [!] No open ports detected.", YELLOW))
        return

    # Header
    click.echo("\n" + _colored("  ┌───────┬──────────┬───────────────┬───────────────────────────────────────────┐", B_WHITE))
    if show_risk:
        click.echo(_colored("  │ PORT  │  STATE   │ SERVICE       │ BANNER & RISK ANALYSIS                    │", B_WHITE))
    else:
        click.echo(_colored("  │ PORT  │  STATE   │ SERVICE       │ BANNER & VERSION DETECTED                 │", B_WHITE))
    click.echo(_colored("  ├───────┼──────────┼───────────────┼───────────────────────────────────────────┤", B_WHITE))

    for p in sorted(open_results, key=lambda x: x.get('port', 0)):
        port_num = p.get('port', 0)
        if port_num == 0:
            continue

        st = p.get('status', 'unknown').lower()
        service = p.get('service', p.get('service', 'unknown'))
        banner = p.get('banner', p.get('version', ''))

        # State coloring (Exactly 8 visual chars to fit 10-char column with padding)
        if st == 'open':
            state_str = "\x1b[32m🟢 open \x1b[0m"
        elif st in ['filtered', 'forbidden']:
            state_str = "\x1b[33m🟡 filt \x1b[0m"
        else:
            state_str = "\x1b[31m🔴 close\x1b[0m"

        # Risk calculation
        if show_risk:
            score, risk_level, _ = get_risk(port_num, service, banner)
            raw_risk_len = _vis_len(risk_level)
            risk_str = f"{risk_level} ({score})"
            risk_vis_len = raw_risk_len + len(f" ({score})")
            
            avail = 41 - risk_vis_len - 3 # " | "
            if banner and avail > 0:
                clean_banner = str(banner).replace('\n', ' ').replace('\r', '').strip()
                b_trunc = clean_banner[:avail]
                if len(clean_banner) > avail:
                    b_trunc = clean_banner[:avail-2] + ".."
                info_str = f"{risk_str} | {_colored(b_trunc, DIM)}"
            else:
                info_str = risk_str
        else:
            if banner:
                clean_banner = str(banner).replace('\n', ' ').replace('\r', '').strip()
                b_trunc = clean_banner[:41]
                if len(clean_banner) > 41:
                    b_trunc = clean_banner[:39] + ".."
                info_str = _colored(b_trunc, DIM)
            else:
                info_str = _colored("-", DIM)

        svc_trunc = str(service)[:13]
        port_cell = pad_v(str(port_num), 5)
        svc_cell  = pad_v(svc_trunc, 13)
        inf_cell  = pad_v(info_str, 41)

        line = f"  │ {port_cell} │ {state_str} │ {svc_cell} │ {inf_cell} │"
        click.echo(line)

    click.echo(_colored("  └───────┴──────────┴───────────────┴───────────────────────────────────────────┘", B_WHITE))


def render_intel_grid(ip_addr, host_name, dns_enum, intel, os_info, mode, scan_mode, workers, tempo):
    """Render the premium tactical intelligence grid."""
    click.echo("\n" + _colored("╔" + "═" * 78 + "╗", B_CYAN))
    click.echo(_colored("║", B_CYAN) + pad_v(
        f"  {_colored('⚡ HACKIT PORTSTORM — TACTICAL RECON GRID', B_WHITE, bold=True)}", 78
    ) + _colored("║", B_CYAN))
    click.echo(_colored("╠" + "═" * 78 + "╣", B_CYAN))
    click.echo(_colored("║", B_CYAN) + pad_v(f"  {'TARGET IP':<14}: {_colored(ip_addr, B_YELLOW)}", 78) + _colored("║", B_CYAN))
    click.echo(_colored("║", B_CYAN) + pad_v(f"  {'HOST':<14}: {_colored(host_name, B_WHITE)}", 78) + _colored("║", B_CYAN))

    if dns_enum and dns_enum != "N/A":
        click.echo(_colored("║", B_CYAN) + pad_v(f"  {'DNS ENUM':<14}: {_colored(trunc_v(dns_enum, 58), B_GREEN)}", 78) + _colored("║", B_CYAN))

    if intel.get('asn') and intel['asn'] != 'N/A':
        click.echo(_colored("║", B_CYAN) + pad_v(f"  {'ASN / ORG':<14}: {trunc_v(str(intel['asn']), 58)}", 78) + _colored("║", B_CYAN))

    geo = intel.get('geo', '')
    if geo and geo.strip() and geo.strip() not in ('N/A', ', ,', ',,'):
        click.echo(_colored("║", B_CYAN) + pad_v(f"  {'GEOLOCATION':<14}: {_colored(trunc_v(geo, 58), CYAN)}", 78) + _colored("║", B_CYAN))

    os_name = os_info.get('name', 'Unknown')
    if os_name not in ('Unknown', 'Detecting...', ''):
        conf = os_info.get('confidence', os_info.get('accuracy', 0))
        if conf < 1.0:
            conf = int(conf * 100)
        os_conf_str = f"{os_name} (confidence: {conf}%)"
        click.echo(_colored("║", B_CYAN) + pad_v(
            f"  {'OS FINGERPRINT':<14}: {_colored(os_conf_str, B_GREEN)}", 78
        ) + _colored("║", B_CYAN))

    click.echo(_colored("╠" + "═" * 78 + "╣", B_CYAN))
    click.echo(_colored("║", B_CYAN) + pad_v(
        f"  {_colored('MODE', B_WHITE)}: {_colored(mode.upper(), CYAN)}  "
        f"{_colored('STRATEGY', B_WHITE)}: {_colored(scan_mode.upper(), YELLOW)}  "
        f"{_colored('TEMPO', B_WHITE)}: {_colored(tempo.upper(), PURPLE)}  "
        f"{_colored('WORKERS', B_WHITE)}: {_colored(str(workers), B_GREEN)}",
        78
    ) + _colored("║", B_CYAN))
    click.echo(_colored("╚" + "═" * 78 + "╝", B_CYAN))


# ─────────────────────────────────────────────────────────────────
# CLICK COMMAND DEFINITION
# ─────────────────────────────────────────────────────────────────

@click.command()
@click.argument('target_arg', required=False)
# [ CORE TARGETING ]
@click.option('-t', '--target', 'host', help='Target IP, hostname, or CIDR range')
@click.option('-i', '--input', 'host_file', type=click.Path(exists=True), help='Input target list from file')
@click.option('-p', '--ports', help='Ports: 1-1000, 80,443,8080, top:100, all')

# [ STRATEGY & PERFORMANCE ]
@click.option('-m', '--mode', type=click.Choice([
    'syn-stealth', 'tcp-connect', 'udp-spray', 'ack-firewalk', 'fin-silent',
    'xmas-party', 'null-mystery', 'maimon-ghost', 'window-spy', 'idle-zombie',
    'protocol-sweep', 'anon-self'
]), default='tcp-connect', help='Scanning strategy')
@click.option('--tp', '--tempo', type=click.Choice(['shadow', 'whisper', 'gait', 'normal', 'rush', 'blitz']),
              default='normal', help='Speed template')
@click.option('--workers', type=int, help='Number of concurrent workers')
@click.option('--adaptive', is_flag=True, help='Auto-tunes timing based on latency + packet loss')
@click.option('--quantum', is_flag=True, help='Quantum port ordering: most-likely-open ports scanned first')

# [ OUTPUT & VERBOSITY ]
@click.option('-o', '--output', help='Output filename (without extension)')
@click.option('-F', '--format', 'output_format',
              type=click.Choice(['text', 'json', 'xml', 'html', 'grafana']), default='text', help='Output format')
@click.option('-v', '--verbose', count=True, help='Verbosity level (-v, -vv, -vvv)')
@click.option('--open-only', is_flag=True, help='Show only open ports')

# [ STEALTH & EVASION ]
@click.option('--ghost-protocol', is_flag=True, help='Max stealth: SYN+frag+decoys+delays')
@click.option('--chaos', is_flag=True, help='Chaos mode: randomize targets/ports/TTL/IP')
@click.option('--decoy', help='Comma-separated decoy IPs (e.g., 1.2.3.4,5.6.7.8)')
@click.option('--zombie', help='Zombie host for idle/IPID scan')
@click.option('--spoof-ip', help='Spoof source IP address')
@click.option('--sp', '--source-port', type=int, help='Fixed source port (e.g., 53, 80)')
@click.option('--frag', is_flag=True, help='Fragment packets (8-byte chunks)')
@click.option('--mtu', type=int, help='Custom MTU size (min 8)')
@click.option('--ttl', type=int, help='Custom TTL value')

# [ INTELLIGENCE & DETECTION ]
@click.option('--deep', is_flag=True, help='Deep: service version + OS + vuln fingerprinting')
@click.option('--passive', is_flag=True, help='Passive intel: Shodan/Censys/FOFA enrichment')
@click.option('--smart-probe', is_flag=True, help='Smart probes: protocol-specific payloads')
@click.option('--fingerprint', '--fp', type=int, default=5, help='Fingerprint intensity (0-9)')
@click.option('--os-detect', '--os', is_flag=True, help='OS detection via TCP/IP fingerprinting')
@click.option('--script', '--sc', help='Script modules (vuln, exploit, brute, enum, all)')
@click.option('--script-args', help='Script arguments (key=value,key2=value2)')

# [ TIMING & RETRY ]
@click.option('--min-rate', type=int, help='Min packets/sec rate floor')
@click.option('--max-rate', type=int, help='Max packets/sec rate ceiling')
@click.option('--max-retries', type=int, default=3, help='Max retries per port')
@click.option('--host-timeout', type=int, help='Per-host timeout (ms)')
@click.option('--scan-delay', type=int, help='Inter-probe delay (ms)')

# [ NETWORK & DISCOVERY ]
@click.option('--randomize-targets', is_flag=True, help='Randomize multi-target scan order')
@click.option('--randomize-ports', is_flag=True, help='Randomize port scan order')
@click.option('--no-ping', is_flag=True, help='Skip host discovery (treat all as up)')
@click.option('--ping-method', type=click.Choice(['icmp', 'tcp-ack', 'tcp-syn', 'udp', 'arp']),
              help='Host discovery method')
@click.option('--resolve', type=click.Choice(['all', 'none', 'ipv4', 'ipv6']), help='DNS resolution policy')
@click.option('--dns-server', help='Custom DNS server IP')
@click.option('--show-version', is_flag=True, help='Display scanner version')
@click.option('--risk', is_flag=True, help='Show risk score per port')

def scan_ports(**kwargs):
    """
    ⚡ HackIT PortStorm v3.0 — Ultra-Power Polyglot Port Scanner.

    Engines: Go (Orchestrator) · Rust (Mass Scan) · C (Raw Socket)
             C++ (Deep Fingerprint) · Lua (Script Engine)

    Examples:
      scan example.com -p top:100 --deep --os
      scan 10.0.0.0/24 -p 22,80,443,3389 --tempo blitz
      scan 192.168.1.1 --ghost-protocol --chaos -p 1-65535
      scan target.com --deep --script vuln --risk
    """
    # ── Version display ──────────────────────────────────────────
    if kwargs.get('show_version'):
        click.echo(f"\n  {_colored('HackIT PortStorm', B_CYAN, bold=True)} {_colored('v3.0.0', B_WHITE)}")
        click.echo(f"  Engines: {_colored('Go+Rust+C+C+++Lua', B_GREEN)}\n")
        return

    # ── Print premium banner ─────────────────────────────────────
    print_portstorm_banner()

    # ── Engine initialization ────────────────────────────────────
    engine = get_engine()
    engine_ok = engine.available and engine.ensure_compiled()

    if not engine_ok:
        click.echo(_colored("[!] Go engine not found — falling back to Python scanner.", YELLOW))

    # ── Target resolution ────────────────────────────────────────
    target_raw = kwargs.get('target_arg') or kwargs.get('host')
    target_list = []
    if target_raw:
        target_list = parse_targets(target_raw)
    elif kwargs.get('host_file'):
        target_list = parse_targets(f"@{kwargs.get('host_file')}")
    else:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        return

    if not target_list:
        click.echo(_colored("[!] No valid targets resolved.", RED))
        return

    # ── Tempo → timing config ────────────────────────────────────
    tempo = kwargs.get('tempo', 'normal')
    mode  = kwargs.get('mode', 'tcp-connect')

    TEMPO_CONFIG = {
        'shadow':  {'wait': 8000, 'workers': 2,   'delay': 2000, 'desc': 'Ultra Stealth (2 pps)'},
        'whisper': {'wait': 4000, 'workers': 10,  'delay': 500,  'desc': 'Silent (10 pps)'},
        'gait':    {'wait': 2000, 'workers': 50,  'delay': 100,  'desc': 'Polite (50 pps)'},
        'normal':  {'wait': 1000, 'workers': 150, 'delay': 0,    'desc': 'Standard (150 pps)'},
        'rush':    {'wait': 500,  'workers': 350, 'delay': 0,    'desc': 'Aggressive (350 pps)'},
        'blitz':   {'wait': 200,  'workers': 700, 'delay': 0,    'desc': 'Insane (700+ pps)'},
    }

    t_cfg = TEMPO_CONFIG.get(tempo, TEMPO_CONFIG['normal'])
    wait       = kwargs.get('host_timeout') or t_cfg['wait']
    workers    = kwargs.get('workers')      or t_cfg['workers']
    scan_delay = kwargs.get('scan_delay')   or t_cfg['delay']

    # Adaptive override
    if kwargs.get('adaptive'):
        click.echo(_colored("  [ADAPTIVE] Auto-tuning timing based on network conditions...", DIM))

    # ── Scan mode → engine mode mapping ─────────────────────────
    SCAN_MODE_MAP = {
        'syn-stealth':    'syn',
        'tcp-connect':    'connect',
        'udp-spray':      'udp',
        'ack-firewalk':   'ack',
        'fin-silent':     'fin',
        'xmas-party':     'xmas',
        'null-mystery':   'null',
        'maimon-ghost':   'maimon',
        'window-spy':     'window',
        'idle-zombie':    'idle',
        'protocol-sweep': 'protocol',
        'anon-self':      'syn',
    }
    scan_mode = SCAN_MODE_MAP.get(mode, 'connect')
    stealth_val = False

    # ── Stealth flag processing ──────────────────────────────────
    if mode == 'anon-self':
        kwargs['ghost_protocol'] = True
        kwargs['chaos'] = True
        stealth_val = True

    if kwargs.get('ghost_protocol'):
        stealth_val = True
        kwargs['frag'] = True
        kwargs['randomize_ports'] = True
        if not kwargs.get('scan_delay'):
            scan_delay = max(scan_delay, 500)
        click.echo(_colored("  [GHOST] Maximum stealth engaged: SYN+frag+decoys+delays+jitter", PURPLE))

    if kwargs.get('chaos'):
        kwargs['randomize_targets'] = True
        kwargs['randomize_ports'] = True
        if not kwargs.get('ttl'):
            kwargs['ttl'] = random.randint(44, 200)
        click.echo(_colored(f"  [CHAOS] Randomization + TTL={kwargs['ttl']} + IP spoofing engaged", RED))

    # ── Deep scan flag cascade ───────────────────────────────────
    if kwargs.get('deep'):
        kwargs['os_detect'] = True
        kwargs['smart_probe'] = True
        kwargs['fingerprint'] = 9
        if not kwargs.get('script'):
            kwargs['script'] = 'vuln'
        click.echo(_colored("  [DEEP] Full pipeline: OS+service+vuln+fingerprint activated", CYAN))

    # ── Port selection ───────────────────────────────────────────
    ports_str = parse_ports(
        kwargs.get('ports'),
        None,
        kwargs.get('mode') == 'quick',
        kwargs.get('ports') == 'all',
        top_n=None
    )

    # ── Randomize targets ────────────────────────────────────────
    if kwargs.get('randomize_targets'):
        random.shuffle(target_list)

    # ── Pre-scan summary ─────────────────────────────────────────
    click.echo(f"\n  {_colored('TARGETS', B_WHITE)}: {_colored(str(len(target_list)), B_YELLOW)} host(s)  "
               f"{_colored('ENGINE', B_WHITE)}: {_colored('Go+Rust+C+C+++Lua' if engine_ok else 'Python', B_GREEN)}  "
               f"{_colored('TEMPO', B_WHITE)}: {_colored(t_cfg['desc'], CYAN)}")
    click.echo(f"  {_colored('MODE', B_WHITE)}: {_colored(mode.upper(), PURPLE)}  "
               f"{_colored('PORTS', B_WHITE)}: {_colored(str(ports_str)[:60] + '...' if len(str(ports_str)) > 60 else str(ports_str), YELLOW)}")
    click.echo()

    # ═══════════════════════════════════════════════════════════
    # MAIN SCAN LOOP
    # ═══════════════════════════════════════════════════════════
    start_time = datetime.now()
    all_results = []
    grand_open = 0
    grand_total = 0

    def scan_callback(cb_type, data):
        """Real-time callback for Go engine events."""
        if cb_type == "status":
            msg = data.get('message', '')
            if msg and kwargs.get('verbose', 0) >= 1:
                sys.stdout.write(_colored(f"\r  ◈ {msg}..." + " " * 10, DIM))
                sys.stdout.flush()
        elif cb_type == "result":
            port   = data.get('port', 0)
            status = data.get('status', 'unknown')
            if status == 'open' and port > 0:
                service = data.get('service', 'unknown')
                banner  = data.get('banner', data.get('version', ''))

                # Build live intel line
                p_str = _colored(f"{port:<5}", B_WHITE, bold=True)
                s_str = _colored("OPEN", B_GREEN, bold=True)
                v_str = _colored(f"{service[:16]:<16}", B_CYAN)
                b_str = _colored(str(banner)[:35].replace('\n', ' ') if banner else "(probing...)", DIM)

                sys.stdout.write(f"\r  {_colored('▶', B_GREEN)} {p_str} {s_str} {v_str} {b_str}\n")
                sys.stdout.flush()

    for t in target_list:
        # ── Target header ──────────────────────────────────────
        click.echo(_colored("  ┌─────────────────────────────────────────────────────────────────────────────┐", B_CYAN))
        click.echo(_colored("  │", B_CYAN) + pad_v(
            f" {_colored('⚡ SCANNING', YELLOW)}  {_colored(t, B_WHITE, bold=True)}", 77
        ) + _colored("│", B_CYAN))
        click.echo(_colored("  └─────────────────────────────────────────────────────────────────────────────┘", B_CYAN))

        results_cache = []

        # ── Engine execution ───────────────────────────────────
        if engine_ok:
            engine_kwargs = {}
            # Forward all relevant kwargs to engine — exclude params passed explicitly
            explicit_params = {'target_arg', 'host', 'host_file', 'mode', 'ports',
                               'workers', 'tempo', 'risk', 'scan_delay', 'host_timeout',
                               'verbose'}
            for k, v in kwargs.items():
                if k not in explicit_params and v is not None:
                    engine_kwargs[k] = v

            engine_res = engine.run(
                t,
                ports=ports_str,
                timeout=wait,
                threads=workers,
                include_closed=False,
                stealth=stealth_val,
                mode=scan_mode,
                callback=scan_callback,
                scan_delay=scan_delay,
                **engine_kwargs
            )

            all_results.append(engine_res)

            # ── Extract result data ────────────────────────────
            target_data = {}
            if isinstance(engine_res, dict):
                if 'results' in engine_res and isinstance(engine_res['results'], list):
                    target_data = next(
                        (r for r in engine_res['results'] if r.get('host') == t),
                        engine_res['results'][0] if engine_res['results'] else {}
                    )
                elif 'host' in engine_res:
                    target_data = engine_res
            elif isinstance(engine_res, list) and len(engine_res) > 0:
                target_data = engine_res[0]

            intel    = target_data.get('intel', {})
            os_info  = target_data.get('os', {})
            ip_addr  = target_data.get('ip') or target_data.get('host') or t
            host_name = target_data.get('host', t)
            port_results = target_data.get('results') or []

        else:
            # Pure Python fallback
            port_range = ports_str if isinstance(ports_str, str) else "1-1024"
            port_results = fast_port_scan(t, port_range, workers=workers, timeout=wait/1000)
            ip_addr   = t
            host_name = t
            intel     = {}
            os_info   = {}

        # ── DNS enrichment ─────────────────────────────────────
        dns_list = list(intel.get('dns', []))
        try:
            ptr = socket.gethostbyaddr(ip_addr)[0]
            if ptr and ptr not in dns_list:
                dns_list.append(ptr)
        except Exception:
            pass
        dns_enum = " | ".join(dns_list) or "N/A"

        # ── Intel grid display ─────────────────────────────────
        render_intel_grid(ip_addr, host_name, dns_enum, intel, os_info, mode, scan_mode, workers, tempo)

        # ── Filter open ports ──────────────────────────────────
        open_ports  = [p for p in port_results if p and p.get('status', '').lower() == 'open']
        filt_ports  = [p for p in port_results if p and p.get('status', '').lower() in ('filtered', 'forbidden')]
        closed_ports = [p for p in port_results if p and p.get('status', '').lower() == 'closed']

        grand_open  += len(open_ports)
        grand_total += len(port_results)

        # ── Port table ─────────────────────────────────────────
        display_ports = open_ports if kwargs.get('open_only') else open_ports
        render_port_table(display_ports, show_risk=kwargs.get('risk', False))

        # ── Vulnerability/script results ───────────────────────
        vuln_count = 0
        if kwargs.get('verbose', 0) >= 1 or kwargs.get('script'):
            for pr in open_ports:
                vulns = pr.get('vulnerabilities', [])
                scripts = pr.get('scripts', [])
                deep_a = pr.get('deep_analysis', '')
                if vulns or scripts or deep_a:
                    click.echo(f"\n  {_colored('◆ PORT', B_CYAN)} {_colored(str(pr.get('port','')), B_WHITE)}"
                               f" {_colored('INTELLIGENCE', CYAN)}")
                    for v in vulns[:8]:
                        vuln_count += 1
                        click.echo(f"    {_colored('⚠', RED)} {_colored(str(v)[:80], YELLOW)}")
                    for s in scripts[:5]:
                        click.echo(f"    {_colored('◉', CYAN)} {_colored(str(s)[:80], DIM)}")
                    if deep_a:
                        for line in str(deep_a).split('\n')[:5]:
                            if line.strip():
                                click.echo(f"    {_colored('↳', PURPLE)} {line.strip()[:80]}")

        # ── OS details (verbose) ───────────────────────────────
        if kwargs.get('os_detect') and os_info and kwargs.get('verbose', 0) >= 1:
            fp = os_info.get('fingerprint', '')
            if fp:
                click.echo(f"\n  {_colored('◈ OS FINGERPRINT', B_CYAN)}: {_colored(fp[:70], DIM)}")

        # ── Per-host summary ───────────────────────────────────
        elapsed = datetime.now() - start_time
        click.echo("\n" + _colored("  ┌" + "─" * 78 + "┐", B_GREEN))
        click.echo(_colored("  │", B_GREEN) + pad_v(
            f" {_colored('HOST SUMMARY', B_GREEN, bold=True)}", 78
        ) + _colored("│", B_GREEN))
        click.echo(_colored("  ├" + "─" * 78 + "┤", B_GREEN))
        click.echo(_colored("  │", B_GREEN) + pad_v(
            f"  Open Ports    : {_colored(str(len(open_ports)), B_WHITE, bold=True)}", 78
        ) + _colored("│", B_GREEN))
        click.echo(_colored("  │", B_GREEN) + pad_v(
            f"  Filtered      : {_colored(str(len(filt_ports)), YELLOW)}", 78
        ) + _colored("│", B_GREEN))
        click.echo(_colored("  │", B_GREEN) + pad_v(
            f"  Total Probed  : {_colored(str(len(port_results)), B_WHITE)}", 78
        ) + _colored("│", B_GREEN))
        if vuln_count > 0:
            click.echo(_colored("  │", B_GREEN) + pad_v(
                f"  Vulnerabilities: {_colored(str(vuln_count), B_RED, bold=True)}", 78
            ) + _colored("│", B_GREEN))
        click.echo(_colored("  │", B_GREEN) + pad_v(
            f"  Elapsed       : {_colored(str(elapsed).split('.')[0], B_CYAN)}", 78
        ) + _colored("│", B_GREEN))
        click.echo(_colored("  └" + "─" * 78 + "┘", B_GREEN))

        # ── Output file saving ─────────────────────────────────
        if kwargs.get('output') and port_results:
            save_results(
                kwargs['output'],
                kwargs.get('output_format', 'text'),
                t, ip_addr, port_results, open_ports, intel, os_info, elapsed
            )

    # ═══════════════════════════════════════════════════════════
    # GRAND FINAL SUMMARY (multi-target)
    # ═══════════════════════════════════════════════════════════
    if len(target_list) > 1:
        total_elapsed = datetime.now() - start_time
        click.echo("\n" + _colored("═" * 80, B_WHITE))
        click.echo(_colored("  ◈ GRAND SCAN SUMMARY", B_WHITE, bold=True))
        click.echo(_colored("═" * 80, B_WHITE))
        click.echo(f"  Hosts Scanned : {_colored(str(len(target_list)), B_CYAN)}")
        click.echo(f"  Total Open    : {_colored(str(grand_open), B_GREEN, bold=True)}")
        click.echo(f"  Total Probed  : {_colored(str(grand_total), B_WHITE)}")
        click.echo(f"  Total Elapsed : {_colored(str(total_elapsed).split('.')[0], B_YELLOW)}")
        click.echo(_colored("═" * 80, B_WHITE) + "\n")


# ─────────────────────────────────────────────────────────────────
# OUTPUT FORMATTERS
# ─────────────────────────────────────────────────────────────────

def save_results(filename, fmt, host, ip, port_results, open_ports, intel, os_info, elapsed):
    """Save scan results to file in the requested format."""
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    base = filename
    data = {
        "scanner": "HackIT PortStorm v3.0",
        "host": host,
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "elapsed": str(elapsed),
        "os": os_info,
        "intel": intel,
        "open_ports": len(open_ports),
        "total_ports": len(port_results),
        "ports": port_results,
    }

    if fmt == 'json':
        path = f"{base}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        click.echo(_colored(f"\n  [+] Results saved → {path}", B_GREEN))

    elif fmt == 'xml':
        path = f"{base}.xml"
        root = ET.Element("hackit_scan")
        ET.SubElement(root, "host").text = host
        ET.SubElement(root, "ip").text = ip
        ET.SubElement(root, "scan_time").text = datetime.now().isoformat()
        ports_el = ET.SubElement(root, "ports")
        for p in port_results:
            pe = ET.SubElement(ports_el, "port", number=str(p.get('port', 0)), status=p.get('status', ''))
            ET.SubElement(pe, "service").text = str(p.get('service', ''))
            ET.SubElement(pe, "banner").text = str(p.get('banner', ''))
        tree = ET.ElementTree(root)
        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(xmlstr)
        click.echo(_colored(f"\n  [+] Results saved → {path}", B_GREEN))

    elif fmt == 'html':
        path = f"{base}.html"
        rows = ""
        for p in open_ports:
            score, risk_level_raw, _ = get_risk(p.get('port', 0), p.get('service', ''), p.get('banner', ''))
            risk_color = "#ff4444" if score >= 60 else "#ff8800" if score >= 40 else "#ffcc00" if score >= 20 else "#44ff88"
            rows += f"""
            <tr>
                <td>{p.get('port','')}</td>
                <td class="open">OPEN</td>
                <td>{p.get('service','')}</td>
                <td>{str(p.get('banner', p.get('version', '')))[:60]}</td>
                <td style="color:{risk_color}">{score}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HackIT PortStorm — {host}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0e1a; color: #e0e6f0; font-family: 'Segoe UI', monospace; padding: 20px; }}
  h1 {{ color: #00d4ff; text-shadow: 0 0 10px #00d4ff88; margin-bottom: 20px; }}
  .meta {{ background: #111827; border: 1px solid #1e40af; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
  .meta span {{ color: #60a5fa; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #1e3a5f; color: #00d4ff; padding: 10px; text-align: left; border-bottom: 2px solid #2563eb; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #1e2a3a; }}
  tr:hover {{ background: #111827; }}
  .open {{ color: #4ade80; font-weight: bold; }}
</style>
</head>
<body>
<h1>⚡ HackIT PortStorm — Scan Report</h1>
<div class="meta">
  <span>Host:</span> {host} ({ip}) &nbsp;|&nbsp;
  <span>Scanned:</span> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
  <span>Open Ports:</span> {len(open_ports)} &nbsp;|&nbsp;
  <span>Elapsed:</span> {str(elapsed).split('.')[0]}
</div>
<table>
  <thead>
    <tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th><th>Risk Score</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        click.echo(_colored(f"\n  [+] Results saved → {path}", B_GREEN))

    elif fmt == 'grafana':
        path = f"{base}.json"
        # Grafana-compatible JSON format
        grafana_data = {
            "target": host,
            "datapoints": [[len(open_ports), int(datetime.now().timestamp() * 1000)]]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(grafana_data, f, indent=2)
        click.echo(_colored(f"\n  [+] Grafana data saved → {path}", B_GREEN))

    else:
        # Plain text
        path = f"{base}.txt"
        lines = [
            f"HackIT PortStorm v3.0 — Scan Report",
            f"=" * 60,
            f"Target  : {host}",
            f"IP      : {ip}",
            f"Scanned : {datetime.now().isoformat()}",
            f"Elapsed : {str(elapsed).split('.')[0]}",
            f"Open    : {len(open_ports)} / {len(port_results)} ports",
            f"",
            f"PORT   STATE   SERVICE         BANNER",
            f"─" * 60,
        ]
        for p in open_ports:
            lines.append(
                f"{str(p.get('port','')):6} OPEN    "
                f"{str(p.get('service','')):15} {str(p.get('banner', ''))[:40]}"
            )
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        click.echo(_colored(f"\n  [+] Results saved → {path}", B_GREEN))
