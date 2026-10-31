"""
╔═══════════════════════════════════════════════════════════════════╗
║  HackIT PortStorm v3.0 — Polyglot Ultra-Power Scanner            ║
║  Engines: Go · Rust · C · C++ · Lua                               ║
╚═══════════════════════════════════════════════════════════════════╝
"""
import socket
import threading
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import click
import json
import os
import random
import sys
import time as _time
import re as _re
from datetime import datetime
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, BLUE, CYAN, PURPLE, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM

HAS_RICH = False
try:
    from rich.console import Console as _RichConsole
    from rich.progress import Progress as _RichProgress, BarColumn as _RichBar, TextColumn as _RichText, TimeRemainingColumn as _RichTimeRem, SpinnerColumn as _RichSpinner
    HAS_RICH = True
except ImportError:
    pass
from .go_bridge import get_engine
from .targets import parse_targets, parse_ports
from .plugin_loader import discover_plugins, run_lua_plugin, run_ruby_plugin, run_rust_engine, run_c_engine
from hackit.subdomain.go_bridge import get_engine as get_sub_engine

# ─────────────────────────────────────────────────────────────────
# UTILITY HELPERS
# ─────────────────────────────────────────────────────────────────

class TimeoutException(Exception): pass

def timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out")

def with_timeout(seconds, func, *args, **kwargs):
    """Run a function with a timeout using SIGALRM (Unix only)."""
    if not hasattr(signal, 'SIGALRM'):
        return func(*args, **kwargs)
    old = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        result = func(*args, **kwargs)
        signal.alarm(0)
        return result
    except TimeoutException:
        signal.alarm(0)
        raise
    finally:
        signal.signal(signal.SIGALRM, old)

def create_progress_bar(desc="Scanning", total=100, transient=True):
    """Create a progress bar using rich (if available) or simple ASCII."""
    if HAS_RICH:
        console = _RichConsole()
        progress = _RichProgress(
            _RichSpinner(),
            _RichText("[progress.description]{task.description}"),
            _RichBar(),
            _RichText("[progress.percentage]{task.percentage:>3.0f}%"),
            _RichTimeRem(),
            console=console,
            transient=transient,
        )
        progress.start()
        task = progress.add_task(desc, total=total)
        return progress, task, lambda: progress.stop()
    return None, None, lambda: None

def update_progress(progress, task, advance=1, desc=None):
    if progress:
        if desc:
            progress.update(task, description=desc)
        progress.update(task, advance=advance)

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

def print_portstorm_banner(target="", iface="", gw="", uptime=""):
    """Print a compact run header — context, not decoration."""
    import subprocess as _sp

    if not iface:
        try:
            r = _sp.run(['ip', '-4', 'route', 'show', 'default'], capture_output=True, text=True)
            parts = r.stdout.strip().split()
            if len(parts) >= 5:
                iface = parts[4]
                gw = parts[2]
        except Exception:
            iface = iface or "eth0"
            gw = gw or "0.0.0.0"
    if not uptime:
        try:
            with open('/proc/uptime') as f:
                secs = float(f.read().split()[0])
                h, m = divmod(int(secs), 3600)
                m //= 60
                uptime = f"{h}h {m}m"
        except Exception:
            uptime = "0h 0m"

    title = _colored("PORTSTORM", B_CYAN, bold=True)
    if target:
        title += _colored("  ·  ", DIM) + _colored(target, B_WHITE, bold=True)
    context = "  ".join(x for x in (
        f"iface {iface}" if iface else "",
        f"gw {gw}" if gw else "",
        f"up {uptime}" if uptime else "",
    ) if x)

    click.echo()
    click.echo("  " + title)
    if context:
        click.echo("  " + _colored(context, DIM))


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
# SHARED SCAN OPTIONS
# ─────────────────────────────────────────────────────────────────
# Tempo presets: the single source of truth for wait/workers/delay.
TEMPO_CONFIG = {
    'shadow':  {'wait': 8000, 'workers': 4,   'delay': 2000, 'desc': 'Ultra stealth'},
    'whisper': {'wait': 4000, 'workers': 20,  'delay': 500,  'desc': 'Silent'},
    'gait':    {'wait': 2000, 'workers': 100, 'delay': 100,  'desc': 'Polite'},
    'normal':  {'wait': 800,  'workers': 250, 'delay': 0,    'desc': 'Standard'},
    'rush':    {'wait': 400,  'workers': 500, 'delay': 0,    'desc': 'Aggressive'},
    'blitz':   {'wait': 200,  'workers': 1000,'delay': 0,    'desc': 'Maximum'},
}

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
    'anon-self':      'anon-self',
    'c-turbo':        'c-turbo',
}


def build_scan_options(kwargs):
    """Translate CLI flags into one option dict every engine understands.

    Everything an engine needs to honour a flag lives here: timing, retries,
    evasion, intelligence and output. Missing keys mean "engine default".
    """
    tempo = kwargs.get('tempo') or 'normal'
    t_cfg = TEMPO_CONFIG.get(tempo, TEMPO_CONFIG['normal'])

    timeout_sec = kwargs.get('timeout') or 0
    if timeout_sec:
        timeout_ms = int(timeout_sec * 1000)
    else:
        timeout_ms = int(kwargs.get('host_timeout') or t_cfg['wait'])

    workers = int(kwargs.get('workers') or t_cfg['workers'])
    scan_delay = int(kwargs.get('scan_delay') or t_cfg['delay'])
    mode = kwargs.get('mode') or 'tcp-connect'
    scan_mode = SCAN_MODE_MAP.get(mode, 'connect')

    if kwargs.get('plugins'):
        kwargs['script'] = kwargs.get('script') or 'all'
    ghost = bool(kwargs.get('ghost_protocol')) or mode == 'anon-self'
    chaos = bool(kwargs.get('chaos')) or mode == 'anon-self'
    if ghost:
        scan_delay = max(scan_delay, 500)

    fingerprint = kwargs.get('fingerprint')
    if kwargs.get('deep'):
        fingerprint = max(int(fingerprint or 0), 9)
    fingerprint_intensity = kwargs.get('fingerprint_intensity') or fingerprint

    options = {
        'timeout_ms': timeout_ms,
        'workers': workers,
        'scan_mode': scan_mode,
        'stealth': bool(ghost or chaos or mode in ('syn-stealth', 'fin-silent', 'xmas-party', 'null-mystery')),
        'include_closed': bool(kwargs.get('include_closed', True)),
        'scan_delay': scan_delay,
        'max_retries': int(kwargs.get('max_retries') or 0),
        'adaptive': bool(kwargs.get('adaptive')),
        'quantum': bool(kwargs.get('quantum')),
        'randomize_ports': bool(kwargs.get('randomize_ports') or ghost or chaos),
        'randomize_targets': bool(kwargs.get('randomize_targets') or chaos),
        'no_ping': bool(kwargs.get('no_ping')),
        'ping_method': kwargs.get('ping_method'),
        'resolve': kwargs.get('resolve'),
        'dns_server': kwargs.get('dns_server'),
        'ghost_protocol': ghost,
        'chaos': chaos,
        'decoy': kwargs.get('decoy'),
        'zombie': kwargs.get('zombie'),
        'spoof_ip': kwargs.get('spoof_ip'),
        'source_port': kwargs.get('source_port'),
        'frag': bool(kwargs.get('frag') or ghost),
        'frag_size': kwargs.get('frag_size'),
        'mtu': kwargs.get('mtu'),
        'ttl': kwargs.get('ttl'),
        'deep': bool(kwargs.get('deep')),
        'os_detect': bool(kwargs.get('os_detect') or kwargs.get('deep')),
        'smart_probe': bool(kwargs.get('smart_probe') or kwargs.get('deep')),
        'passive': bool(kwargs.get('passive')),
        'fingerprint_intensity': int(fingerprint_intensity) if fingerprint_intensity else None,
        'script': kwargs.get('script') or ('vuln' if kwargs.get('deep') else None),
        'script_args': kwargs.get('script_args'),
        'min_rate': kwargs.get('min_rate'),
        'max_rate': kwargs.get('max_rate'),
        'host_timeout': kwargs.get('host_timeout'),
        'enrich': bool(kwargs.get('enrich')),
        'pipeline': kwargs.get('pipeline'),
    }
    return {k: v for k, v in options.items() if v is not None}


# ─────────────────────────────────────────────────────────────────
# QUICK FALLBACK SCANNER (pure Python, no Go required)
# ─────────────────────────────────────────────────────────────────

def _classify_timeout_err(err):
    err_str = str(err).lower()
    if 'refused' in err_str or 'actively refused' in err_str or 'connection reset' in err_str:
        return "closed"
    if 'timeout' in err_str or 'timed out' in err_str:
        return "filtered"
    if 'unreachable' in err_str or 'no route' in err_str or 'host is down' in err_str:
        return "filtered"
    if 'network is unreachable' in err_str:
        return "filtered"
    return "filtered"

_GREETING_PORTS = {21, 22, 25, 110, 143, 587, 993, 995, 465, 3306, 5432, 6379, 27017,
                   2222, 2223, 3389, 5900, 5901, 5902, 8443, 9443, 2083, 2087, 2096, 636, 853, 5986}
_SSL_PORTS = {443, 8443, 9443, 2083, 2087, 2096, 7443, 993, 995, 465, 636, 853, 5986, 990}
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3000, 4000, 5000, 9000,
               8069, 9090, 8200, 8500, 10000, 5000, 3001, 8001, 8081,
               3001, 4001, 7443, 9443, 4848, 9080, 9443}

_PROBES = {
    21: b"SYST\r\n",
    25: b"EHLO hackit.local\r\n",
    110: b"CAPA\r\n",
    143: b"A1 CAPABILITY\r\n",
    587: b"EHLO hackit\r\n",
    6379: b"INFO server\r\n",
    5432: bytes([0, 0, 0, 8, 4, 210, 22, 47]),
    27017: bytes([0x3f, 0x00, 0x00, 0x00, 0x01]),
    11211: b"stats\r\n",
    22: b"SSH-2.0-hackit\r\n",
    23: b"\r\n",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x02\x1e\x0f\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01\x05\x00",
    123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    389: b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
    3306: bytes([0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00\x00\x00",
    5900: b"RFB 003.003\n",
    9200: b"",
    8080: b"",
    8443: b"",
    3000: b"",
}

def _extract_banner_info(data, service_name=""):
    """Extract server info, version, and service from raw banner."""
    result = []
    for line in data.split('\n')[:10]:
        ll = line.lower().strip()
        if ll.startswith('server:') or ll.startswith('x-powered-by:') or ll.startswith('www-authenticate:'):
            result.append(line.strip())
    if not result and data.strip():
        first = data.split('\n')[0].strip()
        if first:
            result.append(first[:200])
    return " | ".join(result) if result else data.strip()[:200]

def _grab_banner_py(sock, port, host, timeout_val):
    """Protocol-specific banner grabbing for Python fallback."""
    import ssl
    sock.settimeout(min(timeout_val + 0.5, 3.0))

    # ── Greeting-first protocols ──
    if port in _GREETING_PORTS and port not in _SSL_PORTS:
        try:
            sock.settimeout(1.0)
            greet = sock.recv(4096)
            if greet:
                raw = greet.decode(errors='ignore').strip()[:200]
                if port == 22 and raw:
                    return raw
                if port == 21 and raw:
                    return raw
                return raw
        except:
            pass
        sock.settimeout(min(timeout_val + 0.5, 3.0))

    # ── SSL/TLS ports ──
    if port in _SSL_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(sock, server_hostname=host)
            ss.settimeout(2.0)
            if port in (443, 8443, 9443, 2083, 2087, 2096, 7443, 3000, 5000, 8000, 8080, 9090):
                req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            elif port in (993, 143):
                req = b"A1 CAPABILITY\r\n"
            elif port in (995, 110):
                req = b"CAPA\r\n"
            elif port in (465, 587):
                req = f"EHLO {host}\r\n".encode()
            elif port == 636:
                req = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
            else:
                req = b"\r\n\r\n"
            ss.send(req if isinstance(req, bytes) else req.encode())
            data = ss.recv(4096).decode(errors='replace')
            info = []
            cert = ss.getpeercert(binary_form=False) or {}
            if 'subject' in cert:
                for item in cert['subject']:
                    if item[0][0] == 'commonName':
                        info.append(f"CN={item[0][1]}")
            if 'subjectAltName' in cert:
                sans = [s[1] for s in cert['subjectAltName'] if s[0] == 'DNS'][:3]
                if sans:
                    info.append(f"SANs={','.join(sans)}")
            if 'version' in cert:
                info.append(f"TLSv1.{cert['version']-1}" if cert['version'] > 1 else "TLSv1")
            if data.upper().startswith("HTTP/"):
                info.append(data.split('\n')[0].strip())
            for line in data.split('\n'):
                ll = line.lower().strip()
                if ll.startswith('server:') or ll.startswith('x-powered-by:'):
                    info.append(line.strip())
            return " | ".join(info) if info else "(SSL connected)"
        except:
            pass

    # ── HTTP probes ──
    if port in _HTTP_PORTS and port not in _SSL_PORTS:
        try:
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.send(req.encode())
            data = sock.recv(4096).decode(errors='replace')
            return _extract_banner_info(data)
        except:
            pass

    # ── Protocol-specific probes ──
    if port in _PROBES:
        probe = _PROBES[port]
        if probe:
            try:
                sock.send(probe)
            except:
                pass
        try:
            sock.settimeout(max(timeout_val, 1.0))
            data = sock.recv(4096)
            if data:
                raw = data.decode(errors='ignore').strip()
                if raw:
                    lines = [l.strip() for l in raw.split('\n') if l.strip()]
                    return lines[0][:200]
        except:
            pass

    # ── Generic probe ──
    try:
        sock.send(b"\r\n\r\n")
        data = sock.recv(1024).decode(errors='ignore').strip()
        if data:
            return data[:200]
    except:
        pass

    return ""

def fast_port_scan(target, port_range="1-1024", workers=200, timeout=1.5):
    """High-performance pure-Python scanner — detects OPEN/CLOSED/FILTERED accurately."""
    try:
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            ports = list(range(start_port, end_port + 1))
        elif ',' in port_range:
            ports = sorted(set(int(p.strip()) for p in port_range.split(',') if p.strip()))
            start_port, end_port = min(ports), max(ports)
        else:
            start_port = end_port = int(port_range)
            ports = [start_port]
    except Exception:
        start_port, end_port = 1, 1024
        ports = list(range(1, 1025))

    results = []
    lock = threading.Lock()

    resolved = target
    try:
        resolved = socket.getaddrinfo(target, 0, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        pass

    def scan_port(port):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            start_t = _time.time()
            err = s.connect_ex((resolved, port))
            elapsed = _time.time() - start_t

            if err == 0:
                service = COMMON_PORTS.get(port, 'UNKNOWN')
                banner = _grab_banner_py(s, port, resolved, timeout)
                version = banner[:100] if banner else ''
                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "banner": banner,
                        "status": "open",
                    })
            else:
                errno_str = os.strerror(err) if err > 0 else str(err)
                err_lower = errno_str.lower() if errno_str else ''

                if err == 111 or err == 61 or 'refused' in err_lower:
                    status = "closed"
                elif err == 110 or err == 60 or 'timeout' in err_lower or elapsed >= timeout * 0.9:
                    status = "filtered"
                elif err == 113 or 'unreachable' in err_lower or 'no route' in err_lower:
                    status = "filtered"
                elif err == 101 or 'network is unreachable' in err_lower:
                    status = "filtered"
                elif err in (103, 104) or 'connection reset' in err_lower:
                    status = "closed"
                else:
                    status = "filtered" if elapsed >= timeout * 0.7 else "closed"

                service = COMMON_PORTS.get(port, 'UNKNOWN')
                with lock:
                    results.append({
                        "port": port,
                        "service": service,
                        "status": status,
                        "banner": "",
                        "version": "",
                    })
        except Exception:
            with lock:
                results.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, 'UNKNOWN'),
                    "status": "filtered",
                    "banner": "",
                    "version": "",
                })
        finally:
            if s:
                try:
                    s.close()
                except:
                    pass

    total = len(ports)
    progress, task, stop_progress = create_progress_bar("Port scan", total, transient=True)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}
        for f in as_completed(futures):
            if progress:
                update_progress(progress, task)
    stop_progress()
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

def _estimate_port_count(ports_spec):
    """Best-effort count of ports a spec expands to, for the live progress bar.

    Returns 0 when the count is unknown ("default", engine-side presets) so the
    dashboard shows "?" instead of a wrong denominator.
    """
    if not ports_spec:
        return 0
    spec = str(ports_spec).strip().lower()
    if not spec or spec == 'default':
        return 0
    if spec in ('all', 'full'):
        return 65535
    if spec.startswith('top') and spec[3:].isdigit():
        return int(spec[3:])
    total = 0
    for token in spec.replace(' ', '').split(','):
        if not token:
            continue
        if '-' in token:
            lo, _, hi = token.partition('-')
            if lo.isdigit() and hi.isdigit():
                a, b = int(lo), int(hi)
                if a > b:
                    a, b = b, a
                total += b - a + 1
            else:
                total += 1
        elif token.isdigit():
            total += 1
        else:
            return 0
    return total


def render_port_table(port_results, show_risk=False, timeline=None, open_only=False, host=""):
    """Render port results through the shared renderer.

    Columns are port / state / service / protocol / confidence / banner so the
    banner always sits beside the port that produced it.
    """
    from .render import render_port_table as _render

    _render(
        port_results,
        show_risk=show_risk,
        timeline=timeline,
        open_only=open_only,
        host=host,
    )


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

VERSION = "3.1.0"


def _profile_port_spec(profile):
    """Turn a profile into a port spec string the engines understand."""
    if getattr(profile, "ports", None):
        return ",".join(str(p) for p in profile.ports)
    if str(getattr(profile, "name", "")).lower() == "full":
        return "1-65535"
    return "top100"


def _describe_ports(spec):
    text = str(spec or "top100").strip()
    if text == "1-65535":
        return "all 65535 ports"
    if text.startswith("top"):
        return "%s common ports" % text[3:]
    count = _estimate_port_count(text)
    return "%d ports (%s)" % (count, text if len(text) <= 48 else text[:45] + "...")


def _print_script_catalogue(filter_text=None, categories=False):
    """`--list-scripts` / `--script-categories` output."""
    from .nse import NseEngine, CATEGORY_LABELS, available_categories

    engine = NseEngine()
    if not engine.available:
        cli_ui.error("nmap is required for NSE scripts and was not found on PATH")
        return
    scripts = engine.scripts

    if categories:
        cli_ui.section("nse categories", "%d scripts" % len(scripts))
        for name, count in available_categories(scripts).items():
            label = CATEGORY_LABELS.get(name, "")
            cli_ui.emit(cli_ui.GUTTER
                        + cli_ui.paint(name.ljust(14), B_CYAN)
                        + cli_ui.paint(str(count).rjust(4), B_WHITE)
                        + cli_ui.paint("   " + label, DIM))
        cli_ui.emit()
        return

    selected = engine.select([filter_text or "all"])
    cli_ui.section("nse scripts", "%d of %d" % (len(selected), len(scripts)))
    for script in selected:
        cli_ui.emit(cli_ui.GUTTER
                    + cli_ui.paint(script.name.ljust(34), B_WHITE)
                    + cli_ui.paint(script.primary_category.ljust(12), CYAN)
                    + cli_ui.paint(script.short_description, DIM))
    cli_ui.emit()



@click.command()
@click.argument('target_arg', required=False)
# [ CORE TARGETING ]
@click.option('-t', '--target', 'host', envvar='HACKIT_TARGET', help='Target IP, hostname, or CIDR range')
@click.option('-i', '--input', 'host_file', type=click.Path(exists=True), help='Input target list from file')
@click.option('-p', '--ports', envvar='HACKIT_PORTS', help='Ports: 1-1000, 80,443,8080, top:100, all')

# [ STRATEGY & PERFORMANCE ]
@click.option('-m', '--mode', type=click.Choice([
    'syn-stealth', 'tcp-connect', 'udp-spray', 'ack-firewalk', 'fin-silent',
    'xmas-party', 'null-mystery', 'maimon-ghost', 'window-spy', 'idle-zombie',
    'protocol-sweep', 'anon-self'
]), default='tcp-connect', envvar='HACKIT_MODE', help='Scanning strategy')
@click.option('--tp', '--tempo', type=click.Choice(['shadow', 'whisper', 'gait', 'normal', 'rush', 'blitz']),
              default='normal', envvar='HACKIT_TEMPO', help='Speed template')
@click.option('--workers', type=int, envvar='HACKIT_WORKERS', help='Number of concurrent workers')
@click.option('--adaptive', is_flag=True, help='Auto-tunes timing based on latency + packet loss')
@click.option('--quantum', is_flag=True, help='Quantum port ordering: most-likely-open ports scanned first')

# [ OUTPUT & VERBOSITY ]
@click.option('-o', '--output', envvar='HACKIT_OUTPUT', help='Output filename (without extension)')
@click.option('-F', '--format', 'output_format',
              type=click.Choice(['text', 'json', 'xml', 'html', 'grafana', 'csv']), default='text',
              envvar='HACKIT_FORMAT', help='Output format')
@click.option('--json-output', is_flag=True, help='Machine-parseable JSON output to stdout (overrides --format)')
@click.option('-v', '--verbose', count=True, help='Verbosity level (-v, -vv, -vvv)')
@click.option('-q', '--quiet', is_flag=True, help='Minimal output mode')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('--all-ports', is_flag=True, help='Show closed and filtered ports too (default: open only)')
@click.option('--timeout', type=int, default=0, envvar='HACKIT_TIMEOUT', help='Per-host timeout in seconds (0=disabled)')

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
@click.option('--script', '--sc', help='NSE scripts: a name, a category (vuln, brute, auth, discovery, web, safe, malware, intrusive), a prefix (http-), or "all"')
@click.option('--list-scripts', 'list_scripts', is_flag=False, flag_value='all', default=None,
              help='List bundled NSE scripts (optionally filtered by name or category) and exit')
@click.option('--script-categories', is_flag=True, help='List NSE categories with script counts and exit')
@click.option('--script-timeout', type=int, default=30, help='Per-script timeout in seconds (default 30)')
@click.option('--plugins', is_flag=True, help='Run all Lua/Ruby NSE plugins on open ports')
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

# [ ADVANCED ]
@click.option('--frag-size', type=int, help='Fragment size in bytes')
@click.option('--all-engines', is_flag=True, help='Run Go+Rust+C+C++ engines in parallel and correlate')
@click.option('--enrich', is_flag=True, help='Enrich results with Python intelligence pipeline')
@click.option('--cpuprofile', help='Write CPU profile to file')
@click.option('--memprofile', help='Write memory profile to file')
@click.option('--control-socket', help='Unix socket path for GUI control commands')

# [ NEW: Profiles & Pipeline ]
@click.option('--profile', type=click.Choice(['quick', 'stealth', 'full', 'web', 'lan', 'comprehensive']),
              envvar='HACKIT_PROFILE', help='Scan profile (overrides ports/mode/workers)')
@click.option('--pipeline', envvar='HACKIT_PIPELINE', help='Pipeline stages: tcp,service,os,vuln (comma-separated)')
@click.option('--single-engine', is_flag=True, help='Run only Go engine (disable parallel multi-engine)')
@click.option('--dashboard', is_flag=True, help='Show real-time live dashboard')

def scan_ports(**kwargs):
    """
    HackIT port scanner — accurate TCP/service discovery with real NSE scripting.

    Examples:

      scan -t example.com

      scan -t 10.0.0.0/24 -p 22,80,443

      scan -t example.com -p top1000 --deep

      scan -t example.com --script vuln

      scan --list-scripts http-

      scan gui
    """
    from . import cli_ui

    if kwargs.get('no_color'):
        import hackit.ui as _hackit_ui
        _hackit_ui._colored = lambda text, *args, **kw: str(text)
        cli_ui._colored = lambda text, *args, **kw: str(text)

    quiet = bool(kwargs.get('quiet'))
    if quiet:
        kwargs['verbose'] = 0

    if kwargs.get('show_version'):
        click.echo("  HackIT PortStorm %s" % VERSION)
        return

    target_arg = (kwargs.get('target_arg') or '').strip()
    if target_arg.lower() == 'gui':
        try:
            from .gui import GUI
            GUI().run()
        except SystemExit:
            raise
        except Exception as exc:
            cli_ui.error("GUI failed to start: %s" % exc)
        return

    if kwargs.get('list_scripts') is not None or kwargs.get('script_categories'):
        _print_script_catalogue(kwargs.get('list_scripts'),
                                bool(kwargs.get('script_categories')))
        return

    raw_target = target_arg or kwargs.get('host')
    if not raw_target and not kwargs.get('host_file'):
        click.echo(click.get_current_context().get_help())
        return

    if kwargs.get('host_file') and not raw_target:
        targets = parse_targets("@" + kwargs['host_file'])
    else:
        targets = parse_targets(raw_target)
    if not targets:
        cli_ui.error("no valid targets in %r" % raw_target)
        return

    if kwargs.get('randomize_targets'):
        random.shuffle(targets)

    # ── profile ─────────────────────────────────────────────────
    from .engine_profiles import get_profile
    profile_name = (kwargs.get('profile') or 'quick').lower()
    profile = get_profile(profile_name)

    ports_spec = parse_ports(
        kwargs.get('ports') or _profile_port_spec(profile),
        None,
        False,
        kwargs.get('ports') == 'all',
        top_n=None,
    )
    total_ports = _estimate_port_count(ports_spec)

    options = build_scan_options(kwargs)

    # ── engine selection ────────────────────────────────────────
    if kwargs.get('single_engine'):
        engines = ['go']
    elif kwargs.get('all_engines'):
        # The orchestrator runs engine *families*, one process per language:
        # go, rust, c, cpp. Individual helper binaries under bin/ are not scan
        # engines — passing their names silently yields no results.
        from .engine_orchestrator import _cached_available_engines
        available = _cached_available_engines()
        engines = [lang for lang in ('go', 'rust', 'c', 'cpp')
                   if available.get(lang)] or ['go']
    else:
        engines = None  # profile decides

    # ── stages ──────────────────────────────────────────────────
    stage_aliases = {
        'tcp': 'tcp_scan', 'service': 'service_detect', 'os': 'os_detect',
        'vuln': 'vuln_scan', 'discovery': 'discovery', 'enrich': 'enrich',
    }
    if kwargs.get('pipeline'):
        stages = [stage_aliases.get(s.strip(), s.strip())
                  for s in kwargs['pipeline'].split(',') if s.strip()]
    else:
        stages = list(profile.stages)

    if kwargs.get('os_detect') and 'os_detect' not in stages:
        stages.append('os_detect')
    if kwargs.get('deep') and 'vuln_scan' not in stages:
        stages.append('vuln_scan')

    # ── NSE selection ───────────────────────────────────────────
    nse_engine = None
    nse_scripts = []
    want_nse = bool(kwargs.get('script') or kwargs.get('plugins') or kwargs.get('deep'))
    if want_nse:
        from .nse import NseEngine
        nse_engine = NseEngine()
        if not nse_engine.available:
            cli_ui.warn("nmap not found — NSE scripts will be skipped")
            nse_engine = None
        else:
            selection = kwargs.get('script') or ('all' if kwargs.get('plugins') else 'vuln')
            nse_scripts = nse_engine.select([selection])
            if not nse_scripts:
                cli_ui.warn("no NSE scripts match %r" % selection)
                nse_engine = None

    # ── header ──────────────────────────────────────────────────
    nse_label = ("%d scripts" % len(nse_scripts)) if nse_engine else "off"
    if engines:
        engine_label = "+".join(engines)
    else:
        engine_label = "+".join(getattr(profile, "engines", None) or ["go"])
    if not quiet:
        cli_ui.header(
            target=targets[0] + (" (+%d)" % (len(targets) - 1) if len(targets) > 1 else ""),
            address="",
            ports_label=_describe_ports(ports_spec),
            engine=engine_label,
            profile=profile.name,
            nse_label=nse_label,
            workers=int(options.get('workers', profile.workers)),
            timeout_ms=int(options.get('timeout_ms', profile.timeout_ms)),
        )

    # ── scan ────────────────────────────────────────────────────
    from .engine_orchestrator import PortOrchestrator

    orchestrator = PortOrchestrator()
    started = _time.time()
    live_count = {"open": 0, "scanned": 0}
    live_rows = []

    def on_event(kind, data):
        if quiet or kind != 'result' or not isinstance(data, dict):
            return
        if str(data.get('status', '')).lower() != 'open':
            return
        live_rows.append(data)
        cli_ui.live_open(data)

    all_hosts = []
    for target in targets:
        if len(targets) > 1 and not quiet:
            cli_ui.title(target)
        try:
            result = orchestrator.run_scan(
                target,
                ports_spec,
                profile,
                engines=engines,
                stages=stages,
                callback=on_event,
                options=options,
            )
        except Exception as exc:
            cli_ui.error("%s: scan failed: %s" % (target, exc))
            continue
        if not result:
            cli_ui.warn("%s: no results" % target)
            continue
        all_hosts.append((target, result))

    elapsed = _time.time() - started

    if not all_hosts:
        cli_ui.error("scan produced no results")
        return

    # ── presentation + NSE ──────────────────────────────────────
    grand_open = 0
    grand_probed = 0
    all_nse_results = []
    json_hosts = []

    for target, result in all_hosts:
        port_results = [p for p in result.get('results', []) if isinstance(p, dict)]
        open_ports = [p for p in port_results if str(p.get('status', '')).lower() == 'open']
        closed_ports = [p for p in port_results if str(p.get('status', '')).lower() == 'closed']
        filtered_ports = [p for p in port_results
                          if str(p.get('status', '')).lower() in ('filtered', 'forbidden')]

        grand_open += len(open_ports)
        grand_probed += len(port_results)

        if not quiet:
            cli_ui.results_table(port_results, host=target,
                                 show_all=bool(kwargs.get('all_ports')),
                                 show_risk=bool(kwargs.get('risk')))

        host_nse = []
        if nse_engine and open_ports:
            port_map = {int(p.get('port', 0)): str(p.get('service') or '')
                        for p in open_ports if p.get('port')}
            chosen = nse_engine.filter_for_ports(nse_scripts, list(port_map))
            host_nse = nse_engine.run_for_ports(
                target,
                port_map,
                chosen,
                script_args=kwargs.get('script_args'),
                script_timeout=int(kwargs.get('script_timeout') or 30),
                max_parallel=4,
                on_result=(None if quiet else None),
            )
            all_nse_results.extend(host_nse)
            if not quiet:
                cli_ui.nse_findings(host_nse, host=target)

        os_info = result.get('os') or {}
        if os_info and os_info.get('name') not in (None, '', 'Unknown') and not quiet:
            confidence = os_info.get('confidence', os_info.get('accuracy', 0)) or 0
            try:
                confidence = int(float(confidence) * (100 if float(confidence) <= 1 else 1))
            except (TypeError, ValueError):
                confidence = 0
            cli_ui.field("os", cli_ui.paint(str(os_info['name']), B_WHITE, bold=True)
                         + cli_ui.paint("  %d%% confidence" % confidence, DIM),
                         label_width=10)

        if kwargs.get('output'):
            save_results(
                kwargs['output'],
                kwargs.get('output_format', 'text'),
                target,
                result.get('ip') or target,
                port_results,
                open_ports,
                result.get('intel', {}) or {},
                os_info,
                datetime.fromtimestamp(started),
            )

        json_hosts.append({
            "host": target,
            "ip": result.get('ip') or target,
            "os": os_info,
            "ports": port_results,
            "nse": [item.to_dict() for item in host_nse],
        })

    if not quiet:
        high_risk = []
        if kwargs.get('risk'):
            for _target, result in all_hosts:
                for record in result.get('results', []):
                    if str(record.get('status', '')).lower() != 'open':
                        continue
                    score, _level, _reasons = get_risk(
                        record.get('port', 0), record.get('service', ''),
                        record.get('banner', ''))
                    if score >= 60:
                        high_risk.append(record.get('port'))
        critical = sum(1 for item in all_nse_results
                       if item.severity in ('critical', 'high'))
        cli_ui.summary({
            'open': grand_open,
            'filtered': sum(1 for _t, r in all_hosts
                            for p in r.get('results', [])
                            if str(p.get('status', '')).lower() == 'filtered'),
            'closed': sum(1 for _t, r in all_hosts
                          for p in r.get('results', [])
                          if str(p.get('status', '')).lower() == 'closed'),
            'probed': grand_probed,
            'elapsed': elapsed,
            'rate': (grand_probed / elapsed) if elapsed > 0 else 0.0,
            'scripts': len(all_nse_results),
            'high_risk': high_risk,
            'critical_findings': critical,
        })

    if kwargs.get('json_output'):
        click.echo(json.dumps({
            "scanner": "HackIT PortStorm %s" % VERSION,
            "scan_time": datetime.now().isoformat(),
            "targets": targets,
            "elapsed_seconds": round(elapsed, 3),
            "open_total": grand_open,
            "probed_total": grand_probed,
            "hosts": json_hosts,
        }, indent=2, default=str))


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

    elif fmt == 'csv':
        path = f"{base}.csv"
        import csv as _csv
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = _csv.writer(f)
            w.writerow(['port', 'state', 'service', 'banner', 'version'])
            for p in open_ports:
                w.writerow([p.get('port', ''), p.get('status', '').upper(),
                           p.get('service', ''), p.get('banner', ''),
                           p.get('version', '')])
        click.echo(_colored(f"\n  [+] Results saved → {path}", B_GREEN))

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
