"""
Advanced Port Scanner (Polyglot)
Simplified powerful interface.
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
from datetime import datetime
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, BLUE, CYAN, PURPLE, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM
from .go_bridge import get_engine
from .targets import parse_targets, parse_ports
from hackit.subdomain.go_bridge import get_engine as get_sub_engine
import re as _re

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

COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 43: 'WHOIS',
    53: 'DNS', 80: 'HTTP', 81: 'HTTP-ALT', 88: 'KERBEROS', 110: 'POP3', 111: 'RPCBIND',
    123: 'NTP', 135: 'MSRPC', 137: 'NETBIOS-NS', 138: 'NETBIOS-DGM', 139: 'NETBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 514: 'SYSLOG', 515: 'LPD', 548: 'AFP', 587: 'SMTP-MSA', 631: 'IPP',
    636: 'LDAPS', 873: 'RSYNC', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS',
    1194: 'OPENVPN', 1433: 'MSSQL', 1521: 'ORACLE', 2049: 'NFS', 2375: 'DOCKER',
    2376: 'DOCKER-SSL', 3000: 'GOGS/GRAFANA', 3306: 'MYSQL', 3389: 'RDP',
    5000: 'UPNP', 5432: 'POSTGRES', 5672: 'AMQP', 5900: 'VNC', 6379: 'REDIS',
    7000: 'AFS', 8000: 'HTTP-ALT', 8080: 'HTTP-PROXY', 8081: 'HTTP-ALT',
    8443: 'HTTPS-ALT', 9000: 'SONARQUBE', 9090: 'ZEUS-ADMIN', 9200: 'ELASTICSEARCH',
    11211: 'MEMCACHED', 27017: 'MONGODB'
}

def fast_port_scan(target, port_range="1-1024"):
    try:
        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
        else:
            start_port = end_port = int(port_range)
    except Exception:
        start_port, end_port = 1, 1024

    results = []
    lock = threading.Lock()

    def grab_banner(s):
        try:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors='ignore').strip()
            if banner:
                for line in banner.split('\n'):
                    if line.lower().startswith('server:'):
                        return line.split(':', 1)[1].strip()
                return banner[:50]
        except Exception: pass
        return "Unknown"

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1.5)
            result = s.connect_ex((target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'UNKNOWN')
                version = "Unknown"
                if port in [21, 22, 25, 80, 110, 143, 443, 8080]:
                    version = grab_banner(s)
                with lock:
                    results.append({"port": port, "service": service, "version": version, "status": "OPEN", "col": "green"})
            s.close()
        except Exception: pass

    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scan_port, ports)
    return sorted(results, key=lambda x: x['port'])

@click.command()
@click.argument('target_arg', required=False)
# [ CORE TARGETING ]
@click.option('-t', '--target', 'host', help='Target IP, hostname, or CIDR range (e.g., 192.168.1.1, example.com, 10.0.0.0/24)')
@click.option('-i', '--input', 'host_file', type=click.Path(exists=True), help='Input target list from file')
@click.option('-p', '--ports', help='Ports to scan. Formats: 1-1000, 80,443,8080, top:100, all')

# [ STRATEGY & PERFORMANCE ]
@click.option('-m', '--mode', type=click.Choice([
    'syn-stealth', 'tcp-connect', 'udp-spray', 'ack-firewalk', 'fin-silent', 
    'xmas-party', 'null-mystery', 'maimon-ghost', 'window-spy', 'idle-zombie', 
    'protocol-sweep', 'anon-self'
]), default='syn-stealth', help='Scanning strategy')
@click.option('--tp', '--tempo', type=click.Choice(['shadow', 'whisper', 'gait', 'normal', 'rush', 'blitz']), default='normal', help='Speed template')
@click.option('--workers', type=int, help='Number of concurrent workers (Auto-tuned by tempo if not set)')
@click.option('--adaptive', is_flag=True, help='Auto-tunes timing based on latency, packet loss, and rate-limiting')
@click.option('--quantum', is_flag=True, help='Quantum port ordering: scan ports most likely to be open first')

# [ OUTPUT & VERBOSITY ]
@click.option('-o', '--output', help='Output filename (without extension)')
@click.option('-F', '--format', 'output_format', type=click.Choice(['text', 'json', 'xml', 'html', 'grafana']), default='text', help='Output format')
@click.option('-v', '--verbose', count=True, help='Verbosity level (-v, -vv, -vvv)')
@click.option('--open-only', is_flag=True, help='Show only open ports')

# [ STEALTH & EVASION ]
@click.option('--ghost-protocol', is_flag=True, help='Maximum stealth: SYN stealth, fragmentation, random decoys, delays')
@click.option('--chaos', is_flag=True, help='Chaos mode: randomize targets, ports, spoof IP, TTL')
@click.option('--decoy', help='Comma-separated list of decoy IPs')
@click.option('--zombie', help='Zombie host for idle scan (requires --mode idle-zombie)')
@click.option('--spoof-ip', help='Spoof source IP address')
@click.option('--sp', '--source-port', type=int, help='Use specific source port (e.g., 53)')
@click.option('--frag', type=int, nargs=0, is_flag=True, help='Fragment packets (standard size)')
@click.option('--frag-size', type=int, help='Specify fragment size (e.g., 16)')
@click.option('--mtu', type=int, help='Set MTU (minimum 8)')
@click.option('--ttl', type=int, help='Set custom TTL value to evade hop-count detection')

# [ INTELLIGENCE & DETECTION ]
@click.option('--deep', is_flag=True, help='Deep inspection: enables service version detection + OS fingerprinting')
@click.option('--passive', is_flag=True, help='Passive intelligence gathering (Shodan/Censys/FOFA)')
@click.option('--smart-probe', is_flag=True, help='Smart service probe: send minimal payloads for service detection')
@click.option('--fingerprint', '--fp', type=int, default=5, help='Service fingerprint intensity (0-9)')
@click.option('--os-detect', '--os', is_flag=True, help='Enable OS detection')
@click.option('--script', '--sc', help='Run script modules (e.g., vuln, exploit, brute)')
@click.option('--script-args', help='Arguments for scripts (format: key=value)')

# [ TIMING & RETRY ]
@click.option('--min-rate', type=int, help='Minimum send rate (packets/sec)')
@click.option('--max-rate', type=int, help='Maximum send rate (packets/sec)')
@click.option('--max-retries', type=int, help='Maximum retries per port')
@click.option('--host-timeout', type=int, help='Per-host timeout in milliseconds')
@click.option('--scan-delay', type=int, help='Delay between probes in milliseconds')

# [ NETWORK & DISCOVERY ]
@click.option('--randomize-targets', is_flag=True, help='Randomize target scan order')
@click.option('--randomize-ports', is_flag=True, help='Randomize port scan order')
@click.option('--no-ping', is_flag=True, help='Skip host discovery - treat all hosts as up')
@click.option('--ping-method', type=click.Choice(['icmp', 'tcp-ack', 'tcp-syn', 'udp', 'arp']), help='Host discovery method')
@click.option('--resolve', type=click.Choice(['all', 'none', 'ipv4', 'ipv6']), help='DNS resolution policy')
@click.option('--dns-server', help='Use a specific DNS server')
@click.option('--show-version', is_flag=True, help='Display tool version information')

def scan_ports(**kwargs):
    """
    Super Powerful Port Scanner (Go-Powered) - Simple & Powerful Version.
    """
    if kwargs.get('show_version'):
        click.echo("HackIt Port Scanner v2.1.0")
        return

    display_tool_banner('Port Scanner Tools')
    
    engine = get_engine()
    if not engine.available:
        click.echo(_colored("[!] Go engine not found. Please rebuild.", RED))
        return

    # 1. Parse Targets
    target_raw = kwargs.get('target_arg') or kwargs.get('host')
    target_list = []
    if target_raw:
        target_list = parse_targets(target_raw)
    elif kwargs.get('host_file'):
        target_list = parse_targets(f"@{kwargs.get('host_file')}")
    else:
        # Instead of error, show help if no targets provided during interactive use
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        return

    if not target_list:
        click.echo(_colored("[!] No valid targets found.", RED))
        return

    # 2. Map Tempo & Strategy Layer
    tempo = kwargs.get('tempo', 'normal')
    mode = kwargs.get('mode', 'syn-stealth')
    
    # Timing Overrides based on Tempo
    tempo_map = {
        'shadow':  {'wait': 5000, 'workers': 1,   'delay': 1000},
        'whisper': {'wait': 3000, 'workers': 5,   'delay': 500},
        'gait':    {'wait': 2000, 'workers': 20,  'delay': 100},
        'normal':  {'wait': 1000, 'workers': 100, 'delay': 0},
        'rush':    {'wait': 500,  'workers': 250, 'delay': 0},
        'blitz':   {'wait': 200,  'workers': 500, 'delay': 0}
    }
    
    t_config = tempo_map.get(tempo)
    wait = kwargs.get('wait') or t_config['wait']
    workers = kwargs.get('workers') or t_config['workers']
    scan_delay = kwargs.get('scan_delay') or t_config['delay']
    
    # Strategy Mapping
    scan_mode = "syn" # Default for most stealth modes
    stealth_val = False
    
    if mode == 'tcp-connect':
        scan_mode = "connect"
    elif mode == 'udp-spray':
        scan_mode = "udp"
    elif mode == 'ack-firewalk':
        scan_mode = "ack"
    elif mode == 'fin-silent':
        scan_mode = "fin"
    elif mode == 'xmas-party':
        scan_mode = "xmas"
    elif mode == 'null-mystery':
        scan_mode = "null"
    elif mode == 'maimon-ghost':
        scan_mode = "maimon"
    elif mode == 'window-spy':
        scan_mode = "window"
    elif mode == 'idle-zombie':
        scan_mode = "idle"
    elif mode == 'protocol-sweep':
        scan_mode = "protocol"
    elif mode == 'anon-self':
        scan_mode = "syn"
        kwargs['ghost_protocol'] = True
        kwargs['chaos'] = True

    # Stealth & Evasion Layer Logic
    if kwargs.get('ghost_protocol'):
        stealth_val = True
        kwargs['frag'] = True
        kwargs['randomize_ports'] = True
        if not kwargs.get('scan_delay'): scan_delay = max(scan_delay, 500)
        
    if kwargs.get('chaos'):
        kwargs['randomize_targets'] = True
        kwargs['randomize_ports'] = True
        kwargs['ttl'] = kwargs.get('ttl') or random.randint(64, 128)

    # Deep Intelligence Pass
    if kwargs.get('deep'):
        kwargs['os_detect'] = True
        kwargs['detect_service'] = True
        kwargs['fingerprint'] = 9
        kwargs['sc'] = 'vuln,exploit,brute'

    # Intelligence Layer Mapping
    if kwargs.get('intel'):
        kwargs['detect_service'] = True
        kwargs['os_detection'] = True
        kwargs['tech_analyze'] = True
        kwargs['enrich'] = True
        
    if kwargs.get('banner'):
        kwargs['detect_service'] = True
        
    if kwargs.get('fingerprint'):
        kwargs['os_detection'] = True
        kwargs['identify_os'] = True

    # 3. Port Selection
    ports_str = parse_ports(
        kwargs.get('ports'), 
        None, 
        kwargs.get('mode') == 'quick', 
        kwargs.get('ports') == 'all',
        top_n=None
    )

    click.echo(f"[*] Engine: {_colored('HackIT Polyglot', GREEN)}")
    click.echo(f"[*] Mode: {_colored(mode.upper(), CYAN)} ({scan_mode.upper()})")
    click.echo(f"[*] Targets: {len(target_list)} hosts")

    # 4. Execution Logic
    start_time = datetime.now()
    all_results = []
    results_cache = []
    
    def scan_callback(type, data):
        if type == "status":
            msg = data.get('message', '')
            if msg:
                ticker = _colored(f"\r  » [TACTICAL] {msg}...", DIM)
                sys.stdout.write(ticker + "\033[K")
                sys.stdout.flush()
        elif type == "result":
            status = data.get('status', 'unknown')
            port = data.get('port', 0)
            if status == 'open' and port > 0:
                if not any(r.get('port') == port for r in results_cache):
                    results_cache.append(data)
                    # Real-time surfacing of open ports
                    service = data.get('service', 'unknown')
                    banner = data.get('banner', data.get('version', ''))
                    if not banner: banner = _colored("[!] Fingerprinting Service...", DIM)
                    
                    # High-Fidelity Tactical Intelligence Feed
                    p_str = _colored(f"{port:<5}", B_WHITE, bold=True)
                    s_str = _colored("OPEN", GREEN, bold=True)
                    v_str = _colored(f"{service[:10]:<10}", B_CYAN)
                    
                    # Clean banner for feed
                    b_clean = str(banner).replace('\n', ' ').replace('\r', '').strip()
                    if b_clean == "(analyzing...)": b_clean = _colored(b_clean, DIM)
                    if len(b_clean) > 40: b_clean = b_clean[:37] + "..."
                    
                    feed_line = f"\r  {_colored('» [INTEL]', B_CYAN)} DISCOVERED: {p_str} | {s_str} | {v_str} | {b_clean}"
                    sys.stdout.write(feed_line + "\n")
                    sys.stdout.flush()
                    sys.stdout.flush()

    for t in target_list:
        click.echo(f"\n" + _colored("┌── [POWERFUL RECONNAISSANCE INITIALIZED]", B_CYAN))
        click.echo(_colored("│", B_CYAN) + f" TARGET NODE: {_colored(t, B_WHITE, bold=True)}")
        click.echo(_colored("│", B_CYAN) + f" SCAN ENGINE: {_colored('MULTI-SYNC (GO+RUST+C)', GREEN)}")
        click.echo(_colored("└" + "─" * 40, B_CYAN) + "\n")
        
        results_cache = []
        engine_kwargs = kwargs.copy()
        for k in ['target_arg', 'host', 'host_file', 'mode', 'ports', 'intel', 'banner', 'fingerprint', 'workers', 'wait']:
            engine_kwargs.pop(k, None)

        engine_res = engine.run(
            t,
            ports=ports_str,
            timeout=wait,
            threads=workers,
            include_closed=False,
            stealth=stealth_val,
            mode=scan_mode,
            callback=scan_callback,
            **engine_kwargs
        )
        
        all_results.append(engine_res)
        
        # Robust Extraction from Polyglot Payload
        target_data = {}
        if isinstance(engine_res, dict):
            if 'results' in engine_res and isinstance(engine_res['results'], list):
                # Search for target in results list
                target_data = next((r for r in engine_res['results'] if r.get('host') == t), engine_res['results'][0] if engine_res['results'] else {})
            elif 'host' in engine_res:
                target_data = engine_res
        elif isinstance(engine_res, list) and len(engine_res) > 0:
            target_data = engine_res[0]

        intel = target_data.get('intel', {})
        os_info = target_data.get('os', {})
        ip_addr = target_data.get('ip') or target_data.get('host') or t
        host_name = target_data.get('host', t)
        
        # Industrial-Grade DNS Reconnaissance
        dns_list = intel.get('dns', [])
        if not dns_list:
            try:
                # PTR Lookup
                dns_list.append(socket.gethostbyaddr(ip_addr)[0])
            except: pass
            
        try:
            # Domain Resolution
            if ip_addr != t and t not in dns_list:
                dns_list.append(t)
        except: pass
        
        # Check for MX records if it looks like a domain
        if '.' in t and not any(c.isdigit() for c in t.split('.')[-1]):
            try:
                import subprocess
                mx_out = subprocess.check_output(['nslookup', '-type=mx', t], timeout=2, stderr=subprocess.DEVNULL).decode()
                for line in mx_out.split('\n'):
                    if 'mail exchanger' in line:
                        mx_host = line.split('=')[-1].strip()
                        if mx_host not in dns_list: dns_list.append(f"MX:{mx_host}")
            except: pass

        dns_enum = " | ".join(dns_list) or "N/A"
        if len(dns_enum) > 70: dns_enum = dns_enum[:67] + "..."
        
        # Grid Display (High-Fidelity Box Drawing - Tactical Grid)
        click.echo(_colored("╔" + "═" * 78 + "╗", B_WHITE))
        click.echo(_colored("║", B_WHITE) + pad_v(f"  {_colored('TACTICAL IP INTELLIGENCE GRID', B_WHITE, bold=True)}", 78) + _colored("║", B_WHITE))
        click.echo(_colored("╠" + "═" * 78 + "╣", B_WHITE))
        click.echo(_colored("║", B_WHITE) + pad_v(f"  » TARGET IP   : {_colored(ip_addr, B_YELLOW)}", 78) + _colored("║", B_WHITE))
        click.echo(_colored("║", B_WHITE) + pad_v(f"  » HOST        : {_colored(host_name, B_WHITE)}", 78) + _colored("║", B_WHITE))
        click.echo(_colored("║", B_WHITE) + pad_v(f"  » DNS ENUM    : {_colored(dns_enum, B_CYAN)}", 78) + _colored("║", B_WHITE))
        
        if intel.get('asn') and intel['asn'] != 'N/A':
            click.echo(_colored("║", B_WHITE) + pad_v(f"  » ASN/ORG     : {trunc_v(intel['asn'], 60)}", 78) + _colored("║", B_WHITE))
            
        geo = intel.get('geo', '')
        if geo and geo.strip() and geo.strip() != 'N/A' and geo.strip() != ', ,':
            click.echo(_colored("║", B_WHITE) + pad_v(f"  » GEOLOCATION : {trunc_v(geo, 60)}", 78) + _colored("║", B_WHITE))
            
        os_name = os_info.get('name', 'Unknown')
        if os_name != 'Unknown':
            conf = os_info.get('confidence', os_info.get('accuracy', 0))
            if conf < 1.0: conf = conf * 100 # Normalize to percentage
            click.echo(_colored("║", B_WHITE) + pad_v(f"  » OS FINGERPRNT: {_colored(os_name + ' (' + str(int(conf)) + '%)', B_GREEN)}", 78) + _colored("║", B_WHITE))
            
        click.echo(_colored("╚" + "═" * 78 + "╝", B_WHITE))
        
        port_results = target_data.get('results') or []
        open_ports = [p for p in port_results if p and p.get('status', '').lower() == 'open']
        closed_ports = [p for p in port_results if p and p.get('status', '').lower() == 'closed']
        filtered_ports = [p for p in port_results if p and p.get('status', '').lower() in ['filtered', 'forbidden']]
        
        if port_results:
            click.echo("")
            # Exact Grid Format requested by user
            grid_header  = "┌───────┬──────────┬──────────┬──────────────────────┐"
            grid_titles  = "│ Port  │ Status   │ Service  │ Banner (raw)         │"
            grid_divider = "├───────┼──────────┼──────────┼──────────────────────┤"
            grid_footer  = "└───────┴──────────┴──────────┴──────────────────────┘"
            
            # Filter to show only OPEN ports as requested by user
            open_results = [p for p in port_results if p and p.get('status', '').lower() == 'open']
            
            if open_results:
                click.echo(_colored(grid_header, B_WHITE))
                click.echo(_colored(grid_titles, B_WHITE))
                click.echo(_colored(grid_divider, B_WHITE))
                
                for p in sorted(open_results, key=lambda x: x.get('port', 0)):
                    port_num = p.get('port', 0)
                    if port_num == 0: continue
                    
                    st = p.get('status', 'unknown').lower()
                    service = p.get('service', 'unknown')
                    banner = p.get('banner', p.get('version', ''))
                    
                    if not banner:
                        if st == 'filtered' or st == 'forbidden':
                            banner = "(no response)"
                        elif st == 'closed':
                            banner = "(RST)"
                        else:
                            banner = "(timeout)"
                    
                    # Status Indicator with color
                    if st == 'open':
                        status_str = "🟢 open"
                    elif st in ['filtered', 'forbidden']:
                        status_str = "🟡 filtered"
                    else:
                        status_str = "🔴 closed"
                    
                    # Truncate for grid
                    banner_clean = str(banner).replace('\n', ' ').replace('\r', '').strip()
                    if len(banner_clean) > 20: banner_clean = banner_clean[:17] + "..."
                    if len(service) > 8: service = service[:8]
                    
                    # Format row with visible length padding (for emoji support)
                    p_cell = pad_v(str(port_num), 5)
                    s_cell = pad_v(status_str, 8)
                    v_cell = pad_v(service, 8)
                    b_cell = pad_v(banner_clean, 20)
                    
                    line = f"│ {p_cell} │ {s_cell} │ {v_cell} │ {b_cell} │"
                    click.echo(_colored(line, B_WHITE))
                
                click.echo(_colored(grid_footer, B_WHITE))
            else:
                click.echo(_colored("\n[!] No real open ports detected on this target.", YELLOW))
            
            # Mission Summary Box
            click.echo("\n" + _colored("╔" + "═" * 38 + "╗", B_GREEN))
            click.echo(_colored("║", B_GREEN) + pad_v(f"  {_colored('MISSION RECONNAISSANCE SUMMARY', B_GREEN, bold=True)}", 38) + _colored("║", B_GREEN))
            click.echo(_colored("╠" + "═" * 38 + "╣", B_GREEN))
            click.echo(_colored("║", B_GREEN) + pad_v(f"  » ACTIVE SERVICES : {_colored(str(len(open_results)), B_WHITE, bold=True)}", 38) + _colored("║", B_GREEN))
            click.echo(_colored("║", B_GREEN) + pad_v(f"  » TOTAL ANALYZED  : {_colored(str(len(port_results)), B_WHITE)}", 38) + _colored("║", B_GREEN))
            click.echo(_colored("║", B_GREEN) + pad_v(f"  » ELAPSED TIME    : {_colored(f'{datetime.now() - start_time}', B_CYAN)}", 38) + _colored("║", B_GREEN))
            click.echo(_colored("╚" + "═" * 38 + "╝", B_GREEN))
