"""
Advanced Port Scanner (Nmap-Style)
Rombak total dengan atribut lengkap untuk powerfull scanning.
"""
import click
import json
import os
import sys
import time as _time
from datetime import datetime
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, BLUE, CYAN, PURPLE, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM
from .go_bridge import get_engine
from .targets import parse_targets, parse_ports
from hackit.subdomain.go_bridge import get_engine as get_sub_engine

@click.command()
# ============================== 
# TARGET CONTROL 
# ============================== 
@click.option('-u', '--host', 'host', help='Target host (IP / domain)')
@click.option('--host-file', type=click.Path(exists=True), help='File berisi daftar target')
@click.option('--skip-host', help='Exclude target tertentu')
@click.option('--skip-file', type=click.Path(exists=True), help='File exclude target')
@click.option('--enable-ipv6', is_flag=True, help='Aktifkan IPv6')
@click.option('--force-resolve', is_flag=True, help='Resolve DNS sebelum scan')

# ============================== 
# PORT CONTROL 
# ============================== 
@click.option('-p', '--ports', help='Port spesifik (80,443,22)')
@click.option('--range', 'port_range', help='Range port (1-1000)')
@click.option('--popular', is_flag=True, help='Scan port populer')
@click.option('--top-ports', type=int, help='Scan N port paling populer (misal: 100)')
@click.option('--full-range', is_flag=True, help='Scan seluruh port (1-65535)')
@click.option('--omit-ports', help='Exclude port tertentu')

# ============================== 
# SCAN MODES 
# ============================== 
@click.option('--scan', type=click.Choice(['connect', 'stealth', 'udp', 'ack', 'null', 'fin', 'xmas', 'window', 'maimon']), default='connect', help='Tentukan mode scan (Scalable Mode)')
@click.option('--engine', type=click.Choice(['go', 'rust', 'c', 'cpp', 'lua', 'python', 'ruby']), default='go', help='Pilih engine utama (Multi-Engine support)')
@click.option('--connect', is_flag=True, help='Full TCP handshake scan (Legacy flag)')
@click.option('--stealth', is_flag=True, help='Silent half-open scan (SYN) (Legacy flag)')
@click.option('--udp', is_flag=True, help='UDP port scan (Legacy flag)')
@click.option('--ack-check', is_flag=True, help='Firewall ACK test (Legacy flag)')
@click.option('--null-probe', is_flag=True, help='Empty flag scan (Legacy flag)')
@click.option('--fin-probe', is_flag=True, help='FIN packet scan (Legacy flag)')
@click.option('--xmas-probe', is_flag=True, help='Multi-flag stealth scan (Legacy flag)')
@click.option('--window-check', is_flag=True, help='TCP window analysis (Legacy flag)')
@click.option('--maimon-probe', is_flag=True, help='Advanced FIN/ACK probe (Legacy flag)')

# ============================== 
# PERFORMANCE TUNING 
# ============================== 
@click.option('--workers', default=100, type=int, help='Jumlah concurrent worker')
@click.option('--speed', default=3, type=click.IntRange(1, 5), help='Scan intensity (1-5)')
@click.option('--max-rate', type=int, help='Max request per second')
@click.option('--wait', default=1000, type=int, help='Timeout per port (ms)')
@click.option('--retry', default=1, type=int, help='Retry attempt')
@click.option('--cooldown', default=0, type=int, help='Delay antar batch (ms)')

# ============================== 
# SERVICE ANALYSIS 
# ============================== 
@click.option('--detect-service', is_flag=True, help='Service detection')
@click.option('--grab-banner', is_flag=True, help='Banner grabbing')
@click.option('--identify-os', is_flag=True, help='OS fingerprint')
@click.option('--analyze-protocol', is_flag=True, help='Protocol fingerprint')
@click.option('--http-inspect', is_flag=True, help='HTTP inspection')
@click.option('--tech-analyze', is_flag=True, help='Web technology detection')

# ============================== 
# WEB EXTENSIONS 
# ============================== 
@click.option('--http-method', default='GET', help='Custom HTTP method')
@click.option('--http-endpoint', default='/', help='Custom path')
@click.option('--follow', is_flag=True, help='Follow redirect')
@click.option('--show-status', is_flag=True, help='Show HTTP status')
@click.option('--show-title', is_flag=True, help='Extract page title')
@click.option('--tls-analyze', is_flag=True, help='TLS detail info')
@click.option('--cert-view', is_flag=True, help='SSL certificate info')

# ============================== 
# NETWORK INTEL 
# ============================== 
@click.option('--dns-info', is_flag=True, help='DNS lookup')
@click.option('--reverse-lookup', is_flag=True, help='Reverse DNS')
@click.option('--sub-enum', is_flag=True, help='Subdomain discovery')
@click.option('--whois-info', is_flag=True, help='Whois lookup')
@click.option('--geo-info', is_flag=True, help='GeoIP lookup')
@click.option('--asn-info', is_flag=True, help='ASN lookup')

# ============================== 
# MODULE SYSTEM 
# ============================== 
@click.option('--run-module', help='Jalankan module tertentu')
@click.option('--module-path', help='Custom module directory')
@click.option('--list-module', is_flag=True, help='List module tersedia')
@click.option('--auto-vuln', is_flag=True, help='Jalankan vulnerability check')
@click.option('--default-check', is_flag=True, help='Jalankan check bawaan')

# ============================== 
# OUTPUT CONTROL 
# ============================== 
@click.option('--output-text', help='Output normal')
@click.option('--output-json', help='Output JSON')
@click.option('--output-xml', help='Output XML')
@click.option('--output-csv', help='Output CSV')
@click.option('--output-all', help='Semua format (base name)')
@click.option('--verbose', is_flag=True, help='Verbose mode')
@click.option('--debug-mode', is_flag=True, help='Debug mode')
@click.option('--quiet', is_flag=True, help='Silent mode')
@click.option('--no-style', is_flag=True, help='Nonaktifkan warna')

# ============================== 
# STEALTH & ADVANCED 
# ============================== 
@click.option('--ghost-scan', is_flag=True, help='Ultra-stealth mode (Decoys + Slow + Random)')
@click.option('--turbo-scan', is_flag=True, help='Maximum speed and concurrency')
@click.option('--deep-scan', is_flag=True, help='Service + OS + Script + Intel')
@click.option('--detect-honeypot', is_flag=True, help='Check for potential honeypots')
@click.option('--smart-bypass', is_flag=True, help='Try automatic firewall bypass')
@click.option('--mask-ip', help='Spoof source IP')
@click.option('--random-order', is_flag=True, help='Randomize target')
@click.option('--decoy-ip', help='Gunakan IP decoy (comma separated)')
@click.option('--packet-split', is_flag=True, help='Fragment packet')
@click.option('--custom-ttl', type=int, help='Custom TTL')
@click.option('--spoof-mac', help='Spoof MAC')
@click.option('--use-proxy', help='Gunakan proxy (http://ip:port)')
@click.option('--use-tor', is_flag=True, help='Route via TOR')
@click.option('--mtu', type=int, help='Set MTU size for fragmentation')
@click.option('--data-length', type=int, help='Append random data to packets')
@click.option('--source-port', type=int, help='Set custom source port')
@click.option('--proxies', help='List of proxies (file path)')
@click.option('--script', help='Run specific Lua scripts (NSE-style)')
@click.option('--script-args', help='Arguments for Lua scripts')
@click.option('--version-intensity', type=int, default=7, help='Intensity for version detection (0-9)')
@click.option('--osscan-limit', is_flag=True, help='Limit OS detection to promising targets')
@click.option('--osscan-guess', is_flag=True, help='Guess OS more aggressively')
@click.option('--host-timeout', type=int, help='Give up on target after X ms')
@click.option('--scan-delay', type=int, help='Delay between probes (ms)')
@click.option('--max-scan-delay', type=int, help='Max delay between probes (ms)')
@click.option('--defeat-rst-ratelimit', is_flag=True, help='Bypass RST rate limits')
@click.option('--defeat-icmp-ratelimit', is_flag=True, help='Bypass ICMP rate limits')
@click.option('--nsock-engine', type=click.Choice(['epoll', 'kqueue', 'poll', 'select']), help='Select nsock IO engine')

# ============================== 
# NMAP PARITY (NEW)
# ============================== 
@click.option('-sS', 'scan_syn', is_flag=True, help='TCP SYN scan')
@click.option('-sT', 'scan_connect', is_flag=True, help='TCP Connect scan')
@click.option('-sU', 'scan_udp', is_flag=True, help='UDP scan')
@click.option('-sV', 'scan_version', is_flag=True, help='Version detection')
@click.option('-O', 'scan_os', is_flag=True, help='OS detection')
@click.option('-A', 'scan_aggressive', is_flag=True, help='Aggressive scan (OS, Version, Scripts, Traceroute)')
@click.option('-Pn', 'no_ping', is_flag=True, help='Treat all hosts as online')
@click.option('-F', 'fast_scan', is_flag=True, help='Fast mode - Scan fewer ports')
@click.option('-r', 'no_random_ports', is_flag=True, help='Don\'t randomize ports')
@click.option('--top-ports-nmap', 'top_ports_n', type=int, help='Scan <number> most common ports')
@click.option('-T', 'timing_template', type=click.IntRange(0, 5), help='Set timing template (0-5)')
@click.option('-f', 'fragment_packets', is_flag=True, help='Fragment packets')
@click.option('-S', 'spoof_source', help='Spoof source address')
@click.option('-e', 'interface', help='Use specified interface')
@click.option('-g', 'source_port_nmap', type=int, help='Use given port number')
@click.option('--proxies-nmap', 'proxies_list', help='Relay connections through HTTP/SOCKS4 proxies')
@click.option('--data', 'hex_data', help='Append custom binary data')
@click.option('--data-string', help='Append custom ASCII string')
@click.option('--data-length-nmap', 'data_len', type=int, help='Append random data')
@click.option('--ttl', 'ttl_val', type=int, help='Set IP time-to-live field')
@click.option('--spoof-mac-nmap', 'mac_addr', help='Spoof MAC address')
@click.option('--badsum', is_flag=True, help='Send packets with a bogus TCP/UDP/SCTP checksum')
@click.option('-sC', 'default_scripts', is_flag=True, help='Equivalent to --script=default')
@click.option('--script-nmap', 'script_list', help='Comma separated list of scripts')
@click.option('--script-args-nmap', 'script_args_val', help='Arguments for scripts')
@click.option('--script-help', help='Show help about scripts')
@click.option('--traceroute', is_flag=True, help='Trace hop path to each host')
@click.option('--reason', is_flag=True, help='Display the reason a port is in a particular state')
@click.option('--open-only', 'open_only', is_flag=True, help='Only show open (or possibly open) ports')
@click.option('--packet-trace', is_flag=True, help='Show all packets sent and received')
@click.option('--iflist', is_flag=True, help='List interfaces and routes')
@click.option('--resume', 'resume_file', help='Resume an aborted scan')

# ============================== 
# DISCOVERY OPTIONS 
# ============================== 
@click.option('--ping-scan', is_flag=True, help='Ping only')
@click.option('--skip-discovery', is_flag=True, help='Skip host discovery')
@click.option('--smart-discovery', is_flag=True, help='Adaptive host discovery')

# ============================== 
# ENGINE CONTROL 
# ============================== 
@click.option('--config-file', type=click.Path(exists=True), help='Load config file')
@click.option('--workspace', help='Workspace directory')
@click.option('--resume-scan', help='Resume scan from session ID')
@click.option('--engine-update', is_flag=True, help='Update engine')
@click.option('--show-version', is_flag=True, help='Show tool version')
@click.option('--os-detection', is_flag=True, help='Os deteksi')
@click.option('--fast', is_flag=True, help='Optimize for speed')

def scan_ports(**kwargs):
    """
    Super Powerful Port Scanner (Go-Powered) - Nmap Version.
    """
    import sys
    if kwargs.get('show_version'):
        click.echo("HackIt Port Scanner v2.0.0")
        return

    display_tool_banner('Port Scanner Tools')
    
    engine = get_engine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    # 1. Parse Targets
    target_list = []
    if kwargs.get('host'):
        target_list = parse_targets(kwargs.get('host'))
    elif kwargs.get('host_file'):
        target_list = parse_targets(f"@{kwargs.get('host_file')}")
    else:
        click.echo(_colored("[!] Target host atau host-file harus disediakan.", RED))
        return

    if not target_list:
        click.echo(_colored("[!] Tidak ada target valid ditemukan.", RED))
        return

    # 2. Port Selection
    ports_str = parse_ports(
        kwargs.get('ports'), 
        kwargs.get('port_range'), 
        kwargs.get('popular') or kwargs.get('fast_scan'), 
        kwargs.get('full_range'),
        top_n=kwargs.get('top_ports') or kwargs.get('top_ports_n')
    )
    
    # 3. Determine Scan Mode
    scan_mode = kwargs.get('scan') # Default from Choice is 'connect'
    
    # Engine specific mode adjustment
    selected_engine = kwargs.get('engine', 'go')
    if selected_engine == 'rust':
        scan_mode = "syn" # Rust is used for SYN scanning
    elif selected_engine == 'c':
        scan_mode = "c-turbo"
    elif selected_engine == 'ruby':
        scan_mode = "ruby"
    
    # Priority for legacy and Nmap-style flags
    if kwargs.get('udp') or kwargs.get('scan_udp'): scan_mode = "udp"
    elif kwargs.get('stealth') or kwargs.get('scan_syn'): scan_mode = "syn"
    elif kwargs.get('scan_connect'): scan_mode = "connect"
    elif kwargs.get('fin_probe'): scan_mode = "fin"
    elif kwargs.get('xmas_probe'): scan_mode = "xmas"
    elif kwargs.get('null_probe'): scan_mode = "null"
    elif kwargs.get('ack_check'): scan_mode = "ack"
    elif kwargs.get('window_check'): scan_mode = "window"
    elif kwargs.get('maimon_probe'): scan_mode = "maimon"

    # Aggressive mode (-A)
    if kwargs.get('scan_aggressive') or kwargs.get('deep_scan'):
        kwargs['detect_service'] = True
        kwargs['os_detection'] = True
        kwargs['default_scripts'] = True
        kwargs['enrich'] = True
    
    # Ghost mode logic
    if kwargs.get('ghost_scan'):
        kwargs['stealth'] = True
        kwargs['timing_template'] = 1 # Sneaky
        kwargs['packet_split'] = True
        kwargs['random_order'] = True
    
    # Turbo mode logic
    if kwargs.get('turbo_scan'):
        kwargs['timing_template'] = 5 # Insane
        kwargs['fast'] = True
    
    # Honeypot detection
    if kwargs.get('detect_honeypot'):
        kwargs['script'] = 'honeypot-detect'
    
    # Smart bypass
    if kwargs.get('smart_bypass'):
        kwargs['packet_split'] = True
        kwargs['badsum'] = True
        kwargs['custom_ttl'] = 128
    
    click.echo(f"[*] Engine: {_colored('HackIT', GREEN)}")
    click.echo(f"[*] Mode: {_colored(scan_mode.upper(), CYAN)}")
    click.echo(f"[*] Targets: {len(target_list)} hosts")

    # 4. Execution Logic
    start_time = datetime.now()
    all_results = []
    
    # Timing templates mapping (Nmap-style T0-T5)
    timing_map = {
        0: {'timeout': 10000, 'workers': 1, 'cooldown': 300000}, # Paranoid
        1: {'timeout': 5000, 'workers': 5, 'cooldown': 15000},   # Sneaky
        2: {'timeout': 3000, 'workers': 20, 'cooldown': 1000},  # Polite
        3: {'timeout': 1000, 'workers': 100, 'cooldown': 0},    # Normal
        4: {'timeout': 500, 'workers': 200, 'cooldown': 0},     # Aggressive
        5: {'timeout': 200, 'workers': 500, 'cooldown': 0},     # Insane
    }
    
    t_idx = kwargs.get('timing_template', 3)
    t_conf = timing_map.get(t_idx, timing_map[3])
    
    wait = kwargs.get('wait') or t_conf['timeout']
    workers = kwargs.get('workers') or t_conf['workers']
    cooldown = kwargs.get('cooldown', 0)

    # Map Nmap-style OS/Service flags
    if kwargs.get('scan_os'): kwargs['os_detection'] = True
    if kwargs.get('scan_version'): kwargs['detect_service'] = True
    if kwargs.get('default_scripts'): kwargs['script'] = 'default'
    if kwargs.get('script_list'): kwargs['script'] = kwargs.get('script_list')
    if kwargs.get('script_args_val'): kwargs['script_args'] = kwargs.get('script_args_val')
    if kwargs.get('ttl_val'): kwargs['custom_ttl'] = kwargs.get('ttl_val')
    if kwargs.get('data_len'): kwargs['data_length'] = kwargs.get('data_len')
    if kwargs.get('source_port_nmap'): kwargs['source_port'] = kwargs.get('source_port_nmap')
    if kwargs.get('mac_addr'): kwargs['spoof_mac'] = kwargs.get('mac_addr')
    if kwargs.get('fragment_packets'): kwargs['packet_split'] = True

    # State tracking for powerful tactical UI
    results_cache = []
    last_status = {"msg": "", "time": _time.time()}
    
    def scan_callback(type, data):
        nonlocal last_status
        if type == "status":
            # Real-time status ticker (Non-intrusive)
            msg = data.get('message', '')
            if msg:
                ticker = _colored(f"\r  » [TACTICAL] {msg}...", DIM)
                sys.stdout.write(ticker + "\033[K")
                sys.stdout.flush()
                last_status = {"msg": msg, "time": _time.time()}
        elif type == "result":
            status = data.get('status', 'unknown')
            port = data.get('port', 0)
            if status == 'open' and port > 0:
                if not any(r.get('port') == port for r in results_cache):
                    results_cache.append(data)
                sys.stdout.flush()

    # Apply Power-Scan Enhancements
    kwargs['turbo_scan'] = True
    kwargs['workers'] = kwargs.get('workers', 250) # Boost default concurrency
    kwargs['timeout'] = kwargs.get('wait', 800)     # Aggressive timing

    for t in target_list:
        click.echo(f"\n" + _colored("┌── [POWERFUL RECONNAISSANCE INITIALIZED]", B_CYAN))
        click.echo(_colored("│", B_CYAN) + f" TARGET NODE: {_colored(t, B_WHITE, bold=True)}")
        click.echo(_colored("│", B_CYAN) + f" SCAN ENGINE: {_colored('MULTI-SYNC (GO+RUST+LUA)', GREEN)}")
        click.echo(_colored("└" + "─" * 40, B_CYAN) + "\n")
        
        results_cache = []
        last_status = {"msg": "", "time": _time.time()}
        
        # Mapping kwargs to engine params
        engine_kwargs = kwargs.copy()
        engine_kwargs.pop('ports', None)
        engine_kwargs.pop('timeout', None)
        engine_kwargs.pop('threads', None)
        engine_kwargs.pop('include_closed', None)
        engine_kwargs.pop('stealth', None)
        engine_kwargs.pop('mode', None)
        engine_kwargs.pop('callback', None)

        engine_res = engine.run(
            t,
            ports=ports_str,
            timeout=kwargs.get('wait', 1000),
            threads=kwargs.get('workers', 100),
            include_closed=False,
            stealth=kwargs.get('stealth') or scan_mode == 'stealth',
            mode=scan_mode,
            callback=scan_callback,
            **engine_kwargs
        )
        
        # Add to all results for output saving
        all_results.append(engine_res)

        # Display Professional IP Intelligence Section (Tactical Overview)
        intel = engine_res.get('intel', {})
        os_info = engine_res.get('os', {})
        ip_addr = engine_res.get('ip', 'Unknown')
        
        click.echo(f"\n" + _colored("╔══════════════════════════════════════════════════════════════════════════════╗", B_WHITE))
        click.echo(_colored("║", B_WHITE) + f"  {_colored('TACTICAL IP INTELLIGENCE GRID', B_WHITE):<75} " + _colored("║", B_WHITE))
        click.echo(_colored("╠══════════════════════════════════════════════════════════════════════════════╣", B_WHITE))
        click.echo(_colored("║", B_WHITE) + f"  » TARGET IP   : {_colored(ip_addr, B_YELLOW):<64} " + _colored("║", B_WHITE))
        
        if intel.get('asn') and intel['asn'] != 'N/A':
            click.echo(_colored("║", B_WHITE) + f"  » ASN/ORG     : {intel['asn']:<64} " + _colored("║", B_WHITE))
        
        if intel.get('geo') and intel['geo'] != 'N/A':
            click.echo(_colored("║", B_WHITE) + f"  » GEOLOCATION : {intel['geo']:<64} " + _colored("║", B_WHITE))
            
        if intel.get('dns'):
            dns_str = ", ".join(intel['dns'][:2]) # Show top 2 for spacing
            click.echo(_colored("║", B_WHITE) + f"  » DNS RECORDS : {dns_str:<64} " + _colored("║", B_WHITE))

        os_name = os_info.get('name', 'Unknown')
        if os_name != 'Unknown':
            conf = os_info.get('confidence', os_info.get('accuracy', 0))
            os_display = f"{os_name} ({conf}%)"
            click.echo(_colored("║", B_WHITE) + f"  » OS FINGERPRNT: {_colored(os_display, B_GREEN):<75} " + _colored("║", B_WHITE))
            
        click.echo(_colored("╚══════════════════════════════════════════════════════════════════════════════╝", B_WHITE))

        # Subdomain Enumeration
        if kwargs.get('sub_enum'):
            click.echo(f"\n[*] Enumerating subdomains for {t}...")
            sub_engine = get_sub_engine()
            if sub_engine.available:
                sub_engine.run(domain=t, passive_only=True)
            else:
                click.echo(_colored("[!] Subdomain engine not available.", RED))

    # 5. Handle Output Formats
    if kwargs.get('output_json'):
        with open(kwargs.get('output_json'), 'w') as f:
            json.dump(all_results, f, indent=4)
        click.echo(_colored(f"\n[+] Results saved to JSON: {kwargs.get('output_json')}", GREEN))

    if kwargs.get('output_csv'):
        import csv
        with open(kwargs.get('output_csv'), 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'IP', 'Port', 'Status', 'Service', 'Version'])
            for res in all_results:
                host = res.get('host')
                ip = res.get('ip')
                for p in res.get('results', []):
                    writer.writerow([host, ip, p.get('port'), p.get('status'), p.get('service'), p.get('version')])
        click.echo(_colored(f"[+] Results saved to CSV: {kwargs.get('output_csv')}", GREEN))

    if kwargs.get('output_xml'):
        try:
            import xml.etree.ElementTree as ET
            root = ET.Element("scan_results")
            for res in all_results:
                target_node = ET.SubElement(root, "target", host=res.get('host'), ip=res.get('ip'))
                ports_node = ET.SubElement(target_node, "ports")
                for p in res.get('results', []):
                    ET.SubElement(ports_node, "port", 
                                 id=str(p.get('port')), 
                                 status=p.get('status'), 
                                 service=p.get('service'), 
                                 version=p.get('version'))
            tree = ET.ElementTree(root)
            tree.write(kwargs.get('output_xml'))
            click.echo(_colored(f"[+] Results saved to XML: {kwargs.get('output_xml')}", GREEN))
        except Exception as e:
            click.echo(_colored(f"[!] Failed to save XML: {e}", RED))

    duration = datetime.now() - start_time
    click.echo(f"\n[*] Scan finished in {duration.total_seconds():.2f}s")
