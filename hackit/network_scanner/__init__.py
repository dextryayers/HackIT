import click
import json
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from .go_bridge import GoEngine
from hackit.ui import display_tool_banner, _colored, BLUE, GREEN, RED, YELLOW, B_CYAN, B_GREEN, B_RED, B_YELLOW, DIM, B_WHITE, RESET


def _resolve_hostname(ip: str, timeout: float = 1.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.getfqdn(ip)
    except Exception:
        return ""


def _tcp_ping(ip: str, port: int = 80, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _scan_host(ip_str: str, ports: List[int], timeout: float) -> Optional[Dict[str, Any]]:
    for port in ports:
        if _tcp_ping(ip_str, port, timeout):
            hostname = _resolve_hostname(ip_str, timeout)
            open_ports = []
            for p in ports:
                if _tcp_ping(ip_str, p, timeout):
                    open_ports.append(p)
            return {
                'ip': ip_str,
                'hostname': hostname if hostname != ip_str else '',
                'alive': True,
                'open_ports': open_ports,
                'latency_ms': 0,
            }
    return None


def _python_scan(cidr: str, ports: List[int], timeout: float, threads: int,
                 verbose: bool = False) -> Dict[str, Any]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {'error': str(e), 'alive_count': 0, 'hosts': []}

    total = network.num_addresses
    if total > 65536:
        return {'error': f'Network too large: {total} hosts. Max 65536.', 'alive_count': 0, 'hosts': []}

    hosts = []
    scanned = 0
    start = time.time()

    ips = [str(ip) for ip in network.hosts()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for ip_str in ips:
            f = executor.submit(_scan_host, ip_str, ports, timeout)
            futures[f] = ip_str

        for future in as_completed(futures):
            scanned += 1
            try:
                result = future.result(timeout=timeout * 2)
                if result:
                    hosts.append(result)
                    if verbose:
                        click.echo(f"  {_colored('[+]', GREEN)} {_colored(result['ip'], B_GREEN)} alive"
                                 + (f" ({result['hostname']})" if result['hostname'] else ""))
            except Exception:
                pass

    elapsed = time.time() - start

    return {
        'cidr': cidr,
        'alive_count': len(hosts),
        'total_scanned': scanned,
        'hosts': sorted(hosts, key=lambda h: ipaddress.ip_address(h['ip'])),
        'scan_time': round(elapsed, 2),
    }


def _display_results(results: Dict[str, Any]):
    alive = results.get('alive_count', 0)
    total = results.get('total_scanned', 0)
    scan_time = results.get('scan_time', 0)
    hosts = results.get('hosts', [])

    click.echo(f"\n  {_colored('SCAN RESULTS', B_WHITE, bold=True)}")
    click.echo(f"  {_colored('=' * 60, DIM)}")
    click.echo(f"  Network      : {_colored(results.get('cidr', 'N/A'), B_CYAN)}")
    click.echo(f"  Alive Hosts  : {_colored(str(alive), B_GREEN)} / {total}")
    click.echo(f"  Scan Time    : {_colored(f'{scan_time}s', B_CYAN)}")
    click.echo(f"  {_colored('-' * 60, DIM)}")

    if hosts:
        click.echo(f"\n  {'IP Address':<20} {'Hostname':<30} {'Open Ports':<15}")
        click.echo(f"  {'-'*20} {'-'*30} {'-'*15}")
        for host in hosts:
            ip = host.get('ip', 'N/A')
            hostname = host.get('hostname', '') or '-'
            open_ports = host.get('open_ports', [])
            ports_str = ','.join(str(p) for p in open_ports[:5])
            if len(open_ports) > 5:
                ports_str += f"+{len(open_ports)-5}"
            click.echo(f"  {_colored(ip, B_GREEN):<30} {hostname:<30} {_colored(ports_str or '-', B_CYAN)}")
    else:
        click.echo(f"\n  {_colored('[*] No alive hosts detected.', DIM)}")

    click.echo(f"\n  {_colored('=' * 60, DIM)}")


@click.command()
@click.argument('cidr')
@click.option('-o', '--output', help='Save results to JSON file')
@click.option('-p', '--ports', default='21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443',
              help='Ports to probe (comma separated)')
@click.option('-t', '--timeout', default=1.0, type=float, help='Connection timeout per host (seconds)')
@click.option('-w', '--threads', default=100, type=int, help='Concurrent scan threads')
@click.option('--no-go', is_flag=True, help='Force Python engine (skip Go)')
@click.option('--verbose', '-v', is_flag=True, help='Show live discoveries')
@click.option('--json-only', is_flag=True, help='Output JSON only')
@click.option('--resolve', is_flag=True, help='Resolve all hostnames (slower)')
def scan_range(cidr, output, ports, timeout, threads, no_go, verbose, json_only, resolve):
    """Network Scanner - Alive Host Detection (Go + Python Dual Engine)

    Scans a CIDR range for alive hosts using TCP probes.

    Examples:

      hackit recon ips 192.168.1.0/24

      hackit recon ips 10.0.0.0/16 -w 200 -p 22,80,443

      hackit recon ips 192.168.1.0/24 --verbose -o results.json
    """
    if not json_only:
        display_tool_banner('IP RANGE SCANNER')
        click.echo(f"  [*] Target Network: {_colored(cidr, BLUE)}")

    port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]

    go_success = False
    if not no_go:
        try:
            engine = GoEngine()
            if engine.available:
                if not engine.ensure_compiled():
                    if not json_only:
                        click.echo(_colored("  [*] Go engine compilation failed, using Python fallback...", DIM))
                else:
                    if not json_only:
                        click.echo(f"  [*] Engine: {_colored('Go (native)', B_GREEN)}")
                        click.echo("  [*] Detecting alive hosts (TCP Ping)...")
                    results = engine.run(cidr, timeout=int(timeout * 1000), threads=threads)

                    if 'error' not in results:
                        go_success = True
                        if json_only:
                            click.echo(json.dumps(results, indent=2, default=str))
                        else:
                            _display_results(results)

                        if output:
                            with open(output, 'w') as f:
                                json.dump(results, f, indent=2, default=str)
                            if not json_only:
                                click.echo(_colored(f"\n  [+] Results saved to {output}", B_GREEN))
                        return
        except Exception:
            pass

    if not go_success:
        if not json_only:
            click.echo(f"  [*] Engine: {_colored('Python (threaded)', B_YELLOW)}")
            click.echo(f"  [*] Probing {len(port_list)} ports across {cidr}...")

        results = _python_scan(cidr, port_list, timeout, threads, verbose)

        if 'error' in results:
            click.echo(_colored(f"  [!] Error: {results['error']}", RED))
            return

        if json_only:
            click.echo(json.dumps(results, indent=2, default=str))
        else:
            _display_results(results)

        if output:
            with open(output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            if not json_only:
                click.echo(_colored(f"\n  [+] Results saved to {output}", B_GREEN))
