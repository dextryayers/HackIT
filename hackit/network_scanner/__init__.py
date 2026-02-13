import click
from .go_bridge import GoEngine
from hackit.ui import display_tool_banner, _colored, BLUE, GREEN, RED, YELLOW

@click.command()
@click.argument('cidr')
@click.option('-o', '--output', help='Output file to save results')
def scan_range(cidr, output):
    """
    Network Scanner powered by Go.
    """
    display_tool_banner('Network Scanner (Go Engine)')
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    click.echo(f"[*] Scanning Network: {_colored(cidr, BLUE)}")
    click.echo("[*] Detecting alive hosts (TCP Ping)...")
    
    # Run Go Engine
    # Default timeout 1000ms, threads 100
    results = engine.run(cidr, timeout=1000, threads=100)
    
    if 'error' in results:
        click.echo(_colored(f"[!] Error: {results['error']}", RED))
        return

    alive_count = results.get('alive_count', 0)
    hosts = results.get('hosts', [])
    
    click.echo(f"\n[*] Scan Complete. Found {_colored(str(alive_count), GREEN)} alive hosts.\n")
    
    if alive_count > 0:
        click.echo(f"{'IP Address':<20} {'Hostname':<30}")
        click.echo("-" * 50)
        for host in hosts:
            ip = host.get('ip', 'N/A')
            hostname = host.get('hostname', '')
            click.echo(f"{_colored(ip, GREEN):<30} {hostname:<30}")
            
    if output:
        # Save to file logic if needed, for now just print
        pass
