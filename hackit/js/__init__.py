"""
JS Analyzer Module
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, YELLOW, DIM, TablePrinter
from .go_bridge import GoEngine

@click.command()
@click.option('-u', '--url', required=True, help='Target Website URL')
@click.option('-o', '--output', help='Save results to JSON')
def analyze_js(url, output):
    """JS Hunter Ultra - Deep Recon Crawler (Katana Elite)"""
    # Force HTTPS if no protocol specified
    if not url.startswith('http'):
        url = f"https://{url}"
        
    banner = _colored(r"""
      _  _____   _   _ _   _ _   _ _____ _____ _____ 
     | |/ ____| | | | | | | | \ | |_   _|  ___|  __ \
     | | (___   | |_| | | | |  \| | | | | |__ | |__) |
 _   | |\___ \  |  _  | | | | . ` | | | |  __||  _  / 
| |__| |____) | | | | | |_| | |\  |_| |_| |___| | \ \ 
 \____/|_____/  |_| |_|\___/|_| \_|_____|_____|_|  \_\
    """, GREEN, bold=True)
    
    click.echo(banner)
    click.echo(_colored(f"        [ HACKIT V2.1 - JS HUNTER ELITE ]", YELLOW, bold=True))
    click.echo(_colored(f"  " + "-" * 56, DIM))
    print()
    
    # Disclaimer matching the photo
    wrn = _colored("[WRN]", YELLOW)
    click.echo(f"{wrn} Use with caution. You are responsible for your actions.")
    click.echo(f"{wrn} Developers assume no liability and are not responsible for any misuse or damage.\n")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    # click.echo("[*] Initiating real-time discovery...")
    all_results = []
    found_any = False
    
    try:
        for result in engine.run(url):
            if not isinstance(result, dict):
                continue

            if 'error' in result:
                click.echo(_colored(f"[!] Engine Error: {result['error']}", RED))
                continue
                
            found_any = True
            all_results.append(result)
            
            # Print URL immediately (Katana style)
            click.echo(result.get('url'))
            
    except KeyboardInterrupt:
        click.echo(_colored("\n[!] Scan interrupted by user.", YELLOW))

    if not found_any:
        click.echo(_colored(f"[*] No artifacts discovered on {url}", YELLOW))

    if output and all_results:
        with open(output, 'w') as f:
            json.dump({"results": all_results, "target": url}, f, indent=2)
        # click.echo(f"\n[+] Ultra report saved to: {_colored(output, GREEN)}")
