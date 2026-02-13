"""
Web Fuzzer (Directory/File Bruteforcer) Module
"""
import click
import json
import os
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE
from .go_bridge import GoEngine

@click.command()
@click.option('-u', '--url', required=True, help='Target URL')
@click.option('-w', '--wordlist', type=click.Path(exists=True), help='Path to wordlist')
@click.option('-x', '--extensions', help='Comma separated extensions (php,html,js)')
@click.option('-t', '--threads', default=50, type=int, help='Threads')
@click.option('--status', default='200,204,301,302,307,401,403', help='Status codes to display (default: 200,204,301,302,307,401,403)')
@click.option('--bypass', is_flag=True, help='Attempt 403 Bypass automatically')
@click.option('-o', '--output', help='Save output to JSON')
def fuzz(url, wordlist, extensions, threads, status, bypass, output):
    """
    Powerful Web Fuzzer (Go Engine).
    Recursive directory scanning, extension fuzzing, and 403 bypass.
    """
    display_tool_banner('Web Fuzzer (Go Engine)')
    
    # Handle wordlist logic
    if not wordlist:
        # Default to comprehensive wordlist if not provided
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        default_list = os.path.join(base_dir, 'wordlists', 'dicc.txt')
        
        if os.path.exists(default_list):
            click.echo(_colored(f"[*] No wordlist provided. Using default comprehensive list: {default_list}", CYAN))
            wordlist = default_list
        else:
            click.echo(_colored("[!] Default list not found. Please provide a wordlist with -w.", RED))
            # Fallback to creating a temp list? 
            # For Go engine, we need a file.
            # Let's create a temporary tiny list if needed.
            temp_list = os.path.join(os.path.dirname(__file__), 'temp_wordlist.txt')
            with open(temp_list, 'w') as f:
                f.write('\n'.join(['admin', 'login', 'dashboard', 'api', 'backup', 'config', 'uploads', 'images', 'js', 'css', '.env', '.git']))
            wordlist = temp_list
            click.echo(_colored("[!] Using temporary tiny fallback list.", YELLOW))

    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    click.echo(f"[*] Wordlist: {wordlist}")
    if extensions:
        click.echo(f"[*] Extensions: {extensions}")
    
    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return
    
    click.echo("\n[+] Starting Scan...\n")
    click.echo(f"{'CODE':<6} {'LENGTH':<10} {'URL':<50} {'TITLE/REDIRECT'}")
    click.echo("-" * 90)
    
    try:
        results = engine.run(
            url=url,
            wordlist=wordlist,
            extensions=extensions or "",
            status=status,
            threads=threads,
            bypass=bypass
        )
    except KeyboardInterrupt:
        click.echo("\n[!] Interrupted")
        return
    except Exception as e:
        click.echo(f"\n[!] Error: {e}")
        return

    # Check for general error
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        click.echo(f"\n[!] Scan Error: {results[0]['error']}")
        return

    # Print results
    for r in sorted(results, key=lambda x: x.get('status', 0)):
        code = r.get('status', 0)
        length = r.get('length', 0)
        u = r.get('url', '')
        title = r.get('title', '')
        redirect = r.get('redirect', '')
        
        info = title
        if code in [301, 302, 307] and redirect:
            info = f"-> {redirect}"
        elif r.get('is_bypass'):
            info = f"[BYPASS SUCCESS] {r.get('payload')}"
            
        color = GREEN
        if code in [301, 302]: color = CYAN
        elif code in [403, 401]: color = YELLOW
        elif code >= 500: color = RED
        
        if r.get('is_bypass'):
            color = GREEN # Highlight bypass success
            
        row = f"{code:<6} {length:<10} {u:<50} {info}"
        click.echo(_colored(row, color))
        
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Saved to {output}")
