"""
Dir Finder Module (Expert Rust + Go Engine)
"""
import click
import json
import os
import subprocess
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE

@click.command()
# TARGET OPTIONS
@click.option('-u', '--url', required=True, help='Target URL')
@click.option('-l', '--list', 'wordlist', help='Wordlist file')
@click.option('--stdin', is_flag=True, help='Read wordlist from STDIN')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST', 'HEAD']), help='HTTP method (default: GET)')
@click.option('--data', help='POST body data')
@click.option('-H', '--header', multiple=True, help='Custom header (repeatable, format: "Key: Value")')
@click.option('--cookie', help='Set cookie')
@click.option('--auth', help='Basic authentication (user:pass)')
@click.option('--proxy', help='Use proxy (http://ip:port)')
@click.option('--user-agent', help='Custom user agent')

# PERFORMANCE OPTIONS
@click.option('-t', '--threads', default=50, type=int, help='Number of threads (default: 50)')
@click.option('--timeout', default=10, type=int, help='Request timeout in seconds (default: 10)')
@click.option('--delay', default=0, type=int, help='Delay between requests in ms')
@click.option('--retries', default=2, type=int, help='Retry failed requests (default: 2)')
@click.option('--random-agent', is_flag=True, help='Randomize User-Agent')
@click.option('--http2', is_flag=True, help='Enable HTTP/2')
@click.option('--follow-redirect', is_flag=True, help='Follow HTTP redirects')
@click.option('--max-redirect', default=5, type=int, help='Max redirect depth')

# SCANNING OPTIONS
@click.option('-e', '--extensions', help='File extensions to append (comma separated)')
@click.option('--no-extension', is_flag=True, help='Disable extension appending')
@click.option('--recursive', is_flag=True, help='Enable recursive scanning')
@click.option('--depth', default=2, type=int, help='Max recursion depth (default: 2)')
@click.option('--force-extension', is_flag=True, help='Force add extension')
@click.option('--prefix', help='Add prefix to words')
@click.option('--suffix', help='Add suffix to words')
@click.option('--exclude-status', help='Exclude HTTP status codes (comma separated)')
@click.option('--include-status', help='Include only HTTP status codes (comma separated)')
@click.option('--exclude-length', help='Exclude by response length (comma separated)')
@click.option('--include-length', help='Include by response length (comma separated)')

# DETECTION OPTIONS
@click.option('--detect-waf', is_flag=True, help='Detect WAF')
@click.option('--detect-tech', is_flag=True, help='Detect technology stack')
@click.option('--detect-cms', is_flag=True, help='Detect CMS')
@click.option('--detect-backup', is_flag=True, help='Search backup files (.bak, .old, etc)')
@click.option('--smart-filter', is_flag=True, help='Auto-detect false positives')
@click.option('--wildcard-detect', is_flag=True, help='Detect wildcard responses')

# ADVANCED OPTIONS
@click.option('--fuzz', help='Fuzz parameter')
@click.option('--api-mode', is_flag=True, help='Optimize for API endpoint scanning')
@click.option('--json-body', is_flag=True, help='Send JSON body')
@click.option('--graphql', is_flag=True, help='GraphQL mode')
@click.option('--upload-test', is_flag=True, help='Test upload endpoints')
@click.option('--rate-limit', type=int, help='Limit requests per second')
@click.option('--rotate-proxy', help='Rotate proxies from file')
@click.option('--tor', is_flag=True, help='Use Tor network')

# OSINT / SMART MODE
@click.option('--auto-wordlist', is_flag=True, help='Generate wordlist from target (Smart Mode)')
@click.option('--crawl', is_flag=True, help='Crawl target before brute force')
@click.option('--extract-js', is_flag=True, help='Extract endpoints from JS files')
@click.option('--subdomain-mode', is_flag=True, help='Enable subdomain brute force')
@click.option('--asset-discovery', is_flag=True, help='Discover static assets')

# OUTPUT OPTIONS
@click.option('-o', '--output', help='Save results to file')
@click.option('--format', type=click.Choice(['txt', 'json', 'xml', 'csv']), help='Output format')
@click.option('-v', '--verbose', is_flag=True, help='Verbose mode')
@click.option('-q', '--quiet', is_flag=True, help='Quiet mode')
@click.option('--color/--no-color', default=True, help='Enable/Disable colored output')
@click.option('--progress', is_flag=True, help='Show progress bar')
@click.option('--log', help='Save raw log')

# DEBUG & SESSION
@click.option('--debug', is_flag=True, help='Debug mode')
@click.option('--dry-run', is_flag=True, help='Run without sending requests')
@click.option('--benchmark', is_flag=True, help='Benchmark engine speed')
@click.option('--config', help='Use config file')
@click.option('--save-session', is_flag=True, help='Save scan session')
@click.option('--resume', is_flag=True, help='Resume previous session')

def dirfinder(**kwargs):
    """
    Powerful Directory Finder (Expert Rust + Go Engine).
    Designed for speed, stealth, and deep reconnaissance.
    """
    display_tool_banner('Dir Finder (Expert Engine)')
    
    url = kwargs['url']
    wordlist = kwargs['wordlist']
    
    # Handle auto-wordlist / default wordlist
    wordlist_str = ""
    if wordlist:
        if os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                wordlist_str = ",".join([line.strip() for line in f if line.strip()])
        else:
            click.echo(_colored(f"[!] Wordlist file not found: {wordlist}", RED))
            return
    elif kwargs['stdin']:
        import sys
        wordlist_str = ",".join([line.strip() for line in sys.stdin if line.strip()])
    
    # Path to Go binary
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    go_bin = os.path.join(base_dir, 'hackit', 'dir_finder', 'go', 'dir_finder.exe')

    if not os.path.exists(go_bin):
        click.echo(_colored("[!] Go binary not found. Please compile it first.", RED))
        return

    # Build command for Go orchestrator
    cmd = [go_bin, "-u", url]
    
    # Mapping kwargs to Go flags
    flag_map = {
        'wordlist_str': '-w',
        'method': '-method',
        'data': '-data',
        'cookie': '-cookie',
        'auth': '-auth',
        'proxy': '-proxy',
        'user_agent': '-user-agent',
        'threads': '-t',
        'timeout': '-timeout',
        'delay': '-delay',
        'retries': '-retries',
        'max_redirect': '-max-redirect',
        'extensions': '-e',
        'depth': '-depth',
        'exclude_status': '-exclude-status',
        'include_status': '-include-status',
        'exclude_length': '-exclude-length',
        'include_length': '-include-length',
        'fuzz': '-fuzz',
        'rate_limit': '-rate-limit',
    }

    if wordlist_str: cmd.extend(["-w", wordlist_str])
    
    for key, flag in flag_map.items():
        if key in kwargs and kwargs[key] is not None and key != 'wordlist_str':
            cmd.extend([flag, str(kwargs[key])])

    # Boolean flags
    bool_flags = {
        'random_agent': '-random-agent',
        'http2': '-http2',
        'follow_redirect': '-follow-redirect',
        'recursive': '-recursive',
        'detect_waf': '-detect-waf',
        'detect_tech': '-detect-tech',
        'detect_cms': '-detect-cms',
        'detect_backup': '-detect-backup',
        'smart_filter': '-smart-filter',
        'api_mode': '-api-mode',
        'json_body': '-json-body',
        'graphql': '-graphql',
        'auto_wordlist': '-auto-wordlist',
        'crawl': '-crawl',
        'extract_js': '-extract-js',
    }

    for key, flag in bool_flags.items():
        if kwargs.get(key):
            cmd.append(flag)

    # Headers
    if kwargs.get('header'):
        cmd.extend(["-H", ",".join(kwargs['header'])])

    click.echo(f"[*] Target: {_colored(url, BLUE)}")
    click.echo(f"[*] Engine: {_colored('Rust (Async Core) + Go (Orchestrator)', GREEN)}")
    click.echo(f"[*] Threads: {kwargs['threads']} | Timeout: {kwargs['timeout']}s")
    
    if kwargs.get('auto_wordlist'):
        click.echo(_colored("[*] Smart Mode enabled: Generating pattern-based wordlist...", CYAN))

    click.echo("\n[+] Starting Expert Scan...\n")
    
    try:
        # Execute Go binary and stream output
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
        process.wait()
    except KeyboardInterrupt:
        click.echo("\n[!] Scan interrupted by user.")
    except Exception as e:
        click.echo(f"\n[!] Execution Error: {e}")

if __name__ == '__main__':
    dirfinder()
