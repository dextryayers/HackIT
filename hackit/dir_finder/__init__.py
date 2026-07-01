"""
Dir Finder Module (Go Expert Engine with 9 engines - dirsearch-equivalent)
"""
import click
import json
import os
import subprocess
import sys
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE

@click.command()
@click.argument('mode', required=False)

# === TARGET OPTIONS ===
@click.option('-u', '--url', help='Target URL')
@click.option('-l', '--list', 'urls_file', help='URL list file')
@click.option('--stdin', is_flag=True, help='Read URL(s) from STDIN')
@click.option('--raw', help='Load raw HTTP request from file')
@click.option('--session', help='Session file to resume')
@click.option('--session-id', type=int, help='Resume session by ID')

# === DICTIONARY SETTINGS ===
@click.option('-w', '--wordlist', 'wordlists', help='Wordlist files (comma separated)')
@click.option('--wordlist-categories', help='Wordlist categories (comma separated, e.g. common,php,infra)')
@click.option('-e', '--extensions', help='File extensions (comma separated, e.g. php,asp)')
@click.option('-f', '--force-extensions', is_flag=True, help='Force extensions on every wordlist entry')
@click.option('--overwrite-extensions', is_flag=True, help='Overwrite existing extensions in wordlist')
@click.option('--exclude-extensions', help='Exclude extensions (comma separated)')
@click.option('--prefixes', help='Add prefixes to all entries (comma separated)')
@click.option('--suffixes', help='Add suffixes to all entries (comma separated)')
@click.option('-U', '--uppercase', is_flag=True, help='Uppercase wordlist')
@click.option('-L', '--lowercase', is_flag=True, help='Lowercase wordlist')
@click.option('-C', '--capital', is_flag=True, help='Capital wordlist')

# === GENERAL SETTINGS ===
@click.option('-t', '--threads', default=25, type=int, help='Number of threads (default: 25)')
@click.option('-r', '--recursive', is_flag=True, help='Recursive brute-force')
@click.option('--deep-recursive', is_flag=True, help='Deep recursive scan (split paths)')
@click.option('--force-recursive', is_flag=True, help='Force recursive on all found paths, not just dirs')
@click.option('-R', '--max-recursion-depth', default=3, type=int, help='Max recursion depth (default: 3)')
@click.option('--recursion-status', help='Status codes for recursion (comma separated, supports ranges)')
@click.option('--subdirs', help='Scan sub-directories (comma separated)')
@click.option('--exclude-subdirs', help='Exclude subdirs during recursive scan (comma separated)')
@click.option('-i', '--include-status', help='Include status codes (comma separated, supports ranges)')
@click.option('-x', '--exclude-status', default='', help='Exclude status codes (default: none)')
@click.option('--exclude-sizes', help='Exclude response sizes (comma separated, e.g. 0,0B,4KB)')
@click.option('--exclude-text', help='Exclude responses containing text')
@click.option('--exclude-regex', help='Exclude responses matching regex')
@click.option('--exclude-redirect', help='Exclude redirects matching pattern')
@click.option('--exclude-response', help='Exclude responses similar to this path')
@click.option('--skip-on-status', help='Skip target on these status codes')
@click.option('--min-response-size', help='Minimum response size (e.g. 1024, 1KB)')
@click.option('--max-response-size', help='Maximum response size (e.g. 1024, 1KB)')
@click.option('--max-time', type=int, help='Maximum scan time in seconds')
@click.option('--exit-on-error', is_flag=True, help='Exit on error')

# === ADVANCED FILTERING ===
@click.option('--auto-calibration', is_flag=True, help='Force extra wildcard calibration')
@click.option('--match-status', help='Match status codes (advanced, comma separated, ranges)')
@click.option('--filter-status', help='Filter status codes (advanced)')
@click.option('--match-size', help='Match response size (advanced)')
@click.option('--filter-size', help='Filter response size (advanced)')
@click.option('--match-words', help='Match word count (advanced)')
@click.option('--filter-words', help='Filter word count (advanced)')
@click.option('--match-lines', help='Match line count (advanced)')
@click.option('--filter-lines', help='Filter line count (advanced)')
@click.option('--match-regex', help='Match body regex (advanced)')
@click.option('--filter-regex', help='Filter body regex (advanced)')
@click.option('--match-header', help='Match response header text')
@click.option('--filter-header', help='Filter response header text')

# === REQUEST SETTINGS ===
@click.option('-m', '--method', 'http_method', default='GET', type=click.Choice(['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']), help='HTTP method (default: GET)')
@click.option('-d', '--data', help='HTTP request body data')
@click.option('--data-file', help='File containing HTTP request data')
@click.option('-H', '--header', multiple=True, help='Custom header (repeatable: "Key: Value")')
@click.option('--headers-file', help='File containing HTTP headers')
@click.option('-F', '--follow-redirects', is_flag=True, help='Follow HTTP redirects')
@click.option('--random-agent', is_flag=True, help='Use random User-Agent')
@click.option('--auth', help='Authentication credentials (user:pass or bearer token)')
@click.option('--auth-type', type=click.Choice(['basic', 'digest', 'bearer', 'ntlm', 'jwt']), help='Auth type')
@click.option('--user-agent', help='Custom User-Agent')
@click.option('--cookie', help='HTTP Cookie header')

# === CONNECTION SETTINGS ===
@click.option('--timeout', default=10, type=int, help='Connection timeout in seconds (default: 10)')
@click.option('--delay', default=0, type=int, help='Delay between requests in ms')
@click.option('-p', '--proxy', help='Proxy URL (http:// or socks5://)')
@click.option('--proxies-file', help='File containing proxy servers')
@click.option('--proxy-auth', help='Proxy authentication')
@click.option('--tor', is_flag=True, help='Use Tor network')
@click.option('--scheme', help='URL scheme (http/https)')
@click.option('--max-rate', type=float, help='Max requests per second')
@click.option('--retries', default=2, type=int, help='Number of retries for failed requests (default: 2)')
@click.option('--ip', help='Server IP address')
@click.option('--interface', help='Network interface to use')

# === ADVANCED SETTINGS ===
@click.option('--crawl', is_flag=True, help='Crawl for new paths in responses')

# === VIEW SETTINGS ===
@click.option('--full-url', is_flag=True, help='Show full URLs in output')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('-q', '--quiet', is_flag=True, help='Quiet mode (minimal output)')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')

# === OUTPUT SETTINGS ===
@click.option('-O', '--output-formats', help='Output formats (simple,plain,json,xml,md,csv,html)')
@click.option('-o', '--output', help='Output file')
@click.option('--log', help='Log file')

# === DETECTION FEATURES ===
@click.option('--detect-waf', is_flag=True, help='Detect WAF fingerprinting')
@click.option('--detect-tech', is_flag=True, help='Detect technology stack')
@click.option('--detect-cms', is_flag=True, help='Detect CMS')
@click.option('--detect-backup', is_flag=True, help='Search backup files (.bak, .old, .zip, etc)')
@click.option('--smart-filter', is_flag=True, help='Smart false-positive filtering (soft-404, wildcard)')
@click.option('--extract-js', is_flag=True, help='Extract endpoints from JavaScript files')
@click.option('--auto-wordlist', is_flag=True, help='Auto-generate wordlist from target (Smart Mode)')

# === SESSION & PERFORMANCE ===
@click.option('--save-session', is_flag=True, help='Save scan session for resume')
@click.option('--http2', is_flag=True, help='Enable HTTP/2')
@click.option('--api-mode', is_flag=True, help='Optimize for API endpoint scanning')
@click.option('--json-body', is_flag=True, help='Send JSON body')
@click.option('--graphql', is_flag=True, help='GraphQL mode')

@click.pass_context
def dirfinder(ctx, mode, **kwargs):
    """
    Expert Dir Finder - Go Engine with dirsearch-equivalent capabilities.

    9 integrated engines: Scanner, Detector, Filter, Wordlist, Recursive,
    Reporter, HTTP Engine, Smart Analysis, Session Manager.
    """
    if mode == 'gui':
        from hackit.dir_finder.gui import DirFinderGUI
        DirFinderGUI().run()
        return

    if not kwargs.get('url') and not kwargs.get('urls_file') and not kwargs.get('stdin'):
        click.echo(ctx.get_help())
        return

    display_tool_banner('Dir Finder (Expert Go Engine v3.0)')

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    go_bin = os.path.join(base_dir, 'hackit', 'dir_finder', 'go', 'dir_finder')
    if not os.path.exists(go_bin):
        click.echo(_colored("[!] Go binary not found. Please compile it first.", RED))
        click.echo(f"    Expected at: {go_bin}")
        return

    cmd = [go_bin]

    # Map kwargs to Go CLI flags
    flag_map = {
        'url': '-u',
        'urls_file': '-l',
        'stdin': '-stdin',
        'wordlists': '-w',
        'wordlist_categories': '-wordlist-categories',
        'extensions': '-e',
        'exclude_extensions': '-exclude-extensions',
        'prefixes': '-prefixes',
        'suffixes': '-suffixes',
        'threads': '-t',
        'max_recursion_depth': '-R',
        'recursion_status': '-recursion-status',
        'subdirs': '-subdirs',
        'exclude_subdirs': '-exclude-subdirs',
        'include_status': '-i',
        'exclude_status': '-x',
        'exclude_sizes': '-exclude-sizes',
        'exclude_text': '-exclude-text',
        'exclude_regex': '-exclude-regex',
        'exclude_redirect': '-exclude-redirect',
        'exclude_response': '-exclude-response',
        'skip_on_status': '-skip-on-status',
        'min_response_size': '-min-response-size',
        'max_response_size': '-max-response-size',
        'max_time': '-max-time',
        'match_status': '-match-status',
        'filter_status': '-filter-status',
        'match_size': '-match-size',
        'filter_size': '-filter-size',
        'match_words': '-match-words',
        'filter_words': '-filter-words',
        'match_lines': '-match-lines',
        'filter_lines': '-filter-lines',
        'match_regex': '-match-regex',
        'filter_regex': '-filter-regex',
        'match_header': '-match-header',
        'filter_header': '-filter-header',
        'http_method': '-m',
        'data': '-d',
        'data_file': '-data-file',
        'headers_file': '-headers-file',
        'auth': '-auth',
        'auth_type': '-auth-type',
        'user_agent': '-user-agent',
        'cookie': '-cookie',
        'timeout': '-timeout',
        'delay': '-delay',
        'proxy': '-p',
        'proxies_file': '-proxies-file',
        'proxy_auth': '-proxy-auth',
        'scheme': '-scheme',
        'max_rate': '-max-rate',
        'retries': '-retries',
        'ip': '-ip',
        'interface': '-interface',
        'output_formats': '-O',
        'output': '-o',
        'log': '-log',
    }

    for kw, flag in flag_map.items():
        val = kwargs.get(kw)
        if val is not None and val != '' and val is not False:
            if isinstance(val, bool):
                cmd.append(flag)
            else:
                cmd.extend([flag, str(val)])

    # Boolean flags
    bool_flags = {
        'force_extensions': '-f',
        'overwrite_extensions': '-overwrite-extensions',
        'uppercase': '-U',
        'lowercase': '-L',
        'capital': '-C',
        'recursive': '-r',
        'deep_recursive': '-deep-recursive',
        'force_recursive': '-force-recursive',
        'exit_on_error': '-exit-on-error',
        'auto_calibration': '-auto-calibration',
        'follow_redirects': '-F',
        'random_agent': '-random-agent',
        'tor': '-tor',
        'crawl': '-crawl',
        'full_url': '-full-url',
        'no_color': '-no-color',
        'quiet': '-q',
        'verbose': '-v',
        'detect_waf': '-detect-waf',
        'detect_tech': '-detect-tech',
        'detect_cms': '-detect-cms',
        'detect_backup': '-detect-backup',
        'smart_filter': '-smart-filter',
        'extract_js': '-extract-js',
        'auto_wordlist': '-auto-wordlist',
        'save_session': '-save-session',
        'http2': '-http2',
        'api_mode': '-api-mode',
        'json_body': '-json-body',
        'graphql': '-graphql',
    }

    for kw, flag in bool_flags.items():
        if kwargs.get(kw):
            cmd.append(flag)

    # Headers (multi-value)
    if kwargs.get('header'):
        headers_str = ",".join(kwargs['header'])
        cmd.extend(['-H', headers_str])

    click.echo(f"[*] Target: {_colored(kwargs.get('url', 'STDIN / File'), BLUE)}")
    click.echo(f"[*] Engine: {_colored('Go (dirsearch-equivalent, 9 engines)', GREEN)}")
    click.echo(f"[*] Threads: {kwargs.get('threads', 25)} | Timeout: {kwargs.get('timeout', 10)}s | Retries: {kwargs.get('retries', 2)}")

    if kwargs.get('detect_waf'):
        click.echo(_colored("[*] WAF Detection enabled", CYAN))
    if kwargs.get('extract_js'):
        click.echo(_colored("[*] JS Endpoint Extraction enabled", CYAN))
    if kwargs.get('recursive'):
        click.echo(_colored(f"[*] Recursive scan (depth: {kwargs.get('max_recursion_depth', 3)})", CYAN))
    if kwargs.get('smart_filter'):
        click.echo(_colored("[*] Smart Filtering enabled (soft-404, wildcard, honeypot)", CYAN))

    click.echo("\n" + _colored("[+] Starting Expert Scan...", GREEN) + "\n")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )

        for line in iter(process.stdout.readline, ''):
            if line:
                print(line, end='', flush=True)

        process.wait()
    except KeyboardInterrupt:
        click.echo("\n" + _colored("[!] Scan interrupted by user.", YELLOW))
    except Exception as e:
        click.echo(f"\n" + _colored(f"[!] Execution Error: {e}", RED))

if __name__ == '__main__':
    dirfinder()
