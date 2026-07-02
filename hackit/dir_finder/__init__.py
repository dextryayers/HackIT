"""
Dir Finder Module (Go Expert Engine with 16 engines - dirsearch-equivalent)
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
@click.option('-u', '--url', help='Target URL (e.g. https://example.com)')
@click.option('-l', '--list', 'urls_file', help='URL list file (one target per line)')
@click.option('--stdin', is_flag=True, help='Read URL(s) from STDIN')
@click.option('--raw', help='Load raw HTTP request from file (Burp-style, extracts URL/method/headers/body)')
@click.option('--session', help='Session file to resume (loads remaining paths, continues scan)')
@click.option('--session-id', type=int, help='Resume session by numeric ID')

# === DICTIONARY SETTINGS ===
@click.option('-w', '--wordlist', 'wordlists', help='Wordlist files or directories (comma separated)')
@click.option('--wordlist-categories', help='Wordlist categories (comma separated, e.g. common,php,infra,admin)')
@click.option('-e', '--extensions', help='File extensions to append (comma separated, e.g. php,asp,html,txt)')
@click.option('-f', '--force-extensions', is_flag=True, help='Force extensions on every wordlist entry (not just path-based)')
@click.option('--overwrite-extensions', is_flag=True, help='Overwrite existing extensions in wordlist entries')
@click.option('--exclude-extensions', help='Exclude these extensions (comma separated)')
@click.option('--prefixes', help='Add prefixes to all wordlist entries (comma separated)')
@click.option('--suffixes', help='Add suffixes to all wordlist entries (comma separated)')
@click.option('-U', '--uppercase', is_flag=True, help='Generate uppercase variants of all wordlist entries')
@click.option('-L', '--lowercase', is_flag=True, help='Generate lowercase variants of all wordlist entries')
@click.option('-C', '--capital', is_flag=True, help='Generate capitalized variants of all wordlist entries')

# === GENERAL SETTINGS ===
@click.option('-t', '--threads', default=5, type=int, help='Number of concurrent threads (default: 5)')
@click.option('-r', '--recursive', is_flag=True, help='Recursive brute-force on found directories')
@click.option('--deep-recursive', is_flag=True, help='Deep recursive scan — split paths into directory levels')
@click.option('--force-recursive', is_flag=True, help='Force recursive scan on all found paths, not just directories')
@click.option('-R', '--max-recursion-depth', default=3, type=int, help='Maximum recursion depth (default: 3)')
@click.option('--recursion-status', help='Status codes that trigger recursion (comma separated, supports ranges like 200-399)')
@click.option('--subdirs', help='Scan these sub-directories (comma separated)')
@click.option('--exclude-subdirs', help='Exclude these subdirectories during recursive scan (comma separated)')
@click.option('-i', '--include-status', help='Only show responses matching these status codes (comma separated, supports ranges)')
@click.option('-x', '--exclude-status', default='', help='Exclude responses with these status codes (default: none)')
@click.option('--exclude-sizes', help='Exclude responses matching sizes (comma separated, e.g. 0,0B,4KB,1MB)')
@click.option('--exclude-text', help='Exclude responses containing this text (substring match, case-sensitive)')
@click.option('--exclude-regex', help='Exclude responses matching this regex pattern')
@click.option('--exclude-redirect', help='Exclude responses redirecting to URLs matching this pattern')
@click.option('--exclude-response', help='Exclude responses matching reference path response (for wildcard exclusion)')
@click.option('--skip-on-status', help='Skip target entirely on these status codes (comma separated)')
@click.option('--min-response-size', help='Minimum response size to show (e.g. 1024, 1KB, 1MB)')
@click.option('--max-response-size', help='Maximum response size to show (e.g. 1024, 1KB, 1MB)')
@click.option('--max-time', type=int, help='Maximum scan time in seconds (auto-stop after this)')
@click.option('--exit-on-error', is_flag=True, help='Exit immediately on any error')

# === ADVANCED FILTERING ===
@click.option('--auto-calibration', is_flag=True, help='Force extra wildcard calibration phase (more accurate filtering)')
@click.option('--match-status', help='Advanced: only match responses with these status codes')
@click.option('--filter-status', help='Advanced: filter out responses with these status codes')
@click.option('--match-size', help='Advanced: only match responses within size range (e.g. 100-1000,500)')
@click.option('--filter-size', help='Advanced: filter out responses within size range')
@click.option('--match-words', help='Advanced: only match responses with word count in range')
@click.option('--filter-words', help='Advanced: filter out responses with word count in range')
@click.option('--match-lines', help='Advanced: only match responses with line count in range')
@click.option('--filter-lines', help='Advanced: filter out responses with line count in range')
@click.option('--match-regex', help='Advanced: only match responses matching body regex')
@click.option('--filter-regex', help='Advanced: filter out responses matching body regex')
@click.option('--match-header', help='Advanced: only match responses containing header text')
@click.option('--filter-header', help='Advanced: filter out responses containing header text')

# === REQUEST SETTINGS ===
@click.option('-m', '--method', 'http_method', default='GET', type=click.Choice(['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']), help='HTTP method (default: GET)')
@click.option('-d', '--data', help='HTTP request body data (for POST/PUT/DELETE requests)')
@click.option('--data-file', help='File containing HTTP request body data')
@click.option('-H', '--header', multiple=True, help='Custom HTTP header (repeatable, format: "Key: Value")')
@click.option('--headers-file', help='File containing custom HTTP headers (one per line, Key: Value)')
@click.option('-F', '--follow-redirects', is_flag=True, help='Follow HTTP redirects (301/302/307/308) during scan')
@click.option('--random-agent', is_flag=True, help='Use random User-Agent from built-in list')
@click.option('--auth', help='Authentication credentials (format: user:pass for basic, or token string for bearer/jwt)')
@click.option('--auth-type', type=click.Choice(['basic', 'digest', 'bearer', 'ntlm', 'jwt']), help='Authentication type (default: basic)')
@click.option('--user-agent', help='Custom User-Agent header value')
@click.option('--cookie', help='HTTP Cookie header value')

# === CONNECTION SETTINGS ===
@click.option('--timeout', default=5, type=int, help='Connection timeout per request in seconds (default: 5)')
@click.option('--delay', default=0, type=int, help='Delay between requests in milliseconds')
@click.option('-p', '--proxy', help='Proxy URL (http://user:pass@host:port, socks5://host:port)')
@click.option('--proxies-file', help='File containing proxy servers (one per line, rotated)')
@click.option('--proxy-auth', help='Proxy authentication credentials (user:pass)')
@click.option('--tor', is_flag=True, help='Route traffic through Tor network (requires Tor service)')
@click.option('--scheme', help='Force URL scheme override (http or https)')
@click.option('--max-rate', type=float, help='Maximum requests per second (rate limiting)')
@click.option('--retries', default=1, type=int, help='Number of retries for failed requests (default: 1)')
@click.option('--ip', help='Server IP address (skip DNS resolution)')
@click.option('--interface', help='Network interface or local IP to bind to')

# === ADVANCED SETTINGS ===
@click.option('--crawl', is_flag=True, help='Crawl homepage, robots.txt, and sitemap.xml for additional paths')

# === VIEW SETTINGS ===
@click.option('--full-url', is_flag=True, help='Show full URLs in output instead of relative paths')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('-q', '--quiet', is_flag=True, help='Quiet mode — minimal output (only results)')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output — show detailed scan information')

# === OUTPUT SETTINGS ===
@click.option('-O', '--output-formats', help='Output formats (comma separated: simple,plain,json,xml,md,csv,html)')
@click.option('-o', '--output', help='Output file path (saves all found results)')
@click.option('--log', help='Log file path (saves scan log with timestamps)')

# === DETECTION FEATURES ===
@click.option('--detect-waf', is_flag=True, help='Detect WAF fingerprinting (20+ WAF signatures: Cloudflare, Akamai, ModSecurity, AWS WAF, etc)')
@click.option('--detect-tech', is_flag=True, help='Detect technology stack (50+ signatures: servers, frameworks, languages)')
@click.option('--detect-cms', is_flag=True, help='Detect CMS (WordPress, Joomla, Drupal, Magento, Shopify, etc)')
@click.option('--detect-backup', is_flag=True, help='Search backup files (.bak, .old, .tmp, .zip, .tar.gz, .sql, .save, .backup, .conf)')
@click.option('--smart-filter', is_flag=True, help='Smart false-positive filtering — soft-404 detection, wildcard suppression, body hashing [ON by default]')
@click.option('--extract-js', is_flag=True, help='Extract API endpoints and URLs from JavaScript files')
@click.option('--auto-wordlist', is_flag=True, help='Auto-generate wordlist from target fingerprint (tech-specific payloads)')

# === SESSION & PERFORMANCE ===
@click.option('--save-session', is_flag=True, help='Save scan session to file for later resume')
@click.option('--http2', is_flag=True, help='Enable HTTP/2 support')
@click.option('--api-mode', is_flag=True, help='API mode — presets for API scanning (json/xml extensions, Accept header, auto tech/WAF detection)')
@click.option('--json-body', is_flag=True, help='Send request body as JSON (Content-Type: application/json)')
@click.option('--graphql', is_flag=True, help='GraphQL mode — wraps body in {"query": "..."} format')
@click.option('--adaptive-rate', is_flag=True, help='Dynamically adjust scan rate based on server response (errors/success ratio)')
@click.option('--detect-login', is_flag=True, help='Detect login and admin pages (login, admin, dashboard, wp-admin, etc)')
@click.option('--detect-api', is_flag=True, help='Detect API endpoints (api/, v1/, graphql, swagger, rest)')
@click.option('--js-deep', is_flag=True, help='Deep JavaScript analysis — follows imports, evaluates dynamic URLs, extracts endpoints recursively')
@click.option('--swagger', is_flag=True, help='Detect Swagger/OpenAPI documentation (swagger.json, api-docs, openapi.json, v2/v3)')
@click.option('--similarity', type=int, default=0, help='Response similarity threshold 0-100 for filtering (default: 0 = disabled)')
@click.option('--report', help='Generate scan report file (JSON format with full results, stats, and metadata)')

@click.pass_context
def dirfinder(ctx, mode, **kwargs):
    """
    Expert Dir Finder - Go Engine with dirsearch-equivalent capabilities.

    16 integrated engines: Scanner, Detector, Filter, Wordlist, Recursive,
    Reporter, HTTP Engine, Smart Analysis, Session Manager, Comparator,
    Scheduler, Parser, Signature, Output Engine, Compare Engine, Analyze Engine.
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
        click.echo(f"[!] Go binary not found at {go_bin}")
        click.echo("[!] Build it first: cd hackit/dir_finder/go && go build -ldflags='-s -w' -o dir_finder .")
        return

    cmd = [go_bin]

    # Map kwargs to Go CLI flags
    flag_map = {
        'url': '-u',
        'urls_file': '-l',
        'raw': '-raw',
        'session': '-session',
        'session_id': '-session-id',
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
        'similarity': '-similarity',
        'report': '-report',
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
        'adaptive_rate': '-adaptive-rate',
        'detect_login': '-detect-login',
        'detect_api': '-detect-api',
        'js_deep': '-js-deep',
        'swagger': '-swagger',
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
