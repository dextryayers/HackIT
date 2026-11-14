"""
Dir Finder Module (Go Expert Engine with 16 engines)
"""
import click
import json
import os
import subprocess
import sys
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE, BOLD, DIM, B_CYAN, B_GREEN, MAGENTA

_DIRFINDER_BANNER = r"""
 ██████╗ ██╗██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
 ██╔══██╗██║██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
 ██║  ██║██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
 ██║  ██║██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
 ██████╔╝██║██║  ██║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""

def _interactive_examples():
    """Launch screen: banner + quick examples."""
    click.echo()
    click.echo(_colored(_DIRFINDER_BANNER, B_CYAN))
    click.echo(_colored("  DIRFINDER — HackIT sniper directory & file discovery", BOLD))
    click.echo(_colored("  DIR or FUZZ marks the substitution slot; everything else stays fixed.", DIM))
    click.echo()
    _interactive_help()


def _interactive_help():
    """Command list with explanations — no banner."""
    click.echo(_colored("  COMMANDS", YELLOW))
    click.echo(_colored("  input : <url> [keys...]      run a sniper scan — everything on the line is one shot", BOLD))
    click.echo()
    click.echo(_colored("  EXAMPLES", YELLOW))
    click.echo(_colored("    input : https://example.com/DIR threads 25 sc 200,404 verbose on", GREEN))
    click.echo(_colored("    input : https://example.com/DIR full threads 50 verbose on", GREEN))
    click.echo(_colored("    input : https://example.com/file.DIR sc 200", GREEN))
    click.echo(_colored("    input : https://FUZZ.example.com/ threads 30 sc 403,200", GREEN))
    click.echo(_colored("    input : https://example.com/DIR wordlists /home/user/WD.txt threads 25", GREEN))
    click.echo(_colored("    input : https://example.com/DIR wordlists /home/user/lists/ threads 25  (folder: all .txt/.lst/... inside)", GREEN))
    click.echo(_colored("    input : https://example.com/DIR exclude 404 recursive on", GREEN))
    click.echo()
    click.echo(_colored("  KEYS (case-insensitive, anywhere on the line)", YELLOW))
    for key, desc in [
        ("threads/t N", "concurrency, 1-200 (default 30)"),
        ("sc 200,403", "only show these status codes (ranges like 200-299 ok)"),
        ("exclude 404", "hide these status codes"),
        ("ext php,bak", "file extensions to try (also fuzz marker position)"),
        ("full", "use wordlists/dicc.txt (deep) instead of internal default"),
        ("subdomains", "use wordlists/subdomains.txt (host fuzz)"),
        ("wordlists a,b/f", "external lists — file or folder, comma-separated, any folder"),
        ("method GET|POST|HEAD|PUT|DELETE", "HTTP method (default GET)"),
        ("verbose on|off", "live per-attempt output (bare 'verbose' = on)"),
        ("quiet on|off", "only findings, no progress line"),
        ("recursive on|off", "recurse into found directories"),
        ("http2", "HTTP/2 auto-negotiated via ALPN (no-op key, kept for muscle memory)"),
        ("delay N", "delay between requests in ms"),
        ("timeout N", "per-request timeout in seconds"),
        ("rate N", "cap requests per second"),
    ]:
        click.echo(f"    {_colored(key, GREEN):40s} {_colored(desc, DIM)}")
    click.echo(_colored("    empty input quits · 'help' reprints this", DIM))
    click.echo()

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
        _interactive()
        return

    display_tool_banner('Dir Finder (Expert Go Engine v3.0)')
    _run_engine(kwargs)


def _run_engine(kwargs):
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

    try:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            click.echo(f"[!] Go binary exited with code {result.returncode}")
    except FileNotFoundError:
        click.echo(f"[!] Go binary not found: {go_bin}")
    except Exception as e:
        click.echo(f"[!] Failed to execute Go binary: {e}")


_TRUE = {"on", "yes", "true", "1", "y"}
_FALSE = {"off", "no", "false", "0", "n"}
_WL_EXTS = {".txt", ".lst", ".list", ".csv", ".dic", ".words", ""}


def _validate_wordlists(raw: str):
    """Resolve external wordlist paths (file or folder). Returns (list[str], error)."""
    entries = [part.strip() for part in raw.split(",") if part.strip()]
    if not entries:
        return None, "wordlists needs at least one path"
    resolved = []
    for entry in entries:
        path = os.path.expanduser(entry)
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        if os.path.isfile(path):
            if not os.access(path, os.R_OK):
                return None, f"wordlist not readable: {path}"
            resolved.append(path)
            continue
        if os.path.isdir(path):
            found = False
            for root, _dirs, files in os.walk(path):
                for name in files:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in _WL_EXTS:
                        candidate = os.path.join(root, name)
                        if os.access(candidate, os.R_OK):
                            found = True
            if not found:
                return None, f"folder has no wordlist files (.txt/.lst/.list/.csv/extension-less): {path}"
            resolved.append(path)
            continue
        return None, f"wordlist not found: {path}"
    return resolved, None


def _parse_sc_list(raw: str) -> str:
    parts = raw.replace("/", ",").replace(";", ",").split(",")
    out = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part[1:]:
            bits = part.split("-", 1)
            if bits[0].strip().isdigit() and bits[1].strip().isdigit():
                out.append(f"{bits[0].strip()}-{bits[1].strip()}")
            continue
        if part.isdigit():
            out.append(part)
    return ",".join(out)


def _bool_token(tokens, i, default_when_bare=True):
    """Return (bool, consumed) for 'verbose', 'verbose on', 'verbose off'."""
    if i + 1 < len(tokens) and tokens[i + 1].lower() in _TRUE | _FALSE:
        return tokens[i + 1].lower() in _TRUE, 2
    return default_when_bare, 1


def _interactive_parse(text: str):
    """Parse the free-form input line. Returns kwargs dict or an error string."""
    import shlex
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        return None, f"could not parse input: {exc}"
    if not tokens:
        return None, "empty"

    if tokens[0].lower() in ("help", "?", "examples"):
        return None, "help"

    kwargs = {"url": None, "threads": 30, "verbose": False}
    i = 0
    target = None
    for tok in tokens:
        if tok.startswith(("http://", "https://", "www.", "ftp://")) or (
            "://" not in tok and "." in tok and not tok.startswith("-")):
            target = tok
            break
    if target is None:
        # allow bare "example.com/DIR" without scheme
        if "." in tokens[0] and not tokens[0].startswith(("-", "help")):
            target = tokens[0]
        else:
            return None, f"no URL found in input: {tokens[0]!r}"

    if target.startswith("www."):
        target = "https://" + target

    i = tokens.index(target) + 1
    while i < len(tokens):
        key = tokens[i].lower()
        val = tokens[i + 1] if i + 1 < len(tokens) else None

        if key in ("threads", "t", "th") and val:
            try:
                kwargs["threads"] = max(1, min(int(val), 200))
            except ValueError:
                return None, f"bad threads value: {val!r}"
            i += 2
        elif key in ("sc", "status", "statuses", "match", "-i") and val:
            parsed = _parse_sc_list(val)
            if not parsed:
                return None, f"bad sc value: {val!r}"
            kwargs["include_status"] = parsed
            i += 2
        elif key in ("exclude", "x", "-x") and val:
            parsed = _parse_sc_list(val)
            if not parsed:
                return None, f"bad exclude value: {val!r}"
            kwargs["exclude_status"] = parsed
            i += 2
        elif key == "ext" and val:
            kwargs["extensions"] = val.replace(" ", "")
            i += 2
        elif key == "method" and val:
            kwargs["http_method"] = val.upper()
            i += 2
        elif key == "delay" and val:
            kwargs["delay"] = int(val)
            i += 2
        elif key == "timeout" and val:
            kwargs["timeout"] = int(val)
            i += 2
        elif key == "rate" and val:
            try:
                kwargs["max_rate"] = float(val)
            except ValueError:
                return None, f"bad rate value: {val!r}"
            i += 2
        elif key in ("wordlists", "wordlist", "wl") and val:
            resolved, error = _validate_wordlists(val)
            if error:
                return None, error
            kwargs["wordlists"] = ",".join(resolved)
            i += 2
        elif key == "full":
            repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            kwargs["wordlists"] = os.path.join(repo, "wordlists", "dicc.txt")
            i += 1
        elif key == "subdomains":
            repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            kwargs["wordlists"] = os.path.join(repo, "wordlists", "subdomains.txt")
            i += 1
        elif key in ("verbose", "v"):
            flag, consumed = _bool_token(tokens, i)
            kwargs["verbose"] = flag
            i += consumed
        elif key in ("quiet", "q"):
            flag, consumed = _bool_token(tokens, i)
            kwargs["quiet"] = flag
            i += consumed
        elif key == "recursive":
            flag, consumed = _bool_token(tokens, i)
            kwargs["recursive"] = flag
            i += consumed
        elif key == "http2":
            flag, consumed = _bool_token(tokens, i)
            kwargs["http2"] = flag
            i += consumed
        elif key == "help":
            return None, "help"
        else:
            return None, f"unknown key: {key!r}"

    kwargs["url"] = target
    return kwargs, None


def _interactive():
    _interactive_examples()
    while True:
        try:
            raw = input(_colored("  input : ", B_CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            click.echo(_colored("\n  bye.", DIM))
            return
        if not raw:
            click.echo(_colored("  rail cold — bye.", DIM))
            return
        kwargs, error = _interactive_parse(raw)
        if error == "help":
            _interactive_help()
            continue
        if error:
            click.echo(_colored(f"  [!] {error} — 'help' for examples", YELLOW))
            continue
        display_tool_banner('Dir Finder (Expert Go Engine v3.0)')
        if kwargs.get("url"):
            click.echo(_colored(f"  [+] target {kwargs['url']}", B_GREEN))
        _run_engine(kwargs)
        click.echo()
