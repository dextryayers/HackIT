"""SQL injection testing module.

The command line interface is a thin layer over the Go worker. It exposes the
same actions through direct flags, subcommands, and an interactive shell.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import sys
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import click

from . import report as report_mod
from .go_bridge import GoEngine

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


BANNER = """HackIt SQL Injection Engine
Version 4.0
"""

WARNING = (
    "Use this module only against systems you own or have explicit written "
    "permission to test."
)

DEFAULT_OPTIONS: Dict[str, Any] = {
    "url": None,
    "data": None,
    "method": "GET",
    "cookie": None,
    "headers": (),
    "agent": "HackIt/4.0",
    "referer": None,
    "proxy": None,
    "timeout": 15,
    "follow_redirect": False,
    "threads": 10,
    "delay": 0,
    "level": 1,
    "risk_level": 1,
    "technique": "auto",
    "dbms": "",
    "prefix": "",
    "suffix": "",
    "param": "",
    "skip_param": "",
    "tamper": (),
    "encode": "",
    "randomize_case": False,
    "bypass_waf": False,
    "stealth": False,
    "time_secs": 3,
    "extract_technique": "auto",
    "extract_charset": "common",
    "max_length": 512,
    "list_dbs": False,
    "list_tables": False,
    "list_columns": False,
    "schema": False,
    "count_rows": False,
    "dump_all": False,
    "dump_table": "",
    "database": "",
    "table": "",
    "column": "",
    "columns_csv": "",
    "where": "",
    "search": "",
    "sql_query": "",
    "rows": 50,
    "limit": 50,
    "offset": 0,
    "current_db": False,
    "current_user": False,
    "hostname": False,
    "banner": False,
    "privileges": False,
    "is_dba": False,
    "users": False,
    "passwords": False,
    "roles": False,
    "fingerprint": False,
    "banner_grab": False,
    "waf_detect": False,
    "file_read": "",
    "file_write": "",
    "file_exec": "",
    "crawl": "",
    "crawl_depth": 5,
    "crawl_threads": 10,
    "crawl_output": "crawl_output",
    "output_format": "text",
    "no_color": False,
    "verbose": 0,
    "report": None,
}

ACTION_KEYS = {
    "list_dbs",
    "list_tables",
    "list_columns",
    "schema",
    "count_rows",
    "dump_all",
    "dump_table",
    "search",
    "sql_query",
    "current_db",
    "current_user",
    "hostname",
    "banner",
    "privileges",
    "is_dba",
    "users",
    "passwords",
    "roles",
    "fingerprint",
    "banner_grab",
    "waf_detect",
    "file_read",
    "file_write",
    "file_exec",
    "crawl",
}

PASSTHROUGH_KEYS = {
    "data",
    "method",
    "cookie",
    "agent",
    "referer",
    "proxy",
    "follow_redirect",
    "threads",
    "delay",
    "level",
    "risk_level",
    "technique",
    "dbms",
    "prefix",
    "suffix",
    "param",
    "skip_param",
    "encode",
    "randomize_case",
    "bypass_waf",
    "stealth",
    "time_secs",
    "extract_technique",
    "extract_charset",
    "max_length",
    "list_dbs",
    "list_tables",
    "list_columns",
    "schema",
    "count_rows",
    "dump_all",
    "dump_table",
    "database",
    "table",
    "column",
    "columns_csv",
    "where",
    "search",
    "sql_query",
    "rows",
    "limit",
    "offset",
    "current_db",
    "current_user",
    "hostname",
    "banner",
    "privileges",
    "is_dba",
    "users",
    "passwords",
    "roles",
    "fingerprint",
    "banner_grab",
    "waf_detect",
    "file_read",
    "file_write",
    "file_exec",
    "crawl",
    "crawl_depth",
    "crawl_threads",
    "crawl_output",
}


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _log(level: str, message: str) -> None:
    prefix = {
        "info": "[+]",
        "ok": "[+]",
        "warn": "[-]",
        "error": "[x]",
        "debug": "[.]",
    }.get(level, "[+]")
    color = {
        "info": "cyan",
        "ok": "green",
        "warn": "yellow",
        "error": "red",
        "debug": "bright_black",
    }.get(level)
    click.secho(
        "%s %s %s" % (prefix, _ts(), message),
        fg=color,
        err=True,
    )


def _split_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _has_action(opts: Dict[str, Any]) -> bool:
    for key in ACTION_KEYS:
        value = opts.get(key)
        if isinstance(value, str):
            if value:
                return True
        elif value:
            return True
    return False


def _default_scan(opts: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(opts)
    if not _has_action(result):
        result.update(
            fingerprint=True,
            current_db=True,
            current_user=True,
            list_dbs=True,
            list_tables=True,
        )
    return result


def _title_for(opts: Dict[str, Any]) -> str:
    if opts.get("dump_all") or opts.get("dump_table"):
        return "Data extraction"
    if opts.get("sql_query"):
        return "SQL query result"
    if opts.get("file_read") or opts.get("file_exec"):
        return "File and command access"
    if opts.get("list_dbs") or opts.get("list_tables") or opts.get("list_columns"):
        return "Database enumeration"
    if opts.get("schema"):
        return "Schema enumeration"
    if opts.get("count_rows"):
        return "Row counts"
    if opts.get("users") or opts.get("passwords") or opts.get("roles"):
        return "Account enumeration"
    if opts.get("fingerprint") or opts.get("banner_grab") or opts.get("current_db"):
        return "DBMS fingerprint"
    return "SQL injection assessment"


def _engine_kwargs(opts: Dict[str, Any]) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {}
    for key in PASSTHROUGH_KEYS:
        value = opts.get(key)
        if value is None or value is False or value == "":
            continue
        kwargs[key] = value
    headers = _split_list(opts.get("headers"))
    if headers:
        kwargs["header"] = ",".join(headers)
    tamper = _split_list(opts.get("tamper"))
    if tamper:
        kwargs["tamper"] = ",".join(tamper)
    return kwargs


def _run_engine(opts: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    engine = GoEngine()
    if not engine.available:
        _log("error", "Go is not installed and the worker binary is missing.")
        return None

    kwargs = _engine_kwargs(opts)
    request_timeout = int(opts.get("timeout") or 15)
    subprocess_timeout = max(300, request_timeout * 30)
    verbose = int(opts.get("verbose") or 0)
    try:
        if verbose > 0:
            results = engine.run_stream(
                opts["url"],
                on_verbose=lambda line: click.echo(line, err=True),
                verbose_lvl=verbose,
                request_timeout=request_timeout,
                **kwargs,
            )
        else:
            results = engine.run(
                opts["url"],
                timeout=subprocess_timeout,
                request_timeout=request_timeout,
                **kwargs,
            )
    except Exception as exc:
        _log("error", "engine invocation failed: %s" % exc)
        return None

    if results is None:
        _log("error", "the engine returned no output")
        return None
    if not isinstance(results, list):
        results = [results]
    return results


def _print_results(
    results: Sequence[Dict[str, Any]],
    title: str,
    target: str,
    output_format: str,
) -> None:
    if output_format == "json":
        click.echo(json.dumps(list(results), indent=2, ensure_ascii=False))
        return
    if output_format == "ndjson":
        for item in results:
            click.echo(json.dumps(item, ensure_ascii=False))
        return
    report_mod.print_console(list(results), title=title, target=target)


def _write_report(results: Sequence[Dict[str, Any]], path: str, target: str) -> None:
    extension = os.path.splitext(path)[1].lower().lstrip(".")
    base = os.path.splitext(path)[0]
    if extension in ("html", "json", "csv", "txt"):
        report_mod.generate_report(list(results), base, formats=(extension,), target=target)
        return
    report_mod.generate_report(list(results), path, formats=("html", "json"), target=target)


def _execute(opts: Dict[str, Any], default_scan: bool = False) -> int:
    options = dict(opts)
    if not options.get("url"):
        _log("error", "a target URL is required (use -u or --url)")
        return 2
    if options.get("no_color"):
        report_mod.set_no_color(True)
    if default_scan:
        options = _default_scan(options)

    url = str(options["url"])
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        options["url"] = url

    _log("info", "target: %s" % url)
    results = _run_engine(options)
    if results is None:
        return 1

    fatal = [
        item for item in results
        if item.get("type") == "fatal" or ("error" in item and "type" not in item)
    ]
    if fatal and len(results) == 1:
        message = fatal[0].get("payload") or fatal[0].get("error") or "scan failed"
        _log("error", str(message))
        if options.get("output_format") in ("json", "ndjson"):
            _print_results(results, "SQL injection assessment", url, options["output_format"])
        return 1

    _print_results(results, _title_for(options), url, str(options.get("output_format") or "text"))

    report_path = options.get("report")
    if report_path:
        _write_report(results, str(report_path), url)

    return 0


# ---------------------------------------------------------------------------
# Click interface
# ---------------------------------------------------------------------------


@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
    invoke_without_command=True,
)
@click.option("-u", "--url", default=None, help="Target URL.")
@click.option("--data", default=None, help="Request body, form encoded or JSON.")
@click.option("-X", "--method", default="GET", help="HTTP method. Default: GET.")
@click.option("--cookie", default=None, help="Cookie header.")
@click.option("-H", "--header", "headers", multiple=True, help="Extra header. Repeatable.")
@click.option("--agent", default="HackIt/4.0", help="User-Agent header.")
@click.option("--referer", default=None, help="Referer header.")
@click.option("--proxy", default=None, help="HTTP proxy URL.")
@click.option("--timeout", default=15, type=int, help="Per-request timeout in seconds.")
@click.option("--follow-redirect", is_flag=True, help="Follow HTTP redirects.")
@click.option("--threads", default=10, type=int, help="Worker threads.")
@click.option("--delay", default=0, type=int, help="Delay between requests in milliseconds.")
@click.option("--level", default=1, type=click.IntRange(1, 3), help="Injection level 1-3.")
@click.option("--risk-level", default=1, type=click.IntRange(1, 3), help="Risk level 1-3.")
@click.option(
    "--technique",
    default="auto",
    type=click.Choice(["auto", "union", "error", "boolean", "time", "stacked"]),
    help="Injection technique.",
)
@click.option("--dbms", default="", help="Force a DBMS instead of fingerprinting.")
@click.option("--prefix", default="", help="Force the injection prefix.")
@click.option("--suffix", default="", help="Force the injection suffix.")
@click.option("--param", default="", help="Only test these parameters, comma separated.")
@click.option("--skip-param", default="", help="Skip these parameters, comma separated.")
@click.option("--tamper", multiple=True, help="Tamper script. Repeatable.")
@click.option("--encode", default="", type=click.Choice(["", "url", "double", "base64"]))
@click.option("--randomize-case", is_flag=True, help="Randomize payload letter case.")
@click.option("--bypass-waf", is_flag=True, help="Enable WAF bypass payloads.")
@click.option("--stealth", is_flag=True, help="Use low noise request pacing.")
@click.option("--time-secs", default=3, type=int, help="Time based delay in seconds.")
@click.option(
    "--extract-technique",
    default="auto",
    type=click.Choice(["auto", "union", "error", "boolean", "blind", "time"]),
    help="Force the extraction technique.",
)
@click.option("--extract-charset", default="common", help="Blind extraction character set.")
@click.option("--max-length", default=512, type=int, help="Maximum blind extraction length.")
@click.option("--dbs", "--list-dbs", "list_dbs", is_flag=True, help="List databases.")
@click.option("--tables", "--list-tables", "list_tables", is_flag=True, help="List tables.")
@click.option("--columns", "--list-columns", "list_columns", is_flag=True, help="List columns.")
@click.option("--schema", is_flag=True, help="Dump table and column types.")
@click.option("--count-rows", is_flag=True, help="Count rows per table.")
@click.option("--dump-all", is_flag=True, help="Dump every non-system table.")
@click.option("--dump-table", default="", help="Dump one table.")
@click.option("--db", "--database", "database", default="", help="Database name.")
@click.option("--table", default="", help="Table name.")
@click.option("--column", default="", help="Single column name.")
@click.option("--columns-csv", default="", help="Columns to dump, comma separated.")
@click.option("--where", default="", help="WHERE clause for a dump.")
@click.option("--search", default="", help="Search table and column names.")
@click.option("--sql-query", default="", help="Run a scalar SQL query.")
@click.option("--rows", default=50, type=int, help="Maximum rows to dump.")
@click.option("--limit", default=50, type=int, help="Maximum rows per table.")
@click.option("--offset", default=0, type=int, help="Row offset.")
@click.option("--current-db", is_flag=True, help="Show the current database.")
@click.option("--current-user", is_flag=True, help="Show the current database user.")
@click.option("--hostname", is_flag=True, help="Show the database hostname.")
@click.option("--banner", is_flag=True, help="Show the DBMS banner.")
@click.option("--privileges", is_flag=True, help="Show database privileges.")
@click.option("--is-dba", is_flag=True, help="Check for DBA privileges.")
@click.option("--users", is_flag=True, help="List database users.")
@click.option("--passwords", is_flag=True, help="List password hashes.")
@click.option("--roles", is_flag=True, help="List database roles.")
@click.option("--fingerprint", is_flag=True, help="Fingerprint the DBMS and session.")
@click.option("--banner-grab", is_flag=True, help="Alias for --fingerprint.")
@click.option("--waf-detect", is_flag=True, help="Report WAF detection details.")
@click.option("--file-read", default="", help="Read a file from the database server.")
@click.option("--file-write", default="", help="Write a file on the database server.")
@click.option("--file-exec", default="", help="Execute an OS command through the database.")
@click.option(
    "--crawl",
    default="",
    type=click.Choice(["", "full", "schema", "sensitive", "system", "procs", "views"]),
    help="Run the database crawler.",
)
@click.option("--crawl-depth", default=5, type=int)
@click.option("--crawl-threads", default=10, type=int)
@click.option("--crawl-output", default="crawl_output")
@click.option(
    "--format",
    "output_format",
    default="text",
    type=click.Choice(["text", "json", "ndjson"]),
    help="Output format.",
)
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.option("-v", "--verbose", count=True, help="Show engine progress. Repeatable.")
@click.option("--report", default=None, help="Write a report to this path after the run.")
@click.pass_context
def test_sqli(ctx: click.Context, **opts: Any) -> None:
    """SQL injection testing with enumeration and data extraction."""
    ctx.ensure_object(dict)
    ctx.obj.update(opts)
    if ctx.invoked_subcommand is not None:
        return
    if not opts.get("url"):
        interactive_shell()
        return
    ctx.exit(_execute(ctx.obj, default_scan=True))


@test_sqli.command()
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Fingerprint, enumerate databases, and list tables."""
    ctx.exit(_execute(ctx.obj, default_scan=True))


@test_sqli.command()
@click.pass_context
def dbs(ctx: click.Context) -> None:
    """List databases."""
    options = dict(ctx.obj)
    options["list_dbs"] = True
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("database", required=True)
@click.pass_context
def tables(ctx: click.Context, database: str) -> None:
    """List tables in a database."""
    options = dict(ctx.obj)
    options.update(database=database, list_tables=True)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("database", required=True)
@click.argument("table", required=True)
@click.pass_context
def columns(ctx: click.Context, database: str, table: str) -> None:
    """List columns in a table."""
    options = dict(ctx.obj)
    options.update(database=database, table=table, list_columns=True)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("database", required=True)
@click.argument("table", required=True)
@click.option("--rows", default=50, type=int, help="Maximum rows to dump.")
@click.option("--columns-csv", default="", help="Columns to dump, comma separated.")
@click.option("--where", default="", help="WHERE clause for the dump.")
@click.pass_context
def dump(ctx: click.Context, database: str, table: str, rows: int,
         columns_csv: str, where: str) -> None:
    """Dump a table."""
    options = dict(ctx.obj)
    options.update(
        database=database,
        dump_table=table,
        rows=rows,
        columns_csv=columns_csv,
        where=where,
    )
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("keyword", required=True)
@click.option("--db", "--database", "database", default="", help="Limit to one database.")
@click.pass_context
def search(ctx: click.Context, keyword: str, database: str) -> None:
    """Search table and column names."""
    options = dict(ctx.obj)
    options.update(search=keyword, database=database)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("database", required=False, default="")
@click.pass_context
def schema(ctx: click.Context, database: str) -> None:
    """Enumerate the schema with column types."""
    options = dict(ctx.obj)
    options.update(schema=True, database=database)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("database", required=False, default="")
@click.pass_context
def rows(ctx: click.Context, database: str) -> None:
    """Count rows per table."""
    options = dict(ctx.obj)
    options.update(count_rows=True, database=database)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.argument("query", required=True)
@click.option(
    "--technique",
    default="auto",
    type=click.Choice(["auto", "union", "error", "boolean", "blind", "time"]),
    help="Force the extraction technique.",
)
@click.pass_context
def sql(ctx: click.Context, query: str, technique: str) -> None:
    """Run a scalar SQL query."""
    options = dict(ctx.obj)
    options.update(sql_query=query, extract_technique=technique)
    ctx.exit(_execute(options))


@test_sqli.command()
@click.option("--query", "query", required=True, help="Scalar SQL expression to extract.")
@click.option(
    "--technique",
    default="auto",
    type=click.Choice(["auto", "union", "error", "boolean", "blind", "time"]),
)
@click.option("--charset", default="common", help="Blind extraction character set.")
@click.option("--max-length", default=512, type=int, help="Maximum extraction length.")
@click.pass_context
def extract(ctx: click.Context, query: str, technique: str, charset: str,
            max_length: int) -> None:
    """Extract one value with an explicit technique."""
    options = dict(ctx.obj)
    options.update(
        sql_query=query,
        extract_technique=technique,
        extract_charset=charset,
        max_length=max_length,
    )
    ctx.exit(_execute(options))


@test_sqli.command()
@click.option(
    "--mode",
    default="full",
    type=click.Choice(["full", "schema", "sensitive", "system", "procs", "views"]),
)
@click.option("--depth", default=5, type=int, help="Crawl depth.")
@click.option("--workers", default=10, type=int, help="Crawl workers.")
@click.option("--output", default="crawl_output", help="Output directory.")
@click.pass_context
def crawl(ctx: click.Context, mode: str, depth: int, workers: int, output: str) -> None:
    """Crawl the database for schema and sensitive data."""
    options = dict(ctx.obj)
    options.update(
        crawl=mode,
        crawl_depth=depth,
        crawl_threads=workers,
        crawl_output=output,
    )
    ctx.exit(_execute(options))


@test_sqli.command()
@click.option("--file", "path", required=True, help="File path to read.")
@click.pass_context
def readfile(ctx: click.Context, path: str) -> None:
    """Read a file through the database."""
    options = dict(ctx.obj)
    options["file_read"] = path
    ctx.exit(_execute(options))


@test_sqli.command(name="exec")
@click.option("--cmd", required=True, help="OS command to execute.")
@click.pass_context
def exec_command(ctx: click.Context, cmd: str) -> None:
    """Execute an OS command through the database."""
    options = dict(ctx.obj)
    options["file_exec"] = cmd
    ctx.exit(_execute(options))


@test_sqli.command()
@click.option("--input", "input_path", default=None, help="Read results from a JSON file.")
@click.option(
    "--format",
    "formats",
    multiple=True,
    type=click.Choice(["html", "json", "csv", "txt"]),
    default=("html",),
    help="Report format. Repeatable.",
)
@click.option("--output", default="sqli_report", help="Output base path.")
@click.pass_context
def report(ctx: click.Context, input_path: Optional[str],
           formats: Tuple[str, ...], output: str) -> None:
    """Generate a report from a saved result file or a live scan."""
    if input_path:
        try:
            with open(input_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError) as exc:
            _log("error", "could not read %s: %s" % (input_path, exc))
            ctx.exit(1)
        results = loaded.get("results") if isinstance(loaded, dict) else loaded
        if not isinstance(results, list):
            _log("error", "the input file does not contain a result list")
            ctx.exit(1)
        target = str(loaded.get("summary", {}).get("target", "")) if isinstance(loaded, dict) else ""
    else:
        options = _default_scan(dict(ctx.obj))
        if not options.get("url"):
            _log("error", "a target URL or --input is required")
            ctx.exit(2)
        results = _run_engine(options)
        if not results:
            ctx.exit(1)
        target = str(options["url"])

    report_mod.set_no_color(bool(ctx.obj.get("no_color")))
    paths = report_mod.generate_report(results, output, formats=formats or ("html",), target=target)
    for path in paths.values():
        _log("ok", "report: %s" % path)


@test_sqli.command()
def gui() -> None:
    """Launch the graphical interface."""
    from .gui import launch_gui

    launch_gui()


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------


SHELL_HELP = """Commands:
  set <url>                     Set the current target.
  scan [url]                    Fingerprint and enumerate the target.
  dbs [url]                     List databases.
  tables <db> [url]             List tables in a database.
  columns <db> <table> [url]    List columns in a table.
  dump <db> <table> [url]       Dump a table.
  search <keyword> [url]        Search table and column names.
  schema [db] [url]             Show schema with column types.
  rows [db] [url]               Count rows per table.
  sql <query> [url]             Run a scalar SQL query.
  report [url]                  Scan and write HTML and JSON reports.
  gui                           Open the graphical interface.
  clear                         Clear the screen.
  help                          Show this help.
  exit                          Leave the shell.

A target set with 'set' is used when a command omits the URL.
"""


def _base_options() -> Dict[str, Any]:
    return dict(DEFAULT_OPTIONS)


def _shell_target(parts: Sequence[str], index: int, current: Optional[str]) -> Optional[str]:
    if len(parts) > index:
        candidate = parts[index]
        if candidate.startswith(("http://", "https://")):
            return candidate
    return current


def _shell_execute(options: Dict[str, Any], default_scan: bool = False) -> None:
    try:
        _execute(options, default_scan=default_scan)
    except SystemExit:
        pass


def interactive_shell() -> None:
    click.echo(BANNER)
    click.secho(WARNING, fg="yellow")
    click.echo()
    click.echo("Type 'help' for commands, 'exit' to quit.")
    click.echo()

    target: Optional[str] = None
    while True:
        try:
            raw = click.prompt("sqli", prompt_suffix="> ", default="", show_default=False)
        except (EOFError, KeyboardInterrupt):
            click.echo()
            break

        raw = raw.strip()
        if not raw:
            continue
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            _log("error", "could not parse input: %s" % exc)
            continue
        if not parts:
            continue

        command = parts[0].lower()
        if command in ("exit", "quit"):
            break
        if command in ("help", "?"):
            click.echo(SHELL_HELP)
            continue
        if command == "clear":
            click.clear()
            click.echo(BANNER)
            continue
        if command == "gui":
            try:
                from .gui import launch_gui

                launch_gui()
            except Exception as exc:
                _log("error", "GUI unavailable: %s" % exc)
            continue
        if command in ("set", "target"):
            if len(parts) < 2:
                _log("warn", "usage: set <url>")
                continue
            target = parts[1]
            if not target.startswith(("http://", "https://")):
                target = "https://" + target
            _log("ok", "target set to %s" % target)
            continue

        # Legacy form: <url> <command> [arguments].
        if command.startswith(("http://", "https://")):
            if len(parts) < 2:
                options = _base_options()
                options["url"] = parts[0]
                _shell_execute(options, default_scan=True)
                continue
            target = parts[0]
            parts = [parts[1]] + parts[2:]
            command = parts[0].lower()

        options = _base_options()
        options["url"] = target

        if command == "scan":
            options["url"] = _shell_target(parts, 1, target)
            _shell_execute(options, default_scan=True)
        elif command == "dbs":
            options["url"] = _shell_target(parts, 1, target)
            options["list_dbs"] = True
            _shell_execute(options)
        elif command == "tables":
            if len(parts) < 2:
                _log("warn", "usage: tables <db> [url]")
                continue
            options["database"] = parts[1]
            options["url"] = _shell_target(parts, 2, target)
            options["list_tables"] = True
            _shell_execute(options)
        elif command == "columns":
            if len(parts) < 3:
                _log("warn", "usage: columns <db> <table> [url]")
                continue
            options.update(database=parts[1], table=parts[2], list_columns=True)
            options["url"] = _shell_target(parts, 3, target)
            _shell_execute(options)
        elif command == "dump":
            if len(parts) < 3:
                _log("warn", "usage: dump <db> <table> [url]")
                continue
            options.update(database=parts[1], dump_table=parts[2])
            options["url"] = _shell_target(parts, 3, target)
            _shell_execute(options)
        elif command == "search":
            if len(parts) < 2:
                _log("warn", "usage: search <keyword> [url]")
                continue
            options["search"] = parts[1]
            options["url"] = _shell_target(parts, 2, target)
            _shell_execute(options)
        elif command == "schema":
            if len(parts) > 1 and not parts[1].startswith(("http://", "https://")):
                options["database"] = parts[1]
            options["url"] = _shell_target(parts, 2 if options["database"] else 1, target)
            options["schema"] = True
            _shell_execute(options)
        elif command == "rows":
            if len(parts) > 1 and not parts[1].startswith(("http://", "https://")):
                options["database"] = parts[1]
            options["url"] = _shell_target(parts, 2 if options["database"] else 1, target)
            options["count_rows"] = True
            _shell_execute(options)
        elif command in ("sql", "query"):
            if len(parts) < 2:
                _log("warn", "usage: sql <query> [url]")
                continue
            options["sql_query"] = parts[1]
            options["url"] = _shell_target(parts, 2, target)
            _shell_execute(options)
        elif command == "report":
            options["url"] = _shell_target(parts, 1, target)
            if not options["url"]:
                _log("warn", "set a target first")
                continue
            results = _run_engine(_default_scan(options))
            if results:
                report_mod.generate_report(
                    results,
                    "sqli_report",
                    formats=("html", "json"),
                    target=str(options["url"]),
                )
        else:
            _log("warn", "unknown command: %s" % command)
            click.echo("Type 'help' for available commands.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_sqli()
    else:
        interactive_shell()
