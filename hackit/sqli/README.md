# HackIt SQL Injection Engine

A multi-DBMS SQL injection scanner, enumerator, and data extraction engine. The
heavy lifting is done by a Go worker. Python provides the command line
interface, report generation, and the desktop interface.

Use this module only against systems you own or have explicit written
permission to test.

## Features

- Injection point discovery in query strings, form bodies, JSON bodies,
  cookies, and custom headers.
- Boundary detection for string, numeric, parenthesized, and quoted contexts.
- Confirmation through UNION, error based, boolean, and time based oracles.
- DBMS fingerprinting with version detection, including boolean-only and
  time-only targets.
- Enumeration of databases, tables, columns, schemas, row counts, users,
  password hashes, and roles.
- Table dumps with column selection, row limits, and offsets.
- Free-form scalar SQL extraction through the confirmed technique.
- Blind extraction with a configurable character set and maximum length.
- Report export to HTML, JSON, CSV, and plain text.
- JSON and NDJSON output for automation.
- Interactive shell and a Tkinter desktop interface.
- No external database drivers. Everything runs through the target
  application.

## Supported DBMS

| DBMS | Aliases | Enumeration | Dump | File read | OS command |
| --- | --- | --- | --- | --- | --- |
| MySQL | MariaDB, Percona | yes | yes | yes | yes |
| PostgreSQL | postgres | yes | yes | yes | yes |
| Microsoft SQL Server | mssql | yes | yes | yes | stacked query only |
| Oracle | ora | yes | yes | yes | no |
| SQLite | sqlite3 | yes | yes | no | no |
| ClickHouse | - | yes | yes | yes | no |
| DuckDB | - | yes | yes | yes | no |
| CockroachDB | - | yes | yes | yes | no |
| Snowflake | - | yes | yes | no | no |
| BigQuery | - | yes | yes | no | no |
| Firebird | - | yes | yes | no | no |
| Sybase | - | yes | yes | yes | stacked query only |
| H2 | - | yes | yes | no | no |

Actual capabilities depend on the database account, the injection context, and
the technique that the target allows. A feature marked yes still requires
enough privileges on the target.

## Requirements

- Go 1.21 or newer to build the worker.
- Python 3.9 or newer.
- Python packages used by the rest of HackIt: `click`, `rich`.
- `tkinter` for the desktop interface.

## Build

Build the Go worker once after cloning or after changing Go code:

```bash
cd hackit/sqli/go
go build -o bin/worker .
```

The Python bridge also attempts to build the worker automatically when the
binary is missing and Go is installed.

## Quick start

Fingerprint the target and enumerate its databases and tables:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" scan
```

List databases:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" dbs
```

List tables in a database:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" tables appdb
```

Dump a table:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" dump appdb users --rows 20
```

Run a scalar query:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" sql "SELECT version()"
```

Write an HTML report after a scan:

```bash
hackit vuln sqli -u "http://target.test/item?id=1" report --format html --output sqli_report
```

Generate a report from a previously saved JSON report:

```bash
hackit vuln sqli report --input sqli_report.json --format html --output rebuilt
```

## Direct flags

The same actions are available without a subcommand. Group options must come
before a subcommand when both are used.

```bash
# Enumerate databases and dump one table.
hackit vuln sqli -u "http://target.test/item?id=1" --dbs --dump-table users --db appdb

# Dump every non-system table.
hackit vuln sqli -u "http://target.test/item?id=1" --dump-all

# Extract through a forced technique.
hackit vuln sqli -u "http://target.test/item?id=1" --technique boolean \
  --sql-query "SELECT password FROM users WHERE id=1"

# Use a fixed delay for time based extraction.
hackit vuln sqli -u "http://target.test/item?id=1" --technique time \
  --time-secs 2 --sql-query "SELECT current_database()"

# Force the injection boundary.
hackit vuln sqli -u "http://target.test/search?q=alice" --prefix "'" --suffix "-- -"

# Send a JSON body.
hackit vuln sqli -u "http://target.test/api/user" -X POST \
  --data '{"id":1}' --dump-table users

# Test a cookie or a header.
hackit vuln sqli -u "http://target.test/profile" --cookie "uid=1" --level 2 --dbs
hackit vuln sqli -u "http://target.test/profile" -H "X-User-Id: 1" --level 3 --dbs
```

## Important options

### Request

| Option | Description |
| --- | --- |
| `-u`, `--url` | Target URL. |
| `--data` | Form encoded or JSON request body. |
| `-X`, `--method` | HTTP method. Default GET. |
| `--cookie` | Cookie header. |
| `-H`, `--header` | Extra header. Repeatable. |
| `--proxy` | HTTP proxy URL. |
| `--timeout` | Per-request timeout in seconds. |
| `--follow-redirect` | Follow HTTP redirects. |
| `--level` | 1 query and body, 2 adds cookies, 3 adds headers. |

### Injection

| Option | Description |
| --- | --- |
| `--technique` | `auto`, `union`, `error`, `boolean`, `time`, or `stacked`. |
| `--extract-technique` | `auto`, `union`, `error`, `boolean`, `blind`, or `time`. |
| `--dbms` | Force a DBMS instead of fingerprinting. |
| `--prefix` / `--suffix` | Force the injection boundary. |
| `--param` / `--skip-param` | Include or exclude parameters by name. |
| `--tamper` | Tamper script name. Repeatable. |
| `--encode` | `url`, `double`, or `base64`. |
| `--randomize-case` | Randomize payload letter case. |
| `--bypass-waf` | Use WAF bypass payloads. |
| `--stealth` | Use low noise request pacing. |
| `--time-secs` | Delay used by time based tests and extraction. |
| `--extract-charset` | Character set for blind extraction. |
| `--max-length` | Maximum length for blind extraction. |

### Enumeration and extraction

| Option | Description |
| --- | --- |
| `--dbs` | List databases. |
| `--tables` | List tables. |
| `--columns` | List columns. |
| `--schema` | Show tables and column types. |
| `--count-rows` | Count rows per table. |
| `--dump-table` | Dump one table. |
| `--dump-all` | Dump every non-system table. |
| `--db` | Database name. |
| `--table` | Table name. |
| `--columns-csv` | Columns to dump, comma separated. |
| `--rows`, `--limit`, `--offset` | Row limits and pagination. |
| `--where` | Reserved for filtered dumps. Currently emits a warning. |
| `--search` | Search table and column names. |
| `--sql-query` | Run a scalar SQL query. |
| `--current-db` | Show the current database. |
| `--current-user` | Show the current database user. |
| `--hostname` | Show the database hostname. |
| `--banner` | Show the DBMS banner. |
| `--privileges` | Show database privileges. |
| `--is-dba` | Check for DBA privileges. |
| `--users` | List database users. |
| `--passwords` | List password hashes. |
| `--roles` | List database roles. |
| `--fingerprint` | Fingerprint the DBMS and session. |
| `--file-read` | Read a file through the database. |
| `--file-exec` | Execute an OS command through the database. |
| `--file-write` | Reserved for file writes. Currently emits a warning. |

### Output

| Option | Description |
| --- | --- |
| `--format` | `text`, `json`, or `ndjson`. |
| `--no-color` | Disable colored output. |
| `-v`, `--verbose` | Show engine progress. Repeatable. |
| `--report` | Write a report after the run. The extension selects the format. |

Logs always go to standard error, so `--format json` keeps standard output
clean for pipelines.

## Subcommands

```text
scan                         Fingerprint, enumerate databases, list tables
dbs                          List databases
tables <database>            List tables
columns <database> <table>   List columns
dump <database> <table>      Dump a table
search <keyword>             Search table and column names
schema [database]            Show schema with column types
rows [database]              Count rows per table
sql <query>                  Run a scalar SQL query
extract --query <query>      Extract with an explicit technique
crawl [--mode full|schema]   Schema, row counts, and data dump
readfile --file <path>       Read a file through the database
exec --cmd <command>         Execute an OS command through the database
report                       Generate a report from a scan or a JSON file
gui                          Launch the desktop interface
```

`crawl` is a composition of schema enumeration, column listing, row counts,
and a full table dump. Use `--mode schema` to skip the data dump. The `--output`
value is a report base path, so `crawl --output reports/db` writes
`reports/db.html` and `reports/db.json`.

## Interactive shell

Run the module without a URL to enter the shell:

```bash
python -m hackit.sqli
```

Or start it from the main CLI:

```bash
hackit vuln sqli
```

Commands:

```text
set <url>
scan [url]
dbs [url]
tables <db> [url]
columns <db> <table> [url]
dump <db> <table> [url]
search <keyword> [url]
schema [db] [url]
rows [db] [url]
sql <query> [url]
report [url]
gui
clear
help
exit
```

## Desktop interface

```bash
hackit vuln sqli gui
```

The interface exposes the same request options, technique selection, discovery
and extraction actions, a findings table, enumeration view, data browser, and
a live worker log. Reports can be exported from the interface.

## Output formats

### Text

Human readable tables and sections. This is the default.

### JSON

A JSON array of result objects on standard output. Each object can contain:

```json
{
  "parameter": "id",
  "type": "dump-table",
  "payload": "3 rows",
  "dbms": "SQLite",
  "dbms_version": "3.46.1",
  "details": "main.users",
  "confidence": 1.0,
  "location": "query",
  "technique": "union",
  "prefix": "'",
  "suffix": "-- -",
  "columns": 4,
  "column_names": ["id", "username", "email", "role"],
  "rows": [["1", "alice", "alice@example.test", "admin"]]
}
```

### NDJSON

One JSON object per line. Useful for streaming into another tool.

## Reports

`report` writes one file per requested format. The output value is a base path
without an extension.

```bash
hackit vuln sqli -u "http://target.test/item?id=1" report \
  --format html --format json --format csv --format txt \
  --output reports/assessment
```

The HTML report is self contained, escapes untrusted values, and includes a
summary, findings, enumeration, metadata, and extracted data. The JSON report
contains a summary block and the raw result list. The CSV report has one row
per finding, enumeration value, or data row. The text report is suitable for
tickets and terminal review.

## How it works

1. `DiscoverInjectionPoints` builds injection points from the URL, body,
   cookies, and headers. Cookies require level 2. Headers require level 3.
2. The engine requests the target and captures a baseline response.
3. `DetectBoundary` tries known prefix and suffix pairs. Each candidate is
   checked with boolean, error, time, and UNION probes. A candidate is accepted
   only when the true and false responses are stable and clearly different.
4. `IdentifyDBMS` tries dialect version expressions through UNION and error
   output. If neither works, it uses the confirmed boolean oracle. Targets that
   only answer through timing use the time oracle.
5. `DetectUnionColumns` finds the column count and the first string compatible
   column for in-band extraction.
6. `Executor.Scalar` selects the extraction path. It honors a forced
   `--extract-technique` or `--technique`. Blind extraction uses binary search
   over the configured character set. Time extraction uses dialect specific
   delay primitives.
7. `Explorer` runs the requested enumeration, dumps, account checks, searches,
   and scalar queries.
8. Python renders the result list or writes report files.

The primary pipeline is `StartV2`. If no boundary is confirmed, the engine
falls back to the legacy scanner so that targets with unusual contexts still
receive a best effort assessment.

## Project layout

```text
hackit/sqli/
  __init__.py          CLI, subcommands, interactive shell
  __main__.py          python -m hackit.sqli entry point
  go_bridge.py         Python to Go worker bridge
  report.py            Console, HTML, JSON, CSV, and text reports
  gui.py               Tkinter desktop interface
  go/
    main.go            Worker flags and entry point
    core/
      session.go       Session and injection point discovery
      boundary.go      Boundary detection and DBMS fingerprint
      dialect.go       DBMS dialects and SQL primitives
      executor.go      Extraction oracles and binary search
      explorer.go      Enumeration, dumps, and queries
      scanner_v2.go    Primary scan pipeline
      similarity.go    Response normalization and comparison
      helpers_test.go  Unit tests for core helpers
  tests/               Python unit tests
```

## Testing

Go unit tests:

```bash
cd hackit/sqli/go
go test ./...
```

Python unit tests:

```bash
python3 -m unittest discover -s hackit/sqli/tests -v
```

The end to end suite used during development runs the worker against a local
intentionally vulnerable SQLite application. It covers numeric and string GET
parameters, form and JSON POST bodies, cookies, headers, UNION dumps, scalar
queries, table search, fingerprinting, blind boolean extraction, and time based
extraction.

## Limitations

- `--where` is not applied by the current row extractor. Use `--sql-query` for
  filtered extraction.
- `--file-write` is not implemented through the extraction path. Use
  `--sql-query` with a dialect specific statement when the account allows it.
- Stacked query execution depends on the driver and is not available on every
  DBMS.
- Time based extraction is slow by design. Prefer UNION or error based
  extraction when the target allows it.
- Blind extraction assumes the configured character set contains every
  character in the value. Increase `--extract-charset` or `--max-length` when a
  value is truncated.
- The worker binary is not rebuilt automatically when it already exists.
  Rebuild it after changing Go code.

## Legal

This tool is for authorized security testing, research, and education. You are
responsible for complying with the law and with the scope of your engagement.
