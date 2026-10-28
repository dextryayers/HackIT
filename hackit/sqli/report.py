"""Report generation for SQL injection results.

The report layer is intentionally independent from the engine. It accepts the
JSON result list produced by the Go worker and renders it as console output,
HTML, JSON, CSV, or plain text.
"""

from __future__ import annotations

import csv
import html
import json
import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from rich import box
from rich.console import Console
from rich.table import Table

_console = Console()
_error_console = Console(stderr=True)


def set_no_color(enabled: bool = True) -> None:
    """Disable or enable ANSI colors for console reports."""
    _console.no_color = enabled
    _error_console.no_color = enabled

FINDING_TYPES = {"boolean", "error", "time", "union", "stacked", "auth-bypass"}

LIST_TYPES = {
    "list-dbs",
    "list-tables",
    "list-columns",
    "schema",
    "count-rows",
    "users",
    "passwords",
    "roles",
    "search-tables",
    "search",
}

SCALAR_TYPES = {
    "current-db",
    "current-user",
    "hostname",
    "banner",
    "privileges",
    "is-dba",
    "sql-query",
    "os-cmd",
    "file-read",
}

TYPE_LABELS = {
    "boolean": "Boolean",
    "error": "Error based",
    "time": "Time based",
    "union": "UNION based",
    "stacked": "Stacked query",
    "auth-bypass": "Authentication bypass",
    "list-dbs": "Databases",
    "list-tables": "Tables",
    "list-columns": "Columns",
    "schema": "Schema",
    "count-rows": "Row counts",
    "dump-table": "Table data",
    "sql-query": "SQL query",
    "current-db": "Current database",
    "current-user": "Current user",
    "hostname": "Hostname",
    "banner": "Banner",
    "privileges": "Privileges",
    "is-dba": "DBA check",
    "users": "Database users",
    "passwords": "Password hashes",
    "roles": "Roles",
    "search-tables": "Table search",
    "search": "Search",
    "os-cmd": "OS command",
    "file-read": "File read",
    "file-write": "File write",
}


def severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "Critical"
    if confidence >= 0.7:
        return "High"
    if confidence >= 0.4:
        return "Medium"
    return "Low"


def split_values(value: Any) -> List[str]:
    """Split an enumeration payload into individual values."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item) != ""]
    text = str(value)
    if text == "":
        return []
    if any(separator in text for separator in ("\x1e", "\x1f", "\n")):
        normalized = text.replace("\x1e", "\n").replace("\x1f", "\n")
        return [part.strip() for part in normalized.split("\n") if part.strip()]
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text.strip()]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, default=str)


def result_table(result: Dict[str, Any]) -> Tuple[List[str], List[List[str]]]:
    """Return columns and rows for a dump-table result."""
    columns = [str(item) for item in result.get("column_names") or []]
    rows = [[_as_text(cell) for cell in row] for row in result.get("rows") or []]
    if not columns:
        payload = result.get("payload", "")
        if isinstance(payload, str) and payload.lstrip().startswith("["):
            try:
                parsed = json.loads(payload)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, list) and parsed:
                if isinstance(parsed[0], dict):
                    columns = list(parsed[0].keys())
                    rows = [[_as_text(row.get(col, "")) for col in columns] for row in parsed]
                else:
                    columns = ["Value"]
                    rows = [[_as_text(row)] for row in parsed]
    if not columns and rows:
        columns = ["Column %d" % (index + 1) for index in range(len(rows[0]))]
    return columns, rows


def summarize(results: Sequence[Dict[str, Any]], target: str = "") -> Dict[str, Any]:
    findings = [item for item in results if item.get("type") in FINDING_TYPES]
    databases: List[str] = []
    tables: List[str] = []
    dump_tables = 0
    dumped_rows = 0
    dbms = ""
    version = ""
    techniques = set()
    parameters = set()
    locations = set()

    for item in results:
        if item.get("dbms") and not dbms:
            dbms = str(item["dbms"])
        if item.get("dbms_version") and not version:
            version = str(item["dbms_version"])
        if item.get("technique"):
            techniques.add(str(item["technique"]))
        if item.get("parameter"):
            parameters.add(str(item["parameter"]))
        if item.get("location"):
            locations.add(str(item["location"]))
        kind = item.get("type")
        if kind == "list-dbs":
            for value in split_values(item.get("payload")):
                if value not in databases:
                    databases.append(value)
        elif kind == "list-tables":
            for value in split_values(item.get("payload")):
                if value not in tables:
                    tables.append(value)
        elif kind == "dump-table":
            dump_tables += 1
            dumped_rows += len(item.get("rows") or [])

    return {
        "target": target,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "dbms": dbms or "Unknown",
        "dbms_version": version,
        "vulnerable": bool(findings),
        "findings": len(findings),
        "parameters": sorted(parameters),
        "locations": sorted(locations),
        "techniques": sorted(techniques),
        "databases": databases,
        "table_count": len(tables),
        "dump_tables": dump_tables,
        "dumped_rows": dumped_rows,
        "result_count": len(results),
    }


def _summary_table(summary: Dict[str, Any]) -> Table:
    table = Table(box=box.ASCII, show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    if summary.get("target"):
        table.add_row("Target", summary["target"])
    table.add_row("DBMS", summary["dbms"] + (
        " " + summary["dbms_version"] if summary.get("dbms_version") else ""
    ))
    table.add_row("Vulnerable", "yes" if summary["vulnerable"] else "no")
    if summary["parameters"]:
        table.add_row("Parameters", ", ".join(summary["parameters"]))
    if summary["techniques"]:
        table.add_row("Techniques", ", ".join(summary["techniques"]))
    if summary["databases"]:
        table.add_row("Databases", ", ".join(summary["databases"]))
    if summary["table_count"]:
        table.add_row("Tables", str(summary["table_count"]))
    if summary["dump_tables"]:
        table.add_row("Dumped tables", str(summary["dump_tables"]))
        table.add_row("Dumped rows", str(summary["dumped_rows"]))
    return table


def print_console(
    results: List[Dict[str, Any]],
    title: str = "SQL injection assessment",
    target: str = "",
) -> None:
    """Print results in a compact, readable console layout."""
    if not results:
        _console.print("[yellow]No results.[/]")
        return

    summary = summarize(results, target=target)
    _console.print()
    _console.print("[bold]%s[/]" % title)
    _console.print(_summary_table(summary))

    findings = [item for item in results if item.get("type") in FINDING_TYPES]
    if findings:
        table = Table(title="Findings", box=box.ASCII)
        table.add_column("#", justify="right")
        table.add_column("Parameter")
        table.add_column("Location")
        table.add_column("Technique")
        table.add_column("DBMS")
        table.add_column("Confidence", justify="right")
        for index, item in enumerate(findings, 1):
            table.add_row(
                str(index),
                str(item.get("parameter", "")),
                str(item.get("location", "")),
                str(item.get("technique") or item.get("type", "")),
                str(item.get("dbms", "")),
                "%.0f%%" % (float(item.get("confidence") or 0) * 100),
            )
        _console.print(table)

    _print_enumeration(results)
    _print_scalars(results)
    _print_data(results)
    _console.print()


def _print_enumeration(results: Sequence[Dict[str, Any]]) -> None:
    grouped: Dict[str, List[Tuple[str, str]]] = {}
    for item in results:
        kind = str(item.get("type", ""))
        if kind not in ("list-dbs", "list-tables", "list-columns", "schema", "count-rows",
                        "users", "passwords", "roles", "search-tables", "search"):
            continue
        details = str(item.get("details", ""))
        for value in split_values(item.get("payload")):
            grouped.setdefault(kind, []).append((details, value))

    titles = {
        "list-dbs": "Databases",
        "list-tables": "Tables",
        "list-columns": "Columns",
        "schema": "Schema",
        "count-rows": "Row counts",
        "users": "Database users",
        "passwords": "Password hashes",
        "roles": "Roles",
        "search-tables": "Table search",
        "search": "Search results",
    }

    layouts = {
        "list-dbs": ("Database",),
        "list-tables": ("Database", "Table"),
        "list-columns": ("Table", "Column"),
        "schema": ("Table", "Definition"),
        "count-rows": ("Table", "Rows"),
        "users": ("Database user",),
        "passwords": ("Password hash",),
        "roles": ("Role",),
        "search-tables": ("Match",),
        "search": ("Result",),
    }

    for kind, entries in grouped.items():
        headers = layouts.get(kind, ("Detail", "Value"))
        table = Table(title=titles.get(kind, TYPE_LABELS.get(kind, kind)), box=box.ASCII)
        for header in headers:
            table.add_column(header)
        for details, value in entries:
            if len(headers) == 1:
                table.add_row(value)
            else:
                table.add_row(details or "-", value)
        _console.print(table)


def _print_scalars(results: Sequence[Dict[str, Any]]) -> None:
    table = Table(title="Metadata", box=box.ASCII)
    table.add_column("Item")
    table.add_column("Value")
    found = False
    for item in results:
        kind = str(item.get("type", ""))
        if kind not in SCALAR_TYPES:
            continue
        found = True
        label = TYPE_LABELS.get(kind, kind)
        details = str(item.get("details", ""))
        if details and details.lower() != label.lower():
            label = "%s (%s)" % (label, details)
        table.add_row(label, _as_text(item.get("payload", "")))
    if found:
        _console.print(table)


def _print_data(results: Sequence[Dict[str, Any]]) -> None:
    for item in results:
        if item.get("type") != "dump-table":
            continue
        columns, rows = result_table(item)
        if not columns:
            continue
        table = Table(title="Data: %s" % item.get("details", "table"), box=box.ASCII)
        for column in columns:
            table.add_column(str(column))
        for row in rows:
            padded = list(row) + [""] * (len(columns) - len(row))
            table.add_row(*padded[: len(columns)])
        _console.print(table)


def _html_rows(columns: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    head = "".join("<th>%s</th>" % html.escape(str(col)) for col in columns)
    body = []
    for row in rows:
        cells = "".join("<td>%s</td>" % html.escape(_as_text(cell)) for cell in row)
        body.append("<tr>%s</tr>" % cells)
    return (
        "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>"
        % (head, "".join(body))
    )


def _html_sections(results: Sequence[Dict[str, Any]]) -> str:
    parts: List[str] = []

    enum_rows: List[Tuple[str, str, str]] = []
    for item in results:
        kind = str(item.get("type", ""))
        if kind in ("list-dbs", "list-tables", "list-columns", "schema", "count-rows",
                    "users", "passwords", "roles", "search-tables", "search"):
            for value in split_values(item.get("payload")):
                enum_rows.append((TYPE_LABELS.get(kind, kind), str(item.get("details", "")), value))
    if enum_rows:
        parts.append("<h2>Enumeration</h2>")
        parts.append(
            _html_rows(["Section", "Object", "Value"], enum_rows)
        )

    scalar_rows: List[Tuple[str, str]] = []
    for item in results:
        kind = str(item.get("type", ""))
        if kind in SCALAR_TYPES:
            label = TYPE_LABELS.get(kind, kind)
            details = str(item.get("details", ""))
            if details and details.lower() != label.lower():
                label = "%s (%s)" % (label, details)
            scalar_rows.append((label, _as_text(item.get("payload", ""))))
    if scalar_rows:
        parts.append("<h2>Metadata</h2>")
        parts.append(_html_rows(["Item", "Value"], scalar_rows))

    for item in results:
        if item.get("type") != "dump-table":
            continue
        columns, rows = result_table(item)
        if not columns:
            continue
        parts.append("<h2>Data: %s</h2>" % html.escape(str(item.get("details", "table"))))
        parts.append(_html_rows(columns, rows))

    return "\n".join(parts)


def generate_html(
    results: List[Dict[str, Any]],
    output_path: str,
    target: str = "",
    crawl_results: Optional[Dict[str, Any]] = None,
) -> str:
    """Write a self-contained HTML report."""
    summary = summarize(results, target=target)
    findings = [item for item in results if item.get("type") in FINDING_TYPES]

    finding_rows = []
    for index, item in enumerate(findings, 1):
        confidence = float(item.get("confidence") or 0)
        finding_rows.append(
            "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td><span class=\"badge %s\">%s</span></td></tr>"
            % (
                index,
                html.escape(str(item.get("parameter", ""))),
                html.escape(str(item.get("location", ""))),
                html.escape(str(item.get("technique") or item.get("type", ""))),
                html.escape(str(item.get("dbms", ""))),
                html.escape(str(item.get("details", ""))),
                severity(confidence).lower(),
                severity(confidence),
            )
        )

    if finding_rows:
        findings_html = (
            "<table><thead><tr><th>#</th><th>Parameter</th><th>Location</th>"
            "<th>Technique</th><th>DBMS</th><th>Details</th><th>Severity</th>"
            "</tr></thead><tbody>%s</tbody></table>" % "".join(finding_rows)
        )
    else:
        findings_html = "<p class=\"muted\">No injection was confirmed.</p>"

    meta_rows = [
        ("Target", summary.get("target") or "not recorded"),
        ("DBMS", summary["dbms"] + (" " + summary["dbms_version"] if summary["dbms_version"] else "")),
        ("Vulnerable", "yes" if summary["vulnerable"] else "no"),
        ("Parameters", ", ".join(summary["parameters"]) or "none"),
        ("Techniques", ", ".join(summary["techniques"]) or "none"),
        ("Databases", ", ".join(summary["databases"]) or "none"),
        ("Tables", str(summary["table_count"])),
        ("Dumped tables", str(summary["dump_tables"])),
        ("Dumped rows", str(summary["dumped_rows"])),
    ]
    meta_html = "".join(
        "<tr><th>%s</th><td>%s</td></tr>" % (html.escape(key), html.escape(value))
        for key, value in meta_rows
    )

    document = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQL injection report</title>
<style>
:root {{
  color-scheme: light;
  --ink: #1f2328;
  --muted: #59636e;
  --line: #d0d7de;
  --panel: #f6f8fa;
  --accent: #0969da;
  --critical: #cf222e;
  --high: #bc4c00;
  --medium: #9a6700;
  --low: #1a7f37;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  padding: 40px 24px;
  background: #ffffff;
  color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}}
main {{ max-width: 1100px; margin: 0 auto; }}
header {{ border-bottom: 1px solid var(--line); padding-bottom: 18px; margin-bottom: 28px; }}
h1 {{ margin: 0 0 6px; font-size: 28px; letter-spacing: -0.02em; }}
h2 {{ margin: 34px 0 12px; font-size: 20px; }}
p {{ margin: 0 0 12px; }}
.muted {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; margin: 0 0 18px; font-size: 14px; }}
th, td {{ border: 1px solid var(--line); padding: 8px 10px; text-align: left; vertical-align: top; }}
th {{ background: var(--panel); font-weight: 600; }}
tr:nth-child(even) td {{ background: #fbfcfd; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
.badge.critical {{ background: #ffebe9; color: var(--critical); }}
.badge.high {{ background: #fff1e5; color: var(--high); }}
.badge.medium {{ background: #fff8c5; color: var(--medium); }}
.badge.low {{ background: #dafbe1; color: var(--low); }}
footer {{ margin-top: 36px; border-top: 1px solid var(--line); padding-top: 14px; color: var(--muted); font-size: 13px; }}
</style>
</head>
<body>
<main>
<header>
<h1>SQL injection report</h1>
<p class="muted">Generated {generated} by the HackIT SQL injection engine.</p>
</header>
<h2>Summary</h2>
<table>{meta}</table>
<h2>Findings</h2>
{findings}
{sections}
<footer>This report contains security testing results. Handle it as sensitive data.</footer>
</main>
</body>
</html>
""".format(
        generated=html.escape(summary["generated_at"]),
        meta=meta_html,
        findings=findings_html,
        sections=_html_sections(results),
    )

    _ensure_parent(output_path)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(document)
    _error_console.print("[green]HTML report written:[/] %s" % output_path)
    return output_path


def generate_csv(results: List[Dict[str, Any]], output_path: str) -> str:
    """Write one CSV row per finding, enumeration value, or data row."""
    _ensure_parent(output_path)
    fieldnames = [
        "section", "parameter", "type", "dbms", "dbms_version", "location",
        "technique", "details", "payload", "column", "value",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            base = {
                "parameter": item.get("parameter", ""),
                "type": item.get("type", ""),
                "dbms": item.get("dbms", ""),
                "dbms_version": item.get("dbms_version", ""),
                "location": item.get("location", ""),
                "technique": item.get("technique", ""),
                "details": item.get("details", ""),
            }
            if item.get("type") == "dump-table":
                columns, rows = result_table(item)
                for row in rows:
                    record = dict(base)
                    record["section"] = "data"
                    record["column"] = "|".join(columns)
                    record["value"] = "|".join(row)
                    writer.writerow(record)
                continue
            if item.get("type") in LIST_TYPES:
                for value in split_values(item.get("payload")):
                    record = dict(base)
                    record["section"] = "enumeration"
                    record["value"] = value
                    writer.writerow(record)
                continue
            record = dict(base)
            record["section"] = "finding" if item.get("type") in FINDING_TYPES else "metadata"
            record["payload"] = _as_text(item.get("payload", ""))
            writer.writerow(record)
    _error_console.print("[green]CSV report written:[/] %s" % output_path)
    return output_path


def generate_json(
    results: List[Dict[str, Any]],
    output_path: str,
    target: str = "",
    extra_data: Optional[Dict[str, Any]] = None,
) -> str:
    """Write a JSON report with summary metadata."""
    report: Dict[str, Any] = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "engine": "HackIT SQL injection engine",
        "summary": summarize(results, target=target),
        "results": results,
    }
    if extra_data:
        report["extra"] = extra_data
    _ensure_parent(output_path)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, default=str)
    _error_console.print("[green]JSON report written:[/] %s" % output_path)
    return output_path


def generate_txt(
    results: List[Dict[str, Any]],
    output_path: str,
    target: str = "",
) -> str:
    """Write a plain text report."""
    summary = summarize(results, target=target)
    lines: List[str] = [
        "SQL injection report",
        "=" * 72,
        "Generated : %s" % summary["generated_at"],
        "Target    : %s" % (summary["target"] or "not recorded"),
        "DBMS      : %s" % (
            summary["dbms"] + (" " + summary["dbms_version"] if summary["dbms_version"] else "")
        ),
        "Vulnerable: %s" % ("yes" if summary["vulnerable"] else "no"),
        "Findings  : %d" % summary["findings"],
        "",
    ]

    findings = [item for item in results if item.get("type") in FINDING_TYPES]
    if findings:
        lines.append("Findings")
        lines.append("-" * 72)
        for index, item in enumerate(findings, 1):
            confidence = float(item.get("confidence") or 0)
            lines.extend([
                "%d. %s" % (index, TYPE_LABELS.get(str(item.get("type")), item.get("type"))),
                "   Parameter : %s" % item.get("parameter", ""),
                "   Location  : %s" % item.get("location", ""),
                "   Technique : %s" % item.get("technique", ""),
                "   DBMS      : %s" % item.get("dbms", ""),
                "   Severity  : %s (%.0f%%)" % (severity(confidence), confidence * 100),
                "   Details   : %s" % item.get("details", ""),
                "",
            ])

    for item in results:
        kind = str(item.get("type", ""))
        if kind in LIST_TYPES:
            values = split_values(item.get("payload"))
            if not values:
                continue
            lines.append("%s (%s)" % (TYPE_LABELS.get(kind, kind), item.get("details", "")))
            lines.append("-" * 72)
            for value in values:
                lines.append("  %s" % value)
            lines.append("")
        elif kind in SCALAR_TYPES:
            lines.append("%s: %s" % (TYPE_LABELS.get(kind, kind), _as_text(item.get("payload", ""))))
        elif kind == "dump-table":
            columns, rows = result_table(item)
            if not columns:
                continue
            lines.append("Data: %s" % item.get("details", "table"))
            lines.append("-" * 72)
            lines.append(" | ".join(columns))
            for row in rows:
                lines.append(" | ".join(row))
            lines.append("")

    lines.extend(["", "End of report", "=" * 72])
    _ensure_parent(output_path)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    _error_console.print("[green]TXT report written:[/] %s" % output_path)
    return output_path


def generate_report(
    results: List[Dict[str, Any]],
    output_base: str,
    formats: Iterable[str] = ("html",),
    target: str = "",
) -> Dict[str, str]:
    """Generate one or more report files and return their paths."""
    paths: Dict[str, str] = {}
    for output_format in formats:
        name = output_format.lower().strip()
        if name not in ("html", "json", "csv", "txt"):
            raise ValueError("unsupported report format: %s" % output_format)
        path = "%s.%s" % (output_base, name)
        if name == "html":
            paths[name] = generate_html(results, path, target=target)
        elif name == "json":
            paths[name] = generate_json(results, path, target=target)
        elif name == "csv":
            paths[name] = generate_csv(results, path)
        else:
            paths[name] = generate_txt(results, path, target=target)
    return paths


def auto_generate(
    results: List[Dict[str, Any]],
    base_name: str = "sqli_report",
    crawl_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Generate every report format. Kept for API compatibility."""
    return generate_report(
        results,
        base_name,
        formats=("html", "json", "csv", "txt"),
    )


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
