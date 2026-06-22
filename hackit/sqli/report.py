"""
Advanced Report Generator — HTML, CSV, JSON, TXT with crawl results, sensitive data, visualizations
"""

import json
import csv
import os
import html as html_mod
from datetime import datetime
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table

_console = Console()


def _severity(confidence: float) -> str:
    if confidence >= 0.9: return "CRITICAL"
    if confidence >= 0.7: return "HIGH"
    if confidence >= 0.4: return "MEDIUM"
    return "LOW"


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ff4444", "HIGH": "#ff8800",
            "MEDIUM": "#ffcc00", "LOW": "#88ff88"}.get(sev, "#ffffff")


def _risk_icon(sev: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")


# ── Console Output ───────────────────────────────────────────

def print_console(results: List[Dict[str, Any]], title: str = "Scan Results"):
    """Pretty-print results to console using Rich"""
    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    _console.print(f"\n[bold cyan]═══ {title} ═══[/]")
    _console.print(f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]")

    if findings:
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim")
        table.add_column("Parameter")
        table.add_column("Type")
        table.add_column("DBMS")
        table.add_column("Confidence")
        table.add_column("Payload")

        for i, r in enumerate(findings[:20], 1):
            conf = r.get('confidence', 0)
            sev = _severity(conf)
            color = _severity_color(sev)
            table.add_row(
                str(i),
                r.get('parameter', 'N/A'),
                r.get('type', 'N/A'),
                r.get('dbms', 'Unknown'),
                f"[{color}]{sev} ({conf*100:.0f}%)[/]",
                str(r.get('payload', ''))[:60]
            )
        _console.print(table)

        if len(findings) > 20:
            _console.print(f"[dim]... and {len(findings)-20} more findings[/]")

    # Enumeration summary
    if enums:
        _console.print(f"\n[bold yellow]📊 Enumeration: {len(enums)} items[/]")

    return results


# ── HTML Report ──────────────────────────────────────────────

def generate_html(results: List[Dict[str, Any]], output_path: str,
                  title: str = "SQLi Scan Report",
                  crawl_results: Dict = None) -> str:
    """Generate comprehensive HTML report with crawl data"""
    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    vuln_rows = ""
    for i, r in enumerate(findings, 1):
        conf = r.get('confidence', 0)
        sev = _severity(conf)
        color = _severity_color(sev)
        icon = _risk_icon(sev)
        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td>{html_mod.escape(str(r.get('parameter', 'N/A')))}</td>
            <td>{html_mod.escape(str(r.get('type', 'N/A')))}</td>
            <td>{html_mod.escape(str(r.get('dbms', 'Unknown')))}</td>
            <td style="color:{color};font-weight:bold">{icon} {sev} ({conf*100:.0f}%)</td>
            <td><code>{html_mod.escape(str(r.get('payload', ''))[:120])}</code></td>
        </tr>"""

    enum_html = ""
    for e in enums:
        etype = e.get('type', '')
        detail = e.get('details', '')
        items = [s.strip() for s in str(e.get('payload', '')).split(',') if s.strip()]
        enum_html += f"""
        <div class="enum-section">
            <h3>📋 {html_mod.escape(str(etype))} - {html_mod.escape(str(detail))}</h3>
            <ul>{"".join(f'<li>{html_mod.escape(item)}</li>' for item in items[:80])}</ul>
            {f"<p><em>... and {len(items)-80} more</em></p>" if len(items) > 80 else ""}
        </div>"""

    # Crawl results section
    crawl_html = ""
    if crawl_results:
        sensitive = crawl_results.get('Sensitive', [])
        summary = crawl_results.get('Summary', {})
        system_info = crawl_results.get('SystemInfo', {})
        databases = crawl_results.get('Databases', {})

        crawl_html += '<h2>📦 Crawl Results</h2>'

        # Summary stats
        crawl_html += '<div class="summary">'
        if summary:
            for key in ['TotalDatabases', 'TotalTables', 'TotalColumns', 'TotalRows', 'TotalSensitive']:
                val = summary.get(key, 0)
                crawl_html += f'<div class="summary-card"><div class="label">{key.replace("Total","")}</div><div class="value">{val}</div></div>'
        crawl_html += '</div>'

        # Sensitive data
        if sensitive:
            crawl_html += '<h3>🔑 Sensitive Data Findings</h3><table><tr><th>Risk</th><th>DB</th><th>Table</th><th>Column</th><th>Category</th><th>Sample</th><th>Confidence</th></tr>'
            for f in sensitive:
                risk = f.get('Risk', 'LOW')
                color = _severity_color(risk)
                sample = str(f.get('Sample', ''))[:80]
                crawl_html += f'<tr><td style="color:{color}">{risk}</td><td>{html_mod.escape(str(f.get("Database","")))}</td><td>{html_mod.escape(str(f.get("Table","")))}</td><td>{html_mod.escape(str(f.get("Column","")))}</td><td>{html_mod.escape(str(f.get("Category","")))}</td><td><code>{html_mod.escape(sample)}</code></td><td>{float(f.get("Confidence",0))*100:.0f}%</td></tr>'
            crawl_html += '</table>'

        # System info
        if system_info:
            crawl_html += '<h3>🖥️ System Information</h3><div class="system-info"><dl>'
            for k, v in system_info.items():
                crawl_html += f'<dt>{html_mod.escape(str(k))}</dt><dd>{html_mod.escape(str(v))}</dd>'
            crawl_html += '</dl></div>'

        # Database structure
        if databases:
            crawl_html += '<h3>🗄️ Database Structure</h3>'
            for db_name, db_info in databases.items():
                crawl_html += f'<details><summary><b>{html_mod.escape(str(db_name))}</b></summary>'
                tables = db_info.get('Tables', {})
                for tbl_name, tbl_info in tables.items():
                    cols = tbl_info.get('Columns', [])
                    crawl_html += f'<details style="margin-left:20px"><summary><b>{html_mod.escape(str(tbl_name))}</b> ({len(cols)} cols)</summary><table><tr><th>Column</th><th>Type</th><th>PK</th><th>Sensitive</th></tr>'
                    for col in cols:
                        sensitive_flag = '🔴' if col.get('IsSensitive') else ''
                        crawl_html += f'<tr><td>{html_mod.escape(str(col.get("Name","")))}</td><td>{html_mod.escape(str(col.get("Type","")))}</td><td>{"✅" if col.get("IsPK") else ""}</td><td>{sensitive_flag}</td></tr>'
                    crawl_html += '</table></details>'
                crawl_html += '</details>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html_mod.escape(title)}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
               background:#0d1117; color:#c9d1d9; padding:30px; }}
        h1 {{ color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:10px; }}
        h2 {{ color:#f0883e; margin:30px 0 15px; }}
        h3 {{ color:#3fb950; margin:20px 0 10px; }}
        .meta {{ color:#8b949e; margin:10px 0 20px; }}
        table {{ width:100%; border-collapse:collapse; margin:15px 0; }}
        th, td {{ padding:10px 12px; text-align:left; border-bottom:1px solid #30363d; }}
        th {{ background:#161b22; color:#58a6ff; font-weight:600; }}
        tr:hover {{ background:#1c2128; }}
        code {{ background:#161b22; padding:2px 6px; border-radius:3px; font-size:13px;
                word-break:break-all; }}
        .summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
                    gap:15px; margin:15px 0; }}
        .summary-card {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
                         padding:15px; text-align:center; }}
        .summary-card .label {{ color:#8b949e; font-size:11px; text-transform:uppercase; }}
        .summary-card .value {{ font-size:28px; font-weight:bold; color:#f0f6fc; }}
        .enum-section {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
                         padding:15px; margin:10px 0; }}
        .enum-section h3 {{ color:#3fb950; margin-bottom:10px; }}
        .enum-section ul {{ list-style:none; padding:0; max-height:300px; overflow-y:auto; }}
        .enum-section li {{ padding:4px 0; border-bottom:1px solid #21262d;
                            font-family:monospace; font-size:13px; }}
        .system-info {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
                        padding:15px; }}
        .system-info dt {{ color:#58a6ff; font-weight:bold; margin-top:8px; }}
        .system-info dd {{ margin-left:20px; color:#c9d1d9; }}
        details {{ margin:10px 0; background:#161b22; border:1px solid #30363d;
                   border-radius:6px; padding:10px; }}
        details summary {{ cursor:pointer; color:#58a6ff; font-weight:bold; }}
        @media (max-width:768px) {{ body {{ padding:15px; }}
            .summary {{ grid-template-columns:repeat(2,1fr); }} }}
        .footer {{ color:#8b949e; font-size:12px; text-align:center; margin-top:30px;
                   border-top:1px solid #30363d; padding-top:15px; }}
    </style>
</head>
<body>
    <h1>🔍 {html_mod.escape(title)}</h1>
    <div class="meta">📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 📊 {len(results)} results</div>

    <div class="summary">
        <div class="summary-card"><div class="label">Vulnerabilities</div><div class="value">{len(findings)}</div></div>
        <div class="summary-card"><div class="label">Parameters</div><div class="value">{len(set(r.get('parameter') for r in findings))}</div></div>
        <div class="summary-card"><div class="label">DBMS</div><div class="value">{", ".join(sorted(set(r.get('dbms','') for r in findings))) or "Unknown"}</div></div>
        <div class="summary-card"><div class="label">Max Confidence</div><div class="value">{max((r.get('confidence',0) for r in findings), default=0)*100:.0f}%</div></div>
    </div>

    <h2>🚨 Vulnerability Findings</h2>
    <table>
        <tr><th>#</th><th>Parameter</th><th>Type</th><th>DBMS</th><th>Severity</th><th>Payload</th></tr>
        {vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;color:#8b949e">✅ No vulnerabilities found</td></tr>'}
    </table>

    {f'<h2>📋 Database Enumeration</h2>{enum_html}' if enum_html else ''}

    {crawl_html}

    <div class="footer">
        🛡️ SQLi Penetration Engine v4.0 | Generated by HackIt Security Framework
    </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    _console.print(f"[green][+] HTML report saved: {output_path}[/]")
    return output_path


# ── CSV Report ───────────────────────────────────────────────

def generate_csv(results: List[Dict[str, Any]], output_path: str) -> str:
    """Generate CSV report with all findings"""
    fieldnames = ['parameter', 'type', 'payload', 'dbms', 'confidence', 'details']
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in results:
            if r.get('parameter') != "enumeration":
                writer.writerow({
                    'parameter': r.get('parameter', ''),
                    'type': r.get('type', ''),
                    'payload': str(r.get('payload', ''))[:200],
                    'dbms': r.get('dbms', ''),
                    'confidence': r.get('confidence', 0),
                    'details': str(r.get('details', ''))[:200],
                })
    _console.print(f"[green][+] CSV report saved: {output_path}[/]")
    return output_path


# ── JSON Report ──────────────────────────────────────────────

def generate_json(results: List[Dict[str, Any]], output_path: str,
                  extra_data: Dict = None) -> str:
    """Generate JSON report with optional extra data"""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    report = {
        "scan_date": datetime.now().isoformat(),
        "engine": "SQLi Penetration Engine v4.0",
        "summary": {
            "total_results": len(results),
            "vulnerabilities": len([r for r in results if r.get('parameter') != "enumeration"]),
            "enumerations": len([r for r in results if r.get('parameter') == "enumeration"]),
        },
        "results": results,
    }
    if extra_data:
        report["extra"] = extra_data

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str, ensure_ascii=False)
    _console.print(f"[green][+] JSON report saved: {output_path}[/]")
    return output_path


# ── TXT Report ───────────────────────────────────────────────

def generate_txt(results: List[Dict[str, Any]], output_path: str) -> str:
    """Generate plain text summary"""
    findings = [r for r in results if r.get('parameter') != "enumeration"]

    lines = [
        "=" * 60,
        "SQLi SCAN REPORT",
        "=" * 60,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Results: {len(results)}",
        f"Vulnerabilities: {len(findings)}",
        "-" * 60,
    ]

    for i, r in enumerate(findings, 1):
        conf = r.get('confidence', 0)
        sev = _severity(conf)
        lines.append(f"\n[{i}] {sev.upper()} ({conf*100:.0f}%)")
        lines.append(f"    Parameter : {r.get('parameter', 'N/A')}")
        lines.append(f"    Type      : {r.get('type', 'N/A')}")
        lines.append(f"    DBMS      : {r.get('dbms', 'Unknown')}")
        lines.append(f"    Payload   : {r.get('payload', '')[:100]}")
        lines.append(f"    Details   : {r.get('details', '')}")

    lines.extend(["\n" + "=" * 60, "End of Report", "=" * 60])

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    _console.print(f"[green][+] TXT report saved: {output_path}[/]")
    return output_path


# ── Auto Generate ────────────────────────────────────────────

def auto_generate(results: List[Dict[str, Any]],
                  base_name: str = "sqli_report",
                  crawl_results: Dict = None) -> Dict[str, str]:
    """Generate all report formats automatically"""
    paths = {}
    paths['html'] = generate_html(results, f"{base_name}.html", crawl_results=crawl_results)
    paths['csv'] = generate_csv(results, f"{base_name}.csv")
    paths['json'] = generate_json(results, f"{base_name}.json",
                                   extra_data=crawl_results)
    paths['txt'] = generate_txt(results, f"{base_name}.txt")
    return paths
