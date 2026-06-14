"""
SQLi Report Generator — HTML, CSV, JSON output with detailed findings.
"""
import json
import csv
import os
import html
from datetime import datetime
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel

_console = Console()


def _severity(confidence: float) -> str:
    if confidence >= 0.9:   return "CRITICAL"
    if confidence >= 0.7:   return "HIGH"
    if confidence >= 0.4:   return "MEDIUM"
    return "LOW"


def _severity_color(severity: str) -> str:
    return {"CRITICAL": "#ff0000", "HIGH": "#ff6600",
            "MEDIUM": "#ffcc00", "LOW": "#999999"}.get(severity, "#ffffff")


def generate_html(results: List[Dict[str, Any]], output_path: str, title: str = "SQLi Scan Report") -> str:
    findings = [r for r in results if r.get('parameter') != "enumeration"]
    enums = [r for r in results if r.get('parameter') == "enumeration"]

    vuln_rows = ""
    for i, r in enumerate(findings, 1):
        conf = r.get('confidence', 0)
        sev = _severity(conf)
        color = _severity_color(sev)
        vuln_rows += f"""
        <tr>
            <td>{i}</td>
            <td>{html.escape(r.get('parameter', 'N/A'))}</td>
            <td>{html.escape(r.get('type', 'N/A'))}</td>
            <td>{html.escape(r.get('dbms', 'Unknown'))}</td>
            <td style="color:{color};font-weight:bold">{sev} ({conf*100:.0f}%)</td>
            <td><code>{html.escape(r.get('payload', '')[:100])}</code></td>
        </tr>"""

    enum_html = ""
    for e in enums:
        etype = e.get('type', '')
        detail = e.get('details', '')
        items = [s.strip() for s in e.get('payload', '').split(',') if s.strip()]
        enum_html += f"""
        <div class="enum-section">
            <h3>{html.escape(etype)} - {html.escape(detail)}</h3>
            <ul>{"".join(f'<li>{html.escape(item)}</li>' for item in items[:50])}</ul>
            {f"<p><em>... and {len(items)-50} more</em></p>" if len(items) > 50 else ""}
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{html.escape(title)}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
               background:#0d1117; color:#c9d1d9; padding:30px; }}
        h1 {{ color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:10px; }}
        h2 {{ color:#f0883e; margin:20px 0 10px; }}
        .meta {{ color:#8b949e; margin:10px 0 20px; }}
        table {{ width:100%; border-collapse:collapse; margin:15px 0; }}
        th, td {{ padding:10px 12px; text-align:left; border-bottom:1px solid #30363d; }}
        th {{ background:#161b22; color:#58a6ff; font-weight:600; }}
        tr:hover {{ background:#1c2128; }}
        code {{ background:#161b22; padding:2px 6px; border-radius:3px; font-size:13px; }}
        .severity {{ font-weight:bold; }}
        .summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:15px; margin:15px 0; }}
        .summary-card {{ background:#161b22; border:1px solid #30363d; border-radius:6px; padding:15px; }}
        .summary-card .label {{ color:#8b949e; font-size:12px; text-transform:uppercase; }}
        .summary-card .value {{ font-size:24px; font-weight:bold; color:#f0f6fc; }}
        .enum-section {{ background:#161b22; border:1px solid #30363d; border-radius:6px; padding:15px; margin:10px 0; }}
        .enum-section h3 {{ color:#3fb950; margin-bottom:10px; }}
        .enum-section ul {{ list-style:none; padding:0; }}
        .enum-section li {{ padding:4px 0; border-bottom:1px solid #21262d; font-family:monospace; }}
        .footer {{ color:#8b949e; font-size:12px; text-align:center; margin-top:30px; border-top:1px solid #30363d; padding-top:15px; }}
    </style>
</head>
<body>
    <h1>{html.escape(title)}</h1>
    <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {len(results)} results</div>

    <div class="summary">
        <div class="summary-card"><div class="label">Vulnerabilities</div><div class="value">{len(findings)}</div></div>
        <div class="summary-card"><div class="label">Parameters Affected</div><div class="value">{len(set(r.get('parameter') for r in findings))}</div></div>
        <div class="summary-card"><div class="label">DBMS</div><div class="value">{", ".join(sorted(set(r.get('dbms','') for r in findings))) or "Unknown"}</div></div>
        <div class="summary-card"><div class="label">Max Confidence</div><div class="value">{max((r.get('confidence',0) for r in findings), default=0)*100:.0f}%</div></div>
    </div>

    <h2>Vulnerability Findings</h2>
    <table>
        <tr><th>#</th><th>Parameter</th><th>Type</th><th>DBMS</th><th>Severity</th><th>Payload</th></tr>
        {vuln_rows if vuln_rows else '<tr><td colspan="6" style="text-align:center;color:#8b949e">No vulnerabilities found</td></tr>'}
    </table>

    {f'<h2>Database Enumeration</h2>{enum_html}' if enum_html else ''}

    <div class="footer">
        SQLi Penetration Engine v4.0 | Generated by HackIt Security Framework
    </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html_content)
    _console.print(f"[green][+] HTML report saved: {output_path}[/]")
    return output_path


def generate_csv(results: List[Dict[str, Any]], output_path: str) -> str:
    fieldnames = ['parameter', 'type', 'payload', 'dbms', 'confidence', 'details']
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or '.', exist_ok=True)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for r in results:
            if r.get('parameter') != "enumeration":
                writer.writerow(r)
    _console.print(f"[green][+] CSV report saved: {output_path}[/]")
    return output_path


def generate_json(results: List[Dict[str, Any]], output_path: str) -> str:
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
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    _console.print(f"[green][+] JSON report saved: {output_path}[/]")
    return output_path


def auto_generate(results: List[Dict[str, Any]], base_name: str = "sqli_report") -> Dict[str, str]:
    paths = {}
    paths['html'] = generate_html(results, f"{base_name}.html")
    paths['csv'] = generate_csv(results, f"{base_name}.csv")
    paths['json'] = generate_json(results, f"{base_name}.json")
    return paths
