import json
import os
from datetime import datetime


def generate_html_report(data: dict, output_path: str = "") -> str:
    query = data.get("query", data.get("username", "unknown"))
    summary = data.get("summary", data.get("analysis", {}))
    hits = summary.get("hits", 0)
    possible = summary.get("possible", 0)
    total = summary.get("total", len(data.get("profiles", data.get("results", []))))

    profiles = data.get("profiles", data.get("results", []))
    results_html = ""
    for p in profiles:
        if isinstance(p, dict):
            platform = p.get("platform", p.get("name", ""))
            url = p.get("url", "")
            status = p.get("status", "")
            title = p.get("title", "")
            category = p.get("category", "")
            confidence = p.get("confidence", 0)

            icon = {"hit": "✅", "possible": "❓", "miss": "❌", "unknown": "⚠️"}.get(status, "➖")
            color = {"hit": "#00c853", "possible": "#ff9100", "miss": "#ff1744", "unknown": "#9e9e9e"}.get(status, "#666")

            results_html += f"""<tr style="border-bottom:1px solid #eee;">
                <td style="padding:8px">{icon}</td>
                <td style="padding:8px"><strong>{platform}</strong></td>
                <td style="padding:8px"><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{status.upper()}</span></td>
                <td style="padding:8px;color:#666">{category}</td>
                <td style="padding:8px"><a href="{url}" target="_blank" style="color:#1a73e8;text-decoration:none;max-width:400px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{url}</a></td>
                <td style="padding:8px;font-size:12px;color:#666">{title[:80] if title else '-'}</td>
                <td style="padding:8px;text-align:center">{confidence}%</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HackIT OSINT Report - {query}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Arial,sans-serif; background:#f5f5f5; color:#333; line-height:1.6; }}
.container {{ max-width:1200px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg,#1a1a2e,#16213e); color:#fff; padding:40px; border-radius:12px; margin-bottom:30px; }}
.header h1 {{ font-size:28px; margin-bottom:10px; }}
.header .meta {{ color:#aaa; font-size:14px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:20px; margin-bottom:30px; }}
.stat-card {{ background:#fff; padding:20px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.1); text-align:center; }}
.stat-card .number {{ font-size:32px; font-weight:700; }}
.stat-card .label {{ color:#666; font-size:14px; margin-top:5px; }}
.stat-card.hit .number {{ color:#00c853; }}
.stat-card.possible .number {{ color:#ff9100; }}
.stat-card.miss .number {{ color:#ff1744; }}
table {{ width:100%; background:#fff; border-radius:10px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.1); }}
th {{ background:#1a1a2e; color:#fff; padding:12px; text-align:left; font-size:14px; }}
td {{ font-size:13px; }}
.breach-section {{ background:#fff; border-radius:10px; padding:20px; box-shadow:0 2px 8px rgba(0,0,0,.1); margin-top:30px; }}
.breach-section h2 {{ margin-bottom:15px; color:#1a1a2e; }}
.breach-item {{ padding:10px; border-left:4px solid #ff1744; margin-bottom:10px; background:#fff5f5; border-radius:0 8px 8px 0; }}
.footer {{ text-align:center; padding:30px; color:#999; font-size:13px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>🔍 OSINT Report: {query}</h1>
    <div class="meta">
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
        Total Checks: {total} | Hits: {hits} | Possible: {possible}
    </div>
</div>

<div class="stats">
    <div class="stat-card hit"><div class="number">{hits}</div><div class="label">Accounts Found</div></div>
    <div class="stat-card possible"><div class="number">{possible}</div><div class="label">Possible</div></div>
    <div class="stat-card miss"><div class="number">{total - hits - possible}</div><div class="label">Not Found</div></div>
    <div class="stat-card"><div class="number">{total}</div><div class="label">Total Sites Checked</div></div>
</div>

<h2 style="margin:20px 0 10px;color:#1a1a2e;">Profile Results</h2>
<table>
<thead><tr>
    <th></th><th>Platform</th><th>Status</th><th>Category</th><th>URL</th><th>Title</th><th>Confidence</th>
</tr></thead>
<tbody>{results_html}</tbody>
</table>"""

    email = data.get("email", {})
    if email and email.get("domain"):
        html += f"""
<div class="breach-section">
    <h2>📧 Email Intelligence</h2>
    <p><strong>Email:</strong> {email.get('email', email.get('query', 'N/A'))}</p>
    <p><strong>Domain:</strong> {email.get('domain', 'N/A')}</p>
    <p><strong>MX Records:</strong> {email.get('mx', 'N/A')}</p>
    <p><strong>Gravatar:</strong> {'✅ Found' if email.get('gravatar') else '❌ Not found'}</p>"""

        breaches = email.get("breaches", [])
        if breaches:
            html += '<h3 style="margin-top:15px;color:#ff1744;">⚠️ Data Breaches Found</h3>'
            for b in breaches:
                if isinstance(b, dict):
                    html += f'<div class="breach-item"><strong>{b.get("source", "Unknown")}</strong><br>{b.get("data_class", "")}</div>'

        html += "</div>"

    phone = data.get("phone", {})
    if phone:
        html += f"""
<div class="breach-section">
    <h2>📱 Phone Intelligence</h2>
    <p><strong>Number:</strong> {phone.get('number', 'N/A')}</p>
    <p><strong>Country:</strong> {phone.get('country', 'N/A')}</p>
    <p><strong>Carrier:</strong> {phone.get('carrier', 'N/A')}</p>
    <p><strong>Line Type:</strong> {phone.get('line_type', 'N/A')}</p>
    <p><strong>Social Found:</strong> {', '.join(phone.get('social_found', [])) or 'None'}</p>
</div>"""

    domain = data.get("domain", {})
    if domain:
        html += f"""
<div class="breach-section">
    <h2>🌐 Domain Intelligence</h2>
    <p><strong>Domain:</strong> {domain.get('domain', 'N/A')}</p>
    <p><strong>Registrar:</strong> {domain.get('registrar', 'N/A')}</p>
    <p><strong>Created:</strong> {domain.get('creation_date', 'N/A')}</p>
    <p><strong>Name Servers:</strong> {', '.join(domain.get('name_servers', [])) or 'N/A'}</p>
    <p><strong>MX Records:</strong> {', '.join(domain.get('mx_records', [])) or 'N/A'}</p>
</div>"""

    html += f"""<div class="footer">Generated by <strong>HackIT OSINT Engine</strong> | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div>
</body>
</html>"""

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html)
        print(f"[+] HTML report saved to {output_path}")

    return html
