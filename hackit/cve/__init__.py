import click
import json
from urllib.parse import urlparse

from hackit.cve.go_bridge import GoEngine, run_cve_scan
from hackit.ui import _colored, BLUE, CYAN, YELLOW, RESET, MAGENTA, GREEN, RED


def _show_cve_banner():
    banner = f"""{CYAN}
       _____     _______   _____
      / ___/| | / / ____/  / ___/_________ _____  ____  ___  ____
     / /   | | / / __/     \\__ \\/ ___/ __ `/ __ \\/ __ \\/ _ \\/ ___/
    / /___ | |/ / /___    ___/ / /__/ /_/ / / / / / / /  __/ /
    \\____/ |___/_____/   /____/\\___/\\__,_/_/ /_/_/ /_/\\___/_/
    {RESET}{BLUE}
    [+] Professional Defensive Vulnerability & Exposure Scanner [+]
    {RESET}
    {MAGENTA} "Knowing your vulnerabilities is the first step to true defense.
     Intelligence-driven security saves networks."{RESET}
    """
    click.echo(banner)


def _sev_color(severity: str) -> str:
    sev = (severity or "").upper()
    if sev in ("CRITICAL", "HIGH"):
        return RED
    if sev == "MEDIUM":
        return YELLOW
    if sev == "LOW":
        return CYAN
    if sev == "INFO":
        return GREEN
    return RESET


def _print_cve_briefing(report, refs: bool = False) -> None:
    """Print the structured JSON report in a human briefing layout."""
    if not isinstance(report, dict):
        click.secho("[!] No report produced — engine offline or NVD rate-limit hit.", fg='red', bold=True)
        return
    target = report.get("target", "unknown")
    total = report.get("total_cves", 0)
    sev = report.get("severity_counts", {}) or {}
    tech_list = report.get("techs", []) or []
    subs = report.get("subdomains", []) or []
    click.secho(f"\n[+] CVE Briefing: {target}", fg='cyan', bold=True)
    click.echo(f"    Mode:       {report.get('mode', 'main')}")
    click.echo(f"    CVEs total: {total}")
    click.echo(f"    CRITICAL {sev.get('CRITICAL', 0)}  HIGH {sev.get('HIGH', 0)}  "
               f"MEDIUM {sev.get('MEDIUM', 0)}  LOW {sev.get('LOW', 0)}  INFO {sev.get('INFO', 0)}")
    risk = report.get("risk_score")
    if risk is not None:
        click.echo(f"    Risk score: {risk}")
    click.echo(f"    Technologies: {', '.join(tech_list[:20])}")
    if subs:
        click.echo(f"    Subdomains scanned: {len(subs)} reachable")
    elif report.get("mode") == "main":
        click.echo("    Subdomains scanned: 0 reachable")

    findings = report.get("findings", []) or []
    if not findings:
        click.secho("    No CVEs matched the fingerprinted technologies.", fg='green')
        return
    click.echo("")
    shown = 0
    for item in findings:
        if shown >= 20:
            click.echo(f"    ... and {len(findings) - shown} more in JSON report (use --output)")
            break
        sev_label = _sev_color(item.get("severity", "INFO"))
        click.echo(f"  {sev_label}{item.get('cve_id')}{RESET}  CVSS {item.get('score', 0)}  ({item.get('severity')})")
        if item.get("software"):
            version = item.get("version") or ""
            click.echo(f"    Affects: {item.get('software')} {version}".rstrip())
        if item.get("vector"):
            click.echo(f"    Vector: {item.get('vector')}")
        if item.get("attack_type"):
            click.echo(f"    Attack: {item.get('attack_type')}")
        if item.get("cwe"):
            click.echo(f"    CWE: {item.get('cwe')}")
        if item.get("published"):
            pub = str(item.get("published"))[:10]
            click.echo(f"    Published: {pub}")
        if item.get("epss") is not None and item.get("epss") != -1:
            try:
                click.echo(f"    EPSS: {float(item.get('epss')):.4f}")
            except (TypeError, ValueError):
                pass
        desc = (item.get("description") or "").strip()
        if desc:
            click.echo(f"    Summary: {desc[:240]}")
        if item.get("confidence") and item.get("match_type"):
            click.echo(f"    Source:   {item.get('match_type')} · confidence {item.get('confidence')}")
        if refs:
            for url in item.get("references", [])[:5]:
                click.echo(f"    · {url}")
        click.echo("")
        shown += 1

    if subs:
        click.secho("\n[+] Subdomain CVEs", fg='cyan', bold=True)
        for sub in subs:
            host = sub.get("subdomain")
            sub_cves = sub.get("cves", [])
            tech = sub.get("technologies", []) or []
            if not sub.get("reachable"):
                continue
            click.echo(f"  {host} — tech: {', '.join(tech) if tech else 'n/a'} — {len(sub_cves)} CVEs")
            for c in sub_cves[:5]:
                sev_color = _sev_color(c.get("severity", "INFO"))
                click.echo(f"    {sev_color}{c.get('cve_id')}{RESET} CVSS {c.get('score', 0)} ({c.get('severity')})  {c.get('software')}")
            if len(sub_cves) > 5:
                click.echo(f"    ... and {len(sub_cves) - 5} more")


@click.command(name='cve')
@click.argument('target', required=False, default=None)
@click.option('--mode', 'mode_option', type=click.Choice(['parameter', 'main']),
              help='Scan mode. Default: main.')
@click.option('--output', help='Save structured JSON report to this file.')
@click.option('--deep', is_flag=True, help='Enhanced fingerprinting + subdomain pass (slower, broader).')
@click.option('--subdomains', is_flag=True, help='Also enumerate the target domain and common subdomains.')
@click.option('--subdomains-file', help='File with one subdomain label per line.')
@click.option('--api-key', help='NVD API key for higher rate limits')
@click.option('--max-results', type=int, default=20, help='Maximum CVEs per technology scan')
@click.option('--json-out', help='Same as --output, but still prints the briefing.')
@click.option('--refs', is_flag=True, help='Include reference URLs and advisory links for each CVE.')
@click.option('--no-interactive', is_flag=True, help='Skip banner and input prompts (scripted use).')
def check_cve(target, mode_option, output, deep, subdomains, subdomains_file, api_key,
              max_results, json_out, refs, no_interactive):
    """Professional intelligence-backed CVE scanner.

    Detects technologies for the target (and optionally every advertised subdomain),
    queries NVD + CISA KEV + EPSS + OSV, and emits a structured JSON report
    with full references, CVSS vector strings, CWEs, OWASP mappings and
    exploitability signals, with source metadata on every finding.
    """
    if target:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        if not no_interactive:
            _show_cve_banner()
        mode_str = mode_option or "main"
        click.secho(f"[+] Go+NVD CVE scan for {target} (mode={mode_str})...", fg='cyan', bold=True)
        report_output = json_out or output
        report = run_cve_scan(target=target, mode=mode_str, api_key=api_key,
                              max_results=max_results, output=report_output,
                              subdomains=bool(subdomains or deep or subdomains_file),
                              deep=bool(deep), subdomains_file=subdomains_file)
        _print_cve_briefing(report, refs=refs)
        return

    if not no_interactive:
        _show_cve_banner()

    click.secho("[ Pilih Mode Pemindaian ]", fg='yellow', bold=True)
    click.echo("  [1] Parameter Link (WAF & Logic Scanning)")
    click.echo("  [2] Main URL (Deep Port & Tech Scanning)")
    click.echo("  [3] Deep Scan (Fingerprinting, common subdomains, full NVD pass)")
    mode_choice = input(f"\n{YELLOW}Pilih [1/2/3]: {RESET}").strip()
    if mode_choice == "1":
        mode_str, subdomains_flag, deep_flag = "parameter", False, False
    elif mode_choice == "3":
        mode_str, subdomains_flag, deep_flag = "main", True, True
    else:
        mode_str, subdomains_flag, deep_flag = "main", False, False

    target = input(f"{YELLOW}Input URL/IP Target : {RESET}").strip()
    if not target:
        click.secho("[!] Target tidak boleh kosong.", fg='red', bold=True)
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    click.secho(f"\n[*] Deep CVE scan starting for {target} (mode={mode_str})...", fg='cyan', bold=True)
    report_output = json_out or output
    report = run_cve_scan(target=target, mode=mode_str, api_key=api_key,
                          max_results=max_results, output=report_output,
                          subdomains=subdomains_flag, deep=deep_flag)
    _print_cve_briefing(report, refs=refs)
