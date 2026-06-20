#!/usr/bin/env python3
import os, sys, json, click
from .go_bridge import AtomixGoEngine
from hackit.ui import (
    display_tool_banner, _colored,
    GREEN, RED, BLUE, YELLOW, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM, PURPLE,
)

BANNER = r"""
[bold cyan]
   ▒▓█ \ PERMISSION OR PRISON. CHOOSE WISELY. █▓▒
   █████╗ ████████╗ ██████╗ ███╗   ███╗██╗██╗  ██╗
  ██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║██║╚██╗██╔╝
  ███████║   ██║   ██║   ██║██╔████╔██║██║ ╚███╔╝ 
  ██╔══██║   ██║   ██║   ██║██║╚██╔╝██║██║ ██╔██╗ 
  ██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║██║██╔╝ ██╗
  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝
  ┌─────────────────────────────────────────────────┐
  │ HackIT V2.1 - By: AniipID                       │
  │ Vulnerability Toolkit - Nailed It               │
  └─────────────────────────────────────────────────┘
[/bold cyan]"""

def display_banner():
    from rich.console import Console
    Console().print(BANNER)


# ── Custom Grouped Help Formatter ─────────────────────────────────────
SECTION_ORDER = [
    "BASIC SCAN", "RESULT & OUTPUT", "TEMPLATE FILTER",
    "PERFORMANCE", "ADVANCED", "HEADLESS BROWSER",
    "PROTOCOL SCAN", "TARGET DISCOVERY", "NOTIFICATIONS",
    "SIGN & VERIFY", "UTILITY",
]

SECTIONS = {
    "BASIC SCAN": [
        "url", "target_file", "timeout", "threads", "severity", "tags",
        "id", "method", "proxy", "resolver", "no_banner", "silent", "verbose",
    ],
    "RESULT & OUTPUT": [
        "output", "json_output", "jsonl", "csv", "html", "markdown", "sarif",
        "stats", "metrics", "analytics", "no_color", "debug",
    ],
    "TEMPLATE FILTER": [
        "author", "type", "exclude_tags", "exclude_severity", "exclude_pat",
        "scope_file", "exclude_file",
    ],
    "PERFORMANCE": [
        "concurrency", "retries", "rate_limit", "bulk_size",
        "follow_redirects", "max_redirects", "priority", "no_cache",
        "adaptive_rate", "keep_alive", "http2", "http2_downgrade",
    ],
    "ADVANCED": [
        "custom_dir", "load", "from_git", "smart", "chain", "multi",
        "fuzz", "fuzz_thread", "fuzz_recursive", "path", "payloads",
        "detect_tech", "waf_skip", "waf_bypass", "api_discovery",
        "auth", "auth_token", "api_key", "custom_agent", "rand_agent",
        "cookie", "cookie_jar", "header", "dns_resolver", "scan_all_ips",
        "exclude_ports", "interactsh", "oob_server", "oob_token", "oob_type",
        "monitor", "diff", "replay",
    ],
    "HEADLESS BROWSER": [
        "headless", "no_sandbox", "show_browser", "system_chrome",
        "use_chrome", "headless_opt", "headless_page_timeout",
        "headless_action_timeout",
    ],
    "PROTOCOL SCAN": [
        "protocol", "tls_impersonate", "scan_all_ips",
    ],
    "TARGET DISCOVERY": [
        "uncover", "uncover_engine", "uncover_query",
        "uncover_limit", "uncover_field",
    ],
    "NOTIFICATIONS": [
        "push", "slack", "telegram", "telegram_chat",
        "dashboard", "dashboard_port", "dashboard_path", "dashboard_auth",
    ],
    "SIGN & VERIFY": [
        "sign", "verify", "sign_key", "sign_pass", "verify_key",
    ],
    "UTILITY": [
        "health", "update", "probe", "validate", "validate_deep",
        "list_flag", "list_sources", "custom_guide",
        "examples", "completion", "config", "project", "project_path",
        "allow_local_access", "version", "license",
    ],
}

# Descriptions for each flag (use click's built-in by default)
FLAG_DESCS = {}

# Build options decorator
def build_option(*param_decls, **attrs):
    return click.option(*param_decls, **attrs)


# ── Command ───────────────────────────────────────────────────────────
class _GroupedHelpCommand(click.Command):
    def format_help(self, ctx, formatter=None):
        from click.formatting import HelpFormatter
        fmtr = formatter or HelpFormatter(width=getattr(ctx, "max_content_width", 100))
        self.format_usage(ctx, fmtr)
        fmtr.write_paragraph()
        fmtr.write_text("Atomix - Nuclei-Style Vulnerability Scanner\n"
                        "Multi-engine toolkit with 310+ YAML templates, "
                        "headless browser, protocol scanning, target discovery, "
                        "and template signing.")

        opts = {o.name: o for o in self.params if isinstance(o, click.Option)}
        seen = set()
        for section_name, opt_names in SECTIONS.items():
            lines = []
            for n in opt_names:
                o = opts.get(n)
                if o is None:
                    continue
                seen.add(n)
                decls = []
                for d in o.opts:
                    m = ""
                    if hasattr(o, "metavar") and o.metavar:
                        m = " " + o.metavar
                    elif not o.is_flag:
                        m = " " + (o.type.name.upper() if o.type else "TEXT")
                    decls.append(d + m)
                lines.append((", ".join(decls), o.help or ""))
            if lines:
                fmtr.write_paragraph()
                with fmtr.section(section_name):
                    fmtr.write_dl(lines, col_max=50)

        extras = [(o.name, o) for o in self.params if isinstance(o, click.Option) and o.name not in seen]
        if extras:
            fmtr.write_paragraph()
            with fmtr.section("OTHER"):
                fmtr.write_dl([(", ".join(o.opts), o.help or "") for _, o in extras])

        fmtr.write_paragraph()
        fmtr.write_text("Use 'atomix <flag>' for each option or combine multiple flags.")
        click.echo(fmtr.getvalue())

@click.command(name="atomix", context_settings=dict(help_option_names=["-h", "--help"]),
               cls=_GroupedHelpCommand)

# ── BASIC SCAN ──
@click.option("-u", "--url", default="", help="Target URL to scan")
@click.option("--timeout", default=60, type=int, help="Request timeout in seconds")
@click.option("-c", "--threads", default=25, type=int, help="Concurrency (parallel templates)")
@click.option("--severity", "--s", default="", help="Filter: info,low,medium,high,critical")
@click.option("--tags", default="", help="Filter by tags (comma-separated)")
@click.option("--id", default="", help="Run specific template by ID")
@click.option("-m", "--method", default="", help="HTTP method: GET,POST,PUT,DELETE,PATCH")
@click.option("-p", "--proxy", default="", help="HTTP proxy URL (http://host:port)")
@click.option("-r", "--resolver", default="", help="Custom DNS resolver (host:port)")
@click.option("--no-banner", is_flag=True, help="Skip banner display")
@click.option("--silent", is_flag=True, help="Show findings only")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")

# ── RESULT & OUTPUT ──
@click.option("-o", "--output", default="", help="Output file path")
@click.option("--json", "json_output", is_flag=True, help="Raw JSON output")
@click.option("--jsonl", is_flag=True, help="JSON Lines format")
@click.option("--csv", is_flag=True, help="CSV format")
@click.option("--html", is_flag=True, help="HTML report")
@click.option("--md", "--markdown", "markdown", default="", help="Markdown report (file path)")
@click.option("--sarif", is_flag=True, help="SARIF format")
@click.option("--stats", is_flag=True, help="Show statistics after scan")
@click.option("--metrics", is_flag=True, help="Show metrics after scan")
@click.option("--analytics", is_flag=True, help="Template analytics (match rates)")
@click.option("--no-color", "--nc", is_flag=True, help="Disable colored output")
@click.option("--debug", "-d", is_flag=True, help="Debug output")

# ── TEMPLATE FILTER ──
@click.option("--author", default="", help="Filter by template author")
@click.option("--type", default="", help="Filter by template type")
@click.option("--exclude-tags", "--etag", default="", help="Exclude templates by tags")
@click.option("--exclude-severity", "--es", default="", help="Exclude templates by severity")
@click.option("--exclude-pat", "--ep", default="", help="Exclude URLs matching regex")
@click.option("--scope-file", default="", help="File with allowed scope patterns")
@click.option("--exclude-file", default="", help="File with URLs to exclude")

# ── PERFORMANCE ──
@click.option("--concurrency", default=25, type=int, help="Threads per template")
@click.option("--retries", default=0, type=int, help="Max retries per request")
@click.option("--rate-limit", default=0, type=int, help="Rate limit (req/sec)")
@click.option("--bulk-size", default=0, type=int, help="Batch processing size")
@click.option("--follow-redirects", is_flag=True, help="Follow HTTP redirects")
@click.option("--max-redirects", default=10, type=int, help="Max redirects")
@click.option("--priority", is_flag=True, help="Priority: critical/high templates first")
@click.option("--no-cache", is_flag=True, help="Disable template cache")
@click.option("--adaptive-rate", is_flag=True, help="Adaptive rate limiting")
@click.option("--keep-alive", is_flag=True, help="HTTP keep-alive")
@click.option("--http2", is_flag=True, help="Enable HTTP/2")
@click.option("--http2-downgrade", is_flag=True, help="Disable HTTP/2")

# ── ADVANCED ──
@click.option("--custom-dir", default="", help="Custom template directory")
@click.option("--load", default="", help="Load template file, dir, or URL (comma-sep)")
@click.option("--from-git", default="", help="Load templates from git repo URL")
@click.option("--smart", is_flag=True, help="Smart template selection")
@click.option("-w", "--chain", default="", help="Workflow file")
@click.option("--multi", is_flag=True, help="Multi-target coordinated scan")
@click.option("--fuzz", default="", help="Fuzz mode: param,path,header")
@click.option("--fuzz-thread", default=10, type=int, help="Fuzzer thread count")
@click.option("--fuzz-recursive", is_flag=True, help="Recursive fuzzing")
@click.option("--path", default="", help="Custom request path")
@click.option("--payloads", default="", help="Custom payloads file")
@click.option("--detect-tech", "--tech-detect", is_flag=True, help="Detect technologies")
@click.option("--waf-skip", is_flag=True, help="Skip WAF detection")
@click.option("--waf-bypass", is_flag=True, help="WAF bypass attempts")
@click.option("--api-discovery", is_flag=True, help="Discover API endpoints")
@click.option("--auth", default="", help="Basic auth: user:pass")
@click.option("--auth-token", default="", help="Bearer token")
@click.option("--api-key", default="", help="API key")
@click.option("--custom-agent", default="", help="Custom User-Agent")
@click.option("--rand-agent", is_flag=True, help="Random User-Agent per request")
@click.option("--cookie", default="", help="Set Cookie header")
@click.option("--cookie-jar", default="", help="Cookie jar file")
@click.option("-H", "--header", "headers", default="", help='Custom header "Name: Value"')
@click.option("--dns-resolver", default="", help="Custom DNS resolver for proto scan")
@click.option("--scan-all-ips", is_flag=True, help="Scan all resolved IPs")
@click.option("--exclude-ports", default="", help="Ports to exclude")
@click.option("--interactsh", is_flag=True, help="Interactsh OOB support")
@click.option("--oob-server", default="", help="Custom OOB server URL")
@click.option("--oob-token", default="", help="OOB auth token")
@click.option("--oob-type", default="", help="OOB type: dns,http,ldap,rmi")
@click.option("--monitor", default="", help="Monitor mode: target:interval_sec")
@click.option("--diff", default="", help="Diff result files: old:new")
@click.option("--replay", default="", help="Replay findings from JSON file")

# ── HEADLESS BROWSER ──
@click.option("--headless", is_flag=True, help="Headless browser scan (JS/SPA)")
@click.option("--no-sandbox", is_flag=True, help="Chrome no-sandbox mode")
@click.option("--show-browser", is_flag=True, help="Show browser window (debug)")
@click.option("--system-chrome", is_flag=True, help="Use system Chrome")
@click.option("--use-chrome", default="", help="Path to Chrome/Chromium binary")
@click.option("--headless-opt", default="", help="Chrome extra options")
@click.option("--headless-page-timeout", default=10000, type=int, help="Page load timeout (ms)")
@click.option("--headless-action-timeout", default=5000, type=int, help="Action timeout (ms)")

# ── PROTOCOL SCAN ──
@click.option("--proto", "--protocol", "protocol", default="", help="Protocol scan: dns,tcp,tls,all")
@click.option("--tls-impersonate", is_flag=True, help="TLS fingerprint impersonation")

# ── TARGET DISCOVERY ──
@click.option("--uncover", is_flag=True, help="Enable target discovery")
@click.option("--uncover-engine", default="shodan", help="Engine: shodan,censys,fofa")
@click.option("--uncover-query", default="", help="Uncover search query")
@click.option("--uncover-limit", default=100, type=int, help="Max uncover results")
@click.option("--uncover-field", default="ip:port", help="Output field: ip,host,ip:port")

# ── NOTIFICATIONS ──
@click.option("--push", default="", help="Push to webhook URL")
@click.option("--slack", default="", help="Slack webhook URL")
@click.option("--telegram", default="", help="Telegram bot token")
@click.option("--telegram-chat", default="", help="Telegram chat ID")
@click.option("--dashboard", is_flag=True, help="Enable web dashboard")
@click.option("--dashboard-port", default=8484, type=int, help="Dashboard port")
@click.option("--dashboard-path", default="/dashboard", help="Dashboard URL path")
@click.option("--dashboard-auth", default="", help="Dashboard auth: user:pass")

# ── SIGN & VERIFY ──
@click.option("--sign", default="", help="Sign a template file")
@click.option("--verify", default="", help="Verify a template signature")
@click.option("--sign-key", default="", help="Private key file for signing")
@click.option("--sign-pass", default="", help="Signing key passphrase")
@click.option("--verify-key", default="", help="Public key file for verification")

# ── UTILITY ──
@click.option("--health", is_flag=True, help="Run health check")
@click.option("--update", is_flag=True, help="Update templates from Nuclei hub")
@click.option("--probe", is_flag=True, help="Probe target: tech + WAF")
@click.option("--validate", is_flag=True, help="Validate all templates")
@click.option("--validate-deep", is_flag=True, help="Deep schema validation")
@click.option("-l", "--list", "list_flag", is_flag=True, help="List templates")
@click.option("--list-sources", is_flag=True, help="List custom template sources")
@click.option("--custom-guide", is_flag=True, help="Custom template guide")
@click.option("--examples", is_flag=True, help="Usage examples")
@click.option("--completion", default="", help="Shell completion: bash,zsh,fish")
@click.option("--config", default="", help="Atomix config file")
@click.option("--project", default="", help="Project name for organized scanning")
@click.option("--project-path", default="", help="Project directory path")
@click.option("--allow-local-access", is_flag=True, help="Allow local file access in templates")
@click.option("--version", is_flag=True, help="Show version")
@click.option("--license", is_flag=True, help="Show license")
@click.option("--target-file", default="", help="File with target URLs")
@click.option("--resume", default="", help="Resume from resume file")
@click.option("--trace", default="", help="Trace log file path")
def atomix_command(**kwargs):
    """Atomix - Nuclei-Style Vulnerability Scanner"""
    engine = AtomixGoEngine()

    passthrough = {
        "list_flag": "--list", "list_sources": "--list-sources",
        "custom_guide": "--custom-guide", "validate_deep": "--validate-deep",
        "health": "--health", "update": "--update", "probe": "--probe",
        "version": "--version", "examples": "--examples", "license": "--license",
    }
    for key, flag in passthrough.items():
        if kwargs.get(key):
            engine.run_direct(flag)
            return
    if kwargs.get("validate"):
        engine.run_direct("--validate")
        return
    if kwargs.get("completion"):
        engine.run_direct(f"--completion={kwargs['completion']}")
        return

    has_any = any(kwargs.get(k) for k in (
        "url", "list_flag", "list_sources", "custom_guide",
        "validate", "validate_deep", "health", "update",
        "probe", "version", "examples", "license", "completion",
        "sign", "verify", "headless", "protocol", "uncover",
    ))
    if not has_any:
        click.echo(atomix_command.get_help(click.Context(atomix_command)))
        return

    if not kwargs.get("no_banner"):
        display_banner()

    if kwargs.get("sign"):
        engine.run_direct(f"--sign={kwargs['sign']}")
        return
    if kwargs.get("verify"):
        engine.run_direct(f"--verify={kwargs['verify']}")
        return

    if not kwargs.get("url"):
        click.echo(_colored("  [!] --url/-u required", RED))
        return
    if not engine.available:
        click.echo(_colored("  [!] Go binary not found", RED))
        return

    click.echo(_colored(f"  [*] Scanning {kwargs['url']} ...", B_CYAN))
    parts = []
    if kwargs.get("severity"): parts.append(f"sev={kwargs['severity']}")
    if kwargs.get("tags"): parts.append(f"tags={kwargs['tags']}")
    if kwargs.get("threads"): parts.append(f"threads={kwargs['threads']}")
    if kwargs.get("smart"): parts.append("smart")
    if kwargs.get("headless"): parts.append("headless")
    if kwargs.get("protocol"): parts.append(f"proto={kwargs['protocol']}")
    if kwargs.get("uncover"): parts.append("uncover")
    if parts:
        click.echo(_colored(f"  [*] {' | '.join(parts)}", DIM))

    scan_kwargs = {k: v for k, v in kwargs.items() if k != "url"}
    results = engine.run(kwargs["url"], **scan_kwargs)

    if not results:
        click.echo(_colored("\n  [+] No vulnerabilities found.", B_GREEN))
        return
    if isinstance(results, list) and results and "error" in results[0]:
        click.echo(_colored(f"  [!] {results[0]['error']}", RED))
        return
    if kwargs.get("json_output"):
        click.echo(json.dumps(results, indent=2))
        return

    click.echo(_colored(f"\n  === RESULTS ({len(results)} findings) ===\n", B_CYAN))
    for r in results:
        if not isinstance(r, dict):
            continue
        sev = r.get("severity", "info").upper()
        color = {"CRITICAL": B_RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": BLUE, "INFO": GREEN}.get(sev, DIM)
        click.echo(f"  [{_colored(sev, color)}] {r.get('url', '?')}")
        click.echo(f"     Template: {r.get('template_name', '?')} ({r.get('template_id', '?')})")
        click.echo(f"     Matched:  {r.get('matcher_name', '?')}")
        if r.get("tags"):
            click.echo(f"     Tags:     {r['tags']}")
        if r.get("extracted"):
            click.echo(f"     Extract:  {_colored(r['extracted'], B_YELLOW)}")
        click.echo()



