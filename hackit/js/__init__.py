"""
JS Analyzer Module — Katana‑style JS crawler & sensitive data hunter
Usage:  hackit web js <url>
        hackit web js -u <url> -o results.json
"""
import click
import json
from hackit.ui import display_tool_banner, _colored, GREEN, RED, BLUE, B_CYAN, YELLOW, CYAN, MAGENTA, BOLD, DIM, TablePrinter
from .go_bridge import GoEngine


@click.command()
@click.option('-o', '--output', default=None, help='Save results to JSON')
@click.option('--code', is_flag=True, default=False, help='Show full JS source code in output')
@click.argument('target_url', default=None, required=False)
@click.pass_context
def analyze_js(ctx, target_url, output, code):
    display_tool_banner("JS HUNTER", force=True)

    if target_url:
        final_url = target_url
    else:
        click.echo()
        click.echo(_colored("  → Enter target URL:", CYAN))
        click.echo(_colored("  → Example: https://example.com", DIM))
        try:
            final_url = input(_colored("  > ", CYAN)).strip()
        except (EOFError, KeyboardInterrupt):
            final_url = ""
        if not final_url:
            click.echo(_colored("  [!] No target specified.", RED))
            ctx.exit(1)

    if not final_url.startswith('http'):
        final_url = f"https://{final_url}"

    wrn = _colored("[WRN]", YELLOW)
    click.echo(f"{wrn} Use with caution. You are responsible for your actions.")
    click.echo(f"{wrn} Developers assume no liability and are not responsible for any misuse or damage.\n")

    engine = GoEngine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    all_results = []
    discovered = []
    sensitives = []
    comments = []
    sourcemaps = []
    js_sources = []
    found_any = False

    try:
        for result in engine.run(final_url, show_code=code):
            if not isinstance(result, dict):
                continue
            if 'error' in result:
                click.echo(_colored(f"[!] Engine Error: {result['error']}", RED))
                continue
            found_any = True

            rtype = result.get('type', 'result')
            url_val = result.get('url', '')

            if rtype == 'discovered':
                discovered.append(result)
                click.echo(f"  {_colored('[+]', GREEN)} {url_val}")
            elif rtype == 'sourcemap':
                sourcemaps.append(result)
                click.echo(f"  {_colored('[MAP]', YELLOW)} {url_val}")
            elif rtype == 'sourcemap_source':
                sourcemaps.append(result)
                click.echo(f"         {_colored('  └─', DIM)} {url_val}")
            elif rtype == 'robots_entry':
                click.echo(f"  {_colored('[ROBOT]', BLUE)} {url_val}  ({result.get('rule', '')})")
            elif rtype == 'sitemap_entry':
                click.echo(f"  {_colored('[SITEMAP]', CYAN)} {url_val}")
            elif rtype == 'sensitive':
                sensitives.append(result)
                name = result.get('name', 'secret')
                match = result.get('match', '')
                click.echo(f"  {_colored('[SECRET]', RED)} {_colored(name, RED)} → {match}")
            elif rtype == 'comment':
                comments.append(result)
                cmt = result.get('comment', '')
                click.echo(f"  {_colored('[COMMENT]', MAGENTA)} {cmt}")
            elif rtype == 'js_source':
                js_sources.append(result)
                body = result.get('body', '')
                length = result.get('length', 0)
                click.echo(f"  {_colored('[JS]', GREEN)} {url_val} {_colored(f'({length} bytes)', DIM)}")
                if body and body != f'[skipped: {length} bytes]':
                    rows = body.split('\n')
                    for i, row in enumerate(rows[:30]):
                        click.echo(f"    {_colored(f'{i+1:>4}', DIM)} {row}")
                    if len(rows) > 30:
                        click.echo(f"    {_colored('... truncated', DIM)}")
                    click.echo()
            elif rtype == 'subdomain':
                click.echo(f"  {_colored('[SUB]', B_CYAN)} {url_val}")
            elif rtype == 'subdomain_hint':
                click.echo(f"         {_colored('  └─ hint:', DIM)} {result.get('host', '')}")
            elif rtype == 'wayback':
                click.echo(f"  {_colored('[ARCHIVE]', YELLOW)} {url_val} ({result.get('timestamp', '')})")
            elif rtype == 'dependency':
                click.echo(f"  {_colored('[DEP]', BLUE)} {result.get('resolved', url_val)}")
            elif rtype == 'network_entry':
                rtype2 = result.get('resource_type', 'resource')
                click.echo(f"  {_colored(f'[{rtype2.upper()}]', B_CYAN)} {url_val}")
            elif rtype == 'network_result':
                status = result.get('status', 0)
                ct = result.get('content_type', '')
                length = result.get('length', 0)
                s_color = GREEN if status == 200 else (YELLOW if status < 400 else RED)
                click.echo(f"  {_colored(f'[{status}]', s_color)} {url_val} {_colored(f'({ct})', DIM)} {_colored(f'{length}b', DIM)}")
                body = result.get('body', '')
                if body and c.ShowCode and 'javascript' in ct:
                    rows = body.split('\n')
                    for i, row in enumerate(rows[:20]):
                        click.echo(f"    {_colored(f'{i+1:>4}', DIM)} {row}")
                    if len(rows) > 20:
                        click.echo(f"    {_colored('... truncated', DIM)}")
            elif rtype == 'summary':
                all_results.append(result)
                click.echo(f"\n  {_colored('═' * 56, DIM)}")
                click.echo(f"  {_colored('[DONE]', GREEN)} Crawled: {result.get('total', 0)} pages, "
                          f"{result.get('js_files', 0)} JS files, "
                          f"{result.get('subdomains', 0)} subdomains in {result.get('elapsed', '0s')}")
            else:
                click.echo(f"  {_colored('[?]', DIM)} {url_val}")

            all_results.append(result)

    except KeyboardInterrupt:
        click.echo(_colored("\n[!] Scan interrupted.", YELLOW))

    if not found_any:
        click.echo(_colored(f"[*] No artifacts discovered on {final_url}", YELLOW))

    # Print summary table
    if discovered or sensitives or sourcemaps:
        click.echo(f"\n  {_colored('═' * 56, DIM)}")
        click.echo(f"  {_colored('SUMMARY', BOLD)}")
        click.echo(f"  {_colored('─' * 56, DIM)}")
        if discovered:
            click.echo(f"  {_colored('URLs Discovered:', CYAN)} {len(discovered)}")
        js_count = sum(1 for d in discovered if d.get('url', '').endswith('.js'))
        if js_count:
            click.echo(f"  {_colored('JavaScript Files:', CYAN)} {js_count}")
        if sourcemaps:
            click.echo(f"  {_colored('Source Maps:', CYAN)} {len(sourcemaps)}")
        if sensitives:
            click.echo(f"  {_colored('Sensitive Findings:', RED)} {len(sensitives)}")
            for s in sensitives:
                click.echo(f"    {_colored('•', RED)} {s.get('name', '?')}: {s.get('match', '')}")
        if comments:
            click.echo(f"  {_colored('Notable Comments:', MAGENTA)} {len(comments)}")
            for c in comments[:5]:
                click.echo(f"    {_colored('•', MAGENTA)} {c.get('comment', '')[:80]}")
        click.echo(f"  {_colored('─' * 56, DIM)}")

    # Save to JSON
    if output and all_results:
        with open(output, 'w') as f:
            json.dump({
                "target": final_url,
                "results": all_results,
                "stats": {
                    "discovered": len(discovered),
                    "sensitive": len(sensitives),
                    "comments": len(comments),
                    "sourcemaps": len(sourcemaps),
                }
            }, f, indent=2)
        click.echo(f"  {_colored('[+]', GREEN)} Results saved to {output}")
