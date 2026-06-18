import click
import json
import sys
import threading
import time
from hackit.ui import display_tool_banner, _colored, GREEN, YELLOW, RED, CYAN, BLUE, WHITE, BOLD, DIM, MAGENTA
from .go_bridge import get_engine

PARAM_ART = r"""
    ____                        _____                __         
   / __ \____ _____ ___  ___   / ___/_____________  / /_  ____ _
  / /_/ / __ `/ __ `__ \/ _ \  \__ \/ ___/ ___/ _ \/ __ \/ __ `/
 / ____/ /_/ / / / / / /  __/ ___/ / /__/ /  /  __/ /_/ / /_/ / 
/_/    \__,_/_/ /_/ /_/\___//____/\___/_/   \___/_.___/\__,_/  
"""

SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

class Spinner:
    def __init__(self, msg=" Scanning Archives..."):
        self.msg = msg
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        i = 0
        while self._running:
            sys.stdout.write(f"\r  {_colored(SPINNER[i % len(SPINNER)], CYAN)} {_colored(self.msg, DIM)}")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)


@click.command()
@click.option('-d', '--domain', help='Domain for archive discovery (e.g. example.com)')
@click.option('-u', '--url', help='Direct URL with parameters (e.g. https://site.com/page?foo=bar)')
@click.option('-l', '--list', 'domain_list', help='File containing list of domains')
@click.option('-p', '--placeholder', default='FUZZ', help='Placeholder for parameter values (default: FUZZ)')
@click.option('-s', '--stream', is_flag=True, help='Stream discovered URLs to terminal')
@click.option('--fuzz', 'enable_fuzz', is_flag=True, help='Enable fuzzing mode (test params for reflection/errors)')
@click.option('--params', help='Parameters to fuzz (comma separated, for --fuzz mode)')
@click.option('--payloads', help='Custom payloads file (for --fuzz mode)')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST']), help='HTTP method for fuzzing')
@click.option('--threads', default=10, help='Concurrent requests')
@click.option('--timeout', default=10, help='Request timeout in seconds')
@click.option('-o', '--output', help='Save results to JSON file')
@click.option('--proxy', help='HTTP proxy address (e.g. 127.0.0.1:8080)')
@click.option('--sources', default='wayback,otx,urlscan,commoncrawl', help='Archive sources: wayback,otx,urlscan,commoncrawl')
@click.option('-e', '--exclude', help='Extra extensions to exclude (comma separated)')
@click.option('-v', '--verbose', is_flag=True, help='Verbose debug output')
@click.pass_context
def scan(ctx, domain, url, domain_list, placeholder, stream, enable_fuzz, params,
         payloads, method, threads, timeout, output, proxy, sources,
         exclude, verbose):
    if not domain and not url and not domain_list:
        click.echo(ctx.get_help())
        return

    color = CYAN
    click.echo()
    click.echo(_colored(PARAM_ART, color, bold=True))
    click.echo(_colored(f"  {'ParamTracer v2.0':^55}", BLUE, bold=True))
    click.echo(_colored(f"  {'─' * 55}", DIM))
    click.echo(f"  {_colored('Target:', WHITE, bold=True)} {_colored(domain or url or domain_list, BLUE)}")
    click.echo()

    engine = get_engine()
    if not engine.available:
        click.echo(_colored("[!] Go is not installed.", RED))
        return

    if not engine.ensure_compiled():
        click.echo(_colored("[!] Failed to compile Go engine.", RED))
        return

    spinner = Spinner()
    spinner.start()

    full_result = {}
    disco_count = 0
    fuzz_count = 0
    finding_count = 0
    all_discovered = []
    param_details = []

    for event in engine.run(
        domain=domain, url=url, domain_list=domain_list,
        placeholder=placeholder, enable_fuzz=enable_fuzz,
        fuzz_params=params, payload_file=payloads,
        method=method, threads=threads, timeout=timeout,
        output=output, proxy=proxy, sources=sources,
        verbose=verbose
    ):
        etype = event.get('type', '')

        if etype == 'summary':
            spinner.stop()
            full_result = event
            d = event.get('domain', '')
            u = event.get('urls', 0)
            p = event.get('params', 0)
            click.echo(f"  {_colored('Domain:', WHITE, bold=True)} {_colored(d, BLUE)} {_colored('|', DIM)} {u} URLs, {_colored(str(p), CYAN)} unique params")
            if u > 0:
                click.echo()

        elif etype == 'discovery':
            disco_count += 1
            url_str = event.get('url', '')
            pc = event.get('param_count', 0)
            params_found = event.get('param_names', [])
            all_discovered.append(event)
            click.echo(f"  {_colored('├─', DIM)} {_colored(url_str[:120], WHITE)} ({_colored(str(pc), CYAN)} param{'s' if pc != 1 else ''})")
            if (stream or verbose) and params_found:
                click.echo(f"  {_colored('│  params:', DIM)} {_colored(', '.join(params_found[:10]), DIM)}")

        elif etype == 'param_detail':
            param_details.append(event)

        elif etype == 'finding':
            finding_count += 1
            ftype = event.get('finding_type', '')
            cat = event.get('category', '')
            desc = event.get('description', '')
            sev = event.get('severity', 'Info')
            sev_color = RED if sev in ('High', 'Critical') else YELLOW if sev == 'Medium' else GREEN
            click.echo(f"  {_colored('⚠', sev_color)} {_colored(cat, sev_color, bold=True)} [{sev}]")
            click.echo(f"     {desc}")

        elif etype == 'fuzz_result':
            fuzz_count += 1
            param = event.get('param', '')
            payload = event.get('payload', '')
            status = event.get('status', 0)
            reflected = event.get('reflected', False)
            err = event.get('error', '')
            ctx = event.get('context', '')[:80]

            if reflected:
                click.echo(f"  {_colored('◈', RED)} {_colored('REFLECTED', RED, bold=True)} {param}={payload!r} [{status}]")
                if ctx:
                    click.echo(f"     {_colored(ctx, DIM)}")
            if err:
                click.echo(f"  {_colored('◈', YELLOW)} {_colored('ERROR', YELLOW)} {param}: {err}")

        elif etype == 'done':
            spinner.stop()
            duration = event.get('duration_ms', 0)

            if param_details:
                click.echo(f"\n  {_colored('▸ Parameter Analysis', WHITE, bold=True)}")
                click.echo(f"  {_colored('─' * 55, DIM)}")
                for ev in param_details:
                    name = ev.get('name', '')
                    ptype = ev.get('param_type', ev.get('type', 'unknown'))
                    urls = ev.get('url_count', 0)
                    sample = ev.get('sample', '')
                    sensitive = ev.get('sensitive', False)
                    sources = ev.get('sources', [])
                    type_color = {
                        'jwt': RED, 'sensitive': RED, 'base64': YELLOW,
                        'hash': YELLOW, 'path': YELLOW, 'graphql': MAGENTA,
                        'numeric': CYAN, 'boolean': CYAN, 'uuid': CYAN,
                        'url': CYAN, 'email': CYAN, 'date': CYAN, 'timestamp': CYAN,
                        'empty': DIM,
                    }.get(ptype, WHITE)
                    sens_tag = _colored(' ⚑', RED) if sensitive else ''
                    sample_str = sample[:45] if sample else ''
                    sample_tag = _colored(f'  {sample_str}', DIM) if sample else ''
                    click.echo(f"  {_colored(f'{name:26}', WHITE, bold=True)} {_colored(f'{ptype:10}', type_color)} {urls:2} URLs{sens_tag}{sample_tag}")
                    if verbose and sources:
                        for src in sources[:3]:
                            click.echo(f"  {_colored('  └─', DIM)} {_colored(src[:90], DIM)}")
                click.echo()

            else:
                click.echo(f"\n  {_colored('▸ No parameters discovered', DIM)}")
                click.echo()

            click.echo(f"  {_colored('─' * 55, DIM)}")
            summary_parts = []
            summary_parts.append(f"{_colored(str(disco_count) + ' URLs', CYAN)}")
            summary_parts.append(f"{_colored(str(len(param_details)) + ' params', BLUE)}")
            summary_parts.append(f"{_colored(str(finding_count) + ' findings', RED)}")
            click.echo(f"  {' | '.join(summary_parts)}")
            click.echo(f"  {_colored(f'Completed in {duration}ms', DIM)}")
            click.echo()

        elif etype == 'error':
            spinner.stop()
            click.echo(f"\n  {_colored('✖ Error:', RED)} {event.get('message', 'Unknown')}")

    if output and full_result:
        combined = {'summary': full_result, 'discovered': all_discovered, 'params': param_details}
        with open(output, 'w') as f:
            json.dump(combined, f, indent=2, default=str)
        click.echo(f"  {_colored('▸ Saved to', GREEN)} {output}")

fuzz_params = scan
