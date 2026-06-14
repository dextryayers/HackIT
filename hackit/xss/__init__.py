#!/usr/bin/env python3
import os, sys, json, click
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

from go_bridge import GoEngine
from python_bridge import PythonEngine

from hackit.ui import (
    display_tool_banner, _colored,
    GREEN, RED, BLUE, YELLOW, B_GREEN, B_CYAN, B_WHITE, B_RED, B_YELLOW, DIM, PURPLE
)


def pick_engine(preferred: str = "go"):
    engines = {
        "go": GoEngine(),
        "python": PythonEngine(),
    }
    if preferred in engines:
        return engines[preferred]
    return engines["go"]


def correlate_results(all_results: list) -> list:
    by_url_param = {}
    for engine_name, results in all_results:
        for r in results:
            if not isinstance(r, dict) or r.get('error'):
                continue
            key = (r.get('url', ''), r.get('parameter', ''))
            if key not in by_url_param:
                by_url_param[key] = {'results': [], 'max_conf': 0.0}
            by_url_param[key]['results'].append(r)
            conf_val = 0.9 if r.get('confidence') == "High" else 0.7 if r.get('confidence') == "Medium" else 0.4
            if conf_val > by_url_param[key]['max_conf']:
                by_url_param[key]['max_conf'] = conf_val

    correlated = []
    for (url_param), data in by_url_param.items():
        engine_count = len(data['results'])
        avg_conf = sum(
            0.9 if r.get('confidence') == "High" else 0.7 if r.get('confidence') == "Medium" else 0.4
            for r in data['results']
        ) / max(engine_count, 1)
        if engine_count >= 2:
            avg_conf = min(1.0, avg_conf + 0.15)
        best = max(data['results'], key=lambda r: (
            0.9 if r.get('confidence') == "High" else 0.7 if r.get('confidence') == "Medium" else 0.4
        ))
        best['confidence'] = avg_conf
        best['correlation_count'] = engine_count
        correlated.append(best)

    correlated.sort(key=lambda r: (
        0.9 if r.get('confidence') == "High" else 0.7 if r.get('confidence') == "Medium" else 0.4
    ), reverse=True)
    return correlated


def severity_color(sev: str) -> str:
    sev_lower = sev.lower() if sev else ""
    if sev_lower in ("critical", "high"):
        return B_RED
    elif sev_lower == "medium":
        return B_YELLOW
    else:
        return B_GREEN


def confidence_color(conf: str) -> str:
    return B_RED if conf == "High" else B_YELLOW


@click.command(name="xss")
@click.option('-u', '--url', required=True, help='Target URL (with parameters)')
@click.option('-o', '--output', help='Save results to file')
@click.option('--timeout', default=10, type=int, help='Request timeout in seconds')
@click.option('--threads', default=10, type=int, help='Concurrent threads')
@click.option('--engines', default='go,python', help='Engines: go,python (comma-separated)')
def scan_xss(url, output, timeout, threads, engines):
    """Advanced XSS Scanner — Multi-Engine Correlation (Go · Python)

    Tests each parameter with 150+ payloads across multiple contexts.
    Uses two engines for cross-verification and false-positive reduction.
    """
    display_tool_banner('XSS Scanner (Go + Python)')
    print(f"{BLUE}[*] Target: {url}{DIM}\n")

    selected = [e.strip().lower() for e in engines.split(',') if e.strip()]
    engine_map = {
        'go': ('Go', GoEngine()),
        'python': ('Python', PythonEngine()),
    }

    all_results = []

    for eng_name in selected:
        if eng_name not in engine_map:
            print(f"{YELLOW}⚠ Unknown engine: {eng_name}, skipping{DIM}")
            continue
        label, eng = engine_map[eng_name]
        print(f"{B_CYAN}[*] Running {label} engine...{DIM}")

        if not eng.available:
            print(f"{YELLOW}⚠ {label} not available, skipping{DIM}")
            all_results.append((label, [{"error": f"{label} not available"}]))
            continue

        if not eng.ensure_compiled():
            print(f"{YELLOW}⚠ {label} engine compilation failed, skipping{DIM}")
            all_results.append((label, [{"error": f"{label} compilation failed"}]))
            continue

        try:
            results = eng.run(url, timeout=timeout, threads=threads)
            all_results.append((label, results))
        except Exception as e:
            all_results.append((label, [{"error": str(e)}]))
            print(f"{RED}✗ {label} engine error: {e}{DIM}")

    correlated = correlate_results(all_results)

    vuln_results = [r for r in correlated if not r.get('error')]
    errors = [r for r in correlated if r.get('error')]

    if vuln_results:
        print(f"\n{B_RED}╔{'═'*60}╗{DIM}")
        print(f"{B_RED}║  ⚠ {len(vuln_results)} XSS Vulnerability(ies) Detected{' ' * (43 - len(str(len(vuln_results))))}║{DIM}")
        print(f"{B_RED}╚{'═'*60}╝{DIM}")

        for r in vuln_results:
            sev_color = severity_color(r.get('severity', ''))
            conf = r.get('confidence', 0)
            conf_str = f"{conf * 100:.0f}%" if isinstance(conf, (int, float)) else r.get('confidence', '?')

            print(f"\n{sev_color}[{r.get('severity', '?').upper()}]{DIM} "
                  f"Parameter: {B_WHITE}{r.get('parameter', '?')}{DIM}")
            print(f"  {PURPLE}Payload:{DIM} {r.get('payload', '?')[:100]}")
            print(f"  {PURPLE}Context:{DIM} {r.get('details', '?')}")
            print(f"  {PURPLE}Confidence:{DIM} {conf_str}")
            print(f"  {PURPLE}Impact:{DIM} {r.get('impact', '?')}")
            engines_used = r.get('engine', '?')
            if r.get('correlation_count', 1) > 1:
                engines_used += f" (+{r['correlation_count'] - 1} correlated)"
            print(f"  {PURPLE}Engine:{DIM} {engines_used}")
            print(f"  {PURPLE}URL:{DIM} {r.get('url', '?')[:120]}")
    else:
        print(f"\n{B_GREEN}[✓] No XSS vulnerabilities detected.{DIM}")
        safe_count = sum(1 for _, res in all_results for r in res if not r.get('error'))
        print(f"{DIM}  {safe_count} parameter(s) tested, all clean.{DIM}")

    if errors:
        print(f"\n{RED}{len(errors)} error(s):{DIM}")
        for e in errors:
            print(f"  {RED}✗ {e.get('error', 'Unknown')}{DIM}")

    if output:
        try:
            with open(output, 'w') as f:
                json.dump(correlated, f, indent=2)
            print(f"\n{GREEN}✓ Results saved to {output}{DIM}")
        except Exception as e:
            print(f"\n{RED}✗ Failed to save results: {e}{DIM}")

    if vuln_results:
        print(f"\n{B_RED}⚠ VULNERABILITY CONFIRMED: Cross-Site Scripting{DIM}")
    else:
        print(f"\n{B_GREEN}✓ Target appears secure against tested XSS vectors.{DIM}")
