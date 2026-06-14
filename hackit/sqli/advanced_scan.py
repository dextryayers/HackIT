"""
SQLi Advanced Scan Engine — Multi-target parallel scanning with correlation analysis.
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from .go_bridge import GoEngine

_console = Console()


@dataclass
class ScanTarget:
    url: str
    method: str = "GET"
    data: Optional[str] = None
    cookie: Optional[str] = None
    proxy: Optional[str] = None
    headers: tuple = ()
    label: str = ""


@dataclass
class ScanResult:
    target: ScanTarget
    vulnerabilities: List[Dict] = field(default_factory=list)
    enumeration: List[Dict] = field(default_factory=list)
    vuln_count: int = 0
    error: Optional[str] = None
    duration: float = 0.0


def _merge_results(results_a: List[Dict], results_b: List[Dict]) -> List[Dict]:
    seen = set()
    merged = []
    for r in results_a + results_b:
        key = f"{r.get('parameter','')}|{r.get('type','')}|{r.get('dbms','')}"
        if key not in seen:
            seen.add(key)
            merged.append(r)
    return merged


def scan_target(target: ScanTarget, engine: GoEngine, **scan_kwargs) -> ScanResult:
    start = time.time()
    result = ScanResult(target=target)
    try:
        kwargs = {
            'url': target.url,
            'method': target.method,
            'data': target.data,
            'cookie': target.cookie,
            'proxy': target.proxy,
            'header': target.headers,
            **scan_kwargs,
        }
        raw = engine.run(**kwargs)
        result.duration = time.time() - start
        if raw and isinstance(raw, list) and len(raw) > 0 and 'error' in raw[0]:
            result.error = raw[0]['error']
            return result
        for r in raw:
            if r.get('parameter') == "enumeration":
                result.enumeration.append(r)
            else:
                result.vulnerabilities.append(r)
        result.vuln_count = len(result.vulnerabilities)
    except Exception as e:
        result.error = str(e)
        result.duration = time.time() - start
    return result


def parallel_scan(
    targets: List[ScanTarget],
    max_workers: int = 5,
    risk_level: int = 3,
    threads: int = 5,
    timeout: int = 30,
    dbs: bool = False,
    dump_all: bool = False,
) -> Dict[str, Any]:
    _console.print(Panel(
        f"[bold cyan]Multi-Target Parallel Scan[/]\n"
        f"  Targets: {len(targets)}  Workers: {max_workers}  Risk: {risk_level}/5\n"
        f"  Enumerate: {'Yes' if dbs else 'No'}  Dump: {'Yes' if dump_all else 'No'}",
        border_style="cyan"
    ))

    engine = GoEngine()
    if not engine.available:
        return {"error": "Go engine not available"}

    base_kwargs = {
        'risk_level': risk_level,
        'threads': threads,
        'timeout': timeout,
        'fingerprint': True,
        'list_dbs': dbs,
        'dump_all': dump_all,
    }

    results: List[ScanResult] = []
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[bold cyan]{task.description}[/]"),
        BarColumn(bar_width=40),
        console=_console
    ) as progress:
        task = progress.add_task(f"Scanning {len(targets)} targets...", total=len(targets))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_target, t, engine, **base_kwargs): t for t in targets}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append(ScanResult(target=futures[future], error=str(e)))
                progress.advance(task)

    _console.print()
    _console.print(Panel("[bold]Scan Summary[/]", border_style="green"))
    summary = Table(box=box.ROUNDED, show_lines=True)
    summary.add_column("Target", style="cyan")
    summary.add_column("Vulns", style="red", justify="center")
    summary.add_column("DBMS", style="green", justify="center")
    summary.add_column("Time", style="yellow", justify="right")
    summary.add_column("Status", style="white")

    global_db_set = set()
    total_vulns = 0
    for r in results:
        label = r.target.label or r.target.url
        for v in r.vulnerabilities:
            global_db_set.add(v.get('dbms', 'Unknown'))
        total_vulns += r.vuln_count
        dbms_hint = ", ".join(sorted(set(v.get('dbms', '') for v in r.vulnerabilities))) or "-"
        status = f"[green]{r.vuln_count} vuln(s)[/]" if r.vuln_count > 0 else "[dim]None[/]"
        if r.error:
            status = f"[red]Error: {r.error[:30]}[/]"
        summary.add_row(
            label[:60],
            str(r.vuln_count),
            dbms_hint[:20],
            f"{r.duration:.1f}s",
            status,
        )
    summary.add_row(
        f"[bold]{len(results)} targets[/]",
        f"[bold]{total_vulns}[/]",
        ", ".join(sorted(global_db_set))[:25],
        "",
        ""
    )
    _console.print(summary)

    return {
        "results": [
            {
                "target": r.target.url,
                "vulnerabilities": r.vulnerabilities,
                "enumeration": r.enumeration,
                "vuln_count": r.vuln_count,
                "error": r.error,
                "duration": r.duration,
            }
            for r in results
        ],
        "total_vulns": total_vulns,
        "dbms_detected": list(global_db_set),
    }


def deep_scan_single(
    url: str,
    risk_escalate: bool = True,
    timeout: int = 60,
) -> Dict[str, Any]:
    engine = GoEngine()
    if not engine.available:
        return {"error": "Go engine not available"}

    _console.print(f"\n[bold cyan]Deep Scan:[/] {url}")
    _console.print("[dim]Progressive escalation: risk 1 → 3 → 5[/dim]\n")

    all_vulns = []
    all_enums = []

    for risk in ([1, 3, 5] if risk_escalate else [5]):
        _console.print(f"[yellow]─ Risk level {risk}/5 ─[/]")
        results = engine.run(url=url, risk_level=risk, timeout=timeout,
                             fingerprint=True, list_dbs=(risk >= 3), dump_all=(risk >= 5))
        if results and 'error' in results[0]:
            _console.print(f"[red]  Error: {results[0]['error']}[/]")
            continue
        for r in results:
            if r.get('parameter') == "enumeration":
                all_enums.append(r)
            else:
                all_vulns.append(r)
        if results:
            _console.print(f"  Found {len([r for r in results if r.get('parameter')!='enumeration'])} vuln(s)")
        time.sleep(0.5)

    all_vulns = _merge_results(all_vulns, [])
    _console.print(f"\n[bold]Total unique vulnerabilities: {len(all_vulns)}[/]")
    return {
        "url": url,
        "vulnerabilities": all_vulns,
        "enumeration": all_enums,
        "total_vulns": len(all_vulns),
    }
