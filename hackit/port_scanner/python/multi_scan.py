"""
HackIT PortStorm — multiprocessing engine for shared-memory parallel scanning.
Bypasses the GIL via ProcessPoolExecutor for CPU-bound banner parsing + I/O overlap.
"""

import sys
import time
import argparse
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from multiprocessing import cpu_count
from typing import List

from .engine_banner import analyze_port, ScanResult, export_json, export_xml, COMMON_PORTS

try:
    from tqdm import tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False
    tqdm = None

__all__ = [
    'scan_target_mp',
    'scan_range_mp',
    'scan_top_ports_mp',
    'chunked_scan',
    'main',
]


def scan_target_mp(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    workers: int = None,
    progress: bool = True,
) -> List[ScanResult]:
    """Scan a list of ports in parallel using ProcessPoolExecutor."""
    if workers is None:
        workers = cpu_count()

    results = []
    fn = partial(analyze_port, host, timeout=timeout)

    with ProcessPoolExecutor(max_workers=workers) as pool:
        it = pool.map(fn, ports)
        if _HAS_TQDM and progress:
            it = tqdm(it, total=len(ports), desc='Scanning', unit='port')
        for res in it:
            if res.state == 'open':
                results.append(res)

    return sorted(results, key=lambda x: x.port)


def scan_range_mp(
    host: str,
    start: int,
    end: int,
    timeout: float = 2.0,
    workers: int = None,
) -> List[ScanResult]:
    """Scan a contiguous range of ports [start, end] using multiprocessing."""
    ports = list(range(start, end + 1))
    return scan_target_mp(host, ports, timeout, workers)


def scan_top_ports_mp(
    host: str,
    n: int = 100,
    timeout: float = 2.0,
    workers: int = None,
) -> List[ScanResult]:
    """Scan the N most commonly used ports using multiprocessing."""
    top = [
        80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
        8080, 1723, 111, 995, 993, 5900, 587, 8443, 6379, 27017, 5432,
        2375, 9200, 11211, 1433, 1521, 5672, 8000, 8888, 3000, 9090,
        6443, 10250, 2379, 2376, 5985, 5986, 389, 465, 514, 515, 548,
        631, 636, 873, 902, 1080, 1194, 1434, 1701, 2049, 2082, 2083,
        2181, 2483, 2484, 2967, 3074, 3128, 3535, 4333, 4443, 4444,
        4500, 5000, 5060, 5222, 5353, 5631, 5666, 5800, 5901, 6000,
        6001, 7001, 7070, 8008, 8009, 8081, 8500, 9000, 9001, 9100,
        9300, 9418, 9999, 10000, 27018, 50000,
    ]
    if n > len(top):
        top = list(range(1, n + 1))
    return scan_target_mp(host, top[:n], timeout, workers)


def _scan_chunk_impl(host: str, ports: List[int], timeout: float) -> List[ScanResult]:
    """Sequentially scan a chunk of ports (runs inside a worker process)."""
    out = []
    for p in ports:
        r = analyze_port(host, p, timeout)
        if r.state == 'open':
            out.append(r)
    return out


def chunked_scan(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    workers: int = None,
    progress: bool = True,
) -> List[ScanResult]:
    """Divide *ports* into worker-sized chunks, scan each chunk in a subprocess, merge results.

    Reduces inter-process call overhead compared to ``scan_target_mp`` when
    scanning very large port sets.
    """
    if workers is None:
        workers = cpu_count()
    if workers < 1:
        workers = 1

    chunk_size = max(1, len(ports) // workers)
    chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]

    fn = partial(_scan_chunk_impl, host, timeout=timeout)

    results = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        it = pool.map(fn, chunks)
        if _HAS_TQDM and progress:
            it = tqdm(it, total=len(chunks), desc='Chunks', unit='chunk')
        for chunk_results in it:
            results.extend(chunk_results)

    return sorted(results, key=lambda x: x.port)


def main():
    """CLI entry point — parse arguments and run the selected scan strategy."""
    parser = argparse.ArgumentParser(
        description='HackIT PortStorm — Multiprocessing Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('host', help='Target hostname or IP address')
    parser.add_argument(
        'ports', nargs='?', default='80,443,22,21,25,3306',
        help='Comma/range-separated ports (e.g. 80,443,1-1000)',
    )
    parser.add_argument(
        '-t', '--timeout', type=float, default=2.0,
        help='Connection timeout per port in seconds (default: 2.0)',
    )
    parser.add_argument(
        '-w', '--workers', type=int, default=None,
        help='Number of worker processes (default: CPU count)',
    )
    parser.add_argument(
        '--chunked', action='store_true',
        help='Use chunked scanning strategy (each worker handles a batch of ports)',
    )
    parser.add_argument('-o', '--output', help='Export results to file')
    parser.add_argument(
        '--format', choices=['json', 'xml'], default='json',
        help='Output format (default: json)',
    )
    parser.add_argument(
        '--range', nargs=2, type=int, metavar=('START', 'END'),
        help='Scan a port range instead of --ports',
    )
    parser.add_argument(
        '--top', type=int, metavar='N',
        help='Scan the top N most common ports',
    )
    parser.add_argument(
        '--no-progress', action='store_true',
        help='Disable progress bar',
    )

    args = parser.parse_args()

    port_list: List[int] = []
    if args.range:
        port_list = list(range(args.range[0], args.range[1] + 1))
    elif args.top is not None:
        top = [
            80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306,
            8080, 1723, 111, 995, 993, 5900, 587, 8443, 6379, 27017, 5432,
            2375, 9200, 11211, 1433, 1521, 5672, 8000, 8888, 3000, 9090,
            6443, 10250, 2379, 2376, 5985, 5986, 389, 465, 514, 515, 548,
            631, 636, 873, 902, 1080, 1194, 1434, 1701, 2049, 2082, 2083,
            2181, 2483, 2484, 2967, 3074, 3128, 3535, 4333, 4443, 4444,
            4500, 5000, 5060, 5222, 5353, 5631, 5666, 5800, 5901, 6000,
            6001, 7001, 7070, 8008, 8009, 8081, 8500, 9000, 9001, 9100,
            9300, 9418, 9999, 10000, 27018, 50000,
        ]
        if args.top > len(top):
            port_list = list(range(1, args.top + 1))
        else:
            port_list = top[:args.top]
    else:
        for part in args.ports.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = map(int, part.split('-', 1))
                port_list.extend(range(a, b + 1))
            else:
                port_list.append(int(part))

    if not port_list:
        parser.error('No ports to scan.')

    workers = args.workers or cpu_count()
    show_progress = not args.no_progress

    print(f'\n  HackIT Multiprocessing Scanner — scanning {args.host}')
    print(f'  Targets: {len(port_list)} ports | Workers: {workers}\n')

    start = time.time()

    if args.chunked:
        results = chunked_scan(args.host, port_list, args.timeout, workers, show_progress)
    else:
        results = scan_target_mp(args.host, port_list, args.timeout, workers, show_progress)

    elapsed = time.time() - start

    print(f'  PORT    STATE   SERVICE         VERSION                BANNER')
    print(f'  {"─" * 70}')
    for r in results:
        ver = r.version[:20] if r.version else ''
        ban = r.banner[:40] if r.banner else ''
        print(f'  {r.port:<6} OPEN    {r.service:<15} {ver:<20} {ban}')
    print(f'\n  Completed {len(port_list)} ports in {elapsed:.2f}s ({len(results)} open)\n')

    if args.output:
        if args.format == 'json':
            export_json(results, args.output)
        else:
            export_xml(results, args.output, args.host)
        print(f'  Results exported to {args.output}\n')


if __name__ == '__main__':
    main()
