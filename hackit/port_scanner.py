"""
Async Port Scanner - Multi-threaded TCP port scanning
"""
import asyncio
import json
import socket
import ipaddress
from typing import List, Dict, Set, Iterable
from datetime import datetime
import click
from typing import Any
from hackit.cve_checker import CVEChecker
from hackit.nse_engine import load_scripts, run_scripts_for_port

# Optional scapy for SYN scans
from hackit.cve_checker import CVEChecker

try:
    import scapy.all as scapy  # type: ignore
except Exception:
    scapy = None


class PortScanner:
    """Async port scanner with timeout and filtering"""
    
    def __init__(self, timeout: int = 3, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports: Set[int] = set()
        self.closed_ports: Set[int] = set()
        self.filtered_ports: Set[int] = set()
        self._sem: asyncio.Semaphore = asyncio.Semaphore(value=max_workers)
    
    async def check_port(self, host: str, port: int) -> Dict:
        """Check if a single port is open"""
        # If SYN scan requested, try that first (may return None to fall back)
        if getattr(self, 'syn_scan', False):
            syn_res = await self._maybe_syn_scan(host, port)
            if syn_res is not None:
                return syn_res

        try:
            async with self._sem:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                banner = None
                try:
                    # only attempt banner/service detection when requested
                    if getattr(self, 'service_detect', False):
                        try:
                            banner = await asyncio.wait_for(reader.read(1024), timeout=0.8)
                            if isinstance(banner, bytes):
                                banner = banner.decode(errors='ignore').strip()
                        except asyncio.TimeoutError:
                            banner = None
                        # service-specific probing for better version detection
                        svc = self._get_service_name(port)
                        try:
                            sv = await self._service_probe(reader, writer, host, port, svc)
                            if sv:
                                banner = sv
                        except Exception:
                            pass
                    else:
                        banner = None
                except Exception:
                    banner = None
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            self.open_ports.add(port)
            result = {"port": port, "status": "open", "service": self._get_service_name(port)}
            if banner:
                result['banner'] = banner
            return result
        except asyncio.TimeoutError:
            self.filtered_ports.add(port)
            return {"port": port, "status": "filtered"}
        except ConnectionRefusedError:
            self.closed_ports.add(port)
            return {"port": port, "status": "closed"}
        except OSError as e:
            # Network unreachable, no route, DNS error, etc.
            self.filtered_ports.add(port)
            return {"port": port, "status": "filtered", "error": str(e)}
        except Exception as e:
            self.filtered_ports.add(port)
            return {"port": port, "status": "filtered", "error": str(e)}
    
    async def scan(self, host: str, ports: List[int], open_only: bool = False) -> List[Dict]:
        """Scan multiple ports concurrently"""
        tasks = [self.check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)

        if open_only:
            return [r for r in results if r["status"] == "open"]
        return results

    def _parse_banner_for_software(self, banner: str):
        """Try to extract (software, version) from common banners like 'nginx/1.18.0' or 'Apache/2.4.49'"""
        if not banner:
            return None
        import re
        # common pattern name/version
        m = re.search(r"([A-Za-z0-9_\-]+)[/ ]([0-9]+(?:\.[0-9a-zA-Z_\-]+)*)", banner)
        if m:
            name = m.group(1)
            version = m.group(2)
            return (name, version)
        return None

    async def _tcp_fingerprint(self, host: str, port: int = 80) -> dict | None:
        """Attempt to collect IP TTL and TCP window size via scapy SYN-ACK (best-effort).
        Returns dict {'ttl': int, 'window': int} or None.
        """
        if scapy is None:
            return None
        try:
            pkt = scapy.IP(dst=host)/scapy.TCP(dport=port, flags='S')
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                return None
            ttl = resp.ttl if hasattr(resp, 'ttl') else None
            win = None
            if resp.haslayer(scapy.TCP):
                win = resp.getlayer(scapy.TCP).window
            return {'ttl': ttl, 'window': win}
        except Exception:
            return None

    def _guess_os_from_fingerprint(self, fp: dict | None, banners: List[str] | None = None) -> str | None:
        """Heuristic OS guess from ttl/window and banners."""
        # banner hints
        if banners:
            for b in banners:
                if b:
                    lb = b.lower()
                    if 'windows' in lb:
                        return 'Windows (banner)'
                    if 'ubuntu' in lb or 'debian' in lb or 'linux' in lb or 'centos' in lb or 'red hat' in lb:
                        return 'Linux (banner)'
                    if 'cisco' in lb or 'ios' in lb:
                        return 'Cisco/Embedded (banner)'
        if not fp:
            return None
        ttl = fp.get('ttl')
        win = fp.get('window')
        if ttl is None:
            return None
        # heuristics: TTL 128 -> Windows, 64 -> Linux, 255 -> BSD/Embedded
        if ttl >= 128:
            return 'Windows'
        if ttl >= 200:
            return 'BSD/Embedded'
        if ttl >= 64:
            return 'Linux/Unix'
        return None

    async def check_udp_port(self, host: str, port: int) -> Dict:
        """Best-effort UDP probe: send a small packet and wait for response or ICMP reply."""
        loop = asyncio.get_event_loop()

        def _udp_probe(h: str, p: int, timeout: float):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                # send a single nul byte (some services reply)
                s.sendto(b"\x00", (h, p))
                data, _ = s.recvfrom(4096)
                banner = data.decode(errors='ignore').strip() if data else None
                self.open_ports.add(p)
                return {"port": p, "status": "open", "service": self._get_service_name(p), "banner": banner}
            except socket.timeout:
                # no reply -> open|filtered
                return {"port": p, "status": "filtered"}
            except ConnectionRefusedError:
                # ICMP port unreachable usually maps to connection refused
                self.closed_ports.add(p)
                return {"port": p, "status": "closed"}
            except OSError as e:
                return {"port": p, "status": "filtered", "error": str(e)}
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        # run blocking UDP probe in executor
        try:
            result = await loop.run_in_executor(None, _udp_probe, host, port, self.timeout)
            return result
        except Exception as e:
            return {"port": port, "status": "filtered", "error": str(e)}

    async def scan_udp(self, host: str, ports: List[int]) -> List[Dict]:
        tasks = [self.check_udp_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return results

    async def _maybe_syn_scan(self, host: str, port: int) -> Dict | None:
        """Attempt a SYN scan using scapy when possible. Returns a result dict or None to fall back."""
        if scapy is None:
            return None
        try:
            pkt = scapy.IP(dst=host)/scapy.TCP(dport=port, flags='S')
            resp = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                return {"port": port, "status": "filtered"}
            if resp.haslayer(scapy.TCP):
                tcp = resp.getlayer(scapy.TCP)
                if tcp.flags & 0x12:  # SYN-ACK
                    rst = scapy.IP(dst=host)/scapy.TCP(dport=port, flags='R')
                    scapy.send(rst, verbose=0)
                    self.open_ports.add(port)
                    return {"port": port, "status": "open", "service": self._get_service_name(port)}
                elif tcp.flags & 0x14:  # RST-ACK
                    self.closed_ports.add(port)
                    return {"port": port, "status": "closed"}
            return {"port": port, "status": "filtered"}
        except PermissionError:
            return None
        except Exception:
            return None

    async def _service_probe(self, reader, writer, host: str, port: int, svc: str) -> str | None:
        """Service-specific probes for better version detection. Returns banner/version string or None."""
        try:
            if svc == 'SSH':
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    if data:
                        return data.decode(errors='ignore').strip()
                except Exception:
                    return None
            if svc in ('FTP', 'SMTP', 'POP3'):
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    banner = data.decode(errors='ignore').strip() if data else None
                    if svc == 'SMTP' and banner:
                        try:
                            writer.write(b'EHLO probe.example.com\r\n')
                            await writer.drain()
                            resp = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                            if resp:
                                return (banner + ' | ' + resp.decode(errors='ignore').split('\r\n')[0])
                        except Exception:
                            pass
                    return banner
                except Exception:
                    return None
            if svc in ('HTTP', 'HTTPS', 'HTTP-ALT', 'HTTPS-ALT'):
                try:
                    req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                    writer.write(req.encode())
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(2048), timeout=1.5)
                    if data:
                        txt = data.decode(errors='ignore')
                        for line in txt.split('\r\n'):
                            if line.lower().startswith('server:'):
                                return line.split(':',1)[1].strip()
                        return txt.split('\r\n')[0]
                except Exception:
                    return None
        except Exception:
            return None
        return None

    async def scan_hosts_parallel(self, hosts: Iterable[str], ports: List[int], open_only: bool = False, chunk_size: int | None = None) -> Dict[str, List[Dict]]:
        """Scan multiple hosts in parallel by scheduling host-port tasks globally with chunking."""
        all_pairs = [(h, p) for h in hosts for p in ports]
        if chunk_size is None:
            chunk_size = max(100, self.max_workers * 10)
        results: Dict[str, List[Dict]] = {h: [] for h in hosts}
        for i in range(0, len(all_pairs), chunk_size):
            chunk = all_pairs[i:i+chunk_size]
            tasks = [self.check_port(h, p) for (h, p) in chunk]
            chunk_results = await asyncio.gather(*tasks)
            for (h, p), res in zip(chunk, chunk_results):
                results[h].append(res)
        if open_only:
            filtered = {h: [r for r in res if r.get('status') == 'open'] for h, res in results.items()}
            return filtered
        return results

    async def scan_hosts(self, hosts: Iterable[str], ports: List[int], open_only: bool = False) -> Dict[str, List[Dict]]:
        """Scan multiple hosts concurrently. Returns dict host -> results list."""
        host_tasks = {host: asyncio.create_task(self.scan(host, ports, open_only=open_only)) for host in hosts}
        results: Dict[str, List[Dict]] = {}
        for host, task in host_tasks.items():
            try:
                results[host] = await task
            except Exception as e:
                results[host] = [{"error": str(e)}]
        return results
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get common service name for port"""
        services = {
            21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")


@click.command()
@click.option('--host', required=False, help='Target host (single). Ignored if --targets provided')
@click.option('--targets', default=None, help='Comma-separated hosts/CIDRs or @file path with hosts')
@click.option('-p', '--ports', default='1-1000', help='Port range (e.g., 1-1000 or 22,80,443)')
@click.option('-A', '--scan-all', is_flag=True, help='Scan all TCP ports (1-65535)')
@click.option('--ping', '-P', is_flag=True, help='Host discovery only (TCP ping)')
@click.option('-sV', '--service-detect', 'service_detect', is_flag=True, help='Attempt simple service/banner detection (like nmap -sV)')
@click.option('-sS', '--syn', 'syn_scan', is_flag=True, help='Perform TCP SYN scan (requires root and scapy)')
@click.option('--timeout', default=3, type=int, help='Timeout per port in seconds')
@click.option('--threads', default=100, type=int, help='Number of concurrent workers')
@click.option('--open-only', is_flag=True, help='Show only open ports')
@click.option('-sU', '--udp', 'udp_scan', is_flag=True, help='Scan UDP ports (best-effort)')
@click.option('--parallel', is_flag=True, help='Enable parallel host scanning (global concurrency)')
@click.option('-f', '--format', 'out_format', default='json', type=click.Choice(['json','gnmap','xml','csv']), help='Output format when using --output')
@click.option('--os-detect', is_flag=True, help='Attempt OS detection using banners and TCP/IP fingerprints')
@click.option('--scripts', default=None, help='Comma-separated NSE script names to run, or "all" to load all')
@click.option('--cve', is_flag=True, help='Run CVE matching against detected services/versions')
@click.option('--output', default=None, help='Save results to file (format controls extension)')
@click.option('--max-hosts', default=256, type=int, help='Maximum hosts to expand for CIDR inputs')
def scan_ports(host, targets, ports, scan_all, ping, service_detect, syn_scan, timeout, threads, open_only, udp_scan, out_format, os_detect, scripts, cve, parallel, output, max_hosts):
    """Async TCP port scanner supporting multiple targets and CIDR/file input."""

    # Build host list
    host_list: List[str] = []
    if targets:
        items = [t.strip() for t in targets.split(',') if t.strip()]
        for item in items:
            if item.startswith('@'):
                path = item[1:]
                try:
                    with open(path, 'r') as fh:
                        for line in fh:
                            v = line.strip()
                            if v:
                                host_list.append(v)
                except Exception as e:
                    click.echo(f"[!] Could not read hosts file {path}: {e}")
            elif '/' in item:
                try:
                    net = ipaddress.ip_network(item, strict=False)
                    count = 0
                    for ip in net.hosts():
                        host_list.append(str(ip))
                        count += 1
                        if count >= max_hosts:
                            break
                except Exception as e:
                    click.echo(f"[!] Invalid CIDR {item}: {e}")
            else:
                host_list.append(item)
    elif host:
        host_list = [host]
    else:
        click.echo("[!] Either --host or --targets must be provided")
        return

    # Determine ports to scan
    if scan_all:
        ports = '1-65535'

    port_list: List[int] = []
    for part in ports.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))

    scanner = PortScanner(timeout=timeout, max_workers=threads)
    # ensure semaphore reflects requested worker count
    scanner._sem = asyncio.Semaphore(value=threads)
    # attach service detection flag to scanner
    scanner.service_detect = bool(service_detect)
    # attach UDP scan flag
    scanner.udp_scan = bool(udp_scan)
    # attach SYN scan flag
    scanner.syn_scan = bool(syn_scan)
    scanner.os_detect = bool(os_detect)
    # nse scripts list (empty by default)
    scanner.nse_scripts = []
    if scripts:
        if scripts.strip().lower() == 'all':
            scanner.nse_scripts = load_scripts()
        else:
            scanner.nse_scripts = [s.strip() for s in scripts.split(',') if s.strip()]
    # CVE integration flag
    run_cve = bool(cve)

    click.echo(f"Starting Nmap-like scan at {datetime.utcnow().isoformat()}")
    click.echo(f"[*] Targets: {len(host_list)} hosts")
    click.echo(f"[*] Scanning {len(port_list)} ports each; Timeout: {timeout}s, Workers: {threads}")

    results: Dict[str, List[Dict]] = {}
    start_time = datetime.now()
    os_map: Dict[str, str] = {}
    cve_matches: Dict[str, List[Dict]] = {}
    script_findings: Dict[str, List[Dict]] = {}

    # simple host discovery function (TCP ping)
    def tcp_ping(h: str, timeout_s: float = 1.0) -> bool:
        try:
            with socket.create_connection((h, 80), timeout=timeout_s):
                return True
        except Exception:
            try:
                with socket.create_connection((h, 443), timeout=timeout_s):
                    return True
            except Exception:
                return False

    # chunking to avoid creating huge number of tasks at once
    chunk_size = 1000 if len(port_list) > 2000 else len(port_list)

    if parallel and len(host_list) > 1:
        # run global parallel host scanning
        if ping:
            for h in host_list:
                up = tcp_ping(h, timeout_s=1.0)
                click.echo(f"\nNmap scan report for {h}")
                click.echo(f"Host is {'up' if up else 'down'}")
                results[h] = []
        else:
            # parallel host scanning uses scan_hosts_parallel (currently TCP only)
            results = asyncio.run(scanner.scan_hosts_parallel(host_list, port_list, open_only=False))
    else:
        for h in host_list:
            host_results: List[Dict] = []
            # host discovery only
            if ping:
                up = tcp_ping(h, timeout_s=1.0)
                click.echo(f"\nNmap scan report for {h}")
                click.echo(f"Host is {'up' if up else 'down'}")
                results[h] = []
                continue

            # for each chunk, run scan (TCP or UDP)
            for i in range(0, len(port_list), chunk_size):
                chunk = port_list[i:i+chunk_size]
                if getattr(scanner, 'udp_scan', False):
                    # run UDP scan
                    res_chunk = asyncio.run(scanner.scan_udp(h, chunk))
                else:
                    res_chunk = asyncio.run(scanner.scan(h, chunk, open_only=False))
                host_results.extend(res_chunk)

            results[h] = host_results

    elapsed = datetime.now() - start_time
    total_open = 0
    # Display results per host in nmap-like format
    for h, res in results.items():
        click.echo(f"\nNmap scan report for {h}")
        host_up = any(r.get('status') == 'open' for r in res) if res else False
        click.echo(f"Host is {'up' if host_up else 'down'}")
        # OS detection per-host (banner + TCP fingerprint)
        if scanner.os_detect:
            banners = [r.get('banner') for r in res if r.get('banner')]
            fp = None
            # try fingerprint using first open port or port 80
            try_port = None
            for r in res:
                if r.get('status') == 'open':
                    try_port = r.get('port')
                    break
            if try_port is None:
                try_port = 80
            # perform tcp fingerprint (scapy) if possible
            fp = asyncio.run(scanner._tcp_fingerprint(h, try_port)) if 'asyncio' in globals() else None
            guessed = scanner._guess_os_from_fingerprint(fp, banners)
            if guessed:
                os_map[h] = guessed
                click.echo(f"OS guess: {guessed}")
        click.echo("PORT\tSTATE\tSERVICE\tBANNER")
        if res:
            open_results = [r for r in res if r.get('status') == 'open']
            for r in sorted(open_results, key=lambda x: x['port']):
                banner = r.get('banner', '')
                svc = r.get('service', 'unknown')
                click.echo(f"{r['port']}/tcp\topen\t{svc}\t{banner}")
                # run NSE-like scripts on open ports if scripts available
                if scanner and getattr(scanner, 'nse_scripts', None):
                    s_names = scanner.nse_scripts
                    findings = run_scripts_for_port(s_names, h, r['port'], r)
                    if findings:
                        script_findings.setdefault(h, []).extend(findings)
            # CVE matching per-host from banners
            if run_cve:
                fingerprints = []
                for r in res:
                    b = r.get('banner')
                    parsed = scanner._parse_banner_for_software(b) if b else None
                    if parsed:
                        fingerprints.append(parsed)
                if fingerprints:
                    checker = CVEChecker()
                    matches = checker.check_multiple_versions(fingerprints)
                    cve_matches[h] = matches
                    # print critical matches if any
                    critical = checker.get_cves_by_severity(matches, 'Critical')
                    if critical:
                        click.echo(f"[*] Critical CVEs found for {h}: {len(critical)}")
            click.echo(f"\nScanned ports: {len(res)} | Open: {len(open_results)} | Closed: {len([r for r in res if r.get('status')=='closed'])} | Filtered: {len([r for r in res if r.get('status')=='filtered'])}")
            total_open += len(open_results)
        else:
            click.echo("(no ports scanned)")

    click.echo(f"\nNmap done: {len(host_list)} IP address(es) scanned in {elapsed}, {total_open} open port(s) found")

    # Save to file in requested format
    if output:
        data = {
            "targets": host_list,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "open": len(scanner.open_ports),
                "closed": len(scanner.closed_ports),
                "filtered": len(scanner.filtered_ports)
            },
            "results": results,
            "os": os_map,
            "cve_matches": cve_matches,
            "script_findings": script_findings
        }
        try:
            if out_format == 'json':
                with open(output, 'w') as f:
                    json.dump(data, f, indent=2)
            elif out_format == 'csv':
                import csv
                with open(output, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['host','port','status','service','banner'])
                    for h, res in results.items():
                        for r in res:
                            writer.writerow([h, r.get('port'), r.get('status'), r.get('service',''), r.get('banner','')])
            elif out_format == 'gnmap':
                with open(output, 'w') as f:
                    for h, res in results.items():
                        ports_str = []
                        for r in res:
                            ports_str.append(f"{r.get('port')}/{r.get('status')}/tcp//{r.get('service','')}//")
                        f.write(f"Host: {h} \tPorts: {','.join(ports_str)}\n")
            elif out_format == 'xml':
                from xml.etree.ElementTree import Element, SubElement, ElementTree
                root = Element('nmaprun')
                for h, res in results.items():
                    host_el = SubElement(root, 'host')
                    addr = SubElement(host_el, 'address')
                    addr.set('addr', h)
                    ports_el = SubElement(host_el, 'ports')
                    for r in res:
                        port_el = SubElement(ports_el, 'port')
                        port_el.set('portid', str(r.get('port')))
                        state = SubElement(port_el, 'state')
                        state.set('state', r.get('status'))
                        service = SubElement(port_el, 'service')
                        service.set('name', r.get('service',''))
                ElementTree(root).write(output, encoding='utf-8', xml_declaration=True)
            click.echo(f"\n[+] Results saved to {output} ({out_format})")
        except Exception as e:
            click.echo(f"[!] Could not write output file: {e}")


if __name__ == "__main__":
    scan_ports()
