"""
IP Range Scanner - CIDR scanning with alive host detection
"""
import asyncio
import ipaddress
import subprocess
import json
import click
from typing import List, Set


class IPRangeScanner:
    """Scan IP ranges and detect alive hosts"""
    
    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.alive_hosts: Set[str] = set()
    
    async def ping_host(self, ip: str) -> tuple:
        """Async ping check"""
        try:
            # Use ping with timeout
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', str(int(self.timeout * 1000)), str(ip),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            returncode = await proc.wait()
            if returncode == 0:
                self.alive_hosts.add(str(ip))
                return str(ip), True
            return str(ip), False
        except Exception:
            return str(ip), False
    
    async def scan_range(self, cidr: str) -> List[dict]:
        """Scan CIDR range"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts()) if network.num_addresses > 2 else list(network)
            
            click.echo(f"[*] Scanning {len(hosts)} hosts in {cidr}")
            
            tasks = [self.ping_host(str(host)) for host in hosts]
            results = await asyncio.gather(*tasks)
            
            found = [
                {"ip": ip, "status": "alive"}
                for ip, alive in results if alive
            ]
            return found
        except Exception as e:
            click.echo(f"[!] Error: {e}")
            return []


@click.command()
@click.option('--cidr', required=True, help='CIDR range (e.g., 192.168.1.0/24)')
@click.option('--timeout', default=2, type=int, help='Ping timeout in seconds')
@click.option('--output', default=None, help='Save results to JSON')
def scan_range(cidr, timeout, output):
    """Scan IP range and detect alive hosts"""
    
    scanner = IPRangeScanner(timeout=timeout)
    results = asyncio.run(scanner.scan_range(cidr))
    
    click.echo(f"\n[+] Found {len(results)} alive hosts:\n")
    for result in results:
        click.echo(f"    {result['ip']}")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "range": cidr,
                "alive": len(results),
                "hosts": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    scan_range()
