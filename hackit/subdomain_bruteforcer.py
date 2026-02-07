"""
Subdomain Brute Forcer - DNS enumeration with wildcard detection
"""
import asyncio
import dns.resolver
import dns.reversename
from typing import List, Set
import click
import json


class SubdomainBruteForcer:
    """DNS subdomain enumeration with async"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.found_domains: Set[str] = set()
    
    async def resolve(self, domain: str) -> tuple:
        """Async DNS resolution"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self.resolver.resolve, domain, 'A'
            )
            ips = [str(rdata) for rdata in result]
            return domain, ips
        except Exception:
            return domain, None
    
    async def brute_force(self, domain: str, wordlist: List[str]) -> List[dict]:
        """Brute force subdomains"""
        tasks = []
        for word in wordlist:
            subdomain = f"{word}.{domain}"
            tasks.append(self.resolve(subdomain))
        
        results = await asyncio.gather(*tasks)
        found = [
            {"subdomain": d, "ips": ips}
            for d, ips in results if ips is not None
        ]
        return found
    
    def check_wildcard(self, domain: str) -> bool:
        """Detect wildcard DNS"""
        try:
            # Try resolving a random subdomain
            random_sub = f"x{hash('wildcard')}.{domain}"
            result = self.resolver.resolve(random_sub, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
            return False


@click.command()
@click.option('--domain', required=True, help='Target domain')
@click.option('--wordlist', required=True, type=click.File('r'), help='Wordlist file')
@click.option('--timeout', default=5, type=int, help='DNS timeout in seconds')
@click.option('--check-wildcard', is_flag=True, help='Check for wildcard DNS')
@click.option('--output', default=None, help='Save results to JSON')
def brute_subdomains(domain, wordlist, timeout, check_wildcard, output):
    """DNS subdomain brute forcer"""
    
    words = [line.strip() for line in wordlist.readlines() if line.strip()]
    
    brute = SubdomainBruteForcer(timeout=timeout)
    
    click.echo(f"[*] Bruteforcing subdomains for {domain}")
    click.echo(f"[*] Wordlist size: {len(words)}")
    
    if check_wildcard:
        click.echo(f"[*] Checking for wildcard DNS...")
        is_wildcard = brute.check_wildcard(domain)
        marker = '!' if is_wildcard else '+'
        result = 'YES' if is_wildcard else 'NO'
        click.echo(f"[{marker}] Wildcard DNS: {result}")
    
    # Run brute force
    results = asyncio.run(brute.brute_force(domain, words))
    
    click.echo(f"\n[+] Found {len(results)} subdomains:\n")
    for result in results:
        click.echo(f"    {result['subdomain']}")
        for ip in result['ips']:
            click.echo(f"        -> {ip}")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "domain": domain,
                "total": len(results),
                "subdomains": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    brute_subdomains()
