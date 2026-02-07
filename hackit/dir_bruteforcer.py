"""
Directory Bruteforce Tool - Recursive directory scanning with filters
"""
import asyncio
import aiohttp
import json
import click
import ssl as sslmod
from hackit.config import get_proxy, verify_ssl_default
from hackit.logger import get_logger

logger = get_logger(__name__)
from typing import List, Set
from urllib.parse import urljoin


class DirectoryBruteforcer:
    """Async directory scanner with recursion support"""
    
    def __init__(self, timeout: int = 10, delay: float = 0, proxy: str = None):
        self.timeout = timeout
        self.delay = delay
        self.proxy = proxy
        self.found: Set[str] = set()
        self.status_codes = {}
    
    async def check_path(self, session: aiohttp.ClientSession, url: str, status_filter: List[int] = None) -> dict:
        """Check if directory exists"""
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            proxy = self.proxy or get_proxy()
            verify = verify_ssl_default()
            ssl_param = None if verify else False

            try:
                async with session.get(url, timeout=self.timeout, allow_redirects=False, proxy=proxy, ssl=ssl_param) as response:
                    status = response.status

                    if status_filter is None or status in status_filter:
                        self.found.add(url)
                        return {"url": url, "status": status}
                    return None
            except Exception as e:
                logger.debug('dir_bruteforcer: request failed for %s: %s', url, e)
                return None
        except Exception:
            return None
    
    async def scan(self, base_url: str, wordlist: List[str], status_filter: List[int] = None,
                   extensions: List[str] = None, max_workers: int = 50) -> List[dict]:
        """Scan directories"""
        
        if status_filter is None:
            status_filter = [200, 204, 301, 302, 307, 401, 403]
        
        connector = aiohttp.TCPConnector(limit_per_host=max_workers)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_obj,
            trust_env=True
        ) as session:
            tasks = []
            
            for word in wordlist:
                # Add base path
                url = urljoin(base_url, word)
                tasks.append(self.check_path(session, url, status_filter))
                
                # Add extensions
                if extensions:
                    for ext in extensions:
                        url = urljoin(base_url, f"{word}{ext}")
                        tasks.append(self.check_path(session, url, status_filter))
            
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]
    
    async def recursive_scan(self, base_url: str, wordlist: List[str], 
                           max_depth: int = 2, depth: int = 0,
                           status_filter: List[int] = None) -> List[dict]:
        """Recursive directory scanning"""
        
        if depth >= max_depth:
            return []
        
        if status_filter is None:
            status_filter = [200, 301, 302]
        
        results = await self.scan(base_url, wordlist, status_filter, max_workers=20)
        all_results = results.copy()
        
        # Recurse into found directories
        for result in results:
            if result['status'] in [301, 302, 200]:
                found_url = result['url']
                if found_url.endswith('/'):
                    click.echo(f"[*] Recursing into {found_url}")
                    sub_results = await self.recursive_scan(
                        found_url, wordlist, max_depth, depth + 1, status_filter
                    )
                    all_results.extend(sub_results)
        
        return all_results


@click.command()
@click.option('--url', required=True, help='Base URL (e.g., http://example.com/)')
@click.option('--wordlist', required=True, type=click.File('r'), help='Wordlist file')
@click.option('--extensions', default=None, help='File extensions (e.g., .php,.html,.txt)')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--delay', default=0, type=float, help='Delay between requests (seconds)')
@click.option('--recursive', is_flag=True, help='Enable recursive scanning')
@click.option('--max-depth', default=2, type=int, help='Max recursion depth')
@click.option('--status-codes', default='200,301,302,401,403', help='Status codes to report')
@click.option('--threads', default=50, type=int, help='Number of concurrent requests')
@click.option('--proxy', default=None, help='Proxy URL (e.g., http://127.0.0.1:8080)')
@click.option('--output', default=None, help='Save results to JSON')
def bruteforce_dirs(url, wordlist, extensions, timeout, delay, recursive, max_depth, 
                    status_codes, threads, proxy, output):
    """Directory and file bruteforcer"""
    
    words = [line.strip() for line in wordlist.readlines() if line.strip()]
    status_filter = [int(s.strip()) for s in status_codes.split(',')]
    exts = extensions.split(',') if extensions else None
    
    bruteforcer = DirectoryBruteforcer(timeout=timeout, delay=delay, proxy=proxy)
    
    click.echo(f"[*] Scanning {url}")
    click.echo(f"[*] Wordlist: {len(words)} entries")
    click.echo(f"[*] Status codes: {status_filter}")
    click.echo(f"[*] Threads: {threads}")
    
    if recursive:
        results = asyncio.run(
            bruteforcer.recursive_scan(url, words, max_depth, status_filter=status_filter)
        )
    else:
        results = asyncio.run(
            bruteforcer.scan(url, words, status_filter=status_filter, 
                           extensions=exts, max_workers=threads)
        )
    
    click.echo(f"\n[+] Found {len(results)} paths:\n")
    for result in sorted(results, key=lambda x: x['url']):
        status_color = '✓' if result['status'] == 200 else '*'
        click.echo(f"    [{status_color}] {result['url']} ({result['status']})")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "url": url,
                "total": len(results),
                "results": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    bruteforce_dirs()
