"""
Open Redirect Finder - Detect open redirect vulnerabilities
"""
import asyncio
import aiohttp
import json
import click
from urllib.parse import urlencode, parse_qs, urlparse
from typing import List, Dict
import re


class OpenRedirectFinder:
    """Detect open redirect vulnerabilities"""
    
    # Common redirect parameters
    COMMON_PARAMS = [
        'url', 'redirect', 'return', 'returnurl', 'redirect_url', 'redirect_to',
        'next', 'from', 'origin', 'referer', 'destination', 'continue',
        'ret', 'target', 'page', 'goto', 'link', 'back', 'ref', 'forward'
    ]
    
    # Payloads to test
    PAYLOADS = [
        'https://google.com',
        'http://google.com',
        '//google.com',
        '///google.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'file:///etc/passwd',
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    async def test_redirect(self, session: aiohttp.ClientSession, 
                          url: str, param: str, payload: str) -> dict:
        """Test parameter for open redirect"""
        try:
            params = {param: payload}
            test_url = f"{url}?{urlencode(params)}"
            
            async with session.get(test_url, timeout=self.timeout, allow_redirects=False) as response:
                # Check redirect headers
                location = response.headers.get('Location', '')
                
                result = {
                    "parameter": param,
                    "payload": payload,
                    "status": response.status,
                    "redirects": False,
                    "location": location
                }
                
                # Check if it's a redirect
                if response.status in [301, 302, 303, 307, 308]:
                    result["redirects"] = True
                    
                    # Check if payload is in location
                    if payload in location or payload.split('//')[1] in location:
                        result["vulnerable"] = True
                    else:
                        result["vulnerable"] = False
                
                return result
        
        except Exception as e:
            return {
                "parameter": param,
                "payload": payload,
                "error": str(e)
            }
    
    def extract_parameters(self, html: str, url: str) -> List[str]:
        """Extract redirect parameters from HTML"""
        params = set()
        
        # Extract from onclick handlers
        onclick_matches = re.findall(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", html)
        for match in onclick_matches:
            parsed = parse_qs(urlparse(match).query)
            params.update(parsed.keys())
        
        # Extract from form action parameters
        form_matches = re.findall(r'<form[^>]*action="([^"]*)"', html)
        for match in form_matches:
            parsed = parse_qs(urlparse(match).query)
            params.update(parsed.keys())
        
        return list(params)
    
    async def scan(self, url: str, params: List[str] = None) -> List[dict]:
        """Scan for open redirect"""
        connector = aiohttp.TCPConnector(limit_per_host=10)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            # Use provided params or common ones
            params_to_test = params if params else self.COMMON_PARAMS
            
            results = []
            
            for param in params_to_test:
                for payload in self.PAYLOADS:
                    result = await self.test_redirect(session, url, param, payload)
                    results.append(result)
                    
                    if result.get("vulnerable"):
                        click.echo(f"[!] Found redirect: {param} -> {payload}")
            
            return results


@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--params', default=None, help='Parameters to test (comma-separated), default: common params')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--output', default=None, help='Save results to JSON')
def find_redirects(url, params, timeout, output):
    """Find open redirect vulnerabilities"""
    
    param_list = [p.strip() for p in params.split(',')] if params else None
    
    finder = OpenRedirectFinder(timeout=timeout)
    
    click.echo(f"[*] Scanning for open redirects: {url}")
    if param_list:
        click.echo(f"[*] Testing parameters: {param_list}")
    else:
        click.echo(f"[*] Using {len(finder.COMMON_PARAMS)} common redirect parameters")
    
    results = asyncio.run(finder.scan(url, param_list))
    
    # Filter redirects and vulnerable
    redirects = [r for r in results if r.get("redirects")]
    vulnerable = [r for r in results if r.get("vulnerable")]
    
    click.echo(f"\n[+] Results:")
    click.echo(f"    Total tests: {len(results)}")
    click.echo(f"    Redirects found: {len(redirects)}")
    click.echo(f"    Vulnerable: {len(vulnerable)}")
    
    if vulnerable:
        click.echo(f"\n[!] OPEN REDIRECT VULNERABILITIES:")
        for result in vulnerable:
            click.echo(f"    Parameter: {result['parameter']}")
            click.echo(f"    Payload: {result['payload']}")
            click.echo(f"    Redirects to: {result['location']}")
            click.echo()
    elif redirects:
        click.echo(f"\n[*] Redirects detected (may be safe):")
        for result in redirects[:5]:
            click.echo(f"    {result['parameter']}: {result['location']}")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "url": url,
                "vulnerable": len(vulnerable),
                "redirects": len(redirects),
                "results": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    find_redirects()
