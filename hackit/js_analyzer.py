"""
JS File Analyzer - Extract endpoints and secrets from JavaScript
"""
import asyncio
import aiohttp
import json
import click
import re
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse


class JSAnalyzer:
    """Analyze JavaScript files for endpoints and secrets"""
    
    # Patterns for finding secrets
    SECRET_PATTERNS = {
        "api_keys": r"['\"]([a-zA-Z0-9]{20,40})['\"]",
        "aws_keys": r"AKIA[0-9A-Z]{16}",
        "private_keys": r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----",
        "tokens": r"(bearer|token|authorization)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9._\-]{20,})",
        "urls": r"(https?://[^\s'\"\)<>]+)",
        "endpoints": r"(['\"]\/[\w\-\/]+['\"]|['\"]\/[a-zA-Z0-9\-_\/]+['\"])",
        "secrets": r"(password|secret|api_key|apikey)['\"]?\s*[:=]\s*['\"]?([^\s'\",};]+)",
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.endpoints: Set[str] = set()
        self.secrets: Dict[str, List[str]] = {}
    
    async def fetch_js(self, session: aiohttp.ClientSession, url: str) -> str:
        """Fetch JavaScript file"""
        try:
            async with session.get(url, timeout=self.timeout) as response:
                return await response.text()
        except Exception as e:
            click.echo(f"[!] Error fetching {url}: {e}")
            return ""
    
    def extract_endpoints(self, js_content: str, base_url: str) -> List[str]:
        """Extract API endpoints from JS"""
        endpoints = []
        
        # Pattern for common API calls
        patterns = [
            r'["\'](/[^"\']+)["\']',  # String endpoints
            r'\.get\(["\']([^"\']+)',  # .get()
            r'\.post\(["\']([^"\']+)',  # .post()
            r'\.put\(["\']([^"\']+)',  # .put()
            r'\.delete\(["\']([^"\']+)',  # .delete()
            r'fetch\(["\']([^"\']+)',  # fetch()
            r'axios\.(get|post)\(["\']([^"\']+)',  # axios calls
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Get the last group (endpoint)
                endpoint = match.groups()[-1]
                if endpoint.startswith('/') and not endpoint.endswith('}'):
                    endpoints.append(endpoint)
        
        return list(set(endpoints))
    
    def extract_secrets(self, js_content: str) -> Dict[str, List[str]]:
        """Extract potential secrets from JS"""
        secrets = {}
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            found = []
            for match in matches:
                value = match.group(0)
                if len(value) > 10 and not value.startswith('/'):  # Filter noise
                    found.append(value[:50])  # Truncate for safety
            
            if found:
                secrets[secret_type] = list(set(found))[:10]  # Top 10
        
        return secrets
    
    async def crawl_and_analyze(self, base_url: str, max_files: int = 50) -> dict:
        """Crawl and analyze JS files from a URL"""
        connector = aiohttp.TCPConnector(limit_per_host=10)
        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            # Fetch main page
            try:
                async with session.get(base_url, timeout=self.timeout) as response:
                    html = await response.text()
            except Exception:
                return {"error": "Failed to fetch base URL"}
            
            # Extract JS files
            js_files = set()
            
            # Find script tags
            script_matches = re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html)
            for match in script_matches:
                src = match.group(1)
                if not src.startswith('http'):
                    src = urljoin(base_url, src)
                js_files.add(src)
            
            click.echo(f"[*] Found {len(js_files)} JS files")
            
            all_endpoints = set()
            all_secrets = {}
            
            for i, js_url in enumerate(list(js_files)[:max_files]):
                click.echo(f"[*] Analyzing [{i+1}/{min(len(js_files), max_files)}]: {urlparse(js_url).path}")
                
                js_content = await self.fetch_js(session, js_url)
                
                if js_content:
                    # Extract endpoints
                    endpoints = self.extract_endpoints(js_content, base_url)
                    all_endpoints.update(endpoints)
                    
                    # Extract secrets
                    secrets = self.extract_secrets(js_content)
                    for secret_type, values in secrets.items():
                        if secret_type not in all_secrets:
                            all_secrets[secret_type] = []
                        all_secrets[secret_type].extend(values)
            
            return {
                "base_url": base_url,
                "js_files_found": len(js_files),
                "endpoints": sorted(list(all_endpoints)),
                "potential_secrets": all_secrets
            }


@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--max-files', default=50, type=int, help='Max JS files to analyze')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--output', default=None, help='Save results to JSON')
def analyze_js(url, max_files, timeout, output):
    """Analyze JavaScript files for endpoints and secrets"""
    
    analyzer = JSAnalyzer(timeout=timeout)
    
    click.echo(f"[*] Analyzing JavaScript files from: {url}")
    click.echo(f"[*] Max files to analyze: {max_files}")
    
    results = asyncio.run(analyzer.crawl_and_analyze(url, max_files))
    
    if "error" in results:
        click.echo(f"[!] Error: {results['error']}")
        return
    
    click.echo(f"\n[+] Results:")
    click.echo(f"    JS files found: {results['js_files_found']}")
    click.echo(f"    Endpoints extracted: {len(results['endpoints'])}")
    
    if results['endpoints']:
        click.echo(f"\n[+] API Endpoints:")
        for endpoint in sorted(results['endpoints'])[:20]:
            click.echo(f"    - {endpoint}")
        if len(results['endpoints']) > 20:
            click.echo(f"    ... and {len(results['endpoints']) - 20} more")
    
    if results['potential_secrets']:
        click.echo(f"\n[!] Potential Secrets Found:")
        for secret_type, values in results['potential_secrets'].items():
            click.echo(f"    {secret_type.upper()}:")
            for value in values[:3]:
                click.echo(f"        - {value}")
            if len(values) > 3:
                click.echo(f"        ... and {len(values) - 3} more")
    
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    analyze_js()
