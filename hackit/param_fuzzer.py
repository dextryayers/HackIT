"""
HTTP Parameter Fuzzer - GET/POST parameter fuzzing with reflection detection
"""
import asyncio
import aiohttp
import json
import click
from urllib.parse import urlencode, parse_qs, urlparse, urljoin
from typing import List, Dict
import difflib


class ParameterFuzzer:
    """Fuzz HTTP parameters and detect reflection"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = []
    
    async def fuzz_get(self, session: aiohttp.ClientSession, url: str, 
                       param_name: str, payloads: List[str]) -> List[dict]:
        """Fuzz GET parameters"""
        results = []
        
        for payload in payloads:
            try:
                params = {param_name: payload}
                async with session.get(url, params=params, timeout=self.timeout) as response:
                    content = await response.text()
                    
                    # Check for reflection
                    is_reflected = payload.lower() in content.lower()
                    
                    results.append({
                        "method": "GET",
                        "param": param_name,
                        "payload": payload,
                        "status": response.status,
                        "reflected": is_reflected,
                        "content_length": len(content)
                    })
            except Exception as e:
                results.append({
                    "method": "GET",
                    "param": param_name,
                    "payload": payload,
                    "error": str(e)
                })
        
        return results
    
    async def fuzz_post(self, session: aiohttp.ClientSession, url: str,
                        param_name: str, payloads: List[str]) -> List[dict]:
        """Fuzz POST parameters"""
        results = []
        
        for payload in payloads:
            try:
                data = {param_name: payload}
                async with session.post(url, data=data, timeout=self.timeout) as response:
                    content = await response.text()
                    
                    # Check for reflection
                    is_reflected = payload.lower() in content.lower()
                    
                    results.append({
                        "method": "POST",
                        "param": param_name,
                        "payload": payload,
                        "status": response.status,
                        "reflected": is_reflected,
                        "content_length": len(content)
                    })
            except Exception as e:
                results.append({
                    "method": "POST",
                    "param": param_name,
                    "payload": payload,
                    "error": str(e)
                })
        
        return results
    
    def detect_length_diff(self, results: List[dict]) -> List[dict]:
        """Detect significant response length differences"""
        if not results:
            return []
        
        base_length = results[0]['content_length']
        anomalies = []
        
        for result in results[1:]:
            diff = abs(result['content_length'] - base_length)
            diff_percent = (diff / base_length * 100) if base_length > 0 else 0
            
            if diff_percent > 10:  # 10% difference threshold
                result['length_diff'] = diff
                result['diff_percent'] = diff_percent
                anomalies.append(result)
        
        return anomalies


@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--method', type=click.Choice(['GET', 'POST', 'BOTH']), default='GET', help='HTTP method')
@click.option('--params', required=True, help='Parameters to fuzz (comma-separated)')
@click.option('--payloads', required=True, type=click.File('r'), help='Payloads file')
@click.option('--timeout', default=10, type=int, help='Request timeout')
@click.option('--output', default=None, help='Save results to JSON')
def fuzz_params(url, method, params, payloads, timeout, output):
    """Fuzz HTTP parameters and detect reflection"""
    
    param_list = [p.strip() for p in params.split(',')]
    payload_list = [line.strip() for line in payloads.readlines() if line.strip()]
    
    fuzzer = ParameterFuzzer(timeout=timeout)
    
    click.echo(f"[*] Fuzzing {url}")
    click.echo(f"[*] Method: {method}")
    click.echo(f"[*] Parameters: {param_list}")
    click.echo(f"[*] Payloads: {len(payload_list)}")
    
    async def run_fuzz():
        connector = aiohttp.TCPConnector(limit_per_host=10)
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj) as session:
            all_results = []
            
            for param in param_list:
                if method in ['GET', 'BOTH']:
                    click.echo(f"[*] Fuzzing GET parameter: {param}")
                    get_results = await fuzzer.fuzz_get(session, url, param, payload_list)
                    all_results.extend(get_results)
                
                if method in ['POST', 'BOTH']:
                    click.echo(f"[*] Fuzzing POST parameter: {param}")
                    post_results = await fuzzer.fuzz_post(session, url, param, payload_list)
                    all_results.extend(post_results)
            
            return all_results
    
    results = asyncio.run(run_fuzz())
    
    # Find reflected payloads
    reflected = [r for r in results if r.get('reflected')]
    
    click.echo(f"\n[+] Results:")
    click.echo(f"    Total requests: {len(results)}")
    click.echo(f"    Reflected payloads: {len(reflected)}")
    
    if reflected:
        click.echo(f"\n[!] Reflected Payloads:")
        for r in reflected:
            click.echo(f"    [{r['method']}] {r['param']} = {r['payload']}")
    
    # Detect anomalies
    anomalies = fuzzer.detect_length_diff(results)
    if anomalies:
        click.echo(f"\n[!] Length Anomalies Detected:")
        for a in anomalies[:5]:  # Show top 5
            click.echo(f"    {a['method']} {a['param']} (+{a['diff_percent']:.1f}%)")
    
    if output:
        with open(output, 'w') as f:
            json.dump({
                "url": url,
                "total": len(results),
                "reflected": len(reflected),
                "anomalies": len(anomalies),
                "results": results
            }, f, indent=2)
        click.echo(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    fuzz_params()
