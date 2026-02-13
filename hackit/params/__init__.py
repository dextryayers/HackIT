import click
import asyncio
import json
from hackit.params.go_bridge import GoEngine
from hackit.ui import display_tool_banner

@click.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--params', required=True, help='Parameters to fuzz (comma separated)')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST']), help='HTTP Method')
@click.option('--payloads', help='Custom payloads file')
@click.option('--threads', default=10, help='Number of concurrent threads')
@click.option('--timeout', default=10, help='Request timeout')
@click.option('--output', help='Save results to JSON file')
def fuzz_params(url, params, method, payloads, threads, timeout, output):
    """HTTP Parameter Fuzzer & Reflection Analyzer"""
    display_tool_banner('WEB FUZZER') 
    
    # ParamFuzzer Go Engine Integration
    engine = GoEngine()
    
    # Parse params string to list if needed for Python logic, 
    # but Go engine takes comma separated string or handle list in bridge.
    # Bridge expects list or string. Let's pass the raw string if possible or list.
    # Looking at go_bridge.py: "-params", ",".join(params) if isinstance(params, list) else params
    # The input 'params' is a string from click option.
    
    engine.run(
        url=url,
        params=params,
        method=method,
        payloads=payloads,
        threads=threads,
        timeout=timeout,
        output=output
    )
