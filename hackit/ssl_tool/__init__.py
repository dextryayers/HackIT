import click
import json
from hackit.ssl_tool.go_bridge import GoEngine
from hackit.ui import display_tool_banner

@click.command()
@click.option('--host', required=True, help='Target Host (e.g. google.com)')
@click.option('--port', default=443, type=int, help='Target Port')
@click.option('--timeout', default=10, type=int, help='Timeout in seconds')
@click.option('--output', help='Save results to JSON file')
def scan_ssl(host, port, timeout, output):
    """Deep SSL/TLS Analyzer with Grading"""
    display_tool_banner('SSL/TLS ANALYZER')
    
    # SSL Tool Go Engine Integration
    engine = GoEngine()
    
    engine.run(
        host=host,
        port=port,
        timeout=timeout,
        output=output
    )
