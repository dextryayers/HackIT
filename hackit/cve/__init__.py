import click
import json
from hackit.cve.go_bridge import GoEngine
from hackit.ui import display_tool_banner

@click.command()
@click.option('--software', required=True, help='Software name (e.g. wordpress)')
@click.option('--version', required=True, help='Version (e.g. 5.0.0)')
@click.option('--output', help='Save results to JSON file')
def check_cve(software, version, output):
    """CVE Vulnerability Checker"""
    display_tool_banner('CVE CHECKER')
    
    # CVE Checker Go Engine Integration
    engine = GoEngine()
    
    engine.run(
        software=software,
        version=version,
        output=output
    )
