import click
import json
import os
import sys

try:
    from pygments import highlight
    from pygments.lexers import JsonLexer
    from pygments.formatters import TerminalFormatter
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False

from .go_bridge import run_go_engine

# --- AESTHETIC COLORS ---
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
B_RED = '\033[1;91m'
B_CYAN = '\033[1;96m'
RESET = '\033[0m'

def _colored(text, color_code):
    return f"{color_code}{text}{RESET}"

# Aggressive tactical flags removed for safety.
# The tool operates purely in a safe, passive reconnaissance mode.


@click.group(invoke_without_command=True)
@click.pass_context
def hunter_cli(ctx):
    if ctx.invoked_subcommand is None:
        _show_banner_internal()
        print(ctx.get_help())

def _show_banner_internal():
    art = r"""
       _____         _     _    _             _            
      |_   _|__  ___| |__ | |  | |_   _ _ __ | |_ ___ _ __ 
        | |/ _ \/ __| '_ \| |__| | | | | '_ \| __/ _ \ '__|
        | |  __/ (__| | | |  __  | |_| | | | | ||  __/ |   
        |_|\___|\___|_| |_|_|  |_|\__,_|_| |_|\__\___|_|   
    """
    print(f"{CYAN}{art}{RESET}{BLUE}")
    print("    [+] Professional Defensive Asset Mapping & Intelligence [+]")
    print(f"{RESET}")
    print(f"""{MAGENTA} "Cybersecurity is a shared responsibility, and it boils down to this: 
     In cybersecurity, the more systems we secure, the more secure we all are."{RESET}""")

@hunter_cli.command(name='banner')
def banner_command():
    """Show the Tech Hunter banner."""
    _show_banner_internal()

# --- CORE RECONNAISSANCE LOGIC (RAW FUNCTION) ---
def run_tactical_engine(target):
    """Pure logic to trigger the Go/Rust/C++ engines."""
    
    # Trigger Bridge to Go/Rust/C++ Engine (Safely)
    result = run_go_engine(target)
    
    if isinstance(result, dict) and "error" in result:
        click.secho(f"[!] Engine Error: {result['error']}", fg='red', bold=True)
        return

    # Display Intelligence Map
    click.secho("\n[!] INTELLIGENCE MAP GENERATED:", fg='green', bold=True)
    
    if isinstance(result, str):
        print(result)
    else:
        formatted_json = json.dumps(result, indent=2)
        if PYGMENTS_AVAILABLE:
            print(highlight(formatted_json, JsonLexer(), TerminalFormatter()))
        else:
            print(formatted_json)

# --- FRAMEWORK INTEGRATION CALLBACK ---
@click.option('-t', '--target', required=False, help=_colored('Primary target (domain or IP)', BLUE))
def detect_callback(target):
    """Industrial-grade Hybrid Reconnaissance Engine"""
    _show_banner_internal()
    if not target:
        target = input(f"{YELLOW}Input Target: {RESET}").strip()
    run_tactical_engine(target)

# Create the command for framework
detect = click.command(name='tech-hunter')(detect_callback)

# --- STANDALONE CLI CALLBACK ---
@click.option('-t', '--target', required=False, help=_colored('Primary target (domain or IP)', BLUE))
def standalone_callback(target):
    """Comprehensive Infrastructure Audit"""
    _show_banner_internal()
    if not target:
        target = input(f"{YELLOW}Input Target: {RESET}").strip()
    run_tactical_engine(target)

# Register with hunter_cli
hunter_cli.add_command(click.command(name='scan')(standalone_callback))

if __name__ == '__main__':
    # If run directly with no args, default to standalone with prompt
    if len(sys.argv) == 1:
        _show_banner_internal()
        target = input(f"{YELLOW}Input Target: {RESET}").strip()
        run_tactical_engine(target)
    else:
        hunter_cli()
