import sys
import os
import shlex
try:
    import readline
except ImportError:
    try:
        from pyreadline3 import Readline
        readline = Readline()
    except ImportError:
        readline = None
from typing import List

# Import click to help with command execution
import click

# Import UI elements
import socket
from datetime import datetime
from hackit.ui import _colored, B_CYAN, B_GREEN, B_MAGENTA, B_BLUE, WHITE, YELLOW, DIM, display_banner

class HackItConsole:
    """
    Interactive console for the HackIt framework.
    Provides a Metasploit-like experience.
    """
    
    def __init__(self, cli_group):
        self.cli_group = cli_group
        self.history_file = os.path.join(os.path.expanduser("~"), ".hackit_history")
        self.current_context = "main"
        self.user = "aniipID"
        self.hostname = "hackit"
        
        # Setup history
        if readline:
            try:
                if os.path.exists(self.history_file):
                    readline.read_history_file(self.history_file)
                readline.set_history_length(1000)
            except Exception:
                pass
                
            # Setup autocompletion
            readline.set_completer(self.completer)
            if hasattr(readline, '__doc__') and readline.__doc__ and 'libedit' in readline.__doc__: # for macOS
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")

    def completer(self, text: str, state: int) -> str:
        """Tab completion for console commands."""
        # Get all top-level command names from the click group
        commands = list(self.cli_group.commands.keys())
        commands.extend(["exit", "quit", "help", "clear", "banner", "back"])
        
        options = [i for i in commands if i.startswith(text)]
        if state < len(options):
            return options[state]
        else:
            return None

    def start(self):
        """Start the interactive loop."""
        # Show banner once on start
        os.environ['HACKIT_NO_BANNER'] = '1' # Prevent double banner from cli() calls
        display_banner()
        
        print(_colored("\n  [*] Welcome to the HackIt Interactive Console", DIM))
        print(_colored("  [*] Type 'help' for commands or 'exit' to quit\n", DIM))

        while True:
            try:
                # Kali Linux Style Prompt
                now = datetime.now().strftime("%H:%M:%S")
                
                # Line 1: ┌──(user㉿host)-[time]-[context]
                l1_prefix = _colored("┌──(", B_BLUE)
                l1_user = _colored(self.user, B_BLUE)
                l1_sep = _colored("㉿", B_BLUE)
                l1_host = _colored(self.hostname, B_BLUE)
                l1_mid = _colored(")-[", B_BLUE)
                l1_time = _colored(now, WHITE)
                l1_mid2 = _colored("]-[", B_BLUE)
                l1_ctx = _colored(self.current_context, B_MAGENTA)
                l1_end = _colored("]", B_BLUE)
                
                line1 = f"{l1_prefix}{l1_user}{l1_sep}{l1_host}{l1_mid}{l1_time}{l1_mid2}{l1_ctx}{l1_end}"
                
                # Line 2: └─$
                line2 = _colored("└─$ ", B_BLUE)
                
                prompt = f"{line1}\n{line2}"
                
                line = input(prompt).strip()
                if not line:
                    continue
                
                # Handle built-in console commands
                if line.lower() in ['exit', 'quit']:
                    self.save_history()
                    print(_colored("\n  [*] Shutdown sequence complete. Goodbye!\n", DIM))
                    break
                
                if line.lower() == 'clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                    # Also clear readline history if possible
                    if readline:
                        try:
                            readline.clear_history()
                            if os.path.exists(self.history_file):
                                os.remove(self.history_file)
                        except Exception:
                            pass
                    continue
                
                if line.lower() == 'banner':
                    display_banner()
                    continue
                
                if line.lower() == 'back':
                    self.current_context = "main"
                    continue

                # Parse and execute using click
                args = shlex.split(line)
                
                # Track context (module being used)
                if args[0] in ['web', 'ports', 'recon', 'vuln', 'ssl', 'util', 'dirfinder']:
                    self.current_context = args[0]
                elif args[0] == 'main':
                    self.current_context = 'main'
                
                # Auto-prefix context if in a group and command is not top-level
                final_args = args
                if self.current_context != "main" and args[0] not in self.cli_group.commands:
                    group = self.cli_group.commands.get(self.current_context)
                    if group and hasattr(group, 'commands') and args[0] in group.commands:
                        final_args = [self.current_context] + args

                # Special case for help
                if args[0] == 'help':
                    with click.Context(self.cli_group) as ctx:
                        click.echo(self.cli_group.get_help(ctx))
                    continue

                # Execute the command
                try:
                    # We invoke the cli group with the provided arguments
                    # standalone_mode=False allows us to catch exceptions here
                    self.cli_group.main(args=final_args, standalone_mode=False)
                except click.exceptions.UsageError as e:
                    # Catch cases like "No such command" or missing parameters
                    if "No such command" in str(e):
                        print(_colored(f"  [!] Unknown command: {args[0]}", "red"))
                    elif "Missing parameter" in str(e) or "Missing option" in str(e):
                        print(_colored(f"  [!] {e}", YELLOW))
                        print(_colored(f"  [*] Tip: Use '{args[0]} --help' to see required arguments\n", DIM))
                        
                        # Automatically show help for the command that failed
                        try:
                            # Use final_args to get the correct subcommand help
                            ctx_args = final_args + ["--help"]
                            self.cli_group.main(args=ctx_args, standalone_mode=False)
                        except: pass
                    else:
                        print(_colored(f"  [!] Usage error: {e}", "red"))
                except click.exceptions.Exit:
                    # Click uses Exit for normal termination (like --help)
                    pass
                except Exception as e:
                    print(_colored(f"  [!] Execution error: {e}", "red"))

            except (EOFError, KeyboardInterrupt):
                print()
                self.save_history()
                break
            except Exception as e:
                print(_colored(f"  [!] Console error: {e}", "red"))

    def save_history(self):
        """Save command history to file."""
        if readline:
            try:
                readline.write_history_file(self.history_file)
            except Exception:
                pass

def start_console(cli_group):
    """Entry point for the console."""
    console = HackItConsole(cli_group)
    console.start()
