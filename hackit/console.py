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
from hackit.ui import (
    _colored, B_CYAN, B_GREEN, B_MAGENTA, B_BLUE, WHITE, YELLOW, DIM, display_banner,
    BG_BLUE, BG_CYAN, BG_GREEN, BG_MAGENTA, BG_YELLOW, BG_WHITE, BG_BLACK, RESET, BOLD
)

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

    def get_prompt(self):
        """Generate the prompt based on the selected theme."""
        from hackit.config import load_config
        cfg = load_config()
        theme = cfg.get("theme", "kali")
        user = cfg.get("user", "aniipID")
        hostname = cfg.get("hostname", "hackit")
        now = datetime.now().strftime("%H:%M:%S")
        
        # Debug: Print current theme being used
        # print(f"DEBUG: Active Theme is {theme}")
        
        if theme == "powerline":
            # Style 1: Segmented backgrounds (Powerline-like)
            #  (U+E0B0)
            sep = " \x1b[0m\x1b[34m\x1b[43m\ue0b0\x1b[0m"
            sep2 = " \x1b[0m\x1b[33m\ue0b0\x1b[0m"
            
            p1 = f"{BG_BLUE}{WHITE} \uf120 {user} {RESET}"
            p2 = f"{BG_YELLOW}\x1b[30m \uf07b {self.current_context} {RESET}"
            p3 = f"{BG_MAGENTA}{WHITE} \uf017 {now} {RESET}"
            
            # Simple version for non-nerd fonts
            s1 = f"{BG_BLUE}{WHITE} {user} {RESET}"
            s2 = f"{BG_CYAN}\x1b[30m {self.current_context} {RESET}"
            s3 = f"{BG_MAGENTA}{WHITE} {now} {RESET}"
            
            return f"{s1}{s2}{s3} \u276f "

        elif theme == "modern":
            # Style 2: Angled/Modern segments
            #  (U+E0B1)
            p1 = _colored(f"{user} ", B_CYAN)
            p2 = _colored("\u276f ", B_MAGENTA)
            p3 = _colored(f"{self.current_context} ", B_GREEN)
            p4 = _colored("\u276f ", B_MAGENTA)
            return f"{p1}{p2}{p3}{p4}"

        elif theme == "pill":
            # Style 3: Pill/Rounded segments
            p1 = _colored(f" ({user}) ", BG_BLUE + WHITE)
            p2 = _colored(f" ({self.current_context}) ", BG_GREEN + WHITE)
            p3 = _colored(f" [{now}] ", DIM)
            return f"{p1} {p2} {p3} \u279c "

        elif theme == "cyberpunk":
            # Cyberpunk: Neon, 1-line, geometric
            p_user = _colored(user, B_CYAN)
            p_sep = _colored(" ❯❯ ", B_MAGENTA)
            p_ctx = _colored(f"[{self.current_context}]", B_GREEN)
            return f"{p_user}{p_sep}{p_ctx} "
            
        elif theme == "minimalist":
            # Minimalist: Just text and a caret
            return _colored(f"hackit({self.current_context}) > ", DIM)
            
        elif theme == "retro":
            # Retro: Green on black, matrix style
            return _colored(f"{user}@{hostname}:{self.current_context}$ ", B_GREEN)
            
        elif theme == "gacor":
            # Gacor: Industrial, symbol heavy
            p_icon = _colored("🔥 ", YELLOW)
            p_user = _colored(f"[{user}@{hostname}]", B_MAGENTA)
            p_ctx = _colored(f" ⚙️  {self.current_context}", B_CYAN)
            p_end = _colored(" 🚀 ", B_GREEN)
            return f"{p_icon}{p_user}{p_ctx}{p_end}"
            
        else:
            # Kali Linux Style Prompt (Default)
            # Line 1: ┌──([user]㉿host)-[time]-[context]
            l1_prefix = _colored("┌──(", B_BLUE)
            l1_user = _colored(user, B_BLUE)
            l1_sep = _colored("㉿", B_BLUE)
            l1_host = _colored(hostname, B_BLUE)
            l1_mid = _colored(")-[", B_BLUE)
            l1_time = _colored(now, WHITE)
            l1_mid2 = _colored("]-[", B_BLUE)
            l1_ctx = _colored(self.current_context, B_MAGENTA)
            l1_end = _colored("]", B_BLUE)
            
            line1 = f"{l1_prefix}{l1_user}{l1_sep}{l1_host}{l1_mid}{l1_time}{l1_mid2}{l1_ctx}{l1_end}"
            
            # Line 2: └─$
            line2 = _colored("└─$ ", B_BLUE)
            
            return f"{line1}\n{line2}"

    def start(self):
        """Start the interactive loop."""
        # Show banner once on start
        os.environ['HACKIT_NO_BANNER'] = '1' # Prevent double banner from cli() calls
        display_banner()
        
        print(_colored("\n  [*] Welcome to the HackIt Interactive Console", B_CYAN, bold=True))
        print(_colored("  [*] Type 'run' to launch Web Intelligence Dashboard", B_GREEN))
        print(_colored("  [*] Type 'help' for commands or 'exit' to quit\n", DIM))

        while True:
            try:
                prompt = self.get_prompt()
                line = input(prompt).strip()
                if not line:
                    continue
                
                # Handle universal /AI commands
                from hackit.agent import handle_ai_command
                if handle_ai_command(line):
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
                    display_banner(force=True)
                    continue

                if line.lower() == 'whoami':
                    import getpass
                    import platform
                    user = getpass.getuser()
                    system = platform.system()
                    node = platform.node()
                    print(_colored("\n  [ USER IDENTITY ]", B_CYAN))
                    print(f"  • User     : " + _colored(user, B_GREEN))
                    print(f"  • Device   : " + _colored(node, B_GREEN))
                    print(f"  • Platform : " + _colored(system, YELLOW))
                    print()
                    continue

                if line.lower() in ['recon/osint', 'osint']:
                    self.current_context = "recon/osint"
                    from hackit.osint import start_osint_console
                    start_osint_console()
                    self.current_context = "main"
                    continue
                
                if line.lower() == 'back':
                    if '/' in self.current_context:
                        parts = self.current_context.split('/')
                        self.current_context = '/'.join(parts[:-1])
                    else:
                        self.current_context = "main"
                    continue

                # Parse and execute using click
                args = shlex.split(line)
                
                # Special Case: hackit [options] to set global state from within console
                if args[0] == 'hackit':
                    # This allows setting --proxy, --no-verify, etc. dynamically
                    try:
                        self.cli_group.main(args=args[1:], standalone_mode=False)
                        # The click group execution will update the environment variables
                        # in cli.py, which persist for the current process.
                        print(_colored("  [*] Global session configuration updated.", B_GREEN))
                    except Exception as e:
                        if not isinstance(e, click.exceptions.Exit):
                            print(_colored(f"  [!] Configuration error: {e}", "red"))
                    continue
                
                # Track context (module being used)
                # If command is a top-level group, set context
                if args[0] in ['web', 'ports', 'recon', 'vuln', 'ssl', 'util', 'dirfinder']:
                    if self.current_context == "main":
                        self.current_context = args[0]
                    elif args[0] not in self.current_context:
                        self.current_context = f"{self.current_context}/{args[0]}"
                
                # Check for subcommands to deepen context
                if self.current_context != "main":
                    parts = self.current_context.split('/')
                    # Get the click group for the last part of context
                    current_group = self.cli_group
                    for part in parts:
                        current_group = current_group.commands.get(part)
                        if not current_group: break
                    
                    if current_group and hasattr(current_group, 'commands'):
                        if args[0] in current_group.commands:
                            # It's a subcommand or sub-group - ALWAYS deepen context
                            if args[0] not in self.current_context.split('/'):
                                self.current_context = f"{self.current_context}/{args[0]}"
                
                elif args[0] == 'main':
                    self.current_context = 'main'
                
                # Auto-prefix context if in a group and command is not top-level
                final_args = args
                if self.current_context != "main" and args[0] not in self.cli_group.commands:
                    parts = self.current_context.split('/')
                    # Prepend context but avoid duplication if args[0] is part of context
                    if args[0] in parts:
                        idx = parts.index(args[0])
                        final_args = parts[:idx] + args
                    else:
                        final_args = parts + args

                # Special case for help (Context-Aware)
                if args[0] == 'help':
                    if self.current_context == "main":
                        with click.Context(self.cli_group) as ctx:
                            click.echo(self.cli_group.get_help(ctx))
                    else:
                        # Find the command object for the current context
                        parts = self.current_context.split('/')
                        target_cmd = self.cli_group
                        for p in parts:
                            target_cmd = target_cmd.commands.get(p)
                            if not target_cmd: break
                        
                        if target_cmd:
                            from hackit.ui import display_tool_banner
                            display_tool_banner(parts[-1])
                            with click.Context(target_cmd) as ctx:
                                click.echo(target_cmd.get_help(ctx))
                        else:
                            with click.Context(self.cli_group) as ctx:
                                click.echo(self.cli_group.get_help(ctx))
                    continue

                # Execute the command
                try:
                    self.cli_group.main(args=final_args, standalone_mode=False)
                except click.exceptions.UsageError as e:
                    if "No such command" in str(e):
                        from hackit.ui import RED
                        print(_colored(f"  [!] Unknown command: {args[0]}", RED))
                    elif "Missing parameter" in str(e) or "Missing option" in str(e):
                        print(_colored(f"  [!] {e}", YELLOW))
                        print(_colored(f"  [*] Tip: Use '{args[0]} --help' to see required arguments\n", DIM))
                        try:
                            ctx_args = final_args + ["--help"]
                            self.cli_group.main(args=ctx_args, standalone_mode=False)
                        except: pass
                    else:
                        from hackit.ui import RED
                        print(_colored(f"  [!] Usage error: {e}", RED))
                except click.exceptions.Exit:
                    pass
                except Exception as e:
                    from hackit.ui import RED
                    print(_colored(f"  [!] Execution error: {e}", RED))

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
