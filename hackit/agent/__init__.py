import click
import requests
import json
import os
from hackit.ui import _colored, GREEN, RED, BLUE, YELLOW, DIM, B_CYAN, MAGENTA
from hackit.config import load_config

from hackit.agent.brain import AIHyperBrain

@click.group(invoke_without_command=True)
@click.pass_context
def agent(ctx):
    """HackIt AI Agent - Your Cybersecurity Companion"""
    from hackit.ui import display_tool_banner
    display_tool_banner('AI AGENT', force=True)
    
    if ctx.invoked_subcommand is None:
        # If no subcommand, check if keys are configured, then start chat
        from hackit.config import load_config
        cfg = load_config()
        if not any(cfg.get("ai_keys", {}).values()):
            click.echo(_colored("  Usage: agent <command> [options]", DIM))
            click.echo(_colored("  Try 'agent --help' for more information.\n", DIM))
            click.echo(_colored("  [!] Hint: Run 'agent setting' to configure AI providers.", YELLOW))
        else:
            start_interactive_chat()

def start_interactive_chat():
    """Starts the persistent AI chat session"""
    click.echo(_colored("\n  [!] ENTERING INTERACTIVE AI CHAT MODE", YELLOW))
    click.echo(_colored("  [!] Type 'help' to show available commands", DIM))
    click.echo(_colored("  [!] Type 'exit' or 'quit' to return to main menu.", DIM))
    click.echo(_colored("  [!] Use '/' prefix for specialized commands (e.g., /risk).", DIM))
    
    while True:
        try:
            # Use a simple prompt for better compatibility
            prompt_str = f" (hackit) {_colored('(agent)', B_CYAN)} ➜ "
            user_input = click.prompt(prompt_str, prompt_suffix="").strip()
            
            if user_input.lower() in ['exit', 'quit', 'back']:
                click.echo(_colored("\n  [*] Returning to main menu...", DIM))
                break
            
            # Command Interception (clear, setting, status, guide, help)
            clean_input = user_input.lower().strip()
            if clean_input in ['clear', 'setting', 'status', 'guide', 'help', '?', '/help']:
                from hackit.agent import clear, setting, status, guide, help
                cmd_map = {
                    'clear': clear, 'setting': setting, 'status': status, 
                    'guide': guide, 'help': help, '?': guide, '/help': guide
                }
                ctx = click.get_current_context()
                ctx.invoke(cmd_map[clean_input])
                continue
                
            if not user_input:
                continue
                
            # If it's a slash command, handle it, otherwise chat normally
            if user_input.startswith('/'):
                handle_ai_command(user_input)
            else:
                # Chat normally
                handle_ai_command("/" + user_input)
                
        except (KeyboardInterrupt, EOFError):
            click.echo(_colored("\n  [*] Returning to main menu...", DIM))
            break

@agent.command()
def help():
    """Show core commands and options for the AI Agent"""
    click.echo(_colored("\n  [ HACKIT AI AGENT - COMMANDS ]", B_CYAN))
    click.echo(_colored("  ------------------------------------------------", DIM))
    click.echo(f"  • {_colored('status', YELLOW):<12} : Check AI connectivity and active providers.")
    click.echo(f"  • {_colored('setting', YELLOW):<12} : Configure API keys and select AI models.")
    click.echo(f"  • {_colored('clear', YELLOW):<12} : Reset conversation history and clear context.")
    click.echo(f"  • {_colored('guide', YELLOW):<12} : Show full tactical guide for slash commands.")
    click.echo(f"  • {_colored('chat', YELLOW):<12} : Enter interactive AI chat mode.")
    click.echo(_colored("\n  [!] Usage: agent <command> or type them inside chat.", DIM))
    click.echo()

@agent.command()
def chat():
    """Start an interactive chat session with the AI Agent"""
    start_interactive_chat()

@agent.command()
@click.option('--provider', type=click.Choice(['gemini', 'groq', 'openai', 'claude', 'deepseek', 'openrouter']), help='Set AI provider')
@click.option('--key', help='Set API key (or leave empty for interactive prompt)')
def setting(provider, key):
    """Configure AI Agent settings and API keys"""
    from hackit.config import load_config, save_config
    cfg = load_config()
    
    if not provider:
        click.echo(_colored("\n  [ SELECT AI PROVIDER ]", B_CYAN))
        click.echo("  1. Gemini (Google)")
        click.echo("  2. Groq")
        click.echo("  3. OpenAI")
        click.echo("  4. Claude (Anthropic)")
        click.echo("  5. DeepSeek")
        click.echo("  6. OpenRouter")
        click.echo(_colored("  0. Back to Main", DIM))
        choice = click.prompt(_colored("\n  [?] Select provider (0-6)", YELLOW), type=int)
        
        if choice == 0:
            click.echo(_colored("\n  [*] Returning...", DIM))
            return
            
        providers = ['gemini', 'groq', 'openai', 'claude', 'deepseek', 'openrouter']
        if 1 <= choice <= len(providers):
            provider = providers[choice-1]
        else:
            click.echo(_colored("[!] Invalid choice.", RED))
            return

    if not key:
        key = click.prompt(_colored(f"  [?] Paste your {provider.upper()} API Key", YELLOW), hide_input=False)
    
    if provider and key:
        # Update the specific provider key in the dictionary
        if "ai_keys" not in cfg:
            cfg["ai_keys"] = {}
        
        cfg["ai_provider"] = provider
        cfg["ai_keys"][provider] = key
        
        if save_config(cfg):
            click.echo(_colored(f"\n  [+] SUCCESS: {provider.upper()} API Key saved permanently and privately!", GREEN))
        else:
            click.echo(_colored(f"\n  [!] FAILED: Could not write configuration file.", RED))
        
    # Re-load to verify state from disk
    cfg = load_config()
    # Show current settings
    click.echo(_colored("\n  [ AI AGENT STATUS ]", B_CYAN))
    click.echo(f"  • Active Provider : " + _colored(cfg.get('ai_provider', 'NONE').upper(), YELLOW))
    for p, k in cfg.get('ai_keys', {}).items():
        status = _colored("READY", GREEN) if k else _colored("NOT CONFIGURED", DIM)
        click.echo(f"  • {p:<15}: {status}")

@agent.command()
def status():
    """Check AI Agent connectivity and current settings"""
    from hackit.config import load_config
    cfg = load_config()
    click.echo(_colored("\n  [ HACKIT AI STATUS ]", B_CYAN))
    click.echo(f"  • Active Provider : " + _colored(cfg.get('ai_provider', 'NONE').upper(), YELLOW))
    click.echo(f"  • Config File     : " + _colored(os.path.join(os.path.expanduser('~'), '.hackit_config.json'), DIM))
    
    for p, k in cfg.get('ai_keys', {}).items():
        status = _colored("READY", GREEN) if k else _colored("NOT CONFIGURED", DIM)
        click.echo(f"  • {p:<15}: {status}")

@agent.command()
def clear():
    """Clear AI conversation history"""
    brain = AIHyperBrain()
    result = brain.clear_history()
    click.echo(f"\n  [+] {result}")

@agent.command()
def guide():
    """Show detailed usage guide for HackIt AI Agent"""
    from hackit.ui import B_CYAN, WHITE, GREEN, YELLOW, MAGENTA, DIM
    
    click.echo(_colored("\n  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓", B_CYAN))
    click.echo(_colored("  ┃          HACKIT AI AGENT - PROFESSIONAL USER GUIDE         ┃", B_CYAN))
    click.echo(_colored("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛", B_CYAN))
    
    click.echo(_colored("\n  [ 1. INITIAL SETUP ]", YELLOW))
    click.echo("  To start using the AI Hyper-Brain, you must configure at least one API key.")
    click.echo(_colored("  Command:", DIM) + _colored(" agent setting", GREEN))
    click.echo("  Supported Providers: Gemini, Groq, OpenAI, Claude, DeepSeek, OpenRouter.")
    
    click.echo(_colored("\n  [ 2. UNIVERSAL AI TRIGGER (/) ]", YELLOW))
    click.echo("  You can call the AI from ANY context (any tool or console) using the '/' prefix.")
    click.echo(_colored("  Example:", DIM) + _colored(" /how do I bypass a WAF for SQLi?", GREEN))
    
    click.echo(_colored("\n  [ 3. SPECIALIZED INTELLIGENCE COMMANDS ]", YELLOW))
    click.echo("  The Hyper-Brain supports over 40 specialized commands for surgical analysis.")
    
    click.echo(_colored("\n  [ CORE ]", B_CYAN))
    click.echo("  /halo      : Activate full intelligence mode (Senior Pentester persona).")
    click.echo("  /summary   : Brief summary of ports, subdomains, and vulnerabilities.")
    click.echo("  /explain   : Human-readable explanation of technical findings.")
    click.echo("  /report    : Generate a professional pentesting report structure.")

    click.echo(_colored("\n  [ ANALYSIS ]", B_CYAN))
    click.echo("  /insight   : Highlight core vulnerabilities and critical insights.")
    click.echo("  /risk      : Detailed risk assessment (CVSS, Impact, Exploitability).")
    click.echo("  /score     : Assign a security score (0-100) with justification.")
    click.echo("  /priority  : Identify high-value targets for immediate testing.")
    click.echo("  /anomaly   : Detect non-standard headers or system behaviors.")
    click.echo("  /pattern   : Identify recurring misconfigs or design flaws.")
    click.echo("  /logic     : Analyze business logic for race conditions or bypasses.")
    click.echo("  /behavior  : Analyze system behavior under stress or malformed input.")
    click.echo("  /context   : Evaluate threats within specific business/technical context.")

    click.echo(_colored("\n  [ CORRELATION ]", B_CYAN))
    click.echo("  /correlate : Find complex attack chains from multiple data points.")
    click.echo("  /graph     : Map logical relationships between nodes and services.")
    click.echo("  /flow      : Analyze data flow and potential exfiltration points.")
    click.echo("  /boundary  : Identify trust boundaries and security zone crossings.")
    click.echo("  /zone      : Classify assets into Public, Internal, or Restricted.")
    click.echo("  /dependency: Identify third-party library and supply chain risks.")

    click.echo(_colored("\n  [ ATTACK INTEL ]", B_CYAN))
    click.echo("  /attack    : Generate step-by-step attack paths for objectives.")
    click.echo("  /chain     : Build vulnerability chains (Info Leak -> RCE).")
    click.echo("  /vector    : Rank and identify primary attack vectors exposed.")
    click.echo("  /entry     : Pinpoint the weakest entry points found so far.")
    click.echo("  /surface   : Define total attack surface (including Shadow IT).")
    click.echo("  /scenario  : Simulate attack scenarios (APT, Ransomware, etc.).")

    click.echo(_colored("\n  [ API & AUTH ]", B_CYAN))
    click.echo("  /remaining : Report on token/API usage and session quota.")
    click.echo("  /session   : Analyze cookie/JWT management for hijacking risks.")

    click.echo(_colored("\n  [ CLOUD & INFRA ]", B_CYAN))
    click.echo("  /cloud     : Audit S3, IAM roles, Metadata, and Lambda functions.")
    click.echo("  /origin    : Predict Origin IP by bypassing CDN/WAF protections.")
    click.echo("  /waf       : Analyze WAF/IPS for bypass heuristics and rule gaps.")

    click.echo(_colored("\n  [ OSINT ]", B_CYAN))
    click.echo("  /osint     : Correlate DNS/WHOIS data with internal scan results.")
    click.echo("  /employee  : Identify employee patterns and social engineering targets.")
    click.echo("  /leak      : Search for exposed secrets, API keys, or data dumps.")

    click.echo(_colored("\n  [ STRATEGY ]", B_CYAN))
    click.echo("  /strategy  : Recommend testing strategy (Black-box vs Grey-box).")
    click.echo("  /next      : Immediate next tactical steps for the analyst.")
    click.echo("  /focus     : Identify the single most critical area to target now.")
    click.echo("  /plan      : Generate exploitation plan with tools and payloads.")

    click.echo(_colored("\n  [ OUTPUT MODES ]", B_CYAN))
    click.echo("  /json      : Output strictly as a valid JSON object.")
    click.echo("  /clean     : Minimal fluff, core findings only.")
    click.echo("  /detail    : Maximum technical evidence and artifact analysis.")
    click.echo("  /dev       : Developer-focused (code snippets, RFC references).")
    click.echo("  /human     : Easy-to-read, professionally formatted output.")

    click.echo(_colored("\n  [ ADVANCED ]", B_CYAN))
    click.echo("  /deep      : Multi-layer reasoning for complex edge cases.")
    click.echo("  /auto      : Autonomous correlation and reporting mode.")
    click.echo("  /adaptive  : Adjust style based on previous analyst feedback.")
    click.echo("  /learn     : Save recurring patterns and successful payloads.")

    click.echo(_colored("\n  [ 4. CONTEXT AWARENESS & HISTORY ]", YELLOW))
    click.echo("  The agent uses a Go-powered history module to remember previous interactions.")
    click.echo("  It builds a tactical context of your target as you chat.")
    click.echo(_colored("  Reset History  :", DIM) + _colored(" agent clear", RED))
    
    click.echo(_colored("\n  [ 5. VULNERABILITY AUDITING ]", YELLOW))
    click.echo("  The AI can analyze raw scan results from HackIt tools to find vulnerabilities.")
    click.echo("  Simply pass the scan data or ask the AI to summarize discovery artifacts.")
    
    click.echo(_colored("\n  [ PRO TIP ]", MAGENTA))
    click.echo("  Use " + _colored("/deep", GREEN) + " for extremely thorough analysis and complex exploit chains.")
    click.echo(_colored("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", DIM))
    click.echo()

def handle_ai_command(cmd: str):
    """Handles universal /AI commands with Multi-Intelligence Selection"""
    if not cmd.startswith('/'):
        return False
    
    prompt = cmd[1:].strip()
    if not prompt:
        return True
    
    cfg = load_config()
    available_keys = {p: k for p, k in cfg.get("ai_keys", {}).items() if k}
    
    selected_provider = cfg.get("ai_provider", "gemini")
    
    # If multiple keys are available, offer a quick selection
    if len(available_keys) > 1:
        click.echo(_colored("\n  ┌────────────────────────────────────────────────────────────┐", DIM))
        click.echo(_colored("  │             SELECT ACTIVE INTELLIGENCE CORE                │", B_CYAN))
        click.echo(_colored("  └────────────────────────────────────────────────────────────┘", DIM))
        
        providers = sorted(list(available_keys.keys()))
        for i, p in enumerate(providers, 1):
            status = _colored("ONLINE", GREEN)
            active_mark = _colored(" <CURRENT>", YELLOW) if p == selected_provider else ""
            click.echo(f"  [{i}] {p.upper():<12} : {status}{active_mark}")
        
        click.echo(_colored(f"  [0] Keep Default ({selected_provider.upper()})", DIM))
        
        try:
            choice = click.prompt(_colored("\n  [?] Switch core?", YELLOW), type=int, default=0, show_default=False)
            if 1 <= choice <= len(providers):
                selected_provider = providers[choice-1]
        except:
            pass

    click.echo(_colored(f"\n[*] Consulting HackIt AI...", DIM))
    brain = AIHyperBrain()
    brain.provider = selected_provider 
    
    response = brain.chat(prompt)
    
    click.echo(_colored(f"\n[ HACKIT AI ]", MAGENTA, bold=True))
    click.echo(response)
    click.echo(_colored("─" * 40, DIM))
    click.echo()
    return True
