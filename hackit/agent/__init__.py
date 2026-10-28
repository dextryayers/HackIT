import click
import requests
import json
import os
import shlex
import sys
from hackit.ui import _colored, GREEN, RED, BLUE, YELLOW, DIM, B_CYAN, B_RED, MAGENTA, RESET, BOLD, CYAN
from hackit.config import load_config

from hackit.agent.brain import AIHyperBrain
from hackit.agent import providers as provider_registry
from hackit.agent import payloads as payload_registry

@click.group(invoke_without_command=True)
@click.pass_context
def agent(ctx):
    """HackIt AI Agent - Your Cybersecurity Companion"""
    if ctx.invoked_subcommand is None:
        enter_agent_shell()

def enter_agent_shell():
    """Dedicated Agent CLI Shell — the agent's own terminal"""
    import shutil, time, subprocess as _sp

    cols = shutil.get_terminal_size().columns
    rows = shutil.get_terminal_size().lines

    # ── 1. Clear screen ──
    _sp.run(['clear' if os.name == 'posix' else 'cls'], shell=True)

    # ── 2. Cinematic loading sequence ──
    stages = [
        ("SYSTEM", "Booting kernel modules", B_CYAN, 8),
        ("NETWORK", "Initializing network stack", BLUE, 6),
        ("CORE", "Loading AI engine core", MAGENTA, 10),
        ("AGENTS", "Deploying 28 swarm agents", GREEN, 12),
        ("MEMORY", "Allocating neural buffers", YELLOW, 6),
        ("READY", "Agent shell ready", GREEN, 4),
    ]
    spinner_chars = ['▉', '▊', '▋', '▌', '▍', '▎', '▏', '▎', '▍', '▌', '▋', '▊', '▉']
    dir_chars = ['◢', '◣', '◤', '◥']
    total_steps = sum(s[3] for s in stages)
    step = 0
    bar_width = min(30, cols // 4)
    for stage_name, stage_msg, stage_color, stage_steps in stages:
        for s in range(stage_steps):
            pct = int((step / total_steps) * 100)
            sp = spinner_chars[step % len(spinner_chars)]
            sd = dir_chars[(step // 2) % len(dir_chars)]
            filled = '▓' * (pct * bar_width // 100)
            empty  = '░' * (bar_width - len(filled))
            bar = filled + empty
            if stage_name == "READY" and s == stage_steps - 1:
                label = _colored("● READY", GREEN, bold=True)
            else:
                label = _colored(f"{sd} {stage_name}", stage_color)
            line = f"{_colored(sp, stage_color)} {label}  {_colored(stage_msg, DIM)}  [{_colored(bar, DIM)}]  {_colored(f'{pct:>3}%', YELLOW)}"
            sys.stdout.write(f"\r{line}{' ' * max(0, cols - len(line))}")
            sys.stdout.flush()
            time.sleep(0.06 + (0.02 if stage_name == "READY" else 0.0))
            step += 1

    sys.stdout.write('\r' + ' ' * cols + '\r')
    sys.stdout.flush()
    time.sleep(0.15)

    # ── 3. Robot art header ──
    from hackit.ui import TOOL_ART
    art = TOOL_ART.get("AI AGENT", "")
    for art_line in art.split('\n'):
        stripped = art_line.strip('\r')
        if stripped:
            click.echo(f"  {_colored(stripped, B_CYAN)}")
        else:
            click.echo()
    click.echo(f"  {GREEN}▸{RESET}  {DIM}commands  |  chat  |  back  |  exit  |  help{RESET}")
    click.echo()

    # ── 4. Compact command grid (precise alignment) ──
    cmds = [
        ("swarm",     "28-agent full scan",      "autopilot",  "autonomous AI hunter"),
        ("auto",      "full pentest pipeline",   "chat",       "AI chat + tools"),
        ("payload",   "AI payload forge",        "osint",      "OSINT footprint"),
        ("doctor",    "provider diagnostics",    "setting",    "configure AI keys"),
        ("status",    "connectivity status",     "reset",      "reset AI config"),
        ("guide",     "command reference",       "clear",      "clear screen"),
    ]
    click.echo(f"  {'─' * 60}")
    col_right = 46
    for c1, d1, c2, d2 in cmds:
        l = f"  {GREEN}▶{RESET} {B_CYAN}{c1:>9}{RESET}  {DIM}{d1}{RESET}"
        r = f"{GREEN}▶{RESET} {B_CYAN}{c2:>9}{RESET}  {DIM}{d2}{RESET}"
        vis = 15 + len(d1)
        pad = max(1, col_right - vis)
        click.echo(f"{l}{' ' * pad}{r}")
    click.echo(f"  {'─' * 60}")
    click.echo(f"  {YELLOW}✦{RESET}  {DIM}commands  |  chat  |  back  |  exit  |  help{RESET}")
    click.echo()

    # ── 5. Interactive loop with dual-mode tracker ──
    from hackit.config import get_user_info
    user, _ = get_user_info()

    # Enable readline for arrow-up/down history
    try:
        import readline
    except ImportError:
        readline = None

    cmd_mode = False

    while True:
        try:
            mode_tag = f"{MAGENTA}[{RESET}{YELLOW}commands{RESET}{MAGENTA}]{RESET}" if cmd_mode else f"{MAGENTA}[{RESET}{YELLOW}chat{RESET}{MAGENTA}]{RESET}"
            prompt_str = f" {B_CYAN}{BOLD}[⚙{RESET}{GREEN}{BOLD} agent{RESET}{B_CYAN}{BOLD}]{RESET} {mode_tag} {B_CYAN}{BOLD}>{RESET} "
            user_input = input(prompt_str).strip()

            if not user_input:
                continue

            parts = user_input.split()
            base_cmd = parts[0].lower()
            remaining = ' '.join(parts[1:]) if len(parts) > 1 else ''

            # ── global: exit ──
            if base_cmd in ('exit', 'quit', 'q', 'bye'):
                click.echo(f"\n  {GREEN}✦{RESET}  {DIM}Agent shell terminated.{RESET}  {DIM}Happy hunting,{RESET} {GREEN}{user}{RESET}{DIM}.{RESET}\n")
                break

            # ── global: mode switching ──
            if base_cmd in ('commands', 'cmd'):
                if cmd_mode:
                    click.echo(f"  {YELLOW}✦{RESET}  {DIM}Already in commands mode. Type{RESET}  {GREEN}back{RESET}  {DIM}to return.{RESET}")
                else:
                    cmd_mode = True
                    click.echo(f"  {GREEN}▶{RESET}  {DIM}Commands mode — type{RESET}  {GREEN}back{RESET}  {DIM}to return,{RESET}  {GREEN}exit{RESET}  {DIM}to quit.{RESET}")
                continue

            if base_cmd == 'back':
                if cmd_mode:
                    cmd_mode = False
                    click.echo(f"  {GREEN}▶{RESET}  {DIM}Chat mode — just type anything.{RESET}")
                else:
                    click.echo(f"  {YELLOW}✦{RESET}  {DIM}Already in chat mode.{RESET}")
                continue

            # ── global: help ──
            if base_cmd in ('help', '?'):
                click.echo(f"  {'─' * 48}")
                helps = [
                    ("swarm",     "28-agent autonomous scan"),
                    ("autopilot", "AI-powered bug hunting"),
                    ("auto",      "Full recon→OSINT→scan→attack→report"),
                    ("payload",   "AI payload forge"),
                    ("osint",     "OSINT footprint discovery"),
                    ("dashboard", "Real-time TUI dashboard"),
                    ("reset",     "Reset AI keys/provider/models"),
                    ("setting",   "Configure AI providers & keys"),
                    ("status",    "Check AI connectivity"),
                    ("doctor",    "Deep provider diagnostics"),
                    ("chat",      "AI conversation mode"),
                    ("guide",     "Full command reference"),
                    ("clear",     "Clear terminal screen"),
                    ("commands",  "Enter commands mode"),
                    ("back",      "Return to chat mode"),
                    ("exit",      "Return to main framework"),
                ]
                for cmd, desc in helps:
                    click.echo(f"  {GREEN}▶{RESET} {B_CYAN}{cmd:>10}{RESET}   {DIM}{desc}{RESET}")
                click.echo(f"  {'─' * 48}")
                click.echo(f"  {YELLOW}✦{RESET}  {DIM}Ask anything in chat mode  |  commands  |  back  |  exit{RESET}")
                continue

            # ── global: clear ──
            if base_cmd == 'clear':
                _sp.run(['clear' if os.name == 'posix' else 'cls'], shell=True)
                click.echo(f"\n  {B_CYAN}╭{RESET}{'─' * 18}{B_CYAN}╮{RESET}")
                click.echo(f"  │{'SHELL CLEARED':^18}│")
                click.echo(f"  {B_CYAN}╰{RESET}{'─' * 18}{B_CYAN}╯{RESET}\n")
                continue

            # ── global: reset ──
            if base_cmd == 'reset':
                click.get_current_context().invoke(reset)
                continue

            # ── global: guide / setting / status ──
            if base_cmd == 'guide':
                click.get_current_context().invoke(guide)
                continue
            if base_cmd == 'setting':
                click.get_current_context().invoke(setting)
                continue
            if base_cmd == 'status':
                click.get_current_context().invoke(status)
                continue

            # ── global: chat / autopilot → launch interactive TUI ──
            if base_cmd == 'chat':
                cfg = load_config()
                if not provider_registry.configured_providers(cfg) and not provider_registry.detect_ollama().online:
                    click.echo(f"  {RED}✦{RESET}  {DIM}No AI provider configured. Run{RESET}  {GREEN}setting{RESET}  {DIM}first.{RESET}")
                    continue
                try:
                    from hackit.agent.interactive import create_ui
                    ui = create_ui("chat")
                    ui.run()
                except Exception as e:
                    click.echo(f"  {RED}[!] Chat UI error: {e}{RESET}")
                continue

            if base_cmd == 'autopilot':
                try:
                    from hackit.agent.interactive import create_ui
                    ui = create_ui("autopilot")
                    if remaining:
                        ui.target = remaining
                    ui.run()
                except Exception as e:
                    click.echo(f"  {RED}[!] Autopilot UI error: {e}{RESET}")
                continue

            # ── COMMAND MODE: only explicit commands ──
            if cmd_mode:
                if base_cmd == 'swarm':
                    t = remaining or None
                    if not t:
                        click.echo(f"  {RED}✦{RESET}  {DIM}Usage:{RESET} {GREEN}swarm <target> [--scope passive|active_stealth|aggressive]{RESET}")
                        continue
                    s = 'passive'
                    if '--scope' in parts:
                        idx = parts.index('--scope')
                        if idx + 1 < len(parts): s = parts[idx + 1]
                    swarm_cmd(t, s)
                    continue

                if base_cmd == 'dashboard':
                    t = remaining or None
                    if not t:
                        click.echo(f"  {RED}✦{RESET}  {DIM}Usage:{RESET} {GREEN}dashboard <target> [--scope ...]{RESET}")
                        continue
                    s = 'passive'
                    if '--scope' in parts:
                        idx = parts.index('--scope')
                        if idx + 1 < len(parts): s = parts[idx + 1]
                    dashboard_cmd(t, s)
                    continue

                if base_cmd == 'autopilot':
                    try:
                        from hackit.agent.interactive import create_ui
                        ui = create_ui("autopilot")
                        if remaining:
                            ui.target = remaining
                        ui.run()
                    except Exception as e:
                        click.echo(f"  {RED}[!] Autopilot UI error: {e}{RESET}")
                    continue

                if base_cmd in ('scan', 'recon', 'discover', 'enumerate', 'fingerprint'):
                    t = remaining or None
                    if not t:
                        click.echo(f"  {RED}✦{RESET}  {DIM}Usage:{RESET} {GREEN}{base_cmd} <target>{RESET}")
                        continue
                    click.echo(f"  {YELLOW}✦{RESET}  {DIM}Use{RESET}  {GREEN}swarm {t}{RESET}  {DIM}for full 28-agent scan.{RESET}")
                    continue

                if base_cmd in ('auto', 'payload', 'probe', 'osint', 'doctor', 'models', 'memory'):
                    handle_ai_command("/" + user_input)
                    continue

                click.echo(f"  {YELLOW}✦{RESET}  {DIM}Unknown command. Type{RESET}  {GREEN}help{RESET}  {DIM}or{RESET}  {GREEN}back{RESET}  {DIM}to chat.{RESET}")
                continue

            # ── CHAT MODE: explicit slash command or natural language ──
            if user_input.startswith('/'):
                if handle_ai_command(user_input):
                    continue
            _ask_brain(user_input)
            continue

        except (KeyboardInterrupt, EOFError):
            click.echo(f"\n  {GREEN}✦{RESET}  {DIM}Shell terminated.{RESET}  {DIM}See you later.{RESET}\n")
            break


def autopilot_cmd(target):
    """Run autopilot AI hunter"""
    import subprocess
    base_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(base_dir, 'go', 'ai_engine.exe' if os.name == 'nt' else 'ai_engine')
    if not os.path.exists(engine_path):
        click.echo(_colored(f"  [!] Missing AI engine at {engine_path}", RED))
        return
    click.echo(_colored(f"\n  [⚡] Autopilot hunting {target}...\n", B_CYAN))
    subprocess.run([engine_path, '--autopilot', target])


def swarm_cmd(target, scope='passive'):
    """Run 28-node swarm"""
    import subprocess
    base_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(base_dir, 'go', 'ai_engine.exe' if os.name == 'nt' else 'ai_engine')
    if not os.path.exists(engine_path):
        click.echo(_colored(f"  [!] Missing AI engine at {engine_path}", RED))
        return
    click.echo(_colored(f"\n  [ SWARM ] 28 agents attacking {target} [{scope}]\n", B_CYAN, bold=True))
    try:
        dash_script = os.path.join(base_dir, 'dashboard.py')
        if os.path.exists(dash_script):
            subprocess.run([sys.executable, dash_script, target, scope])
            return
        subprocess.run([engine_path, '--swarm', target, '--swarm-scope', scope])
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Swarm terminated.", RED))


def dashboard_cmd(target, scope='passive'):
    """Launch dashboard"""
    import subprocess
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dash_script = os.path.join(base_dir, 'dashboard.py')
    if not os.path.exists(dash_script):
        click.echo(_colored(f"  [!] Dashboard script not found", RED))
        return
    subprocess.run([sys.executable, dash_script, target, scope])


def clear_cmd():
    import subprocess
    subprocess.run(['clear' if os.name == 'posix' else 'cls'], shell=True)
    from hackit.ui import display_tool_banner
    display_tool_banner('AI AGENT', force=True)
    click.echo(_colored("\n  [+] Screen cleared.", DIM))


def guide_cmd():
    ctx = click.get_current_context()
    ctx.invoke(guide)


def setting_cmd():
    ctx = click.get_current_context()
    ctx.invoke(setting)


def status_cmd():
    ctx = click.get_current_context()
    ctx.invoke(status)


def chat_cmd():
    cfg = load_config()
    has_keys = bool(provider_registry.configured_providers(cfg))
    if not has_keys and not provider_registry.detect_ollama().online:
        click.echo(_colored("\n  [!] No AI provider configured. Run 'setting' first.", YELLOW))
        return
    click.echo(_colored("\n  [*] Entering AI chat mode...", DIM))
    click.echo(_colored("  [*] Type 'exit' to return to agent shell.", DIM))
    try:
        import readline
    except ImportError:
        readline = None

    while True:
        try:
            prompt_str = f" {_colored('ai', GREEN, bold=True)} {_colored('❯', YELLOW)} "
            user_input = input(prompt_str).strip()
            if not user_input:
                continue
            if user_input.lower() in ['exit', 'quit', 'back']:
                break
            handle_ai_command(user_input if user_input.startswith('/') else '/' + user_input)
        except (KeyboardInterrupt, EOFError):
            break

@agent.command()
def help():
    """Show core commands and options for the AI Agent"""
    click.echo(_colored("\n  [ HACKIT AI AGENT - COMMANDS ]", B_CYAN))
    click.echo(_colored("  ------------------------------------------------", DIM))
    click.echo(f"  • {_colored('swarm [domain/ip]', YELLOW):<12} : Launch 28-node swarm (with TUI dashboard)")
    click.echo(f"  • {_colored('dashboard [domain/ip]', YELLOW):<12} : Real-time TUI dashboard only")
    click.echo(f"  • {_colored('autopilot [domain/ip]', YELLOW):<12} : Autopilot, Automation Testing with Ai")
    click.echo(f"  • {_colored('status', YELLOW):<12} : Check AI connectivity and active providers.")
    click.echo(f"  • {_colored('setting', YELLOW):<12} : Configure API keys and select AI models.")
    click.echo(f"  • {_colored('clear', YELLOW):<12} : Reset conversation history and clear context.")
    click.echo(f"  • {_colored('reset', YELLOW):<12} : Reset AI config (keys, provider, models) with dropdown.")
    click.echo(f"  • {_colored('guide', YELLOW):<12} : Show full tactical guide for slash commands.")
    click.echo(f"  • {_colored('chat', YELLOW):<12} : Enter interactive AI chat mode.")
    click.echo(_colored("\n  [!] Usage: agent <command> or type them inside chat.", DIM))
    click.echo()

@agent.command()
def chat():
    """Start an interactive chat session with the AI Agent"""
    try:
        from hackit.agent.interactive import create_ui
        ui = create_ui("chat")
        ui.run()
    except Exception as e:
        click.echo(f"\n  {RED}[!] Chat UI error: {e}{RESET}")
        sys.exit(1)

# ── animated spinner ──
def _spin(msg, duration=1.2):
    import time, threading
    done = False
    def _run():
        for c in '◢◣◤◥':
            if done: break
            sys.stdout.write(f"\r  {MAGENTA}{c}{RESET}  {DIM}{msg}{RESET}  ")
            sys.stdout.flush()
            time.sleep(0.1)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(duration)
    done = True
    sys.stdout.write(f"\r  {GREEN}✓{RESET}  {DIM}{msg}{RESET}{' ' * 20}\n")
    sys.stdout.flush()


# ── curated model database with pricing ──
MODEL_DB = {
    "gemini": [
        ("gemini-3.5-flash",       "free",    "FREE — 1M ctx, newest reasoning (May 2026)"),
        ("gemini-3.1-flash-lite",  "free",    "FREE — high-throughput, low cost"),
        ("gemini-3.1-pro",         "paid",    "PAID — advanced reasoning, agentic"),
        ("gemini-3-flash",         "free",    "FREE — balanced speed & quality"),
        ("gemini-2.5-flash",       "free",    "FREE — 1M ctx, multimodal (legacy)"),
        ("gemini-2.5-pro",         "paid",    "PAID — legacy pro, deep reasoning"),
        ("gemini-2.0-flash",       "free",    "FREE — legacy, highest rate limits"),
        ("gemini-2.0-flash-lite",  "free",    "FREE — legacy lite, cheapest"),
    ],
    "openai": [
        ("gpt-4o",                 "paid",    "PAID — flagship multimodal"),
        ("gpt-4o-mini",            "paid",    "PAID — cheap & fast, per-token cost"),
        ("gpt-4.1",                "paid",    "PAID — latest GPT-4 generation"),
        ("gpt-4.1-mini",           "paid",    "PAID — new mini, cheap but not free"),
        ("gpt-4.1-nano",           "paid",    "PAID — nano tier, cheapest"),
        ("gpt-4-turbo",            "paid",    "PAID — legacy turbo, strong vision"),
        ("gpt-4",                  "paid",    "PAID — original GPT-4, reliable"),
        ("o3",                     "paid",    "PAID — latest reasoning, best accuracy"),
        ("o3-mini",                "paid",    "PAID — reasoning mini, efficient"),
        ("o1",                     "paid",    "PAID — premium reasoning model"),
        ("o1-mini",                "paid",    "PAID — compact reasoning model"),
    ],
    "claude": [
        ("claude-4-sonnet",        "paid",    "PAID — newest sonnet, state-of-art"),
        ("claude-3-5-sonnet",      "paid",    "PAID — best balance speed and quality"),
        ("claude-3-opus",          "paid",    "PAID — maximum intelligence, premium"),
        ("claude-3-sonnet",        "paid",    "PAID — legacy sonnet, reliable"),
        ("claude-3-5-haiku",       "paid",    "PAID — fastest Claude, cheap"),
        ("claude-3-haiku",         "paid",    "PAID — legacy haiku, cheap"),
        ("claude-opus-4",          "paid",    "PAID — next-gen opus, ultimate power"),
    ],
    "groq": [
        ("llama-4-scout",              "freeish","Free tier (rate-limited) — fastest Llama 4"),
        ("llama-4-maverick",           "freeish","Free tier (rate-limited) — powerful Llama 4"),
        ("llama-3.3-70b-versatile",    "freeish","Free tier (rate-limited) — Meta Llama 3.3"),
        ("llama-3.1-8b-instant",       "freeish","Free tier (rate-limited) — lightning fast"),
        ("llama3-70b-8192",            "freeish","Free tier (rate-limited) — legacy 70B"),
        ("llama3-8b-8192",             "freeish","Free tier (rate-limited) — legacy 8B"),
        ("mixtral-8x7b-32768",         "freeish","Free tier (rate-limited) — Mistral MoE"),
        ("gemma2-9b-it",               "freeish","Free tier (rate-limited) — Gemma 2 9B"),
        ("gemma-7b-it",                "freeish","Free tier (rate-limited) — Gemma 1 7B"),
        ("deepseek-r1-distill-llama-70b", "freeish","Free tier (rate-limited) — R1 distilled"),
        ("whisper-large-v3",           "freeish","Free tier (rate-limited) — speech-to-text"),
    ],
    "deepseek": [
        ("deepseek-chat",          "paid",    "PAID — $0.14/M input, best value"),
        ("deepseek-coder",         "paid",    "PAID — $0.28/M, code specialist"),
        ("deepseek-v3",            "paid",    "PAID — $0.27/M, latest V3"),
        ("deepseek-reasoner",      "paid",    "PAID — $0.50/M, deeper reasoning"),
        ("deepseek-r1",            "paid",    "PAID — $0.70/M, reasoning Gen 2"),
    ],
    "openrouter": [
        # TRULY FREE models (append :free, no credits needed)
        ("google/gemini-2.5-flash:free",                  "free",  "Gemini 2.5 Flash — 1M ctx, multimodal"),
        ("google/gemini-3-flash-preview:free",            "free",  "Gemini 3 Flash Preview — newest"),
        ("google/gemma-4-31b-it:free",                    "free",  "Gemma 4 31B — dense multimodal"),
        ("google/gemma-3-27b-it:free",                    "free",  "Gemma 3 27B — open model"),
        ("google/gemma-3-12b-it:free",                    "free",  "Gemma 3 12B — smaller Gemma"),
        ("meta-llama/llama-4-maverick:free",              "free",  "Llama 4 Maverick 17B — multimodal"),
        ("meta-llama/llama-4-scout:free",                 "free",  "Llama 4 Scout 17B — 10M ctx"),
        ("meta-llama/llama-3.3-70b-instruct:free",        "free",  "Llama 3.3 70B — strong all-purpose"),
        ("meta-llama/llama-3.2-90b-vision-instruct:free", "free",  "Llama 3.2 90B Vision"),
        ("meta-llama/llama-3.1-8b-instruct:free",         "free",  "Llama 3.1 8B — fast & efficient"),
        ("deepseek/deepseek-r1:free",                     "free",  "DeepSeek R1 — top reasoning, 128K"),
        ("deepseek/deepseek-chat-v3-0324:free",           "free",  "DeepSeek V3 0324 — general chat"),
        ("qwen/qwen3-235b-a22b:free",                     "free",  "Qwen3 235B A22B — MoE reasoning"),
        ("qwen/qwen3-coder:free",                         "free",  "Qwen3 Coder 480B — best free coder"),
        ("qwen/qwen-2.5-coder-32b-instruct:free",         "free",  "Qwen2.5 Coder 32B — coding"),
        ("qwen/qwen-2.5-7b-instruct:free",                "free",  "Qwen2.5 7B — multilingual"),
        ("mistralai/mistral-small-3.1-24b-instruct:free", "free",  "Mistral Small 3.1 24B — multimodal"),
        ("mistralai/mistral-nemo:free",                   "free",  "Mistral Nemo 12B — multilingual"),
        ("nousresearch/hermes-3-llama-3.1-405b:free",     "free",  "Hermes 3 405B — largest free"),
        ("nousresearch/hermes-3-llama-3.1-70b:free",      "free",  "Hermes 3 70B — roleplay/agentic"),
        ("microsoft/phi-4:free",                          "free",  "Phi-4 14B — reasoning"),
        ("x-ai/grok-3-mini:free",                         "free",  "Grok 3 Mini — fast reasoning"),
        ("openchat/openchat-7b:free",                     "free",  "OpenChat 3.5 7B — lightweight"),
        ("nvidia/nemotron-3-ultra-550b-a55b:free",        "free",  "Nemotron 3 Ultra — frontier reasoning"),
        # PAID models (need credits in OpenRouter account)
        ("openai/gpt-4o-mini",                "paid",   "PAID — cheap GPT-4o"),
        ("openai/gpt-4o",                     "paid",   "PAID — flagship multimodal"),
        ("openai/gpt-4.1",                    "paid",   "PAID — latest GPT-4"),
        ("openai/o3-mini",                    "paid",   "PAID — reasoning mini"),
        ("openai/o1",                         "paid",   "PAID — premium reasoning"),
        ("openai/gpt-4-turbo",                "paid",   "PAID — legacy turbo"),
        ("anthropic/claude-4-sonnet",         "paid",   "PAID — newest sonnet"),
        ("anthropic/claude-3.5-sonnet",       "paid",   "PAID — best balance"),
        ("anthropic/claude-3-haiku",          "paid",   "PAID — fast Claude"),
        ("anthropic/claude-3-opus",           "paid",   "PAID — full Claude opus"),
        ("cohere/command-r-plus",             "paid",   "PAID — Cohere premium"),
    ],
    "mistral": [
        ("ministral-3b",           "freeish", "Exp tier (2 RPM) — $0.04/M, ultra-light"),
        ("open-mistral-nemo",      "freeish", "Exp tier (2 RPM) — $0.15/M, open 12B"),
        ("mistral-small-latest",   "freeish", "Exp tier (2 RPM) — $0.10/M, fast"),
        ("codestral-latest",       "freeish", "Exp tier (2 RPM) — $0.30/M, code"),
        ("mistral-medium-latest",  "freeish", "Exp tier (2 RPM) — $1.50/M, balanced"),
        ("mistral-large-latest",   "freeish", "Exp tier (2 RPM) — $2.00/M, premium"),
        ("pixtral-large-latest",   "freeish", "Exp tier (2 RPM) — $2.00/M, vision"),
    ],
    "togetherai": [
        ("meta-llama/Llama-3.3-70B-Instruct-Turbo",       "paid",  "PAID — per-token cost"),
        ("meta-llama/Llama-4-Maverick-17B-128E-Instruct", "paid",  "PAID — Llama 4 via Together"),
        ("mistralai/Mixtral-8x22B-Instruct-v0.1",         "paid",  "PAID — Mixtral MoE"),
        ("deepseek-ai/DeepSeek-R1",                       "paid",  "PAID — DeepSeek R1 premium"),
        ("deepseek-ai/DeepSeek-V3",                       "paid",  "PAID — latest V3"),
        ("Qwen/Qwen2.5-72B-Instruct-Turbo",               "paid",  "PAID — Qwen 72B"),
        ("Qwen/Qwen2.5-Coder-32B-Instruct",               "paid",  "PAID — Qwen Coder 32B"),
        ("google/gemma-2-27b-it",                         "paid",  "PAID — Gemma 2 27B"),
        ("google/gemma-2-9b-it",                          "paid",  "PAID — Gemma 2 9B"),
        ("microsoft/phi-4",                               "paid",  "PAID — Phi-4 14B"),
        ("upstage/SOLAR-10.7B-Instruct-v1.0",             "paid",  "PAID — SOLAR 10.7B"),
    ],
}

MODEL_PRICING_LABELS = {
    "free": f"{GREEN}FREE{RESET}",
    "freeish": f"{YELLOW}FREE TIER{RESET}",
    "paid": f"{RED}PAID{RESET}",
}


def _spinner_loading(msg):
    import itertools, threading, time
    _done = False
    def _spin():
        for c in itertools.cycle('◢◣◤◥'):
            if _done: break
            sys.stdout.write(f"\r  {MAGENTA}{c}{RESET}  {DIM}{msg}{RESET}  ")
            sys.stdout.flush()
            time.sleep(0.1)
    t = threading.Thread(target=_spin, daemon=True)
    t.start()
    def stop():
        nonlocal _done
        _done = True
        sys.stdout.write(f"\r  {GREEN}✓{RESET}{' ' * 50}\n")
        sys.stdout.flush()
    return stop

def _done_spinner():
    pass

def _model_loading_animation(model_name, provider_label):
    """Multi-stage cinematic loading after model selection."""
    import time
    stages = [
        f"Binding neural pathways for {model_name}",
        f"Synchronizing with {provider_label}",
        "Establishing encrypted API channel",
        "Verifying model compatibility",
        "AI neural core initialized",
    ]
    for msg in stages:
        _spin(msg, 0.3)
        time.sleep(0.05)
    click.echo(f"  {GREEN}✓{RESET}  {B_CYAN}{model_name}{RESET} {DIM}is now active and ready{RESET}")


def _dropdown_select(provider, models, fetched_ids=None):
    """Interactive dropdown model selector with ↑↓ navigation.
    Returns model ID string, or empty string if cancelled.
    """
    import os

    try:
        import fcntl
        import termios
        import tty
    except ImportError:  # pragma: no cover - Windows
        fcntl = termios = tty = None  # type: ignore[assignment]

    fet = set(f.lower() for f in (fetched_ids or []))
    items = [(m, tier, desc,
              f"{GREEN}◉{RESET}" if m.lower() in fet else f"{DIM}○{RESET}",
              MODEL_PRICING_LABELS.get(tier, f"{DIM}?{RESET}"))
             for m, tier, desc in models]

    if not items:
        return ""

    if not (termios and tty and fcntl and sys.stdin.isatty()):
        # Portable fallback: numbered list, no raw terminal handling.
        click.echo(f"\n  {B_CYAN}{BOLD}MODEL SELECTION{RESET} "
                   f"{DIM}({PROVIDER_LABELS.get(provider, provider.upper())}){RESET}\n")
        for index, (m, tier, desc, dot, badge) in enumerate(items, 1):
            suffix = f" {DIM}[{tier}]{RESET}" if tier else ""
            click.echo(f"  {index:>2}. {dot} {m} {DIM}{desc}{RESET}{suffix}")
        try:
            choice = click.prompt(
                f"\n  {YELLOW}Select model{RESET}",
                type=click.IntRange(1, len(items)),
                default=1,
            )
        except (click.Abort, KeyboardInterrupt, EOFError):
            return ""
        selected = items[choice - 1][0]
        click.echo(f"  {GREEN}✓{RESET}  {B_CYAN}{selected}{RESET}")
        return selected

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)

    n = len(items)
    cur = 0
    top = 0
    page = min(n, 12)

    click.echo(f"\n  {B_CYAN}{BOLD}╭{'─' * 52}{B_CYAN}{BOLD}╮{RESET}")
    click.echo(f"  │{'':>6}{B_CYAN}{BOLD}MODEL SELECTION{RESET}{B_CYAN}{BOLD}{'':<6}│{RESET}")
    click.echo(f"  │  {PROVIDER_LABELS.get(provider, provider.upper())}{'':>28}│")
    click.echo(f"  {B_CYAN}{BOLD}╰{'─' * 52}{B_CYAN}{BOLD}╯{RESET}")
    click.echo()
    _HL = "\033[48;5;236m\033[38;5;15m"
    _R = "\033[0m"
    result = ""

    def _read_key():
        nonlocal fd
        ch = os.read(fd, 1)
        if not ch:
            return 'ESC'
        ch = chr(ch[0])
        if ch == '\x1b':
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
            try:
                seq = os.read(fd, 2)
                seq = seq.decode('utf-8', errors='replace') if seq else ''
            except (BlockingIOError, OSError):
                seq = ''
            fcntl.fcntl(fd, fcntl.F_SETFL, fl)
            if seq == '[A': return 'UP'
            if seq == '[B': return 'DOWN'
            return 'ESC'
        if ch in ('\r', '\n'): return 'ENTER'
        if ch == '\x03': return 'CTRLC'
        return ch

    def draw():
        nonlocal cur, top
        if cur < top:
            top = cur
        if cur >= top + page:
            top = cur - page + 1

        sys.stdout.write("\033[2J\033[H")

        sys.stdout.write(f"\n  {B_CYAN}{BOLD}╭{'─' * 52}{B_CYAN}{BOLD}╮{RESET}\r\n")
        sys.stdout.write(f"  │{'':>6}{B_CYAN}{BOLD}MODEL SELECTION{RESET}{B_CYAN}{BOLD}{'':<6}│{RESET}\r\n")
        sys.stdout.write(f"  │  {PROVIDER_LABELS.get(provider, provider.upper())}{'':>28}│\r\n")
        sys.stdout.write(f"  {B_CYAN}{BOLD}╰{'─' * 52}{B_CYAN}{BOLD}╯{RESET}\r\n")
        sys.stdout.write("\r\n")

        for i in range(page):
            idx = top + i
            if idx >= n:
                sys.stdout.write("\033[K\r\n")
                continue
            m, tier, desc, dot, badge = items[idx]
            if idx == cur:
                sys.stdout.write(f"\r  {_HL} \033[38;5;46m▸\033[38;5;15m {dot} {badge} {m:<36} {desc}{_R}\033[K\r\n")
            else:
                sys.stdout.write(f"\r     {dot} {badge} \033[2m{m:<36}\033[0m\033[2m {desc}\033[0m\033[K\r\n")

        sys.stdout.write(f"\r  \033[2m{GREEN}◉\033[0m\033[2mver  {DIM}○\033[0m\033[2mcur  │  {GREEN}F\033[0m\033[2m {YELLOW}FT\033[0m\033[2m {RED}P\033[0m\033[2m  │  ↑↓ {cur+1}/{n}  Enter=sel\033[0m\033[K")
        sys.stdout.flush()

    try:
        tty.setraw(fd)
        draw()
        while True:
            k = _read_key()
            if k == 'UP' and cur > 0:
                cur -= 1
                draw()
            elif k == 'DOWN' and cur < n - 1:
                cur += 1
                draw()
            elif k == 'ENTER':
                m, tier, desc = items[cur][:3]
                if tier == "paid":
                    sys.stdout.write(f"\033[2J\033[H\033[K")
                    click.echo(f"  {RED}⚠{RESET}  {YELLOW}{m}{RESET}  {DIM}is paid — proceed?{RESET} {GREEN}(y/n){RESET}")
                    c = os.read(fd, 1)
                    c = chr(c[0]) if c else 'n'
                    if c not in ('y', 'Y'):
                        draw()
                        continue
                result = m
                break
            elif k in ('ESC', 'CTRLC', 'q'):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\033[2J\033[H")
        if result:
            click.echo(f"  {GREEN}✓{RESET}  {B_CYAN}{result}{RESET}")
        else:
            click.echo(f"  {DIM}no model selected{RESET}")
        sys.stdout.flush()

    return result


_display_models = _dropdown_select  # alias for compatibility


def _fetch_models_for(provider, key):
    """Fetch real-time models from a provider API (best effort)."""
    provider = provider_registry.normalize_provider(provider)
    try:
        return provider_registry.list_remote_models(provider, key=key, timeout=5.0)
    except Exception:
        return []


PROVIDERS = list(provider_registry.PROVIDERS)

PROVIDER_LABELS = dict(provider_registry.PROVIDER_LABELS)

PROVIDER_MODEL_URLS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", True, "gemini"),
    "openai": ("https://api.openai.com/v1/models", True, None),
    "groq": ("https://api.groq.com/openai/v1/models", True, None),
    "deepseek": ("https://api.deepseek.com/models", True, None),
    "mistral": ("https://api.mistral.ai/v1/models", True, None),
    "togetherai": ("https://api.together.xyz/v1/models", True, None),
    "openrouter": ("https://openrouter.ai/api/v1/models", False, None),
}


def _check_ollama():
    return provider_registry.detect_ollama().online


def _check_provider_reachable(provider, key):
    if provider == "ollama":
        return _check_ollama()
    try:
        status = provider_registry.check_provider(provider, key=key, timeout=4.0)
        return status.reachable
    except Exception:
        return False


def _print_status(cfg):
    from hackit.config import CONFIG_PATH

    click.echo(_colored("\n  [ AI AGENT STATUS ]", B_CYAN))
    click.echo(f"  • Config File     : {DIM}{CONFIG_PATH}{RESET}")

    active = provider_registry.get_active_provider(cfg)
    configured = provider_registry.configured_providers(cfg)
    models = cfg.get("ai_models", {})

    click.echo(f"  • Active Provider : {YELLOW}{(active or 'NONE').upper()}{RESET}")
    if active:
        model = provider_registry.effective_model(active, cfg)
        click.echo(f"  • Active Model    : {YELLOW}{model or '(auto)'}{RESET}")
    click.echo(f"  • Configured      : {DIM}{', '.join(configured) if configured else 'none'}{RESET}")

    click.echo(_colored("  • Probing providers…", DIM))
    statuses = {item.provider: item for item in provider_registry.doctor(cfg, timeout=4.0)}

    for provider in PROVIDERS:
        status = statuses.get(provider)
        if status is None:
            tag = f"{DIM}NOT CONFIGURED{RESET}"
            latency = ""
            model = models.get(provider, "")
            if model:
                tag += f"  {DIM}({model}){RESET}"
            click.echo(f"  {GREEN}▶{RESET} {B_CYAN}{provider:<12}{RESET}{tag}")
            continue

        if status.state == "ready":
            tag = f"{GREEN}READY{RESET}"
            latency = f"  {DIM}{status.latency_ms} ms{RESET}" if status.latency_ms else ""
        elif status.state == "offline":
            tag = f"{RED}OFFLINE (NOT RUNNING){RESET}"
            latency = ""
        elif status.state == "unreachable":
            tag = f"{YELLOW}UNREACHABLE{RESET}"
            latency = ""
        elif status.state == "configured":
            tag = f"{GREEN}CONFIGURED{RESET}"
            latency = ""
        else:
            tag = f"{DIM}NOT CONFIGURED{RESET}"
            latency = ""

        model = models.get(provider, "") or provider_registry.effective_model(provider, cfg)
        detail = ""
        if status.models:
            detail += f"  {DIM}{len(status.models)} model(s){RESET}"
        if status.error:
            detail += f"  {RED}{status.error[:120]}{RESET}"
        click.echo(f"  {GREEN}▶{RESET} {B_CYAN}{provider:<12}{RESET}{tag}{latency}{detail}")
        if model:
            click.echo(f"    {DIM}model: {model}{RESET}")


@agent.command()
@click.option('--provider', type=click.Choice(PROVIDERS), help='Set AI provider')
@click.option('--key', help='Set API key (or leave empty for interactive prompt)')
@click.option('--model', help='Set AI model (or leave empty for optimal default)')
def setting(provider, key, model):
    """Configure AI Agent settings and API keys"""
    from hackit.config import load_config, save_config
    cfg = load_config()
    
    if not provider:
        click.echo(_colored("\n  [ SELECT AI PROVIDER ]", B_CYAN))
        for i, p in enumerate(PROVIDERS, 1):
            click.echo(f"  {i:2d}. {PROVIDER_LABELS[p]}")
        click.echo(_colored("  0. Back to Main", DIM))
        choice = click.prompt(_colored("\n  [?] Select provider (0-9)", YELLOW), type=int)
        
        if choice == 0:
            click.echo(_colored("\n  [*] Returning...", DIM))
            return
            
        if 1 <= choice <= len(PROVIDERS):
            provider = PROVIDERS[choice-1]
        else:
            click.echo(_colored("[!] Invalid choice.", RED))
            return

    if not key:
        if provider == "ollama":
            key = "AUTO_DETECT"
            info = provider_registry.detect_ollama()
            if info.online:
                click.echo(_colored(
                    f"\n  [*] Ollama online at {info.host} — {len(info.models)} model(s) detected",
                    GREEN,
                ))
            else:
                click.echo(_colored(
                    f"\n  [!] Ollama not reachable at {info.host}. Start it with: ollama serve",
                    YELLOW,
                ))
        else:
            key = click.prompt(
                _colored(f"  [?] Paste your {provider.upper()} API Key", YELLOW),
                hide_input=True,
            )
    
    if provider and key:
        if "ai_keys" not in cfg:
            cfg["ai_keys"] = {}
        if "ai_models" not in cfg:
            cfg["ai_models"] = {}
        
        cfg["ai_provider"] = provider
        cfg["ai_keys"][provider] = key
        
        if model is None and provider != "ollama":
            _spin(f"Fetching {PROVIDER_LABELS.get(provider, provider)} models ...", 0.6)
            fetched = _fetch_models_for(provider, key)
            if fetched:
                click.echo(f"  {GREEN}◉{RESET}  {DIM}Found {len(fetched)} models on API{RESET}")
            curated = MODEL_DB.get(provider, [])
            visible = curated[:]
            if fetched:
                fet_lower = set(f.lower() for f in fetched)
                for m_id in fetched:
                    if m_id.lower() not in set(c[0].lower() for c in curated):
                        visible.append((m_id, "freeish" if provider in ("openrouter",) else "free", "From API"))
            model = _display_models(provider, visible, fetched)
            if model:
                _model_loading_animation(model, PROVIDER_LABELS.get(provider, provider))
            else:
                click.echo(f"  {DIM}No model selected — will auto-detect optimal default.{RESET}")
                model = ""
        elif model is None and provider == "ollama":
            _spin("Scanning local Ollama models ...", 0.5)
            info = provider_registry.detect_ollama()
            if info.online and info.models:
                click.echo(f"  {GREEN}◉{RESET}  {DIM}Local models: {', '.join(info.models[:5])}{RESET}")
                ollama_items = [(m, "free", "Local Ollama model") for m in info.models]
                model = _dropdown_select(provider, ollama_items, info.models)
            elif info.online:
                click.echo(_colored("  [!] Ollama is running but has no models. Run: ollama pull llama3", YELLOW))
            else:
                click.echo(_colored(f"  [!] Ollama offline at {info.host}: {info.error}", YELLOW))
            
        cfg["ai_models"][provider] = model.strip() if isinstance(model, str) else ""
        
        _spin(f"Verifying {PROVIDER_LABELS.get(provider, provider)} connection ...", 0.5)
        status = provider_registry.check_provider(provider, key=key, cfg=cfg, timeout=5.0)
        if status.reachable:
            detail = f" · {len(status.models)} model(s)" if status.models else ""
            latency = f" · {status.latency_ms} ms" if status.latency_ms else ""
            click.echo(f"  {GREEN}✓{RESET}  {DIM}Connection verified{detail}{latency}{RESET}")
        elif provider == "ollama":
            click.echo(_colored(
                f"  [!] Ollama offline at {provider_registry.ollama_host()}: {status.error}",
                YELLOW,
            ))
            click.echo(_colored("      Start it with: ollama serve", DIM))
        elif status.reachable is False:
            click.echo(_colored(
                f"  [!] API did not respond: {status.error or 'check the key and network'}",
                YELLOW,
            ))
        else:
            click.echo(f"  {DIM}Connection check skipped.{RESET}")
        
        if save_config(cfg):
            click.echo(f"  {GREEN}✓{RESET}  {DIM}Configuration saved.{RESET}")
        else:
            click.echo(f"  {RED}✗{RESET}  {DIM}Write failed.{RESET}")
        
    cfg = load_config()
    _print_status(cfg)

@agent.command()
def status():
    """Check AI Agent connectivity — smart detect all providers & Ollama"""
    from hackit.config import load_config
    _print_status(load_config())


@agent.command()
def doctor():
    """Deep provider diagnostics: keys, latency, model discovery and Ollama."""
    from hackit.config import load_config

    cfg = load_config()
    _print_status(cfg)
    click.echo(_colored("\n  [ DIAGNOSTICS ]", B_CYAN))
    click.echo(f"  • Config dir      : {DIM}{os.path.join(os.path.expanduser('~'), '.hackit')}{RESET}")
    click.echo(f"  • Ollama host     : {DIM}{provider_registry.ollama_host()}{RESET}")
    click.echo(f"  • Workflow engine : {DIM}{_workflow_engine()}{RESET}")
    click.echo(f"  • Memory backend  : {DIM}{_memory_backend()}{RESET}")
    click.echo(f"  • Authorization   : {DIM}HACKIT_AUTHORIZED={os.environ.get('HACKIT_AUTHORIZED', '0')}{RESET}")
    if os.environ.get("HACKIT_AUTHORIZED", "").lower() not in ("1", "true", "yes", "y"):
        click.echo(_colored("  [!] Active payload verification is disabled until HACKIT_AUTHORIZED=1", YELLOW))
    click.echo()


def _workflow_engine():
    try:
        from hackit.agent.workflow import workflow_engine
        return workflow_engine()
    except Exception as exc:  # noqa: BLE001
        return f"unavailable ({exc})"


def _memory_backend():
    try:
        from hackit.agent.memory import langchain_available
        return "langchain" if langchain_available() else "builtin"
    except Exception:
        return "builtin"


@agent.command()
@click.argument('provider', required=False)
@click.option('--curated/--remote', default=False, help='Only show curated models')
def models(provider, curated):
    """List available models for a provider (including live discovery)."""
    from hackit.config import load_config

    cfg = load_config()
    provider = provider_registry.normalize_provider(
        provider or provider_registry.get_active_provider(cfg) or "gemini"
    )
    key = provider_registry.resolve_api_key(provider, cfg)
    click.echo(_colored(f"\n  [ MODELS · {provider} ]", B_CYAN))
    items = provider_registry.model_options(provider, key=key, include_remote=not curated)
    if not items:
        click.echo(_colored("  [!] No models found. Check the key or start Ollama.", YELLOW))
        return
    for index, (model, tier, description) in enumerate(items, 1):
        click.echo(
            f"  {GREEN}{index:>2}.{RESET} {B_CYAN}{model:<48}{RESET} "
            f"{DIM}{tier:<8} {description}{RESET}"
        )
    click.echo(_colored("\n  Set one with: agent setting --provider ... --model ...", DIM))


@agent.command()
@click.argument('vuln_type')
@click.option('--context', default='', help='Target/context for the payloads')
@click.option('--count', default=12, type=int, help='Number of payloads')
@click.option('--no-ai', is_flag=True, help='Use the offline catalogue only')
@click.option('--out', default='', help='Save results to .json or .md')
def payload(vuln_type, context, count, no_ai, out):
    """Forge payloads for a vulnerability class using the active AI provider."""
    click.echo(_colored(f"\n  [ PAYLOAD FORGE · {vuln_type.upper()} ]", B_CYAN))
    brain = AIHyperBrain(engine="native", enable_memory=False)
    result = brain.generate_payloads(vuln_type, context=context, count=count, use_ai=not no_ai)
    items = result.get("payloads", [])
    if not items:
        click.echo(_colored("  [!] No payloads generated.", RED))
        return
    for index, item in enumerate(items, 1):
        click.echo(f"  {GREEN}{index:>2}.{RESET} {item.get('payload', '')}")
        notes = item.get("notes", "")
        technique = item.get("technique", "")
        if technique or notes:
            click.echo(f"      {DIM}{technique}{(' · ' + notes) if notes else ''}{RESET}")
    click.echo(_colored(
        f"\n  Source: {result.get('source')} · provider={result.get('provider') or 'auto'} · "
        f"model={result.get('model') or 'auto'}",
        DIM,
    ))
    if result.get("ai_error"):
        click.echo(_colored(f"  [!] AI note: {result['ai_error']}", YELLOW))
    if out:
        payload_registry.save({"results": {result.get("type", vuln_type): result}}, out)
        click.echo(_colored(f"  [+] Saved to {out}", GREEN))


@agent.command()
@click.argument('vuln_type')
@click.argument('target')
@click.option('--param', default='', help='Parameter to inject into')
@click.option('--method', default='GET', type=click.Choice(['GET', 'POST']))
@click.option('--count', default=6, type=int, help='Payloads to send')
@click.option('--use-ai/--no-ai', default=True, help='Include AI-generated payloads')
def probe(vuln_type, target, param, method, count, use_ai):
    """Send generated payloads to an authorised target and analyse responses."""
    if os.environ.get("HACKIT_AUTHORIZED", "").lower() not in ("1", "true", "yes", "y"):
        click.echo(_colored(
            "\n  [!] Refusing active probing. Set HACKIT_AUTHORIZED=1 only when you "
            "have written permission to test this target.",
            RED,
        ))
        return
    brain = AIHyperBrain(engine="native", enable_memory=False)
    result = brain.generate_payloads(vuln_type, context=target, count=count, use_ai=use_ai)
    payload_list = [item.get("payload", "") for item in result.get("payloads", []) if item.get("payload")]
    if not payload_list:
        click.echo(_colored("  [!] No payloads to send.", RED))
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    click.echo(_colored(f"\n  [ PROBE · {vuln_type.upper()} ] {target}", B_CYAN))
    if param:
        click.echo(_colored(f"  Parameter: {param} · method: {method}", DIM))
    else:
        click.echo(_colored("  No parameter supplied — payloads are appended as ?url=…", DIM))

    def on_result(item):
        marker = _colored("VULN", RED) if item.get("vulnerable") else _colored("·", DIM)
        click.echo(f"  {marker} {item.get('payload', '')[:90]}  {DIM}{item.get('evidence', '')[:120]}{RESET}")

    results = brain.probe_payloads(
        target, vuln_type, payload_list, parameter=param, method=method,
        timeout=10.0, on_result=on_result,
    )
    click.echo(_colored("\n  " + payload_registry.summarize_probe(results).replace("\n", "\n  "), BOLD))


@agent.command()
@click.argument('target')
@click.option('--scope', default='active_stealth',
              type=click.Choice(['passive', 'active_stealth', 'aggressive']))
@click.option('--resume', is_flag=True, help='Resume the latest saved state')
def auto(target, scope, resume):
    """Run the autonomous recon → OSINT → scan → payload → attack → report pipeline."""
    from hackit.agent.workflow import run_pentest

    click.echo(_colored(f"\n  [ AUTONOMOUS PENTEST ] target={target} scope={scope}", B_CYAN, bold=True))
    click.echo(_colored(f"  Engine: {_workflow_engine()}", DIM))
    if os.environ.get("HACKIT_AUTHORIZED", "").lower() not in ("1", "true", "yes", "y"):
        click.echo(_colored(
            "  [!] Active payload verification is disabled. Set HACKIT_AUTHORIZED=1 "
            "only for targets you own or have permission to test.",
            YELLOW,
        ))

    def progress(phase, message):
        click.echo(f"  {CYAN}▸{RESET} {B_CYAN}{phase:<10}{RESET} {DIM}{message}{RESET}")

    try:
        state = run_pentest(target, scope=scope, resume=resume, progress=progress)
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Pipeline interrupted.", YELLOW))
        return
    except Exception as exc:  # noqa: BLE001
        click.echo(_colored(f"\n  [!] Pipeline failed: {exc}", RED))
        if os.environ.get("HACKIT_DEBUG"):
            import traceback
            click.echo(traceback.format_exc())
        return

    findings = state.get("findings", []) if isinstance(state, dict) else []
    click.echo(_colored(
        f"\n  [+] Pipeline complete · {len(findings)} finding(s) · "
        f"risk {state.get('risk_score', 0)}/10",
        GREEN, bold=True,
    ))
    if state.get("report_path"):
        click.echo(_colored(f"  [+] Report: {state['report_path']}", GREEN))
    click.echo(_colored(f"  [+] State: {os.path.join(os.path.expanduser('~'), '.hackit', 'workflow_state')}", DIM))


@agent.command(name='osint')
@click.argument('query')
@click.option('--deep', is_flag=True, help='Deep handle variants and wider coverage')
@click.option('--json-out', default='', help='Write the raw result to a JSON file')
def osint_cmd(query, deep, json_out):
    """Run OSINT footprint discovery for a username, email or domain."""
    from hackit.osint.core import run_full_scan

    click.echo(_colored(f"\n  [ OSINT ] {query}", B_CYAN, bold=True))
    try:
        data = run_full_scan(
            query, timeout=7, workers=24, verbose=True, deep=deep,
            check_domain=True, check_phone=False,
        )
    except Exception as exc:  # noqa: BLE001
        click.echo(_colored(f"  [!] OSINT failed: {exc}", RED))
        return
    summary = data.get("summary", {})
    analysis = data.get("analysis", {})
    click.echo(_colored(
        f"\n  [+] Checked {summary.get('checked', 0)} source(s) · "
        f"{summary.get('hits', 0)} hit(s) · {summary.get('possible', 0)} possible · "
        f"confidence {analysis.get('confidence_score', 0)}/100",
        GREEN,
    ))
    if json_out:
        with open(json_out, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, default=str)
        click.echo(_colored(f"  [+] Saved: {json_out}", DIM))


@agent.command()
@click.option('--session', default='chat_default', help='Memory session name')
@click.option('--show/--stats', default=False, help='Show remembered facts')
@click.option('--clear', 'clear_memory', is_flag=True, help='Clear this memory session')
@click.option('--export', default='', help='Export memory to a JSON file')
def memory(session, show, clear_memory, export):
    """Inspect or manage the agent's long-term conversation memory."""
    from hackit.agent.memory import AgentMemory

    store = AgentMemory(session=session)
    if clear_memory:
        store.clear()
        click.echo(_colored(f"  [+] Memory session '{session}' cleared.", GREEN))
        return
    if export:
        store.export(export)
        click.echo(_colored(f"  [+] Memory exported to {export}", GREEN))
        return
    stats = store.stats()
    click.echo(_colored(f"\n  [ MEMORY · {session} ]", B_CYAN))
    for key, value in stats.items():
        click.echo(f"  • {key:<18}: {DIM}{value}{RESET}")
    if show:
        facts = store._facts  # noqa: SLF001 - read-only display
        if not facts:
            click.echo(_colored("  No long-term facts recorded yet.", DIM))
        else:
            click.echo(_colored("\n  Long-term facts:", B_CYAN))
            for fact in facts:
                click.echo(f"  {GREEN}·{RESET} {fact}")

@agent.command()
@click.argument('target')
@click.option('--scope', default='passive', type=click.Choice(['passive', 'active_stealth', 'aggressive']), help='Swarm aggressiveness level')
@click.option('--dashboard/--no-dashboard', default=True, help='Show real-time TUI dashboard')
def swarm(target, scope, dashboard):
    """Launch the 28-node Autonomous Swarm against a target"""
    import subprocess
    click.echo(_colored(f"\n[ SWARM ] Launching 28-node autonomous swarm against {target} [{scope}]...", B_CYAN, bold=True))
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    engine_path = os.path.join(base_dir, 'go', 'ai_engine.exe' if os.name == 'nt' else 'ai_engine')
    
    if not os.path.exists(engine_path):
        click.echo(_colored(f"  [!] Missing AI engine at {engine_path}", RED))
        return

    if dashboard:
        try:
            dash_script = os.path.join(base_dir, 'dashboard.py')
            if os.path.exists(dash_script):
                cmd = [sys.executable, dash_script, target, scope]
                subprocess.run(cmd)
                return
        except Exception:
            pass

    try:
        cmd = [engine_path, '--swarm', target, '--swarm-scope', scope]
        subprocess.run(cmd, cwd=os.path.join(base_dir, 'go'))
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Swarm terminated by user.", RED))
    except Exception as e:
        click.echo(_colored(f"\n  [!] Swarm crashed: {str(e)}", RED))

@agent.command()
@click.argument('target')
@click.option('--scope', default='passive', type=click.Choice(['passive', 'active_stealth', 'aggressive']))
def dashboard(target, scope):
    """Launch real-time TUI dashboard for swarm execution"""
    import subprocess
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dash_script = os.path.join(base_dir, 'dashboard.py')
    if not os.path.exists(dash_script):
        click.echo(_colored(f"  [!] Dashboard script not found at {dash_script}", RED))
        return
    cmd = [sys.executable, dash_script, target, scope]
    subprocess.run(cmd)

@agent.command()
@click.argument('target', required=False, default='')
def autopilot(target):
    """Launch the Autonomous AI Bug Hunter against a target"""
    try:
        from hackit.agent.interactive import create_ui
        ui = create_ui("autopilot")
        if target:
            ui.target = target
        ui.run()
    except Exception as e:
        click.echo(f"\n  {RED}[!] Autopilot UI error: {e}{RESET}")
        sys.exit(1)

@agent.command()
def clear():
    """Clear AI conversation history"""
    brain = AIHyperBrain()
    result = brain.clear_history()
    click.echo(f"\n  [+] {result}")

@agent.command()
def reset():
    """Reset AI configuration — API keys, provider, models, history, or all"""
    import os
    import shutil

    try:
        import fcntl
        import termios
        import tty
    except ImportError:  # pragma: no cover - Windows
        fcntl = termios = tty = None  # type: ignore[assignment]

    RESET_OPTIONS = [
        ("api_keys",    "API Keys",       "Clear ALL provider API keys from config"),
        ("provider",    "AI Provider",    "Reset active provider to none"),
        ("models",      "Model Choices",  "Clear all model selections per provider"),
        ("local",       "Ollama Config",  "Reset Ollama local model selection"),
        ("conversation","Conversation",   "Clear AI conversation history"),
        ("all",         "EVERYTHING",     "⚠  Keys + Provider + Models + History"),
    ]

    result = ""
    use_raw = bool(termios and tty and fcntl and sys.stdin.isatty())

    if not use_raw:
        # Portable fallback for Windows, pipes and dumb terminals.
        click.echo(f"\n  {BOLD}\u26a0  RESET AI CONFIGURATION{RESET}")
        click.echo(f"  {DIM}Select what to erase permanently{RESET}\n")
        for index, (_key, label, desc) in enumerate(RESET_OPTIONS, 1):
            click.echo(f"  {index}. {label:<16} {DIM}{desc}{RESET}")
        try:
            choice = click.prompt(
                f"\n  {YELLOW}Select option{RESET}",
                type=click.IntRange(1, len(RESET_OPTIONS)),
                default=len(RESET_OPTIONS),
            )
            result = RESET_OPTIONS[choice - 1][0]
        except (click.Abort, KeyboardInterrupt, EOFError):
            result = ""
    else:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        n = len(RESET_OPTIONS)
        cur = 0

        def _read_key():
            ch = os.read(fd, 1)
            if not ch: return 'ESC'
            ch = chr(ch[0])
            if ch == '\x1b':
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                try:
                    seq = os.read(fd, 2)
                    seq = seq.decode('utf-8', errors='replace') if seq else ''
                except Exception:
                    seq = ''
                fcntl.fcntl(fd, fcntl.F_SETFL, fl)
                if seq == '[A': return 'UP'
                if seq == '[B': return 'DOWN'
                return 'ESC'
            if ch in ('\r', '\n'): return 'ENTER'
            if ch == '\x03': return 'CTRLC'
            if ch == 'y': return 'y'
            if ch == 'n': return 'n'
            return ch

        def draw():
            nonlocal cur
            term_cols = shutil.get_terminal_size().columns
            box_w = min(term_cols - 6, 56)
            pad1 = box_w - 31 if box_w > 31 else 0
            pad2 = box_w - 38 if box_w > 38 else 0
            sep = '─' * box_w
            out = ["\033[2J\033[H"]
            out.append(f"  {BOLD}{B_RED}\u250c{sep}\u2510{RESET}\r\n")
            out.append(f"  {BOLD}{B_RED}\u2502{RESET}  {BOLD}\u26a0  RESET AI CONFIGURATION{' ' * pad1}{BOLD}{B_RED}\u2502{RESET}\r\n")
            out.append(f"  {BOLD}{B_RED}\u2502{RESET}  {DIM}Select what to erase permanently{' ' * pad2}{BOLD}{B_RED}\u2502{RESET}\r\n")
            out.append(f"  {BOLD}{B_RED}\u2514{sep}\u2518{RESET}\r\n")
            out.append(f"\r\n")
            for i, (key, label, desc) in enumerate(RESET_OPTIONS):
                if i == cur:
                    out.append(f"  \033[48;5;196m\033[38;5;15m \u25b8 {label:<16} {desc}\033[0m\033[K\r\n")
                else:
                    out.append(f"    \033[2m{label:<16} {desc}\033[0m\033[K\r\n")
            out.append(f"  \033[2m\u2191\u2193 navigate  |  Enter select  |  ESC cancel\033[0m\033[K\r\n")
            sys.stdout.write(''.join(out))
            sys.stdout.flush()

        try:
            tty.setraw(fd)
            draw()
            while True:
                k = _read_key()
                if k == 'UP' and cur > 0:
                    cur -= 1
                    draw()
                elif k == 'DOWN' and cur < n - 1:
                    cur += 1
                    draw()
                elif k == 'ENTER':
                    result = RESET_OPTIONS[cur][0]
                    break
                elif k in ('ESC', 'CTRLC'):
                    break
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()

    if not result:
        click.echo(f"  {DIM}Reset cancelled.{RESET}")
        return

    # Confirm for ALL
    if result == "all":
        click.echo(f"\n  {BOLD}{B_RED}⚠ Confirm RESET ALL?{RESET}")
        click.echo(f"  {DIM}This will erase: API keys, provider, models, and history.{RESET}")
        try:
            confirmed = click.confirm(f"  {YELLOW}Are you sure?{RESET}", default=False)
        except (KeyboardInterrupt, EOFError):
            click.echo(f"  {DIM}Cancelled.{RESET}")
            return
        if not confirmed:
            click.echo(f"  {DIM}Cancelled.{RESET}")
            return

    from hackit.config import load_config, save_config
    cfg = load_config()
    changes = []

    if result in ("api_keys", "all"):
        keys = cfg.get("ai_keys", {})
        active_p = cfg.get("ai_provider", "")
        cleared = [p.upper() for p, k in list(keys.items()) if k]
        for p in list(keys.keys()):
            if keys[p]:
                del keys[p]
        # If active provider lost its key, also reset provider + its model
        if active_p.upper() in cleared:
            cfg["ai_provider"] = ""
            models = cfg.get("ai_models", {})
            if active_p in models:
                del models[active_p]
        if cleared:
            changes.append(f"Keys removed: {', '.join(cleared)} (provider+model also reset)")
        else:
            changes.append("No API keys to clear")

    if result in ("provider", "all"):
        old_p = cfg.get("ai_provider", "")
        cfg["ai_provider"] = ""
        changes.append(f"Provider reset ({old_p.upper() or 'none'} \u2192 none)")

    if result in ("models", "all"):
        old_m = cfg.get("ai_models", {})
        cfg["ai_models"] = {}
        if old_m:
            details = ", ".join(f"{p}={m}" for p, m in old_m.items() if m)
            changes.append(f"Models cleared ({details or 'none configured'})")
        else:
            changes.append("No models to clear")

    if result in ("local", "all"):
        ollama_key = cfg.get("ai_keys", {}).pop("ollama", None)
        ollama_model = cfg.get("ai_models", {}).pop("ollama", None)
        if ollama_key or ollama_model:
            changes.append("Ollama config removed")
        else:
            changes.append("No Ollama config to clear")

    if result in ("conversation", "all"):
        try:
            brain = AIHyperBrain(engine="chat")
            brain.clear_history()
            brain2 = AIHyperBrain(engine="native")
            brain2.clear_history()
            changes.append("Conversation history cleared (chat + autopilot)")
        except Exception as e:
            changes.append(f"History clear attempted ({e})")

    if changes:
        save_config(cfg)
        click.echo(f"\n  {BOLD}{B_RED}✔ Reset Complete{RESET}")
        for c in changes:
            click.echo(f"    {DIM}•{RESET} {c}")
        click.echo(f"\n  {DIM}Run '{GREEN}agent status{DIM}' to verify{RESET}")
    else:
        click.echo(f"  {DIM}Nothing to reset.{RESET}")

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
    click.echo("  Supported Providers: Gemini, Groq, OpenAI, Claude, DeepSeek, OpenRouter, Ollama.")
    
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

# Slash aliases that map to full Click subcommands.  Everything else that
# starts with ``/`` is treated as an AI mode (see commands.COMMAND_MODES).
_AGENT_ACTIONS = {
    "payload": "payload",
    "probe": "probe",
    "auto": "auto",
    "osint": "osint",
    "models": "models",
    "doctor": "doctor",
    "memory": "memory",
    "setting": "setting",
    "status": "status",
    "swarm": "swarm",
    "scan": "swarm",
    "dashboard": "dashboard",
    "autopilot": "autopilot",
    "clear": "clear",
    "reset": "reset",
    "guide": "guide",
    "help": "help",
    "chat": "chat",
}


def _click_registry():
    return {
        "payload": payload,
        "probe": probe,
        "auto": auto,
        "osint": osint_cmd,
        "models": models,
        "doctor": doctor,
        "memory": memory,
        "setting": setting,
        "status": status,
        "swarm": swarm,
        "dashboard": dashboard,
        "autopilot": autopilot,
        "clear": clear,
        "reset": reset,
        "guide": guide,
        "help": help,
        "chat": chat,
    }


def _dispatch_agent_action(name: str, rest: str) -> bool:
    """Run a Click subcommand from a slash command such as ``/payload sqli``."""
    command_name = _AGENT_ACTIONS.get(name)
    command = _click_registry().get(command_name or "")
    if command is None:
        return False
    try:
        args = shlex.split(rest)
    except ValueError as exc:
        click.echo(_colored(f"  [!] Invalid arguments: {exc}", RED))
        return True
    try:
        command.main(
            args=args,
            prog_name=f"agent {command_name}",
            standalone_mode=False,
        )
    except (click.exceptions.Exit, SystemExit):
        pass
    except click.ClickException as exc:
        exc.show()
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Cancelled.", YELLOW))
    except Exception as exc:  # noqa: BLE001 - a command must not kill the shell
        click.echo(_colored(f"  [!] {command_name} failed: {exc}", RED))
        if os.environ.get("HACKIT_DEBUG"):
            import traceback
            click.echo(traceback.format_exc())
    return True


def _ask_brain(prompt: str, show_banner: bool = True) -> str:
    """Send natural language to the unified brain (provider fallback + memory)."""
    cfg = load_config()
    if not provider_registry.configured_providers(cfg) and not provider_registry.detect_ollama().online:
        click.echo(_colored("  [!] No AI provider configured. Run `agent setting`.", RED))
        return ""

    brain = AIHyperBrain(engine="chat")
    if show_banner:
        click.echo(_colored(f"\n[*] Consulting HackIt AI ({brain.provider.upper()})...", DIM))
    try:
        response = brain.chat(prompt)
    except KeyboardInterrupt:
        click.echo(_colored("\n  [!] Cancelled.", YELLOW))
        return ""
    except Exception as exc:  # noqa: BLE001
        click.echo(_colored(f"  [!] Agent error: {exc}", RED))
        if os.environ.get("HACKIT_DEBUG"):
            import traceback
            click.echo(traceback.format_exc())
        return ""

    if show_banner:
        click.echo(_colored("\n[ HACKIT AI ]", MAGENTA, bold=True))
    click.echo(response)
    click.echo(_colored("─" * 40, DIM))
    click.echo()
    return response


def handle_ai_command(cmd: str):
    """Handle a universal slash command.

    * ``/payload``, ``/probe``, ``/auto``, ``/osint``, ``/swarm`` ... dispatch
      to the corresponding Click command.
    * ``/risk``, ``/attack``, ``/report`` ... are AI modes and reach the engine
      with the leading slash intact (the previous implementation stripped it,
      which made every mode dead).
    * An unknown ``/word`` followed by text is treated as a natural question.
    """
    if not isinstance(cmd, str):
        return False
    raw = cmd.strip()
    if not raw.startswith("/"):
        return False

    body = raw[1:].strip()
    if not body:
        return True

    head, _, rest = body.partition(" ")
    head = head.lower().strip()
    rest = rest.strip()

    from hackit.agent.commands import COMMAND_MODES

    if head in _AGENT_ACTIONS:
        return _dispatch_agent_action(head, rest)

    if head in COMMAND_MODES:
        _ask_brain(raw)
        return True

    # Unknown mode: the user asked a question, not a directive.
    _ask_brain(body)
    return True
