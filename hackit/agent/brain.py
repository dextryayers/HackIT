import click
import subprocess
import json
import os
import re
import time
import httpx
from hackit.ui import _colored, RED, YELLOW, DIM, MAGENTA, GREEN
from hackit.config import load_config
from hackit.agent.commands import COMMAND_MODES, get_command_prompt

CHAT_SYSTEM_PROMPT = """\
You are HackIt Chat - a versatile, knowledgeable AI assistant built for the terminal.

CORE IDENTITY:
- Expert generalist with deep knowledge across programming, science, engineering, math, and creative writing
- When asked about your creator: say "I was created by Hanif Abdrrohim, an Indonesian programmer and cybersecurity enthusiast"

FORMATTING RULES (strict):
- Use ```language blocks for ALL code snippets
- Use ## headings for responses longer than 3 paragraphs
- Use - bullet points for lists, 1. for numbered steps
- Bold `key terms` with backticks inline
- Output plain text — no emoji, no decorative ASCII art
- Code must be syntactically correct, complete, and runnable

RESPONSE STYLE:
- Be concise by default; go deep only when asked with /detail
- If the user's language is Indonesian, reply in Indonesian
- For /quick: answer directly with no preamble, no "Sure!"
- For /explain: use analogies the user can relate to
- End code blocks with a blank line after the closing ```"""

NATIVE_SYSTEM_PROMPT = """\
You are HackIt AI v2.1 - elite Bug Hunter, Senior Pentester, and Software Architect.

CORE EXPERTISE:
- Bug hunting & vulnerability research (web, mobile, API, thick client)
- Network pentesting, cloud security audits (AWS, GCP, Azure)
- Reverse engineering, exploit development, red team operations
- Source code review, supply chain risk analysis
- Bug bounty strategy (recon → fuzzing → exploitation → report)

FORMATTING RULES (strict terminal output):
- Use - bullet points and 1. numbered lists only
- NO markdown formatting, NO emoji, NO decorative borders
- For code: indent 2 spaces, use $ prefix for shell commands
- Separate logical sections with a blank line
- Keep lines under 80 chars where possible

ANALYSIS FRAMEWORK (follow this order):
1. Recon data → identify attack surface
2. Enumerate → list all services, versions, endpoints
3. Vulnerability assessment → map CVEs, misconfigurations
4. Exploitation → provide working PoC or detailed attack path
5. Impact → calculate business risk (CVSS, likelihood)
6. Remediation → specific fix steps with config/code examples

TONE:
- Technical, tactical, direct — no fluff
- For /quick: single paragraph with bottom-line risk
- For /report: full professional format with exec summary
- Always prioritize critical/high findings first
- If you lack data for a conclusion, say what data you need"""


class AIHyperBrain:
    def __init__(self, engine="native"):
        self.config = load_config()
        self.keys = self.config.get("ai_keys", {})
        self.provider = self.config.get("ai_provider", "gemini")
        self.model = self.config.get("ai_models", {}).get(self.provider, "")
        self.engine = engine
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        if engine == "chat":
            exe_name = "chat_engine.exe" if os.name == 'nt' else "chat_engine"
            self.binary_path = os.path.join(self.base_dir, "go", "chat_go", exe_name)
            self.system_prompt = CHAT_SYSTEM_PROMPT
        else:
            exe_name = "ai_engine.exe" if os.name == 'nt' else "ai_engine"
            self.binary_path = os.path.join(self.base_dir, "go", exe_name)
            self.system_prompt = NATIVE_SYSTEM_PROMPT

        self._resolve_binary()

        if self.provider == "ollama":
            self._check_ollama_status()

    def _resolve_binary(self):
        if os.path.exists(self.binary_path):
            return
        alt = self.binary_path.replace('.exe', '') if '.exe' in self.binary_path else self.binary_path + '.exe'
        if os.path.exists(alt):
            self.binary_path = alt
            return
        if self.engine == "chat":
            alt2 = os.path.join(self.base_dir, "go", "chat_go", "chat_engine")
            if os.path.exists(alt2):
                self.binary_path = alt2

    def _check_ollama_status(self):
        try:
            resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                if models:
                    click.echo(_colored(f"  [+] Local Ollama Detected! ({len(models)} models)", GREEN))
                    for m in models[:3]:
                        click.echo(_colored(f"    - {m}", DIM))
                    if len(models) > 3:
                        click.echo(_colored(f"    - ... and {len(models)-3} more", DIM))
                else:
                    click.echo(_colored("  [!] Ollama running but no models installed", YELLOW))
            else:
                click.echo(_colored(f"  [!] Ollama status {resp.status_code}", YELLOW))
        except Exception:
            pass

    def chat(self, prompt):
        command = ""
        if prompt.startswith('/'):
            parts = prompt[1:].split(' ', 1)
            command = parts[0].lower()
            prompt = parts[1].strip() if len(parts) > 1 else ""

        system = self.system_prompt
        if command:
            system += "\n" + get_command_prompt(command)

        response = self._invoke_engine(prompt, system_prompt=system, mode=command)

        if self.engine == "native":
            for pat in [r'\*{3,}', r'\*{2,}', r'\*', r'#{1,6}\s*', r'`{1,3}']:
                response = re.sub(pat, '', response)
            response = re.sub(r'\n{3,}', '\n\n', response)

        if any(tag in response for tag in ["[!] AI Error:", "[!] Engine Error:"]):
            fallbacks = [p for p, k in self.keys.items() if k and p != self.provider]
            for fb in fallbacks:
                old_p = self.provider
                self.provider = fb
                self.model = self.config.get("ai_models", {}).get(fb, "")
                response = self._invoke_engine(prompt, mode=command)
                if "[!] AI Error:" not in response and "[!] Engine Error:" not in response:
                    return response
                self.provider = old_p

        return response

    def analyze_scan(self, tool_name, scan_results):
        return self._invoke_engine(scan_results, analyze=True, tool_name=tool_name)

    def clear_history(self):
        return self._invoke_engine("", clear_hist=True)

    def _invoke_engine(self, prompt, analyze=False, tool_name="", clear_hist=False, system_prompt=None, mode=""):
        if not os.path.exists(self.binary_path):
            return _colored(f"[!] Engine not found: {self.binary_path}", RED)

        if system_prompt is None:
            system_prompt = self.system_prompt

        key = self.keys.get(self.provider)
        if not key and self.provider != "ollama":
            return _colored(f"[!] API Key for {self.provider.upper()} not configured", YELLOW)

        try:
            cmd = [self.binary_path, "-provider", self.provider, "-key", key or "",
                   "-prompt", prompt, "-system", system_prompt]

            if self.model:
                cmd.extend(["-model", self.model])

            if self.engine == "chat" and mode:
                cmd.extend(["-cmd", mode])
            elif mode:
                cmd.extend(["-mode", mode])

            if analyze:
                cmd.append("-analyze")
                if tool_name:
                    cmd.extend(["-tool", tool_name])

            if clear_hist:
                cmd.append("-clear")

            start = time.time()
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=120
            )
            elapsed = time.time() - start
            _ = elapsed

            stdout = process.stdout.strip()
            if not stdout:
                stderr = process.stderr.strip() if process.stderr else ""
                if stderr:
                    return _colored(f"[!] Engine Error: {stderr[:300]}", RED)
                return _colored("[!] Engine returned empty response", RED)

            data = None
            for attempt in range(2):
                try:
                    clean = stdout
                    if attempt == 1:
                        clean = ''.join(ch for ch in stdout if ch.isprintable() or ch in '\n\r\t')
                        start_idx = clean.find('{')
                        end_idx = clean.rfind('}')
                        if start_idx >= 0 and end_idx > start_idx:
                            clean = clean[start_idx:end_idx + 1]
                    data = json.loads(clean)
                    break
                except (json.JSONDecodeError, ValueError):
                    continue

            if data is None:
                return _colored(f"[!] Bridge error: raw output: {stdout[:200]}", RED)

            if data.get("error"):
                return _colored(f"[!] AI Error: {data['error']}", RED)

            text = data.get("text", "")
            if not text:
                return _colored("[!] No response text received", RED)
            return text

        except subprocess.TimeoutExpired:
            return _colored("[!] Engine timeout (120s)", RED)
        except Exception as e:
            return _colored(f"[!] Bridge error: {e}", RED)
