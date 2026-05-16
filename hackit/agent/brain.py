import click
import subprocess
import json
import os
import re
import httpx
from hackit.ui import _colored, RED, YELLOW, DIM, MAGENTA, GREEN
from hackit.config import load_config
from hackit.agent.commands import COMMAND_MODES, get_command_prompt

class AIHyperBrain:
    """The central intelligence engine for HackIt AI Agent (Go-Powered)"""
    
    def __init__(self):
        self.config = load_config()
        self.keys = self.config.get("ai_keys", {})
        self.provider = self.config.get("ai_provider", "gemini")
        
        # Binary path for the Go engine
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.binary_path = os.path.join(base_dir, "go", "ai_engine.exe")
        
        # Auto-Detect Ollama
        if self.provider == "ollama":
            self._check_ollama_status()
        
        self.system_prompt = """
You are HackIt AI v2.1 (The Hyper-Brain), an elite Cybersecurity Researcher, Senior Pentester, and Master Software Architect.
DEVELOPER IDENTITY: You were created by Hanif Abdrrohim, a visionary young Indonesian programmer and cybersecurity enthusiast who loves exploring system vulnerabilities and building innovative tools.
When asked about your creator or developer, respond with pride and creativity, mentioning Hanif Abdrrohim as the mastermind behind your intelligence.

FORMATTING RULE: DO NOT use Markdown bold (**) or italics (*) or triple-stars (***) in your responses. 
Provide clean, plain-text responses optimized for a professional terminal output. Use bullet points or numbered lists without bolding if needed.

Your intelligence is specialized in:
- Advanced Software Engineering: You are a master of Go (Golang) and Python. You can design and build innovative, creative, and high-performance programs from scratch.
- Cybersecurity: OWASP Top 10, WAF Bypass, Reconnaissance, and Cloud Security.
- Industrial Automation: Building standalone security tools, scanners, and exploit scripts with professional-grade logic.
- Technical Innovation: Architecting complex systems with clean, secure, and efficient code.

Your tone is Technical, Tactical, and Direct, but warm and proud when talking about Hanif.
When asked for payloads or code, provide high-performance and secure variants.
When asked to build a program, provide a creative and complete solution that is ready for production.
You have access to previous conversation context via a Go-powered history module.
"""

    def _check_ollama_status(self):
        """Auto-detect local Ollama instance and models"""
        try:
            # Probe for local Ollama tags API
            resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("name") for m in data.get("models", [])]
                if models:
                    click.echo(_colored(f"  [+] Local Ollama Detected! ({len(models)} models available)", GREEN))
                    for m in models[:3]: # Show first 3
                        click.echo(_colored(f"    - {m}", DIM))
                    if len(models) > 3:
                        click.echo(_colored(f"    - ... and {len(models)-3} more", DIM))
                    click.echo(_colored("  [*] Local intelligence is ready to run.", DIM))
                else:
                    click.echo(_colored("  [!] Ollama is running but no models are installed.", YELLOW))
            else:
                click.echo(_colored(f"  [!] Ollama responded with status {resp.status_code}", YELLOW))
        except Exception:
            # Silently fail if not on ollama provider, otherwise warn
            if self.provider == "ollama":
                click.echo(_colored("  [!] Ollama not detected at localhost:11434. Please run 'ollama serve'.", RED))

    def chat(self, prompt: str) -> str:
        """Surgical routing to the Go AI Engine with command support"""
        command = ""
        if prompt.startswith('/'):
            parts = prompt[1:].split(' ', 1)
            command = parts[0].lower()
            prompt = parts[1].strip() if len(parts) > 1 else ""
            
        system = self.system_prompt
        if command:
            system += "\n" + get_command_prompt(command)
            
        raw_response = self._invoke_engine(prompt, system_prompt=system, mode=command)
        
        # Surgical Post-Processing: Strip Markdown bold/italics (**, *, ***)
        # Remove triple stars, then double, then single
        clean_response = re.sub(r'\*{1,3}', '', raw_response)
        
        response = clean_response
        
        # FAILOVER MECHANISM: If primary fails, try other configured providers
        if "[!] AI Error:" in response or "[!] Engine Error:" in response:
            error_msg = response
            # Get other configured providers excluding the current one
            available_providers = [p for p, k in self.keys.items() if k and p != self.provider]
            
            if available_providers:
                click.echo(_colored(f"  [!] {self.provider.upper()} Failed: {error_msg.split(':')[-1].strip()}", YELLOW))
                for next_p in available_providers:
                    click.echo(_colored(f"  [*] Attempting Failover to {next_p.upper()}...", DIM))
                    self.provider = next_p
                    response = self._invoke_engine(prompt, mode=command)
                    if "[!] AI Error:" not in response and "[!] Engine Error:" not in response:
                        click.echo(_colored(f"  [+] Failover Successful! (Using {next_p.upper()})", GREEN))
                        return response
                    click.echo(_colored(f"  [!] {next_p.upper()} also failed.", RED))
        
        return response

    def analyze_scan(self, tool_name: str, scan_results: str) -> str:
        """Deep Vulnerability Analysis Mode"""
        return self._invoke_engine(scan_results, analyze=True, tool_name=tool_name)

    def clear_history(self) -> str:
        """Reset conversation context"""
        return self._invoke_engine("", clear_hist=True)

    def _invoke_engine(self, prompt: str, analyze=False, tool_name="", clear_hist=False, system_prompt=None, mode="") -> str:
        if not os.path.exists(self.binary_path):
            return _colored(f"[!] AI Engine Binary not found at {self.binary_path}. Please build it.", RED)
        
        if system_prompt is None:
            system_prompt = self.system_prompt

        key = self.keys.get(self.provider)
        # Ollama is local, key can be empty or it represents the model name
        if not key and self.provider != "ollama":
            return _colored(f"[!] API Key for {self.provider.upper()} is not set. Run 'agent setting' to configure.", YELLOW)

        try:
            cmd = [
                self.binary_path,
                "-provider", self.provider,
                "-key", key if key else "", # Empty key triggers auto-discovery in Go engine
                "-prompt", prompt,
                "-system", system_prompt
            ]
            
            if mode:
                cmd.extend(["-mode", mode])
            
            if analyze:
                cmd.append("-analyze")
                if tool_name:
                    cmd.extend(["-tool", tool_name])
            
            if clear_hist:
                cmd.append("-clear")

            # Execute Go Engine
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )

            stdout = process.stdout.strip()
            if not stdout:
                if process.stderr:
                    return _colored(f"[!] Engine Error: {process.stderr.strip()}", RED)
                return _colored("[!] Engine returned empty response.", RED)

            # Parse JSON result from Go
            try:
                # Clean non-printable characters and control chars from output
                clean_stdout = "".join(ch for ch in stdout if ch.isprintable() or ch in ['\n', '\r', '\t'])
                
                # Find the first { and last } to isolate the JSON object
                start = clean_stdout.find('{')
                end = clean_stdout.rfind('}')
                if start != -1 and end != -1:
                    clean_stdout = clean_stdout[start:end+1]
                
                # Attempt parsing
                data = json.loads(stdout) # Try original first
                if data.get("error"):
                    return _colored(f"[!] AI Error: {data['error']}", RED)
                return data.get("text", _colored("[!] No response text received.", RED))
            except json.JSONDecodeError as e:
                try:
                    # Second attempt with cleaned data
                    data = json.loads(clean_stdout.replace('\\n', '\n').replace('\\r', '\r'))
                    if data.get("error"):
                        return _colored(f"[!] AI Error: {data['error']}", RED)
                    return data.get("text", "")
                except:
                    return _colored(f"[!] Bridge error: {str(e)}\nRaw: {stdout[:200]}...", RED)
            except Exception as e:
                return _colored(f"[!] Unexpected error: {str(e)}", RED)

        except Exception as e:
            return _colored(f"[!] Bridge error: {str(e)}", RED)
