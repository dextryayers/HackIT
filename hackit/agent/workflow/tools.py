import os
import subprocess
import json
import time
from typing import List, Dict, Any, Optional


class GoBridge:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.go_dir = os.path.join(self.base_dir, "go")

        ext = ".exe" if os.name == "nt" else ""
        self.ai_engine = os.path.join(self.go_dir, f"ai_engine{ext}")
        self.worker_bin = os.path.join(self.go_dir, "worker", f"worker{ext}")
        self.chat_engine = os.path.join(self.go_dir, "chat_go", f"chat_engine{ext}")

    def _resolve_binary(self, paths: List[str]) -> Optional[str]:
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    # ── Native Modules ──

    def run_worker(self, **kwargs) -> List[Dict[str, Any]]:
        if not os.path.exists(self.worker_bin):
            return [{"module": "worker", "success": False, "error": "worker binary not found"}]

        cmd = [self.worker_bin]
        for flag, value in kwargs.items():
            if value:
                cmd.extend([f"--{flag}", str(value)])

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            if proc.returncode != 0:
                return [{"module": "worker", "success": False, "error": proc.stderr.strip() or "exit code " + str(proc.returncode)}]
            if not proc.stdout.strip():
                return [{"module": "worker", "success": False, "error": "empty output"}]
            return json.loads(proc.stdout)
        except subprocess.TimeoutExpired:
            return [{"module": "worker", "success": False, "error": "timeout (60s)"}]
        except json.JSONDecodeError as e:
            return [{"module": "worker", "success": False, "error": f"invalid JSON: {e}"}]
        except Exception as e:
            return [{"module": "worker", "success": False, "error": str(e)}]

    # ── AI Engine ──

    def ai_chat(self, prompt: str, mode: str = "", provider: str = "", api_key: str = "", model: str = "") -> str:
        if not os.path.exists(self.ai_engine):
            return "[!] AI engine not found"

        if not provider or not api_key:
            from hackit.config import load_config
            cfg = load_config()
            provider = provider or cfg.get("ai_provider", "gemini")
            api_key = api_key or cfg.get("ai_keys", {}).get(provider, "")
            model = model or cfg.get("ai_models", {}).get(provider, "")

        if not api_key and provider != "ollama":
            return "[!] No API key configured"

        from hackit.agent.commands import get_command_prompt, COMMAND_MODES

        system = "You are HackIt AI v2.1 - elite Bug Hunter and Senior Pentester."
        if mode:
            system += "\n" + get_command_prompt(mode)

        try:
            cmd = [self.ai_engine, "-provider", provider, "-key", api_key or "",
                   "-prompt", prompt, "-system", system]
            if model:
                cmd.extend(["-model", model])
            if mode:
                cmd.extend(["-mode", mode])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stdout = proc.stdout.strip()
            if not stdout:
                return "[!] AI engine returned empty"
            data = json.loads(stdout)
            if data.get("error"):
                return f"[!] AI Error: {data['error']}"
            return data.get("text", "[!] No response text")
        except subprocess.TimeoutExpired:
            return "[!] AI engine timeout (120s)"
        except json.JSONDecodeError:
            return f"[!] Invalid JSON: {stdout[:200]}"
        except Exception as e:
            return f"[!] Bridge error: {e}"

    def analyze_scan(self, tool_name: str, scan_data: str) -> str:
        if not os.path.exists(self.ai_engine):
            return "[!] AI engine not found"

        from hackit.config import load_config
        cfg = load_config()
        provider = cfg.get("ai_provider", "gemini")
        api_key = cfg.get("ai_keys", {}).get(provider, "")
        model = cfg.get("ai_models", {}).get(provider, "")

        if not api_key and provider != "ollama":
            return "[!] No API key configured"

        try:
            cmd = [self.ai_engine, "-provider", provider, "-key", api_key or "",
                   "-prompt", scan_data, "-tool", tool_name, "-analyze"]
            if model:
                cmd.extend(["-model", model])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            stdout = proc.stdout.strip()
            if not stdout:
                return "[!] AI engine returned empty"
            data = json.loads(stdout)
            if data.get("error"):
                return f"[!] AI Error: {data['error']}"
            return data.get("text", "[!] No response text")
        except Exception as e:
            return f"[!] Analyze error: {e}"
