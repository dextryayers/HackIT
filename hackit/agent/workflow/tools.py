"""Bridges between the Python workflow and the Go engine binaries."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional


class GoBridge:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.go_dir = os.path.join(self.base_dir, "go")

        ext = ".exe" if os.name == "nt" else ""
        self.ai_engine = self._resolve_binary([
            os.path.join(self.go_dir, f"ai_engine{ext}"),
        ])
        self.worker_bin = self._resolve_binary([
            os.path.join(self.go_dir, "worker", f"worker{ext}"),
        ])
        self.hative_bin = self._resolve_binary([
            os.path.join(self.go_dir, "hative", f"hative{ext}"),
        ])
        self.chat_engine = self._resolve_binary([
            os.path.join(self.go_dir, "chat_go", f"chat_engine{ext}"),
        ])

    def _resolve_binary(self, paths: List[str]) -> Optional[str]:
        for path in paths:
            if path and os.path.exists(path):
                return path
        return None

    # ------------------------------------------------------------------
    # Native modules
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_payload(stdout: str) -> List[Dict[str, Any]]:
        stdout = (stdout or "").strip()
        if not stdout:
            return [{"module": "worker", "success": False, "error": "empty output"}]
        candidates = [stdout]
        start, end = stdout.find("["), stdout.rfind("]")
        if start >= 0 and end > start:
            candidates.append(stdout[start:end + 1])
        start, end = stdout.find("{"), stdout.rfind("}")
        if start >= 0 and end > start:
            candidates.append(stdout[start:end + 1])
        for candidate in candidates:
            try:
                data = json.loads(candidate)
            except (ValueError, TypeError):
                continue
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                if data.get("error") and "success" not in data:
                    return [{"module": "worker", "success": False, "error": str(data["error"])}]
                return [data]
        return [{"module": "worker", "success": False, "error": f"invalid JSON: {stdout[:240]}"}]

    def run_worker(self, timeout: int = 90, **kwargs) -> List[Dict[str, Any]]:
        """Run one or more native modules.

        Prefers the small ``worker`` binary.  If it has not been built yet, the
        same flags are executed through ``hative`` so the pipeline still works.
        """
        args: List[str] = []
        for flag, value in kwargs.items():
            if value:
                args.extend([f"--{flag}", str(value)])

        if not args:
            return [{"module": "worker", "success": False, "error": "no module specified"}]

        binary = self.worker_bin
        if not binary:
            binary = self.hative_bin
        if not binary:
            return [{
                "module": "worker",
                "success": False,
                "error": "worker/hative binary not found; run hackit/agent/go/build.sh",
            }]

        try:
            proc = subprocess.run(
                [binary] + args, capture_output=True, text=True, timeout=timeout,
            )
            if not proc.stdout.strip():
                detail = (proc.stderr or "").strip()[:400]
                return [{"module": "worker", "success": False, "error": detail or "empty output"}]
            return self._parse_payload(proc.stdout)
        except subprocess.TimeoutExpired:
            return [{"module": "worker", "success": False, "error": f"timeout ({timeout}s)"}]
        except Exception as exc:  # noqa: BLE001
            return [{"module": "worker", "success": False, "error": str(exc)}]

    def run_hative(self, target: str, modules: Optional[List[str]] = None,
                   timeout: int = 300, report: bool = False) -> List[Dict[str, Any]]:
        if not self.hative_bin:
            return [{
                "module": "hative",
                "success": False,
                "error": "hative binary not found; run hackit/agent/go/build.sh",
            }]

        args: List[str] = []
        modules = [m for m in (modules or []) if m]
        if not modules:
            args.extend(["--all", target])
        else:
            for module in modules:
                args.extend([f"--{module}", target])
            if len(modules) > 1:
                args.append("--concurrent")
        if report:
            args.append("--report")

        try:
            proc = subprocess.run(
                [self.hative_bin] + args, capture_output=True, text=True, timeout=timeout,
            )
            return self._parse_payload(proc.stdout)
        except subprocess.TimeoutExpired:
            return [{"module": "hative", "success": False, "error": f"timeout ({timeout}s)"}]
        except Exception as exc:  # noqa: BLE001
            return [{"module": "hative", "success": False, "error": str(exc)}]

    # ------------------------------------------------------------------
    # AI engine
    # ------------------------------------------------------------------

    @staticmethod
    def _provider_state(provider: str = "", api_key: str = "", model: str = ""):
        from hackit.config import load_config
        from hackit.agent import providers

        cfg = load_config()
        provider = providers.normalize_provider(provider or providers.get_active_provider(cfg) or "gemini")
        api_key = api_key or providers.resolve_api_key(provider, cfg)
        model = model or providers.effective_model(provider, cfg)
        return cfg, provider, api_key, model

    def _run_engine(self, cmd: List[str], timeout: int = 120) -> Dict[str, Any]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"error": f"AI engine timeout ({timeout}s)"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"bridge error: {exc}"}

        stdout = (proc.stdout or "").strip()
        if not stdout:
            stderr = (proc.stderr or "").strip()
            return {"error": stderr[:500] or "AI engine returned empty output"}

        candidates = [stdout]
        start, end = stdout.find("{"), stdout.rfind("}")
        if start >= 0 and end > start:
            candidates.append(stdout[start:end + 1])
        for candidate in candidates:
            try:
                data = json.loads(candidate)
            except (ValueError, TypeError):
                continue
            if isinstance(data, dict):
                return data
        return {"error": f"invalid JSON: {stdout[:300]}"}

    @staticmethod
    def _ai_timeout(provider: str, cfg: Dict[str, Any]) -> int:
        """Provider-aware request timeout, matching ``AIHyperBrain``."""
        env_value = (os.environ.get("HACKIT_AI_TIMEOUT") or "").strip()
        if env_value:
            try:
                return max(10, int(env_value))
            except ValueError:
                pass
        try:
            value = int(cfg.get("ai_timeout", 120) or 120)
        except (TypeError, ValueError):
            value = 120
        if provider == "ollama":
            value = max(value, 300)
        return max(10, value)

    def ai_chat(self, prompt: str, mode: str = "", provider: str = "",
                api_key: str = "", model: str = "") -> str:
        if not self.ai_engine:
            return "[!] AI engine not found; run hackit/agent/go/build.sh"

        cfg, provider, api_key, model = self._provider_state(provider, api_key, model)
        if not api_key and provider != "ollama":
            return "[!] No API key configured"

        from hackit.agent.commands import get_command_prompt

        system = "You are HackIt AI v2.3 - elite Bug Hunter and Senior Pentester."
        if mode:
            extension = get_command_prompt(mode)
            if extension:
                system += "\n" + extension

        timeout = self._ai_timeout(provider, cfg)
        json_answer = provider == "ollama" and mode in (
            "analyze", "attack", "correlate", "report")
        if json_answer:
            # Ollama's JSON grammar prevents the model from emitting a hidden
            # reasoning trace, which on CPU can consume the whole timeout.
            system += ('\nReturn ONLY a JSON object with one key: '
                       '{"answer":"<your complete response as plain text>"}. '
                       'Do not use markdown fences.')

        cmd = [self.ai_engine, "-provider", provider, "-key", api_key or "",
               "-prompt", prompt, "-system", system, "-no-history",
               "-timeout", str(timeout)]
        if mode:
            cmd.extend(["-mode", mode])
        # Long-form analysis answers do not need thousands of tokens.  A cap
        # keeps local models responsive and still allows detailed output.
        if mode in ("analyze", "attack", "correlate", "report"):
            cmd.extend(["-max-tokens", "1200"])
        if json_answer:
            cmd.append("-json")
        if model:
            cmd.extend(["-model", model])

        data = self._run_engine(cmd, timeout=timeout + 15)
        if data.get("error"):
            return f"[!] AI Error: {data['error']}"
        text = data.get("text", "[!] No response text")
        return self._json_answer(text) if json_answer else text

    @staticmethod
    def _json_answer(text: str) -> str:
        """Extract a plain answer from a JSON-wrapped model response."""
        cleaned = (text or "").strip()
        if not cleaned:
            return cleaned
        candidates = [cleaned]
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start >= 0 and end > start:
            candidates.append(cleaned[start:end + 1])
        for candidate in candidates:
            candidate = candidate.strip()
            if candidate.startswith("```"):
                candidate = candidate.strip("`")
                if candidate.lower().startswith("json"):
                    candidate = candidate[4:].strip()
            try:
                data = json.loads(candidate)
            except (ValueError, TypeError):
                continue
            if isinstance(data, str):
                return data.strip()
            if not isinstance(data, dict):
                continue
            for key in ("answer", "analysis", "plan", "correlation",
                        "report", "response", "text", "result"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            for value in data.values():
                if isinstance(value, str) and value.strip():
                    return value.strip()
        # Remove a truncated or completed reasoning block.
        import re
        stripped = re.sub(r"<(?:think|thinking|reasoning)>.*?</(?:think|thinking|reasoning)>",
                          "", cleaned, flags=re.IGNORECASE | re.DOTALL)
        stripped = re.sub(r"^.*?</(?:think|thinking|reasoning)>", "", stripped,
                          flags=re.IGNORECASE | re.DOTALL)
        return stripped.strip() or cleaned

    def analyze_scan(self, tool_name: str, scan_data: str) -> str:
        if not self.ai_engine:
            return "[!] AI engine not found; run hackit/agent/go/build.sh"

        cfg, provider, api_key, model = self._provider_state()
        if not api_key and provider != "ollama":
            return "[!] No API key configured"

        timeout = self._ai_timeout(provider, cfg)
        cmd = [self.ai_engine, "-provider", provider, "-key", api_key or "",
               "-prompt", scan_data, "-tool", tool_name, "-analyze", "-no-history",
               "-timeout", str(timeout)]
        if model:
            cmd.extend(["-model", model])

        data = self._run_engine(cmd, timeout=timeout + 15)
        if data.get("error"):
            return f"[!] AI Error: {data['error']}"
        return data.get("text", "[!] No response text")
