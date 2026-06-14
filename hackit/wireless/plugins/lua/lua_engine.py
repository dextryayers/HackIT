import os
import subprocess
import json
import shutil
from pathlib import Path

BASE = Path(__file__).parent


class LuaEngine:
    def __init__(self):
        self._lua_bin = shutil.which("lua") or shutil.which("luajit") or shutil.which("lua5.4") or shutil.which("lua5.3") or shutil.which("lua5.2") or shutil.which("lua5.1")

    def available(self) -> bool:
        return self._lua_bin is not None

    def list_scripts(self) -> list[str]:
        scripts_dir = BASE / "scripts"
        if not scripts_dir.exists():
            return []
        return [f.stem for f in sorted(scripts_dir.glob("*.lua"))]

    def run(self, script_name: str, args: list[str] = None) -> str:
        if not self._lua_bin:
            raise RuntimeError("Lua interpreter not found. Install lua or luajit.")
        script_path = BASE / "scripts" / f"{script_name}.lua"
        if not script_path.exists():
            raise FileNotFoundError(f"Lua script not found: {script_path}")
        cmd = [self._lua_bin, str(script_path)]
        if args:
            cmd.extend(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + result.stderr

    def run_stream(self, script_name: str, args: list[str] = None):
        if not self._lua_bin:
            raise RuntimeError("Lua interpreter not found.")
        script_path = BASE / "scripts" / f"{script_name}.lua"
        cmd = [self._lua_bin, str(script_path)]
        if args:
            cmd.extend(args)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
