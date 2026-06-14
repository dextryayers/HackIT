import os
import subprocess
import shutil
from pathlib import Path

BASE = Path(__file__).parent


class RubyEngine:
    def __init__(self):
        self._ruby_bin = shutil.which("ruby")

    def available(self) -> bool:
        return self._ruby_bin is not None

    def list_scripts(self) -> list[str]:
        scripts_dir = BASE / "scripts"
        if not scripts_dir.exists():
            return []
        return [f.stem for f in sorted(scripts_dir.glob("*.rb"))]

    def run(self, script_name: str, args: list[str] = None) -> str:
        if not self._ruby_bin:
            raise RuntimeError("Ruby interpreter not found. Install ruby.")
        script_path = BASE / "scripts" / f"{script_name}.rb"
        if not script_path.exists():
            raise FileNotFoundError(f"Ruby script not found: {script_path}")
        cmd = [self._ruby_bin, str(script_path)]
        if args:
            cmd.extend(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout + result.stderr

    def run_stream(self, script_name: str, args: list[str] = None):
        if not self._ruby_bin:
            raise RuntimeError("Ruby interpreter not found.")
        script_path = BASE / "scripts" / f"{script_name}.rb"
        cmd = [self._ruby_bin, str(script_path)]
        if args:
            cmd.extend(args)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    def run_msf_rpc(self, workspace: str = "default", resource: str = None) -> str:
        if not self._ruby_bin:
            raise RuntimeError("Ruby interpreter not found.")
        script_path = BASE / "scripts" / "msf_rpc_bridge.rb"
        cmd = [self._ruby_bin, str(script_path), "--workspace", workspace]
        if resource:
            cmd.extend(["--resource", resource])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr
