import os
import subprocess
import json
import platform
from typing import Dict, Any, List

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.binary_name = 'fuzzer.exe' if platform.system() == 'Windows' else 'fuzzer'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)

    def ensure_compiled(self, force: bool = False) -> bool:
        if force or not os.path.exists(self.binary_path):
            try:
                # High-Performance Go Build: Stripped and Optimized
                subprocess.run(['go', 'build', '-ldflags="-s -w"', '-o', self.binary_name, '.'], 
                             cwd=self.go_dir, check=True, capture_output=True)
                return True
            except Exception as e:
                print(f"[!] Go Compilation Error: {e}")
                return False
        return True

    def shape(self, intel_json: str) -> List[Dict[str, Any]]:
        """Bridge between Rust and C++ via Go Shaper."""
        if not self.ensure_compiled():
            return []

        try:
            cmd = [self.binary_path, '-intel', intel_json]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # The Go program outputs a JSON array on stdout, and status messages on stderr
            return json.loads(result.stdout)
        except Exception as e:
            return [{"error": str(e)}]

    def harvest(self, domain: str) -> List[str]:
        """High-performance parameter discovery from multiple sources via Go."""
        if not self.ensure_compiled():
            return []
        try:
            cmd = [self.binary_path, '-harvest', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # Standard lines of URLs
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception as e:
            print(f"[!] Go Harvester Error: {e}")
            return []
