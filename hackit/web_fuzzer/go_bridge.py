import os
import subprocess
import json
import sys
import platform
from typing import Dict, Any, List

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.binary_name = 'worker.exe' if platform.system() == 'Windows' else 'worker'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.source_path = os.path.join(self.go_dir, 'main.go')

    @property
    def available(self) -> bool:
        """Check if Go is installed."""
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def ensure_compiled(self) -> bool:
        """Compile the Go binary if it doesn't exist or is outdated."""
        if not os.path.exists(self.binary_path) or \
           os.path.getmtime(self.source_path) > os.path.getmtime(self.binary_path):
            try:
                # Build the binary
                cmd = ['go', 'build', '-o', self.binary_name, '.']
                subprocess.run(cmd, cwd=self.go_dir, check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Compilation error: {e.stderr.decode()}")
                return False
        return True

    def run(self, url: str, wordlist: str, extensions: str, status: str, threads: int, bypass: bool) -> List[Dict[str, Any]]:
        """Run the Go worker."""
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        cmd = [
            self.binary_path,
            '-url', url,
            '-wordlist', wordlist,
            '-extensions', extensions,
            '-status', status,
            '-threads', str(threads)
        ]
        if bypass:
            cmd.append('-bypass')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            # The Go program outputs a JSON array
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            return [{"error": f"Execution failed: {e.stderr}"}]
        except json.JSONDecodeError:
            return [{"error": "Failed to parse Go output", "raw": result.stdout}]
