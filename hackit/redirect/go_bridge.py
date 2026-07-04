import os
import subprocess
import json
import platform
import signal
from typing import Dict, Any, List


class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.binary_name = 'worker.exe' if platform.system() == 'Windows' else 'worker'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.source_dir = self.go_dir
        self._compiled = False

    @property
    def available(self) -> bool:
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True, timeout=10)
            return True
        except Exception:
            return False

    def ensure_compiled(self) -> bool:
        if self._compiled and os.path.exists(self.binary_path):
            return True
        if os.path.exists(self.binary_path):
            self._compiled = True
            return True
        try:
            subprocess.run(
                ['go', 'build', '-buildvcs=false', '-tags=netcgo', '-o', self.binary_name, '.'],
                cwd=self.go_dir, check=True, capture_output=True, timeout=60
            )
            self._compiled = True
            return True
        except Exception:
            return False

    def run(self, url: str, timeout: int = 15) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        try:
            proc = subprocess.run(
                [self.binary_path, '--json', '-url', url, '-timeout', str(timeout)],
                capture_output=True, text=True, timeout=timeout + 30
            )
            if proc.returncode != 0:
                return [{"error": proc.stderr.strip() or "Go engine exited with code " + str(proc.returncode)}]
            if not proc.stdout.strip():
                return [{"error": "Empty output from Go engine"}]
            return json.loads(proc.stdout)
        except subprocess.TimeoutExpired:
            return [{"error": "Go engine timed out"}]
        except json.JSONDecodeError as e:
            return [{"error": f"Invalid JSON output: {e}"}]
        except Exception as e:
            return [{"error": str(e)}]
