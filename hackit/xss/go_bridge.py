import os, sys
import subprocess
import json
import platform
from typing import Dict, Any, List

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        exe = '.exe' if platform.system() == 'Windows' else ''
        self.binary_name = f'worker{exe}'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.source_path = os.path.join(self.go_dir, 'main.go')

    @property
    def available(self) -> bool:
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def ensure_compiled(self) -> bool:
        if os.path.exists(self.binary_path):
            src_mtime = os.path.getmtime(self.source_path)
            bin_mtime = os.path.getmtime(self.binary_path)
            if src_mtime <= bin_mtime:
                return True
        try:
            subprocess.run(['go', 'build', '-o', self.binary_name, '.'], cwd=self.go_dir, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[Go Build Error] {e.stderr}", file=sys.stderr)
            return False

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        payload_file = os.path.join(self.base_dir, 'payload.txt')
        cmd = [self.binary_path, '-url', url]
        if kwargs.get('timeout'):
            cmd.extend(['-timeout', str(kwargs['timeout'])])
        if kwargs.get('method'):
            cmd.extend(['-method', kwargs['method']])
        if os.path.exists(payload_file):
            cmd.extend(['-payloads', payload_file])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.get('timeout', 30) + 15)
            if result.stdout:
                return json.loads(result.stdout)
            return [{"error": "empty response"}]
        except subprocess.TimeoutExpired:
            return [{"error": "Go engine timed out"}]
        except Exception as e:
            return [{"error": str(e)}]
