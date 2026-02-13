import os
import subprocess
import json
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
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            return True
        except:
            return False

    def ensure_compiled(self) -> bool:
        if not os.path.exists(self.binary_path) or \
           os.path.getmtime(self.source_path) > os.path.getmtime(self.binary_path):
            try:
                subprocess.run(['go', 'build', '-o', self.binary_name, '.'], cwd=self.go_dir, check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return True

    def run(self, url: str) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        try:
            result = subprocess.run(
                [self.binary_path, '-url', url],
                capture_output=True, text=True, check=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            return [{"error": str(e)}]
