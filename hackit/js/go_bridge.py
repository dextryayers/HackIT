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
        except Exception:
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

    def run(self, url: str):
        """Runs the Go engine and yields results line-by-line (Streaming)"""
        if not self.ensure_compiled():
            yield {"error": "Failed to compile Go engine"}
            return

        try:
            process = subprocess.Popen(
                [self.binary_path, '-url', url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                # Filter out noise and extract JSON
                if '{' in line:
                    json_str = line[line.find('{'):]
                    if '}' in json_str:
                        json_str = json_str[:json_str.rfind('}')+1]
                        try:
                            yield json.loads(json_str)
                        except:
                            continue
            
            process.stdout.close()
            process.wait()
            
        except Exception as e:
            yield {"error": f"Bridge error: {str(e)}"}
