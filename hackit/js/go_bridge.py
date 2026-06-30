import os
import subprocess
import json
import platform
from typing import Dict, Any, List, Generator

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.binary_name = 'js_hunter.exe' if platform.system() == 'Windows' else 'js_hunter'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)

    @property
    def available(self) -> bool:
        try:
            res = subprocess.run(['go', 'version'], capture_output=True)
            return res.returncode == 0
        except Exception:
            return False

    def ensure_compiled(self) -> bool:
        needs_rebuild = not os.path.exists(self.binary_path)
        if not needs_rebuild:
            bin_mtime = os.path.getmtime(self.binary_path)
            for f in os.listdir(self.go_dir):
                if f.endswith('.go'):
                    if os.path.getmtime(os.path.join(self.go_dir, f)) > bin_mtime:
                        needs_rebuild = True
                        break
        if needs_rebuild:
            try:
                subprocess.run(['go', 'build', '-o', self.binary_name, '.'],
                             cwd=self.go_dir, check=True, capture_output=True)
                return True
            except Exception:
                return False
        return True

    def run(self, url: str, show_code: bool = False, depth: int = 3,
            concurrency: int = 50, timeout: int = 30, delay: int = 0,
            proxy: str = '', crawl: bool = True, js_analysis: bool = True,
            secrets: bool = True, subdomains: bool = True, archive: bool = True,
            brute: bool = True, sourcemap: bool = True, tech: bool = True,
            endpoints: bool = True, network: bool = True, json_out: bool = False,
            rate_limit: int = 0) -> Generator[Dict, None, None]:
        if not self.ensure_compiled():
            yield {"error": "Failed to compile Go engine"}
            return

        try:
            args = [self.binary_path, '-url', url]
            if show_code:
                args.append('-code')
            args.extend(['-depth', str(depth)])
            args.extend(['-concurrency', str(concurrency)])
            args.extend(['-timeout', str(timeout)])
            if delay > 0:
                args.extend(['-delay', str(delay)])
            if proxy:
                args.extend(['-proxy', proxy])
            if not crawl:
                args.append('-crawl=false')
            if not js_analysis:
                args.append('-js=false')
            if not secrets:
                args.append('-secrets=false')
            if not subdomains:
                args.append('-subdomains=false')
            if not archive:
                args.append('-archive=false')
            if not brute:
                args.append('-brute=false')
            if not sourcemap:
                args.append('-sourcemap=false')
            if not tech:
                args.append('-tech=false')
            if not endpoints:
                args.append('-endpoints=false')
            if not network:
                args.append('-network=false')
            if json_out:
                args.append('-json')
            if rate_limit > 0:
                args.extend(['-rate-limit', str(rate_limit)])

            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
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
