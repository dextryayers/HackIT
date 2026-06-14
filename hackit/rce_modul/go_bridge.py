import os, sys, subprocess, json, platform, shutil
from typing import List, Dict, Any, Optional

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        exe = '.exe' if platform.system() == 'Windows' else ''
        self.binary_name = f'rce_engine{exe}'
        self.binary_path = os.path.join(self.go_dir, 'bin', self.binary_name)
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
            os.makedirs(os.path.join(self.go_dir, 'bin'), exist_ok=True)
            result = subprocess.run(
                ['go', 'build', '-o', self.binary_path, '.'],
                cwd=self.go_dir, check=True, capture_output=True, text=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[Go Build Error] {e.stderr}", file=sys.stderr)
            return False

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]
        cmd = [self.binary_path, '-u', url]
        flag_map = {
            'cmd': '-c', 'data': '-d', 'param': '-p', 'method': '-m',
            'timeout': '--timeout', 'proxy': '--proxy', 'cookie': '--cookie',
            'ua': '--ua', 'oob': '--oob',
        }
        for key, flag in flag_map.items():
            val = kwargs.get(key)
            if val:
                cmd.extend([flag, str(val)])
        if kwargs.get('detect', False):
            cmd.append('--detect')
        if kwargs.get('exploit', False):
            cmd.append('--exploit')
        if kwargs.get('blind', False):
            cmd.append('--blind')
        if kwargs.get('verbose', False):
            cmd.append('--verbose')
        if kwargs.get('json', True):
            cmd.append('--json')
        if kwargs.get('all_params', False):
            cmd.append('--all')
        if kwargs.get('threads'):
            cmd.extend(['-t', str(kwargs['threads'])])
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1
            )
            stdout, stderr = process.communicate(timeout=kwargs.get('timeout', 30) + 10)
            if stderr:
                print(f"[Go Engine] {stderr}", file=sys.stderr)
            if kwargs.get('json', True):
                try:
                    return json.loads(stdout)
                except json.JSONDecodeError:
                    return self._parse_output(stdout)
            else:
                return self._parse_output(stdout)
        except subprocess.TimeoutExpired:
            return [{"error": "Go engine timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('|')
            if len(parts) >= 3:
                if parts[0] == 'VULNERABLE' and len(parts) >= 6:
                    results.append({
                        'vulnerable': True,
                        'url': parts[1], 'parameter': parts[2],
                        'technique': parts[3], 'confidence': float(parts[4]),
                        'output': parts[5], 'engine': 'go'
                    })
                elif parts[0] == 'SAFE':
                    results.append({
                        'vulnerable': False, 'url': parts[1], 'engine': 'go'
                    })
                elif parts[0] == 'OUTPUT' and len(parts) >= 2:
                    results.append({
                        'vulnerable': True, 'output': parts[1], 'engine': 'go',
                        'technique': 'exploit'
                    })
        return results if results else [{'vulnerable': False, 'url': '', 'engine': 'go', 'note': 'parse_fallback'}]
