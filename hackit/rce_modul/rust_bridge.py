import os, sys, subprocess, json, platform
from typing import List, Dict, Any

class RustEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.rust_dir = os.path.join(self.base_dir, 'rust')
        exe = '.exe' if platform.system() == 'Windows' else ''
        self.binary_name = f'rce_engine{exe}'
        self.binary_path = os.path.join(self.rust_dir, 'target', 'release', self.binary_name)

    @property
    def available(self) -> bool:
        try:
            subprocess.run(['cargo', '--version'], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def ensure_compiled(self) -> bool:
        if os.path.exists(self.binary_path):
            return True
        try:
            os.makedirs(os.path.join(self.rust_dir, 'target', 'release'), exist_ok=True)
            result = subprocess.run(
                ['cargo', 'build', '--release'],
                cwd=self.rust_dir, check=True, capture_output=True, text=True,
                timeout=120
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[Rust Build Error] {e.stderr}", file=sys.stderr)
            return False
        except subprocess.TimeoutExpired:
            print("[Rust Build] Timed out", file=sys.stderr)
            return False

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Rust engine"}]
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
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=kwargs.get('timeout', 30) + 10
            )
            if result.stderr:
                print(f"[Rust Engine] {result.stderr}", file=sys.stderr)
            if kwargs.get('json', True):
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return self._parse_output(result.stdout)
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            return [{"error": "Rust engine timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        results = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('|')
            if parts[0] == 'VULNERABLE' and len(parts) >= 6:
                results.append({
                    'vulnerable': True, 'url': parts[1], 'parameter': parts[2],
                    'technique': parts[3], 'confidence': float(parts[4]),
                    'output': parts[5], 'engine': 'rust'
                })
            elif parts[0] == 'SAFE':
                results.append({'vulnerable': False, 'url': parts[1], 'engine': 'rust'})
        return results if results else [{'vulnerable': False, 'engine': 'rust', 'note': 'parse_fallback'}]
