import os
import subprocess
import json
import platform
import sys
from typing import Dict, Any, List


class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        exe = '.exe' if platform.system() == 'Windows' else ''
        self.binary_name = f'worker{exe}'
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
        try:
            os.makedirs(os.path.join(self.go_dir, 'bin'), exist_ok=True)
            subprocess.run(
                ['go', 'build', '-o', self.binary_path, '.'],
                cwd=self.go_dir, check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[Go Build Error] {e.stderr.decode() if e.stderr else e}", file=sys.stderr)
            return False

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        cmd = [self.binary_path, '-u', url]

        # Complete flag mapping: every Options field in engine.go
        flag_map = {
            'data': '-data',
            'cookie': '-cookie',
            'header': '-header',
            'agent': '-agent',
            'referer': '-referer',
            'method': '-method',
            'timeout': '-timeout',
            'proxy': '-proxy',
            'follow_redirect': '-follow-redirect',
            'mode': '-mode',
            'risk_level': '-risk-level',
            'depth': '-depth',
            'threads': '-threads',
            'delay': '-delay',
            'randomize_case': '-randomize-case',
            'tamper': '-tamper',
            'encode': '-encode',
            'bypass_waf': '-bypass-waf',
            'stealth': '-stealth',
            'fingerprint': '-fingerprint',
            'banner_grab': '-banner-grab',
            'os_detect': '-os-detect',
            'waf_detect': '-waf-detect',
            'smart_diff': '-smart-diff',
            'baseline': '-baseline',
            'tech_detect': '-tech-detect',
            'list_dbs': '-list-dbs',
            'list_tables': '-list-tables',
            'list_columns': '-list-columns',
            'database': '-db',
            'table': '-table',
            'column': '-column',
            'schema': '-schema',
            'count_rows': '-count-rows',
            'search': '-search',
            'dump_table': '-dump-table',
            'dump_all': '-dump-all',
            'priv_esc': '-priv-esc',
            'os_access': '-os-access',
            'exfil_dns': '-exfil-dns',
            'exfil_http': '-exfil-http',
            'no_color': '-no-color',
            'verbose': '-verbose',
            'retry': '-retry',
            'output_format': '-output-format',
        }

        for key, val in kwargs.items():
            if key not in flag_map:
                continue
            flag = flag_map[key]

            # Skip empty default values (tuple/list)
            if isinstance(val, (tuple, list)):
                if len(val) == 0:
                    continue
                # Join tuples to comma-separated for Go
                cmd.extend([flag, ','.join(val)])
            elif isinstance(val, bool):
                if val:
                    cmd.append(flag)
            elif isinstance(val, int):
                # Skip zero defaults that match Go's zero-value
                if val == 0 and key in ('delay', 'verbose', 'retry'):
                    continue
                # Skip default values that Go already has
                if key == 'timeout' and val == 10:
                    continue
                if key == 'threads' and val == 10:
                    continue
                if key == 'depth' and val == 2:
                    continue
                if key == 'risk_level' and val == 1:
                    continue
                cmd.extend([flag, str(val)])
            elif isinstance(val, str) and val:
                # Skip defaults that match Go's built-in defaults
                if key == 'agent' and val == 'HackIT/4.0':
                    continue
                if key == 'method' and val == 'GET':
                    continue
                if key == 'output_format' and val == 'json':
                    continue
                cmd.extend([flag, val])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        import threading

        def stream_stderr(pipe):
            for line in pipe:
                print(line, end='', file=sys.stderr, flush=True)

        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        stdout_content = []
        if process.stdout:
            for line in process.stdout:
                stdout_content.append(line)

        process.wait()
        stderr_thread.join()

        if process.returncode != 0 and not stdout_content:
            return [{"error": f"Go engine exited with code {process.returncode}"}]

        if not stdout_content:
            return []

        try:
            for line in reversed(stdout_content):
                line = line.strip()
                if line.startswith('[') or line.startswith('{'):
                    return json.loads(line)
            return [{"error": "No JSON output found in stdout"}]
        except json.JSONDecodeError as e:
            raw = ''.join(stdout_content)
            return [{"error": f"JSON parse error: {e}\nRaw: {raw[:500]}"}]
