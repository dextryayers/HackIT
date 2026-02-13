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

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        # Map Python kwargs to Go flags
        cmd = [self.binary_path, '-u', url]
        
        # Mapping table for flags
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
            'bypass_waf': '-bypass-waf',
            'stealth': '-stealth',
            'fingerprint': '-fingerprint',
            'banner_grab': '-banner-grab',
            'os_detect': '-os-detect',
            'waf_detect': '-waf-detect',
            'list_dbs': '-list-dbs',
            'list_tables': '-list-tables',
            'list_columns': '-list-columns',
            'dump_table': '-dump-table',
            'dump_all': '-dump-all',
            'verbose': '-verbose'
        }

        for key, val in kwargs.items():
            if key in flag_map:
                flag = flag_map[key]
                if isinstance(val, bool):
                    if val:
                        cmd.append(flag)
                elif val is not None:
                    cmd.extend([flag, str(val)])

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Stream stderr in real-time
        import threading
        def stream_stderr(pipe):
            for line in pipe:
                print(line, end='', file=sys.stderr, flush=True)
        
        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        # Capture stdout (JSON result)
        stdout_content = []
        for line in process.stdout:
            stdout_content.append(line)
        
        process.wait()
        stderr_thread.join()

        if process.returncode != 0 and not stdout_content:
            return [{"error": f"Command failed with exit code {process.returncode}"}]
        
        if not stdout_content:
            return []

        try:
            # Find the last line which should be the JSON output
            for line in reversed(stdout_content):
                line = line.strip()
                if line.startswith('[') or line.startswith('{'):
                    return json.loads(line)
            return [{"error": "No JSON output found in stdout"}]
        except json.JSONDecodeError as e:
            return [{"error": f"JSON parse error: {str(e)}\nRaw output: {result.stdout}"}]
