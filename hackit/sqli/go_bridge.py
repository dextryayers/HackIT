"""
Go Engine Bridge - Advanced communication between Python and Go SQLi engine
Supports all engine features: crawl, extract, scan, bypass, file ops, OOB
"""

import os
import subprocess
import json
import platform
import sys
import threading
from typing import Dict, Any, List, Optional, Callable


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
            result = subprocess.run(
                ['go', 'build', '-o', self.binary_path, '.'],
                cwd=self.go_dir, check=True, capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            print(f"[Go Build Error] {err}", file=sys.stderr)
            # Try with go mod init if needed
            if "go.mod" in err:
                try:
                    subprocess.run(['go', 'mod', 'init', 'hackit/sqli/go'],
                                   cwd=self.go_dir, check=True, capture_output=True)
                    subprocess.run(['go', 'mod', 'tidy'],
                                   cwd=self.go_dir, check=True, capture_output=True)
                    subprocess.run(
                        ['go', 'build', '-o', self.binary_path, '.'],
                        cwd=self.go_dir, check=True, capture_output=True
                    )
                    return True
                except Exception:
                    return False
            return False

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        cmd = [self.binary_path, '-u', url]

        # Complete flag map matching all Options fields
        flag_map = {
            'data': '-data', 'cookie': '-cookie', 'header': '-header',
            'agent': '-agent', 'referer': '-referer', 'method': '-method',
            'timeout': '-timeout', 'proxy': '-proxy',
            'follow_redirect': '-follow-redirect',
            'mode': '-mode', 'risk_level': '-risk-level',
            'depth': '-depth', 'threads': '-threads', 'delay': '-delay',
            'randomize_case': '-randomize-case', 'tamper': '-tamper',
            'encode': '-encode', 'bypass_waf': '-bypass-waf', 'stealth': '-stealth',
            'fingerprint': '-fingerprint', 'banner_grab': '-banner-grab',
            'os_detect': '-os-detect', 'waf_detect': '-waf-detect',
            'smart_diff': '-smart-diff', 'baseline': '-baseline',
            'tech_detect': '-tech-detect',
            'list_dbs': '-list-dbs', 'list_tables': '-list-tables',
            'list_columns': '-list-columns', 'database': '-db',
            'table': '-table', 'column': '-column', 'schema': '-schema',
            'count_rows': '-count-rows', 'search': '-search',
            'dump_table': '-dump-table', 'dump_all': '-dump-all',
            'priv_esc': '-priv-esc', 'os_access': '-os-access',
            'exfil_dns': '-exfil-dns', 'exfil_http': '-exfil-http',
            'no_color': '-no-color', 'verbose': '-verbose', 'retry': '-retry',
            'output_format': '-output-format',

            # Crawl flags
            'crawl': '-crawl', 'crawl_depth': '-crawl-depth',
            'crawl_threads': '-crawl-threads',
            'crawl_extract': '-crawl-extract',
            'crawl_sensitive': '-crawl-sensitive',
            'crawl_procs': '-crawl-procs', 'crawl_views': '-crawl-views',
            'crawl_indexes': '-crawl-indexes', 'crawl_system': '-crawl-system',
            'crawl_output': '-crawl-output', 'crawl_report': '-crawl-report',

            # Extraction flags
            'extract_technique': '-extract-technique',
            'extract_charset': '-extract-charset',
            'extract_workers': '-extract-workers',
            'extract_batch': '-extract-batch',

            # Network scan
            'network_scan': '-network-scan', 'scan_target': '-scan-target',
            'scan_ports': '-scan-ports',

            # Auth bypass
            'auth_bypass': '-auth-bypass', 'auth_user': '-auth-user',
            'auth_pass': '-auth-pass',

            # File operations
            'file_read': '-file-read', 'file_write': '-file-write',
            'file_exec': '-file-exec',

            # OOB
            'oob_channel': '-oob-channel', 'oob_domain': '-oob-domain',
        }

        for key, val in kwargs.items():
            if key not in flag_map:
                continue
            flag = flag_map[key]

            if isinstance(val, (tuple, list)):
                if len(val) == 0:
                    continue
                cmd.extend([flag, ','.join(str(v) for v in val)])
            elif isinstance(val, bool):
                if val:
                    cmd.append(flag)
            elif isinstance(val, int):
                defaults = {'delay': 0, 'verbose': 1, 'retry': 3,
                           'timeout': 10, 'threads': 10, 'depth': 2,
                           'risk_level': 1, 'crawl_depth': 5,
                           'crawl_threads': 10, 'extract_workers': 5,
                           'extract_batch': 100}
                if val != defaults.get(key, -1):
                    cmd.extend([flag, str(val)])
            elif isinstance(val, str) and val:
                defaults = {'agent': 'HackIT/4.0', 'method': 'GET',
                           'output_format': 'json', 'crawl_output': 'crawl_output',
                           'crawl_report': 'json', 'extract_charset': 'common',
                           'extract_technique': 'auto', 'oob_channel': 'dns',
                           'auth_user': 'admin', 'auth_pass': 'password'}
                if val != defaults.get(key, None):
                    cmd.extend([flag, val])

        return self._execute(cmd)

    def crawl(self, url: str, mode: str = "full", **kwargs) -> List[Dict[str, Any]]:
        """Run crawl mode with all options"""
        params = {'crawl': mode, **kwargs}
        return self.run(url, **params)

    def extract(self, url: str, technique: str = "auto", **kwargs) -> List[Dict[str, Any]]:
        """Run extraction with specific technique"""
        params = {'extract_technique': technique, **kwargs}
        return self.run(url, **params)

    def network_scan(self, target: str, ports: str = None, **kwargs) -> List[Dict[str, Any]]:
        """Run network scan via SQLi"""
        params = {'network_scan': True, 'scan_target': target}
        if ports:
            params['scan_ports'] = ports
        params.update(kwargs)
        return self.run(target, **params)

    def file_operation(self, url: str, operation: str, path: str,
                       content: str = None, **kwargs) -> List[Dict[str, Any]]:
        """File read/write/exec operations"""
        flag_map = {'read': 'file_read', 'write': 'file_write', 'exec': 'file_exec'}
        flag = flag_map.get(operation, 'file_read')
        params = {flag: path if operation != 'write' else content}
        params.update(kwargs)
        return self.run(url, **params)

    def auth_bypass(self, url: str, username: str = "admin",
                     password: str = "password", **kwargs) -> List[Dict[str, Any]]:
        """Auth bypass testing"""
        params = {
            'auth_bypass': True, 'auth_user': username, 'auth_pass': password
        }
        params.update(kwargs)
        return self.run(url, **params)

    # ── Batch Operations ──────────────────────────────────────────

    def batch_scan(self, urls: List[str], **kwargs) -> Dict[str, Any]:
        """Scan multiple URLs"""
        results = {}
        for url in urls:
            results[url] = self.run(url, **kwargs)
        return results

    def batch_crawl(self, urls: List[str], mode: str = "full") -> Dict[str, Any]:
        """Crawl multiple targets"""
        results = {}
        for url in urls:
            results[url] = self.crawl(url, mode)
        return results

    # ── Internal ──────────────────────────────────────────────────

    def _execute(self, cmd: List[str]) -> List[Dict[str, Any]]:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

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

    # ── Node/Subprocess Management ────────────────────────────────

    def start_daemon(self, host: str = "127.0.0.1", port: int = 8765):
        """Start Go engine as a persistent daemon process"""
        import socket
        import atexit

        self.ensure_compiled()

        # Start process in daemon mode
        proc = subprocess.Popen(
            [self.binary_path, '--daemon', f'--listen={host}:{port}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        atexit.register(proc.kill)

        # Connect socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        def send_command(cmd: dict) -> dict:
            sock.send(json.dumps(cmd).encode() + b'\n')
            response = sock.recv(65536).decode()
            return json.loads(response)

        self._daemon = {'socket': sock, 'send': send_command}
        return self._daemon

    def stop_daemon(self):
        if hasattr(self, '_daemon'):
            self._daemon['socket'].close()
