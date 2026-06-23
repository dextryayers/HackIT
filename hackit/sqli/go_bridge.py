"""
Go Engine Bridge - Communication between Python and Go SQLi engine
Shares flag mapping and parsing logic with gui.py GoEngine.
"""

import os
import subprocess
import json
import platform
import sys
import threading
from typing import Dict, Any, List, Optional, Callable

GO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'go')
BINARY_NAME = f'worker{".exe" if platform.system() == "Windows" else ""}'
BINARY_PATH = os.path.join(GO_DIR, 'bin', BINARY_NAME)

# Shared flag map: Python kwarg → Go CLI flag
FLAG_MAP = {
    'database': '--db',
    'columns': '--column',
    'dump_table': '--dump-table',
    'list_dbs': '--list-dbs',
    'list_tables': '--list-tables',
    'list_columns': '--list-columns',
    'dump_all': '--dump-all',
    'risk_level': '--risk-level',
    'follow_redirect': '--follow-redirect',
    'randomize_case': '--randomize-case',
    'bypass_waf': '--bypass-waf',
    'os_detect': '--os-detect',
    'waf_detect': '--waf-detect',
    'smart_diff': '--smart-diff',
    'tech_detect': '--tech-detect',
    'banner_grab': '--banner-grab',
    'priv_esc': '--priv-esc',
    'os_access': '--os-access',
    'exfil_dns': '--exfil-dns',
    'exfil_http': '--exfil-http',
    'no_color': '--no-color',
    'output_format': '--output-format',
    'crawl_depth': '--crawl-depth',
    'crawl_threads': '--crawl-threads',
    'crawl_extract': '--crawl-extract',
    'crawl_sensitive': '--crawl-sensitive',
    'crawl_procs': '--crawl-procs',
    'crawl_views': '--crawl-views',
    'crawl_indexes': '--crawl-indexes',
    'crawl_system': '--crawl-system',
    'crawl_output': '--crawl-output',
    'crawl_report': '--crawl-report',
    'count_rows': '--count-rows',
    'extract_technique': '--extract-technique',
    'extract_charset': '--extract-charset',
    'extract_workers': '--extract-workers',
    'extract_batch': '--extract-batch',
    'network_scan': '--network-scan',
    'scan_target': '--scan-target',
    'scan_ports': '--scan-ports',
    'auth_bypass': '--auth-bypass',
    'auth_user': '--auth-user',
    'auth_pass': '--auth-pass',
    'file_read': '--file-read',
    'file_write': '--file-write',
    'file_exec': '--file-exec',
    'oob_channel': '--oob-channel',
    'oob_domain': '--oob-domain',
}

BOOL_FLAGS = frozenset({
    'follow_redirect', 'randomize_case', 'bypass_waf', 'fingerprint',
    'banner_grab', 'os_detect', 'waf_detect', 'smart_diff', 'baseline',
    'tech_detect', 'list_dbs', 'list_tables', 'list_columns', 'schema',
    'count_rows', 'dump_all', 'priv_esc', 'os_access', 'exfil_dns',
    'exfil_http', 'no_color', 'crawl_extract', 'crawl_sensitive',
    'crawl_procs', 'crawl_views', 'crawl_indexes', 'crawl_system',
    'network_scan', 'auth_bypass', 'stealth',
})

STRING_FLAGS = frozenset({
    'data', 'cookie', 'header', 'agent', 'referer', 'method',
    'proxy', 'mode', 'tamper', 'encode', 'database', 'table',
    'column', 'search', 'dump_table', 'crawl_mode', 'crawl_output',
    'crawl_report', 'extract_technique', 'extract_charset',
    'scan_target', 'scan_ports', 'auth_user', 'auth_pass',
    'file_read', 'file_write', 'file_exec', 'oob_channel', 'oob_domain',
    'output_format',
})

INT_FLAGS = frozenset({
    'timeout', 'risk_level', 'depth', 'threads', 'delay',
    'verbose', 'retry', 'crawl_depth', 'crawl_threads',
    'extract_workers', 'extract_batch',
})


def build_args(url, verbose_lvl=2, **kwargs) -> List[str]:
    args = [BINARY_PATH, '-u', url]
    if verbose_lvl:
        args.extend(['--verbose', str(verbose_lvl)])
    for k, v in kwargs.items():
        if v is None or v is False:
            continue
        flag = FLAG_MAP.get(k, f"--{k.replace('_', '-')}")
        if k in BOOL_FLAGS:
            if v:
                args.append(flag)
        elif k in INT_FLAGS:
            args.extend([flag, str(int(v))])
        elif k in STRING_FLAGS:
            val = str(v)
            if val:
                args.extend([flag, val])
        elif isinstance(v, bool):
            if v:
                args.append(flag)
        elif isinstance(v, int):
            args.extend([flag, str(v)])
        elif isinstance(v, str):
            if v:
                args.extend([flag, v])
        elif isinstance(v, (tuple, list)):
            for item in v:
                s = str(item)
                if s:
                    args.extend([flag, s])
    return args


def parse_stdout(raw: str) -> Optional[List[Dict[str, Any]]]:
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    for line in reversed(raw.split('\n')):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    try:
        return [json.loads(raw)]
    except (json.JSONDecodeError, TypeError):
        pass
    return None


class GoEngine:
    def __init__(self):
        self.binary_path = BINARY_PATH
        self._proc = None

    @property
    def available(self) -> bool:
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            return True
        except Exception:
            return os.path.exists(self.binary_path)

    def ensure_compiled(self) -> bool:
        if os.path.exists(self.binary_path):
            return True
        try:
            os.makedirs(os.path.join(GO_DIR, 'bin'), exist_ok=True)
            subprocess.run(
                ['go', 'build', '-o', self.binary_path, '.'],
                cwd=GO_DIR, check=True, capture_output=True, timeout=120)
            return True
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            print(f"[Go Build Error] {err}", file=sys.stderr)
            if "go.mod" in err:
                try:
                    subprocess.run(['go', 'mod', 'init', 'hackit/sqli/go'],
                                   cwd=GO_DIR, check=True, capture_output=True)
                    subprocess.run(['go', 'mod', 'tidy'],
                                   cwd=GO_DIR, check=True, capture_output=True)
                    subprocess.run(
                        ['go', 'build', '-o', self.binary_path, '.'],
                        cwd=GO_DIR, check=True, capture_output=True, timeout=120)
                    return True
                except Exception:
                    return False
            return False
        except Exception:
            return False

    def run(self, url: str, timeout: int = 300, **kwargs) -> List[Dict[str, Any]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        args = build_args(url, verbose_lvl=0, **kwargs)
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout)
            if r.returncode != 0 and not r.stdout.strip():
                err = r.stderr.strip()[:300] if r.stderr.strip() else \
                      f"exit code {r.returncode}"
                return [{"error": err}]
            result = parse_stdout(r.stdout)
            return result if result is not None else \
                   [{"error": "No JSON output from Go engine"}]
        except subprocess.TimeoutExpired:
            return [{"error": "Go engine timed out"}]
        except Exception as e:
            return [{"error": str(e)}]

    def run_stream(self, url: str, on_verbose: Optional[Callable] = None,
                   stop_event: Optional[threading.Event] = None,
                   **kwargs) -> Optional[List[Dict[str, Any]]]:
        if not self.ensure_compiled():
            return [{"error": "Failed to compile Go engine"}]

        args = build_args(url, verbose_lvl=2, **kwargs)
        try:
            self._proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
            proc = self._proc

            def read_stderr():
                try:
                    for line in iter(proc.stderr.readline, ''):
                        if not line:
                            break
                        line = line.rstrip('\n\r')
                        if on_verbose:
                            on_verbose(line)
                except ValueError:
                    pass

            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            stdout_data = []
            while True:
                if stop_event and stop_event.is_set():
                    proc.kill()
                    break
                line = proc.stdout.readline()
                if not line:
                    break
                stdout_data.append(line.rstrip('\n\r'))

            proc.wait(timeout=10)
            stderr_thread.join(timeout=5)

            full = ''.join(stdout_data)
            return parse_stdout(full)
        except Exception:
            return None
        finally:
            self._proc = None

    def kill(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None

    # ── High-level helpers ────────────────────────────────────

    def crawl(self, url: str, mode: str = "full", **kwargs) -> List[Dict[str, Any]]:
        return self.run(url, crawl_mode=mode, **kwargs)

    def extract(self, url: str, technique: str = "auto", **kwargs) -> List[Dict[str, Any]]:
        return self.run(url, extract_technique=technique, **kwargs)

    def network_scan(self, target: str, ports: str = None, **kwargs) -> List[Dict[str, Any]]:
        params = {'network_scan': True, 'scan_target': target}
        if ports:
            params['scan_ports'] = ports
        params.update(kwargs)
        return self.run(target, **params)

    def file_operation(self, url: str, operation: str, path: str,
                       content: str = None, **kwargs) -> List[Dict[str, Any]]:
        flag_map = {'read': 'file_read', 'write': 'file_write', 'exec': 'file_exec'}
        flag = flag_map.get(operation, 'file_read')
        params = {flag: path if operation != 'write' else content}
        params.update(kwargs)
        return self.run(url, **params)

    def auth_bypass(self, url: str, username: str = "admin",
                    password: str = "password", **kwargs) -> List[Dict[str, Any]]:
        params = {'auth_bypass': True, 'auth_user': username, 'auth_pass': password}
        params.update(kwargs)
        return self.run(url, **params)

    # ── Batch Operations ──────────────────────────────────────

    def batch_scan(self, urls: List[str], **kwargs) -> Dict[str, Any]:
        return {url: self.run(url, **kwargs) for url in urls}

    def batch_crawl(self, urls: List[str], mode: str = "full") -> Dict[str, Any]:
        return {url: self.crawl(url, mode) for url in urls}

    # ── Daemon Mode ───────────────────────────────────────────

    def start_daemon(self, host: str = "127.0.0.1", port: int = 8765):
        import socket
        import atexit

        self.ensure_compiled()
        proc = subprocess.Popen(
            [self.binary_path, '--daemon', f'--listen={host}:{port}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        atexit.register(proc.kill)

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
