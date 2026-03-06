import os
import subprocess
import json
import sys
import platform
from typing import Dict, Any

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.rust_dir = os.path.join(self.go_dir, 'rust_engine')
        self.binary_name = 'tech_hunter.exe' if platform.system() == 'Windows' else 'tech_hunter'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.go_source = os.path.join(self.go_dir, 'main.go')
        
        # Rust lib path
        if platform.system() == 'Windows':
            self.rust_lib = os.path.join(self.rust_dir, 'target', 'release', 'tech_hunter_rust.dll')
        else:
            self.rust_lib = os.path.join(self.rust_dir, 'target', 'release', 'libtech_hunter_rust.so')

    @property
    def available(self) -> bool:
        """Check if Go and Rust are installed."""
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            subprocess.run(['cargo', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def ensure_compiled(self) -> bool:
        """Compile Rust core and then Go orchestrator."""
        # 1. Compile Rust Core if needed
        if not os.path.exists(self.rust_lib):
            try:
                print("[*] Compiling Rust Core Engine (High Performance)...")
                subprocess.run(['cargo', 'build', '--release'], cwd=self.rust_dir, check=True)
            except subprocess.CalledProcessError as e:
                print(f"[!] Rust compilation error: {e}")
                return False

        # 2. Compile Go Orchestrator if needed
        if not os.path.exists(self.binary_path) or \
           os.path.getmtime(self.go_source) > os.path.getmtime(self.binary_path):
            try:
                print("[*] Compiling Go Orchestrator...")
                cmd = ['go', 'build', '-o', self.binary_name, '.']
                subprocess.run(cmd, cwd=self.go_dir, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"[!] Go compilation error: {e.stderr.decode()}")
                return False
        return True

    def run(self, **kwargs) -> Dict[str, Any]:
        """Run the Go tech hunter which orchestrates Rust and Python."""
        if not self.ensure_compiled():
            return {"error": "Failed to compile engines"}

        cmd = [self.binary_path]

        # Mapping Python kwargs to Go CLI flags
        mapping = {
            'url': '-u',
            'target_list': '-l',
            'cidr': '--cidr',
            'port': '-p',
            'http': '--http',
            'https': '--https',
            'threads': '--threads',
            'timeout': '--timeout',
            'retries': '--retries',
            'rate': '--rate',
            'delay': '--delay',
            'proxy': '--proxy',
            'random_agent': '--random-agent',
            'header': '--header',
            'profile': '--profile',
            'tech_only': '--tech-only',
            'headers_only': '--headers-only',
            'no_body': '--no-body',
            'detect_waf': '--detect-waf',
            'detect_cdn': '--detect-cdn',
            'detect_cms': '--detect-cms',
            'detect_framework': '--detect-framework',
            'confidence': '--confidence',
            'heuristic': '--heuristic',
            'cve': '--cve',
            'risk_score': '--risk-score',
            'fingerprint_db': '--fingerprint-db',
            'update_signature': '--update-signature',
            'output': '-o',
            'format': '--format',
            'pretty': '--pretty',
            'deep': '--deep',
            'favicon': '--favicon',
            'silent': '--silent',
            'raw': '--raw',
            'report_html': '--report-html',
            'deep_scan': '--deep-scan',
            'path': '--path',
            'brutepath': '--brutepath',
            'favicon_hash': '--favicon-hash',
            'tls_info': '--tls-info',
            'http2': '--http2',
            'follow_redirect': '--follow-redirect',
            'verbose': '-v',
            'debug': '--debug',
            'trace': '--trace',
            'dry_run': '--dry-run',
        }

        for key, val in kwargs.items():
            if key in mapping:
                flag = mapping[key]
                if isinstance(val, bool):
                    if val:
                        cmd.append(flag)
                elif val is not None and val != "" and val != 0:
                    cmd.append(flag)
                    cmd.append(str(val))

        try:
            # Using text=False to read as bytes first
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=False,
                bufsize=0
            )
            
            full_stdout = []
            
            # Stream stdout to terminal in real-time
            while True:
                line_bytes = process.stdout.readline()
                if not line_bytes and process.poll() is not None:
                    break
                if line_bytes:
                    line = line_bytes.decode('utf-8', errors='replace')
                    full_stdout.append(line)
                    # If it's NOT part of the JSON markers, print it to terminal
                    if "---JSON_START---" not in line and "---JSON_END---" not in line:
                        # Only print if we are not in JSON mode (determined by flags)
                        if '-o' not in cmd and '--format json' not in ' '.join(cmd):
                            sys.stdout.write(line)
                            sys.stdout.flush()
            
            stdout = "".join(full_stdout)
            stderr_bytes = process.stderr.read()
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            
            if process.returncode != 0:
                # If there's an error, still try to find JSON if possible, otherwise return error
                if "---JSON_START---" not in stdout:
                    return {"error": f"Go engine failed: {stderr}"}

            if not stdout.strip():
                return {"error": "Go engine returned empty output"}

            # Extract JSON between markers
            if "---JSON_START---" in stdout:
                try:
                    json_part = stdout.split("---JSON_START---")[1].split("---JSON_END---")[0].strip()
                    return json.loads(json_part)
                except (IndexError, json.JSONDecodeError) as e:
                    return {"error": f"Failed to parse JSON markers: {str(e)}"}
            else:
                # Fallback to old behavior if no markers found
                try:
                    return json.loads(stdout.strip())
                except json.JSONDecodeError:
                    return {"error": f"Failed to parse raw output as JSON: {stdout[:200]}"}
        except Exception as e:
            return {"error": f"Bridge error: {str(e)}"}
