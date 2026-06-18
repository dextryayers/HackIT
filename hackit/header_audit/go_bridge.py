import os
import subprocess
import sys
import shutil
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from hackit.ui import _colored, GREEN, RED, BLUE, CYAN, YELLOW, WHITE, BOLD, DIM

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.source_file = os.path.join(self.go_dir, 'main.go')
        self.binary_name = 'header_audit.exe' if os.name == 'nt' else 'header_audit'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.available = self._check_go_installed()

    def _check_go_installed(self):
        return shutil.which('go') is not None

    def ensure_compiled(self):
        if not self.available:
            return False
        if not os.path.exists(self.source_file):
            return False
        
        needs_compile = False
        if not os.path.exists(self.binary_path):
            needs_compile = True
        else:
            bin_mtime = os.path.getmtime(self.binary_path)
            for root, dirs, files in os.walk(self.go_dir):
                for f in files:
                    if f.endswith('.go'):
                        src_path = os.path.join(root, f)
                        if os.path.getmtime(src_path) > bin_mtime:
                            needs_compile = True
                            break
                if needs_compile:
                    break

        if needs_compile:
            print(_colored("[*] Compiling Go Header Audit Engine...", BLUE))
            try:
                cmd = ['go', 'build', '-o', self.binary_path, '.']
                subprocess.check_call(cmd, cwd=self.go_dir)
                print(_colored("[+] Engine compiled successfully!", GREEN))
                return True
            except subprocess.CalledProcessError as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, url, ndjson=True):
        if not self.ensure_compiled():
            raise RuntimeError("Go engine compilation failed")

        cmd = [self.binary_path, '-u', url]
        if ndjson:
            cmd.append('-ndjson')

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            if ndjson:
                results = {}
                for line in process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        yield obj
                    except json.JSONDecodeError:
                        pass
                
                process.wait()
            else:
                stdout, stderr = process.communicate()
                if process.returncode != 0:
                    yield {'error': stderr.strip()}
                try:
                    yield json.loads(stdout)
                except json.JSONDecodeError:
                    yield {'error': f"Invalid JSON output: {stdout}"}

        except Exception as e:
            yield {'error': str(e)}

    def run_sync(self, url):
        results = list(self.run(url, ndjson=False))
        if results:
            return results[0]
        return {'error': 'No output from engine'}


class RustEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.rust_dir = os.path.join(self.base_dir, 'rust')
        self.tools = self._find_tools()

    def _find_tools(self):
        tools = {}
        # Map: tool name -> (binary basename in Cargo.toml)
        tool_binaries = {
            'inspector': 'header-inspector',
            'tls_scanner': 'tls-scanner',
            'policy_checker': 'policy-checker',
        }
        for name, binary in tool_binaries.items():
            binary_exe = f'{binary}.exe' if os.name == 'nt' else binary
            release_path = os.path.join(self.rust_dir, name, 'target', 'release', binary_exe)
            if os.path.exists(release_path):
                tools[name] = release_path
        return tools

    def available(self):
        return len(self.tools) > 0

    def run_tool(self, name, url):
        path = self.tools.get(name)
        if not path:
            return
        try:
            process = subprocess.Popen(
                [path, url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    yield obj
                except json.JSONDecodeError:
                    pass
            process.wait()
        except Exception as e:
            yield {'type': 'error', 'message': f'Rust {name}: {e}', 'source': 'rust'}

    def run_all(self, url):
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(list, self.run_tool(name, url)): name
                for name in self.tools
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    for event in future.result():
                        yield event
                except Exception as e:
                    yield {'type': 'error', 'message': f'Rust {name}: {e}', 'source': 'rust'}


def get_engine():
    return GoEngine()

def get_rust_engine():
    return RustEngine()
