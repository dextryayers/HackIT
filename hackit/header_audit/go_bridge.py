import os
import subprocess
import sys
import shutil
import json
from hackit.ui import _colored, GREEN, RED, BLUE

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
        if not self.available: return False
        if not os.path.exists(self.source_file): return False
        
        needs_compile = False
        if not os.path.exists(self.binary_path):
            needs_compile = True
        else:
            bin_mtime = os.path.getmtime(self.binary_path)
            # Check all go files
            for root, dirs, files in os.walk(self.go_dir):
                for f in files:
                    if f.endswith('.go'):
                        src_path = os.path.join(root, f)
                        if os.path.getmtime(src_path) > bin_mtime:
                            needs_compile = True
                            break
                if needs_compile: break

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

    def run(self, url):
        if not self.ensure_compiled():
            raise RuntimeError("Go engine compilation failed")

        cmd = [self.binary_path, '-u', url]
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return {'error': stderr.strip()}
            
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return {'error': f"Invalid JSON output: {stdout}"}

        except Exception as e:
            return {'error': str(e)}

def get_engine():
    return GoEngine()
