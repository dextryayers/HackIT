import os
import subprocess
import sys
import shutil
from hackit.ui import _colored, GREEN, RED, BLUE

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.source_file = os.path.join(self.go_dir, 'main.go')
        self.binary_name = 'worker.exe' if os.name == 'nt' else 'worker'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.available = self._check_go_installed()

    def _check_go_installed(self):
        return shutil.which('go') is not None

    def ensure_compiled(self):
        """Compiles the Go worker if it doesn't exist or is older than source"""
        if not self.available:
            return False

        if not os.path.exists(self.source_file):
            return False

        # We need to check all .go files in the directory for changes
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
            print(_colored("[*] Compiling Go Worker...", BLUE))
            try:
                # Use "go build ." to build the package/directory
                cmd = ['go', 'build', '-o', self.binary_path, '.']
                subprocess.check_call(cmd, cwd=self.go_dir)
                print(_colored("[+] Go Worker compiled successfully!", GREEN))
                return True
            except subprocess.CalledProcessError as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        
        return True

    def run(self, domain, wordlist=None, passive_only=False, active_only=False, permutations=False, 
            takeover=False, recursive=False, stealth=False, fast=False, 
            sc=False, ip=False, title=False, server=False, tech_detect=False, asn=False, probe=False, 
            filter_codes=None, threads=100, output=None):
            
        if not self.ensure_compiled():
            raise RuntimeError("Go worker could not be compiled or Go is not installed.")

        cmd = [self.binary_path]
        cmd.extend(['-d', domain])
        cmd.extend(['-c', str(threads)])
        
        if wordlist:
            cmd.extend(['-w', wordlist])
        
        # Mode flags
        if passive_only: cmd.append('-passive-only')
        if active_only: cmd.append('-active-only')
        if permutations: cmd.append('-permutations')
        if takeover: cmd.append('-takeover')
        if recursive: cmd.append('-recursive')
        if stealth: cmd.append('-stealth')
        if fast: cmd.append('-fast')
        
        # Probe flags
        if sc: cmd.append('-sc')
        if ip: cmd.append('-ip')
        if title: cmd.append('-title')
        if server: cmd.append('-server')
        if tech_detect: cmd.append('-tech')
        if asn: cmd.append('-asn')
        if probe: cmd.append('-probe')
        
        if filter_codes:
            cmd.extend(['-fc', filter_codes])
            
        if output:
            cmd.extend(['-o', output])

        # Run the binary and stream output to stdout
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Real-time output streaming
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    sys.stdout.write(line)
                    sys.stdout.flush()
            
            rc = process.poll()
            return rc == 0

        except Exception as e:
            print(_colored(f"[!] Execution error: {e}", RED))
            return False

def get_engine():
    return GoEngine()
