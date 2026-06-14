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
            print(_colored("[*] Compiling Go Worker...", BLUE))
            try:
                cmd = ['go', 'build', '-o', self.binary_path, '.']
                subprocess.check_call(cmd, cwd=self.go_dir)
                print(_colored("[+] Go Worker compiled successfully!", GREEN))
                return True
            except subprocess.CalledProcessError as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, domain, wordlist=None, passive_only=False, active_only=False,
            permutations=False, takeover=False, recursive=False, stealth=False,
            fast=False, sc=False, ip=False, title=False, server=False,
            tech_detect=False, asn=False, probe=False, filter_codes=None,
            threads=100, output=None, verbose=False,
            common=False, all_flag=False, no_wildcard=False, doh=False,
            resolve=True, output_format="text"):
        if not self.ensure_compiled():
            raise RuntimeError("Go worker could not be compiled or Go is not installed.")

        cmd = [self.binary_path]
        cmd.extend(['-d', domain])
        cmd.extend(['-c', str(threads)])

        if wordlist:
            cmd.extend(['-w', wordlist])
        if verbose:
            cmd.append('-v')
        if common:
            cmd.append('-common')
        if all_flag:
            cmd.append('-all')
        if no_wildcard:
            cmd.append('-no-wildcard')
        if doh:
            cmd.append('-doh')
        if not resolve:
            cmd.append('-resolve=false')
        if output_format != "text":
            cmd.extend(['-of', output_format])

        # Mode flags
        if passive_only:
            cmd.append('-passive-only')
        if active_only:
            cmd.append('-active-only')
        if permutations:
            cmd.append('-permutations')
        if takeover:
            cmd.append('-takeover')
        if recursive:
            cmd.append('-recursive')
        if stealth:
            cmd.append('-stealth')
        if fast:
            cmd.append('-fast')

        # Probe flags
        if sc:
            cmd.append('-sc')
        if ip:
            cmd.append('-ip')
        if title:
            cmd.append('-title')
        if server:
            cmd.append('-server')
        if tech_detect:
            cmd.append('-tech')
        if asn:
            cmd.append('-asn')
        if probe:
            cmd.append('-probe')

        if filter_codes:
            cmd.extend(['-fc', filter_codes])
        if output:
            cmd.extend(['-o', output])

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False
            )
            while True:
                line_bytes = process.stdout.readline()
                if not line_bytes and process.poll() is not None:
                    break
                if line_bytes:
                    line = line_bytes.decode('utf-8', errors='replace')
                    sys.stdout.write(line)
                    sys.stdout.flush()
            rc = process.poll()
            return rc == 0
        except Exception as e:
            print(_colored(f"[!] Execution error: {e}", RED))
            return False


def get_engine():
    return GoEngine()
