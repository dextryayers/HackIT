import os
import subprocess
import shutil
import json

class GoEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.base_dir, 'go')
        self.source_files = [os.path.join(self.go_dir, f) for f in ['main.go', 'discovery.go', 'analyzer.go', 'fuzzer.go', 'models.go']]
        self.binary_name = 'param_scanner.exe' if os.name == 'nt' else 'param_scanner'
        self.binary_path = os.path.join(self.go_dir, self.binary_name)
        self.available = self._check_go_installed()

    def _check_go_installed(self):
        return shutil.which('go') is not None

    def ensure_compiled(self):
        if not self.available:
            return False
        if not any(os.path.exists(f) for f in self.source_files):
            return False

        needs_compile = False
        if not os.path.exists(self.binary_path):
            needs_compile = True
        else:
            bin_mtime = os.path.getmtime(self.binary_path)
            for f in self.source_files:
                if os.path.exists(f) and os.path.getmtime(f) > bin_mtime:
                    needs_compile = True
                    break

        if needs_compile:
            from hackit.ui import _colored, BLUE, GREEN, RED
            print(_colored("[*] Compiling Go Param Scanner Engine...", BLUE))
            try:
                cmd = ['go', 'build', '-o', self.binary_name, '.']
                subprocess.check_call(cmd, cwd=self.go_dir)
                print(_colored("[+] Engine compiled successfully!", GREEN))
            except subprocess.CalledProcessError as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, domain=None, url=None, domain_list=None, placeholder="FUZZ",
            enable_fuzz=False, fuzz_params=None, payload_file=None, method="GET",
            threads=10, timeout=10, output=None, proxy=None, sources="wayback,otx,urlscan",
            verbose=False):
        if not self.ensure_compiled():
            raise RuntimeError("Go engine compilation failed")

        cmd = [self.binary_path, '-ndjson']

        if domain:
            cmd.extend(['-d', domain])
        if url:
            cmd.extend(['-u', url])
        if domain_list:
            cmd.extend(['-l', domain_list])
        if placeholder != "FUZZ":
            cmd.extend(['-p', placeholder])
        if enable_fuzz:
            cmd.append('-fuzz')
        if fuzz_params:
            cmd.extend(['-params', fuzz_params])
        if payload_file:
            cmd.extend(['-payloads', payload_file])
        if method != "GET":
            cmd.extend(['-method', method])
        if threads != 10:
            cmd.extend(['-threads', str(threads)])
        if timeout != 10:
            cmd.extend(['-timeout', str(timeout)])
        if output:
            cmd.extend(['-output', output])
        if proxy:
            cmd.extend(['-proxy', proxy])
        if sources != "wayback,otx,urlscan":
            cmd.extend(['-sources', sources])
        if verbose:
            cmd.append('-v')

        try:
            process = subprocess.Popen(
                cmd,
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
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass

            process.wait()
        except Exception as e:
            yield {'type': 'error', 'message': str(e)}

    def run_sync(self, **kwargs):
        results = list(self.run(**kwargs))
        return results


def get_engine():
    return GoEngine()
