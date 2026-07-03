import subprocess
import os
import json
import platform
import signal

class GoEngine:
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.binary_name = "worker.exe" if self.is_windows else "worker"
        self.source_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.source_dir, "go")
        self.binary_path = os.path.join(self.go_dir, self.binary_name)

    def ensure_compiled(self):
        if not os.path.exists(self.binary_path):
            print(f"[*] Compiling Go engine...")
            try:
                cmd = ["go", "build", "-buildvcs=false", "-tags=netcgo", "-o", self.binary_name]
                subprocess.check_call(cmd, cwd=self.go_dir)
                print("[+] Compilation successful")
            except subprocess.CalledProcessError as e:
                print(f"[!] Compilation failed: {e}")
                return False
            except FileNotFoundError:
                print("[!] Go compiler not found")
                return False
        return True

    def run(self, host, port=443, timeout=15, output=None, json_only=False, full=False):
        if not self.ensure_compiled():
            print("[!] Engine not available.")
            return None

        cmd = [
            self.binary_path,
            "--json",
            "-host", host,
            "-port", str(port),
            "-timeout", str(timeout),
        ]
        if full:
            cmd.append("-full")
        if output:
            cmd.extend(["-output", output])

        go_timeout = max(timeout * 2 + 15, 45)

        env = os.environ.copy()
        env['GODEBUG'] = 'netdns=cgo'

        try:
            original = signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(TimeoutError()))
            signal.alarm(go_timeout)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=go_timeout,
                    env=env,
                )
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, original)

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if stderr:
                    print(f"[!] Go engine error: {stderr}")
                return None

            out = result.stdout.strip()
            if not out:
                return None

            if out.startswith('{'):
                try:
                    return json.loads(out)
                except json.JSONDecodeError:
                    pass

            lines = out.split('\n')
            combined = []
            in_json = False
            for line in lines:
                s = line.strip()
                if s.startswith('{'):
                    in_json = True
                    combined = [s]
                elif s.endswith('}') and in_json:
                    combined.append(s)
                    try:
                        return json.loads(''.join(combined))
                    except json.JSONDecodeError:
                        combined = []
                        in_json = False
                elif in_json:
                    combined.append(s)

            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return None

        except (subprocess.TimeoutExpired, TimeoutError):
            print(f"[!] Go engine timed out after {go_timeout}s")
            return None
        except Exception as e:
            print(f"[!] Execution error: {e}")
            return None
