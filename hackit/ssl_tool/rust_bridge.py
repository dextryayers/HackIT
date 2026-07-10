import subprocess
import os
import json
import platform
import signal

class RustEngine:
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.binary_name = "worker_rs.exe" if self.is_windows else "worker_rs"
        self.source_dir = os.path.dirname(os.path.abspath(__file__))
        self.rust_dir = os.path.join(self.source_dir, "rust")
        self.binary_path = os.path.join(self.rust_dir, "target", "release", self.binary_name)

        if not os.path.exists(self.binary_path):
            debug_path = os.path.join(self.rust_dir, "target", "debug", self.binary_name)
            if os.path.exists(debug_path):
                self.binary_path = debug_path

    def ensure_compiled(self) -> bool:
        if os.path.exists(self.binary_path):
            return True

        print("[*] Compiling Rust engine (this may take a while)...")
        try:
            result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=self.rust_dir,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                print(f"[!] Rust compilation failed:\n{result.stderr}")
                return False
            print("[+] Rust compilation successful")
            self.binary_path = os.path.join(self.rust_dir, "target", "release", self.binary_name)
            return True
        except FileNotFoundError:
            print("[!] Rust compiler (cargo) not found")
            return False
        except subprocess.TimeoutExpired:
            print("[!] Rust compilation timed out")
            return False

    def run(self, host: str, port: int = 443, timeout: int = 15,
            output: str = None, json_only: bool = False, full: bool = False):
        if not self.ensure_compiled():
            print("[!] Rust engine not available.")
            return None

        cmd = [
            self.binary_path,
            "--json",
            "--host", host,
            "--port", str(port),
            "--timeout", str(timeout),
        ]
        if full:
            cmd.append("--full")
        if output:
            cmd.extend(["--output", output])

        rust_timeout = max(timeout * 2 + 15, 45)

        try:
            original = signal.signal(signal.SIGALRM, lambda s, f: (_ for _ in ()).throw(TimeoutError()))
            signal.alarm(rust_timeout)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=rust_timeout,
                )
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, original)

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if stderr:
                    print(f"[!] Rust engine error: {stderr}")
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
            print(f"[!] Rust engine timed out after {rust_timeout}s")
            return None
        except Exception as e:
            print(f"[!] Execution error: {e}")
            return None
