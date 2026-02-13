import subprocess
import os
import sys
import platform

class GoEngine:
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.binary_name = "worker.exe" if self.is_windows else "worker"
        self.source_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.source_dir, "go")
        self.binary_path = os.path.join(self.go_dir, self.binary_name)

    def ensure_compiled(self):
        """Compile Go binary if it doesn't exist"""
        if not os.path.exists(self.binary_path):
            print(f"[*] Compiling Go engine for {self.source_dir}...")
            try:
                cmd = ["go", "build", "-o", self.binary_name]
                subprocess.check_call(cmd, cwd=self.go_dir)
                print("[+] Compilation successful")
            except subprocess.CalledProcessError as e:
                print(f"[!] Compilation failed: {e}")
                sys.exit(1)
            except FileNotFoundError:
                print("[!] Go compiler not found. Please install Go.")
                sys.exit(1)

    def run(self, software, version, output=None):
        self.ensure_compiled()
        
        cmd = [
            self.binary_path,
            "-software", software,
            "-version", version
        ]
        
        if output:
            cmd.extend(["-output", output])

        try:
            # Pass through stdout/stderr to show real-time progress
            process = subprocess.Popen(cmd)
            process.wait()
            return process.returncode == 0
        except KeyboardInterrupt:
            process.terminate()
            print("\n[!] Interrupted")
            return False
        except Exception as e:
            print(f"[!] Execution error: {e}")
            return False
