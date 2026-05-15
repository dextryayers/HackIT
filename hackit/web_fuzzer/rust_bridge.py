import subprocess
import os
import sys
from hackit.ui import _colored, RED, YELLOW, GREEN

class RustEngine:
    """Bridge for the Rust-powered Spider Core"""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.rust_dir = os.path.join(self.base_dir, "rust", "spider_core")
        self.binary_path = os.path.join(self.rust_dir, "target", "release", "spider_core.exe")
        
    def ensure_compiled(self, force: bool = False):
        if force or not os.path.exists(self.binary_path):
            print(_colored("[*] Compiling Rust Spider Core (Aggressive Release)...", YELLOW))
            try:
                subprocess.run(["cargo", "build", "--release"], cwd=self.rust_dir, check=True, stdout=subprocess.DEVNULL)
                return os.path.exists(self.binary_path)
            except Exception as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, domain, verbose=False, mask=False):
        if not self.ensure_compiled():
            return []
            
        cmd = [self.binary_path, domain]
        if verbose: cmd.append("-v")
        if mask: cmd.append("--mask")
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            lines = result.stdout.splitlines()
            urls = [line for line in lines if line.startswith("http")]
            return urls
        except Exception as e:
            print(_colored(f"[!] Execution error: {e}", RED))
            return []
