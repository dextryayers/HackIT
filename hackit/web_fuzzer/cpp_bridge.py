import subprocess
import os
from hackit.ui import _colored, RED, YELLOW, GREEN

class CPPEngine:
    """Bridge for the C++ powered Fuzzer Engine"""
    
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.cpp_dir = os.path.join(self.base_dir, "cpp")
        self.binary_path = os.path.join(self.cpp_dir, "fuzzer_engine.exe")
        
    def ensure_compiled(self, force: bool = False):
        if force or not os.path.exists(self.binary_path):
            print(_colored("[*] Compiling C++ Fuzzer Engine (High Performance)...", YELLOW))
            try:
                # Using g++ with O3 optimization and native architecture tuning
                subprocess.run(["g++", "main.cpp", "-o", "fuzzer_engine.exe", "-O3", "-march=native", "-lcurl"], 
                             cwd=self.cpp_dir, check=True)
                return os.path.exists(self.binary_path)
            except Exception as e:
                print(_colored(f"[!] Compilation failed: {e}", RED))
                return False
        return True

    def run(self, url, payload_file, verbose=False, mask=False):
        if not self.ensure_compiled():
            return
            
        cmd = [self.binary_path, url, payload_file]
        if verbose: cmd.append("-v")
        if mask: cmd.append("--mask")
            
        subprocess.run(cmd)
