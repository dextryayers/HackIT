import os
import subprocess
import shutil
import sys

def colored(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

GREEN = "32"
RED = "31"
BLUE = "34"
CYAN = "36"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def build_go():
    print(colored("[*] Building Go Engine...", BLUE))
    go_dir = os.path.join(BASE_DIR, "go")
    try:
        subprocess.check_call(["go", "build", "-o", "port_scanner.exe", "."], cwd=go_dir)
        print(colored("[+] Go Engine compiled successfully!", GREEN))
    except Exception as e:
        print(colored(f"[!] Go build failed: {e}", RED))

def build_rust():
    print(colored("[*] Building Rust Engine...", BLUE))
    rust_dir = os.path.join(BASE_DIR, "go", "rust_engine")
    if not os.path.exists(rust_dir):
        print(colored("[!] Rust engine directory not found!", RED))
        return

    try:
        subprocess.check_call(["cargo", "build", "--release"], cwd=rust_dir)
        # Copy DLL to go directory
        dll_src = os.path.join(rust_dir, "target", "release", "rust_port_scanner.dll")
        dll_dest = os.path.join(BASE_DIR, "go", "rust_port_scanner.dll")
        if os.path.exists(dll_src):
            shutil.copy2(dll_src, dll_dest)
            print(colored("[+] Rust Engine compiled and DLL deployed!", GREEN))
        else:
            print(colored("[!] Rust DLL not found after build!", RED))
    except Exception as e:
        print(colored(f"[!] Rust build failed: {e}", RED))

def build_c():
    print(colored("[*] Building C Engines...", BLUE))
    c_dir = os.path.join(BASE_DIR, "c")
    try:
        # Build advanced_scanner.c
        subprocess.check_call(["gcc", "advanced_scanner.c", "-o", "advanced_scanner.exe", "-lws2_32"], cwd=c_dir)
        # Build os_detect.c as DLL
        subprocess.check_call(["gcc", "-shared", "-o", "os_detect.dll", "os_detect.c", "-lws2_32"], cwd=c_dir)
        print(colored("[+] C Engines compiled successfully!", GREEN))
    except Exception as e:
        print(colored(f"[!] C build failed: {e}. Ensure GCC/MinGW is installed.", RED))

def build_cpp():
    print(colored("[*] Building C++ Engines...", BLUE))
    cpp_dir = os.path.join(BASE_DIR, "cpp")
    try:
        subprocess.check_call(["g++", "advanced_scanner.cpp", "-o", "advanced_scanner.exe", "-lws2_32"], cwd=cpp_dir)
        print(colored("[+] C++ Engines compiled successfully!", GREEN))
    except Exception as e:
        print(colored(f"[!] C++ build failed: {e}. Ensure G++ is installed.", RED))

if __name__ == "__main__":
    print(colored("=== HACKIT PORT SCANNER BUILD SYSTEM ===", CYAN))
    build_rust()
    build_go()
    build_c()
    build_cpp()
    print(colored("=== BUILD COMPLETE ===", CYAN))
