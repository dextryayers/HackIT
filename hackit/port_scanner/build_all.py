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
YELLOW = "33"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, "bin")

def ensure_bin_dir():
    os.makedirs(BIN_DIR, exist_ok=True)

def build_go():
    print(colored("[*] Building Go Engine...", BLUE))
    go_dir = os.path.join(BASE_DIR, "go")
    try:
        subprocess.check_call(["go", "build", "-o", os.path.join(go_dir, "port_scanner"), "."], cwd=go_dir)
        shutil.copy(os.path.join(go_dir, "port_scanner"), os.path.join(BIN_DIR, "port_scanner"))
        print(colored("[+] Go Engine compiled successfully!", GREEN))
    except Exception as e:
        print(colored(f"[!] Go build failed: {e}", RED))
    try:
        subprocess.check_call(["go", "build", "-o", os.path.join(go_dir, "syn_scan"), "-tags=syn", "syn_scan.go", "worker_pool.go"], cwd=go_dir)
        shutil.copy(os.path.join(go_dir, "syn_scan"), os.path.join(BIN_DIR, "syn_scan"))
        print(colored("[+] Go SYN Scanner compiled!", GREEN))
    except Exception as e:
        print(colored(f"[!] Go SYN Scanner build failed (libpcap may be needed): {e}", YELLOW))

def build_rust():
    print(colored("[*] Building Rust Engines (merged workspace)...", BLUE))
    rust_dir = os.path.join(BASE_DIR, "go", "rust_engine")
    if not os.path.exists(rust_dir):
        print(colored("[!] Rust engine directory not found!", RED))
        return
    try:
        targets = ["hyper_scan", "syn_scanner", "os_detect", "dns_detect", "web_fingerprint", "kernel_detect"]
        for target in targets:
            try:
                subprocess.check_call(["cargo", "build", "--release", "--bin", target], cwd=rust_dir)
                src = os.path.join(rust_dir, "target", "release", target)
                bin_name = f"rust_{target}" if target == "syn_scanner" else target
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(BIN_DIR, bin_name))
                    print(colored(f"[+] Rust {target} compiled!", GREEN))
            except Exception as e:
                print(colored(f"[!] Rust {target} build failed: {e}", YELLOW))
        # Also build the cdylib for Go CGo
        try:
            subprocess.check_call(["cargo", "build", "--release"], cwd=rust_dir)
            lib_src = os.path.join(rust_dir, "target", "release", "librust_port_scanner.so")
            if os.path.exists(lib_src):
                shutil.copy2(lib_src, os.path.join(BIN_DIR, "librust_port_scanner.so"))
                print(colored("[+] Rust cdylib compiled!", GREEN))
        except Exception as e:
            print(colored(f"[!] Rust cdylib build failed: {e}", YELLOW))
        print(colored("[+] All Rust Engines processed!", GREEN))
    except Exception as e:
        print(colored(f"[!] Rust build failed: {e}", RED))

def build_c():
    print(colored("[*] Building C Engines...", BLUE))
    c_dir = os.path.join(BASE_DIR, "c")
    ensure_bin_dir()
    opts = "-O3 -march=native -mtune=native -flto -pthread"
    targets = [
        ("syn_scanner.c", "syn_scanner"),
        ("mass_tcp_scanner.c", "mass_tcp_scanner"),
        ("udp_scanner.c", "udp_scanner"),
        ("os_fingerprint.c", "os_fingerprint"),
        ("advanced_scanner.c", "advanced_scanner"),
    ]
    for src, name in targets:
        try:
            subprocess.check_call(f"gcc {opts} -o {name} {src} -lpthread", shell=True, cwd=c_dir)
            shutil.copy(os.path.join(c_dir, name), os.path.join(BIN_DIR, name))
            print(colored(f"[+] C {name} compiled!", GREEN))
        except Exception as e:
            print(colored(f"[!] C {name} build failed: {e}", RED))

def build_cpp():
    print(colored("[*] Building C++ Engines...", BLUE))
    cpp_dir = os.path.join(BASE_DIR, "cpp")
    ensure_bin_dir()
    opts = "-O3 -march=native -mtune=native -flto -pthread -std=c++17"
    targets = [
        ("tls_scanner.cpp", "tls_scanner"),
        ("vuln_matcher.cpp", "vuln_matcher"),
        ("advanced_scanner.cpp", "advanced_scanner"),
    ]
    for src, name in targets:
        try:
            subprocess.check_call(f"g++ {opts} -o {name} {src} -lpthread", shell=True, cwd=cpp_dir)
            shutil.copy(os.path.join(cpp_dir, name), os.path.join(BIN_DIR, name))
            print(colored(f"[+] C++ {name} compiled!", GREEN))
        except Exception as e:
            print(colored(f"[!] C++ {name} build failed: {e}", RED))

def validate_lua():
    print(colored("[*] Validating Lua plugins...", BLUE))
    lua_dir = os.path.join(BASE_DIR, "lua")
    if not os.path.exists(lua_dir):
        print(colored("[!] Lua directory not found!", YELLOW))
        return
    files = sorted([f for f in os.listdir(lua_dir) if f.endswith(".lua")])
    print(colored(f"  Found {len(files)} Lua plugins: {', '.join(files)}", CYAN))

def validate_ruby():
    print(colored("[*] Validating Ruby plugins...", BLUE))
    ruby_dir = os.path.join(BASE_DIR, "ruby")
    if not os.path.exists(ruby_dir):
        print(colored("[!] Ruby directory not found!", YELLOW))
        return
    files = sorted([f for f in os.listdir(ruby_dir) if f.endswith(".rb")])
    print(colored(f"  Found {len(files)} Ruby plugins: {', '.join(files)}", CYAN))

def validate_binaries():
    print(colored("[*] Deployed binaries:", BLUE))
    if os.path.exists(BIN_DIR):
        for f in sorted(os.listdir(BIN_DIR)):
            fpath = os.path.join(BIN_DIR, f)
            size = os.path.getsize(fpath)
            print(colored(f"  {f:40s} {size:>8,} bytes", CYAN))
    else:
        print(colored("  (none yet)", YELLOW))

if __name__ == "__main__":
    print(colored("══════════════════════════════════════════", CYAN))
    print(colored("     HACKIT PORT SCANNER BUILD SYSTEM    ", CYAN))
    print(colored("     Multi-Engine Fusion (C/C++/Go/Rust) ", CYAN))
    print(colored("     20 Plugins (10 Lua + 10 Ruby)       ", CYAN))
    print(colored("══════════════════════════════════════════", CYAN))
    ensure_bin_dir()
    build_rust()
    build_go()
    build_c()
    build_cpp()
    validate_lua()
    validate_ruby()
    validate_binaries()
    print(colored("══════════════════════════════════════════", CYAN))
    print(colored("     BUILD COMPLETE                      ", CYAN))
    print(colored("═" * 46, CYAN))
