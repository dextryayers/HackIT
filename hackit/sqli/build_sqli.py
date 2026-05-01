import os
import subprocess
import platform
import sys

def build_sqli():
    print("[HackIT] Starting SQLi Engine Build System...")
    
    # 1. Build C Module
    print("\nCompiling C Request Orchestrator...")
    c_file = "c/request_orchestrator.c"
    c_out = "c/request_orchestrator.dll" if platform.system() == "Windows" else "c/request_orchestrator.so"
    try:
        subprocess.run(["gcc", "-shared", "-o", c_out, c_file, "-fPIC"], check=True)
        print(f"C Module compiled: {c_out}")
    except Exception as e:
        print(f"Failed to compile C module: {e}")

    # 2. Build C++ Module
    print("\nCompiling C++ Data Dump Engine...")
    cpp_file = "cpp/data_dump_engine.cpp"
    cpp_out = "cpp/data_dump_engine.dll" if platform.system() == "Windows" else "cpp/data_dump_engine.so"
    try:
        subprocess.run(["g++", "-shared", "-o", cpp_out, cpp_file, "-fPIC"], check=True)
        print(f"C++ Module compiled: {cpp_out}")
    except Exception as e:
        print(f"Failed to compile C++ module: {e}")

    # 3. Build Rust Engine
    print("\nBuilding Rust Data Extractor...")
    rust_dir = "go/rust_engine"
    try:
        subprocess.run(["cargo", "build", "--release"], cwd=rust_dir, check=True)
        # Copy to go directory for bridge access
        rust_dll = "go/rust_engine/target/release/rust_engine.dll" if platform.system() == "Windows" else "go/rust_engine/target/release/librust_engine.so"
        target_dll = "go/rust_engine.dll" if platform.system() == "Windows" else "go/rust_engine.so"
        if os.path.exists(rust_dll):
            import shutil
            shutil.copy(rust_dll, target_dll)
            print(f"Rust Engine built and deployed to: {target_dll}")
    except Exception as e:
        print(f"Failed to build Rust engine: {e}")

    # 4. Build Go Engine
    print("\nBuilding Go Core Engine...")
    go_dir = "go"
    go_out = "worker.exe" if platform.system() == "Windows" else "worker"
    try:
        subprocess.run(["go", "build", "-o", go_out, "."], cwd=go_dir, check=True)
        print(f"Go Core compiled: {os.path.join(go_dir, go_out)}")
    except Exception as e:
        print(f"Failed to build Go core: {e}")

    print("\n[HackIT] SQLi Build Process Complete!")

if __name__ == "__main__":
    build_sqli()
