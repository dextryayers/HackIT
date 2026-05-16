import subprocess
import sys
import os
import time

def run_hackit():
    print("""
    =========================================
      HackIT OSINT Tools Engine v2.1
    =========================================
    """)
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_dir = os.path.join(root_dir, "python")
    dist_dir = os.path.join(root_dir, "dist")

    # 1. Check if Astro build is up to date
    should_build = not os.path.exists(dist_dir)
    
    if not should_build:
        # Check if any source file is newer than the build
        src_dir = os.path.join(root_dir, "src")
        dist_index = os.path.join(dist_dir, "index.html")
        if os.path.exists(src_dir) and os.path.exists(dist_index):
            dist_mtime = os.path.getmtime(dist_index)
            for root, dirs, files in os.walk(src_dir):
                for file in files:
                    if os.path.getmtime(os.path.join(root, file)) > dist_mtime:
                        should_build = True
                        break
                if should_build: break

    if should_build:
        print("[!] UI changes detected. Synchronizing frontend assets...")
        try:
            # Use shell=True for Windows compatibility with npm
            subprocess.run(["npm", "run", "build"], cwd=root_dir, shell=True, check=True)
            print("[+] Synchronization successful.")
        except Exception as e:
            print(f"[-] Error building frontend: {e}")
            print("[!] Continuing with existing build (if any)...")
            time.sleep(2)

    # 2. Check Python dependencies
    print("[+] Checking Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=python_dir, shell=True, check=True)
    except Exception as e:
        print(f"[-] Error installing dependencies: {e}")

    # 3. Start the Unified Engine
    print("\n[+] Starting Unified Engine on http://localhost:8080")
    print("[+] API is ready at /api")
    print("[+] Dashboard is ready at /")
    print("-----------------------------------------\n")
    
    try:
        # Run main.py from the python directory
        os.chdir(python_dir)
        subprocess.run([sys.executable, "main.py"], shell=True)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    except Exception as e:
        print(f"[-] Critical Error: {e}")

if __name__ == "__main__":
    run_hackit()
