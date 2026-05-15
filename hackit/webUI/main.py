import subprocess
import sys
import os
import time

def run_hackit():
    print("""
    =========================================
      HackIT Industrial OSINT Engine v2.0
    =========================================
    """)
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    python_dir = os.path.join(root_dir, "python")
    dist_dir = os.path.join(root_dir, "dist")

    # 1. Check if Astro is built
    if not os.path.exists(dist_dir):
        print("[!] Astro build missing. Generating frontend assets...")
        try:
            subprocess.run(["npm", "run", "build"], cwd=root_dir, shell=True, check=True)
            print("[+] Build successful.")
        except Exception as e:
            print(f"[-] Error building frontend: {e}")
            print("[!] Please ensure Node.js and npm are installed.")
            return

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
