import os
import subprocess
import platform
import sys

def build_sqli():
    print("[HackIT] Starting SQLi Engine Build System...")

    print("\nBuilding Go Core Engine...")
    go_dir = os.path.join(os.path.dirname(__file__), 'go')
    go_out = 'worker.exe' if platform.system() == 'Windows' else 'worker'
    try:
        os.makedirs(os.path.join(go_dir, 'bin'), exist_ok=True)
        subprocess.run(['go', 'build', '-o', os.path.join(go_dir, 'bin', go_out), '.'], cwd=go_dir, check=True)
        print(f"Go Core compiled: {os.path.join(go_dir, 'bin', go_out)}")
    except Exception as e:
        print(f"Failed to build Go core: {e}")
        sys.exit(1)

    print("\n[HackIT] SQLi Build Process Complete!")

if __name__ == "__main__":
    build_sqli()
