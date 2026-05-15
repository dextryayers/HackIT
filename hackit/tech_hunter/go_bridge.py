import subprocess
import json
import sys
import os
import argparse
from .brain import correlate

def run_go_engine(target, **opts):
    """
    Orchestrates the execution of the Go hybrid engine with full flag propagation.
    """
    go_exe = os.path.join(os.getcwd(), "go", "tech_hunter.exe")
    if not os.path.exists(go_exe):
        # Fallback for relative execution
        go_exe = os.path.join(os.path.dirname(__file__), "go", "tech_hunter.exe")

    # Base command with JSON mode enabled for Python integration
    cmd = [go_exe, "-t", target, "-json"]

    # Map Python options to Go flags dynamically
    mapping = {
        'threads': '--threads',
        'timeout': '--timeout',
        'full': '--full',
        'whois': '--whois',
        'dns': '--dns',
        'port_scan': '--port-scan',
        'tls': '--tls',
        'tech': '--tech',
        'cloud': '--cloud',
        'waf_detect': '--waf-detect',
        'osint': '--osint',
        'stealth': '--stealth',
        'aggressive': '--aggressive'
    }

    # Default to Industrial Aggressive Mode with High Anonymity (Stealth)
    opts.setdefault('aggressive', True)
    opts.setdefault('stealth', True)
    opts.setdefault('full', True)

    for key, flag in mapping.items():
        val = opts.get(key)
        if val is True:
            cmd.append(flag)
        elif val is not None and not isinstance(val, bool):
            cmd.extend([flag, str(val)])
    # Hardening: Ensure all elements are strings to prevent join/Popen errors
    final_cmd = []
    for c in cmd:
        if isinstance(c, (list, tuple)):
            final_cmd.extend([str(item) for item in c])
        else:
            final_cmd.append(str(c))
    
    # Internal Diagnostic
    # print(f"DEBUG: cmd types: {[type(c) for c in final_cmd]}")
    
    if opts.get('debug'):
        print(f"[*] Command Pipeline: {' '.join(final_cmd)}")
    
    try:
        # Set CWD to the go directory so relative paths to DLLs work
        go_dir = os.path.dirname(go_exe)
        process = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=go_dir)
        stdout, stderr = process.communicate()
        
        if "---JSON_START---" in stdout:
            raw_json = stdout.split("---JSON_START---")[1].split("---JSON_END---")[0]
            go_results = json.loads(raw_json)
            
            # Enrich findings via Intelligence Brain
            intelligence_map = correlate(go_results)
            return intelligence_map
        else:
            error_msg = f"Hybrid engine failed to return data\nSTDOUT: {stdout}\nSTDERR: {stderr}"
            return {"error": error_msg}
            
    except Exception as e:
        return {"error": f"Bridge execution failure: {str(e)}"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tech Hunter: Python Bridge to Hybrid Engine")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--threads", type=int, default=20, help="Threads")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout")
    parser.add_argument("--full", action="store_true", help="Full Recon Mode")
    
    args = parser.parse_args()
    
    result = run_go_engine(args.target, **vars(args))
    print(json.dumps(result, indent=2))
