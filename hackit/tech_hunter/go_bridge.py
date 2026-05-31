import subprocess
import json
import sys
import os
import argparse
from .brain import correlate

def run_go_engine(target):
    """
    Orchestrates the execution of the Go hybrid engine safely.
    """
    go_exe = os.path.join(os.getcwd(), "go", "tech_hunter.exe")
    if not os.path.exists(go_exe):
        # Fallback for relative execution
        go_exe = os.path.join(os.path.dirname(__file__), "go", "tech_hunter.exe")

    # Base command with JSON mode enabled for Python integration
    final_cmd = [go_exe, "-t", target, "-json"]
    
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
    parser = argparse.ArgumentParser(description="Tech Hunter: Safe Python Bridge")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    
    args = parser.parse_args()
    
    result = run_go_engine(args.target)
    print(json.dumps(result, indent=2))
