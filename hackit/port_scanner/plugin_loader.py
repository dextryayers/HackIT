import json
import os
import subprocess
import sys
from pathlib import Path

PLUGIN_DIRS = {
    "lua": os.path.join(os.path.dirname(__file__), "lua"),
    "ruby": os.path.join(os.path.dirname(__file__), "ruby"),
}

BIN_DIR = os.path.join(os.path.dirname(__file__), "bin")

def discover_plugins(engine="lua"):
    d = PLUGIN_DIRS.get(engine)
    if not d or not os.path.exists(d):
        return []
    ext = ".lua" if engine == "lua" else ".rb"
    return sorted([f[:-len(ext)] for f in os.listdir(d) if f.endswith(ext)])

def run_lua_plugin(plugin_name, target, port, banner="", opts=None):
    opts = opts or {}
    script = os.path.join(PLUGIN_DIRS["lua"], f"{plugin_name}.lua")
    if not os.path.exists(script):
        return {"status": "error", "error": f"Plugin {plugin_name} not found"}
    try:
        r = subprocess.run(
            ["lua", script, target, str(port), banner, json.dumps(opts)],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.strip().split("\n"):
            if line.startswith("{"):
                return json.loads(line)
        return {"status": "ok", "output": r.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Plugin timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_ruby_plugin(plugin_name, target, port, banner="", opts=None):
    opts = opts or {}
    script = os.path.join(PLUGIN_DIRS["ruby"], f"{plugin_name}.rb")
    if not os.path.exists(script):
        return {"status": "error", "error": f"Plugin {plugin_name} not found"}
    try:
        r = subprocess.run(
            ["ruby", script, target, str(port), banner, json.dumps(opts)],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.strip().split("\n"):
            if line.startswith("{"):
                return json.loads(line)
        return {"status": "ok", "output": r.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Plugin timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_rust_engine(binary, args):
    bin_path = os.path.join(BIN_DIR, binary)
    if not os.path.exists(bin_path):
        bin_path = os.path.join(os.path.dirname(__file__), "go", "rust_engine", "target", "release", binary)
    if not os.path.exists(bin_path):
        return {"status": "error", "error": f"Binary {binary} not found"}
    try:
        r = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=60)
        results = []
        final = {}
        for line in r.stdout.strip().split("\n"):
            if line.startswith("RESULT:"):
                try:
                    results.append(json.loads(line[7:]))
                except json.JSONDecodeError:
                    results.append({"raw": line[7:]})
            elif line.startswith("FINAL:"):
                try:
                    final = json.loads(line[6:])
                except json.JSONDecodeError:
                    pass
        return {"status": "ok", "results": results, "final": final, "stderr": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Engine timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_c_engine(binary, args):
    bin_path = os.path.join(BIN_DIR, binary)
    if not os.path.exists(bin_path):
        return {"status": "error", "error": f"Binary {binary} not found"}
    try:
        r = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=60)
        results = []
        final = {}
        for line in r.stdout.strip().split("\n"):
            if line.startswith("RESULT:"):
                try:
                    results.append(json.loads(line[7:]))
                except json.JSONDecodeError:
                    results.append({"raw": line[7:]})
            elif line.startswith("FINAL:"):
                try:
                    final = json.loads(line[6:])
                except json.JSONDecodeError:
                    pass
        return {"status": "ok", "results": results, "final": final, "stderr": r.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "Engine timed out"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def run_scan_chain(target, ports="22,80,443", engine="auto"):
    results = {}
    if engine in ("auto", "rust"):
        for binary in ["hyper_scan", "dns_detect", "web_fingerprint", "kernel_detect"]:
            r = run_rust_engine(binary, [target, ports])
            results[binary] = r
    if engine in ("auto", "c"):
        for binary in ["syn_scanner", "mass_tcp_scanner", "os_fingerprint"]:
            r = run_c_engine(binary, [target, ports])
            results[binary] = r
    if engine in ("auto", "lua"):
        for plugin in discover_plugins("lua"):
            r = run_lua_plugin(plugin, target, 80)
            results[f"lua:{plugin}"] = r
    if engine in ("auto", "ruby"):
        for plugin in discover_plugins("ruby"):
            r = run_ruby_plugin(plugin, target, 80)
            results[f"ruby:{plugin}"] = r
    return results

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = sys.argv[2] if len(sys.argv) > 2 else "22,80,443"
    engine = sys.argv[3] if len(sys.argv) > 3 else "auto"
    print(json.dumps(run_scan_chain(target, ports, engine), indent=2))
