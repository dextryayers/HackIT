import subprocess
import json
import sys
import os
import argparse
import platform as _platform
from .brain import correlate


def _binary_name():
    return "tech_hunter.exe" if os.name == "nt" else "tech_hunter"


def _resolve_binary():
    """Find the engine binary next to this file (never CWD-dependent)."""
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "go")
    cand = os.path.join(here, _binary_name())
    if os.path.exists(cand):
        return cand
    # Legacy/alternate names from older builds.
    for alt in ("tech_hunter", "tech_hunter.exe", "worker", "worker.exe"):
        p = os.path.join(here, alt)
        if os.path.exists(p):
            return p
    return cand


def _go_available():
    try:
        r = subprocess.run(["go", "version"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def ensure_compiled():
    """Rebuild the engine when sources are newer than the binary."""
    go_dir = os.path.dirname(_resolve_binary())
    binary = _resolve_binary()
    if not os.path.isdir(go_dir):
        return False, "Go engine directory missing"
    needs = not os.path.exists(binary)
    if not needs:
        try:
            bin_mtime = os.path.getmtime(binary)
            for f in os.listdir(go_dir):
                if f.endswith(".go") and os.path.getmtime(os.path.join(go_dir, f)) > bin_mtime:
                    needs = True
                    break
        except OSError:
            needs = True
    if not needs:
        return True, binary
    if not _go_available():
        return False, "Go toolchain not installed"
    try:
        p = subprocess.run(
            ["go", "build", "-buildvcs=false", "-o", os.path.basename(binary), "."],
            cwd=go_dir, capture_output=True, text=True, timeout=600,
        )
        if p.returncode != 0:
            err = (p.stderr or p.stdout or "").strip()[-500:]
            return False, f"Go build failed: {err}"
        try:
            os.chmod(binary, 0o755)
        except OSError:
            pass
        return True, binary
    except subprocess.TimeoutExpired:
        return False, "Go build timed out"
    except Exception as e:
        return False, f"Go build error: {e}"


def _normalize_target(target):
    t = (target or "").strip()
    if not t:
        return t
    if "://" not in t:
        t = "https://" + t.lstrip("/")
    return t


def run_go_engine(target, timeout=60, threads=10, full=False):
    """
    Orchestrates the execution of the Go hybrid engine safely.
    Auto-builds the binary when missing or stale.
    """
    target = _normalize_target(target)
    if not target:
        return {"error": "Empty target"}

    ok, binary_or_err = ensure_compiled()
    if not ok:
        return {"error": binary_or_err}
    binary = binary_or_err

    final_cmd = [binary, "-t", target, "-json",
                 "-timeout", str(timeout), "-threads", str(threads)]
    if full:
        final_cmd.append("-full")

    try:
        # Run with go/ as CWD so relative helper paths resolve.
        go_dir = os.path.dirname(os.path.abspath(binary))
        process = subprocess.Popen(final_cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, cwd=go_dir)
        try:
            stdout, stderr = process.communicate(timeout=max(120, timeout * 10))
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except Exception:
                pass
            stdout, stderr = process.communicate()
            return {"error": "Engine timed out (target too slow or filtered)"}

        if "---JSON_START---" in stdout:
            raw_json = stdout.split("---JSON_START---", 1)[1].split("---JSON_END---")[0]
            try:
                go_results = json.loads(raw_json)
            except json.JSONDecodeError as e:
                return {"error": f"Engine returned corrupt JSON: {e}"}

            # Enrich findings via Intelligence Brain
            try:
                intelligence_map = correlate(go_results)
                return intelligence_map
            except Exception:
                return go_results
        else:
            tail_out = (stdout or "")[-800:]
            tail_err = (stderr or "")[-800:]
            return {"error": f"Hybrid engine failed to return data\nSTDOUT: {tail_out}\nSTDERR: {tail_err}"}

    except FileNotFoundError:
        return {"error": f"Engine binary not executable: {binary}"}
    except Exception as e:
        return {"error": f"Bridge execution failure: {str(e)}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tech Hunter: Safe Python Bridge")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--full", action="store_true")

    args = parser.parse_args()

    result = run_go_engine(args.target, timeout=args.timeout,
                           threads=args.threads, full=args.full)
    print(json.dumps(result, indent=2, default=str))
