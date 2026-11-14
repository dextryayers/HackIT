import subprocess
import os
import sys
import platform

class GoEngine:
    def __init__(self):
        self.system = platform.system().lower()
        self.is_windows = self.system == "windows"
        self.binary_name = "worker.exe" if self.is_windows else "worker"
        self.source_dir = os.path.dirname(os.path.abspath(__file__))
        self.go_dir = os.path.join(self.source_dir, "go")
        self.binary_path = os.path.join(self.go_dir, self.binary_name)

    def ensure_compiled(self):
        """Compile Go binary if it doesn't exist"""
        if not os.path.exists(self.binary_path):
            print(f"[*] Compiling Go engine for {self.source_dir}...")
            try:
                cmd = ["go", "build", "-o", self.binary_name]
                subprocess.check_call(cmd, cwd=self.go_dir)
                print("[+] Compilation successful")
            except subprocess.CalledProcessError as e:
                print(f"[!] Compilation failed: {e}")
                return False
            except FileNotFoundError:
                print("[!] Go compiler not found. Please install Go.")
                return False
        # Auto-rebuild when the Go sources changed since the last build.
        go_dir = os.path.join(self.go_dir)
        source_dirty = False
        if os.path.exists(go_dir):
            try:
                binary_time = os.path.getmtime(self.binary_path)
            except OSError:
                binary_time = 0.0
            for root, _dirs, files in os.walk(go_dir):
                for name in files:
                    if not name.endswith(".go"):
                        continue
                    try:
                        mtime = os.path.getmtime(os.path.join(root, name))
                    except OSError:
                        continue
                    if mtime > binary_time:
                        source_dirty = True
                        break
                if source_dirty:
                    break
        if source_dirty:
            print("[*] Sources changed - rebuilding CVE engine...")
            try:
                cmd = ["go", "build", "-o", self.binary_name]
                subprocess.check_call(cmd, cwd=self.go_dir)
                print("[+] Recompilation successful")
            except subprocess.CalledProcessError as e:
                print(f"[!] Compilation failed: {e}")
                return False
            except FileNotFoundError:
                print("[!] Go compiler not found. Please install Go.")
                return False
        return True

    def run(self, target, mode="main", output=None, api_key=None, max_results=None,
            subdomains=False, deep=False, subdomains_file=None, nvd_concurrency=None):
        if not self.ensure_compiled():
            print("[!] Engine not available.")
            return False

        cmd = [
            self.binary_path,
            "-target", target,
            "-mode", mode
        ]

        if output:
            cmd.extend(["-output", output])
        if api_key:
            cmd.extend(["--api-key", api_key])
        if max_results:
            cmd.extend(["--max-results", str(max_results)])
        if subdomains:
            cmd.append("--subdomains")
        if deep:
            cmd.append("--deep")
        if subdomains_file:
            cmd.extend(["--subdomains-file", subdomains_file])
        if nvd_concurrency:
            cmd.extend(["--nvd-concurrency", str(nvd_concurrency)])

        import threading as _threading

        def _forward(proc):
            # Live-stream the Go worker's output so the user sees progress and
            # NVD queries actually moving, instead of a silent wait.
            if proc.stdout is None:
                return
            try:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if line:
                        print(line)
            except Exception:
                pass

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            forwarder = _threading.Thread(target=_forward, args=(process,), daemon=True)
            forwarder.start()
            process.wait(timeout=300)
            return process.returncode == 0
        except KeyboardInterrupt:
            process.terminate()
            try:
                process.wait(timeout=2)
            except Exception:
                process.kill()
            print("\n[!] Interrupted")
            return False
        except subprocess.TimeoutExpired:
            process.kill()
            print("\n[!] Engine timeout (>300s)")
            return False
        except Exception as e:
            print(f"[!] Execution error: {e}")
            return False


def run_cve_scan(target, mode="main", output=None, api_key=None,
                 max_results=20, subdomains=False, deep=False, subdomains_file=None,
                 nvd_concurrency=None):
    """Run the Go CVE worker with JSON export and return the parsed report."""
    import json
    import os
    import tempfile
    from hackit.cve.go_bridge import GoEngine

    engine = GoEngine()
    if not engine.ensure_compiled():
        return None

    parse_target = output
    if parse_target is None:
        fd, parse_target = tempfile.mkstemp(prefix="cve_report_", suffix=".json")
        os.close(fd)

    if not engine.run(target=target, mode=mode, output=parse_target,
                      api_key=api_key, max_results=max_results,
                      subdomains=subdomains, deep=deep,
                      subdomains_file=subdomains_file,
                      nvd_concurrency=nvd_concurrency):
        return None
    try:
        with open(parse_target, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except Exception:
        return None
    finally:
        if output is None:
            try:
                os.remove(parse_target)
            except OSError:
                pass
    return report
