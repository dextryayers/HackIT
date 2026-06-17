import subprocess
import json
import os
import sys
import time
import click

class Bypass403Pro:
    def __init__(self, target_url, verbose=True, only_success=False):
        self.target_url = target_url
        self.verbose = verbose
        self.only_success = only_success
        self.engine_path = os.path.join(os.path.dirname(__file__), "go_engine", "bypass_engine")
        
        if not os.name == 'nt':
            self.engine_path = self.engine_path.replace(".exe", "")

    def print_banner(self):
        banner = """\033[36m
   ██╗  ██╗ ██████╗ ██████╗        ██╗  ██╗██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
   ██║  ██║██╔═████╗╚════██╗       ╚██╗██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ███████║██║██╔██║ █████╔╝█████╗  ╚███╔╝ ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
   ╚════██║████╔╝██║ ╚═══██╗╚════╝  ██╔██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
        ██║╚██████╔╝██████╔╝       ██╔╝ ██╗██████╔╝   ██║   ██║     ██║  ██║███████║███████║
        ╚═╝ ╚═════╝ ╚═════╝        ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                            \033[33m[ Industrial-Grade Authorization Fuzzer ]\033[0m
        """
        print(banner)

    def run(self):
        self.print_banner()
        print(f"[\033[36m*\033[0m] Target: {self.target_url}")
        start = time.time()
        
        if not os.path.exists(self.engine_path):
            print(f"[\033[31mX\033[0m] Go engine not found at {self.engine_path}")
            return

        try:
            process = subprocess.run(
                [self.engine_path, "-url", self.target_url],
                capture_output=True, text=True
            )
            
            if process.returncode != 0:
                print(f"[\033[31mX\033[0m] Engine failed:\n{process.stderr}")
                return

            try:
                results = json.loads(process.stdout)
            except json.JSONDecodeError:
                print(f"[\033[31mX\033[0m] Failed to parse engine output")
                return

            elapsed = time.time() - start

            by_status = {}
            for r in results:
                s = r.get("status_code", 0)
                by_status[s] = by_status.get(s, 0) + 1

            bypasses = [r for r in results if 200 <= r.get("status_code", 0) <= 299]
            redirects = [r for r in results if 300 <= r.get("status_code", 0) <= 399]
            errors5xx = [r for r in results if 500 <= r.get("status_code", 0) <= 599]
            blocked = [r for r in results if r.get("status_code", 0) >= 400]

            print(f"[\033[36m*\033[0m] Payloads: {len(results)}  |  Time: {elapsed:.1f}s")
            print(f"  \033[1;32mBypasses: {len(bypasses)}\033[0m  |  \033[33mRedirects: {len(redirects)}\033[0m  |  \033[36m5xx: {len(errors5xx)}\033[0m  |  \033[31mBlocked: {len(blocked)}\033[0m\n")

            if bypasses:
                print(f"\033[1;32m{'═' * 80}\033[0m")
                print(f"\033[1;32m  ✅ SUCCESSFUL BYPASSES ({len(bypasses)})\033[0m")
                print(f"\033[1;32m{'═' * 80}\033[0m")
                print(f"\033[1;36m{'STATUS':<8} {'METHOD':<10} {'LENGTH':<10} {'TECHNIQUE'}\033[0m")
                print("\033[90m" + "─" * 80 + "\033[0m")
                for r in bypasses:
                    status = r.get("status_code", 0)
                    method = r.get("method", "GET")
                    length = r.get("length", 0)
                    payload = r.get("payload", "")
                    print(f"\033[1;32m{status:<8} {method:<10} {length:<10} \033[1;37m{payload}\033[0m")
                print()

            if self.verbose and not self.only_success:
                print(f"\033[1;33m{'═' * 80}\033[0m")
                print(f"\033[1;33m  ALL ATTEMPTS ({len(results)} total)\033[0m")
                print(f"\033[1;33m{'═' * 80}\033[0m")
                print(f"\033[1;36m{'STATUS':<8} {'METHOD':<10} {'LENGTH':<10} {'PAYLOAD'}\033[0m")
                print("\033[90m" + "─" * 80 + "\033[0m")
                results.sort(key=lambda x: x.get("status_code", 999))
                for r in results:
                    status = r.get("status_code", 0)
                    method = r.get("method", "GET")
                    length = r.get("length", 0)
                    payload = r.get("payload", "")
                    if 200 <= status <= 299:
                        color = "\033[1;32m"
                    elif 300 <= status <= 399:
                        color = "\033[33m"
                    elif 500 <= status <= 599:
                        color = "\033[36m"
                    else:
                        color = "\033[31m"
                    print(f"{color}{status:<8} {method:<10} {length:<10} {payload}\033[0m")

            if not self.verbose and not bypasses:
                print("[\033[33m!\033[0m] No bypasses found. Use --verbose to see all attempts.")

        except Exception as e:
            print(f"[\033[31mX\033[0m] Exception: {str(e)}")


@click.command()
@click.option('--url', required=True, help='Target URL returning 403 (e.g., https://example.com/admin)')
@click.option('--verbose', is_flag=True, default=True, help='Show all attempts (default: True)')
@click.option('--only-success', is_flag=True, default=False, help='Show only successful bypasses (2xx)')
def run_bypass_cli(url, verbose, only_success):
    """High-Speed 403-XBypass Pro — 1000+ payloads, 100 concurrent workers"""
    scanner = Bypass403Pro(url, verbose, only_success)
    scanner.run()

# CLI Interface if ran directly
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python __init__.py --url <target_url>")
        sys.exit(1)
        
    target = sys.argv[1]
    scanner = Bypass403Pro(target)
    scanner.run()
