import subprocess
import json
import os
import sys
import click

class Bypass403Pro:
    def __init__(self, target_url, verbose=True):
        self.target_url = target_url
        self.verbose = verbose
        self.engine_path = os.path.join(os.path.dirname(__file__), "go_engine", "bypass_engine.exe")
        
        # Cross platform path
        if not os.name == 'nt':
            self.engine_path = self.engine_path.replace(".exe", "")

    def print_banner(self):
        banner = """\033[36m
   ██╗  ██╗ ██████╗ ██████╗        ██╗  ██╗██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
   ██║  ██║██╔═████╗╚════██╗       ╚██╗██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ███████║██║██╔██║ █████╔╝█████╗  ╚███╔╝ ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
   ╚════██║████╔╝██║ ╚═══██╗╚════╝  ██╔██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
        ██║╚██████╔╝██████╔╝       ██╔╝ ██╗██████╔╝   ██║   ██║     ██║  ██║███████║███████║
        ╚═╝ ╚═════╝ ╚═════╝        ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝\033[0m
                            \033[33m[ Industrial-Grade Authorization Fuzzer ]\033[0m
        """
        print(banner)

    def run(self):
        self.print_banner()
        print(f"[\033[36m*\033[0m] Launching High-Speed 403-XBypass Engine against: {self.target_url}\n")
        
        if not os.path.exists(self.engine_path):
            print(f"[\033[31mX\033[0m] Native Go Engine not found at {self.engine_path}.")
            print("Please run compilation first.")
            return

        try:
            # Execute the Go binary
            process = subprocess.run(
                [self.engine_path, "-url", self.target_url],
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                print(f"[\033[31mX\033[0m] Engine Execution Failed:\n{process.stderr}")
                return

            try:
                results = json.loads(process.stdout)
            except json.JSONDecodeError:
                print(f"[\033[31mX\033[0m] Failed to parse engine output.")
                return

            print(f"\033[1;36m{'STATUS':<10} {'METHOD':<10} {'LENGTH':<10} {'PAYLOAD'}\033[0m")
            print("\033[90m" + "━" * 100 + "\033[0m")
            
            # Sort results to put 200 OKs at the top, then 300s, then errors
            results.sort(key=lambda x: x.get("status_code", 999))

            for res in results:
                status = res.get("status_code", 0)
                method = res.get("method", "GET")
                length = res.get("length", 0)
                payload = res.get("payload", "")
                
                # Color coding based on HTTP Status Code
                color = "\033[0m" # Default
                status_str = str(status)
                
                if 200 <= status <= 299:
                    color = "\033[1;32m" # Bold Green for success bypass!
                    status_str = f"✅ {status}"
                elif 300 <= status <= 399:
                    color = "\033[33m" # Yellow for redirect
                elif 500 <= status <= 599:
                    color = "\033[36m" # Cyan for server error
                elif status >= 400:
                    color = "\033[31m" # Red for access denied/not found

                if self.verbose or (200 <= status <= 299):
                    print(f"{color}{status_str:<10} {method:<10} {length:<10} {payload}\033[0m")
            
            print("\n[\033[36m+\033[0m] Scan Complete. Processed {} payloads concurrently.".format(len(results)))
            if not self.verbose:
                print("[\033[33m!\033[0m] Verbose mode is OFF. Only showing successful bypasses (2xx).")
                
        except Exception as e:
            print(f"[\033[31mX\033[0m] Critical Exception: {str(e)}")


@click.command()
@click.option('--url', required=True, help='Target URL returning 403 (e.g., https://example.com/admin)')
@click.option('--verbose', is_flag=True, default=True, help='Verbose output (show all responses, enabled by default)')
def run_bypass_cli(url, verbose):
    """High-Speed 403-XBypass Pro (Native Go Engine)"""
    scanner = Bypass403Pro(url, verbose)
    scanner.run()

# CLI Interface if ran directly
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python __init__.py --url <target_url>")
        sys.exit(1)
        
    target = sys.argv[1]
    scanner = Bypass403Pro(target)
    scanner.run()
