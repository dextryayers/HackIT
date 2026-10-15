import os, sys, json, subprocess
from pathlib import Path
from typing import Any

BINARY_PATH = Path(__file__).parent / "go" / "bin" / "atomix"

FLAG_MAP = {
    "url": "-u", "target_file": "-target-file", "exclude_file": "-exclude-file",
    "scope_file": "-scope-file", "resume": "-resume", "exclude_pat": "-ep",
    "severity": "-severity", "tags": "-tags", "exclude_tags": "-etag",
    "exclude_severity": "-exclude-severity", "id": "-id", "author": "-author", "type": "-type",
    "custom_dir": "-custom-dir", "load": "-load", "from_git": "-from-git",
    "no_cache": "-no-cache", "priority": "-priority", "adaptive_rate": "-adaptive-rate",
    "threads": "-c", "concurrency": "-threads", "timeout": "-timeout",
    "retries": "-retries", "rate_limit": "-rate-limit", "bulk_size": "-bulk-size",
    "method": "-m", "proxy": "-p", "resolver": "-r", "scan_all_ips": "-scan-all-ips",
    "exclude_ports": "-exclude-ports", "path": "-path", "payloads": "-payloads",
    "fuzz": "-fuzz", "fuzz_thread": "-fuzz-thread", "fuzz_recursive": "-fuzz-recursive",
    "output": "-o", "jsonl": "-jsonl", "csv": "-csv", "html": "-html",
    "markdown": "-md", "sarif": "-sarif",
    "json_output": "-json", "silent": "-silent", "verbose": "-v",
    "debug": "-d", "no_color": "-no-color", "stats": "-stats", "metrics": "-metrics",
    "analytics": "-analytics", "trace": "-trace",
    "headers": "-H", "cookie": "-cookie", "cookie_jar": "-cookie-jar",
    "custom_agent": "-custom-agent", "rand_agent": "-rand-agent",
    "http2": "-http2", "http2_downgrade": "-http2-downgrade", "keep_alive": "-keep-alive",
    "follow_redirects": "-follow-redirects", "max_redirects": "-max-redirects",
    "auth": "-auth", "auth_token": "-auth-token", "api_key": "-api-key",
    "waf_skip": "-waf-skip", "waf_bypass": "-waf-bypass",
    "detect_tech": "-tech-detect", "api_discovery": "-api-discovery",
    "interactsh": "-interactsh", "oob_server": "-oob-server",
    "oob_token": "-oob-token", "oob_type": "-oob-type",
    "chain": "-w", "smart": "-smart", "multi": "-multi",
    "replay": "-replay", "diff": "-diff", "monitor": "-monitor",
    "passive": "-passive", "min_confidence": "-min-confidence",
    "dashboard": "-dashboard", "dashboard_port": "-dashboard-port",
    "dashboard_path": "-dashboard-path", "dashboard_auth": "-dashboard-auth",
    "push": "-push", "slack": "-slack", "telegram": "-telegram",
    "telegram_chat": "-telegram-chat", "config": "-config",
    # Section 11: Headless
    "headless": "-headless", "headless_opt": "-headless-opt",
    "no_sandbox": "-no-sandbox", "show_browser": "-show-browser",
    "system_chrome": "-system-chrome", "use_chrome": "-use-chrome",
    "headless_page_timeout": "-headless-page-timeout",
    "headless_action_timeout": "-headless-action-timeout",
    # Section 12: Project
    "project": "-project", "project_path": "-project-path",
    "allow_local_access": "-allow-local-access",
    # Section 13: Protocol
    "protocol": "-proto", "dns_resolver": "-dns-resolver",
    "tls_impersonate": "-tls-impersonate",
    # Section 14: Uncover
    "uncover": "-uncover", "uncover_engine": "-uncover-engine",
    "uncover_query": "-uncover-query", "uncover_limit": "-uncover-limit",
    "uncover_field": "-uncover-field",
    # Section 15: Sign
    "sign": "-sign", "verify": "-verify",
    "sign_key": "-sign-key", "sign_pass": "-sign-pass",
    "verify_key": "-verify-key",
}

# Options that must never be forwarded with empty/zero values.
_SKIP_IF_EMPTY = set(FLAG_MAP.keys()) - {
    "threads", "timeout", "concurrency", "fuzz_thread",
    "max_redirects", "dashboard_port", "uncover_limit",
    "headless_page_timeout", "headless_action_timeout",
}

# Go defaults; skip forwarding when value equals default to avoid
# overriding Go-side defaults unintentionally.
_GO_DEFAULTS = {
    "threads": 25, "timeout": 60, "concurrency": 25,
    "max_redirects": 10, "dashboard_port": 8484,
    "uncover_limit": 100, "fuzz_thread": 10,
    "headless_page_timeout": 10000, "headless_action_timeout": 5000,
}

DIRECT_ACTIONS = [
    "list", "list-sources", "custom-guide", "validate", "validate-deep",
    "health", "update", "probe", "version", "examples", "license",
]


class AtomixGoEngine:
    def __init__(self):
        self.binary = str(BINARY_PATH)
        self._available = None

    @property
    def available(self) -> bool:
        if self._available is not None:
            return self._available
        if not os.path.isfile(self.binary):
            self._available = False
            return False
        try:
            result = subprocess.run(
                [self.binary, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            self._available = result.returncode == 0
        except Exception:
            self._available = False
        return self._available

    def build_args(self, url: str = "", **kwargs) -> list:
        args = [self.binary]
        kwargs.pop("url", None)
        for action in DIRECT_ACTIONS:
            key = action.replace("-", "_")
            # click uses list_flag for --list
            if action == "list":
                key = "list_flag"
            if kwargs.get(key):
                args.append(f"--{action}")
                return args
        if kwargs.get("completion"):
            args.extend(["--completion", str(kwargs["completion"])])
            return args
        targets = []
        if url:
            targets.append(url)
        if kwargs.get("target_file"):
            # target-file handled via FLAG_MAP below; no -u needed
            pass
        elif url:
            args.extend(["-u", url])
        for click_key, go_flag in FLAG_MAP.items():
            if click_key not in kwargs:
                continue
            if click_key == "url":
                continue
            val = kwargs[click_key]
            if val is None or val is False:
                continue
            if isinstance(val, bool):
                if val is True:
                    args.append(go_flag)
                continue
            if isinstance(val, str) and val == "" and click_key in _SKIP_IF_EMPTY:
                continue
            if isinstance(val, (int, float)) and val == 0 and click_key in _SKIP_IF_EMPTY:
                continue
            if click_key in _GO_DEFAULTS and val == _GO_DEFAULTS[click_key]:
                # Still forward threads/timeout since Go defaults differ
                # (-c 20 vs click 25). Only skip purely optional ones.
                if click_key in ("max_redirects", "dashboard_port", "uncover_limit",
                                 "fuzz_thread", "headless_page_timeout",
                                 "headless_action_timeout", "concurrency"):
                    continue
            args.append(f"{go_flag}={val}")
        return args

    def run_direct(self, *flags: str) -> tuple:
        args = [self.binary, *flags]
        if not os.path.isfile(self.binary):
            msg = f"Go binary not found: {self.binary}"
            print(f"  [!] {msg}", file=sys.stderr)
            return "", msg, 1
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=60,
            )
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            msg = "Engine timed out"
            print(f"  [!] {msg}", file=sys.stderr)
            return "", msg, 1
        except FileNotFoundError as e:
            msg = f"Go binary not found: {e}"
            print(f"  [!] {msg}", file=sys.stderr)
            return "", msg, 1

    def list_templates(self) -> list:
        if not os.path.isfile(self.binary):
            return []
        try:
            result = subprocess.run(
                [self.binary, "-l", "-json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return []

    def run(self, url: str = "", **kwargs) -> Any:
        args = self.build_args(url, **kwargs)
        # Only force JSON when no structured format was requested.
        # Forcing --json breaks --csv/--html/--jsonl/--sarif/--md handling
        # in Go handleResults (JSON branch returns first).
        wants_structured = any(
            kwargs.get(k) for k in (
                "json_output", "jsonl", "csv", "html", "sarif", "markdown",
            )
        )
        if not wants_structured and "-json" not in args and "--json" not in args:
            args.append("-json")
        user_timeout = kwargs.get("timeout", 60)
        if not isinstance(user_timeout, int):
            try:
                user_timeout = int(user_timeout)
            except (ValueError, TypeError):
                user_timeout = 60
        user_timeout = max(1, user_timeout)
        process_timeout = min(max(user_timeout * 3, 60), 1800)
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=process_timeout,
            )
        except subprocess.TimeoutExpired:
            return [{"error": f"Engine timed out after {process_timeout}s. Use --timeout to increase."}]
        except FileNotFoundError:
            return [{"error": f"Go binary not found: {self.binary}. Build with: cd hackit/atomix/go && go build -o bin/atomix ."}]
        if result.returncode not in (0, 1):
            return [{"error": result.stderr.strip() or f"Exit code {result.returncode}"}]
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list):
                    return data
                return data
            except json.JSONDecodeError:
                pass
        # Non-JSON modes (csv/html/table) write to stdout; not an error.
        if result.stdout.strip() == "" and result.stderr.strip() == "":
            return []
        if wants_structured:
            return [{"error": "Engine returned non-JSON output", "raw": result.stdout[:2000]}]
        return []
