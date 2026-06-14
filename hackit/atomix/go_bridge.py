import os, sys, json, subprocess, tempfile
from pathlib import Path
from typing import Optional, Any

BINARY_PATH = Path(__file__).parent / "go" / "bin" / "atomix"

FLAG_MAP = {
    "url": "-u", "target_file": "-target-file", "exclude_file": "-exclude-file",
    "scope_file": "-scope-file", "resume": "-resume", "exclude_pat": "-ep",
    "severity": "-severity", "tags": "-tags", "exclude_tags": "-etag",
    "exclude_severity": "-es", "id": "-id", "author": "-author", "type": "-type",
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

BOOL_FLAGS = {
    "json", "json_output", "list_flag", "silent", "verbose", "debug", "no_color", "jsonl", "csv", "html",
    "sarif", "stats", "metrics", "analytics", "follow_redirects", "rand_agent",
    "http2", "http2_downgrade", "keep_alive", "waf_skip", "waf_bypass",
    "detect_tech", "api_discovery", "interactsh", "smart", "dashboard", "multi",
    "scan_all_ips", "no_cache", "priority", "adaptive_rate", "fuzz_recursive",
    "headless", "no_sandbox", "show_browser", "system_chrome",
    "tls_impersonate", "uncover", "allow_local_access",
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
            if kwargs.get(key):
                args.append(f"--{action}")
                return args
        if kwargs.get("completion"):
            args.extend(["--completion", kwargs["completion"]])
            return args
        if url:
            args.extend(["-u", url])
        for click_key, go_flag in FLAG_MAP.items():
            if click_key not in kwargs:
                continue
            val = kwargs[click_key]
            if val is None or val is False:
                continue
            if isinstance(val, bool):
                args.append(go_flag)
            else:
                args.append(f"{go_flag}={val}")
        return args

    def run_direct(self, flag: str) -> tuple:
        args = [self.binary, flag]
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

    def list_templates(self) -> list:
        try:
            result = subprocess.run(
                [self.binary, "-l", "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except Exception:
            pass
        return []

    def run(self, url: str = "", **kwargs) -> Any:
        args = self.build_args(url, **kwargs)
        if "--json" not in args and "--list" not in args:
            args.append("--json")
        user_timeout = kwargs.get("timeout", 60)
        if not isinstance(user_timeout, int):
            try:
                user_timeout = int(user_timeout)
            except (ValueError, TypeError):
                user_timeout = 60
        process_timeout = max(user_timeout * 3, 600)
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=process_timeout,
            )
        except subprocess.TimeoutExpired:
            return [{"error": f"Engine timed out after {process_timeout}s. Use --timeout to increase."}]
        if result.returncode not in (0, 1):
            return [{"error": result.stderr.strip() or f"Exit code {result.returncode}"}]
        if result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        return []
