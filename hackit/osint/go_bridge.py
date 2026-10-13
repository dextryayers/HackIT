import subprocess
import json
import os
from typing import Optional

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_engine_binary():
    base = os.path.join(ENGINE_DIR, "go", "osint")
    if os.name == "nt" and not os.path.exists(base) and os.path.exists(base + ".exe"):
        return base + ".exe"
    return base


GO_ENGINE = _resolve_engine_binary()


def check_username(
    username: str,
    proxy: Optional[str] = None,
    retry: int = 1,
    timeout: int = 15,
    workers: int = 50,
    raw: bool = False,
) -> dict:
    if not os.path.exists(GO_ENGINE):
        return {"username": username, "results": [], "summary": None, "error": f"Engine not found at {GO_ENGINE}"}

    cmd = [GO_ENGINE, "-u", username, "--retry", str(retry), "--timeout", str(timeout), "--workers", str(workers), "--json"]
    if proxy:
        cmd.extend(["--proxy", proxy])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and not result.stdout:
            return {"username": username, "results": [], "summary": None, "error": result.stderr}
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError as e:
        return {"username": username, "results": [], "summary": None, "error": f"JSON parse error: {e}"}
    except subprocess.TimeoutExpired:
        return {"username": username, "results": [], "summary": None, "error": "Engine timed out"}
    except FileNotFoundError:
        return {"username": username, "results": [], "summary": None, "error": f"Engine not found: {GO_ENGINE}"}
    except Exception as e:
        return {"username": username, "results": [], "summary": None, "error": str(e)}
