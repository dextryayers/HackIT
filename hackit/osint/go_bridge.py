import subprocess
import json
import os
from typing import Optional

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
GO_ENGINE = os.path.join(ENGINE_DIR, "go", "osint")


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
