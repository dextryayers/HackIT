import subprocess
import json
import os
import asyncio

ENGINE_PATH = os.path.join(os.path.dirname(__file__), "modules", "rust_engine", "target", "release", "hackit_engine")
if not os.path.exists(ENGINE_PATH):
    debug_path = os.path.join(os.path.dirname(__file__), "modules", "rust_engine", "target", "debug", "hackit_engine")
    if os.path.exists(debug_path):
        ENGINE_PATH = debug_path

async def run_engine(command: str, target: str, timeout: int = 30) -> dict:
    if not os.path.exists(ENGINE_PATH):
        return {"error": f"Rust engine not found at {ENGINE_PATH}"}
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: subprocess.run(
                [ENGINE_PATH, command, target],
                capture_output=True, text=True, timeout=timeout
            )
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip() or f"Exit code {result.returncode}"}
        if not result.stdout.strip():
            return {"error": "No output"}
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from engine"}
    except subprocess.TimeoutExpired:
        return {"error": "Engine timed out"}
    except Exception as e:
        return {"error": str(e)}

async def scan_subdomains(domain: str) -> list:
    data = await run_engine("subdomain", domain)
    return data if isinstance(data, list) else []

async def scan_ports(host: str) -> list:
    data = await run_engine("ports", host)
    return data if isinstance(data, list) else []

async def scan_dns(domain: str) -> dict:
    data = await run_engine("dns", domain)
    return data if isinstance(data, dict) else {}

async def scan_emails(domain: str) -> dict:
    data = await run_engine("email", domain)
    return data if isinstance(data, dict) else {}

async def scan_webtech(url: str) -> dict:
    data = await run_engine("webtech", url)
    return data if isinstance(data, dict) else {}

async def scan_all(target: str) -> dict:
    data = await run_engine("all", target, timeout=120)
    return data if isinstance(data, dict) else {"error": "No data"}
