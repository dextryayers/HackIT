import asyncio

import httpx

from osint_common import normalize_target, make_finding


EXPOSURE_PATHS = [
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD", ".svn/entries",
    "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "db.sql", "dump.sql", "database.sql",
    "config.json", "config.yml", "config.yaml", "settings.py", "local_settings.py",
    "wp-config.php.bak", "wp-config.php.save", "phpinfo.php", "info.php",
    "server-status", "actuator/env", "actuator/heapdump", "actuator/health",
    "swagger.json", "swagger.yaml", "openapi.json", "api-docs", "graphql",
    "admin", "dashboard", "cpanel", "login", "wp-admin/",
]


async def probe(client, base_url, path):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = await client.get(url, timeout=6.0, follow_redirects=False)
        if resp.status_code in (200, 401, 403):
            if resp.status_code == 200 and len(resp.text) < 8 and path not in {"admin", "login", "dashboard"}:
                return None
            threat = "High Risk" if path.startswith((".env", ".git")) or path.endswith(".sql") else "Elevated Risk"
            color = "red" if threat == "High Risk" else "orange"
            return make_finding(url, "Exposure Surface Path", "Exposure Surface Deep", "High", color,
                                threat_level=threat, status=str(resp.status_code), raw_data=resp.text[:1500],
                                tags=["exposure", path])
    except Exception:
        return None
    return None


async def crawl(target: str, client: httpx.AsyncClient):
    domain = normalize_target(target)
    base = f"https://{domain}"
    tasks = [probe(client, base, path) for path in EXPOSURE_PATHS]
    results = await asyncio.gather(*tasks)
    return [item for item in results if item]

