import httpx
import asyncio
from models import IntelligenceFinding

async def probe_file(client, base_url, path, description):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        # Use HEAD request for speed if possible, or GET with limited range
        resp = await client.get(url, timeout=5.0, follow_redirects=False)
        
        # Check for status codes that indicate the file exists or is protected
        if resp.status_code == 200:
            # Basic check to avoid false positives from "200 OK" error pages
            if len(resp.text) < 10: return None
            
            return IntelligenceFinding(
                entity=path,
                type="Sensitive File Disclosure",
                source="Sensitive Files Hunter",
                confidence="High",
                color="red",
                category="Vulnerability",
                threat_level="Critical",
                status="FOUND",
                raw_data=f"Sensitive file found at {url}. Description: {description}"
            )
        elif resp.status_code in [401, 403]:
            return IntelligenceFinding(
                entity=path,
                type="Protected Sensitive Path",
                source="Sensitive Files Hunter",
                confidence="Medium",
                color="orange",
                category="Vulnerability",
                threat_level="Medium",
                status="ACCESS DENIED",
                raw_data=f"Path exists but access is restricted (401/403) at {url}. This confirms the existence of the resource."
            )
    except:
        pass
    return None

async def crawl(target, client):
    findings = []
    
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    # Combined list from sfp_junkfiles and other sources
    critical_paths = [
        (".env", "Environment configuration file (often contains passwords/keys)"),
        (".git/config", "Git repository configuration (reveals source code structure)"),
        (".git/HEAD", "Git repository metadata"),
        (".svn/entries", "SVN metadata"),
        (".DS_Store", "Mac OS metadata file"),
        ("package.json", "Node.js dependencies and scripts"),
        ("composer.json", "PHP dependencies"),
        ("docker-compose.yml", "Docker infrastructure definition"),
        ("Dockerfile", "Docker container definition"),
        ("backup.sql", "Database backup"),
        ("dump.sql", "Database dump"),
        ("backup.zip", "Site backup"),
        ("config.php.bak", "PHP configuration backup"),
        ("wp-config.php.save", "WordPress config backup"),
        (".htaccess", "Apache server configuration"),
        ("web.config", "IIS server configuration"),
        ("robots.txt", "Robots exclusion (often points to hidden paths)"),
        ("phpinfo.php", "PHP server information"),
        ("info.php", "PHP information leak"),
        ("server-status", "Apache server status leak"),
    ]
    
    # Run probes concurrently for maximum performance (Powerful++)
    tasks = [probe_file(client, base_url, path, desc) for path, desc in critical_paths]
    results = await asyncio.gather(*tasks)
    
    for r in results:
        if r:
            findings.append(r)
            
    # Logic for Strange Headers (from sfp_strangeheaders)
    try:
        resp = await client.head(base_url, timeout=5.0)
        strange_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime", "Via", "X-Cache"]
        for header in strange_headers:
            val = resp.headers.get(header)
            if val:
                findings.append(IntelligenceFinding(
                    entity=header,
                    type="Information Leakage Header",
                    source="Strange Headers Radar",
                    confidence="Certain",
                    color="yellow",
                    category="Fingerprinting",
                    threat_level="Low",
                    status="Detected",
                    raw_data=f"Header '{header}' reveals backend technology: {val}"
                ))
    except:
        pass
        
    return findings
