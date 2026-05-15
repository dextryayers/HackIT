import httpx
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    # common sensitive files and paths
    secrets = [
        "/.env", "/.git/config", "/.vscode/sftp.json", 
        "/.htaccess", "/web.config", "/config.php",
        "/phpinfo.php", "/server-status", "/robots.txt",
        "/backup.sql", "/dump.sql", "/.aws/credentials",
        "/.ssh/id_rsa", "/.npmrc", "/.docker/config.json"
    ]
    
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    for path in secrets:
        try:
            url = f"{base_url}{path}"
            resp = await client.get(url, follow_redirects=False, timeout=5.0)
            
            if resp.status_code == 200:
                # Basic check to avoid false positives (like custom 404 pages)
                content = resp.text.lower()
                is_sensitive = False
                
                if ".env" in path and ("db_host" in content or "api_key" in content or "app_key" in content):
                    is_sensitive = True
                elif ".git/config" in path and "repository" in content:
                    is_sensitive = True
                elif "phpinfo" in path and "php version" in content:
                    is_sensitive = True
                elif ".sql" in path and ("insert into" in content or "create table" in content):
                    is_sensitive = True
                elif "server-status" in path and "apache" in content:
                    is_sensitive = True
                elif path in ["/robots.txt", "/.htaccess"]: # Always interesting
                    is_sensitive = True
                
                if is_sensitive:
                    findings.append(IntelligenceFinding(
                        entity=url,
                        type="Sensitive File",
                        source="SecretFinder",
                        confidence="High",
                        color="red",
                        category="Information Disclosure",
                        threat_level="High Risk",
                        status="Live",
                        raw_data=resp.text[:1000] # Capture first 1k chars
                    ))
        except:
            continue
            
    return findings
