import httpx
import re
import asyncio
from urllib.parse import urljoin
from models import IntelligenceFinding

SENSITIVE_PATHS = {
    "config": [
        "/.env", "/.env.production", "/.env.development", "/.env.local",
        "/.env.staging", "/.env.example", "/env", "/environment",
        "/config.php", "/config.php.bak", "/config.php.old",
        "/config.json", "/config.yml", "/config.yaml", "/config.xml",
        "/configuration.php", "/configuration.yaml",
        "/app/config.php", "/app/config.yml", "/app/config.yaml",
        "/settings.py", "/settings.json", "/settings.yml",
        "/settings.php", "/settings.rb",
        "/secrets.yml", "/secrets.json", "/secret.yml", "/secret.json",
        "/credentials.json", "/credentials.yml", "/credentials.xml",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/wp-config.php~", "/wp-config-sample.php",
    ],
    "admin": [
        "/admin/", "/administrator/", "/manager/", "/backend/",
        "/cpanel/", "/whm/", "/panel/", "/dashboard/",
        "/admin.php", "/login.php", "/login.aspx", "/login.jsp",
        "/administrator/index.php", "/admin/login.php",
        "/adminpanel/", "/cp/", "/controlpanel/",
    ],
    "backup": [
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.db",
        "/backup.tar", "/backup.gz", "/backup.7z",
        "/dump.sql", "/dump.rdb", "/database.sql", "/db.sql",
        "/db_backup.sql", "/db-dump.sql", "/mysql.sql",
        "/wp-content/backup.zip", "/wp-content/backup.sql",
        "/backup/", "/_backup/", "/backups/",
        "/backup.sql.gz", "/mydb.sql", "/data.sql",
        "/site-backup.tar.gz", "/full-backup.tar.gz",
    ],
    "database": [
        "/database.yml", "/database.php", "/database.config",
        "/db.yml", "/db.json", "/db-config.php",
        "/databases.yml", "/connection.yml",
        "/app/database.php", "/app/database.yml",
        "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/mysql/",
        "/adminer.php", "/adminer-4.7.8.php",
        "/sqlite.db", "/data.db", "/app.db", "/storage.db",
    ],
    "logs": [
        "/error.log", "/access.log", "/debug.log", "/application.log",
        "/log.txt", "/logs/", "/log/",
        "/var/log/system.log", "/storage/logs/laravel.log",
        "/wp-content/debug.log", "/wp-content/debug.log.1",
        "/error_log", "/install.log", "/setup.log",
        "/cron.log", "/mail.log", "/auth.log",
    ],
    "source_code": [
        "/.git/config", "/.gitignore", "/.git/HEAD",
        "/.svn/entries", "/.svn/wc.db",
        "/.hg/", "/.bzr/",
        "/.DS_Store", "/Thumbs.db",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/sitemap.xml", "/robots.txt", "/security.txt",
        "/humans.txt", "/well-known/security.txt",
    ],
    "credentials": [
        "/.htaccess", "/.htpasswd", "/.htgroup", "/.htdigest",
        "/.aws/credentials", "/.aws/config",
        "/.azure/credentials", "/.azure/config",
        "/.gcloud/credentials", "/.gcloud/config",
        "/.ssh/id_rsa", "/.ssh/id_rsa.pub", "/.ssh/authorized_keys",
        "/.ssh/config", "/.ssh/known_hosts",
        "/.npmrc", "/.dockercfg", "/.s3cfg", "/.netrc",
        "/id_rsa", "/id_rsa.pub", "/authorized_keys",
    ],
    "api_docs": [
        "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml",
        "/api/openapi.json", "/api/openapi.yaml",
        "/api/docs", "/api/v1/", "/api/v2/", "/api/v3/",
        "/swagger/", "/swagger-ui/", "/swagger-resources",
        "/v2/api-docs", "/v3/api-docs",
        "/api/", "/rest/", "/graphql", "/graphiql", "/voyager",
        "/api/documentation",
    ],
    "cicd": [
        "/.travis.yml", "/.circleci/config.yml",
        "/.github/workflows/", "/.gitlab-ci.yml",
        "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
        "/docker-compose.yaml", "/.dockerignore",
        "/Makefile", "/.gitmodules",
        "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
    ],
    "environment": [
        "/.env", "/.env.example", "/.env.prod", "/.env.dev",
        "/.env.staging", "/.env.test", "/.env.local",
        "/environment.ts", "/environment.prod.ts",
        "/.flaskenv", "/.env.yaml",
        "/build.env", "/package.env",
    ],
    "security": [
        "/security.txt", "/.well-known/security.txt",
        "/ssl.crt", "/ssl.key", "/server.crt", "/server.key",
        "/cert.pem", "/key.pem", "/fullchain.pem",
        "/privkey.pem", "/chain.pem",
        "/.well-known/", "/acme-challenge/",
    ],
    "archives": [
        "/.git/objects/", "/.git/refs/",
        "/tmp/", "/temp/", "/cache/",
        "/files/", "/uploads/", "/upload/",
        "/downloads/", "/download/",
        "/assets/", "/static/", "/public/",
    ],
    "testing": [
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/tests/", "/test/", "/testing/",
        "/phpunit.xml", "/phpunit.xml.dist",
        "/phpinfo.php.bak", "/info.php.bak",
        "/.phpunit.result.cache",
    ],
    "debug": [
        "/actuator/health", "/actuator/info", "/actuator/env",
        "/actuator/beans", "/actuator/mappings",
        "/actuator/configprops", "/actuator/threaddump",
        "/actuator/heapdump", "/actuator/loggers",
        "/actuator/metrics", "/actuator/prometheus",
        "/actuator/", "/heapdump", "/heapdump.json",
        "/metrics", "/health", "/healthcheck",
        "/env", "/info", "/trace",
        "/.env", "/__init__.py",
    ],
}

SENSITIVE_CONTENT_SIGNATURES = {
    "AWS Access Key": [r'AKIA[0-9A-Z]{16}'],
    "Private Key": [r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE KEY'],
    "Database Credential": [r'(?i)(password|passwd|db_password|db_user).*[=:].*["\']?[a-zA-Z0-9]'],
    "API Key": [r'(?i)(api_key|apikey|api_secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}'],
    "JWT Token": [r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'],
    "Connection String": [r'(?i)(mongodb|postgresql|mysql|redis)://[^\s\'"]+'],
    "GitHub Token": [r'(?i)gh[pousr]_[0-9a-zA-Z]{36}'],
    "Slack Token": [r'(?i)xox[abposr]-[0-9a-zA-Z\-]{10,}'],
    "Discord Webhook": [r'(?:https?://)?discord(?:app)?\.com/api/webhooks/'],
    "Database Dump": [r'(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|SELECT \* FROM)'],
    "Stack Trace": [r'(?:at\s+[a-zA-Z0-9_.]+\(|Traceback \(most recent call last\)|Error:\s+\w+)'],
    "XML Config": [r'<configuration>|<\?xml version.*encoding'],
    "JSON Config": [r'"database"|"connection"|"credentials"|"secret"'],
    "Environment Variable": [r'(?i)(APP_ENV|DB_HOST|DB_PORT|DB_DATABASE|DB_USERNAME|DB_PASSWORD)\s*='],
    "IP Address": [r'\b(?:\d{1,3}\.){3}\d{1,3}\b'],
    "Email Address": [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'],
}

DIRECTORY_LISTING_INDICATORS = [
    "Index of /",
    "<title>Index of",
    "Parent Directory</a>",
    "Name</th><th>Last modified</th>",
    "Directory listing for",
]


async def _check_path(path: str, base_url: str, domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    url = urljoin(base_url, path)
    try:
        resp = await client.get(
            url, timeout=8.0, follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        status = resp.status_code
        if status in (200, 204, 401, 403, 500):
            body = resp.text[:10000] if hasattr(resp, "text") else ""
            content_type = resp.headers.get("content-type", "")
            content_length = len(resp.text) if hasattr(resp, "text") else 0

            tags = ["sensitive", "path"]
            exposed_data_types = []

            for data_type, patterns in SENSITIVE_CONTENT_SIGNATURES.items():
                for pat in patterns:
                    if re.search(pat, body):
                        exposed_data_types.append(data_type)
                        tags.append(data_type.lower().replace(" ", "_"))
                        break

            is_dir_listing = any(indicator in body for indicator in DIRECTORY_LISTING_INDICATORS)
            if is_dir_listing:
                tags.append("directory_listing")
                exposed_data_types.append("Directory Listing")

            has_default_creds = False
            default_cred_patterns = [
                r'(?i)(?:default|admin|root).*(?:password|pass|login)',
                r'(?i)(?:username|login|user)\s*[=:]\s*admin',
                r'(?i)(?:password|pass)\s*[=:]\s*(?:admin|password|1234)',
            ]
            for pat in default_cred_patterns:
                if re.search(pat, body):
                    has_default_creds = True
                    tags.append("default_credentials")
                    if "Default Credentials" not in exposed_data_types:
                        exposed_data_types.append("Default Credentials")
                    break

            severity = "Elevated Risk"
            color = "orange"
            if exposed_data_types:
                severity = "High Risk"
                color = "red"
                if "Private Key" in exposed_data_types or "AWS Access Key" in exposed_data_types:
                    severity = "Critical Risk"
                    color = "red"
            if status == 401:
                severity = "Medium Risk"
                color = "orange"
            if status == 403:
                severity = "Restricted Access"
                color = "orange"

            raw_parts = [f"HTTP {status}"]
            if exposed_data_types:
                raw_parts.append(f"Exposed: {', '.join(exposed_data_types[:3])}")
            raw_parts.append(f"Size: {content_length} bytes")
            raw_parts.append(f"Type: {content_type[:50]}")

            findings.append(IntelligenceFinding(
                entity=url,
                type="Sensitive File/Path",
                source="SensitiveFilesHunter",
                confidence="High",
                color=color,
                threat_level=severity,
                status=f"HTTP {status}",
                tags=tags,
                raw_data=" | ".join(raw_parts),
            ))

            if exposed_data_types:
                for edt in exposed_data_types[:3]:
                    findings.append(IntelligenceFinding(
                        entity=f"{url} - {edt}",
                        type=f"Exposed Data: {edt}",
                        source="SensitiveFilesHunter",
                        confidence="High",
                        color="red",
                        threat_level="Critical Risk" if edt in ("Private Key", "AWS Access Key", "Database Dump") else "High Risk",
                        status=f"HTTP {status}",
                        tags=["exposed-data", edt.lower().replace(" ", "_")],
                        raw_data=f"URL: {url}\nData Type: {edt}",
                    ))

        elif status in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            findings.append(IntelligenceFinding(
                entity=url,
                type="Sensitive Path (Redirect)",
                source="SensitiveFilesHunter",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                status=f"HTTP {status} -> {location[:80]}",
                tags=["redirect"],
            ))

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"

    all_paths = []
    for category, paths in SENSITIVE_PATHS.items():
        for path in paths:
            all_paths.append(path)

    all_paths = list(dict.fromkeys(all_paths))

    batch_size = 15
    for i in range(0, len(all_paths), batch_size):
        batch = all_paths[i:i + batch_size]
        tasks = [_check_path(p, base_url, domain, client) for p in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in batch_results:
            if isinstance(res, list):
                findings.extend(res)

    if not findings:
        http_url = f"http://{domain}"
        try:
            resp = await client.get(
                http_url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code in (200, 301, 302):
                for i in range(0, len(all_paths), batch_size):
                    batch = all_paths[i:i + batch_size]
                    tasks = [_check_path(p, http_url, domain, client) for p in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in batch_results:
                        if isinstance(res, list):
                            findings.extend(res)
        except Exception:
            pass

    summary_type_counts = {}
    for f in findings:
        if f.type and f.type not in ("Sensitive File/Path", "Sensitive Path (Redirect)"):
            summary_type_counts[f.type] = summary_type_counts.get(f.type, 0) + 1

    if summary_type_counts:
        categories = ", ".join([f"{k}({v})" for k, v in list(summary_type_counts.items())[:5]])
        findings.append(IntelligenceFinding(
            entity=f"Sensitive files scan complete: {len(findings)} hits for {domain}. Categories: {categories}",
            type="SensitiveFilesHunter Summary",
            source="SensitiveFilesHunter",
            confidence="High",
            color="purple",
            threat_level="Informational",
            tags=["summary"],
        ))
    elif findings:
        findings.append(IntelligenceFinding(
            entity=f"Sensitive files scan complete: {len(findings)} paths found for {domain}",
            type="SensitiveFilesHunter Summary",
            source="SensitiveFilesHunter",
            confidence="Medium",
            color="purple",
            threat_level="Informational",
            tags=["summary"],
        ))

    return findings
