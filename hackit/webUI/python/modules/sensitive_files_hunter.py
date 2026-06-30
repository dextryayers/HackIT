import httpx
import re
import asyncio
from urllib.parse import urljoin
from models import IntelligenceFinding

SENSITIVE_PATHS = [
    "/.env", "/.env.production", "/.env.development", "/.env.local", "/.env.staging",
    "/.env.example", "/env", "/environment", "/.env.prod", "/.env.dev", "/.env.test",
    "/.env.docker", "/.env.dist", "/.env.bak", "/.env.old", "/env.yaml", "/env.yml",
    "/config", "/config.php", "/config.php.bak", "/config.php.old", "/config.php~",
    "/config.json", "/config.yml", "/config.yaml", "/config.xml", "/config.ini",
    "/configuration.php", "/configuration.yaml", "/configuration.json",
    "/app/config.php", "/app/config.yml", "/app/config.yaml",
    "/settings.py", "/settings.json", "/settings.yml", "/settings.php", "/settings.rb",
    "/secrets.yml", "/secrets.json", "/secret.yml", "/secret.json",
    "/credentials.json", "/credentials.yml", "/credentials.xml",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
    "/wp-config-sample.php", "/wp-config.bak", "/wp-config.old",
    "/admin", "/administrator", "/manager", "/backend", "/cpanel", "/whm",
    "/panel", "/dashboard", "/admin.php", "/login.php", "/login.aspx",
    "/login.jsp", "/administrator/index.php", "/admin/login.php",
    "/adminpanel", "/cp", "/controlpanel", "/admin/", "/administrator/",
    "/manager/", "/backend/", "/cpanel/", "/panel/", "/dashboard/",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.db",
    "/backup.tar", "/backup.gz", "/backup.7z", "/backup.bak",
    "/dump.sql", "/dump.rdb", "/database.sql", "/db.sql",
    "/db_backup.sql", "/db-dump.sql", "/mysql.sql",
    "/wp-content/backup.zip", "/wp-content/backup.sql",
    "/backup/", "/_backup/", "/backups/",
    "/backup.sql.gz", "/mydb.sql", "/data.sql",
    "/site-backup.tar.gz", "/full-backup.tar.gz",
    "/sql-backup.sql", "/mysqldump.sql", "/pgdump.sql",
    "/database.yml", "/database.php", "/database.config",
    "/db.yml", "/db.json", "/db-config.php",
    "/databases.yml", "/connection.yml",
    "/app/database.php", "/app/database.yml",
    "/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/mysql/",
    "/adminer.php", "/adminer-4.7.8.php", "/adminer-*.php",
    "/sqlite.db", "/data.db", "/app.db", "/storage.db",
    "/database.db", "/db.sqlite", "/db.sqlite3",
    "/error.log", "/access.log", "/debug.log", "/application.log",
    "/log.txt", "/logs/", "/log/",
    "/var/log/system.log", "/storage/logs/laravel.log",
    "/wp-content/debug.log", "/wp-content/debug.log.1",
    "/error_log", "/install.log", "/setup.log",
    "/cron.log", "/mail.log", "/auth.log",
    "/apache.log", "/nginx.log", "/php-error.log",
    "/syslog", "/messages.log", "/boot.log",
    "/dmesg", "/lastlog", "/wtmp", "/btmp",
    "/.git/config", "/.gitignore", "/.git/HEAD",
    "/.git/index", "/.git/description",
    "/.git/logs/HEAD", "/.git/packed-refs",
    "/.git/refs/heads/master", "/.git/ORIG_HEAD",
    "/.git/FETCH_HEAD", "/.svn/entries", "/.svn/wc.db",
    "/.svn/all-wcprops", "/.svn/text-base/",
    "/.hg/", "/.hg/hgrc", "/.hg/store/",
    "/.bzr/", "/.bzr/branch/",
    "/.DS_Store", "/Thumbs.db",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/sitemap.xml", "/robots.txt", "/security.txt",
    "/humans.txt", "/well-known/security.txt",
    "/.htaccess", "/.htpasswd", "/.htgroup", "/.htdigest",
    "/.aws/credentials", "/.aws/config",
    "/.aws/credentials.json", "/.aws/config.json",
    "/.azure/credentials", "/.azure/config",
    "/.azure/credentials.json", "/.azure/config.json",
    "/.gcloud/credentials", "/.gcloud/config",
    "/.gcloud/credentials.json", "/.gcloud/config.json",
    "/.ssh/id_rsa", "/.ssh/id_rsa.pub", "/.ssh/authorized_keys",
    "/.ssh/config", "/.ssh/known_hosts",
    "/.ssh/id_dsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
    "/.npmrc", "/.dockercfg", "/.s3cfg", "/.netrc",
    "/id_rsa", "/id_rsa.pub", "/authorized_keys",
    "/.git-credentials", "/.gitconfig",
    "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml",
    "/api/openapi.json", "/api/openapi.yaml",
    "/api/docs", "/api/v1/", "/api/v2/", "/api/v3/",
    "/swagger/", "/swagger-ui/", "/swagger-resources",
    "/v2/api-docs", "/v3/api-docs",
    "/api/", "/rest/", "/graphql", "/graphiql", "/voyager",
    "/api/documentation",
    "/.travis.yml", "/.circleci/config.yml",
    "/.github/workflows/", "/.gitlab-ci.yml",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
    "/docker-compose.yaml", "/.dockerignore",
    "/Makefile", "/.gitmodules",
    "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
    "/.gitlab-ci.yml", "/.circleci/", "/.github/",
    "/environment.ts", "/environment.prod.ts",
    "/.flaskenv", "/.env.yaml",
    "/build.env", "/package.env",
    "/security.txt", "/.well-known/security.txt",
    "/ssl.crt", "/ssl.key", "/server.crt", "/server.key",
    "/cert.pem", "/key.pem", "/fullchain.pem",
    "/privkey.pem", "/chain.pem",
    "/.well-known/", "/acme-challenge/",
    "/.git/objects/", "/.git/refs/",
    "/tmp/", "/temp/", "/cache/",
    "/files/", "/uploads/", "/upload/",
    "/downloads/", "/download/",
    "/assets/", "/static/", "/public/",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/tests/", "/test/", "/testing/",
    "/phpunit.xml", "/phpunit.xml.dist",
    "/phpinfo.php.bak", "/info.php.bak",
    "/.phpunit.result.cache",
    "/actuator/health", "/actuator/info", "/actuator/env",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/configprops", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/loggers",
    "/actuator/metrics", "/actuator/prometheus",
    "/actuator/", "/heapdump", "/heapdump.json",
    "/metrics", "/health", "/healthcheck",
    "/env", "/info", "/trace",
    "/__init__.py",
    "/.git/config", "/.git/HEAD", "/.git/refs",
    "/server-status", "/server-info", "/cgi-bin/",
    "/cgi-bin/test.cgi", "/cgi-bin/php", "/cgi-bin/status",
    "/aws.yml", "/aws.json", "/aws_config",
    "/google-services.json", "/GoogleService-Info.plist",
    "/firebase.json", "/firebase.php", "/firebase.config",
    "/Procfile", "/.slugignore", "/runtime.txt",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/Gemfile", "/Gemfile.lock", "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/yarn.lock", "/pnpm-lock.yaml", "/bower.json",
    "/Gruntfile.js", "/gulpfile.js", "/webpack.config.js",
    "/rollup.config.js", "/vite.config.js", "/tsconfig.json",
    "/.babelrc", "/.eslintrc", "/.prettierrc",
    "/.stylelintrc", "/.jshintrc",
    "/nginx.conf", "/apache.conf", "/httpd.conf",
    "/.htaccess.bak", "/.htaccess.old", "/.htaccess.sav",
    "/htaccess.txt", "/htpasswd",
    "/passwd", "/shadow", "/group",
    "/sudoers", "/sudoers.d/",
    "/mysql_history", "/psql_history", "/bash_history",
    "/zsh_history", "/fish_history",
    "/.mysql_history", "/.psql_history",
    "/.bash_history", "/.zsh_history",
    "/server.key", "/server.csr", "/server.crt",
    "/ca.key", "/ca.crt", "/ca.csr",
    "/client.key", "/client.crt", "/client.csr",
    "/private.key", "/private.pem", "/public.pem",
    "/certificate.pem", "/certificate.crt",
    "/keystore.jks", "/keystore", "/truststore.jks",
    "/.p12", "/.pfx", "/.jks",
    "/index.php.bak", "/index.php.old", "/index.php~",
    "/index.html.bak", "/index.html.old",
    "/.maintenance", "/maintenance.php",
    "/app/.env", "/app/config.php", "/app/settings.php",
    "/api/config", "/api/health", "/api/status",
    "/api/swagger.json", "/api/openapi.json",
    "/graphql", "/graphiql", "/graphql/explorer",
    "/v1/graphql", "/v2/graphql",
    "/actuator", "/actuator/health", "/actuator/info",
    "/.elasticbeanstalk/", "/ebextensions/",
    "/.platform/", "/.buildpacks",
    "/Vagrantfile", "/.vagrant/",
    "/.terraform/", "/terraform.tfstate",
    "/terraform.tfvars", "/backend.tf",
    "/.serverless/", "/serverless.yml",
    "/samconfig.toml", "/template.yaml",
    "/cloudformation.yaml", "/cloudformation.json",
    "/Pulumi.yaml", "/pulumi/",
    "/ansible.cfg", "/ansible/", "/playbook.yml",
    "/inventory.yml", "/hosts.ini",
    "/Dockerfile.prod", "/Dockerfile.dev",
    "/docker-entrypoint.sh", "/docker-entrypoint-initdb.d/",
    "/k8s/", "/kubernetes/", "/deployment.yaml",
    "/service.yaml", "/kustomization.yaml",
    "/Chart.yaml", "/helm/", "/values.yaml",
    "/.helmignore", "/templates/",
    "/Podfile", "/Podfile.lock",
    "/Cartfile", "/Cartfile.resolved",
    "/.swiftpm/", "/Package.swift",
    "/go.mod", "/go.sum", "/Gopkg.toml",
    "/Cargo.toml", "/Cargo.lock",
    "/build.gradle", "/gradle.properties",
    "/gradlew", "/gradlew.bat",
    "/pom.xml", "/settings.xml",
    "/.mvn/", "/mvnw",
    "/web.xml", "/application.xml",
    "/jboss-web.xml", "/glassfish-web.xml",
    "/context.xml", "/server.xml",
    "/tomcat-users.xml", "/catalina.policy",
    "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
    "/META-INF/context.xml",
    "/struts.xml", "/struts-config.xml",
    "/hibernate.cfg.xml", "/mybatis-config.xml",
    "/spring.xml", "/application.properties",
    "/application.yml", "/bootstrap.properties",
    "/bootstrap.yml", "/logback.xml",
    "/log4j.properties", "/log4j2.xml",
    "/logging.properties",
    "/appsettings.json", "/appsettings.Development.json",
    "/nlog.config", "/serilog.json",
    "/elastic-apm-agent.jar",
    "/newrelic.yml", "/newrelic/",
    "/datadog.yml", "/datadog/",
    "/appdynamics/", "/dynatrace/",
    "/.well-known/acme-challenge/",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/dnt-policy.txt",
    "/.well-known/gpc.json",
    "/.well-known/keybase.txt",
    "/.well-known/matrix/",
    "/.well-known/nodeinfo",
    "/.well-known/openid-configuration",
    "/.well-known/pki-validation/",
    "/.well-known/webfinger",
    "/.well-known/webrtc",
    "/server-status", "/server-info",
    "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/php5.cgi",
    "/sitemap.xml.gz", "/sitemaps.xml",
    "/sitemap_index.xml", "/sitemapindex.xml",
    "/sitemap1.xml", "/sitemap2.xml",
    "/rss.xml", "/atom.xml", "/feed.xml",
    "/robots.txt.bak", "/robots.txt.old",
    "/.svn/entries", "/.svn/wc.db",
    "/.svn/all-wcprops", "/.svn/prop-base/",
    "/.svn/text-base/", "/.svn/tmp/",
    "/CVS/", "/CVS/Root", "/CVS/Entries",
    "/.bzr.log", "/.bzr/README",
    "/.hgignore", "/.hgtags", "/.hg/branch",
    "/.DS_Store", "/.localized",
    "/thumbs.db", "/Thumbs.db:encryptable",
    "/.Trashes", "/.Spotlight-V100",
    "/.fseventsd", "/.vol",
    "/.apdisk", "/Desktop.ini",
    "/error.html", "/404.html", "/500.html",
    "/maintenance.html", "/under-construction.html",
    "/index.html", "/index.php", "/index.asp", "/index.aspx",
    "/default.aspx", "/default.asp", "/default.php",
    "/home.php", "/home.html",
    "/.bashrc", "/.bash_profile", "/.profile",
    "/.bash_logout", "/.inputrc",
    "/.vimrc", "/.viminfo", "/.exrc",
    "/.screenrc", "/.tmux.conf",
    "/.gitattributes", "/.mailmap",
    "/.editorconfig", "/.gitkeep",
    "/.nuget/", "/NuGet.Config",
    "/.dotnet/", "/global.json",
    "/project.json", "/project.lock.json",
    "/bundleconfig.json", "/tslint.json",
    "/.jscsrc", "/.jshintignore",
    "/.tern-project", "/jsconfig.json",
    "/.watchmanconfig", "/flow-typed/",
    "/.yarnrc", "/.yarn/",
    "/.npm/", "/.node_repl_history",
    "/.python-version", "/.pythonrc",
    "/.ruby-version", "/.ruby-gemset",
    "/.rbenv/", "/.rvm/",
    "/.bundler/", "/vendor/bundle/",
    "/.bundle/", "/vendor/cache/",
    "/.gem/", "/Gemfile.lock",
    "/composer.lock", "/vendor/",
    "/.php_cs", "/.php_cs.dist",
    "/.phpunit/", "/.phpunit_on_failure",
    "/phpunit.phar", "/phpunit",
    "/behat.yml", "/.behat/",
    "/codeception.yml", "/.codeception/",
    "/.perlcriticrc", "/perltidyrc",
    "/.coveralls.yml", "/.scrutinizer.yml",
    "/.codeclimate.yml", "/.codecov.yml",
    "/sonar-project.properties", "/sonar-project.json",
    "/.sensiolabs.yml", "/.styleci.yml",
    "/crowdin.yml", "/.tx/",
    "/.bootstrap.yml", "/.dockerignore",
    "/.ecr", "/.gitlab/",
    "/mercurial.ini", "/.hgrc",
    "/Procfile", "/.buildpacks",
    "/Aptfile", "/app.json",
    "/scalingo.json", "/.scalingo/",
    "/.platform.app.yaml", "/.platform/",
    "/artisan", "/.env.example",
    "/.php_cs.cache", "/.phpunit.result.cache",
    "/.phpunit_on_failure", "/.phpunit.php",
    "/.phpunit.xml", "/phpunit.xml",
    "/pint.json", "/.pint.json",
    "/.php-cs-fixer.php", "/.php-cs-fixer.dist.php",
    "/rector.php", "/rector.yaml",
    "/deptrac.yaml", "/deptrac.yml",
    "/phpstan.neon", "/phpstan.neon.dist",
    "/phpstan-baseline.neon",
    "/psalm.xml", "/psalm.xml.dist",
    "/psalm-baseline.xml",
    "/.phpdoc/", "/phpdoc.dist.xml",
    "/.phpmetrics.json", "/phpmetrics.json",
    "/infection.json", "/infection.json.dist",
    "/.phpbench/", "/phpbench.json",
    "/.dep/", "/deploy.php", "/deploy.yaml",
    "/.forge/", "/forge.yml",
    "/.envault", "/envault.json",
    "/auth.json", "/composer/auth.json",
    "/satis.json", "/packages.json",
    "/security-checker.php", "/security-checker",
    "/.capsule/", "/capsule.yml",
    "/.php_monitor/", "/php_monitor.yml",
    "/.php_watch/", "/php_watch.yml",
    "/.phplint.yml", "/.php-lint.yml",
    "/.php_cs.cache", "/.php_cs.php",
    "/.phpstorm.meta.php", "/.idea/",
    "/.vscode/", "/.vs/",
    "/phpdoc/", "/docs/",
    "/swagger/", "/redoc/",
    "/api/doc", "/api/documentation",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/.env.production", "/.env.development",
    "/.env.staging", "/.env.testing",
    "/.env.prod", "/.env.dev", "/.env.stage",
    "/.env.test", "/.env.local.php",
    "/.env.docker", "/.env.dist",
    "/.env.mysql", "/.env.postgres",
    "/.env.redis", "/.env.mongo",
    "/.env.aws", "/.env.gcp", "/.env.azure",
    "/.env.s3", "/.env.stripe",
    "/.env.mail", "/.env.smtp",
    "/.env.db", "/.env.database",
    "/.env.cache", "/.env.session",
    "/.env.queue", "/.env.log",
    "/.env.app", "/.env.api",
    "/.env.services", "/.env.integrations",
    "/.env.oauth", "/.env.auth",
    "/.env.pagination", "/.env.cors",
    "/.env.debug", "/.env.logging",
    "/.env.monitoring", "/.env.tracing",
    "/.env.features", "/.env.flags",
    "/.env.build", "/.env.docker-compose",
    "/.env.ci", "/.env.cd",
    "/.env.backup", "/.env.restore",
]

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
    "PHP Error/Notice": [r'(?:PHP Notice|PHP Warning|PHP Fatal|PHP Parse error)'],
    "SQL Error": [r'(?:SQL syntax|MySQL Syntax|SQLSTATE|PDOException|You have an error in your SQL)'],
    "Path Disclosure": [r'(?:Warning: include|Warning: require|Fatal error: Call to undefined function)'],
    "Ruby Error": [r'(?:NameError|NoMethodError|ArgumentError|TypeError)'],
    "Python Error": [r'(?:Traceback|File ".*", line \d+|ModuleNotFoundError|ImportError)'],
    "Java Error": [r'(?:Exception in thread|at org\.|at com\.|at net\.|Caused by:)'],
    "ASP.NET Error": [r'(?:Server Error in|Runtime Error|Stack Trace:.*\.cs)'],
    "NPM Token": [r'(?i)npm.*_[a-z]+[_-]?token\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}'],
    "Password in Config": [r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s\'"]{6,}["\']?'],
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
        if status in (200, 204, 401, 403, 500, 301, 302, 307, 308):
            body = resp.text[:10000] if hasattr(resp, "text") else ""
            content_type = resp.headers.get("content-type", "")
            content_length = len(resp.text) if hasattr(resp, "text") else 0

            tags = ["sensitive", "path"]
            exposed_data_types = []

            if status in (200, 204):
                for data_type, patterns in SENSITIVE_CONTENT_SIGNATURES.items():
                    for pat in patterns:
                        try:
                            if re.search(pat, body):
                                exposed_data_types.append(data_type)
                                tags.append(data_type.lower().replace(" ", "_"))
                                break
                        except:
                            pass

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

            redirect_location = ""
            if status in (301, 302, 307, 308):
                redirect_location = resp.headers.get("location", "")
                raw_parts.append(f"Redirect: {redirect_location[:80]}")

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

            if content_length == 0 and status == 200:
                findings.append(IntelligenceFinding(
                    entity=f"Empty response: {url}",
                    type="Empty Response",
                    source="SensitiveFilesHunter",
                    confidence="Medium",
                    color="yellow",
                    threat_level="Informational",
                    raw_data="Empty body returned (0 bytes)",
                    tags=["sensitive", "empty"],
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

    all_paths = list(dict.fromkeys(SENSITIVE_PATHS))

    batch_size = 20
    for i in range(0, len(all_paths), batch_size):
        batch = all_paths[i:i + batch_size]
        tasks = [_check_path(p, base_url, domain, client) for p in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in batch_results:
            if isinstance(res, list):
                findings.extend(res)

    if not any(f.status not in ("Redirect",) and f.threat_level != "Informational" for f in findings):
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
        if f.type and f.type not in ("Sensitive File/Path", "Sensitive Path (Redirect)", "Empty Response"):
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
