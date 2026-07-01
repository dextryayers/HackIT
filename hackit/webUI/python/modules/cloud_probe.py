import httpx
import asyncio
import re
import socket
from models import IntelligenceFinding

BUCKET_KEYWORDS = [
    "backup", "assets", "data", "storage", "files", "media", "static",
    "uploads", "downloads", "public", "private", "tmp", "temp",
    "logs", "config", "configs", "archive", "archives", "bucket",
    "prod", "production", "dev", "development", "stage", "staging",
    "test", "testing", "demo", "app", "application", "web", "www",
    "cdn", "content", "resources", "images", "img", "css", "js",
    "docs", "documentation", "snapshots", "database",
    "db", "sql", "mysql", "postgres", "redis", "cache",
    "videos", "audio", "music", "photos", "pictures", "screenshots",
    "profiles", "users", "userdata", "avatars", "thumbs",
    "builds", "releases", "dist", "packages", "vendor",
    "models", "weights", "training", "datasets", "ml",
    "analytics", "metrics", "monitoring", "alerts",
    "terraform", "state", "tfstate", "infrastructure",
    "kubernetes", "k8s", "docker", "containers",
    "lambda", "functions", "serverless",
    "cloudtrail", "cloudwatch",
    "certificates", "keys", "secrets", "credentials",
    "gitlab", "github", "bitbucket", "repos",
    "nginx", "apache", "traefik", "caddy",
    "wordpress", "wp", "drupal", "joomla", "magento",
    "shopify", "woocommerce", "ecommerce",
    "api", "rest", "graphql", "endpoint",
    "settings", "env", "environment",
    "backup-old", "old-backup", "legacy", "migration",
    "export", "import", "feeds", "rss",
    "vault", "safe", "encrypted", "secure",
    "frontend", "backend", "spa", "pwa",
    "mobile", "android", "ios", "react", "vue", "angular",
    "pdf", "reports", "invoices", "receipts",
    "temp-uploads", "tmp-uploads", "attachments",
    "thumbnails", "resized", "optimized",
    "company", "corp", "enterprise", "org",
    "personal", "secret", "confidential",
    "genesis", "restore",
    "helm", "charts",
    "ssl", "tls", "encryption", "password",
    "tracking", "events", "streams", "pipelines",
    "billing", "payments", "orders", "customers", "clients", "vendors",
    "binaries", "artifacts", "dependencies",
    "qa", "uat",
    "go", "my", "the", "get",
    "app", "web", "site", "info", "service",
    "automation", "scripts", "ansible", "puppet", "chef", "salt",
    "policies", "compliance", "audit", "logs-audit",
    "internal", "external", "partner", "vendor-portal",
    "marketing", "sales", "support", "helpdesk",
    "docs-api", "swagger", "openapi", "postman",
    "sdk", "cli", "toolkit", "utilities",
    "sync", "replication", "mirror", "clones",
    "processed", "raw", "cleaned", "enriched",
    "index", "search", "elasticsearch", "solr",
    "ingest", "ingestion", "collector", "collectors",
    "events", "event", "stream", "streaming", "queue",
    "pubsub", "notifications", "notification", "webhooks",
    "templates", "template", "layouts", "views", "partials",
    "locales", "i18n", "translations", "language",
    "fonts", "font", "icons", "icon", "sprites",
    "sounds", "music", "audio", "podcasts",
    "ebooks", "epub", "pdfs", "documents",
    "readme", "license", "changelog",
    "installer", "setup", "msi", "dmg", "pkg",
    "clients", "client", "customer", "customers",
    "partners", "partner", "vendors", "vendor",
    "wholesale", "retail", "distributor",
    "inventory", "stock", "products", "product",
    "pricing", "price", "catalog", "catalogue",
    "invoices", "invoice", "receipt", "receipts",
    "orders", "order", "shipment", "shipments",
    "tracking", "track", "delivery", "deliveries",
    "leads", "lead", "prospects", "prospect",
    "opportunities", "opportunity", "deal", "deals",
    "contracts", "contract", "agreements", "agreement",
    "patches", "patch", "hotfix", "hotfixes",
    "updates", "update", "upgrade", "upgrades",
    "migration", "migrations", "schema", "schemas",
    "playbooks", "runbooks", "guides", "handbook",
    "compliance", "audits", "audit", "soc2", "iso27001",
    "gdpr", "hipaa", "pci", "pci-dss",
    "security", "security-audit", "pentest", "vulnerability",
    "risk", "risks", "threat", "threats",
    "incident", "incidents", "response", "response-plan",
    "okr", "okrs", "kpi", "kpis", "metrics",
    "users", "user", "accounts", "account",
    "sessions", "session", "sso", "oauth",
    "permissions", "roles", "rbac", "acl",
]

BUCKET_PATTERNS_AWS = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}.{kw}",
    "{kw}.{target}",
    "{tld}{target}",
    "{target}{tld}",
    "{kw}-{target}-{env}",
    "{target}-{env}-{kw}",
    "{prefix}-{target}-{kw}",
    "{target}-{kw}-{suffix}",
    "{prefix}-{kw}-{target}",
]

BUCKET_PATTERNS_AZURE = [
    "{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}-{env}-{kw}",
    "{kw}-{target}-{env}",
    "{prefix}{target}{kw}",
    "{target}{kw}{suffix}",
]

BUCKET_PATTERNS_GCP = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}_{kw}",
    "{kw}_{target}",
    "{target}-{env}-{kw}",
    "{kw}_{target}_{env}",
    "{prefix}-{target}-{kw}",
]

BUCKET_PATTERNS_DO = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{env}-{kw}",
    "{prefix}{target}{kw}",
]

BUCKET_PATTERNS_WASABI = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{env}-{kw}",
]

BUCKET_PATTERNS_B2 = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{env}-{kw}",
]

BUCKET_PATTERNS_R2 = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{env}-{kw}",
]

BUCKET_PATTERNS_ALIBABA = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{env}-{kw}",
]

BUCKET_PATTERNS_IBM = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
]

BUCKET_PATTERNS_LINODE = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
]

BUCKET_PATTERNS_VULTR = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
]

BUCKET_PATTERNS_HETZNER = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
]

BUCKET_PATTERNS_SCALEWAY = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}{kw}",
    "{kw}{target}",
]

SENSITIVE_FILENAMES = [
    ".env", "config.json", "credentials", ".git/config",
    ".aws/credentials", "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
    "passwords.txt", "secrets.yml", "secrets.yaml",
    "database.yml", "database.yaml", "wp-config.php",
    "config.php", "settings.php", "appsettings.json",
    "credentials.json", "service-account.json",
    ".npmrc", ".dockercfg", "docker-compose.yml",
    "kubeconfig", "admin.conf", "kubectl-config",
    "terraform.tfstate", "terraform.tfvars",
    "s3cfg", ".s3cfg", "aws-credentials",
    "backup.sql", "dump.sql", "db_backup.sql",
    "composer.json", "package.json", "yarn.lock",
    "private.pem", "private.key", "server.key",
    "htpasswd", ".htpasswd", ".htaccess",
    "master.key", "secret_key_base",
    "keystore.jks", "truststore.jks",
    "saml.cert", "saml.key",
    "token.txt", "oauth_token", "api_token",
    "vault-key.json", "vault-token",
    "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
    "psql.sh", "mysql.sh", "mongo.sh",
    "redis.conf", "mongod.conf", "postgresql.conf",
    "docker-compose.override.yml",
    "Makefile", "Dockerfile", "docker-compose.prod.yml",
    ".git-credentials", ".gitconfig",
    "smtp_config.php", "mail_settings.json",
    "recaptcha.json", "stripe_key", "billing.config",
]

PREFIXES = ["go-", "my-", "the-", "get-"]
SUFFIXES = ["-app", "-web", "-site", "-info", "-service"]
ENVIRONMENTS = ["dev", "test", "prod", "stg"]


def _extract_base_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _generate_bucket_names(base: str) -> list:
    names = set()
    base_lower = base.lower()
    base_clean = re.sub(r'[^a-z0-9-]', '', base_lower)
    if not base_clean:
        return []

    for kw in BUCKET_KEYWORDS:
        entry = re.sub(r'[^a-z0-9-]', '', kw.lower())
        if not entry:
            continue
        if len(base_clean) + len(entry) + 1 <= 63:
            names.add(f"{base_clean}-{entry}")
            names.add(f"{entry}-{base_clean}")
            names.add(f"{base_clean}{entry}")
            names.add(f"{entry}{base_clean}")
        if len(base_clean) + len(entry) + 2 <= 63:
            names.add(f"{base_clean}.{entry}")
            names.add(f"{entry}.{base_clean}")

        for env in ENVIRONMENTS:
            combo1 = f"{entry}-{base_clean}-{env}"
            combo2 = f"{base_clean}-{env}-{entry}"
            if len(combo1) <= 63:
                names.add(combo1)
            if len(combo2) <= 63:
                names.add(combo2)

        for prefix in PREFIXES:
            combo = f"{prefix}{entry}-{base_clean}"
            if len(combo) <= 63:
                names.add(combo)
            combo = f"{prefix}{base_clean}-{entry}"
            if len(combo) <= 63:
                names.add(combo)

        for suffix in SUFFIXES:
            combo = f"{entry}-{base_clean}{suffix}"
            if len(combo) <= 63:
                names.add(combo)
            combo = f"{base_clean}-{entry}{suffix}"
            if len(combo) <= 63:
                names.add(combo)

    for prefix in ["prod", "dev", "test", "stag", "app", "my", "data", "go", "the"]:
        if len(prefix) + len(base_clean) + 1 <= 63:
            names.add(f"{prefix}-{base_clean}")

    for suffix in ["-data", "-backup", "-assets", "-storage", "-files", "-public",
                   "-private", "-media", "-uploads", "-static", "-config", "-logs",
                   "-archive", "-cdn", "-prod", "-production", "-dev", "-development",
                   "-staging", "-test", "-testing", "-db", "-database", "-api",
                   "-secrets", "-credentials", "-app", "-web", "-site", "-service",
                   "-info", "-bucket", "-store"]:
        if len(base_clean) + len(suffix) <= 63:
            names.add(f"{base_clean}{suffix}")

    for env in ENVIRONMENTS:
        combo = f"{base_clean}-{env}"
        if len(combo) <= 63:
            names.add(combo)
        for kw_env in ["backup", "data", "assets", "config", "db", "cache", "logs"]:
            combo = f"{base_clean}-{env}-{kw_env}"
            if len(combo) <= 63:
                names.add(combo)
            combo = f"{base_clean}-{kw_env}-{env}"
            if len(combo) <= 63:
                names.add(combo)

    names.add(base_clean)

    return sorted(names)[:200]


async def _dns_resolve(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        return True
    except socket.gaierror:
        return False


async def _check_dns(hostnames: list) -> dict:
    results = {}
    tasks = []
    for hn in hostnames:
        tasks.append(_dns_resolve(hn))
    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    for i, hn in enumerate(hostnames):
        r = resolved[i]
        results[hn] = r if isinstance(r, bool) else False
    return results


def _classify_content_type(content_type: str) -> str:
    ct = content_type.lower()
    if "text/html" in ct:
        return "html"
    if "application/json" in ct or "json" in ct:
        return "json"
    if "application/xml" in ct or "text/xml" in ct:
        return "xml"
    if "image/" in ct:
        return "image"
    if "video/" in ct:
        return "video"
    if "audio/" in ct:
        return "audio"
    if "application/pdf" in ct:
        return "pdf"
    if "application/zip" in ct or "application/gzip" in ct or "application/x-tar" in ct:
        return "archive"
    if "text/" in ct:
        return "text"
    if "application/octet-stream" in ct:
        return "binary"
    if "application/javascript" in ct or "text/javascript" in ct:
        return "javascript"
    if "application/x-www-form-urlencoded" in ct or "multipart/" in ct:
        return "form-data"
    return "unknown"


def _check_leak(body: str, url: str) -> list:
    leaks = []
    body_lower = body.lower()
    haystack = body_lower
    if "aws_access_key_id" in haystack or "aws_secret_access_key" in haystack:
        leaks.append(("AWS Credentials", url))
    if "AKIA" in haystack and len(haystack) > 20:
        count = haystack.count("AKIA")
        if count > 0:
            leaks.append(("AWS Access Key (AKIA*)", url))
    if "-----begin rsa private key-----" in haystack:
        leaks.append(("RSA Private Key", url))
    if "-----begin openssh private key-----" in haystack:
        leaks.append(("SSH Private Key", url))
    if "-----begin pgp private key block-----" in haystack:
        leaks.append(("PGP Private Key", url))
    if "-----begin certificate-----" in haystack:
        leaks.append(("Certificate", url))
    if "password=" in haystack or "\"password\":" in haystack:
        leaks.append(("Password Leak", url))
    if "smtp" in haystack and "password" in haystack:
        leaks.append(("SMTP Credentials", url))
    if "jdbc:" in haystack:
        leaks.append(("JDBC Connection String", url))
    if "mongodb://" in haystack or "mongodb+srv://" in haystack:
        leaks.append(("MongoDB Connection String", url))
    if "postgresql://" in haystack or "postgres://" in haystack:
        leaks.append(("PostgreSQL Connection String", url))
    if "mysql://" in haystack or "mysql+pymysql://" in haystack:
        leaks.append(("MySQL Connection String", url))
    if "redis://" in haystack:
        leaks.append(("Redis Connection String", url))
    if "slack" in haystack and ("token" in haystack or "webhook" in haystack or "api_key" in haystack):
        leaks.append(("Slack Token/Webhook", url))
    if "ghp_" in haystack or "gho_" in haystack or "ghu_" in haystack or "ghs_" in haystack:
        leaks.append(("GitHub Token", url))
    if "sk_live_" in haystack or "pk_live_" in haystack:
        leaks.append(("Stripe Live Key", url))
    if "xoxb-" in haystack or "xoxp-" in haystack or "xoxa-" in haystack:
        leaks.append(("Slack Bot Token", url))
    if "db_password" in haystack or "db_password" in haystack:
        leaks.append(("Database Password", url))
    if "api_key" in haystack or "apikey" in haystack or "api-key" in haystack:
        leaks.append(("API Key", url))
    if "secret" in haystack and ("key" in haystack or "token" in haystack):
        leaks.append(("Secret Key/Token", url))
    return leaks


async def _probe_provider_bucket(name: str, provider: str, display_name: str, urls: list,
                                  client: httpx.AsyncClient, tags: list, exists_patterns: tuple = None) -> list:
    findings = []
    dns_results = await _check_dns(urls)
    resolved_urls = [u for u in urls if dns_results.get(u, False)]
    if not resolved_urls:
        resolved_urls = urls

    for url in resolved_urls:
        try:
            resp = await client.get(url, timeout=5.0, follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                         "Accept": "*/*"})

            if resp.status_code == 200:
                body = resp.text
                content_type = resp.headers.get("content-type", "")
                ct_category = _classify_content_type(content_type)
                is_listing = False
                file_count = 0
                sample_files = []
                leaks = []

                if provider in ("aws", "gcp", "do", "wasabi"):
                    is_listing = "<ListBucketResult" in body or "<Contents>" in body
                    if is_listing:
                        file_count = body.count("<Key>")
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        sample_files = keys[:20]
                elif provider == "azure":
                    is_listing = "Blobs" in body or "Blob" in body or "EnumerationResults" in body
                    if is_listing:
                        keys = re.findall(r"<Name>([^<]+)</Name>", body)
                        file_count = len(keys)
                        sample_files = keys[:20]
                elif provider == "alibaba":
                    is_listing = "ListBucketResult" in body or "Contents" in body
                    if is_listing:
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        file_count = len(keys)
                        sample_files = keys[:20]
                elif provider == "ibm":
                    is_listing = "ListBucketResult" in body or "Contents" in body
                    if is_listing:
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        file_count = len(keys)
                        sample_files = keys[:20]
                else:
                    if "ListBucketResult" in body or "<Contents>" in body:
                        is_listing = True
                        keys = re.findall(r"<Key>([^<]+)</Key>", body)
                        file_count = len(keys)
                        sample_files = keys[:20]

                if file_count > 0:
                    leaks = _check_leak(body, url)

                entity_name = f"{provider}://{name}"
                if file_count > 0:
                    entity_name = f"{provider}://{name} ({file_count} objects)"

                raw = f"Bucket: {name}, Objects: {file_count}, URL: {url}, Content-Type: {content_type}"
                if sample_files:
                    raw += f", Samples: {', '.join(sample_files[:5])}"
                if leaks:
                    raw += f", Leaks: {'; '.join([l[0] for l in leaks])}"

                all_tags = tags + ["exposed"] if file_count > 0 else tags
                if leaks:
                    all_tags = all_tags + ["leak"]

                findings.append(IntelligenceFinding(
                    entity=entity_name,
                    type=f"{display_name} (Public)",
                    source="CloudProbe",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Public",
                    resolution=url,
                    raw_data=raw,
                    tags=all_tags
                ))

                if file_count > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider}://{name} - {file_count} objects exposed",
                        type=f"Exposed {display_name} Data",
                        source="CloudProbe",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Data Exposed",
                        resolution=url,
                        raw_data=f"{file_count} objects found in public {provider} bucket {name}",
                        tags=all_tags + ["exposed-data"]
                    ))

                for leak_type, leak_url in leaks:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider}://{name} - {leak_type}",
                        type="Leak Detected",
                        source="CloudProbe",
                        confidence="High",
                        color="red",
                        threat_level="Critical Risk",
                        status="Leak Found",
                        resolution=leak_url,
                        raw_data=f"{leak_type} detected in bucket {name} at {leak_url}",
                        tags=all_tags + ["leak", "critical"]
                    ))

                break

            elif resp.status_code == 403:
                body = resp.text
                denied_signals = ["AccessDenied", "access_denied", "Access denied"]
                exists_signal = any(sig in body for sig in denied_signals)
                not_found_signals = ["NoSuchBucket", "The specified bucket does not exist", "not found", "NotFound"]
                not_found = any(sig in body for sig in not_found_signals)

                if exists_signal and not not_found:
                    redir = resp.headers.get("location", "")
                    if redir:
                        redir = redir[:200]
                    findings.append(IntelligenceFinding(
                        entity=f"{provider}://{name}",
                        type=f"{display_name} (Exists - Denied)",
                        source="CloudProbe",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Exists (Denied)",
                        resolution=redir or url,
                        raw_data=f"Bucket {name} exists but access denied at {url}",
                        tags=tags
                    ))
                    break
                elif not_found:
                    break
                else:
                    findings.append(IntelligenceFinding(
                        entity=f"{provider}://{name}",
                        type=f"{display_name} (Exists)",
                        source="CloudProbe",
                        confidence="Medium",
                        color="orange",
                        threat_level="Standard Target",
                        status="Exists (Denied)",
                        resolution=url,
                        raw_data=f"Bucket {name} returned 403 at {url}",
                        tags=tags
                    ))
                    break

            elif resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "")
                sig = location.lower()
                redirect_keywords = ["s3", "storage", "blob", "bucket", provider]
                if any(kw in sig for kw in redirect_keywords):
                    findings.append(IntelligenceFinding(
                        entity=f"{provider}://{name}",
                        type=f"{display_name} (Redirect)",
                        source="CloudProbe",
                        confidence="Medium",
                        color="orange",
                        threat_level="Standard Target",
                        status="Redirects",
                        resolution=location[:200],
                        raw_data=f"Bucket {name} redirects to {location}",
                        tags=tags
                    ))
                    break

            elif resp.status_code == 400:
                if "not found" in resp.text.lower() or "nosuchbucket" in resp.text.lower():
                    break
                findings.append(IntelligenceFinding(
                    entity=f"{provider}://{name}",
                    type=f"{display_name} (Exists)",
                    source="CloudProbe",
                    confidence="Low",
                    color="orange",
                    threat_level="Informational",
                    status="Exists (400)",
                    resolution=url,
                    raw_data=f"Bucket {name} returned 400 at {url}",
                    tags=tags
                ))
                break

            elif resp.status_code == 404:
                break

        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            continue
        except Exception:
            continue
    return findings


async def _probe_aws_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
        f"https://{bucket_name}.s3.us-east-1.amazonaws.com",
        f"https://{bucket_name}.s3.us-west-2.amazonaws.com",
        f"https://{bucket_name}.s3.eu-west-1.amazonaws.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "aws", "AWS S3 Bucket", urls, client,
        ["cloud-probe", "aws", "s3", "bucket"]
    )


async def _probe_azure_blob(container_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{container_name}.blob.core.windows.net",
        f"https://{container_name}.blob.core.windows.net/?restype=container&comp=list",
    ]
    return await _probe_provider_bucket(
        container_name, "azure", "Azure Blob Container", urls, client,
        ["cloud-probe", "azure", "blob", "storage"]
    )


async def _probe_gcp_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://storage.googleapis.com/{bucket_name}",
        f"https://{bucket_name}.storage.googleapis.com",
        f"https://storage.cloud.google.com/{bucket_name}",
    ]
    return await _probe_provider_bucket(
        bucket_name, "gcp", "GCP Cloud Storage", urls, client,
        ["cloud-probe", "gcp", "storage", "bucket"]
    )


async def _probe_do_space(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.digitaloceanspaces.com",
        f"https://{bucket_name}.nyc3.digitaloceanspaces.com",
        f"https://{bucket_name}.sfo3.digitaloceanspaces.com",
        f"https://{bucket_name}.ams3.digitaloceanspaces.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "do", "DigitalOcean Space", urls, client,
        ["cloud-probe", "digitalocean", "space", "storage"]
    )


async def _probe_wasabi_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.s3.wasabisys.com",
        f"https://{bucket_name}.s3.us-east-2.wasabisys.com",
        f"https://{bucket_name}.s3.us-west-1.wasabisys.com",
        f"https://{bucket_name}.s3.eu-central-1.wasabisys.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "wasabi", "Wasabi Hot Storage", urls, client,
        ["cloud-probe", "wasabi", "s3", "storage"]
    )


async def _probe_b2_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.backblazeb2.com",
        f"https://{bucket_name}.s3.us-west-002.backblazeb2.com",
        f"https://{bucket_name}.s3.us-west-004.backblazeb2.com",
        f"https://{bucket_name}.s3.eu-central-001.backblazeb2.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "b2", "Backblaze B2 Bucket", urls, client,
        ["cloud-probe", "backblaze", "b2", "storage"]
    )


async def _probe_r2_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.r2.cloudflarestorage.com",
        f"https://{bucket_name}.us-east-1.r2.cloudflarestorage.com",
        f"https://{bucket_name}.eu-west-1.r2.cloudflarestorage.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "r2", "Cloudflare R2 Bucket", urls, client,
        ["cloud-probe", "cloudflare", "r2", "storage"]
    )


async def _probe_alibaba_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.oss-cn-hangzhou.aliyuncs.com",
        f"https://{bucket_name}.oss-us-east-1.aliyuncs.com",
        f"https://{bucket_name}.oss-eu-west-1.aliyuncs.com",
        f"https://{bucket_name}.oss-ap-southeast-1.aliyuncs.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "alibaba", "Alibaba OSS Bucket", urls, client,
        ["cloud-probe", "alibaba", "oss", "storage"]
    )


async def _probe_ibm_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.s3.us-south.cloud-object-storage.appdomain.cloud",
        f"https://{bucket_name}.s3.us-east.cloud-object-storage.appdomain.cloud",
        f"https://{bucket_name}.s3.eu-gb.cloud-object-storage.appdomain.cloud",
        f"https://{bucket_name}.s3.eu-de.cloud-object-storage.appdomain.cloud",
    ]
    return await _probe_provider_bucket(
        bucket_name, "ibm", "IBM Cloud COS Bucket", urls, client,
        ["cloud-probe", "ibm", "cos", "storage"]
    )


async def _probe_linode_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.us-east-1.linodeobjects.com",
        f"https://{bucket_name}.eu-central-1.linodeobjects.com",
        f"https://{bucket_name}.ap-south-1.linodeobjects.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "linode", "Linode Object Storage", urls, client,
        ["cloud-probe", "linode", "object-storage", "storage"]
    )


async def _probe_vultr_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.vultrobjects.com",
        f"https://{bucket_name}.ewr1.vultrobjects.com",
        f"https://{bucket_name}.sjo1.vultrobjects.com",
    ]
    return await _probe_provider_bucket(
        bucket_name, "vultr", "Vultr Object Storage", urls, client,
        ["cloud-probe", "vultr", "object-storage", "storage"]
    )


async def _probe_hetzner_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.fsn1.hetzner.cloud",
        f"https://{bucket_name}.nbg1.hetzner.cloud",
        f"https://{bucket_name}.hel1.hetzner.cloud",
    ]
    return await _probe_provider_bucket(
        bucket_name, "hetzner", "Hetzner Object Storage", urls, client,
        ["cloud-probe", "hetzner", "object-storage", "storage"]
    )


async def _probe_scaleway_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    urls = [
        f"https://{bucket_name}.s3.fr-par.scw.cloud",
        f"https://{bucket_name}.s3.nl-ams.scw.cloud",
        f"https://{bucket_name}.s3.pl-waw.scw.cloud",
    ]
    return await _probe_provider_bucket(
        bucket_name, "scaleway", "Scaleway Object Storage", urls, client,
        ["cloud-probe", "scaleway", "s3", "storage"]
    )


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()

    base_domain = _extract_base_domain(target)
    bucket_names = _generate_bucket_names(base_domain)

    probe_tasks = []
    for name in bucket_names:
        probe_tasks.append(_probe_aws_bucket(name, client))
        probe_tasks.append(_probe_azure_blob(name, client))
        probe_tasks.append(_probe_gcp_bucket(name, client))
        probe_tasks.append(_probe_do_space(name, client))
        probe_tasks.append(_probe_wasabi_bucket(name, client))
        probe_tasks.append(_probe_b2_bucket(name, client))
        probe_tasks.append(_probe_r2_bucket(name, client))
        probe_tasks.append(_probe_alibaba_bucket(name, client))
        probe_tasks.append(_probe_ibm_bucket(name, client))
        probe_tasks.append(_probe_linode_bucket(name, client))
        probe_tasks.append(_probe_vultr_bucket(name, client))
        probe_tasks.append(_probe_hetzner_bucket(name, client))
        probe_tasks.append(_probe_scaleway_bucket(name, client))

    all_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

    for result in all_results:
        if isinstance(result, list):
            findings.extend(result)

    provider_map = {
        "AWS S3 Bucket": "aws",
        "AWS S3 Bucket (Exists - Denied)": "aws",
        "Azure Blob Container": "azure",
        "Azure Blob Container (Exists)": "azure",
        "GCP Cloud Storage": "gcp",
        "GCP Cloud Storage (Exists)": "gcp",
        "DigitalOcean Space": "do",
        "Wasabi Hot Storage": "wasabi",
        "Backblaze B2 Bucket": "b2",
        "Cloudflare R2 Bucket": "r2",
        "Alibaba OSS Bucket": "alibaba",
        "IBM Cloud COS Bucket": "ibm",
        "Linode Object Storage": "linode",
        "Vultr Object Storage": "vultr",
        "Hetzner Object Storage": "hetzner",
        "Scaleway Object Storage": "scaleway",
    }

    provider_public = {}
    provider_exists = {}
    for ptype, pkey in provider_map.items():
        provider_public[pkey] = sum(1 for f in findings if ptype in f.type and "Public" in f.type)
        provider_exists[pkey] = sum(1 for f in findings if ptype in f.type and "Exists" in f.type)

    total_public = sum(provider_public.values())
    total_exists = sum(provider_exists.values())
    total_leaks = sum(1 for f in findings if f.type == "Leak Detected")

    if total_public > 0 or total_exists > 0 or total_leaks > 0:
        raw_lines = []
        for pkey in sorted(provider_public.keys()):
            pub = provider_public[pkey]
            ex = provider_exists[pkey]
            if pub > 0 or ex > 0:
                raw_lines.append(f"{pkey}: {pub} public / {ex} exists")

        if total_leaks > 0:
            raw_lines.append(f"Leaks: {total_leaks}")

        security_score = max(0, 100 - (total_public * 15 + total_exists * 5 + total_leaks * 25))

        summary_raw = " | ".join(raw_lines) if raw_lines else "No buckets found"
        summary_raw += f" | Security Score: {security_score}/100"

        color = "red"
        threat = "Elevated Risk"
        if total_public > 0:
            color = "red"
            threat = "Elevated Risk"
        elif total_leaks > 0:
            color = "red"
            threat = "Critical Risk"
        elif total_exists > 0:
            color = "orange"
            threat = "Standard Target"

        findings.append(IntelligenceFinding(
            entity=f"Cloud Probe Complete: {total_public} public, {total_exists} restricted, {total_leaks} leaks",
            type="Cloud Probe Summary",
            source="CloudProbe",
            confidence="High",
            color=color,
            threat_level=threat,
            status="Complete",
            resolution=f"{len(bucket_names)} names probed across {len(provider_map)} providers",
            raw_data=summary_raw,
            tags=["cloud-probe", "summary"]
        ))

        if total_leaks > 0:
            findings.append(IntelligenceFinding(
                entity=f"Cloud Probe: {total_leaks} data leaks detected in public buckets",
                type="Cloud Probe Leak Summary",
                source="CloudProbe",
                confidence="High",
                color="red",
                threat_level="Critical Risk",
                status="Leaks Detected",
                resolution=f"{total_leaks} leaks in public buckets",
                raw_data=summary_raw,
                tags=["cloud-probe", "leak-summary", "critical"]
            ))

    async def analyze_provider_breakdown():
        for pkey in sorted(provider_public.keys()):
            pub = provider_public[pkey]
            ex = provider_exists[pkey]
            if pub > 0 or ex > 0:
                findings.append(IntelligenceFinding(entity=f"{pkey}: {pub} public, {ex} restricted", type="Provider Breakdown", source="CloudProbe", confidence="Medium", color="orange" if pub else "slate", tags=[pkey, "breakdown"]))
        findings.append(IntelligenceFinding(entity=f"Providers with results: {sum(1 for v in provider_public.values() if v > 0) + sum(1 for v in provider_exists.values() if v > 0)}", type="Provider Count", source="CloudProbe", confidence="Medium", color="slate", tags=["breakdown"]))

    async def analyze_security_score():
        findings.append(IntelligenceFinding(entity=f"Security score: {100 - total_public * 15 - total_exists * 5 - total_leaks * 25}/100", type="Security Score", source="CloudProbe", confidence="Medium", color="red" if total_public else "emerald", tags=["security"]))
        findings.append(IntelligenceFinding(entity=f"Total probes: {len(bucket_names)} x {len(provider_map)} providers", type="Probe Volume", source="CloudProbe", confidence="Medium", color="slate", tags=["security"]))

    async def analyze_exposure_summary():
        findings.append(IntelligenceFinding(entity=f"Exposed buckets: {total_public}", type="Exposure Summary", source="CloudProbe", confidence="Medium", color="red" if total_public else "emerald", tags=["exposure"]))
        findings.append(IntelligenceFinding(entity=f"Data leaks: {total_leaks}", type="Leak Summary", source="CloudProbe", confidence="Medium", color="red" if total_leaks else "emerald", tags=["exposure"]))
        findings.append(IntelligenceFinding(entity=f"Restricted buckets: {total_exists}", type="Restricted Summary", source="CloudProbe", confidence="Medium", color="orange" if total_exists else "slate", tags=["exposure"]))
        findings.append(IntelligenceFinding(entity="Review public bucket configurations immediately", type="Security Recommendation", source="CloudProbe", confidence="Medium", color="orange", tags=["exposure"]))

    async def analyze_probe_coverage():
        findings.append(IntelligenceFinding(entity=f"Keywords used: {len(bucket_names)}", type="Probe Coverage: Keywords", source="CloudProbe", confidence="Medium", color="slate", tags=["coverage"]))
        findings.append(IntelligenceFinding(entity=f"Total bucket probes: {len(bucket_names) * len(provider_map)}", type="Probe Coverage: Total Probes", source="CloudProbe", confidence="Medium", color="slate", tags=["coverage"]))
        findings.append(IntelligenceFinding(entity=f"Providers tested: {len(provider_map)}", type="Probe Coverage: Providers", source="CloudProbe", confidence="Medium", color="slate", tags=["coverage"]))

    async def analyze_provider_risk():
        findings.append(IntelligenceFinding(entity=f"AWS buckets public: {provider_public.get('aws', 0)}", type="Provider Risk: AWS", source="CloudProbe", confidence="Medium", color="red" if provider_public.get('aws', 0) else "emerald", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"Azure containers public: {provider_public.get('azure', 0)}", type="Provider Risk: Azure", source="CloudProbe", confidence="Medium", color="red" if provider_public.get('azure', 0) else "emerald", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"GCP buckets public: {provider_public.get('gcp', 0)}", type="Provider Risk: GCP", source="CloudProbe", confidence="Medium", color="red" if provider_public.get('gcp', 0) else "emerald", tags=["risk"]))
        findings.append(IntelligenceFinding(entity="Enable logging and monitoring for all cloud storage", type="Monitoring Recommendation", source="CloudProbe", confidence="Medium", color="orange", tags=["risk"]))

    async def analyze_leak_impact():
        findings.append(IntelligenceFinding(entity=f"Leak severity: {'Critical' if total_leaks > 0 else 'None'}", type="Leak Impact", source="CloudProbe", confidence="Medium", color="red" if total_leaks else "emerald", tags=["leak"]))
        findings.append(IntelligenceFinding(entity=f"Security posture: {'Compromised' if total_public > 0 else 'Secure'}", type="Security Posture", source="CloudProbe", confidence="Medium", color="red" if total_public else "emerald", tags=["leak"]))

    async def analyze_bucket_inventory():
        bucket_names_list = bucket_names
        findings.append(IntelligenceFinding(entity=f"Keyword inventory: {len(bucket_names_list)} names tested", type="Bucket Inventory: Keywords", source="CloudProbe", confidence="Medium", color="slate", tags=["inventory"]))
        findings.append(IntelligenceFinding(entity=f"Unique providers: {len(provider_map)}", type="Bucket Inventory: Providers", source="CloudProbe", confidence="Medium", color="slate", tags=["inventory"]))
        findings.append(IntelligenceFinding(entity=f"Leak detection: {total_leaks} data leaks found", type="Bucket Inventory: Leaks", source="CloudProbe", confidence="Medium", color="red" if total_leaks else "emerald", tags=["inventory"]))
        findings.append(IntelligenceFinding(entity=f"Accessible buckets: {total_public + total_exists}", type="Bucket Inventory: Accessible", source="CloudProbe", confidence="Medium", color="orange" if (total_public + total_exists) else "emerald", tags=["inventory"]))

    async def analyze_security_tier():
        security_score = max(0, 100 - (total_public * 15 + total_exists * 5 + total_leaks * 25))
        tier = "Secure" if security_score >= 80 else "At Risk" if security_score >= 50 else "Critical"
        findings.append(IntelligenceFinding(entity=f"Security tier: {tier} (score: {security_score}/100)", type="Security Tier", source="CloudProbe", confidence="Medium", color="green" if tier == "Secure" else "red", tags=["tier"]))
        findings.append(IntelligenceFinding(entity=f"Exposure impact: {total_public + total_leaks} exposed resource(s)", type="Exposure Impact", source="CloudProbe", confidence="Medium", color="red", tags=["tier"]))
        findings.append(IntelligenceFinding(entity="Implement automated bucket scanning in CI/CD pipeline", type="Proactive Recommendation", source="CloudProbe", confidence="Medium", color="orange", tags=["tier"]))

    async def analyze_scan_recommendations():
        findings.append(IntelligenceFinding(entity=f"All major cloud providers covered: {len(provider_map)}", type="Scan Recommendation: Coverage", source="CloudProbe", confidence="Medium", color="slate", tags=["rec"]))
        findings.append(IntelligenceFinding(entity=f"Findings across providers: {total_public + total_exists + total_leaks}", type="Scan Recommendation: Total Findings", source="CloudProbe", confidence="Medium", color="purple", tags=["rec"]))
        findings.append(IntelligenceFinding(entity=f"Leak/findings ratio: {round(total_leaks/max(total_public + total_exists + total_leaks,1)*100,1)}%", type="Scan Recommendation: Leak Ratio", source="CloudProbe", confidence="Medium", color="red", tags=["rec"]))
        findings.append(IntelligenceFinding(entity="Review and rotate all exposed bucket credentials immediately", type="Scan Recommendation: Immediate", source="CloudProbe", confidence="Medium", color="red", tags=["rec"]))
        findings.append(IntelligenceFinding(entity="Set up automated monitoring for new public buckets", type="Scan Recommendation: Monitoring", source="CloudProbe", confidence="Medium", color="orange", tags=["rec"]))
        findings.append(IntelligenceFinding(entity=f"Cloud providers: AWS, Azure, GCP, DigitalOcean, Wasabi, Backblaze, Cloudflare R2, Alibaba, IBM, Linode, Vultr, Hetzner, Scaleway", type="Scan Recommendation: Provider List", source="CloudProbe", confidence="Medium", color="slate", tags=["rec"]))
        findings.append(IntelligenceFinding(entity=f"Keywords used for bucket discovery: {len(bucket_names)}", type="Scan Recommendation: Keywords", source="CloudProbe", confidence="Medium", color="slate", tags=["rec"]))

    await asyncio.gather(
        analyze_provider_breakdown(),
        analyze_security_score(),
        analyze_exposure_summary(),
        analyze_probe_coverage(),
        analyze_provider_risk(),
        analyze_leak_impact(),
        analyze_bucket_inventory(),
        analyze_security_tier(),
        analyze_scan_recommendations(),
    )

    return findings
