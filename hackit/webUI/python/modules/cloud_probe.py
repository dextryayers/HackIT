import httpx
import asyncio
from models import IntelligenceFinding

BUCKET_KEYWORDS = [
    "backup", "assets", "data", "storage", "files", "media", "static",
    "uploads", "downloads", "public", "private", "tmp", "temp",
    "logs", "config", "configs", "archive", "archives", "bucket",
    "prod", "production", "dev", "development", "stage", "staging",
    "test", "testing", "demo", "app", "application", "web", "www",
    "cdn", "content", "resources", "images", "img", "css", "js",
    "docs", "documentation", "backup", "snapshots", "database",
    "db", "sql", "mysql", "postgres", "redis", "cache",
    "videos", "audio", "music", "photos", "pictures", "screenshots",
    "profiles", "users", "userdata", "avatars", "thumbs",
    "builds", "releases", "dist", "packages", "vendor",
    "models", "weights", "training", "datasets", "ml",
    "analytics", "metrics", "monitoring", "alerts",
    "terraform", "state", "tfstate", "infrastructure",
    "kubernetes", "k8s", "docker", "containers",
    "lambda", "functions", "serverless",
    "cloudtrail", "cloudwatch", "monitoring",
    "certificates", "keys", "secrets", "credentials",
    "gitlab", "github", "bitbucket", "repos",
    "nginx", "apache", "traefik", "caddy",
    "wordpress", "wp", "drupal", "joomla", "magento",
    "shopify", "woocommerce", "ecommerce",
    "api", "rest", "graphql", "endpoint",
    "config", "settings", "env", "environment",
    "backup-old", "old-backup", "legacy", "migration",
    "export", "import", "feeds", "rss",
    "vault", "safe", "encrypted", "secure",
    "frontend", "backend", "spa", "pwa",
    "mobile", "android", "ios", "react", "vue", "angular",
    "pdf", "reports", "invoices", "receipts",
    "temp-uploads", "tmp-uploads", "attachments",
    "thumbnails", "resized", "optimized",
    "company", "corp", "enterprise", "org",
    "personal", "private", "secret", "confidential",
    "genesis", "backup", "restore",
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
]

BUCKET_PATTERNS_AZURE = [
    "{target}",
    "{target}{kw}",
    "{kw}{target}",
    "{target}-{kw}",
    "{kw}-{target}",
]

BUCKET_PATTERNS_GCP = [
    "{target}",
    "{target}-{kw}",
    "{kw}-{target}",
    "{target}_{kw}",
    "{kw}_{target}",
]


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
        if len(base_clean) + len(kw) + 1 <= 63:
            names.add(f"{base_clean}-{kw}")
            names.add(f"{kw}-{base_clean}")
            names.add(f"{base_clean}{kw}")
        if len(kw) + len(base_clean) + 2 <= 63:
            names.add(f"{base_clean}.{kw}")
            names.add(f"{kw}.{base_clean}")

    for prefix in ["prod", "dev", "test", "stag", "app", "my", "data"]:
        if len(prefix) + len(base_clean) + 1 <= 63:
            names.add(f"{prefix}-{base_clean}")

    names.add(base_clean)
    names.add(f"{base_clean}-data")
    names.add(f"{base_clean}-backup")
    names.add(f"{base_clean}-assets")
    names.add(f"{base_clean}-storage")
    names.add(f"{base_clean}-files")
    names.add(f"{base_clean}-public")
    names.add(f"{base_clean}-private")
    names.add(f"{base_clean}-media")
    names.add(f"{base_clean}-uploads")
    names.add(f"{base_clean}-static")
    names.add(f"{base_clean}-config")
    names.add(f"{base_clean}-logs")
    names.add(f"{base_clean}-archive")
    names.add(f"{base_clean}-cdn")
    names.add(f"{base_clean}-prod")
    names.add(f"{base_clean}-production")
    names.add(f"{base_clean}-dev")
    names.add(f"{base_clean}-development")
    names.add(f"{base_clean}-staging")
    names.add(f"{base_clean}-test")
    names.add(f"{base_clean}-testing")
    names.add(f"{base_clean}-db")
    names.add(f"{base_clean}-database")
    names.add(f"{base_clean}-api")
    names.add(f"{base_clean}-secrets")
    names.add(f"{base_clean}-credentials")

    return sorted(names)[:120]


import re


async def _probe_aws_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    findings = []
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
        f"https://{bucket_name}.s3.us-east-1.amazonaws.com",
    ]
    for url in urls:
        try:
            resp = await client.get(url, timeout=5.0, follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                         "Accept": "*/*"})

            if resp.status_code == 200:
                body = resp.text
                is_listing = "<ListBucketResult" in body or "<Contents>" in body
                is_public = "public" in body.lower() or "ListBucketResult" in body or resp.status_code == 200

                tags = ["cloud-probe", "aws", "s3", "bucket"]
                status = "Public"

                file_count = 0
                if is_listing:
                    file_count = body.count("<Key>")
                    if file_count > 100:
                        file_count = body.count("<Key>")

                entity_name = f"s3://{bucket_name}"
                if file_count > 0:
                    entity_name = f"s3://{bucket_name} ({file_count} objects)"

                findings.append(IntelligenceFinding(
                    entity=entity_name,
                    type="AWS S3 Bucket (Public)",
                    source="CloudProbe",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status=status,
                    resolution=url,
                    raw_data=f"Bucket: {bucket_name}, Objects: {file_count}, URL: {url}",
                    tags=tags + (["exposed"] if file_count > 0 else [])
                ))

                if file_count > 0:
                    findings.append(IntelligenceFinding(
                        entity=f"s3://{bucket_name} - {file_count} objects exposed",
                        type="Exposed S3 Data",
                        source="CloudProbe",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Data Exposed",
                        resolution=url,
                        raw_data=f"{file_count} objects found in public bucket {bucket_name}",
                        tags=tags + ["exposed-data"]
                    ))

                break

            elif resp.status_code == 403:
                body = resp.text
                if "AllAccessDisabled" not in body and "AccessDenied" in body:
                    findings.append(IntelligenceFinding(
                        entity=f"s3://{bucket_name}",
                        type="AWS S3 Bucket (Exists)",
                        source="CloudProbe",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Exists (Denied)",
                        resolution=url,
                        raw_data=f"Bucket {bucket_name} exists but access denied at {url}",
                        tags=["cloud-probe", "aws", "s3", "bucket"]
                    ))
                    break

            elif resp.status_code == 301 or resp.status_code == 307:
                location = resp.headers.get("location", "")
                if "s3" in location:
                    findings.append(IntelligenceFinding(
                        entity=f"s3://{bucket_name}",
                        type="AWS S3 Bucket (Redirect)",
                        source="CloudProbe",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Redirects",
                        resolution=location[:200],
                        raw_data=f"Bucket {bucket_name} redirects to {location}",
                        tags=["cloud-probe", "aws", "s3", "bucket"]
                    ))
                    break

        except Exception:
            continue
    return findings


async def _probe_azure_blob(container_name: str, client: httpx.AsyncClient) -> list:
    findings = []
    urls = [
        f"https://{container_name}.blob.core.windows.net",
        f"https://{container_name}.blob.core.windows.net/?restype=container&comp=list",
    ]
    for url in urls:
        try:
            resp = await client.get(url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0", "x-ms-version": "2021-08-06",
                         "Accept": "*/*"})

            if resp.status_code == 200:
                body = resp.text
                is_listing = "Blobs" in body or "Blob" in body or "Container" in body

                findings.append(IntelligenceFinding(
                    entity=f"azure://{container_name}",
                    type="Azure Blob Container (Public)",
                    source="CloudProbe",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Public",
                    resolution=url,
                    raw_data=f"Azure Blob: {container_name}, URL: {url}",
                    tags=["cloud-probe", "azure", "blob", "storage"]
                ))
                break

            elif resp.status_code in (403, 400):
                x_ms_err = resp.headers.get("x-ms-error-code", "")
                if x_ms_err not in ("ContainerNotFound", "AuthenticationFailed"):
                    findings.append(IntelligenceFinding(
                        entity=f"azure://{container_name}",
                        type="Azure Blob Container (Exists)",
                        source="CloudProbe",
                        confidence="High",
                        color="orange",
                        threat_level="Standard Target",
                        status="Exists",
                        resolution=url,
                        raw_data=f"Azure container {container_name} exists. Error: {x_ms_err}",
                        tags=["cloud-probe", "azure", "blob", "storage"]
                    ))
                    break

        except Exception:
            continue
    return findings


async def _probe_gcp_bucket(bucket_name: str, client: httpx.AsyncClient) -> list:
    findings = []
    urls = [
        f"https://storage.googleapis.com/{bucket_name}",
        f"https://{bucket_name}.storage.googleapis.com",
        f"https://storage.cloud.google.com/{bucket_name}",
    ]
    for url in urls:
        try:
            resp = await client.get(url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0",
                         "Accept": "*/*"})

            if resp.status_code == 200:
                body = resp.text
                is_listing = "Contents" in body or "storage" in body.lower()

                findings.append(IntelligenceFinding(
                    entity=f"gs://{bucket_name}",
                    type="GCP Cloud Storage (Public)",
                    source="CloudProbe",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Public",
                    resolution=url,
                    raw_data=f"GCP Bucket: {bucket_name}, URL: {url}",
                    tags=["cloud-probe", "gcp", "storage", "bucket"]
                ))
                break

            elif resp.status_code in (403, 400):
                findings.append(IntelligenceFinding(
                    entity=f"gs://{bucket_name}",
                    type="GCP Cloud Storage (Exists)",
                    source="CloudProbe",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="Exists",
                    resolution=url,
                    raw_data=f"GCP Bucket {bucket_name} exists at {url}",
                    tags=["cloud-probe", "gcp", "storage", "bucket"]
                ))
                break

        except Exception:
            continue
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()

    base_domain = _extract_base_domain(target)
    bucket_names = _generate_bucket_names(base_domain)

    aws_tasks = [_probe_aws_bucket(name, client) for name in bucket_names]
    azure_tasks = [_probe_azure_blob(name, client) for name in bucket_names[:60]]
    gcp_tasks = [_probe_gcp_bucket(name, client) for name in bucket_names[:60]]

    all_results = await asyncio.gather(*aws_tasks, *azure_tasks, *gcp_tasks, return_exceptions=True)

    for result in all_results:
        if isinstance(result, list):
            findings.extend(result)

    aws_public = sum(1 for f in findings if "AWS S3 Bucket (Public)" in f.type)
    azure_public = sum(1 for f in findings if "Azure Blob Container (Public)" in f.type)
    gcp_public = sum(1 for f in findings if "GCP Cloud Storage (Public)" in f.type)
    aws_exists = sum(1 for f in findings if "AWS S3 Bucket (Exists)" in f.type)
    azure_exists = sum(1 for f in findings if "Azure Blob Container (Exists)" in f.type)
    gcp_exists = sum(1 for f in findings if "GCP Cloud Storage (Exists)" in f.type)

    if aws_public > 0 or azure_public > 0 or gcp_public > 0 or aws_exists > 0 or azure_exists > 0 or gcp_exists > 0:
        findings.append(IntelligenceFinding(
            entity=f"Cloud Probe Complete: {aws_public + azure_public + gcp_public} public, {aws_exists + azure_exists + gcp_exists} restricted",
            type="Cloud Probe Summary",
            source="CloudProbe",
            confidence="High",
            color="red" if (aws_public + azure_public + gcp_public) > 0 else "orange",
            threat_level="Elevated Risk" if (aws_public + azure_public + gcp_public) > 0 else "Standard Target",
            status="Complete",
            resolution=f"{len(bucket_names)} names probed",
            raw_data=f"AWS: {aws_public} public / {aws_exists} exists | Azure: {azure_public} public / {azure_exists} exists | GCP: {gcp_public} public / {gcp_exists} exists",
            tags=["cloud-probe", "summary"]
        ))

    return findings
