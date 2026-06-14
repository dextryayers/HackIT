import httpx
import asyncio
import re
from collections import defaultdict
from urllib.parse import urlparse
from models import IntelligenceFinding

CLOUD_PROVIDERS = {
    "AWS S3": [
        ("https://{name}.s3.amazonaws.com/", "virtual"),
        ("https://s3.amazonaws.com/{name}/", "path"),
        ("https://{name}.s3.us-east-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.us-west-2.amazonaws.com/", "regional"),
        ("https://{name}.s3.eu-west-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.eu-central-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.ap-southeast-1.amazonaws.com/", "regional"),
        ("https://{name}.s3-website-us-east-1.amazonaws.com/", "website"),
        ("https://{name}.s3-website-us-west-2.amazonaws.com/", "website"),
    ],
    "AWS CloudFront": [
        ("https://{name}.cloudfront.net/", "cloudfront"),
    ],
    "Azure Blob": [
        ("https://{name}.blob.core.windows.net/", "standard"),
        ("https://{name}storage.blob.core.windows.net/", "suffixed"),
        ("https://{name}data.blob.core.windows.net/", "data"),
        ("https://{name}assets.blob.core.windows.net/", "assets"),
        ("https://{name}backup.blob.core.windows.net/", "backup"),
        ("https://{name}media.blob.core.windows.net/", "media"),
    ],
    "Azure Container": [
        ("https://{name}.blob.core.windows.net/$web/", "static-web"),
    ],
    "GCP Storage": [
        ("https://storage.googleapis.com/{name}/", "path"),
        ("https://{name}.storage.googleapis.com/", "virtual"),
    ],
    "GCP Firebase": [
        ("https://{name}.firebaseio.com/", "firebase"),
        ("https://{name}.web.app/", "firebase-hosting"),
    ],
    "DigitalOcean Spaces": [
        ("https://{name}.digitaloceanspaces.com/", "standard"),
        ("https://{name}.nyc3.digitaloceanspaces.com/", "nyc"),
        ("https://{name}.ams3.digitaloceanspaces.com/", "ams"),
        ("https://{name}.sgp1.digitaloceanspaces.com/", "sgp"),
    ],
    "Oracle OCI": [
        ("https://objectstorage.{region}.oraclecloud.com/n/{name}/b/", "object-storage"),
        ("https://{name}.objectstorage.{region}.oraclecloud.com/", "v2"),
    ],
    "Alibaba OSS": [
        ("https://{name}.oss-cn-hangzhou.aliyuncs.com/", "cn-hangzhou"),
        ("https://{name}.oss-us-east-1.aliyuncs.com/", "us-east"),
        ("https://{name}.oss-eu-central-1.aliyuncs.com/", "eu-central"),
        ("https://{name}.oss-ap-southeast-1.aliyuncs.com/", "ap-southeast"),
    ],
    "IBM Cloud COS": [
        ("https://{name}.s3.us-south.cloud-object-storage.appdomain.cloud/", "us-south"),
        ("https://{name}.s3.eu-de.cloud-object-storage.appdomain.cloud/", "eu-de"),
    ],
    "Vultr Object": [
        ("https://{name}.vultrobjects.com/", "standard"),
        ("https://{name}.ewr1.vultrobjects.com/", "ewr1"),
    ],
    "Linode Object": [
        ("https://{name}.us-east-1.linodeobjects.com/", "us-east"),
        ("https://{name}.eu-central-1.linodeobjects.com/", "eu-central"),
    ],
    "Scaleway COS": [
        ("https://{name}.s3.fr-par.scw.cloud/", "fr-par"),
        ("https://{name}.s3.nl-ams.scw.cloud/", "nl-ams"),
    ],
    "Hetzner Object": [
        ("https://{name}.fsn1.hetzner.cloud/", "fsn1"),
        ("https://{name}.nbg1.hetzner.cloud/", "nbg1"),
    ],
    "UpCloud": [
        ("https://{name}.upcloudobjects.com/", "standard"),
    ],
    "Backblaze B2": [
        ("https://{name}.s3.us-west-002.backblazeb2.com/", "us-west"),
        ("https://{name}.s3.eu-central-003.backblazeb2.com/", "eu-central"),
    ],
    "Wasabi": [
        ("https://{name}.s3.us-east-2.wasabisys.com/", "us-east"),
        ("https://{name}.s3.eu-central-1.wasabisys.com/", "eu-central"),
    ],
    "StackPath": [
        ("https://{name}.storage.stackpathresearch.com/", "standard"),
    ],
}

BUCKET_NAMING_PATTERNS = [
    "{base}", "{base}-data", "{base}-assets", "{base}-media", "{base}-static",
    "{base}-backup", "{base}-uploads", "{base}-files", "{base}-public",
    "{base}-private", "{base}-dev", "{base}-staging", "{base}-prod",
    "{base}-test", "{base}-storage", "{base}-content", "{base}-resources",
    "{base}-images", "{base}-docs", "{base}-config", "{base}-logs",
    "{base}-app", "{base}-web", "{base}-bucket", "{base}-container",
    "{base}-archive", "{base}-db", "{base}-database", "{base}-backups",
    "{base}-cdn", "{base}-dl", "{base}-download", "{base}-transfer",
    "{base}-share", "{base}-sync", "{base}-state", "{base}-terraform",
    "{base}-cloud", "{base}-s3", "{base}-blob", "{base}-store",
    "{base}-service", "{base}-api", "{base}-frontend", "{base}-backend",
    "{base}-spaces", "{base}-oss", "{base}-cos", "{base}-data-lake",
    "data-{base}", "assets-{base}", "media-{base}", "static-{base}",
    "backup-{base}", "uploads-{base}", "files-{base}", "public-{base}",
    "private-{base}", "dev-{base}", "staging-{base}", "prod-{base}",
    "test-{base}", "storage-{base}", "content-{base}", "resources-{base}",
    "app-{base}", "web-{base}", "bucket-{base}", "cdn-{base}",
    "archive-{base}", "db-{base}", "logs-{base}", "config-{base}",
    "{base}-01", "{base}-02", "{base}-v2", "{base}-prod-01",
]

OCIREGIONS = ["us-phoenix-1", "us-ashburn-1", "eu-frankfurt-1", "uk-london-1",
    "ap-mumbai-1", "ap-osaka-1", "ap-sydney-1", "ap-tokyo-1", "sa-saopaulo-1"]

CLOUDFRONT_DOMAINS = [
    "cloudfront.net", "s3.amazonaws.com", "s3-us-east-1.amazonaws.com",
    "s3-website-us-east-1.amazonaws.com", "s3-website-us-west-2.amazonaws.com",
    "storage.googleapis.com", "blob.core.windows.net", "digitaloceanspaces.com",
]

async def check_bucket(client, url, platform, style, base_name):
    try:
        resp = await client.get(url, timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        status = resp.status_code
        content_type = resp.headers.get("content-type", "")
        body = resp.text[:500].lower() if hasattr(resp, "text") else ""

        if status == 200:
            is_listing = False
            has_index = False

            if "listbucketresult" in body or "contents" in body or \
               "commonprefixes" in body or "<key>" in body or \
               "etag" in body:
                is_listing = True
            if "index.html" in body or "index.htm" in body:
                has_index = True
            if content_type == "application/xml" and ("list" in body or "bucket" in body):
                is_listing = True

            tags = ["cloud-storage", "public"]
            if is_listing:
                tags.append("listing-enabled")

            finding = IntelligenceFinding(
                entity=url[:200],
                type="Cloud Storage Bucket",
                source=f"{platform} Hunter",
                confidence="High",
                color="red" if is_listing else "cyan",
                category="Cloud / Infrastructure OSINT",
                threat_level="Critical" if is_listing else "Medium",
                status="Public" if not is_listing else "Public + Listing",
                resolution=f"Platform: {platform}",
                raw_data=f"Public bucket accessible on {platform}. "
                        f"Style: {style}. Listing: {is_listing}",
                tags=tags
            )
            return finding

        elif status == 403:
            return IntelligenceFinding(
                entity=url[:200],
                type="Cloud Storage Bucket",
                source=f"{platform} Hunter",
                confidence="High",
                color="yellow",
                category="Cloud / Infrastructure OSINT",
                threat_level="Low",
                status="Private",
                resolution=f"Platform: {platform}",
                raw_data=f"Protected bucket on {platform}. Returns 403 Forbidden",
                tags=["cloud-storage", "private"]
            )

        elif status == 404:
            pass

    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass
    return None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    base = domain.split(".")[0] if "." in domain else domain
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base or len(base) < 2:
        base = domain.replace(".", "-")

    names_to_check = set()
    names_to_check.add(base)
    names_to_check.add(f"{base}-storage")
    names_to_check.add(f"{base}-data")
    names_to_check.add(f"{base}-assets")
    names_to_check.add(f"{base}-public")

    for pattern in BUCKET_NAMING_PATTERNS:
        name = pattern.format(base=base)
        if len(name) > 3 and len(name) <= 63:
            names_to_check.add(name)
    names_to_check = list(names_to_check)[:150]

    tasks = []
    for name in names_to_check:
        for platform, endpoints in CLOUD_PROVIDERS.items():
            for url_template, style in endpoints:
                if "{region}" in url_template and "Oracle" in platform:
                    for region in OCIREGIONS:
                        url = url_template.format(name=name, region=region)
                        tasks.append((name, platform, url, style))
                else:
                    url = url_template.format(name=name)
                    tasks.append((name, platform, url, style))

    semaphore = asyncio.Semaphore(30)
    bucket_results = []

    async def bounded_check(name, platform, url, style):
        async with semaphore:
            return await check_bucket(client, url, platform, style, name)

    batch_results = await asyncio.gather(*[
        bounded_check(name, platform, url, style)
        for name, platform, url, style in tasks
    ], return_exceptions=True)

    for r in batch_results:
        if r and isinstance(r, IntelligenceFinding):
            bucket_results.append(r)

    provider_counts = defaultdict(int)
    public_count = 0
    listing_count = 0
    for f in bucket_results:
        provider = f.source.replace(" Hunter", "")
        provider_counts[provider] += 1
        if "Public" in f.status:
            public_count += 1
        if "Listing" in f.status:
            listing_count += 1

    findings.extend(bucket_results)

    if bucket_results:
        top_providers = sorted(provider_counts.items(), key=lambda x: -x[1])[:5]
        prov_str = ", ".join(f"{p}({c})" for p, c in top_providers)
        findings.append(IntelligenceFinding(
            entity=f"{len(bucket_results)} buckets found across {len(provider_counts)} providers | "
                   f"Public: {public_count}, Listable: {listing_count}",
            type="Cloud Storage Summary",
            source="Cloud Infrastructure Hunter",
            confidence="High",
            color="blue",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            status="Summary",
            raw_data=f"Providers: {prov_str}",
            tags=["cloud", "summary"]
        ))

        if listing_count > 0:
            findings.append(IntelligenceFinding(
                entity=f"{listing_count} buckets allow object listing!",
                type="Bucket Listing Warning",
                source="Cloud Infrastructure Hunter",
                confidence="High",
                color="red",
                category="Cloud / Infrastructure OSINT",
                threat_level="Critical",
                status="Listing Enabled",
                tags=["cloud", "listing", "critical"]
            ))

    return findings
