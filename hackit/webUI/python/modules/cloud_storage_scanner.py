import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding
from models import IntelligenceFinding

PROVIDER_CONFIGS = {
    "AWS S3": {
        "urls": ["https://{name}.s3.amazonaws.com", "https://s3.amazonaws.com/{name}",
                 "https://{name}.s3.us-east-1.amazonaws.com", "https://{name}.s3.us-west-2.amazonaws.com",
                 "https://{name}.s3.eu-west-1.amazonaws.com", "https://{name}.s3-website-us-east-1.amazonaws.com"],
        "tag": ["aws", "s3"],
        "xml_listing": "ListBucketResult"
    },
    "GCP GCS": {
        "urls": ["https://storage.googleapis.com/{name}", "https://{name}.storage.googleapis.com",
                 "https://storage.cloud.google.com/{name}"],
        "tag": ["gcp", "gcs"],
        "xml_listing": "ListBucketResult"
    },
    "Azure Blob": {
        "urls": ["https://{name}.blob.core.windows.net", "https://{name}.blob.core.windows.net/?restype=container&comp=list",
                 "https://{name}storage.blob.core.windows.net"],
        "tag": ["azure", "blob"],
        "xml_listing": "EnumerationResults"
    },
    "DigitalOcean Spaces": {
        "urls": ["https://{name}.digitaloceanspaces.com", "https://{name}.nyc3.digitaloceanspaces.com",
                 "https://{name}.ams3.digitaloceanspaces.com", "https://{name}.sgp1.digitaloceanspaces.com",
                 "https://{name}.sfo3.digitaloceanspaces.com"],
        "tag": ["digitalocean", "spaces"],
        "xml_listing": "ListBucketResult"
    },
    "Linode Object": {
        "urls": ["https://{name}.us-east-1.linodeobjects.com", "https://{name}.eu-central-1.linodeobjects.com",
                 "https://{name}.ap-south-1.linodeobjects.com"],
        "tag": ["linode", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "Backblaze B2": {
        "urls": ["https://{name}.s3.us-west-002.backblazeb2.com", "https://{name}.s3.us-west-004.backblazeb2.com",
                 "https://{name}.s3.eu-central-003.backblazeb2.com", "https://{name}.s3.eu-west-001.backblazeb2.com",
                 "https://{name}.backblazeb2.com"],
        "tag": ["backblaze", "b2"],
        "xml_listing": "ListBucketResult"
    },
    "Wasabi": {
        "urls": ["https://{name}.s3.wasabisys.com", "https://{name}.s3.us-east-2.wasabisys.com",
                 "https://{name}.s3.us-west-1.wasabisys.com", "https://{name}.s3.eu-central-1.wasabisys.com"],
        "tag": ["wasabi", "storage"],
        "xml_listing": "ListBucketResult"
    },
    "MinIO": {
        "urls": ["https://{name}.minio.io", "https://{name}.minio.dev",
                 "https://{name}.play.min.io"],
        "tag": ["minio", "s3-compatible"],
        "xml_listing": "ListBucketResult"
    },
    "Alibaba OSS": {
        "urls": ["https://{name}.oss-cn-hangzhou.aliyuncs.com", "https://{name}.oss-us-east-1.aliyuncs.com",
                 "https://{name}.oss-eu-central-1.aliyuncs.com", "https://{name}.oss-ap-southeast-1.aliyuncs.com"],
        "tag": ["alibaba", "oss"],
        "xml_listing": "ListBucketResult"
    },
    "IBM COS": {
        "urls": ["https://{name}.s3.us-south.cloud-object-storage.appdomain.cloud",
                 "https://{name}.s3.us-east.cloud-object-storage.appdomain.cloud",
                 "https://{name}.s3.eu-de.cloud-object-storage.appdomain.cloud"],
        "tag": ["ibm", "cos"],
        "xml_listing": "ListBucketResult"
    },
    "Oracle Object": {
        "urls": ["https://objectstorage.us-phoenix-1.oraclecloud.com/n/{name}/",
                 "https://objectstorage.us-ashburn-1.oraclecloud.com/n/{name}/",
                 "https://objectstorage.eu-frankfurt-1.oraclecloud.com/n/{name}/"],
        "tag": ["oracle", "oci"],
        "xml_listing": "ListBucketResult"
    },
    "Rackspace Cloud Files": {
        "urls": ["https://{name}.rackcdn.com", "https://{name}.clouddrive.com"],
        "tag": ["rackspace", "cloud-files"],
        "xml_listing": ""
    },
    "Vultr Object": {
        "urls": ["https://{name}.vultrobjects.com", "https://{name}.ewr1.vultrobjects.com",
                 "https://{name}.sjo1.vultrobjects.com"],
        "tag": ["vultr", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "Hetzner Object": {
        "urls": ["https://{name}.fsn1.hetzner.cloud", "https://{name}.nbg1.hetzner.cloud",
                 "https://{name}.hel1.hetzner.cloud"],
        "tag": ["hetzner", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "Scaleway Object": {
        "urls": ["https://{name}.s3.fr-par.scw.cloud", "https://{name}.s3.nl-ams.scw.cloud",
                 "https://{name}.s3.pl-waw.scw.cloud"],
        "tag": ["scaleway", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "OVH Object": {
        "urls": ["https://{name}.s3.gra.cloud.ovh.net", "https://{name}.s3.sbg.cloud.ovh.net",
                 "https://{name}.s3.de.cloud.ovh.net"],
        "tag": ["ovh", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "Cloudflare R2": {
        "urls": ["https://{name}.r2.cloudflarestorage.com", "https://{name}.us-east-1.r2.cloudflarestorage.com",
                 "https://pub-{name}.r2.dev"],
        "tag": ["cloudflare", "r2"],
        "xml_listing": "ListBucketResult"
    },
    "UpCloud Object": {
        "urls": ["https://{name}.upcloudobjects.com", "https://{name}.fi-hel1.upcloudobjects.com"],
        "tag": ["upcloud", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
    "Exoscale SOS": {
        "urls": ["https://{name}.sos-ch-gva-2.exo.io", "https://{name}.sos-de-fra-1.exo.io"],
        "tag": ["exoscale", "sos"],
        "xml_listing": "ListBucketResult"
    },
    "Contabo Object": {
        "urls": ["https://{name}.fsn1.contabostorage.com", "https://{name}.nbg1.contabostorage.com"],
        "tag": ["contabo", "object-storage"],
        "xml_listing": "ListBucketResult"
    },
}

BUCKET_SUFFIXES = [
    "", "-data", "-assets", "-backup", "-storage", "-files", "-media", "-public",
    "-private", "-static", "-uploads", "-config", "-logs", "-app", "-web", "-bucket",
    "-archive", "-cdn", "-db", "-cache", "-resources", "-download", "-cdn", "-bucket",
    "-tmp", "-temp", "-test", "-dev", "-staging", "-prod", "-terraform", "-state",
    "-tfstate", "-k8s", "-docker", "-lambda", "-functions", "-api", "-frontend",
    "-backend", "-images", "-docs", "-secrets", "-credentials", "-backup-weekly",
    "-backup-daily", "-snapshots", "-releases", "-builds", "-artifacts", "-helm",
    "-charts", "-monitoring", "-metrics", "-analytics", "-env", "-environment",
]

FILE_TYPES_INTERESTING = [
    "index.html",".env","config.json","credentials","backup.sql","dump.sql",
    "wp-config.php","id_rsa","secret.txt","password.txt",
]

async def _check_bucket(provider: str, config: dict, bucket_name: str, client: httpx.AsyncClient) -> list:
    findings = []
    for url_tmpl in config["urls"]:
        url = url_tmpl.format(name=bucket_name)
        try:
            resp = await safe_fetch(client, url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                body = resp.text[:500]
                content_type = resp.headers.get("content-type", "")
                is_listing = False
                xml_sig = config.get("xml_listing", "")
                if xml_sig and xml_sig in body:
                    is_listing = True
                if "Contents" in body or "<Key>" in body or "CommonPrefixes" in body:
                    is_listing = True
                file_samples = re.findall(r"<Key>([^<]+)</Key>", body)[:10] if is_listing else []
                ct_category = "unknown"
                if "text/html" in content_type: ct_category = "html"
                elif "json" in content_type: ct_category = "json"
                elif "xml" in content_type: ct_category = "xml"

                findings.append(make_finding(
                    entity=f"{provider}://{bucket_name}",
                    type=f"Cloud Storage Public ({provider})",
                    source="CloudStorageScanner",
                    confidence="High",
                    color="red" if is_listing else "orange",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Critical" if is_listing else "Medium",
                    status="Public" + (" + Listing" if is_listing else ""),
                    resolution=url,
                    raw_data=f"Public bucket {bucket_name} on {provider}. Content-Type: {content_type}. Listing: {is_listing}. Files: {len(file_samples)} found. Samples: {', '.join(file_samples[:5]) if file_samples else 'N/A'}",
                    tags=["cloud-storage", "public"] + config["tag"]
                ))
                if is_listing:
                    findings.append(make_finding(
                        entity=f"{provider}://{bucket_name} - Directory Listing",
                        type="Cloud Storage Listing Enabled",
                        source="CloudStorageScanner",
                        confidence="High",
                        color="red",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Critical",
                        status="Listing Enabled",
                        resolution=url,
                        raw_data=f"Directory listing enabled on {bucket_name}. Sample files: {', '.join(file_samples[:5])}",
                        tags=["cloud-storage", "listing"] + config["tag"]
                    ))
                break
            elif resp.status_code == 403:
                body = resp.text[:200]
                if "AccessDenied" in body or "access_denied" in body.lower():
                    findings.append(make_finding(
                        entity=f"{provider}://{bucket_name}",
                        type=f"Cloud Storage Exists ({provider})",
                        source="CloudStorageScanner",
                        confidence="High",
                        color="yellow",
                        category="Cloud / Infrastructure OSINT",
                        threat_level="Low",
                        status="Exists (Denied)",
                        resolution=url,
                        raw_data=f"Bucket {bucket_name} on {provider} exists but access denied",
                        tags=["cloud-storage", "exists"] + config["tag"]
                    ))
                    break
        except Exception:
            continue
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    base = target.split(".")[0] if "." in target else target
    base = re.sub(r"[^a-zA-Z0-9\-]", "", base).strip("-").lower()
    if not base:
        findings.append(make_finding(entity="Invalid target for storage scan", type="Storage Scan Error", source="CloudStorageScanner", confidence="Low", color="red", category="Cloud / Infrastructure OSINT", tags=["error"]))
        return findings

    bucket_names = [f"{base}{s}" for s in BUCKET_SUFFIXES]
    bucket_names = [n for n in bucket_names if len(n) >= 3][:50]

    tasks = []
    for provider, config in PROVIDER_CONFIGS.items():
        for bname in bucket_names:
            tasks.append(_check_bucket(provider, config, bname, client))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    public_buckets = sum(1 for f in findings if "Public" in f.type)
    listing_buckets = sum(1 for f in findings if "Listing" in f.type)
    exists_buckets = sum(1 for f in findings if "Exists" in f.type)
    provider_set = set()
    for f in findings:
        for tag in f.tags:
            if tag in [p.lower().replace(" ", "-") for p in PROVIDER_CONFIGS.keys()]:
                provider_set.add(tag)

    findings.append(make_finding(entity=f"Total public buckets: {public_buckets}", type="Storage Summary: Public", source="CloudStorageScanner", confidence="Medium", color="red" if public_buckets else "emerald", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))
    findings.append(make_finding(entity=f"Buckets with listing: {listing_buckets}", type="Storage Summary: Listing", source="CloudStorageScanner", confidence="Medium", color="red" if listing_buckets else "emerald", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))
    findings.append(make_finding(entity=f"Existing buckets (denied): {exists_buckets}", type="Storage Summary: Exists", source="CloudStorageScanner", confidence="Medium", color="orange" if exists_buckets else "slate", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))
    findings.append(make_finding(entity=f"Bucket names tested: {len(bucket_names)}", type="Storage Summary: Tested", source="CloudStorageScanner", confidence="Medium", color="slate", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))
    findings.append(make_finding(entity=f"Providers with matches: {len(provider_set)}", type="Storage Summary: Providers", source="CloudStorageScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))
    findings.append(make_finding(entity=f"Total findings: {len(findings)}", type="Storage Summary: Total", source="CloudStorageScanner", confidence="Medium", color="purple", category="Cloud / Infrastructure OSINT", tags=["storage", "summary"]))

    return findings
