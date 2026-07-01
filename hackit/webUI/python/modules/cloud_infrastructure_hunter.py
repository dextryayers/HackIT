import httpx
import asyncio
import re
import time
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
        ("https://{name}.s3.ap-northeast-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.ap-south-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.sa-east-1.amazonaws.com/", "regional"),
        ("https://{name}.s3.ca-central-1.amazonaws.com/", "regional"),
        ("https://{name}.s3-website-us-east-1.amazonaws.com/", "website"),
        ("https://{name}.s3-website-us-west-2.amazonaws.com/", "website"),
        ("https://{name}.s3-website-eu-west-1.amazonaws.com/", "website"),
        ("https://{name}.s3-website-ap-southeast-1.amazonaws.com/", "website"),
    ],
    "AWS CloudFront": [
        ("https://{name}.cloudfront.net/", "cloudfront"),
        ("https://d1{name}.cloudfront.net/", "cloudfront-hash"),
        ("https://d2{name}.cloudfront.net/", "cloudfront-hash"),
    ],
    "Azure Blob": [
        ("https://{name}.blob.core.windows.net/", "standard"),
        ("https://{name}.blob.core.usgovcloudapi.net/", "gov"),
        ("https://{name}storage.blob.core.windows.net/", "suffixed"),
        ("https://{name}data.blob.core.windows.net/", "data"),
        ("https://{name}assets.blob.core.windows.net/", "assets"),
        ("https://{name}backup.blob.core.windows.net/", "backup"),
        ("https://{name}media.blob.core.windows.net/", "media"),
        ("https://{name}logs.blob.core.windows.net/", "logs"),
        ("https://{name}config.blob.core.windows.net/", "config"),
        ("https://{name}archive.blob.core.windows.net/", "archive"),
    ],
    "Azure Container": [
        ("https://{name}.blob.core.windows.net/$web/", "static-web"),
    ],
    "GCP Storage": [
        ("https://storage.googleapis.com/{name}/", "path"),
        ("https://{name}.storage.googleapis.com/", "virtual"),
        ("https://storage.cloud.google.com/{name}/", "cloud-google"),
    ],
    "GCP Firebase": [
        ("https://{name}.firebaseio.com/", "firebase"),
        ("https://{name}.web.app/", "firebase-hosting"),
        ("https://{name}.firebaseapp.com/", "firebase-app"),
    ],
    "DigitalOcean Spaces": [
        ("https://{name}.digitaloceanspaces.com/", "standard"),
        ("https://{name}.nyc3.digitaloceanspaces.com/", "nyc"),
        ("https://{name}.ams3.digitaloceanspaces.com/", "ams"),
        ("https://{name}.sgp1.digitaloceanspaces.com/", "sgp"),
        ("https://{name}.fra1.digitaloceanspaces.com/", "fra"),
        ("https://{name}.sfo3.digitaloceanspaces.com/", "sfo"),
    ],
    "Oracle OCI": [
        ("https://objectstorage.{region}.oraclecloud.com/n/{name}/b/", "object-storage"),
        ("https://{name}.objectstorage.{region}.oraclecloud.com/", "v2"),
    ],
    "Alibaba OSS": [
        ("https://{name}.oss-cn-hangzhou.aliyuncs.com/", "cn-hangzhou"),
        ("https://{name}.oss-cn-beijing.aliyuncs.com/", "cn-beijing"),
        ("https://{name}.oss-cn-shanghai.aliyuncs.com/", "cn-shanghai"),
        ("https://{name}.oss-us-east-1.aliyuncs.com/", "us-east"),
        ("https://{name}.oss-eu-central-1.aliyuncs.com/", "eu-central"),
        ("https://{name}.oss-ap-southeast-1.aliyuncs.com/", "ap-southeast"),
        ("https://{name}.oss-ap-southeast-2.aliyuncs.com/", "ap-southeast-2"),
        ("https://{name}.oss-ap-northeast-1.aliyuncs.com/", "ap-northeast"),
    ],
    "IBM Cloud COS": [
        ("https://{name}.s3.us-south.cloud-object-storage.appdomain.cloud/", "us-south"),
        ("https://{name}.s3.us-east.cloud-object-storage.appdomain.cloud/", "us-east"),
        ("https://{name}.s3.eu-de.cloud-object-storage.appdomain.cloud/", "eu-de"),
        ("https://{name}.s3.eu-gb.cloud-object-storage.appdomain.cloud/", "eu-gb"),
        ("https://{name}.s3.au-syd.cloud-object-storage.appdomain.cloud/", "au-syd"),
        ("https://{name}.s3.jp-tok.cloud-object-storage.appdomain.cloud/", "jp-tok"),
        ("https://{name}.s3.ca-tor.cloud-object-storage.appdomain.cloud/", "ca-tor"),
    ],
    "Vultr Object": [
        ("https://{name}.vultrobjects.com/", "standard"),
        ("https://{name}.ewr1.vultrobjects.com/", "ewr1"),
        ("https://{name}.lax1.vultrobjects.com/", "lax1"),
        ("https://{name}.sjo1.vultrobjects.com/", "sjo1"),
    ],
    "Linode Object": [
        ("https://{name}.us-east-1.linodeobjects.com/", "us-east"),
        ("https://{name}.eu-central-1.linodeobjects.com/", "eu-central"),
        ("https://{name}.ap-south-1.linodeobjects.com/", "ap-south"),
        ("https://{name}.us-southeast-1.linodeobjects.com/", "us-southeast"),
    ],
    "Scaleway COS": [
        ("https://{name}.s3.fr-par.scw.cloud/", "fr-par"),
        ("https://{name}.s3.nl-ams.scw.cloud/", "nl-ams"),
        ("https://{name}.s3.pl-waw.scw.cloud/", "pl-waw"),
    ],
    "Hetzner Object": [
        ("https://{name}.fsn1.hetzner.cloud/", "fsn1"),
        ("https://{name}.nbg1.hetzner.cloud/", "nbg1"),
        ("https://{name}.hel1.hetzner.cloud/", "hel1"),
    ],
    "UpCloud": [
        ("https://{name}.upcloudobjects.com/", "standard"),
        ("https://{name}.fi-hel1.upcloudobjects.com/", "helsinki"),
        ("https://{name}.de-fra1.upcloudobjects.com/", "frankfurt"),
    ],
    "Backblaze B2": [
        ("https://{name}.s3.us-west-002.backblazeb2.com/", "us-west"),
        ("https://{name}.s3.us-west-004.backblazeb2.com/", "us-west-2"),
        ("https://{name}.s3.us-east-005.backblazeb2.com/", "us-east"),
        ("https://{name}.s3.eu-central-003.backblazeb2.com/", "eu-central"),
        ("https://{name}.s3.eu-west-001.backblazeb2.com/", "eu-west"),
    ],
    "Wasabi": [
        ("https://{name}.s3.us-east-2.wasabisys.com/", "us-east"),
        ("https://{name}.s3.us-west-1.wasabisys.com/", "us-west"),
        ("https://{name}.s3.eu-central-1.wasabisys.com/", "eu-central"),
        ("https://{name}.s3.eu-west-2.wasabisys.com/", "eu-west"),
        ("https://{name}.s3.ap-northeast-1.wasabisys.com/", "ap-northeast"),
        ("https://{name}.s3.ap-southeast-1.wasabisys.com/", "ap-southeast"),
    ],
    "Cloudflare R2": [
        ("https://{name}.r2.cloudflarestorage.com/", "r2-standard"),
        ("https://pub-{name}.r2.dev/", "r2-dev"),
    ],
    "Celeste (Filebase)": [
        ("https://{name}.filebase.com/", "filebase"),
        ("https://{name}.s3.filebase.com/", "filebase-s3"),
    ],
    "Storj DCS": [
        ("https://gateway.storjshare.io/{name}/", "gateway-path"),
        ("https://{name}.gateway.storjshare.io/", "gateway-vhost"),
    ],
    "Arweave": [
        ("https://arweave.net/{name}/", "arweave"),
        ("https://{name}.arweave.net/", "arweave-vhost"),
    ],
    "Filecoin (Web3)": [
        ("https://{name}.ipfs.dweb.link/", "ipfs-dweb"),
        ("https://{name}.filecoin.io/", "filecoin-io"),
    ],
    "StackPath": [
        ("https://{name}.storage.stackpathresearch.com/", "standard"),
        ("https://{name}.storage.stackpath.com/", "production"),
    ],
    "OVH Object": [
        ("https://{name}.s3.gra.cloud.ovh.net/", "gra"),
        ("https://{name}.s3.sbg.cloud.ovh.net/", "sbg"),
        ("https://{name}.s3.de.cloud.ovh.net/", "de"),
        ("https://{name}.s3.uk.cloud.ovh.net/", "uk"),
        ("https://{name}.s3.us.cloud.ovh.net/", "us"),
    ],
    "Exoscale SOS": [
        ("https://{name}.sos-ch-gva-2.exo.io/", "ch-gva"),
        ("https://{name}.sos-de-fra-1.exo.io/", "de-fra"),
        ("https://{name}.sos-at-vie-1.exo.io/", "at-vie"),
        ("https://{name}.sos-ca-tor-1.exo.io/", "ca-tor"),
    ],
    "Bunny CDN Storage": [
        ("https://{name}.storage.bunnycdn.com/", "bunny"),
        ("https://{name}.storage.bunny.net/", "bunny-net"),
    ],
    "Contabo Object": [
        ("https://{name}.fsn1.contabostorage.com/", "fsn1"),
        ("https://{name}.nbg1.contabostorage.com/", "nbg1"),
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
    "{base}-tfstate", "{base}-k8s", "{base}-kubernetes", "{base}-docker",
    "{base}-container-registry", "{base}-registry", "{base}-helm",
    "{base}-chart", "{base}-charts", "{base}-infra", "{base}-infrastructure",
    "{base}-pipeline", "{base}-ci", "{base}-cd", "{base}-artifact",
    "{base}-artifacts", "{base}-release", "{base}-releases", "{base}-build",
    "{base}-builds", "{base}-deploy", "{base}-deployment", "{base}-deployments",
    "{base}-configmap", "{base}-secret", "{base}-secrets", "{base}-certs",
    "{base}-certificates", "{base}-vault", "{base}-key", "{base}-keys",
    "{base}-encrypted", "{base}-encryption", "{base}-monitoring",
    "{base}-logging", "{base}-analytics", "{base}-reporting",
    "{base}-dashboards", "{base}-qa", "{base}-uat", "{base}-perf",
    "{base}-loadtest", "{base}-preprod", "{base}-canary", "{base}-blue",
    "{base}-green", "{base}-us", "{base}-eu", "{base}-ap",
    "{base}-global", "{base}-primary", "{base}-secondary", "{base}-replica",
    "{base}-2024", "{base}-2025", "{base}-2026", "{base}-v1", "{base}-v2",
    "{base}-latest", "{base}-snapshot", "{base}-snapshots", "{base}-cache",
    "{base}-backup-weekly", "{base}-backup-daily", "{base}-backup-monthly",
    "{base}-lambda", "{base}-function", "{base}-functions", "{base}-queue",
    "{base}-worker", "{base}-workers", "{base}-event", "{base}-events",
    "{base}-stream", "{base}-streams", "{base}-topic", "{base}-notification",
    "data-{base}", "assets-{base}", "media-{base}", "static-{base}",
    "backup-{base}", "uploads-{base}", "files-{base}", "public-{base}",
    "private-{base}", "dev-{base}", "staging-{base}", "prod-{base}",
    "test-{base}", "storage-{base}", "content-{base}", "resources-{base}",
    "app-{base}", "web-{base}", "bucket-{base}", "cdn-{base}",
    "archive-{base}", "db-{base}", "logs-{base}", "config-{base}",
    "infra-{base}", "cloud-{base}", "storage-{base}", "object-{base}",
    "container-{base}", "tf-{base}", "k8s-{base}", "docker-{base}",
    "helm-{base}", "chart-{base}", "env-{base}", "environment-{base}",
    "{base}-01", "{base}-02", "{base}-v2", "{base}-prod-01",
    "{base}-dev-01", "{base}-staging-01", "{base}-prod-v2",
]

OCIREGIONS = [
    "us-phoenix-1", "us-ashburn-1", "us-sanjose-1", "us-chicago-1",
    "eu-frankfurt-1", "uk-london-1", "eu-amsterdam-1", "eu-marseille-1",
    "eu-milan-1", "eu-paris-1", "eu-stockholm-1", "eu-zurich-1",
    "ap-mumbai-1", "ap-osaka-1", "ap-sydney-1", "ap-tokyo-1",
    "ap-seoul-1", "ap-hyderabad-1", "ap-chuncheon-1",
    "sa-saopaulo-1", "sa-santiago-1",
    "me-jeddah-1", "me-dubai-1", "me-abudhabi-1",
    "af-johannesburg-1",
]

CLOUDFRONT_DOMAINS = [
    "cloudfront.net", "s3.amazonaws.com", "s3-us-east-1.amazonaws.com",
    "s3-website-us-east-1.amazonaws.com", "s3-website-us-west-2.amazonaws.com",
    "storage.googleapis.com", "blob.core.windows.net", "digitaloceanspaces.com",
    "r2.cloudflarestorage.com", "r2.dev", "wasabisys.com",
    "backblazeb2.com", "cloud-object-storage.appdomain.cloud",
    "vultrobjects.com", "linodeobjects.com",
]

EXPOSED_FILE_PATTERNS = [
    ".env", ".env.local", ".env.production", ".env.development",
    "config.json", "config.yaml", "config.yml", "config.ini",
    "configuration.json", "settings.json", "settings.yaml",
    "credentials.json", "credentials.yaml", "secrets.json",
    ".git/config", ".git/HEAD", ".gitignore",
    "password", "passwords.txt", "passwd",
    "id_rsa", "id_rsa.pub", "authorized_keys",
    "aws_credentials", "aws-config.json", "credentials",
    "docker-compose.yaml", "docker-compose.yml",
    "Dockerfile", "Makefile", "package.json",
    "npmrc", ".npmrc", "pypirc", ".pypirc",
    "s3cmd.conf", ".s3cfg", "rclone.conf",
    "kubeconfig", "kube-config", ".kube/config",
    "service-account.json", "service-account-key.json",
    "terraform.tfstate", "terraform.tfvars",
    ".terraformrc", "provider.tf",
    "Procfile", "appspec.yml", "buildspec.yml",
    "cloudformation.yml", "cloudformation.yaml",
    "samconfig.toml", "serverless.yml", "serverless.yaml",
    "wp-config.php", "wp-config.php.bak",
    "db_password", "database_password", "db_password.txt",
    "backup.sql", "dump.sql", "export.sql",
    "composer.json", "yarn.lock", "package-lock.json",
    ".htaccess", ".htpasswd", "robots.txt",
    "sitemap.xml", "security.txt",
    ".git-credentials", ".gitconfig", ".gitmodules",
    "deploy.php", "deploy.py", "deploy.sh",
    "config.php", "config.py", "config.rb",
    "database.php", "database.py",
    "db.php", "db.py", "dbconfig.php",
    "wp-config.php.old", "wp-config.php.orig",
    "wp-config.php.save", "wp-config.php.bkp",
    "admin.php", "adminer.php",
    "phpinfo.php", "info.php", "test.php",
    "shell.php", "cmd.php", "webshell.php",
    "cgi-bin/", "cgi-bin/php",
    ".svn/entries", ".svn/wc.db",
    ".DS_Store", "Thumbs.db",
    "README.md", "README.txt", "CHANGELOG.md",
    "LICENSE", "COPYING",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "setup.py", "setup.cfg",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "pubspec.yaml", "build.gradle", "pom.xml",
    "gradle.properties", "local.properties",
    ".eslintrc", ".prettierrc", ".babelrc",
    "tsconfig.json", "webpack.config.js",
    "vite.config.js", "next.config.js",
    "nginx.conf", "httpd.conf", ".htaccess.bak",
    "haproxy.cfg", "traefik.yml",
    "Vagrantfile", "docker-compose.override.yml",
    "init.sql", "schema.sql", "seed.sql",
    "data.sql", "export.json", "export.csv",
    "backup.tar.gz", "backup.zip", "backup.7z",
    "db_backup.sql", "database_backup.sql",
    "wp-config.php~", "config.php~", "config.php.bak",
    ".env.backup", ".env.old", ".env.dev", ".env.prod",
    "keystore.jks", "keystore.p12",
    "google-services.json", "GoogleService-Info.plist",
    "AndroidManifest.xml", "Info.plist",
    "credentials.txt", "passwords.txt", "accounts.txt",
    "token.txt", "api_token.txt", "secret_token.txt",
    "access_key.txt", "secret_key.txt",
    ".s3cfg.bak", "rclone.conf.bak",
    ".cloudflared/config.yml", "warp.conf",
    "wireguard.conf", "openvpn.conf", "ovpn.conf",
    "id_ecdsa", "id_ed25519", "id_dsa",
    "known_hosts", "ssh_config", "sshd_config",
]

ACCESS_CONTROL_INDICATORS = {
    "public-read": ("public-read", "Public Read"),
    "public-read-write": ("public-read-write", "Public Write"),
    "authenticated-read": ("authenticated-read", "Authenticated Users Read"),
    "bucket-owner-read": ("bucket-owner-read", "Bucket Owner Read"),
    "bucket-owner-full-control": ("bucket-owner-full-control", "Owner Full Control"),
    "public": ("public", "Public"),
    "private": ("private", "Private"),
    "allusers": ("AllUsers", "Public"),
    "authenticated-users": ("authenticated-users", "Authenticated Users"),
    "log-delivery-write": ("log-delivery-write", "Log Delivery Write"),
    "aws-exec-read": ("aws-exec-read", "AWS Exec Read"),
    "bucket-owner-read": ("bucket-owner-read", "Owner Read Only"),
    "x-amz-acl": ("x-amz-acl", "Custom ACL"),
    "public-read-write": ("public-read-write", "Public Write"),
}

HEADER_REGION_MAP = {
    "x-amz-region": "AWS",
    "x-amz-bucket-region": "AWS",
    "x-ms-region": "Azure",
    "x-goog-region": "GCP",
    "x-oci-region": "OCI",
    "x-ibm-region": "IBM",
    "x-ddos-region": "DigitalOcean",
    "x-hc-region": "Hetzner",
    "x-upcloud-region": "UpCloud",
}

NON_STANDARD_PORTS = [8080, 8443, 4433, 4443, 9000, 9001, 10000]


async def check_content_analysis(client, base_url, bucket_name):
    findings = []
    for fname in EXPOSED_FILE_PATTERNS:
        url = base_url.rstrip("/") + "/" + fname
        try:
            resp = await client.get(url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0", "Range": "bytes=0-2048"})
            if resp.status_code in (200, 206):
                body_preview = resp.text[:300] if hasattr(resp, "text") else ""
                has_sensitive = any(k in fname.lower() for k in
                    ["password", "credential", "secret", "key", "token", ".env"])
                findings.append({
                    "file": fname,
                    "url": url,
                    "status": resp.status_code,
                    "sensitive": has_sensitive,
                    "preview": body_preview[:100],
                })
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass
    return findings


async def check_bucket(client, url, platform, style, base_name):
    start_time = time.monotonic()
    try:
        resp = await client.get(url, timeout=8.0,
            headers={"User-Agent": "Mozilla/5.0"})
        elapsed = time.monotonic() - start_time
        status = resp.status_code
        content_type = resp.headers.get("content-type", "")
        body = resp.text[:1000].lower() if hasattr(resp, "text") else ""
        access_control = None
        for header, label in ACCESS_CONTROL_INDICATORS.items():
            if header in resp.headers:
                access_control = label[1]
                break
        acl_header = resp.headers.get("x-amz-acl", "")
        if acl_header:
            access_control = ACCESS_CONTROL_INDICATORS.get(acl_header, (None, acl_header))[1]

        detected_region = None
        for hdr, prov in HEADER_REGION_MAP.items():
            val = resp.headers.get(hdr)
            if val:
                detected_region = f"{prov}: {val}"
                break
        region_hint = resp.headers.get("x-amz-region") or resp.headers.get("x-ms-region") or ""
        if not detected_region and region_hint:
            detected_region = region_hint

        body_lower = body
        str_headers_str = str(dict(resp.headers)).lower()

        if status == 200:
            is_listing = False
            has_index = False

            if "listbucketresult" in body_lower or "contents" in body_lower or \
               "commonprefixes" in body_lower or "<key>" in body_lower or \
               "etag" in body_lower or "is_truncated" in body_lower:
                is_listing = True
            if "index.html" in body_lower or "index.htm" in body_lower:
                has_index = True
            if content_type == "application/xml" and ("list" in body_lower or "bucket" in body_lower):
                is_listing = True

            public_write = False
            if "public-read-write" in str_headers_str or "public-read-write" in body_lower:
                public_write = True
            if "acl" in str_headers_str and "public" in str_headers_str:
                if "write" in str_headers_str:
                    public_write = True

            tags = ["cloud-storage", "public"]
            if is_listing:
                tags.append("listing-enabled")
            if public_write:
                tags.append("public-write")
            if detected_region:
                tags.append(f"region-{detected_region.lower().replace(':', '-').replace(' ', '-')}")

            content_findings = await check_content_analysis(client, url, base_name)
            exposed_files = [cf["file"] for cf in content_findings]
            sensitive_exposed = [cf["file"] for cf in content_findings if cf.get("sensitive")]

            raw_lines = [
                f"Public bucket accessible on {platform}.",
                f"Style: {style}.",
                f"Listing: {is_listing}",
                f"Public Write: {public_write}",
                f"Response Time: {elapsed:.2f}s",
            ]
            if detected_region:
                raw_lines.append(f"Detected Region: {detected_region}")
            if access_control:
                raw_lines.append(f"Access Control: {access_control}")
            if exposed_files:
                raw_lines.append(f"Exposed Files ({len(exposed_files)}): {', '.join(exposed_files[:20])}")
            if sensitive_exposed:
                raw_lines.append(f"SENSITIVE EXPOSED ({len(sensitive_exposed)}): {', '.join(sensitive_exposed[:10])}")

            finding = IntelligenceFinding(
                entity=url[:200],
                type="Cloud Storage Bucket",
                source=f"{platform} Hunter",
                confidence="High",
                color="red" if is_listing or sensitive_exposed else "cyan",
                category="Cloud / Infrastructure OSINT",
                threat_level="Critical" if is_listing or sensitive_exposed else "Medium",
                status="Public + Write" if public_write else ("Public + Listing" if is_listing else "Public"),
                resolution=f"Platform: {platform}",
                raw_data=" | ".join(raw_lines),
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
                raw_data=f"Protected bucket on {platform}. Returns 403 Forbidden | Response: {elapsed:.2f}s",
                tags=["cloud-storage", "private"]
            )

        elif status == 404:
            pass

    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass
    return None


async def check_port_scan(client, name, platform, style, base_name):
    port_findings = []
    domain_part = None
    for url_template, _ in CLOUD_PROVIDERS.get(platform, []):
        if "{region}" in url_template and "Oracle" not in platform:
            continue
        try:
            parsed = urlparse(url_template.format(name=name))
            domain_part = parsed.netloc.split(":")[0]
            break
        except Exception:
            continue
    if not domain_part:
        return []
    for port in NON_STANDARD_PORTS:
        alt_url = f"https://{domain_part}:{port}/"
        try:
            resp = await client.get(alt_url, timeout=5.0,
                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code < 500:
                port_findings.append(IntelligenceFinding(
                    entity=alt_url[:200],
                    type="Cloud Storage Bucket (Alt Port)",
                    source=f"{platform} Hunter",
                    confidence="Medium",
                    color="cyan",
                    category="Cloud / Infrastructure OSINT",
                    threat_level="Medium",
                    status=f"Accessible on port {port}",
                    resolution=f"Platform: {platform}",
                    raw_data=f"Bucket accessible on non-standard port {port}",
                    tags=["cloud-storage", "alt-port", "cdn"]
                ))
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass
    return port_findings


async def crawl(target: str, client: httpx.AsyncClient):
    scan_start = time.monotonic()
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
    names_to_check = list(names_to_check)[:200]

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
    stats = {"total": 0, "public": 0, "private": 0, "not_found": 0, "listing": 0, "public_write": 0}
    port_scan_findings = []

    async def bounded_check(name, platform, url, style):
        async with semaphore:
            stats["total"] += 1
            result = await check_bucket(client, url, platform, style, name)
            if result is None:
                stats["not_found"] += 1
            elif "Private" in result.status:
                stats["private"] += 1
            elif "Public" in result.status:
                stats["public"] += 1
                if "Listing" in result.status:
                    stats["listing"] += 1
                if "Write" in result.status:
                    stats["public_write"] += 1
            return result

    batch_results = await asyncio.gather(*[
        bounded_check(name, platform, url, style)
        for name, platform, url, style in tasks
    ], return_exceptions=True)

    for r in batch_results:
        if r and isinstance(r, IntelligenceFinding):
            bucket_results.append(r)

    provider_counts = defaultdict(int)
    provider_buckets = defaultdict(list)
    public_count = 0
    listing_count = 0
    write_count = 0

    for f in bucket_results:
        provider = f.source.replace(" Hunter", "")
        provider_counts[provider] += 1
        provider_buckets[provider].append(f.entity)
        if "Public" in f.status:
            public_count += 1
            if "Listing" in f.status:
                listing_count += 1
            if "Write" in f.status:
                write_count += 1

    findings.extend(bucket_results)

    heavy_providers = [p for p, c in provider_counts.items() if c >= 3]

    for provider in heavy_providers:
        bucket_list = provider_buckets[provider]
        findings.append(IntelligenceFinding(
            entity=f"Heavy usage detected on {provider}: {provider_counts[provider]} buckets",
            type="Provider Heavy Usage",
            source=f"{provider} Hunter",
            confidence="High",
            color="orange",
            category="Cloud / Infrastructure OSINT",
            threat_level="Medium",
            status="Heavy Usage",
            resolution=f"Provider: {provider}",
            raw_data=f"Provider {provider} has {provider_counts[provider]} buckets. "
                     f"Buckets: {'; '.join(bucket_list[:10])}",
            tags=["cloud", "heavy-usage", provider.lower().replace(" ", "-")]
        ))

    if bucket_results:
        scan_duration = time.monotonic() - scan_start
        top_providers = sorted(provider_counts.items(), key=lambda x: -x[1])[:5]
        prov_str = ", ".join(f"{p}({c})" for p, c in top_providers)

        stat_lines = [
            f"Buckets found: {len(bucket_results)}",
            f"Providers: {len(provider_counts)}",
            f"Public: {public_count}",
            f"Listable: {listing_count}",
            f"Public Write: {write_count}",
            f"Private: {stats['private']}",
            f"Not Found: {stats['not_found']}",
            f"Total Requests: {stats['total']}",
            f"Scan Duration: {scan_duration:.2f}s",
        ]

        findings.append(IntelligenceFinding(
            entity=f"Scan Summary | {len(bucket_results)} buckets across {len(provider_counts)} providers",
            type="Cloud Storage Summary",
            source="Cloud Infrastructure Hunter",
            confidence="High",
            color="blue",
            category="Cloud / Infrastructure OSINT",
            threat_level="Informational",
            status="Summary",
            raw_data=f"Stats: {' | '.join(stat_lines)} | Providers: {prov_str}",
            tags=["cloud", "summary", "statistics"]
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

        if write_count > 0:
            findings.append(IntelligenceFinding(
                entity=f"{write_count} buckets allow public WRITE access!",
                type="Bucket Public Write Warning",
                source="Cloud Infrastructure Hunter",
                confidence="High",
                color="red",
                category="Cloud / Infrastructure OSINT",
                threat_level="Critical",
                status="Public Write Enabled",
                tags=["cloud", "public-write", "critical"]
            ))

        if heavy_providers:
            findings.append(IntelligenceFinding(
                entity=f"Heavy provider usage detected: {', '.join(heavy_providers)}",
                type="Provider Concentration",
                source="Cloud Infrastructure Hunter",
                confidence="Medium",
                color="orange",
                category="Cloud / Infrastructure OSINT",
                threat_level="Informational",
                status="Provider Concentration",
                tags=["cloud", "concentration", "heavy-usage"]
            ))

    async def analyze_cloud_security():
        findings.append(IntelligenceFinding(entity=f"Public buckets: {public_count}", type="Cloud Security: Public Exposure", source="CloudInfraHunter", confidence="Medium", color="red" if public_count else "emerald", tags=["security"]))
        findings.append(IntelligenceFinding(entity=f"Listable buckets: {listing_count}", type="Cloud Security: Listing Risk", source="CloudInfraHunter", confidence="Medium", color="red" if listing_count else "emerald", tags=["security"]))
        findings.append(IntelligenceFinding(entity=f"Writable buckets: {write_count}", type="Cloud Security: Write Risk", source="CloudInfraHunter", confidence="Medium", color="red" if write_count else "emerald", tags=["security"]))
        findings.append(IntelligenceFinding(entity=f"Total buckets probed: {stats['total']}", type="Cloud Security: Scan Volume", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["security"]))

    async def analyze_provider_diversity():
        if provider_counts:
            for p, c in sorted(provider_counts.items(), key=lambda x: -x[1])[:5]:
                findings.append(IntelligenceFinding(entity=f"{p}: {c} bucket(s)", type="Cloud Provider: Bucket Count", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["providers"]))
            findings.append(IntelligenceFinding(entity=f"Provider diversity: {len(provider_counts)}", type="Cloud Provider: Diversity", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["providers"]))
        findings.append(IntelligenceFinding(entity=f"Buckets with exposure: {public_count + write_count + listing_count}", type="Cloud Security: Exposure Total", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["security"]))

    async def analyze_exposure_ratio():
        if stats['total'] > 0:
            exposure_pct = round((public_count / stats['total']) * 100, 1)
            findings.append(IntelligenceFinding(entity=f"Exposure ratio: {exposure_pct}%", type="Cloud Security: Exposure Ratio", source="CloudInfraHunter", confidence="Medium", color="red" if exposure_pct > 20 else "orange", tags=["security"]))
            findings.append(IntelligenceFinding(entity=f"Private buckets: {stats['private']}", type="Cloud Security: Private Count", source="CloudInfraHunter", confidence="Medium", color="emerald", tags=["security"]))
        findings.append(IntelligenceFinding(entity=f"Not found buckets: {stats['not_found']}", type="Cloud Security: NotFound Count", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["security"]))

    async def analyze_bucket_overview():
        findings.append(IntelligenceFinding(entity=f"Total buckets found: {len(bucket_results)}", type="Cloud Overview: Found Buckets", source="CloudInfraHunter", confidence="High", color="purple", tags=["overview"]))
        findings.append(IntelligenceFinding(entity=f"Providers with buckets: {len(provider_counts)}", type="Cloud Overview: Provider Count", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["overview"]))
        findings.append(IntelligenceFinding(entity=f"Buckets per provider: {round(len(bucket_results)/max(len(provider_counts),1),1)} avg", type="Cloud Overview: Avg Buckets", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["overview"]))

    async def analyze_exposure_recommendations():
        findings.append(IntelligenceFinding(entity="Enable 'Block Public Access' on all storage buckets", type="Cloud Rec: Block Public Access", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["recommendation"]))
        findings.append(IntelligenceFinding(entity="Audit bucket ACLs and IAM policies regularly", type="Cloud Rec: Regular Audit", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["recommendation"]))
        findings.append(IntelligenceFinding(entity="Use bucket-level logging to monitor access", type="Cloud Rec: Enable Logging", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["recommendation"]))
        findings.append(IntelligenceFinding(entity="Implement least-privilege access for bucket operations", type="Cloud Rec: Least Privilege", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["recommendation"]))

    async def analyze_security_verdict():
        total_risk = public_count + listing_count + write_count
        findings.append(IntelligenceFinding(entity=f"Total security issues: {total_risk}", type="Cloud Security: Issue Count", source="CloudInfraHunter", confidence="Medium", color="red" if total_risk else "emerald", tags=["verdict"]))
        if total_risk == 0:
            findings.append(IntelligenceFinding(entity="No security issues detected in bucket configurations", type="Cloud Security: Clean Bill", source="CloudInfraHunter", confidence="Medium", color="emerald", tags=["verdict"]))
        else:
            findings.append(IntelligenceFinding(entity=f"Immediate action required: {total_risk} bucket(s) with security issues", type="Cloud Security: Action Required", source="CloudInfraHunter", confidence="Medium", color="red", tags=["verdict"]))
        findings.append(IntelligenceFinding(entity=f"Scan completed: {len(tasks)} bucket URL(s) tested", type="Cloud Security: Scan Stats", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["verdict"]))

    async def analyze_risk_assessment():
        findings.append(IntelligenceFinding(entity=f"Critical issues (public): {public_count}", type="Cloud Risk: Critical", source="CloudInfraHunter", confidence="Medium", color="red", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"High issues (listing): {listing_count}", type="Cloud Risk: High", source="CloudInfraHunter", confidence="Medium", color="red", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"Medium issues (write): {write_count}", type="Cloud Risk: Medium", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"Low issues (private): {stats['private']}", type="Cloud Risk: Low", source="CloudInfraHunter", confidence="Medium", color="emerald", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"False positives (not found): {stats['not_found']}", type="Cloud Risk: False Positive", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["risk"]))
        findings.append(IntelligenceFinding(entity=f"Scan efficiency: {round(len(bucket_results)/max(stats['total'],1)*100,1)}% hit rate", type="Cloud Risk: Efficiency", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["risk"]))

    async def analyze_overall_assessment():
        findings.append(IntelligenceFinding(entity=f"Provider: {', '.join(sorted(provider_counts.keys()))}", type="Cloud Assessment: Providers", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["assessment"]))
        findings.append(IntelligenceFinding(entity=f"Public bucket risk: {public_count + listing_count + write_count} issue(s)", type="Cloud Assessment: Public Risk", source="CloudInfraHunter", confidence="Medium", color="red", tags=["assessment"]))
        findings.append(IntelligenceFinding(entity=f"Total buckets tested: {stats['total']}", type="Cloud Assessment: Tested", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["assessment"]))
        findings.append(IntelligenceFinding(entity=f"Scan recommendation: {'Lock all public buckets' if public_count else 'No action needed'}", type="Cloud Assessment: Recommendation", source="CloudInfraHunter", confidence="Medium", color="orange", tags=["assessment"]))
        findings.append(IntelligenceFinding(entity=f"Non-public buckets: {stats['private'] + stats['not_found']}", type="Cloud Assessment: Non-Public", source="CloudInfraHunter", confidence="Medium", color="slate", tags=["assessment"]))

    await asyncio.gather(
        analyze_cloud_security(),
        analyze_provider_diversity(),
        analyze_exposure_ratio(),
        analyze_bucket_overview(),
        analyze_exposure_recommendations(),
        analyze_security_verdict(),
        analyze_risk_assessment(),
        analyze_overall_assessment(),
    )

    return findings
