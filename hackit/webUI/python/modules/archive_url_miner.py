import httpx
import re
from models import IntelligenceFinding
from urllib.parse import urlparse

SENSITIVE_PATTERNS = {
    "Database Backup": [r'\.sql\.gz$', r'\.sql$', r'\.dump$', r'\.dmp$',
                        r'\.sqlite$', r'\.sqlite3$', r'\.mdf$', r'\.ldf$',
                        r'mysqldump', r'pg_dump', r'mongodump'],
    "Archive": [r'\.tar\.gz$', r'\.tar\.bz2$', r'\.tar\.xz$', r'\.tgz$',
                r'\.zip$', r'\.rar$', r'\.7z$', r'\.tar$', r'\.gz$', r'\.bz2$'],
    "Environment/Config": [r'\.env', r'\.env\.', r'\.config$', r'\.conf$',
                           r'\.cfg$', r'\.ini$', r'\.yml$', r'\.yaml$',
                           r'\.toml$', r'\.properties$', r'env\.php',
                           r'configuration\.php', r'config\.php'],
    "Backup File": [r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$',
                    r'\.copy$', r'\.sav$', r'\.save$', r'\.swp$',
                    r'\.~$', r'~$', r'\.back$'],
    "Log File": [r'\.log$', r'\.log\.\d+$', r'error_log',
                 r'access\.log', r'debug\.log'],
    "Exported Data": [r'\.csv$', r'\.xlsx$', r'\.xls$', r'\.json$',
                      r'\.xml$', r'\.tsv$', r'export', r'\.dat$'],
    "Credentials/Keys": [r'\.pem$', r'\.key$', r'\.p12$', r'\.pfx$',
                         r'\.jks$', r'\.keystore$', r'\.pub$', r'\.gpg$',
                         r'\.asc$', r'id_rsa', r'id_dsa', r'password',
                         r'credential', r'secret', r'htpasswd', r'\.htpasswd$'],
    "Source Code": [r'\.git/', r'\.svn/', r'\.hg/', r'\.DS_Store',
                    r'Thumbs\.db', r'wp-config\.php', r'wp-config\.bak',
                    r'composer\.json', r'package\.json', r'Dockerfile',
                    r'docker-compose', r'Procfile', r'build\.gradle',
                    r'pom\.xml', r'Makefile', r'Gruntfile', r'gulpfile'],
}

TAKEOVER_PATTERNS = {
    "AWS S3": ["s3.amazonaws.com", "s3-website", "s3.us-east-1", "s3-eu-west", "s3.ap-southeast",
               "s3.dualstack", "amazonaws.com"],
    "AWS CloudFront": ["cloudfront.net"],
    "Azure": ["azurewebsites.net", "cloudapp.net", "azureedge.net",
              "trafficmanager.net", "blob.core.windows.net", "azurefd.net"],
    "GitHub Pages": ["github.io"],
    "Heroku": ["herokuapp.com", "herokudns.com"],
    "GitLab": ["gitlab.io"],
    "Netlify": ["netlify.app", "netlify.com"],
    "Pantheon": ["pantheonsite.io", "pantheon.io"],
    "Shopify": ["myshopify.com", "shopify.com"],
    "Squarespace": ["squarespace.com", "sqsp.com"],
    "Tumblr": ["tumblr.com"],
    "WordPress": ["wordpress.com", "wpengine.com"],
    "Zendesk": ["zendesk.com"],
    "Freshdesk": ["freshdesk.com"],
    "Readme.io": ["readme.io", "readme.com"],
    "Surge.sh": ["surge.sh"],
    "Fly.io": ["fly.dev", "fly.io"],
    "Fastly": ["fastly.net", "fastly.com"],
    "Bitbucket": ["bitbucket.io"],
    "Campaign Monitor": ["createsend.com", "campaignmonitor.com"],
    "Acquia": ["acquia.com", "acquia-sites.com"],
    "Tilda": ["tilda.ws", "tilda.com"],
    "Unbounce": ["unbouncepages.com", "unbounce.com"],
    "Cargo": ["cargocollective.com"],
    "Instapage": ["instapage.com"],
    "Wix": ["wixsite.com", "wix.com", "editorx.io"],
    "Strikingly": ["strikingly.com", "strikinglydns.com"],
    "Jimdo": ["jimdo.com", "jimdosite.com"],
}

TAKEOVER_FINGERPRINTS = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist", "404 Not Found"],
    "AWS CloudFront": ["ERROR: The request could not be satisfied", "CloudFront",
                       "BadRequest", "X-Cache: Error from CloudFront"],
    "Azure": ["404 Not Found", "The web app you are trying to access does not exist",
              "There is no app hosted here", "404 - Site Not Found"],
    "GitHub Pages": ["There isn't a GitHub Pages site here", "404 Not Found",
                     "github.io 404"],
    "Heroku": ["No such app", "Heroku | No such app", "There is nothing here yet"],
    "GitLab": ["The page you're looking for could not be found", "404"],
    "Netlify": ["Not Found - Netlify", "Page not found", "Netlify Site Not Found"],
    "Shopify": ["Sorry, this shop is currently unavailable", "shopify.com/error"],
    "Squarespace": ["No site found", "This site is no longer available",
                    "Domain not found", "Squarespace - No Such Site"],
    "Tumblr": ["There's nothing here", "Tumblr - page not found", "Whatever you were looking for doesn't exist"],
    "WordPress": ["Domain not found", "WordPress.com", "doesn&rsquo;t exist"],
    "Zendesk": ["Help Center Closed", "This help desk is no longer available",
                "404 (Page Not Found)", "Zendesk - Page Not Found"],
    "Freshdesk": ["This support portal is no longer available", "Freshdesk - 404"],
    "Readme.io": ["Project doesnt exist", "Page Not Found", "404"],
    "Surge.sh": ["project not found", "Surge - Page Not Found", "There is no such project"],
    "Fly.io": ["not found", "App Not Found", "404 Not Found"],
    "Fastly": ["Fastly error: unknown domain", "Fastly - Domain Not Found"],
    "Bitbucket": ["Repository not found", "This repository has been deleted"],
    "Unbounce": ["Unbounce - Page Not Found", "The page you requested does not exist"],
    "Wix": ["Sorry, this site is not published", "Wix - 404"],
    "Strikingly": ["Site Not Found", "strikingly.com/404"],
}

FINGERPRINT_PAGES = {
    "/": ["NoSuchBucket", "There is nothing here yet", "404 Not Found",
          "Project doesnt exist", "No such app"],
    "/robots.txt": ["No such app", "Project doesnt exist"],
}

STATUS_CATEGORIES = {
    200: "Success", 301: "Redirect Permanent", 302: "Redirect Found",
    403: "Forbidden", 404: "Not Found", 410: "Gone",
    500: "Server Error", 502: "Bad Gateway", 503: "Unavailable",
}


def match_sensitive_file(url: str) -> tuple:
    lower = url.lower()
    for category, patterns in SENSITIVE_PATTERNS.items():
        for p in patterns:
            if re.search(p, lower):
                return category
    return None


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        cdx_url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype,length,digest",
            "limit": "10000",
            "collapse": "urlkey",
        }

        resp = await client.get(cdx_url, params=params, timeout=60.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})

        if resp.status_code != 200 or not resp.text.strip():
            findings.append(IntelligenceFinding(
                entity=domain,
                type="Wayback Machine",
                source="ArchiveURLMiner",
                confidence="Low",
                color="slate",
                status="No archived data found",
                resolution="CDX returned no results",
            ))
            return findings

        rows = resp.json()
        if len(rows) < 2:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="Wayback Machine",
                source="ArchiveURLMiner",
                confidence="Low",
                color="slate",
                status="Archive empty",
            ))
            return findings

        header = rows[0]
        data = rows[1:]

        col_idx = {}
        for i, col in enumerate(header):
            col_idx[col] = i

        urls_seen = set()
        removed_pages = []
        sensitive_items = []
        subdomains = set()
        status_dist = {}
        mime_dist = {}
        year_dist = {}
        path_counts = {}
        total_urls = 0

        for row in data:
            if len(row) < 4:
                continue
            url = row[col_idx.get("original", 0)]
            ts = row[col_idx.get("timestamp", 1)]
            sc = row[col_idx.get("statuscode", 2)]
            mt = row[col_idx.get("mimetype", 3)] if len(row) > col_idx.get("mimetype", 3) else ""

            if url in urls_seen:
                continue
            urls_seen.add(url)
            total_urls += 1

            status_dist[sc] = status_dist.get(sc, 0) + 1
            if mt and mt != "-":
                mime_dist[mt] = mime_dist.get(mt, 0) + 1
            if ts and len(ts) >= 4:
                y = ts[:4]
                year_dist[y] = year_dist.get(y, 0) + 1

            if sc in ("404", "410"):
                cat = STATUS_CATEGORIES.get(int(sc), f"HTTP {sc}")
                removed_pages.append((url, sc, ts, cat))

            path = urlparse(url).path or "/"
            path_counts[path] = path_counts.get(path, 0) + 1

            sens_cat = match_sensitive_file(url)
            if sens_cat:
                sensitive_items.append((url, sens_cat, ts, mt))

            try:
                parsed = urlparse(url)
                hn = parsed.hostname or ""
                dotdomain = "." + domain
                if hn.endswith(dotdomain) and hn != domain and hn not in subdomains:
                    subdomains.add(hn)
            except Exception:
                pass

        removed_pages.sort(key=lambda x: int(x[1]) if x[1].isdigit() else 999, reverse=True)

        if removed_pages:
            for url, sc, ts, cat in removed_pages[:12]:
                findings.append(IntelligenceFinding(
                    entity=url[:200],
                    type=f"Removed Page: {cat}",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="red" if sc == "410" else "orange",
                    threat_level="Elevated Risk" if sc == "410" else "Informational",
                    status=cat,
                    resolution=ts,
                    raw_data=f"URL returned HTTP {sc} on {ts}",
                ))
            if len(removed_pages) > 12:
                findings.append(IntelligenceFinding(
                    entity=f"{len(removed_pages)} removed/deleted pages total",
                    type="Removed Pages Summary",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Bulk removed pages",
                ))

        if sensitive_items:
            for url, cat, ts, mt in sensitive_items[:18]:
                findings.append(IntelligenceFinding(
                    entity=url[:200],
                    type=f"Sensitive: {cat}",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status="Exposed in archive",
                    resolution=ts,
                    raw_data=f"MIME: {mt}, Archived: {ts}",
                ))
            if len(sensitive_items) > 18:
                findings.append(IntelligenceFinding(
                    entity=f"{len(sensitive_items)} sensitive files exposed in archive",
                    type="Sensitive Files Summary",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    status=f"{len(sensitive_items)} sensitive files",
                ))

        if subdomains:
            for sub in sorted(subdomains)[:12]:
                findings.append(IntelligenceFinding(
                    entity=sub,
                    type="Historical Subdomain",
                    source="ArchiveURLMiner",
                    confidence="Medium",
                    color="blue",
                    status="Found in archive data",
                    resolution=domain,
                    tags=["subdomain"],
                ))
            if len(subdomains) > 12:
                findings.append(IntelligenceFinding(
                    entity=f"{len(subdomains)} historical subdomains discovered",
                    type="Historical Subdomains Summary",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="purple",
                    status=f"{len(subdomains)} subdomains",
                    resolution=domain,
                ))

        for mime, count in sorted(mime_dist.items(), key=lambda x: -x[1])[:6]:
            if mime and mime != "-":
                findings.append(IntelligenceFinding(
                    entity=f"{mime}: {count} URLs ({100*count/total_urls:.1f}%)",
                    type="Content Type Distribution",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="slate",
                    status="Informational",
                    raw_data=f"MIME: {mime}, Count: {count}, Pct: {100*count/total_urls:.1f}%",
                ))

        for year in sorted(year_dist.keys()):
            if re.match(r'^\d{4}$', year):
                pct = 100 * year_dist[year] / total_urls
                findings.append(IntelligenceFinding(
                    entity=f"{year}: {year_dist[year]} URLs ({pct:.1f}%)",
                    type="Archive Timeline",
                    source="ArchiveURLMiner",
                    confidence="High",
                    color="emerald",
                    status="Informational",
                    raw_data=f"Year: {year}, URLs: {year_dist[year]}",
                ))

        findings.append(IntelligenceFinding(
            entity=f"{total_urls} unique URLs analyzed from Wayback Machine",
            type="Archive Summary",
            source="ArchiveURLMiner",
            confidence="High",
            color="purple",
            status=f"{total_urls} URLs",
            resolution=domain,
            raw_data=f"Domain: {domain}, Total: {total_urls}, "
                    f"Removed: {len(removed_pages)}, "
                    f"Sensitive: {len(sensitive_items)}, "
                    f"Subdomains: {len(subdomains)}",
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Archive URL Miner error: {str(e)[:150]}",
            type="Archive URL Miner Error",
            source="ArchiveURLMiner",
            confidence="Low",
            color="red",
            status="Error",
        ))

    return findings
