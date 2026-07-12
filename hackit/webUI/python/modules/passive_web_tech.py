import re
import json
from urllib.parse import urlparse
from ..module_common import safe_fetch, make_finding

SERVER_TECH_SIGNATURES = {
    "nginx": "Nginx", "apache": "Apache HTTP Server", "cloudflare": "Cloudflare",
    "akamai": "Akamai", "cloudfront": "AWS CloudFront", "iis": "Microsoft IIS",
    "lighttpd": "Lighttpd", "caddy": "Caddy", "openresty": "OpenResty",
    "gunicorn": "Gunicorn", "uvicorn": "Uvicorn", "node": "Node.js",
    "express": "Express.js", "kestrel": "Kestrel (.NET)", "gws": "Google Web Server",
    "gfe": "Google Front End", "tomcat": "Apache Tomcat", "jetty": "Jetty",
    "netty": "Netty", "python": "Python", "java": "Java", "ruby": "Ruby",
    "php": "PHP", "cowboy": "Cowboy (Erlang)", "fasthttp": "FastHTTP",
    "trafficserver": "Apache Traffic Server", "varnish": "Varnish Cache",
}

CDN_SIGNATURES = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "cloudfront": "AWS CloudFront",
    "fastly": "Fastly", "azureedge": "Azure CDN", "akamaiedge": "Akamai Edge",
    "edgesuite": "Akamai", "keycdn": "KeyCDN", "bunnycdn": "BunnyCDN",
    "stackpath": "StackPath", "sucuri": "Sucuri", "incapsula": "Incapsula",
    "imperva": "Imperva", "azurefd": "Azure Front Door", "gcp-cdn": "Google Cloud CDN",
}

FRAMEWORK_META = {
    "WordPress": [r"wordpress", r"wp-", r"wp-content"],
    "Joomla": [r"joomla", r"com_content"],
    "Drupal": [r"drupal", r"drupalSettings"],
    "Magento": [r"magento", r"skin/frontend"],
    "Shopify": [r"shopify", r"myshopify"],
    "Laravel": [r"laravel", r"livewire"],
    "Django": [r"django", r"csrfmiddlewaretoken"],
    "Ruby on Rails": [r"rails", r"turbolinks"],
    "ASP.NET": [r"asp.net", r"__viewstate", r"__requestverificationtoken"],
    "React": [r"react\.js", r"react\.min\.js", r"reactroot"],
    "Vue.js": [r"vue\.js", r"vue\.min\.js", r"__vue__"],
    "Angular": [r"angular\.js", r"ng-app", r"ng-version"],
    "Next.js": [r"__next", r"_next/static"],
    "Nuxt.js": [r"__nuxt", r"_nuxt/"],
    "Gatsby": [r"gatsby", r"___gatsby"],
    "Svelte": [r"svelte", r"__svelte"],
    "Bootstrap": [r"bootstrap\.min\.css", r"col-md-", r"col-xs-"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind"],
    "Google Analytics": [r"google-analytics", r"ga\(", r"gtag"],
    "Facebook Pixel": [r"fbq\(", r"facebook.*pixel"],
    "jQuery": [r"jquery", r"jQuery"],
}

CDNJS_PATTERN = re.compile(r'//cdnjs\.cloudflare\.com/ajax/libs/([\w-]+)/([\d.]+)')
UNPKG_PATTERN = re.compile(r'//unpkg\.com/([\w-]+)@?([\d.]+)?')
JSDELIVR_PATTERN = re.compile(r'//cdn\.jsdelivr\.net/(npm|gh)/([\w-]+)@?([\d.]+)?')

async def _fetch_wayback_html(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=20&filter=statuscode:200", timeout=20.0)
        if resp.status_code == 200:
            data = resp.json()
            urls_to_check = []
            for row in data[1:20]:
                if isinstance(row, list) and len(row) >= 3:
                    orig_url = row[0]
                    ts = row[1]
                    if orig_url.startswith("http"):
                        wb_url = f"http://web.archive.org/web/{ts}if_/{orig_url}"
                        urls_to_check.append((wb_url, ts))
            for wb_url, ts in urls_to_check[:10]:
                try:
                    snap = await safe_fetch(client, wb_url, timeout=15.0)
                    if snap.status_code == 200:
                        html = snap.text[:50000]
                        techs_found = set()
                        for tech, patterns in FRAMEWORK_META.items():
                            for p in patterns:
                                if re.search(p, html, re.I):
                                    techs_found.add(tech)
                                    break
                        for tech in techs_found:
                            findings.append(make_finding(
                                entity=tech,
                                ftype=f"Technology Detected (Wayback - {ts[:8]})",
                                source="Passive Web Tech",
                                confidence="Medium",
                                color="orange",
                                status="Historical",
                                raw_data=f"Tech: {tech} in cached page from {ts[:8]}",
                                tags=["tech", "wayback", "historical"]
                            ))
                        for pattern_tuple in [CDNJS_PATTERN, UNPKG_PATTERN, JSDELIVR_PATTERN]:
                            for m in pattern_tuple.finditer(html):
                                lib = m.group(1) if pattern_tuple != JSDELIVR_PATTERN else m.group(2)
                                ver = m.group(2) if pattern_tuple == CDNJS_PATTERN else (m.group(2) if pattern_tuple == UNPKG_PATTERN and m.group(2) else (m.group(3) if pattern_tuple == JSDELIVR_PATTERN and m.group(3) else "unknown"))
                                lib_entity = f"{lib} v{ver}" if ver and ver != "unknown" else lib
                                findings.append(make_finding(
                                    entity=lib_entity,
                                    ftype="JavaScript Library (Wayback CDN Reference)",
                                    source="Passive Web Tech",
                                    confidence="High",
                                    color="slate",
                                    status="Detected",
                                    raw_data=f"CDN ref: {m.group(0)} from {ts[:8]}",
                                    tags=["tech", "cdn", "javascript"]
                                ))
                except Exception:
                    pass
    except Exception:
        pass
    return findings

async def _fetch_builtwith_data(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://builtwith.com/{domain}", timeout=15.0)
        if resp.status_code == 200:
            tech_sections = re.findall(r'<a[^>]*class="[^"]*tech[^"]*"[^>]*>([^<]+)</a>', resp.text, re.I)
            for tech in tech_sections[:20]:
                tech = tech.strip()
                if tech and len(tech) < 100:
                    findings.append(make_finding(
                        entity=tech[:100],
                        ftype="Technology (BuiltWith)",
                        source="Passive Web Tech",
                        confidence="Medium",
                        color="orange",
                        status="Detected",
                        raw_data=f"BuiltWith detected: {tech}",
                        tags=["tech", "builtwith"]
                    ))
            meta_gen = re.findall(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', resp.text, re.I)
            for gen in meta_gen:
                findings.append(make_finding(
                    entity=gen.strip(),
                    ftype="CMS Generator Tag (BuiltWith)",
                    source="Passive Web Tech",
                    confidence="High",
                    color="blue",
                    status="Detected",
                    raw_data=f"Generator: {gen.strip()}",
                    tags=["tech", "cms", "generator"]
                ))
    except Exception:
        pass
    return findings

async def _fetch_netcraft_data(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://sitereport.netcraft.com/?url=http://{domain}", timeout=15.0)
        if resp.status_code == 200:
            server_match = re.search(r'Server\s*:\s*([^<\n]+)', resp.text, re.I)
            if server_match:
                server_val = server_match.group(1).strip()
                findings.append(make_finding(
                    entity=server_val[:200],
                    ftype="Server Header (Netcraft)",
                    source="Passive Web Tech",
                    confidence="High",
                    color="orange",
                    status="Detected",
                    raw_data=f"Netcraft server: {server_val}",
                    tags=["tech", "server", "netcraft"]
                ))
            tech_matches = re.findall(r'<td[^>]*class="[^"]*tech[^"]*"[^>]*>([^<]+)</td>', resp.text, re.I)
            for t in tech_matches[:10]:
                findings.append(make_finding(
                    entity=t.strip()[:100],
                    ftype="Technology (Netcraft)",
                    source="Passive Web Tech",
                    confidence="Medium",
                    color="slate",
                    status="Detected",
                    tags=["tech", "netcraft"]
                ))
    except Exception:
        pass
    return findings

async def _fetch_archive_headers(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=5&filter=statuscode:200", timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            for row in data[1:6]:
                if isinstance(row, list) and len(row) >= 2:
                    orig_url = row[0]
                    ts = row[1]
                    try:
                        resp_hdrs = await safe_fetch(client, f"http://web.archive.org/web/{ts}if_/{orig_url}", timeout=10.0)
                        hdrs = resp_hdrs.headers
                        server = hdrs.get("server", "")
                        powered = hdrs.get("x-powered-by", "")
                        cf_ray = hdrs.get("cf-ray", "")
                        if server:
                            for sig, label in SERVER_TECH_SIGNATURES.items():
                                if sig in server.lower():
                                    findings.append(make_finding(
                                        entity=label,
                                        ftype=f"Server Technology (Archive - {ts[:8]})",
                                        source="Passive Web Tech",
                                        confidence="High",
                                        color="orange",
                                        status="Historical",
                                        raw_data=f"Server: {server} [{ts[:8]}]",
                                        tags=["tech", "server", "historical"]
                                    ))
                                    break
                            else:
                                findings.append(make_finding(
                                    entity=server[:200],
                                    ftype=f"Server Header (Archive - {ts[:8]})",
                                    source="Passive Web Tech",
                                    confidence="High",
                                    color="slate",
                                    status="Historical",
                                    raw_data=f"Server: {server} [{ts[:8]}]",
                                    tags=["tech", "server", "historical"]
                                ))
                        if powered:
                            findings.append(make_finding(
                                entity=powered[:200],
                                ftype=f"X-Powered-By (Archive - {ts[:8]})",
                                source="Passive Web Tech",
                                confidence="High",
                                color="orange",
                                status="Historical",
                                raw_data=f"X-Powered-By: {powered} [{ts[:8]}]",
                                tags=["tech", "x-powered-by", "historical"]
                            ))
                        if cf_ray:
                            findings.append(make_finding(
                                entity="Cloudflare detected via cf-ray header",
                                ftype=f"CDN Detection (Archive - {ts[:8]})",
                                source="Passive Web Tech",
                                confidence="High",
                                color="orange",
                                status="Historical",
                                raw_data=f"cf-ray in cached headers from {ts[:8]}",
                                tags=["tech", "cloudflare", "cdn"]
                            ))
                        for sig, label in CDN_SIGNATURES.items():
                            if sig in server.lower():
                                findings.append(make_finding(
                                    entity=label,
                                    ftype=f"CDN Detected (Archive - {ts[:8]})",
                                    source="Passive Web Tech",
                                    confidence="High",
                                    color="orange",
                                    status="Historical",
                                    raw_data=f"CDN: {label} from {ts[:8]}",
                                    tags=["tech", "cdn", "historical"]
                                ))
                    except Exception:
                        pass
    except Exception:
        pass
    return findings

async def _check_similarweb_similartech(domain: str, client: AsyncClient) -> list:
    findings = []
    try:
        resp = await safe_fetch(client, f"https://www.similarweb.com/website/{domain}/", timeout=15.0)
        if resp.status_code == 200:
            tech_items = re.findall(r'<span[^>]*class="[^"]*techName[^"]*"[^>]*>([^<]+)</span>', resp.text, re.I)
            for item in tech_items[:15]:
                findings.append(make_finding(
                    entity=item.strip()[:100],
                    ftype="Technology (SimilarTech)",
                    source="Passive Web Tech",
                    confidence="Medium",
                    color="slate",
                    status="Detected",
                    raw_data=f"SimilarTech: {item.strip()}",
                    tags=["tech", "similartech"]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if "://" in domain:
        domain = urlparse(domain).netloc

    findings.append(make_finding(
        entity=f"Starting passive web technology profiling for {domain}",
        ftype="Passive Web Tech - Start",
        source="Passive Web Tech",
        confidence="High", color="blue",
        status="Started",
        tags=["tech", "start"]
    ))

    wayback_findings = await _fetch_wayback_html(domain, client)
    findings.extend(wayback_findings)

    builtwith_findings = await _fetch_builtwith_data(domain, client)
    findings.extend(builtwith_findings)

    netcraft_findings = await _fetch_netcraft_data(domain, client)
    findings.extend(netcraft_findings)

    archive_hdr_findings = await _fetch_archive_headers(domain, client)
    findings.extend(archive_hdr_findings)

    similar_findings = await _check_similarweb_similartech(domain, client)
    findings.extend(similar_findings)

    if findings:
        tech_types = set()
        for f in findings:
            if " - " in f.entity:
                tech_types.add(f.entity.split(" - ")[0])
        findings.append(make_finding(
            entity=f"Passive Web Tech profiling complete: {len(findings)} findings",
            ftype="Passive Web Tech - Summary",
            source="Passive Web Tech",
            confidence="High", color="purple",
            status="Complete",
            tags=["tech", "summary"]
        ))

    return findings
