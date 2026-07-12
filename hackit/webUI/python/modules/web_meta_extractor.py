import re
import json
import httpx
from urllib.parse import urlparse
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

OG_PROPERTIES = [
    "og:title", "og:description", "og:image", "og:url", "og:type",
    "og:site_name", "og:locale", "og:locale:alternate", "og:video",
    "og:audio", "og:determiner", "og:image:width", "og:image:height",
    "og:image:alt", "og:video:width", "og:video:height",
]

TWITTER_PROPERTIES = [
    "twitter:card", "twitter:site", "twitter:creator", "twitter:title",
    "twitter:description", "twitter:image", "twitter:image:alt",
    "twitter:player", "twitter:app:name", "twitter:app:id:iphone",
    "twitter:app:id:googleplay", "twitter:app:url:iphone",
]

META_NAMES = [
    "description", "keywords", "author", "robots", "viewport",
    "generator", "theme-color", "application-name", "msapplication-TileColor",
    "msapplication-config", "google-site-verification", "yandex-verification",
    "facebook-domain-verification", "p:domain_verify", "twitter:site",
    "copyright", "designer", "rating", "revisit-after", "distribution",
    "geo.region", "geo.placename", "geo.position", "ICBM",
]

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client,f"{proto}://{domain}", timeout=10.0, follow_redirects=True, headers={"User-Agent": UA})
            html = resp.text
            break
        except Exception:
            continue

    if not html:
        findings.append(make_finding(
            entity=f"Could not fetch {domain}",
            ftype="Meta: Fetch Failed",
            source="MetaExtractor",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["meta", "error"]
        ))
        return findings

    meta_tags = re.findall(r'<meta[^>]+>', html, re.I)
    if not meta_tags:
        findings.append(make_finding(
            entity="No meta tags found on the page",
            ftype="Meta: None Found",
            source="MetaExtractor",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["meta", "none"]
        ))
        return findings

    findings.append(make_finding(
        entity=f"Found {len(meta_tags)} meta tag(s) on {domain}",
        ftype="Meta: Total Tags",
        source="MetaExtractor",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"meta_count={len(meta_tags)}",
        tags=["meta", "count"]
    ))

    all_meta = {}
    for tag in meta_tags:
        name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        prop_m = re.search(r'property\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        content_m = re.search(r'content\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        charset_m = re.search(r'charset\s*=\s*["\']?([^"\' >]+)["\']?', tag, re.I)

        if charset_m:
            all_meta["charset"] = charset_m.group(1)
            continue

        meta_name = None
        if name_m:
            meta_name = name_m.group(1).lower()
        elif prop_m:
            meta_name = prop_m.group(1).lower()

        if meta_name and content_m:
            all_meta[meta_name] = content_m.group(1)

    generator = all_meta.get("generator", "")
    if generator:
        findings.append(make_finding(
            entity=f"Generator: {generator}",
            ftype="Meta: Generator",
            source="MetaExtractor",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"generator={generator}",
            tags=["meta", "generator"]
        ))

    author = all_meta.get("author", "")
    if author:
        findings.append(make_finding(
            entity=f"Author/Creator: {author}",
            ftype="Meta: Author",
            source="MetaExtractor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"author={author}",
            tags=["meta", "author"]
        ))

    description = all_meta.get("description", "")
    if description:
        findings.append(make_finding(
            entity=f"Description: {description[:120]}",
            ftype="Meta: Description",
            source="MetaExtractor",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"description={description}",
            tags=["meta", "description"]
        ))

    keywords = all_meta.get("keywords", "")
    if keywords:
        kw_list = [k.strip() for k in keywords.split(",")]
        findings.append(make_finding(
            entity=f"Keywords: {', '.join(kw_list[:10])}",
            ftype="Meta: Keywords",
            source="MetaExtractor",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"keywords={keywords}",
            tags=["meta", "keywords"]
        ))

    og_data = {}
    for og_prop in OG_PROPERTIES:
        if og_prop in all_meta:
            og_data[og_prop] = all_meta[og_prop]

    if og_data:
        findings.append(make_finding(
            entity=f"Open Graph tags: {len(og_data)} found",
            ftype="Meta: Open Graph",
            source="MetaExtractor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"og_data={json.dumps(og_data)}",
            tags=["meta", "opengraph"]
        ))

        if og_data.get("og:title"):
            findings.append(make_finding(
                entity=f"OG Title: {og_data['og:title'][:100]}",
                ftype="Meta: OG Title",
                source="MetaExtractor",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["meta", "opengraph"]
            ))
        if og_data.get("og:description"):
            findings.append(make_finding(
                entity=f"OG Description: {og_data['og:description'][:120]}",
                ftype="Meta: OG Description",
                source="MetaExtractor",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["meta", "opengraph"]
            ))
        if og_data.get("og:image"):
            findings.append(make_finding(
                entity=f"OG Image: {og_data['og:image'][:100]}",
                ftype="Meta: OG Image",
                source="MetaExtractor",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["meta", "opengraph"]
            ))
        if og_data.get("og:type"):
            findings.append(make_finding(
                entity=f"OG Type: {og_data['og:type']}",
                ftype="Meta: OG Type",
                source="MetaExtractor",
                confidence="High",
                color="slate",
                threat_level="Informational",
                tags=["meta", "opengraph"]
            ))

    twitter_data = {}
    for tw_prop in TWITTER_PROPERTIES:
        if tw_prop in all_meta:
            twitter_data[tw_prop] = all_meta[tw_prop]

    if twitter_data:
        findings.append(make_finding(
            entity=f"Twitter Card tags: {len(twitter_data)} found",
            ftype="Meta: Twitter Card",
            source="MetaExtractor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"twitter_data={json.dumps(twitter_data)}",
            tags=["meta", "twitter"]
        ))

    json_ld_pattern = re.compile(r'<script[^>]*ftype=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.DOTALL)
    json_ld_items = json_ld_pattern.findall(html)
    if json_ld_items:
        findings.append(make_finding(
            entity=f"JSON-LD structured data: {len(json_ld_items)} block(s) found",
            ftype="Meta: JSON-LD",
            source="MetaExtractor",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"json_ld_count={len(json_ld_items)}",
            tags=["meta", "json-ld", "structured-data"]
        ))
        for idx, item in enumerate(json_ld_items[:3]):
            try:
                parsed = json.loads(item)
                schema_type = parsed.get("@type", "Unknown")
                findings.append(make_finding(
                    entity=f"JSON-LD type: {schema_type}",
                    ftype="Meta: JSON-LD Type",
                    source="MetaExtractor",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"json_ld={item[:200]}",
                    tags=["meta", "json-ld", schema_type.lower().replace(" ", "-")]
                ))
            except Exception:
                continue

    schema_pattern = re.compile(r'itemscope|itemprop|itemftype=["\']https?://schema\.org/([^"\']+)["\']', re.I)
    schema_matches = schema_pattern.findall(html)
    unique_schemas = set(schema_matches)
    if unique_schemas:
        findings.append(make_finding(
            entity=f"Schema.org markup types found: {', '.join(list(unique_schemas)[:5])}",
            ftype="Meta: Schema.org",
            source="MetaExtractor",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"schemas={list(unique_schemas)}",
            tags=["meta", "schema-org"]
        ))

    geo_tags = {}
    for geo_key in ["geo.region", "geo.placename", "geo.position", "ICBM"]:
        if geo_key in all_meta:
            geo_tags[geo_key] = all_meta[geo_key]

    if geo_tags:
        findings.append(make_finding(
            entity=f"Geographic meta tags: {json.dumps(geo_tags)}",
            ftype="Meta: Geographic",
            source="MetaExtractor",
            confidence="High",
            color="green",
            threat_level="Informational",
            raw_data=f"geo_tags={json.dumps(geo_tags)}",
            tags=["meta", "geo", "location"]
        ))

    verification_tags = {}
    for v_key in ["google-site-verification", "yandex-verification", "facebook-domain-verification", "p:domain_verify", "msvalidate.01"]:
        if v_key in all_meta:
            verification_tags[v_key] = all_meta[v_key]

    if verification_tags:
        findings.append(make_finding(
            entity=f"Verification tags: {', '.join(verification_tags.keys())}",
            ftype="Meta: Verification",
            source="MetaExtractor",
            confidence="High",
            color="blue",
            threat_level="Informational",
            raw_data=f"verification={json.dumps(verification_tags)}",
            tags=["meta", "verification"]
        ))

    findings.append(make_finding(
        entity=f"Meta Extraction Summary: {len(meta_tags)} tags, {len(og_data)} OG, {len(twitter_data)} Twitter, {len(json_ld_items)} JSON-LD, {len(unique_schemas)} Schema",
        ftype="Meta: Summary",
        source="MetaExtractor",
        confidence="High",
        color="blue",
        threat_level="Informational",
        raw_data=f"meta_count={len(meta_tags)}, og={len(og_data)}, twitter={len(twitter_data)}, jsonld={len(json_ld_items)}, schema={len(unique_schemas)}",
        tags=["meta", "summary"]
    ))

    return findings
