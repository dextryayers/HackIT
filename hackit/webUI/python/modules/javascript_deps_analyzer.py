import httpx
import re
import json
from models import IntelligenceFinding

VULN_DB = {
    "jquery": {
        "1.0.0-1.12.3": [{"id": "CVE-2020-11023", "severity": "Medium", "desc": "XSS via HTML parsing in jQuery before 3.5.0"}],
        "1.0.0-3.4.9": [{"id": "CVE-2020-11022", "severity": "Medium", "desc": "XSS via .html() in jQuery before 3.5.0"}],
    },
    "lodash": {
        "4.0.0-4.17.20": [{"id": "CVE-2020-28502", "severity": "High", "desc": "Prototype pollution in lodash < 4.17.21"}],
    },
    "react": {
        "0.0.0-16.13.0": [{"id": "CVE-2022-23646", "severity": "Medium", "desc": "XS-Search in React < 17.0.2"}],
    },
    "angular": {
        "1.0.0-1.8.2": [{"id": "CVE-2022-25869", "severity": "High", "desc": "XSS in AngularJS < 1.8.3"}],
    },
    "vue": {
        "2.0.0-2.6.13": [{"id": "CVE-2022-25834", "severity": "Medium", "desc": "XSS in Vue 2 before 2.6.14"}],
    },
    "moment": {
        "2.0.0-2.29.1": [{"id": "CVE-2022-24785", "severity": "Medium", "desc": "Path traversal in moment < 2.29.2"}],
    },
    "axios": {
        "0.0.0-0.21.1": [{"id": "CVE-2021-3749", "severity": "High", "desc": "Server-side request forgery in axios < 0.21.2"}],
    },
    "socket.io": {
        "2.0.0-2.4.0": [{"id": "CVE-2021-23920", "severity": "High", "desc": "XSS in socket.io < 2.5.0"}],
    },
    "express": {
        "4.0.0-4.17.0": [{"id": "CVE-2022-24999", "severity": "Medium", "desc": "qs prototype poisoning in express < 4.17.3"}],
    },
    "handlebars": {
        "4.0.0-4.7.6": [{"id": "CVE-2021-32869", "severity": "High", "desc": "Remote code execution in handlebars < 4.7.7"}],
    },
}

CDN_PATTERNS = [
    (r"cdn\.jsdelivr\.net/(?:npm|gh)/([^/@]+)(?:@([^/]+))?", "jsdelivr"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)", "cdnjs"),
    (r"unpkg\.com/([^@]+)(?:@([^/]+))?", "unpkg"),
    (r"cdn\.jsdelivr\.net/(?:npm|comb/(?:legacy/)?)([^@/]+)(?:@([^/]+))?", "jsdelivr-comb"),
    (r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)", "googleapis"),
    (r"code\.jquery\.com/([^/]+)-(\d[\d.]*\d)", "jquery-cdn"),
    (r"stackpath\.bootstrapcdn\.com/[^/]+/([^/]+)/([^/]+)", "bootstrapcdn"),
    (r"maxcdn\.bootstrapcdn\.com/[^/]+/([^/]+)/([^/]+)", "bootstrapcdn-legacy"),
    (r"cdn\.ampproject\.org/v([\d.]+)", "amp"),
]

SCRIPT_REGEX = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_REGEX = re.compile(r'<link[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
IMPORT_REGEX = re.compile(r'(?:import|require)\s*\(?\s*["\']([^"\']+)["\']', re.IGNORECASE)
WEBPACK_CHUNK = re.compile(r'webpackJsonp|__webpack_require__|webpackChunk')
VERSION_IN_SCRIPT = re.compile(r'(?:version|v)=["\']?(\d[\d.]*\d)')
NPM_REGEX = re.compile(r'["\']_requested["\']:\s*["\'][^/]+/([^@]+)(?:@([^"\']+))?')

def parse_semver(version):
    parts = re.findall(r'\d+', str(version))
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)

def is_vulnerable(lib, version):
    results = []
    lib_lower = lib.lower()
    for name, versions in VULN_DB.items():
        if name in lib_lower or lib_lower in name:
            for ver_range, cvss in versions.items():
                parts = ver_range.split("-")
                if len(parts) == 2:
                    low, high = parts
                    v_parsed = parse_semver(version)
                    v_low = parse_semver(low)
                    v_high = parse_semver(high)
                    if v_low <= v_parsed <= v_high:
                        results.extend(cvss)
    return results

def extract_from_url(url):
    for pattern, source in CDN_PATTERNS:
        m = re.search(pattern, url, re.IGNORECASE)
        if m:
            groups = m.groups()
            lib = groups[0].replace("-", " ").title()
            version = groups[1] if len(groups) > 1 and groups[1] else "unknown"
            return lib, version, source
    m = re.search(r"/node_modules/([^/]+)/", url)
    if m:
        return m.group(1).replace("-", " ").title(), "", "node_modules"
    m = re.search(r"/vendor/([^/]+)/", url)
    if m:
        return m.group(1).replace("-", " ").title(), "", "vendor"
    m = re.search(r"/assets/([^/]+)\.(?:js|css)", url)
    if m:
        name = m.group(1).replace("-", " ").title()
        v = VERSION_IN_SCRIPT.search(url)
        version = v.group(1) if v else ""
        return name, version, "asset-path"
    return None, None, None

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text
        base_href = base_url.rstrip("/")
        scripts = SCRIPT_REGEX.findall(html)
        links = LINK_REGEX.findall(html)
        all_resources = scripts + links

        deps = {}
        for url in all_resources:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = base_href + url
            lib, version, source = extract_from_url(url)
            if lib:
                if lib not in deps:
                    deps[lib] = {"versions": set(), "sources": set(), "urls": []}
                deps[lib]["versions"].add(version if version else "unknown")
                deps[lib]["sources"].add(source)
                deps[lib]["urls"].append(url)

        imports = IMPORT_REGEX.findall(html)
        for imp in imports:
            parts = imp.split("/")
            if parts and parts[0].startswith("@") and len(parts) > 1:
                pkg = f"{parts[0]}/{parts[1]}"
            elif parts and not parts[0].startswith(".") and not parts[0].startswith("/"):
                pkg = parts[0].split("?")[0].split("#")[0]
            else:
                continue
            if pkg and "@" in pkg:
                pkg_name, pkg_ver = pkg.rsplit("@", 1)
                if re.match(r'^\d', pkg_ver):
                    deps[pkg_name] = deps.get(pkg_name, {"versions": set(), "sources": set(), "urls": []})
                    deps[pkg_name]["versions"].add(pkg_ver)
                    deps[pkg_name]["sources"].add("esm-import")

        for lib, info in sorted(deps.items()):
            version_str = ", ".join(sorted(v for v in info["versions"] if v and v != "unknown"))
            versions_to_check = [v for v in info["versions"] if v and v != "unknown"]
            vulns_found = []
            for v in versions_to_check:
                vulns_found.extend(is_vulnerable(lib, v))

            cvss_max = 0
            cve_refs = []
            for vuln in vulns_found:
                sev = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(vuln.get("severity", "Low"), 0)
                if sev > cvss_max:
                    cvss_max = sev
                cve_refs.append(f"{vuln['id']} ({vuln['severity']}: {vuln['desc'][:60]})")

            if vulns_found:
                color = "red" if cvss_max >= 3 else "orange"
                threat = "High Risk" if cvss_max >= 3 else ("Elevated Risk" if cvss_max >= 2 else "Informational")
                findings.append(IntelligenceFinding(
                    entity=f"{lib} {version_str} - {len(vulns_found)} known vulnerabilities",
                    type="JS Dependency - Vulnerable",
                    source="JSDepsAnalyzer",
                    confidence="High",
                    color=color,
                    threat_level=threat,
                    raw_data=f"Library: {lib} | Versions: {version_str} | CVEs: {'; '.join(cve_refs)}",
                    tags=["javascript", "dependency", "vulnerability", "cve"]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"{lib} {version_str}" if version_str else lib,
                    type="JS Dependency",
                    source="JSDepsAnalyzer",
                    confidence="High",
                    color="emerald" if version_str and version_str != "unknown" else "slate",
                    threat_level="Informational",
                    raw_data=f"Library: {lib} | Versions: {version_str} | Sources: {', '.join(info['sources'])}",
                    tags=["javascript", "dependency"]
                ))

        has_webpack = bool(WEBPACK_CHUNK.search(html))
        if has_webpack:
            findings.append(IntelligenceFinding(
                entity="Webpack bundle detected",
                type="Build Tool: Webpack",
                source="JSDepsAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data="Webpack chunk loading detected in page source",
                tags=["build-tool", "webpack"]
            ))
            chunk_files = [s for s in scripts if "chunk" in s.lower() or "bundle" in s.lower()]
            for cf in chunk_files[:5]:
                findings.append(IntelligenceFinding(
                    entity=cf[:200],
                    type="Webpack Chunk",
                    source="JSDepsAnalyzer",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["webpack", "chunk"]
                ))

        for url in all_resources:
            if any(ext in url.lower() for ext in [".js", ".mjs", ".cjs"]):
                if url.startswith("//"):
                    url = "https:" + url
                elif url.startswith("/"):
                    url = base_href + url
                elif not url.startswith("http"):
                    continue
                try:
                    js_resp = await client.get(url, timeout=5.0,
                        headers={"User-Agent": "Mozilla/5.0"})
                    if js_resp.status_code == 200:
                        js_text = js_resp.text[:50000]
                        npm_matches = NPM_REGEX.findall(js_text)
                        for pkg_name, pkg_ver in npm_matches:
                            if pkg_name and pkg_name not in deps:
                                findings.append(IntelligenceFinding(
                                    entity=f"{pkg_name}@{pkg_ver}" if pkg_ver else pkg_name,
                                    type="NPM Dependency (from source map)",
                                    source="JSDepsAnalyzer",
                                    confidence="Medium",
                                    color="slate",
                                    threat_level="Informational",
                                    raw_data=f"Extracted from {url}",
                                    tags=["npm", "dependency"]
                                ))
                except Exception:
                    pass

        if not deps and not has_webpack:
            findings.append(IntelligenceFinding(
                entity="No JavaScript dependencies detected",
                type="JSDeps Summary",
                source="JSDepsAnalyzer",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["javascript", "summary"]
            ))
        else:
            vuln_count = sum(1 for f in findings if "Vulnerable" in f.type)
            findings.append(IntelligenceFinding(
                entity=f"{len(deps)} JS deps found, {vuln_count} vulnerable",
                type="JSDeps Summary",
                source="JSDepsAnalyzer",
                confidence="High",
                color="red" if vuln_count else "emerald",
                threat_level="High Risk" if vuln_count else "Informational",
                raw_data=f"Total dependencies: {len(deps)} | Vulnerable: {vuln_count}",
                tags=["javascript", "summary"]
            ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"JS Deps error: {str(e)[:100]}",
            type="JSDeps Error",
            source="JSDepsAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
