import httpx
import re
from urllib.parse import urlparse, quote
from typing import List
from models import IntelligenceFinding
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip

PACKAGE_REGISTRIES = [
    ("npm", "https://registry.npmjs.org/-/v1/search?text={}&size=10"),
    ("PyPI", "https://pypi.org/simple/{}/"),
    ("PyPI Search", "https://pypi.org/search/?q={}"),
    ("RubyGems", "https://rubygems.org/api/v1/search.json?query={}"),
    ("Maven Central", "https://search.maven.org/solrsearch/select?q={}&rows=10&wt=json"),
    ("NuGet", "https://azuresearch-usnc.nuget.org/query?q={}&prerel=false&take=10"),
    ("Packagist", "https://packagist.org/search.json?q={}"),
    ("Cargo", "https://crates.io/api/v1/crates?q={}&per_page=10"),
    ("Go Modules", "https://proxy.golang.org/{}"),
    ("Hex.pm", "https://hex.pm/api/packages?search={}"),
    ("Pub.dev", "https://pub.dev/api/packages?q={}"),
    ("CPAN", "https://fastapi.metacpan.org/v1/search/author?q={}"),
    ("CRAN", "https://cran.r-project.org/web/packages/available_packages_by_name.html"),
    ("Hackage", "https://hackage.haskell.org/packages/search?terms={}"),
    ("CocoaPods", "https://cocoapods.org/search?q={}"),
    ("Clojars", "https://clojars.org/search?q={}"),
    ("LuaRocks", "https://luarocks.org/m/root/search?q={}"),
    ("Homebrew", "https://formulae.brew.sh/api/formula/{}.json"),
]

VULN_API = "https://api.osv.dev/v1/query"

ADVISORY_DBS = [
    ("GitHub Advisory", "https://api.github.com/advisories?per_page=10"),
]

async def search_npm(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://registry.npmjs.org/-/v1/search?text={quote(target)}&size=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            for pkg in data.get("objects", []):
                p = pkg.get("package", {})
                results.append({
                    "registry": "npm",
                    "name": p.get("name", ""),
                    "desc": p.get("description", "") or "",
                    "version": p.get("version", ""),
                    "publisher": p.get("publisher", {}).get("username", ""),
                    "keywords": p.get("keywords", []),
                    "links": p.get("links", {}),
                })
    except:
        pass
    return results

async def search_pypi(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://pypi.org/simple/{quote(target)}/",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            resp2 = await safe_fetch(client, 
                f"https://pypi.org/pypi/{quote(target)}/json",
                headers={"User-Agent": "OSINT-Module/1.0"},
                timeout=15.0
            )
            if resp2.status_code == 200:
                data = resp2.json()
                info = data.get("info", {})
                results.append({
                    "registry": "PyPI",
                    "name": info.get("name", ""),
                    "version": info.get("version", ""),
                    "summary": info.get("summary", "") or "",
                    "author": info.get("author", "") or info.get("maintainer", "") or "",
                    "author_email": info.get("author_email", "") or info.get("maintainer_email", "") or "",
                    "home_page": info.get("home_page", "") or info.get("project_urls", {}).get("Homepage", ""),
                    "keywords": info.get("keywords", "").split(",") if info.get("keywords") else [],
                    "requires_dist": info.get("requires_dist", []) or [],
                })
    except:
        pass
    return results

async def search_rubygems(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://rubygems.org/api/v1/search.json?query={quote(target)}",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            for item in resp.json():
                results.append({
                    "registry": "RubyGems",
                    "name": item.get("name", ""),
                    "version": item.get("version", ""),
                    "info": item.get("info", "") or "",
                    "downloads": item.get("downloads", 0),
                    "homepage": item.get("homepage_uri", ""),
                })
    except:
        pass
    return results

async def search_maven(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://search.maven.org/solrsearch/select?q={quote(target)}&rows=10&wt=json",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            docs = resp.json().get("response", {}).get("docs", [])
            for doc in docs:
                results.append({
                    "registry": "Maven Central",
                    "name": f"{doc.get('g', '')}:{doc.get('a', '')}",
                    "version": doc.get("latestVersion", ""),
                    "desc": doc.get("description", "") or "",
                })
    except:
        pass
    return results

async def search_nuget(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://azuresearch-usnc.nuget.org/query?q={quote(target)}&prerel=false&take=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("data", []):
                results.append({
                    "registry": "NuGet",
                    "name": item.get("id", ""),
                    "version": item.get("version", ""),
                    "desc": item.get("description", "") or "",
                    "authors": ", ".join(item.get("authors", [])),
                    "total_downloads": item.get("totalDownloads", 0),
                })
    except:
        pass
    return results

async def search_packagist(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://packagist.org/search.json?q={quote(target)}",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("results", []):
                results.append({
                    "registry": "Packagist",
                    "name": item.get("name", ""),
                    "desc": item.get("description", "") or "",
                    "downloads": item.get("downloads", 0),
                    "repository": item.get("repository", ""),
                })
    except:
        pass
    return results

async def search_cargo(target: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, 
            f"https://crates.io/api/v1/crates?q={quote(target)}&per_page=10",
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            for item in resp.json().get("crates", []):
                results.append({
                    "registry": "Cargo",
                    "name": item.get("id", ""),
                    "version": item.get("max_version", ""),
                    "desc": item.get("description", "") or "",
                    "downloads": item.get("downloads", 0),
                })
    except:
        pass
    return results

async def check_vulnerabilities(package_name: str, ecosystem: str, client: httpx.AsyncClient) -> list:
    results = []
    try:
        resp = await safe_fetch(client, VULN_API,
            method="POST",
            data=json.dumps({"package": {"name": package_name, "ecosystem": ecosystem}}),
            headers={"User-Agent": "OSINT-Module/1.0"},
            timeout=15.0
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            for v in vulns[:5]:
                aliases = v.get("aliases", [])
                results.append({
                    "id": v.get("id", ""),
                    "aliases": aliases,
                    "summary": v.get("summary", "") or v.get("details", "") or "",
                    "severity": v.get("severity", [{}])[0].get("score", "") if v.get("severity") else "",
                    "modified": v.get("modified", ""),
                })
    except:
        pass
    return results

async def crawl(target: str, client: httpx.AsyncClient) -> List[IntelligenceFinding]:
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        t = urlparse(t).netloc

    npm_results = await search_npm(t, client)
    for pkg in npm_results[:5]:
        findings.append(make_finding(
            entity=f"npm: {pkg['name']} v{pkg['version']} - {pkg['desc'][:100]}",
            ftype="Dependency: npm Package",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["npm", "package", pkg['name'].replace("/", "-")],
        ))

    pypi_results = await search_pypi(t, client)
    for pkg in pypi_results:
        findings.append(make_finding(
            entity=f"PyPI: {pkg['name']} v{pkg['version']} - {pkg['summary'][:100]}",
            ftype="Dependency: PyPI Package",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["pypi", "python", "package"],
        ))
        if pkg.get("author_email"):
            findings.append(make_finding(
                entity=f"PyPI Maintainer: {pkg['author']} <{pkg['author_email']}>",
                ftype="Dependency: Maintainer Info",
                source="DepAnalyzer",
                confidence="Medium",
                color="slate",
                category="Dependency Intelligence",
                threat_level="Informational",
                status="Identified",
                resolution=t,
                tags=["pypi", "maintainer", "email"],
            ))

    gem_results = await search_rubygems(t, client)
    for gem in gem_results[:5]:
        findings.append(make_finding(
            entity=f"RubyGems: {gem['name']} v{gem['version']} ({gem['downloads']} downloads)",
            type="Dependency: RubyGem",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["rubygems", "ruby", "gem"],
        ))

    maven_results = await search_maven(t, client)
    for art in maven_results[:5]:
        findings.append(make_finding(
            entity=f"Maven: {art['name']} v{art['version']}",
            ftype="Dependency: Maven Artifact",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["maven", "java", "artifact"],
        ))

    nuget_results = await search_nuget(t, client)
    for pkg in nuget_results[:5]:
        findings.append(make_finding(
            entity=f"NuGet: {pkg['name']} v{pkg['version']} ({pkg['total_downloads']} downloads)",
            type="Dependency: NuGet Package",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["nuget", "dotnet", "package"],
        ))

    packagist_results = await search_packagist(t, client)
    for pkg in packagist_results[:5]:
        findings.append(make_finding(
            entity=f"Packagist: {pkg['name']} - {pkg['desc'][:100]}",
            ftype="Dependency: Packagist Package",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["packagist", "php", "package"],
        ))

    cargo_results = await search_cargo(t, client)
    for crate in cargo_results[:5]:
        findings.append(make_finding(
            entity=f"Cargo: {crate['name']} v{crate['version']} ({crate['downloads']} downloads)",
            type="Dependency: Cargo Crate",
            source="DepAnalyzer",
            confidence="High",
            color="blue",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Found",
            resolution=t,
            tags=["cargo", "rust", "crate"],
        ))

    all_package_names = []
    all_package_names.extend([p["name"] for p in npm_results])
    all_package_names.extend([p["name"] for p in pypi_results])
    all_package_names.extend([p["name"] for p in gem_results])
    all_package_names.extend([p["name"] for p in maven_results])
    all_package_names.extend([p["name"] for p in nuget_results])
    all_package_names.extend([p["name"] for p in packagist_results])
    all_package_names.extend([p["name"] for p in cargo_results])

    ecosystems_map = {"npm": "npm", "PyPI": "PyPI", "RubyGems": "RubyGems", "Maven Central": "Maven", "NuGet": "NuGet", "Packagist": "Packagist", "Cargo": "crates.io"}

    vuln_count = 0
    for pkg_name in all_package_names[:10]:
        for eco in ecosystems_map.values():
            vulns = await check_vulnerabilities(pkg_name, eco, client)
            for v in vulns:
                findings.append(make_finding(
                    entity=f"Vulnerability: {v['id']} in {pkg_name} ({eco})",
                    type="Dependency: Known Vulnerability",
                    source="DepAnalyzer",
                    confidence="High",
                    color="red",
                    category="Dependency Intelligence",
                    threat_level="Critical",
                    status="Vulnerable",
                    resolution=t,
                    raw_data=f"Summary: {v['summary'][:200]}",
                    tags=["vulnerability", "cve", eco.lower(), pkg_name.replace("/", "-")],
                ))
                vuln_count += 1

    if not all_package_names and not pypi_results and not npm_results:
        findings.append(make_finding(
            entity="No packages found for target across registries",
            ftype="Dependency: Scan Complete",
            source="DepAnalyzer",
            confidence="Low",
            color="emerald",
            category="Dependency Intelligence",
            threat_level="Informational",
            status="Clean",
            resolution=t,
            tags=["dependency", "clean"],
        ))

    findings.append(make_finding(
        entity=f"Dependency scan complete: {len(all_package_names)} packages found, {vuln_count} vulnerabilities",
        type="Dependency: Scan Summary",
        source="DepAnalyzer",
        confidence="High",
        color="slate",
        category="Dependency Intelligence",
        threat_level="Informational",
        status="Complete",
        resolution=t,
        tags=["dependency", "summary"],
    ))

    return findings
