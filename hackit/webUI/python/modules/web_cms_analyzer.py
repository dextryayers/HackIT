import re
from urllib.parse import urlparse
from models import IntelligenceFinding
from module_common import safe_fetch, make_finding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

CMS_PATTERNS = {
    "WordPress": {
        "patterns": [r"/wp-(content|includes|admin)/", r"wp-content", r"wp-includes", r"wp-json", r"WordPress"],
        "version_paths": ["/wp-includes/version.php", "/readme.html"],
        "version_pattern": r'\$wp_version\s*=\s*["\']([^"\']+)["\']',
        "theme_path": "/wp-content/themes/",
        "plugin_path": "/wp-content/plugins/",
        "install_path": "/wp-admin/install.php",
        "login_path": "/wp-login.php",
        "user_enum_path": "/wp-json/wp/v2/users/",
    },
    "Joomla": {
        "patterns": [r"Joomla", r"/components/", r"/modules/", r"/templates/", r"/media/system/", r"option=com_"],
        "version_paths": ["/administrator/manifests/files/joomla.xml", "/README.txt"],
        "version_pattern": r'<version>(.*?)</version>',
        "login_path": "/administrator/",
        "install_path": "/installation/",
    },
    "Drupal": {
        "patterns": [r"Drupal", r"/sites/default/", r"/sites/all/", r"/core/", r"drupalSettings"],
        "version_paths": ["/core/CHANGELOG.txt", "/CHANGELOG.txt", "/core/version.php"],
        "version_pattern": r'VERSION\s*=\s*["\']([^"\']+)["\']',
        "install_path": "/install.php",
    },
    "Magento": {
        "patterns": [r"Magento", r"/skin/frontend/", r"/media/catalog/", r"/static/version", r"Mage\.", r"mage/"],
        "version_paths": ["/RELEASE_NOTES.txt", "/magento_version", "/pub/RELEASE_NOTES.txt"],
        "version_pattern": r'([\d]+\.[\d]+\.[\d]+)',
        "admin_path": "/admin",
    },
    "Shopify": {
        "patterns": [r"Shopify", r"myshopify\.com", r"/cdn/shop/", r"shopify", r"Shopify\.Call"],
        "login_path": "/admin",
        "version_paths": [],
    },
    "Squarespace": {
        "patterns": [r"Squarespace", r"squarespace\.com", r"static1\.squarespace", r"assets\.squarespace"],
        "version_paths": [],
    },
    "Wix": {
        "patterns": [r"Wix\.com", r"wix\.com", r"static\.wixstatic", r"Wix\.Client"],
        "version_paths": [],
    },
    "Weebly": {
        "patterns": [r"Weebly", r"weebly\.com", r"weebly"],
        "version_paths": [],
    },
    "Ghost": {
        "patterns": [r"Ghost", r"ghost", r"ghost\.io", r"/ghost/"],
        "version_paths": ["/ghost/"],
        "login_path": "/ghost/",
        "version_pattern": r'Ghost\s+([\d]+\.[\d]+)',
    },
    "Jekyll": {
        "patterns": [r"Jekyll", r"jekyll"],
        "version_paths": [],
    },
    "Hugo": {
        "patterns": [r"Hugo", r"hugo"],
        "version_paths": [],
    },
    "Strapi": {
        "patterns": [r"Strapi", r"strapi", r"/admin/", r"/content-manager/"],
        "version_paths": ["/admin/"],
        "login_path": "/admin/auth/login",
    },
    "Contentful": {
        "patterns": [r"Contentful", r"contentful", r"ctfassets\.net"],
        "version_paths": [],
    },
    "Sitecore": {
        "patterns": [r"Sitecore", r"sitecore", r"/sitecore/"],
        "version_paths": ["/sitecore/login"],
        "login_path": "/sitecore/login",
    },
    "Umbraco": {
        "patterns": [r"Umbraco", r"umbraco", r"/umbraco/"],
        "version_paths": ["/umbraco/"],
        "login_path": "/umbraco/",
    },
    "Kentico": {
        "patterns": [r"Kentico", r"kentico", r"/CMSPages/"],
        "version_paths": ["/cms/"],
        "login_path": "/cms/",
    },
    "DotNetNuke": {
        "patterns": [r"DNN|DotNetNuke|dotnetnuke", r"/DNN/"],
        "version_paths": ["/admin/"],
        "login_path": "/login.aspx",
    },
    "TYPO3": {
        "patterns": [r"TYPO3", r"typo3", r"/typo3/"],
        "version_paths": ["/typo3/"],
        "login_path": "/typo3/",
    },
    "Concrete5": {
        "patterns": [r"Concrete5", r"concrete5", r"/concrete/", r"ccm\."],
        "version_paths": [],
        "login_path": "/index.php/login",
    },
}

async def extract_version(client, base_url: str, version_paths: list, version_pattern: str) -> str:
    for path in version_paths:
        try:
            resp = await safe_fetch(client, f"{base_url}{path}", timeout=8.0, follow_redirects=False)
            if resp and resp.status_code == 200:
                m = re.search(version_pattern, resp.text, re.I)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return ""

async def check_user_enum(client, base_url: str, cms_name: str, config: dict) -> list:
    users = []
    if "user_enum_path" in config:
        try:
            resp = await safe_fetch(client, f"{base_url}{config['user_enum_path']}", timeout=8.0)
            if resp and resp.status_code == 200:
                user_matches = re.findall(r'"name":"([^"]+)"', resp.text)
                for u in user_matches[:10]:
                    users.append(u)
        except Exception:
            pass
    return users

async def crawl(target: str, client) -> list[IntelligenceFinding]:
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    base_url = f"https://{domain}"
    html = ""

    for proto in ["https", "http"]:
        try:
            resp = await safe_fetch(client, f"{proto}://{domain}", timeout=10.0)
            if resp:
                html = resp.text
                base_url = f"{proto}://{domain}"
                break
        except Exception:
            continue

    if not html:
        findings.append(make_finding(
            entity=f"Could not fetch {domain}",
            ftype="CMS: Fetch Failed",
            source="CMSAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["cms", "error"]
        ))
        return findings

    detected_cms = []

    for cms_name, cms_config in CMS_PATTERNS.items():
        score = 0
        matched_patterns = []
        for pattern in cms_config.get("patterns", []):
            if re.search(pattern, html, re.I):
                score += 1
                matched_patterns.append(pattern)

        if score > 0:
            version = ""
            if cms_config.get("version_paths") and cms_config.get("version_pattern"):
                version = await extract_version(client, base_url, cms_config["version_paths"], cms_config["version_pattern"])

            detected_cms.append({
                "name": cms_name,
                "confidence": score,
                "patterns_matched": matched_patterns,
                "version": version,
                "login_path": cms_config.get("login_path", ""),
                "install_path": cms_config.get("install_path", ""),
            })

            color_map = {1: "yellow", 2: "orange", 3: "purple"}
            confidence_level = "Low" if score < 2 else ("Medium" if score < 3 else "High")

            entity_parts = [f"CMS Detected: {cms_name}"]
            if version:
                entity_parts.append(f"v{version}")
            entity_parts.append(f"(confidence: {confidence_level})")

            findings.append(make_finding(
                entity=" | ".join(entity_parts),
                ftype="CMS: Detection",
                source="CMSAnalyzer",
                confidence=confidence_level,
                color=color_map.get(score, "slate"),
                threat_level="Informational",
                raw_data=f"cms={cms_name}, version={version or 'Unknown'}, patterns={'; '.join(matched_patterns[:5])}, score={score}",
                tags=["cms", cms_name.lower().replace(" ", "-").replace(".", "-"), "detection"]
            ))

            if version:
                findings.append(make_finding(
                    entity=f"{cms_name} version: {version}",
                    ftype="CMS: Version Detection",
                    source="CMSAnalyzer",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"cms={cms_name}, version={version}",
                    tags=["cms", "version", cms_name.lower().replace(" ", "-")]
                ))

            if cms_config.get("login_path"):
                login_url = f"{base_url}{cms_config['login_path']}"
                findings.append(make_finding(
                    entity=f"Login page: {login_url}",
                    ftype="CMS: Login Page",
                    source="CMSAnalyzer",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"login_url={login_url}",
                    tags=["cms", "login", cms_name.lower().replace(" ", "-")]
                ))

            if cms_config.get("install_path"):
                try:
                    ir = await safe_fetch(client, f"{base_url}{cms_config['install_path']}", timeout=5.0)
                    if ir and ir.status_code == 200:
                        findings.append(make_finding(
                            entity=f"Installation page accessible: {cms_config['install_path']}",
                            ftype="CMS: Install Page Accessible",
                            source="CMSAnalyzer",
                            confidence="High",
                            color="red",
                            threat_level="Critical",
                            status="Vulnerable",
                            raw_data=f"install_path={cms_config['install_path']}",
                            tags=["cms", "install", "vulnerability"]
                        ))
                except Exception:
                    pass

            users = await check_user_enum(client, base_url, cms_name, cms_config)
            if users:
                findings.append(make_finding(
                    entity=f"User enumeration: {len(users)} user(s) found: {', '.join(users[:5])}",
                    ftype="CMS: User Enumeration",
                    source="CMSAnalyzer",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"users={users}",
                    tags=["cms", "user-enumeration", cms_name.lower().replace(" ", "-")]
                ))

            if cms_config.get("plugin_path") or cms_config.get("theme_path"):
                plugin_path = cms_config.get("plugin_path", "")
                if plugin_path:
                    try:
                        pr = await safe_fetch(client, f"{base_url}{plugin_path}", timeout=5.0)
                        if pr and pr.status_code == 200 and "Index of" in pr.text:
                            plugin_matches = re.findall(r'<a href="([^"]+)/?"', pr.text)
                            real_plugins = [p for p in plugin_matches if p not in (".", "..", "") and "/" not in p]
                            if real_plugins:
                                findings.append(make_finding(
                                    entity=f"Plugin enumeration: {len(real_plugins)} plugin(s): {', '.join(real_plugins[:8])}",
                                    ftype="CMS: Plugin Detection",
                                    source="CMSAnalyzer",
                                    confidence="Medium",
                                    color="orange",
                                    threat_level="Informational",
                                    raw_data=f"plugins={real_plugins}",
                                    tags=["cms", "plugins", cms_name.lower().replace(" ", "-")]
                                ))
                    except Exception:
                        pass

    if not detected_cms:
        findings.append(make_finding(
            entity=f"No CMS detected for {domain}",
            ftype="CMS: No Detection",
            source="CMSAnalyzer",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["cms", "none"]
        ))
    else:
        findings.append(make_finding(
            entity=f"CMS Analysis: {len(detected_cms)} CMS platform(s) detected",
            ftype="CMS: Summary",
            source="CMSAnalyzer",
            confidence="High",
            color="purple",
            threat_level="Informational",
            raw_data=f"cms_list={[c['name'] for c in detected_cms]}, versions={[c['version'] for c in detected_cms if c['version']]}",
            tags=["cms", "summary"]
        ))

    return findings
