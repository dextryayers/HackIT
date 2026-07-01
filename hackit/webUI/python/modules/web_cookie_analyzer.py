import httpx
import re
import hashlib
from datetime import datetime
from models import IntelligenceFinding

SESSION_COOKIE_NAMES = [
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "laravel_session",
    "connect.sid", "_session_id", "sid", "token", "session",
    "sessionid", "sessid", "sess_id", "SESSID", "SESSION",
    "ci_session", "symfony", "wordpress_logged_in",
    "wp-settings", "drupal", "DRUPAL_UID", "SESS",
    "auth_token", "access_token", "refresh_token", "id_token",
    "jwt", "bearer", "api_key", "api-key",
    "_csrf", "csrf_token", "XSRF-TOKEN",
    "remember_me", "remember_token", "rememberme",
    "login_token", "logintoken", "user_token",
    "auth", "authentication", "authenticate",
    "ticket", "cas_ticket", "samlsession",
    "oidc", "openid", "idp_session",
    "aws_session", "amz_token", "cognito",
    "firebase_token", "fbtoken",
]

TRACKING_COOKIE_NAMES = [
    "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl_au", "_gcl_aw",
    "_ga_", "_hj", "_hjid", "_hjs", "_hp", "_mk", "_lr",
    "_lr_", "_scid", "_shopify", "_s", "_sp", "_uetsid",
    "_uetvid", "_uacct", "_utm", "__utm", "__utma", "__utmb",
    "__utmc", "__utmt", "__utmz", "__gads", "__gpi", "__eoi",
    "__ar_v4", "__s", "AMP_TOKEN", "_dc_gtm",
    "_fb", "_fbc", "_fsh", "_fss",
    "_ym", "_ym_d", "_ym_isad", "_ym_uid",
    "_ym_visorc", "_hstc", "_hssc", "_hssrc",
    "__hstc", "__hssc", "__hssrc",
    "hubspotutk", "__hs_opt_out",
    "pardot", "lpt_h", "lpt_n",
    "mkt_token", "mkt_data",
    "_clck", "_clsk", "_clskref",
    "ln_or", "li_sugr", "li_at",
    "twitter_id", "twid", "auth_token",
    "guest_id", "personalization_id",
]

ANALYTICS_COOKIE_NAMES = [
    "_pk_id", "_pk_ses", "mtm_", "_pk_ref", "_pk_cvar",
    "_pk_hsr", "piwik_", "_pk_testcookie",
    "pk_id", "pk_ses", "pk_ref", "pk_hsr",
    "mtm_cookie", "matomo",
    "_pa", "_pa_",
    "sa_user_id", "sa_session_id",
]

FRAMEWORK_COOKIE_PATTERNS = {
    "PHP": [r"PHPSESSID", r"laravel_session", r"ci_session", r"wp-settings", r"wordpress_"],
    "Java": [r"JSESSIONID", r"OPENSHIFT", r"LtpaToken", r"rememberMe"],
    "ASP.NET": [r"ASP\.NET_SessionId", r"__RequestVerificationToken", r".ASPXAUTH"],
    "Node.js/Express": [r"connect\.sid", r"session", r"next-auth"],
    "Python/Django": [r"sessionid", r"csrftoken", r"django"],
    "Python/Flask": [r"session"],
    "Ruby/Rails": [r"_session_id", r"_csrf_token", r"rails"],
    "Go/Gin": [r"gin_session", r"go_session"],
}

THIRD_PARTY_COOKIE_DOMAINS = [
    ".doubleclick.net", ".google.com", ".facebook.com", ".fbcdn.net",
    ".adsrvr.org", ".adroll.com", ".criteo.com", ".criteo.net",
    ".amazon-adsystem.com", ".adnxs.com", ".rubiconproject.com",
    ".openx.net", ".pubmatic.com", ".casalemedia.com",
    ".moatads.com", ".scorecardresearch.com", ".quantserve.com",
    ".krxd.net", ".sharethis.com", ".addthis.com",
    ".disqus.com", ".youtube.com", ".vimeo.com",
    ".hotjar.com", ".fullstory.com", ".crazyegg.com",
    ".optimizely.com", ".vwo.com", ".mouseflow.com",
]

def analyze_cookie_attributes(cookie_string):
    analysis = {}
    parts = cookie_string.split(";")
    name_value = parts[0].strip()
    if "=" in name_value:
        analysis["name"], analysis["value"] = name_value.split("=", 1)
    else:
        analysis["name"] = name_value
        analysis["value"] = ""
    analysis["name"] = analysis.get("name", "")
    analysis["value"] = analysis.get("value", "")

    attrs = {}
    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.lower()] = v
        else:
            attrs[part.lower()] = True
    analysis["attributes"] = attrs

    analysis["secure"] = "secure" in attrs
    analysis["httponly"] = "httponly" in attrs
    analysis["samesite"] = attrs.get("samesite", "none").lower()
    analysis["domain"] = attrs.get("domain", "")
    analysis["path"] = attrs.get("path", "/")
    analysis["max_age"] = attrs.get("max-age", "")
    analysis["expires"] = attrs.get("expires", "")
    analysis["same_site_strict"] = attrs.get("samesite", "").lower() == "strict"
    analysis["same_site_lax"] = attrs.get("samesite", "").lower() == "lax"

    return analysis

def classify_cookie(name):
    name_lower = name.lower().replace("-", "_").replace(" ", "_")
    for sn in SESSION_COOKIE_NAMES:
        if name_lower == sn.lower() or name_lower.endswith(f"_{sn.lower()}") or name_lower.startswith(f"{sn.lower()}_"):
            return "Session"
    for tn in TRACKING_COOKIE_NAMES:
        if name_lower.startswith(tn.lower()):
            return "Tracking"
    for an in ANALYTICS_COOKIE_NAMES:
        if name_lower.startswith(an.lower()):
            return "Analytics"
    return "General"

def detect_framework_from_cookie(name):
    for fw, patterns in FRAMEWORK_COOKIE_PATTERNS.items():
        for pat in patterns:
            if re.match(pat, name, re.IGNORECASE):
                return fw
    return None

def is_third_party_cookie(domain):
    for tp_domain in THIRD_PARTY_COOKIE_DOMAINS:
        if domain.endswith(tp_domain) or domain == tp_domain:
            return True
    return False

def is_encrypted_cookie(value):
    indicators = 0
    if len(value) > 20:
        indicators += 1
    if re.match(r'^[A-Za-z0-9+/=]+$', value):
        indicators += 1
    if re.match(r'^[A-Fa-f0-9]{32,}$', value):
        indicators += 2
    if re.match(r'^[A-Fa-f0-9]{40,}$', value):
        indicators += 2
    if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', value):
        indicators += 3
    return indicators >= 2

def rate_cookie_security(c):
    score = 100
    if c.get("secure"):
        score += 10
    else:
        score -= 25
    if c.get("httponly"):
        score += 10
    else:
        score -= 20
    samesite = c.get("samesite", "none")
    if samesite == "strict":
        score += 15
    elif samesite == "lax":
        score += 5
    else:
        score -= 10
    if c.get("domain"):
        if c["domain"].startswith("."):
            score -= 15
        if len(c["domain"].split(".")) <= 2:
            score -= 10
    if c.get("path") and c["path"] == "/":
        score -= 5
    return max(0, min(100, score))

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            raw_cookies = resp.headers.get("set-cookie", "")
            if raw_cookies:
                set_cookie_headers = [raw_cookies]

        all_cookies = resp.cookies if hasattr(resp, "cookies") else {}

        cookie_list = []
        if set_cookie_headers:
            for sc in set_cookie_headers:
                analyzed = analyze_cookie_attributes(sc)
                cookie_list.append(analyzed)

        for name, value in all_cookies.items():
            existing = [c for c in cookie_list if c.get("name") == name]
            if not existing:
                cookie_list.append({
                    "name": name,
                    "value": str(value)[:50],
                    "secure": False,
                    "httponly": False,
                    "samesite": "none",
                    "domain": "",
                    "path": "/",
                    "max_age": "",
                    "expires": "",
                    "attributes": {},
                    "same_site_strict": False,
                    "same_site_lax": False,
                })

        for c in cookie_list:
            name = c.get("name", "")
            if not name:
                continue

            cookie_class = classify_cookie(name)
            framework = detect_framework_from_cookie(name)

            secure = c.get("secure", False)
            httponly = c.get("httponly", False)
            samesite = c.get("samesite", "none")
            domain = c.get("domain", "")
            path = c.get("path", "/")
            max_age = c.get("max_age", "")
            expires = c.get("expires", "")
            value = c.get("value", "")

            security_score = rate_cookie_security(c)
            is_encrypted = is_encrypted_cookie(value)
            is_tp_cookie = is_third_party_cookie(domain)

            issues = []
            if not secure:
                issues.append("Missing Secure flag")
            if not httponly:
                issues.append("Missing HttpOnly flag")
            if samesite == "none":
                issues.append("SameSite=None (no CSRF protection)")
            if not domain:
                issues.append("No Domain restriction")
            if domain.startswith("."):
                issues.append("Wildcard domain (all subdomains)")
            if path == "/":
                issues.append("Root path (all endpoints)")
            if is_tp_cookie:
                issues.append("Third-party cookie domain")

            color = "red" if issues else "emerald"
            threat = "Elevated Risk" if issues else "Informational"

            findings.append(IntelligenceFinding(
                entity=f"{name}={value[:30]}...",
                type=f"Cookie: {cookie_class}",
                source="WebCookieAnalyzer",
                confidence="High",
                color=color,
                threat_level=threat if issues else "Informational",
                raw_data=f"Name: {name} | Secure: {secure} | HttpOnly: {httponly} | SameSite: {samesite} | Domain: {domain} | Path: {path} | Max-Age: {max_age} | Expires: {expires} | Score: {security_score}/100 | Encrypted: {is_encrypted} | Issues: {', '.join(issues) if issues else 'None'} | 3rd-party: {is_tp_cookie}",
                tags=["cookie", cookie_class.lower(), name]
            ))

            if framework:
                findings.append(IntelligenceFinding(
                    entity=f"Framework cookie: {name} -> {framework}",
                    type="Cookie Framework Detection",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="purple",
                    threat_level="Informational",
                    raw_data=f"Cookie {name} suggests {framework} backend",
                    tags=["cookie", "framework", framework.lower().replace("/", "-").replace(".", "-")]
                ))

            if not httponly:
                findings.append(IntelligenceFinding(
                    entity=f"{name} - missing HttpOnly (XSS-accessible)",
                    type="Cookie Security Issue",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    raw_data=f"Cookie {name} has no HttpOnly flag - accessible via JavaScript",
                    tags=["cookie", "security", "httponly"]
                ))

            if cookie_class == "Session" and not secure:
                findings.append(IntelligenceFinding(
                    entity=f"{name} - session cookie without Secure flag",
                    type="Cookie Security Issue",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    raw_data=f"Session cookie {name} transmitted over unencrypted connections",
                    tags=["cookie", "session", "secure-flag"]
                ))

            if domain and not domain.startswith("."):
                findings.append(IntelligenceFinding(
                    entity=f"Cookie domain restricted: {domain}",
                    type="Cookie Scope: Domain",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["cookie", "scope", "domain"]
                ))

            if is_tp_cookie:
                findings.append(IntelligenceFinding(
                    entity=f"Third-party cookie: {domain}{path} {name}",
                    type="Third-Party Cookie",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"Third-party cookie detected: domain={domain}, name={name}",
                    tags=["cookie", "third-party", "tracking"]
                ))

            if is_encrypted and cookie_class == "Session":
                findings.append(IntelligenceFinding(
                    entity=f"Session cookie appears encrypted/hashed: {name}",
                    type="Cookie Encryption Detected",
                    source="WebCookieAnalyzer",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    tags=["cookie", "security", "encryption"]
                ))
            elif cookie_class == "Session" and not is_encrypted and len(value) < 16:
                findings.append(IntelligenceFinding(
                    entity=f"Session cookie appears weak: {name}={value[:20]}",
                    type="Weak Session Cookie",
                    source="WebCookieAnalyzer",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["cookie", "weak-session"]
                ))

        for c in cookie_list:
            prefix_issues = analyze_cookie_prefix(c.get("name", ""), c)
            for issue in prefix_issues:
                findings.append(IntelligenceFinding(
                    entity=issue[:200],
                    type="Cookie Prefix Violation",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="red",
                    threat_level="High Risk",
                    tags=["cookie", "prefix", "security"]
                ))

        jwt_cookies = detect_jwt_in_cookies(cookie_list)
        for jc in jwt_cookies:
            findings.append(IntelligenceFinding(
                entity=f"JWT token in cookie: {jc}",
                type="JWT Cookie Detected",
                source="WebCookieAnalyzer",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"JWT cookie detected: {jc}",
                tags=["cookie", "jwt", "authentication"]
            ))

        for c in cookie_list:
            samesite_analysis = analyze_samesite_protection(c.get("samesite", ""), c.get("secure", False))
            if samesite_analysis.get("risk"):
                findings.append(IntelligenceFinding(
                    entity=f"SameSite={c.get('samesite', 'none')} on {c.get('name', '?')}: {samesite_analysis.get('risk', '')[:100]}",
                    type="Cookie SameSite Analysis",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="orange" if samesite_analysis.get("value") == "none" else "emerald",
                    threat_level="Elevated Risk" if samesite_analysis.get("value") == "none" else "Informational",
                    tags=["cookie", "samesite", "security"]
                ))

            privacy_risk, privacy_score = categorize_privacy_risk(c)
            if privacy_risk == "High":
                findings.append(IntelligenceFinding(
                    entity=f"High privacy risk: {c.get('name', '?')} (score: {privacy_score})",
                    type="Cookie Privacy Risk",
                    source="WebCookieAnalyzer",
                    confidence="Medium",
                    color="red",
                    threat_level="Elevated Risk",
                    tags=["cookie", "privacy", "tracking"]
                ))

            entropy = detect_cookie_entropy(c.get("value", ""))
            if entropy > 3.5:
                findings.append(IntelligenceFinding(
                    entity=f"High entropy cookie: {c.get('name', '?')} (entropy: {entropy})",
                    type="Cookie Entropy Analysis",
                    source="WebCookieAnalyzer",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["cookie", "entropy", "security"]
                ))

            exp_analysis = analyze_expiration(c.get("expires", ""), c.get("max_age", ""))
            if exp_analysis.get("type"):
                findings.append(IntelligenceFinding(
                    entity=f"{c.get('name', '?')}: {exp_analysis['type']}",
                    type="Cookie Expiration Analysis",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["cookie", "expiration", "persistence"]
                ))
            if exp_analysis.get("risk"):
                findings.append(IntelligenceFinding(
                    entity=f"{c.get('name', '?')}: {exp_analysis['risk']}",
                    type="Cookie Persistence Warning",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color="orange",
                    threat_level="Elevated Risk",
                    tags=["cookie", "persistence", "tracking"]
                ))

        for fw_name, patterns in FRAMEWORK_COOKIE_SIGNATURES_EXTRA.items():
            for pat in patterns:
                for c in cookie_list:
                    if re.search(pat, c.get("name", ""), re.IGNORECASE):
                        findings.append(IntelligenceFinding(
                            entity=f"Framework cookie: {c.get('name', '')} -> {fw_name}",
                            type="Cookie Framework Detection",
                            source="WebCookieAnalyzer",
                            confidence="High",
                            color="purple",
                            threat_level="Informational",
                            tags=["cookie", "framework", fw_name.lower().replace("/", "-").replace(" ", "-")]
                        ))
                        break

        if len(cookie_list) > 15:
            findings.append(IntelligenceFinding(
                entity=f"{len(cookie_list)} cookies set - possible cookie inflation",
                type="Cookie Inflation",
                source="WebCookieAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"Total cookies: {len(cookie_list)} - may impact performance and security",
                tags=["cookie", "inflation"]
            ))

        persistent_cookies = [c for c in cookie_list if c.get("max_age") or c.get("expires")]
        if persistent_cookies:
            for c in persistent_cookies[:3]:
                persistence = c.get("max_age") or c.get("expires")
                findings.append(IntelligenceFinding(
                    entity=f"Persistent cookie: {c['name']} (max-age: {persistence})",
                    type="Persistent Cookie",
                    source="WebCookieAnalyzer",
                    confidence="High",
                    color=("red" if "session" in c.get("name", "").lower() else "orange"),
                    threat_level="Elevated Risk" if "session" in c.get("name", "").lower() else "Informational",
                    raw_data=f"Cookie {c['name']} persists: {persistence}",
                    tags=["cookie", "persistent"]
                ))

        session_count = sum(1 for c in cookie_list if classify_cookie(c.get("name", "")) == "Session")
        tracking_count = sum(1 for c in cookie_list if classify_cookie(c.get("name", "")) == "Tracking")
        analytics_count = sum(1 for c in cookie_list if classify_cookie(c.get("name", "")) == "Analytics")
        missing_secure = sum(1 for c in cookie_list if not c.get("secure"))
        missing_httponly = sum(1 for c in cookie_list if not c.get("httponly"))
        third_party_count = sum(1 for c in cookie_list if is_third_party_cookie(c.get("domain", "")))
        encrypted_count = sum(1 for c in cookie_list if is_encrypted_cookie(c.get("value", "")) and classify_cookie(c.get("name", "")) == "Session")

        avg_security = sum(rate_cookie_security(c) for c in cookie_list) / max(len(cookie_list), 1)
        score = 100
        score -= missing_secure * 10
        score -= missing_httponly * 8
        score -= third_party_count * 5
        if session_count > 0:
            all_secure = all(c.get("secure") for c in cookie_list if classify_cookie(c.get("name", "")) == "Session")
            all_httponly = all(c.get("httponly") for c in cookie_list if classify_cookie(c.get("name", "")) == "Session")
            if not all_secure:
                score -= 20
            if not all_httponly:
                score -= 15
        score = max(0, min(100, score))

        color_score = "emerald" if score >= 80 else ("orange" if score >= 50 else "red")
        findings.append(IntelligenceFinding(
            entity=f"Cookie Security Score: {score}/100 ({len(cookie_list)} cookies, {session_count} session, {tracking_count} tracking, {third_party_count} 3rd-party)",
            type="Cookie Security Summary",
            source="WebCookieAnalyzer",
            confidence="High",
            color=color_score,
            threat_level="Elevated Risk" if score < 80 else "Informational",
            raw_data=f"Total: {len(cookie_list)} | Session: {session_count} | Tracking: {tracking_count} | Analytics: {analytics_count} | 3rd-party: {third_party_count} | Missing Secure: {missing_secure} | Missing HttpOnly: {missing_httponly} | Encrypted: {encrypted_count} | Avg Security: {avg_security:.0f}/100",
            tags=["cookie", "summary", "security-score"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Cookie Analyzer error: {str(e)[:100]}",
            type="Cookie Analyzer Error",
            source="WebCookieAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings


# === EXTENDED UPGRADE: Cookie prefix analysis, JWT detection, SameSite analysis, more patterns ===

COOKIE_PREFIX_RULES = {
    "__Host-": {"requires": ["secure", "path=/", "no domain"]},
    "__Secure-": {"requires": ["secure"]},
}

COOKIE_SECURITY_RECOMMENDATIONS = {
    "Missing Secure flag": "Set the 'Secure' flag to ensure cookie is only sent over HTTPS",
    "Missing HttpOnly flag": "Set the 'HttpOnly' flag to prevent JavaScript access (mitigates XSS)",
    "SameSite=None": "Set SameSite=Lax or Strict to provide CSRF protection",
    "No Domain restriction": "Consider setting a specific Domain attribute to limit cookie scope",
    "Wildcard domain": "Avoid wildcard domains (e.g. .example.com) to limit cookie scope",
    "Root path": "Set a more specific Path to restrict cookie scope",
    "Third-party cookie domain": "Review necessity of third-party cookies for privacy compliance",
}

FRAMEWORK_COOKIE_SIGNATURES_EXTRA = {
    "Next.js": [r"__next", r"next-auth", r"_next"],
    "Nuxt.js": [r"__nuxt"],
    "Remix": [r"_remix"],
    "Gatsby": [r"gatsby"],
    "Drupal": [r"DRUPAL", r"SESS", r"SSESS"],
    "Joomla": [r"joomla", r"JOS"],
    "Magento": [r"mage", r"admin", r"MAGE"],
    "Shopify": [r"_shopify", r"cart", r"secure_customer"],
    "WooCommerce": [r"woocommerce", r"wp_woocommerce"],
    "PrestaShop": [r"prestashop", r"PrestaShop"],
    "TYPO3": [r"be_typo", r"fe_typo"],
    "Concrete5": [r"CONCRETE"],
    "SuiteCRM": [r"SuiteCRM"],
    "SugarCRM": [r"sugar"],
    "vBulletin": [r"bb_session", r"vbulletin"],
    "phpBB": [r"phpbb"],
    "Simple Machines Forum": [r"SMF"],
}

MORE_TRACKING_COOKIE_NAMES = [
    "_clsk", "_clck", "_clskref", "_ga", "_gid", "_gat",
    "_fbp", "_fbc", "_gcl_au", "_gcl_aw", "_gcl_gs",
    "_ga_", "_hj", "_hjid", "_hjs", "_hp", "_mk", "_lr",
    "_lr_", "_scid", "_shopify", "_s", "_sp", "_uetsid",
    "_uetvid", "_uacct", "_utm", "__utm", "__utma", "__utmb",
    "__utmc", "__utmt", "__utmz", "__gads", "__gpi", "__eoi",
    "__ar_v4", "__s", "AMP_TOKEN", "_dc_gtm",
    "_ym", "_ym_d", "_ym_isad", "_ym_uid",
    "_ym_visorc", "_hstc", "_hssc", "_hssrc",
    "__hstc", "__hssc", "__hssrc",
    "hubspotutk", "__hs_opt_out",
    "pardot", "lpt_h", "lpt_n",
    "mkt_token", "mkt_data",
    "ln_or", "li_sugr", "li_at",
    "guest_id", "personalization_id",
    "__cfduid", "cf_clearance",
    "AUID", "demdex", "everest",
]

SAMESITE_VALUES = {
    "strict": "Best CSRF protection, but may break some flows",
    "lax": "Good CSRF protection (default in modern browsers)",
    "none": "No CSRF protection, requires Secure flag",
}

JWT_COOKIE_PATTERN = re.compile(r'eyJ[A-Za-z0-9+/=_-]+\.eyJ[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+')

def analyze_cookie_prefix(name, attrs):
    issues = []
    try:
        for prefix, rules in COOKIE_PREFIX_RULES.items():
            if name.startswith(prefix):
                for req in rules["requires"]:
                    if req == "secure" and not attrs.get("secure"):
                        issues.append(f"__Host-/__Secure- cookie '{name}' missing Secure flag")
                    if req == "path=/" and attrs.get("path") != "/":
                        issues.append(f"__Host- cookie '{name}' must have path=/")
                    if "no domain" in req and attrs.get("domain"):
                        issues.append(f"__Host- cookie '{name}' must not have Domain attribute")
    except Exception:
        pass
    return issues

def detect_jwt_in_cookies(cookie_list):
    jwt_cookies = []
    try:
        for c in cookie_list:
            value = c.get("value", "")
            if JWT_COOKIE_PATTERN.match(value):
                jwt_cookies.append(c.get("name", ""))
    except Exception:
        pass
    return jwt_cookies

def analyze_samesite_protection(samesite, secure):
    analysis = {}
    try:
        samesite_lower = samesite.lower() if samesite else "none"
        analysis["value"] = samesite_lower
        analysis["desc"] = SAMESITE_VALUES.get(samesite_lower, "Unknown")
        if samesite_lower == "none" and not secure:
            analysis["risk"] = "Cookie sent on all requests, including cross-site, without HTTPS protection"
        elif samesite_lower == "none" and secure:
            analysis["risk"] = "Cookie sent on all cross-site requests (Secure only)"
        elif samesite_lower == "lax":
            analysis["risk"] = "Cookie sent on top-level navigations (good default)"
        elif samesite_lower == "strict":
            analysis["risk"] = "Cookie only sent in first-party context (most secure)"
    except Exception:
        pass
    return analysis

def categorize_privacy_risk(cookie):
    risk = "Low"
    score = 0
    try:
        name = cookie.get("name", "").lower()
        if any(t in name for t in ["_ga", "_fbp", "_gcl", "_hj", "_ym", "_hstc", "hubspot"]):
            score += 3
            risk = "High"
        if cookie.get("domain", "").startswith("."):
            score += 2
        if not cookie.get("httponly"):
            score += 1
        if cookie.get("samesite", "none").lower() == "none":
            score += 1
        if score >= 5:
            risk = "High"
        elif score >= 3:
            risk = "Medium"
    except Exception:
        pass
    return risk, score

def detect_cookie_entropy(value):
    entropy = 0
    try:
        if not value:
            return 0
        freq = {}
        for ch in value:
            freq[ch] = freq.get(ch, 0) + 1
        for count in freq.values():
            p = count / len(value)
            if p > 0:
                entropy -= p * (p and __import__('math').log2(p))
    except Exception:
        pass
    return round(entropy, 2)

def analyze_expiration(expires, max_age):
    analysis = {}
    try:
        if max_age:
            ma = int(max_age) if max_age.isdigit() else 0
            if ma == 0:
                analysis["type"] = "Session (deleted on browser close)"
            elif ma < 3600:
                analysis["type"] = f"Short-lived ({ma}s)"
            elif ma < 86400:
                analysis["type"] = f"Daily ({ma//3600}h)"
            elif ma < 604800:
                analysis["type"] = f"Weekly ({ma//86400}d)"
            elif ma < 2592000:
                analysis["type"] = f"Monthly ({ma//86400}d)"
            else:
                analysis["type"] = f"Long-lived ({ma//86400}d)"
                analysis["risk"] = "Persistent tracking cookie"
        elif expires:
            analysis["type"] = f"Expires at: {expires[:30]}"
        else:
            analysis["type"] = "Session cookie (no expiry)"
    except Exception:
        pass
    return analysis
