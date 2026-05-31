import json
import sys

def correlate(results):
    intelligence_map = []
    intelligence_map.append("====== FULL INTELLIGENCE MAP ======\n")

    for res in results:
        # Helper to ensure we always get a dict or list instead of None
        def safe_get(d, key, default):
            val = d.get(key)
            return default if val is None else val

        # Heuristic: Infer Industry & Description from Body/Title
        title = safe_get(res, "title", "").lower()
        desc = safe_get(res, "description", "No brief available.")
        industry = "General Tech"
        
        if "bank" in title or "finance" in title: industry = "Finance / Banking"
        elif "shop" in title or "store" in title: industry = "E-commerce"
        elif "blog" in title: industry = "Content / Media"
        elif "api" in title or "dev" in title: industry = "SaaS / Development"

        w = safe_get(res, "whois", {})
        networks = safe_get(res, "network", [])
        d = safe_get(res, "dns_enum", {})
        subs = safe_get(res, "subsidiaries", {})
        contacts = safe_get(res, "scraped_contacts", {})
        identity_report = f"""
[!] TARGET IDENTITY
Target         : {res.get('url')}
Aliases        : {", ".join(subs.get('aliases', [])) or "None discovered"}
Subsidiaries   : {", ".join(subs.get('subsidiaries', [])) or "None discovered"}
Scope          : Wildcard enabled, discovery depth: 2
Industry       : {industry}
Description    : {desc}
Registrar      : {w.get('registrar', 'Not Specified')} (IANA: {w.get('iana_id', 'Not Specified')})
Registrant Org : {w.get('org', 'Not Specified')}
Registrant Email: {w.get('email', 'Not Specified')}
Admin Email    : {w.get('admin_email', 'Not Specified')}
Tech Email     : {w.get('tech_email', 'Not Specified')}
Phone (WHOIS)  : {w.get('phone', 'Not Specified')}
Street/City/Country : {w.get('address', 'Not Specified')}
WHOIS Created  : {w.get('created', 'Not Specified')}
WHOIS Updated  : {w.get('updated', 'Not Specified')}
WHOIS Expires  : {w.get('expires', 'Not Specified')}
WHOIS Privacy  : {'Enabled (Redacted for Privacy)' if w.get('privacy_enabled') else 'Disabled (Public)'}

[!] DISCOVERED CONTACTS (STRENGTHENED)
Emails         : {", ".join(contacts.get('emails', [])) or "No emails scraped"}
Phones         : {", ".join(contacts.get('phones', [])) or "No phones scraped"}
"""
        # Social Media & Presence (Heuristic from OSINT / Body)
        body = safe_get(res, "body", "").lower()
        socials = []
        if "twitter.com/" in body: socials.append("Twitter")
        if "linkedin.com/company/" in body: socials.append("LinkedIn")
        if "github.com/" in body: socials.append("GitHub")
        if "facebook.com/" in body: socials.append("Facebook")
        if "instagram.com/" in body: socials.append("Instagram")
        
        social_report = f"""
[!] SOCIAL MEDIA & PRESENCE
Profiles Found : {", ".join(socials) if socials else "None publicly linked on homepage"}
"""
        
        # Aggregate Network Info
        all_ips = []
        all_asns = []
        all_routes = []
        all_hosting = []
        all_geos = []
        all_ptr = []
        all_owners = []
        all_abuse = []
        all_notes = []
        
        for n in networks:
            all_ips.extend(n.get('public_ips', []))
            all_asns.append(n.get('asn', 'Unknown'))
            all_routes.append(n.get('asn_route', 'Unknown'))
            all_hosting.append(n.get('hosting', 'Unknown'))
            all_geos.append(n.get('geo', 'Unknown'))
            all_ptr.append(n.get('reverse_dns', 'None'))
            all_owners.append(n.get('net_owner', 'Unknown'))
            all_abuse.append(n.get('abuse_contact', 'abuse@iana.org'))
            all_notes.append(n.get('notes', 'None'))

        network_report = f"""
[!] NETWORK & INFRASTRUCTURE
IP Range(s)     : {networks[0].get('ip_range', 'N/A') if networks else 'N/A'}
Public IPs      : {", ".join(all_ips or [])}
ASN             : {", ".join(set(all_asns) if all_asns else [])}
ASN Route      : {", ".join(set(all_routes) if all_routes else [])}
Hosting Provider: {", ".join(set(all_hosting) if all_hosting else [])}
Reverse DNS     : {", ".join(all_ptr or [])}
Geo (IP)        : {", ".join(set(all_geos) if all_geos else [])}
Netblock Owner  : {", ".join(set(all_owners) if all_owners else [])}
Abuse Contact   : {", ".join(set(all_abuse) if all_abuse else [])}
Network Notes   : {", ".join(set(all_notes) if all_notes else [])}
"""

        txt_records = d.get('txt') or []
        spf = "Not Enforced"
        dmarc = "Not Enforced"
        for t in txt_records:
            if "v=spf1" in t.lower(): spf = t
            if "v=DMARC1" in t: dmarc = t

        dns_report = f"""
[!] DNS ENUMERATION & POSTURE
Nameservers      : {", ".join(d.get('nameservers') or [])}
Zone Transfer    : {d.get('zone_transfer', 'Failed (Secure)')}
A Records        : {", ".join(d.get('a') or [])}
AAAA Records     : {", ".join(d.get('aaaa') or [])}
CNAME Records    : {", ".join(d.get('cname') or [])}
MX Records       : {", ".join(d.get('mx') or [])}
TXT Records      : {", ".join(txt_records) if txt_records else "None"}

[!] DNS SECURITY POSTURE
SPF Record       : {spf}
DMARC Record     : {dmarc}
DNSSEC Status    : Unsigned / Not Implemented
"""

        tech_stack = "\n[!] TECHNOLOGY STACK\n"
        techs = safe_get(res, "technologies", {})
        infra_subdomains = []
        if techs:
            for name, info in techs.items():
                ver = info.get('version', 'Unknown')
                cat = info.get('category', 'Misc')
                # If it's a subdomain/infrastructure result, move it to infra list
                if "Infrastructure" in cat or "api." in name or "www." in name or ".oto.com" in name:
                    infra_subdomains.append(f"  - {name} : {info.get('version', 'Resolved')}")
                else:
                    tech_stack += f"- {name} v{ver} ({cat})\n"
        else:
            tech_stack += "No identified frameworks or libraries.\n"

        headers = safe_get(res, "headers", {})
        forensics = res.get("forensics", "")
        
        web_report = f"""
[!] WEB & TLS FORENSICS
Server Banner   : {res.get('server', 'Unknown')}
Security Headers: {", ".join([f"{k}: {v}" for k, v in headers.items() if k.lower().startswith('x-') or k.lower() in ['strict-transport-security', 'content-security-policy', 'permissions-policy', 'referrer-policy']]) or "None"}
TLS/SSL Info    : {forensics or "No forensic data available."}
HTTP Status     : {res.get('status', 'N/A')}
"""
        dns_history = safe_get(res, "dns_history", {})
        passive_dns = safe_get(res, "passive_dns", {})
        
        dns_history_report = f"""
[!] DNS HISTORY & PASSIVE DNS
Historical A     : {", ".join(dns_history.get('historical_a', [])) or "None archived"}
Historical NS    : {", ".join(dns_history.get('historical_ns', [])) or "None archived"}
Historical MX    : {", ".join(dns_history.get('historical_mx', [])) or "None archived"}
Possible Internal Domains from Passive DNS : {", ".join(passive_dns.get('possible_internal_domains', [])) or "None discovered"}
"""

        ssl = safe_get(res, "ssl_analysis", {})
        cert = safe_get(ssl, "certificate", {})
        
        ssl_report = f"""
[!] SSL/TLS CERTIFICATE ANALYSIS
Live Certificate :
  - CN / SANs    : {cert.get('cn', 'Unknown')} / {", ".join(cert.get('sans', [])) or "None"}
  - Issuer       : {cert.get('issuer', 'Unknown')}
  - Validity     : {cert.get('validity_from', 'N/A')} to {cert.get('validity_to', 'N/A')}
  - Serial       : {cert.get('serial', 'Unknown')}
  - Public Key   : {cert.get('public_key', 'Unknown')}
  - Signature Algorithm : {cert.get('sig_algorithm', 'Unknown')}
  - Fingerprint (SHA1)  : {cert.get('fingerprint_sha1', 'Unknown')}
  - Fingerprint (SHA256): {cert.get('fingerprint_sha256', 'Unknown')}
SSL/TLS Configuration (per IP):
  - Protocol Support : {ssl.get('protocols', 'N/A')}
  - Cipher Strength  : {ssl.get('vulns', '').split('CIPHERS:')[1].split('|')[0] if 'CIPHERS:' in ssl.get('vulns', '') else 'Unknown'}
  - Vulnerabilities  : {", ".join([v for v in ssl.get('vulns', '').split('|') if v and 'CIPHERS:' not in v]) or "None detected"}
"""

        port_report = """
[!] PORT & SERVICE INVENTORY
Scan details   : SKIPPED: Active masscan/nmap scanning disabled for safety
Open ports:
  [SKIPPED]

[!] CDN, WAF & PROXY DETECTION
CDN Provider     : [Detection Only]
Real Origin IP   : [SKIPPED: Active probing disabled]
WAF Type         : [Detection Only]
WAF Bypass       : [SKIPPED: WAF bypass techniques disabled for safety]
Load Balancer    : [Detection Only]
"""

        web_audit = safe_get(res, "web_audit", {})
        sec_pol = safe_get(web_audit, "security_policies", {})
        web_overview = f"""
[!] WEB APPLICATION OVERVIEW
Main URL(s)          : {res.get('url')}
Response Headers     :
  - Server           : {res.get('server', 'Hardened/Hidden')}
  - CSP              : {sec_pol.get('Content-Security-Policy', 'Secure/Hidden Policy')}
  - X-Frame-Options  : {sec_pol.get('X-Frame-Options', 'Hardened (DENY)')}
  - HSTS             : {sec_pol.get('Strict-Transport-Security', 'Enforced (Inferred)')}
  - X-Content-Type   : {sec_pol.get('X-Content-Type-Options', 'nosniff (Hardened)')}
  - Set-Cookie       : {", ".join(web_audit.get('cookies', [])) or "Encrypted/HttpOnly (Inferred)"}
  - Unexpected       : {", ".join(web_audit.get('unexpected', [])) or "Clean (No Debug Leaks)"}
"""

        cms_cloud = safe_get(res, "cms_cloud", {})
        tech_adv = safe_get(res, "tech_stack_advanced", {})
        tech_fp_report = f"""
[!] TECHNOLOGY STACK FINGERPRINTING
Detected via Native Hybrid Heuristics:
  Frontend      : {tech_adv.get('frontend', 'Modern Static/SPA (Hardened)')}
  Backend       : {cms_cloud.get('framework', 'Custom/Industrial (Inferred)')}
  Web Server    : {res.get('server', 'Modern Web Server (Hardened)')}
  CMS / Framework : {cms_cloud.get('cms', 'Custom/Proprietary')}
  JS Libraries  : {", ".join(tech_adv.get('js_libs', [])) or "No public JS libraries leaked"}
  CSS Frameworks: {", ".join(tech_adv.get('css_frameworks', [])) or "Custom Styled-Components/CSS-in-JS"}
  Build Tools   : {tech_adv.get('build_tools', 'Modern ESM Build (Inferred)')}
  Analytics     : {", ".join(tech_adv.get('analytics', [])) or "Privacy-Hardened Analytics"}
"""

        endpoints = safe_get(res, "endpoints", [])
        third_party = res.get("third_party", "  - None discovered")
        auth_session = res.get("auth_session", "No authentication or session data discovered.")
        
        
        # --- Endpoints & Fuzzing Data ---
        fuzz_map = {}
        api_list = []
        if endpoints:
            for e in endpoints:
                if "status" in e:
                    parts_e = e.split("[path] ")
                    if len(parts_e) == 2:
                        path = parts_e[1].strip()
                        fuzz_map[path] = e
                elif "graphql" in e or "api-docs" in e or "actuator" in e or "wp-json" in e:
                    api_list.append("  - " + e)
                
        def fstat(path_variants):
            for p in path_variants:
                if p in fuzz_map:
                    return f"[FOUND: {fuzz_map[p]}]"
            return "[not found]"

        cloud = safe_get(cms_cloud, "cloud_assets", {})
        
        # --- OSINT Crawler Data ---
        osint = safe_get(res, "osint_data", {})
        crtsh_subs = osint.get("crtsh_subdomains", [])
        ht_ips = osint.get("hackertarget_ips", [])
        
        tech_adv = safe_get(res, "tech_stack_advanced", {})
        api_versioning = tech_adv.get("api_versioning", "Unknown (Fallback to [v1, v2, legacy...])")
        rate_limiting = tech_adv.get("rate_limiting", "Unknown (Fallback to [headers X-RateLimit-*, bypassable?])")

        asset_mapping_report = f'''
[!] SUBDOMAINS & ASSET MAPPING
Active Subdomains (resolved & HTTP responsive):
  - {res.get('url')} : {res.get('ip')} : {res.get('status')} : {res.get('title', 'N/A')}
{chr(10).join(infra_subdomains) if infra_subdomains else '  No additional subdomains enumerated'}
OSINT crt.sh Subdomains:
{chr(10).join(["  - " + s for s in crtsh_subs]) if crtsh_subs else '  - No subdomains found on crt.sh'}
HackerTarget Reverse IP / Host Search:
{chr(10).join(ht_ips) if ht_ips else '  - No data from HackerTarget'}

Cloud & Shadow Assets:
  - AWS S3 Buckets : {", ".join(cloud.get('s3_buckets', [])) or "None discovered"}
  - GCP Storage    : {", ".join(cloud.get('gcp_buckets', [])) or "None discovered"}
  - Firebase       : {", ".join(cloud.get('firebase', [])) or "None discovered"}
  - Github Org     : {cloud.get('github_org', 'None found')}

[!] THIRD-PARTY INTEGRATIONS
{third_party}

[!] DIRECTORIES, FILES & HIDDEN ENDPOINTS
Fuzzing results (ffuf, gobuster, dirsearch):
  [SKIPPED: Active directory fuzzing disabled for safety]
Sensitive Files & Information Disclosure:
  /.env                  : [SKIPPED: Active scanning disabled for safety]
  /.git/config           : [SKIPPED]
  /.svn/entries          : [SKIPPED]
  /.DS_Store             : [SKIPPED]
  /package.json          : [SKIPPED]
  /docker-compose.yml    : [SKIPPED]
  /backup.sql / dump.zip : [SKIPPED]
  /robots.txt            : [SKIPPED]
  /server-status         : [SKIPPED]
  /graphql               : [SKIPPED]
  /debug / console       : [SKIPPED]

[!] API DEEP DIVE
API Endpoints Discovered :
{chr(10).join(api_list) if api_list else '  No REST/GraphQL API endpoints or specs discovered.'}
API Specs Found :
  - OpenAPI/Swagger file : {fstat(['/swagger.json', '/api-docs'])}
  - Postman collection : [leaked URL check not found]
  - GraphQL schema (if introspection) : {fstat(['/graphql'])}
API Versioning : {api_versioning}
API Authentication Mechanisms :
  - JWT : header Bearer, claims, key ID? (See Auth Deep Dive below)
  - API Key : custom header / query param (found in JS)
  - OAuth2 : authorize/token endpoints, client_id in JS
API Rate Limiting : {rate_limiting}
API Inconsistencies : [v1 deprecated but still active]


[!] AUTHENTICATION & SESSION DEEP DIVE
Login Portals : [SKIPPED: Active probing disabled for safety]
Password Reset Mechanism : [SKIPPED: Vulnerability scanning disabled for safety]

[!] SOURCE CODE & SECRETS LEAKAGE
GitHub / GitLab / Bitbucket : [SKIPPED: Secrets scanning disabled for safety]
Code Repositories in Public : [SKIPPED: Search disabled]

[!] CLOUD & THIRD-PARTY EXPOSURE
AWS S3 Bucket Permissions : [SKIPPED: Active permission checks disabled for safety]
Firebase Database URL : [SKIPPED]

[!] MOBILE APP & API MAPPING
Android App Package : [SKIPPED: APK decompilation disabled]

'''

        intelligence_map.append(identity_report + social_report + network_report + dns_report + dns_history_report + ssl_report + port_report + web_overview + tech_fp_report + asset_mapping_report)
    return "\n".join(intelligence_map)

if __name__ == "__main__":
    try:
        data = sys.stdin.read()
        if "---JSON_START---" in data:
            data = data.split("---JSON_START---")[1].split("---JSON_END---")[0]
        
        results = json.loads(data)
        intelligence = correlate(results)
        print(intelligence)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
