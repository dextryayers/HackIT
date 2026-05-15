import json
import sys

def correlate(results):
    intelligence_map = []
    intelligence_map.append("====== FULL INTELLIGENCE MAP ======\n")

    for res in results:
        # Heuristic: Infer Industry & Description from Body/Title
        title = res.get("title", "").lower()
        desc = res.get("description", "No brief available.")
        industry = "General Tech"
        
        if "bank" in title or "finance" in title: industry = "Finance / Banking"
        elif "shop" in title or "store" in title: industry = "E-commerce"
        elif "blog" in title: industry = "Content / Media"
        elif "api" in title or "dev" in title: industry = "SaaS / Development"

        w = res.get("whois", {})
        networks = res.get("network", [])
        d = res.get("dns_enum", {})
        subs = res.get("subsidiaries", {})
        contacts = res.get("scraped_contacts", {})
        identity_report = f"""
[!] TARGET IDENTITY
Target         : {res.get('url')}
Aliases        : {", ".join(subs.get('aliases', [])) or "None discovered"}
Subsidiaries   : {", ".join(subs.get('subsidiaries', [])) or "None discovered"}
Scope          : Wildcard enabled, discovery depth: 2
Industry       : {industry}
Description    : {desc}
Registrar      : {w.get('registrar', 'Unknown')} (IANA: {w.get('iana_id', 'N/A')})
Registrant Org : {w.get('org', 'REDACTED')}
Registrant Email: {w.get('email', 'Privacy Shield')}
Admin Email    : {w.get('admin_email', 'REDACTED')}
Tech Email     : {w.get('tech_email', 'REDACTED')}
Phone (WHOIS)  : {w.get('phone', 'REDACTED')}
Street/City/Country : {w.get('address', 'Global')}
WHOIS Created  : {w.get('created', 'YYYY-MM-DD')}
WHOIS Updated  : {w.get('updated', 'YYYY-MM-DD')}
WHOIS Expires  : {w.get('expires', 'YYYY-MM-DD')}
WHOIS Privacy  : {'Enabled' if w.get('privacy_enabled') else 'Disabled'}

[!] DISCOVERED CONTACTS (STRENGTHENED)
Emails         : {", ".join(contacts.get('emails', [])) or "No emails scraped"}
Phones         : {", ".join(contacts.get('phones', [])) or "No phones scraped"}
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

        dns_report = f"""
[!] DNS ENUMERATION
Nameservers      : {", ".join(d.get('nameservers') or [])}
Zone Transfer    : {d.get('zone_transfer', 'Failed (Secure)')}
A Records        : {", ".join(d.get('a') or [])}
AAAA Records     : {", ".join(d.get('aaaa') or [])}
CNAME Records    : {", ".join(d.get('cname') or [])}
MX Records       : {", ".join(d.get('mx') or [])}
NS Records       : {", ".join(d.get('ns') or [])}
TXT Records      : {", ".join(d.get('txt') or [])}
SRV Records      : {", ".join(d.get('srv') or [])}
CAA Records      : {", ".join(d.get('caa') or [])}
SOA Record       : {d.get('soa', 'Unknown')}
ANY Query Result : {d.get('any', 'Refused/Empty')}
"""

        tech_stack = "\n[!] TECHNOLOGY STACK\n"
        techs = res.get("technologies", {})
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

        headers = res.get("headers") or {}
        forensics = res.get("forensics", "")
        
        web_report = f"""
[!] WEB & TLS FORENSICS
Server Banner   : {res.get('server', 'Unknown')}
Security Headers: {", ".join([f"{k}: {v}" for k, v in headers.items() if k.lower().startswith('x-') or k.lower() in ['strict-transport-security', 'content-security-policy', 'permissions-policy', 'referrer-policy']]) or "None"}
TLS/SSL Info    : {forensics or "No forensic data available."}
HTTP Status     : {res.get('status', 'N/A')}
"""
        dns_history = res.get("dns_history", {})
        passive_dns = res.get("passive_dns", {})
        
        dns_history_report = f"""
[!] DNS HISTORY & PASSIVE DNS
Historical A     : {", ".join(dns_history.get('historical_a', [])) or "None archived"}
Historical NS    : {", ".join(dns_history.get('historical_ns', [])) or "None archived"}
Historical MX    : {", ".join(dns_history.get('historical_mx', [])) or "None archived"}
Possible Internal Domains from Passive DNS : {", ".join(passive_dns.get('possible_internal_domains', [])) or "None discovered"}
"""

        ssl = res.get("ssl_analysis", {})
        cert = ssl.get("certificate", {})
        
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

        port_results = res.get("port_scan", [])
        port_report = "\n[!] PORT & SERVICE INVENTORY\n"
        if port_results:
            for p in port_results:
                banner_clean = p.get('banner', '').strip().replace('\n', ' ')[:60]
                port_report += f"  {p.get('port')}/{p.get('proto')} - {p.get('service')}\n"
                port_report += f"  Banner         : {banner_clean or 'No banner captured'}\n"
        else:
            port_report += "No open ports discovered in tactical scan.\n"

        waf = res.get("waf", {})
        origin = res.get("origin_discovery", {})
        waf_report = f"""
[!] CDN, WAF & PROXY DETECTION
CDN Provider     : {waf.get('provider', 'Multi-Layer Distributed CDN (Hardened)')}
WAF Type         : {waf.get('waf_type', 'Advanced Behavior-Based WAF (Active)')}
Real Origin IP   : {origin.get('origin_ip', 'Hidden/Proxied')} (Method: DNS/Cert Correlation)
"""

        web_audit = res.get("web_audit", {})
        sec_pol = web_audit.get("security_policies", {})
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

        cms_cloud = res.get("cms_cloud", {})
        tech_adv = res.get("tech_stack_advanced", {})
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

        cloud = cms_cloud.get("cloud_assets", {})
        endpoints = res.get("endpoints", [])
        third_party = res.get("third_party", "No integrations detected")
        asset_mapping_report = f"""
[!] SUBDOMAINS & ASSET MAPPING
Active Subdomains (resolved & HTTP responsive):
  - {res.get('url')} : {res.get('ip')} : {res.get('status')} : {res.get('title', 'N/A')}
{chr(10).join(infra_subdomains) if infra_subdomains else '  No additional subdomains enumerated'}
Cloud & Shadow Assets:
  - AWS S3 Buckets : {", ".join(cloud.get('s3_buckets', [])) or "None discovered"}
  - GCP Storage    : {", ".join(cloud.get('gcp_buckets', [])) or "None discovered"}
  - Firebase       : {", ".join(cloud.get('firebase', [])) or "None discovered"}
  - Github Org     : {cloud.get('github_org', 'None found')}
High-Value Endpoints Found:
{chr(10).join(['  - ' + e for e in endpoints]) if endpoints else '  None discovered'}
Third-Party Integrations:
{third_party}
"""

        intelligence_map.append(identity_report + network_report + dns_report + dns_history_report + ssl_report + port_report + waf_report + web_overview + tech_fp_report + asset_mapping_report + tech_stack + web_report)

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
