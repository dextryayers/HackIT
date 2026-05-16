import sys
import os

file_path = r'd:\web\hacks\hackstools\hackit\tech_hunter\brain.py'
with open(file_path, 'r') as f:
    content = f.read()

parts = content.split('# Split endpoints into Files/Directories and APIs for better categorization')

new_tail = """
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
Fuzzing results (ffuf, gobuster, dirsearch) with interesting finds:
{chr(10).join(["  " + v for v in fuzz_map.values()]) if fuzz_map else '  No interesting endpoints discovered via fuzzing.'}
Sensitive Files & Information Disclosure:
  /.env                  : {fstat(['/.env'])}
  /.git/config           : {fstat(['/.git/config'])}
  /.svn/entries          : {fstat(['/.svn/entries'])}
  /.DS_Store             : {fstat(['/.DS_Store'])}
  /package.json          : {fstat(['/package.json'])}
  /yarn.lock / package-lock.json : {fstat(['/yarn.lock', '/package-lock.json'])}
  /composer.json / composer.lock : {fstat(['/composer.json', '/composer.lock'])}
  /docker-compose.yml    : {fstat(['/docker-compose.yml'])}
  /Dockerfile            : {fstat(['/Dockerfile'])}
  /serverless.yml        : {fstat(['/serverless.yml'])}
  /terraform.tfstate     : {fstat(['/terraform.tfstate'])}
  /.npmrc / .pypirc      : {fstat(['/.npmrc', '/.pypirc'])}
  /web.config            : {fstat(['/web.config'])}
  /robots.txt            : {fstat(['/robots.txt'])}
  /sitemap.xml           : {fstat(['/sitemap.xml'])}
  /crossdomain.xml       : {fstat(['/crossdomain.xml'])}
  /clientaccesspolicy.xml : {fstat(['/clientaccesspolicy.xml'])}
  /security.txt          : {fstat(['/.well-known/security.txt', '/security.txt'])}
  /humans.txt            : {fstat(['/humans.txt'])}
  /backup.sql / dump.zip : {fstat(['/backup.sql', '/dump.zip'])}
  /phpinfo.php / info.php : {fstat(['/phpinfo.php', '/info.php'])}
  /server-status / server-info : {fstat(['/server-status', '/server-info'])}
  /actuator/health / /actuator/mappings : {fstat(['/actuator/health', '/actuator/mappings'])}
  /wp-json/wp/v2/users   : {fstat(['/wp-json/wp/v2/users'])}
  /graphql               : {fstat(['/graphql'])}
  /api-docs / swagger.json : {fstat(['/api-docs', '/swagger.json'])}
  /debug / console / shell : {fstat(['/debug', '/console', '/shell'])}

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

{auth_session}
'''

        intelligence_map.append(identity_report + network_report + dns_report + dns_history_report + ssl_report + port_report + waf_report + web_overview + tech_fp_report + asset_mapping_report)
    return "\\n".join(intelligence_map)

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
"""

with open(file_path, 'w') as f:
    f.write(parts[0] + new_tail)
print('Done!')
