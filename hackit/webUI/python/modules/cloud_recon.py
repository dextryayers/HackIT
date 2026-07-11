import httpx
import asyncio
import re
from module_common import safe_fetch, safe_fetch_json, make_finding, resolve_ip

CDN_DETECTION = {
    "cloudflare": {"name": "Cloudflare", "headers": ["cf-ray", "cf-cache-status", "cf-connecting-ip"], "color": "orange"},
    "cloudfront": {"name": "AWS CloudFront", "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-cf-ip"], "color": "orange"},
    "akamai": {"name": "Akamai", "headers": ["x-akamai-transformed", "x-akamai-request-id"], "color": "orange"},
    "fastly": {"name": "Fastly", "headers": ["x-fastly-request-id", "x-served-by", "x-cache-hits"], "color": "orange"},
    "incapsula": {"name": "Incapsula", "headers": ["x-request-id", "x-cdn", "x-iinfo"], "color": "orange"},
    "sucuri": {"name": "Sucuri", "headers": ["x-sucuri-id", "x-sucuri-cache"], "color": "orange"},
    "stackpath": {"name": "StackPath", "headers": ["x-stackpath-id"], "color": "orange"},
    "keycdn": {"name": "KeyCDN", "headers": ["x-keycdn"], "color": "orange"},
    "bunnycdn": {"name": "BunnyCDN", "headers": ["x-bunnycdn"], "color": "orange"},
    "cachefly": {"name": "CacheFly", "headers": ["x-cachefly"], "color": "orange"},
    "section": {"name": "Section.io", "headers": ["x-section"], "color": "orange"},
    "belugacdn": {"name": "BelugaCDN", "headers": ["x-belugacdn"], "color": "orange"},
    "vercel": {"name": "Vercel", "headers": ["x-vercel-id"], "color": "orange"},
    "netlify": {"name": "Netlify", "headers": ["x-nf-request-id", "x-ns-server"], "color": "orange"},
    "render": {"name": "Render", "headers": ["x-render-origin-server"], "color": "orange"},
    "heroku": {"name": "Heroku", "headers": ["x-heroku-queue-wait-time", "x-heroku-dynos-in-use"], "color": "orange"},
}

CDN_SINGLE_HEADER_CHECKS = [
    ("x-cache", "Generic CDN (x-cache)"),
    ("x-iinfo", "Incapsula"),
    ("x-sucuri-cache", "Sucuri"),
    ("x-ns-server", "Netlify"),
    ("x-vercel-id", "Vercel"),
    ("x-render-origin-server", "Render"),
    ("x-heroku-queue-wait-time", "Heroku"),
]

CDN_COOKIE_CHECKS = [
    ("__cfduid", "Cloudflare"),
    ("_csrf", "Netlify"),
    ("heroku-session-", "Heroku"),
]

PAAS_PLATFORMS = {
    "herokuapp.com": "Heroku",
    "heroku.com": "Heroku",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "onrender.com": "Render",
    "railway.app": "Railway",
    "fly.dev": "Fly.io",
    "fly.io": "Fly.io",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "r2.dev": "Cloudflare R2",
    "azurewebsites.net": "Azure App Service",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure Front Door",
    "trafficmanager.net": "Azure Traffic Manager",
    "azure-api.net": "Azure API Management",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "amazonaws.com": "AWS",
    "compute.amazonaws.com": "AWS EC2",
    "rds.amazonaws.com": "AWS RDS",
    "elb.amazonaws.com": "AWS ELB",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "api-gateway.amazonaws.com": "AWS API Gateway",
    "execute-api": "AWS API Gateway",
    "lambda-url": "AWS Lambda",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase Hosting",
    "firebaseio.com": "Firebase Realtime DB",
    "appspot.com": "Google App Engine",
    "withgoogle.com": "Google Cloud",
    "cloudfunctions.net": "Google Cloud Functions",
    "run.app": "Google Cloud Run",
    "appengine.google.com": "Google App Engine",
    "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "digitalocean.com": "DigitalOcean",
    "ovhcloud.com": "OVHcloud",
    "hetzner.com": "Hetzner",
    "hetzner.cloud": "Hetzner Cloud",
    "linode.com": "Linode",
    "linodeobjects.com": "Linode Object Storage",
    "vultr.com": "Vultr",
    "vultrobjects.com": "Vultr Object Storage",
    "scw.cloud": "Scaleway",
    "scaleway.com": "Scaleway",
    "exoscale.com": "Exoscale",
    "upcloud.com": "UpCloud",
    "phoenixnap.com": "PhoenixNAP",
    "ionos.com": "IONOS",
    "contabo.com": "Contabo",
    "deno.dev": "Deno Deploy",
    "glitch.me": "Glitch",
    "repl.co": "Replit",
    "codepen.io": "CodePen",
    "surge.sh": "Surge",
    "neocities.org": "Neocities",
    "tiiny.host": "Tiiny.host",
    "cyclic.app": "Cyclic",
    "adaptable.app": "Adaptable",
    "koyeb.app": "Koyeb",
    "alwaysdata.net": "AlwaysData",
    "pythonanywhere.com": "PythonAnywhere",
    "eu.pythonanywhere.com": "PythonAnywhere",
    "openshiftapps.com": "OpenShift",
    "bluemix.net": "IBM Cloud",
    "cfapps.io": "Cloud Foundry (Pivotal)",
    "pws.pivotal.io": "Pivotal Web Services",
    "sapcloud.io": "SAP Cloud",
    "alibabacloud.com": "Alibaba Cloud",
    "computenest.aliyuncs.com": "Alibaba Compute",
    "oraclecloud.com": "Oracle Cloud",
    "oci.oraclecloud.com": "Oracle OCI",
    "tencentcloud.com": "Tencent Cloud",
    "qcloud.com": "Tencent Cloud",
    "ucloud.cn": "UCloud",
    "nhost.run": "Nhost",
    "nhost.app": "Nhost",
    "supabase.co": "Supabase",
    "supabase.in": "Supabase",
    "fly.dev": "Fly.io Apps",
    "edgecompute.app": "EdgeCompute",
    "wasmer.app": "Wasmer",
    "fleek.co": "Fleek",
    "ipfs.io": "IPFS",
    "infura.io": "Infura",
    "alchemy.com": "Alchemy",
    "quicknode.com": "QuickNode",
    "moralis.io": "Moralis",
    "thirdweb.com": "Thirdweb",
    "storj.io": "Storj",
    "filebase.com": "Filebase",
    "4everland.io": "4Everland",
    "akash.network": "Akash Network",
    "spheron.network": "Spheron",
    "lighthouse.storage": "Lighthouse Storage",
    "pinata.cloud": "Pinata IPFS",
    "nftstorage.link": "NFT.Storage",
    "web3.storage": "Web3.Storage",
    "bunnycdn.com": "Bunny CDN",
    "bunny.net": "Bunny CDN",
    "belugacdn.com": "BelugaCDN",
    "cachefly.com": "CacheFly",
    "section.io": "Section.io",
    "gcore.com": "G-Core CDN",
    "gcdn.co": "G-Core CDN",
    "edgecastcdn.net": "Edgecast CDN",
    "llnw.net": "Limelight CDN",
    "level3.com": "Level 3 CDN",
    "internap.com": "Internap CDN",
    "swiftcdn.com": "SwiftCDN",
    "bitgravity.com": "BitGravity CDN",
    "highwinds.com": "Highwinds CDN",
    "stackpath.com": "StackPath",
    "stackpathdns.com": "StackPath DNS",
}

CLOUD_SERVER_HEADERS = {
    "cloudflare": "Cloudflare",
    "akamai": "AkamaiGHost",
    "cloudfront": "Amazon CloudFront",
    "amazons3": "Amazon S3",
    "AmazonS3": "Amazon S3",
    "amazon": "AWS",
    "Apache": "Standard Web Server",
    "nginx/": "Standard Web Server",
    "gunicorn": "Standard Web Server",
    "ECS": "AWS ECS",
    "gws": "Google Web Server",
    "gfe": "Google Front End",
    "Google Cloud": "Google Cloud",
    "azure": "Microsoft Azure",
    "Kestrel": "Microsoft ASP.NET Core",
    "IIS": "Microsoft IIS",
    "openresty": "OpenResty",
    "Cowboy": "Cowboy (Erlang/Elixir)",
    "Play": "Play Framework",
    "Jetty": "Eclipse Jetty",
    "Tomcat": "Apache Tomcat",
    "Netlify": "Netlify",
    "Vercel": "Vercel",
    "deno": "Deno Deploy",
}

CLOUD_INDICATORS_HTML = [
    (r"cloudflare", "Cloudflare"),
    (r"cdn-cgi", "Cloudflare"),
    (r"akamai", "Akamai"),
    (r"fastly", "Fastly"),
    (r"netlify", "Netlify"),
    (r"vercel", "Vercel"),
    (r"heroku", "Heroku"),
    (r"digitalocean", "DigitalOcean"),
    (r"linode", "Linode"),
    (r"vultr", "Vultr"),
    (r"ovh", "OVH"),
    (r"hetzner", "Hetzner"),
    (r"amazonaws", "AWS"),
    (r"s3\b", "AWS S3"),
    (r"cloudfront", "CloudFront"),
    (r"azure", "Azure"),
    (r"azureedge", "Azure"),
    (r"firebase", "Firebase"),
    (r"googleapis", "Google Cloud"),
    (r"gstatic", "Google Cloud"),
    (r"googlecloud", "Google Cloud"),
    (r"render\.com", "Render"),
    (r"fly\.io", "Fly.io"),
    (r"railway", "Railway"),
    (r"koyeb", "Koyeb"),
    (r"cyclic", "Cyclic"),
    (r"deno", "Deno Deploy"),
    (r"shopify", "Shopify"),
    (r"myshopify", "Shopify"),
    (r"squarespace", "Squarespace"),
    (r"wix", "Wix"),
    (r"weebly", "Weebly"),
    (r"wordpress", "WordPress"),
    (r"blogspot", "Blogger (Google)"),
    (r"tumblr", "Tumblr"),
    (r"ghost", "Ghost"),
    (r"ghost\.io", "Ghost"),
    (r"incapsula", "Incapsula"),
    (r"sucuri", "Sucuri"),
    (r"newrelic", "New Relic"),
    (r"nr-data\.net", "New Relic"),
    (r"datadog", "Datadog"),
    (r"dd-trace", "Datadog"),
    (r"sentry", "Sentry"),
    (r"stripe", "Stripe"),
    (r"paypal", "PayPal"),
    (r"braintree", "Braintree"),
    (r"alibaba", "Alibaba Cloud"),
    (r"aliyuncs", "Alibaba Cloud"),
    (r"tencent", "Tencent Cloud"),
    (r"oraclecloud", "Oracle Cloud"),
    (r"ocp\.oracle", "Oracle Cloud"),
    (r"ibmcloud", "IBM Cloud"),
    (r"ibm\.com/cloud", "IBM Cloud"),
    (r"scaleway", "Scaleway"),
    (r"exoscale", "Exoscale"),
    (r"upcloud", "UpCloud"),
    (r"contabo", "Contabo"),
    (r"ionos", "IONOS"),
]

TECH_STACK_CMS = [
    (r"/wp-content/", "WordPress"),
    (r"/wp-includes/", "WordPress"),
    (r"wordpress", "WordPress"),
    (r"/sites/default/", "Drupal"),
    (r"drupal", "Drupal"),
    (r"Joomla", "Joomla"),
    (r"joomla", "Joomla"),
    (r"com_content", "Joomla"),
    (r"Shopify", "Shopify"),
    (r"shopify", "Shopify"),
    (r"myshopify\.com", "Shopify"),
    (r"Squarespace", "Squarespace"),
    (r"squarespace", "Squarespace"),
    (r"Wix", "Wix"),
    (r"wixstatic\.com", "Wix"),
    (r"ghost", "Ghost"),
    (r"ghost\-kit", "Ghost"),
    (r"HubSpot", "HubSpot"),
    (r"hubspot", "HubSpot"),
    (r"webflow", "Webflow"),
    (r"Webflow", "Webflow"),
    (r"strikingly", "Strikingly"),
    (r"weebly", "Weebly"),
]

TECH_STACK_JS = [
    (r"__NEXT_DATA__", "Next.js"),
    (r"next", "Next.js"),
    (r"next\.js", "Next.js"),
    (r"nuxt", "Nuxt.js"),
    (r"__NUXT__", "Nuxt.js"),
    (r"gatsby", "Gatsby"),
    (r"react", "React"),
    (r"react\.js", "React"),
    (r"React\.createElement", "React"),
    (r"reactRoot", "React"),
    (r"__REACT_DEVTOOLS", "React"),
    (r"vue", "Vue.js"),
    (r"Vue\.js", "Vue.js"),
    (r"__VUE__", "Vue.js"),
    (r"angular", "Angular"),
    (r"ng-version", "Angular"),
    (r"svelte", "Svelte"),
    (r"__svelte", "Svelte"),
    (r"jquery", "jQuery"),
    (r"alpinejs", "Alpine.js"),
    (r"Alpine\.js", "Alpine.js"),
    (r"htmx", "htmx"),
]

TECH_STACK_CSS = [
    (r"bootstrap", "Bootstrap"),
    (r"tailwind", "Tailwind CSS"),
    (r"bulma", "Bulma"),
    (r"foundation", "Foundation CSS"),
    (r"materialize", "Materialize CSS"),
    (r"material\.min\.css", "Material Design"),
    (r"semantic", "Semantic UI"),
    (r"uikit", "UIkit"),
    (r"purecss", "PureCSS"),
    (r"milligram", "Milligram"),
    (r"spectre", "Spectre CSS"),
]

TECH_STACK_ANALYTICS = [
    (r"google-analytics", "Google Analytics"),
    (r"googletagmanager", "Google Tag Manager"),
    (r"gtag", "Google Analytics 4"),
    (r"gtm\.js", "Google Tag Manager"),
    (r"facebook\.com/tr", "Facebook Pixel"),
    (r"fbq\(", "Facebook Pixel"),
    (r"hotjar", "Hotjar"),
    (r"clarity", "Microsoft Clarity"),
    (r"mixpanel", "Mixpanel"),
    (r"amplitude", "Amplitude"),
    (r"segment\.com", "Segment"),
    (r"analytics\.js", "Segment"),
]

async def _check_paas_cname(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'CNAME'))
            for r in answers:
                cname = str(r.target).rstrip('.').lower()
                for pattern, platform in PAAS_PLATFORMS.items():
                    if pattern in cname:
                        if not any(f.entity == platform and f.type == "PaaS Platform" for f in findings):
                            findings.append(make_finding(
                                entity=platform,
                                type="PaaS Platform",
                                source="CloudRecon",
                                confidence="High",
                                color="purple",
                                threat_level="Informational",
                                status="Detected",
                                resolution=cname,
                                raw_data=f"CNAME: {cname} to {platform}",
                                tags=["cloud", "paas", platform.lower().replace(" ", "-")]
                            ))
        except Exception:
            pass

        try:
            answers_a = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'A'))
            for r in answers_a:
                ip_str = str(r)
                for pattern, platform in PAAS_PLATFORMS.items():
                    if pattern in ip_str:
                        findings.append(make_finding(
                            entity=platform,
                            type="PaaS Platform (IP)",
                            source="CloudRecon",
                            confidence="Medium",
                            color="purple",
                            threat_level="Informational",
                            status="Suspected",
                            resolution=ip_str,
                            raw_data=f"IP {ip_str} associated with {platform}",
                            tags=["cloud", "paas"]
                        ))
        except Exception:
            pass

    except Exception:
        pass
    return findings


async def _check_ns_record(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'NS'))
        ns_providers = {
            "awsdns": "AWS Route53",
            "cloudflare": "Cloudflare DNS",
            "azure-dns": "Azure DNS",
            "azure.com": "Azure DNS",
            "googledomains": "Google Cloud DNS",
            "google": "Google Cloud DNS",
            "dns.google": "Google Cloud DNS",
            "nsone": "NS1",
            "ultradns": "UltraDNS",
            "akamai": "Akamai DNS",
            "dynect": "Oracle Dyn DNS",
            "dyn.com": "Oracle Dyn DNS",
            "dnsmadeeasy": "DNS Made Easy",
            "constellix": "Constellix",
            "dnspod": "DNSPod (Tencent)",
            "alidns": "Alibaba Cloud DNS",
            "hichina": "HiChina (Alibaba)",
            "namecheap": "Namecheap FreeDNS",
            "digitalocean": "DigitalOcean DNS",
            "dnsimple": "DNSimple",
            "registrar-servers.com": "Namecheap",
            "hostgator": "HostGator",
            "bluehost": "Bluehost",
        }
        for r in answers:
            ns = str(r).lower()
            for key, provider in ns_providers.items():
                if key in ns:
                    findings.append(make_finding(
                        entity=f"{provider} ({ns})",
                        type="DNS Nameserver Provider",
                        source="CloudRecon",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Detected",
                        resolution=ns,
                        raw_data=f"NS provider: {provider} via {ns}",
                        tags=["cloud", "dns", provider.lower().replace(" ", "-")]
                    ))
                    break
    except Exception:
        pass
    return findings


async def _check_mx_cloud(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        answers = await loop.run_in_executor(None, lambda: __import__('dns').resolver.resolve(target, 'MX'))
        mx_patterns = {
            "google": "Google Workspace",
            "googlemail": "Google Workspace",
            "outlook": "Microsoft 365",
            "protection.outlook": "Microsoft 365",
            "mail.protection": "Microsoft 365",
            "microsoft": "Microsoft 365",
            "protonmail": "ProtonMail",
            "protonmail.ch": "ProtonMail",
            "zoho": "Zoho Mail",
            "mailgun": "Mailgun",
            "sendgrid": "SendGrid",
            "sparkpost": "SparkPost",
            "yandex": "Yandex Mail",
            "mail.ru": "Mail.ru",
            "gmx": "GMX Mail",
            "icloud": "iCloud Mail",
            "fastmail": "Fastmail",
            "rackspace": "Rackspace Email",
            "exchange": "Microsoft Exchange",
            "mx.aliyun": "Alibaba Cloud Email",
            "mx.qcloud": "Tencent Cloud Email",
        }
        for r in answers:
            mx = str(r.exchange).lower()
            for key, provider in mx_patterns.items():
                if key in mx:
                    findings.append(make_finding(
                        entity=f"{provider} ({mx})",
                        type="Email Cloud Provider (MX)",
                        source="CloudRecon",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Detected",
                        resolution=mx,
                        raw_data=f"MX: {mx} -> {provider}",
                        tags=["cloud", "email", provider.lower().replace(" ", "-")]
                    ))
                    break
    except Exception:
        pass
    return findings


async def _check_tech_stack(html: str) -> list:
    findings = []
    tech_found = set()

    for pattern, name in TECH_STACK_CMS:
        if re.search(pattern, html, re.IGNORECASE) and name not in tech_found:
            tech_found.add(name)
            findings.append(make_finding(
                entity=name,
                type="CMS Detection",
                source="CloudRecon",
                confidence="Medium",
                color="green",
                threat_level="Informational",
                status="Detected",
                raw_data=f"CMS: {name} detected via HTML pattern",
                tags=["tech", "cms", name.lower().replace(" ", "-")]
            ))

    for pattern, name in TECH_STACK_JS:
        if re.search(pattern, html, re.IGNORECASE) and name not in tech_found:
            tech_found.add(name)
            findings.append(make_finding(
                entity=name,
                type="JS Framework",
                source="CloudRecon",
                confidence="Medium",
                color="green",
                threat_level="Informational",
                status="Detected",
                raw_data=f"JS Framework: {name} detected via HTML pattern",
                tags=["tech", "javascript", name.lower().replace(" ", "-")]
            ))

    for pattern, name in TECH_STACK_CSS:
        if re.search(pattern, html, re.IGNORECASE) and name not in tech_found:
            tech_found.add(name)
            findings.append(make_finding(
                entity=name,
                type="CSS Framework",
                source="CloudRecon",
                confidence="Medium",
                color="green",
                threat_level="Informational",
                status="Detected",
                raw_data=f"CSS Framework: {name} detected via HTML pattern",
                tags=["tech", "css", name.lower().replace(" ", "-")]
            ))

    for pattern, name in TECH_STACK_ANALYTICS:
        if re.search(pattern, html, re.IGNORECASE) and name not in tech_found:
            tech_found.add(name)
            findings.append(make_finding(
                entity=name,
                type="Analytics Service",
                source="CloudRecon",
                confidence="Medium",
                color="green",
                threat_level="Informational",
                status="Detected",
                raw_data=f"Analytics: {name} detected via HTML pattern",
                tags=["tech", "analytics", name.lower().replace(" ", "-")]
            ))

    return findings


async def _analyze_headers(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    base = f"https://{target}" if not target.startswith("http") else target
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = headers.get("server", "")
        via = headers.get("via", "")
        x_powered = headers.get("x-powered-by", "")

        for cdn_key, cdn_info in CDN_DETECTION.items():
            for h in cdn_info["headers"]:
                if h in headers:
                    findings.append(make_finding(
                        entity=cdn_info["name"],
                        type="CDN Service",
                        source="CloudRecon",
                        confidence="High",
                        color=cdn_info["color"],
                        threat_level="Informational",
                        status="Active",
                        raw_data=f"CDN: {cdn_info['name']} detected via {h} header",
                        tags=["cdn", cdn_key]
                    ))
                    break

        for header_name, cdn_name in CDN_SINGLE_HEADER_CHECKS:
            if header_name in headers:
                findings.append(make_finding(
                    entity=cdn_name,
                    type="CDN Service (Header)",
                    source="CloudRecon",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"CDN/Proxy: {cdn_name} detected via {header_name} header",
                    tags=["cdn", cdn_name.lower().replace(" ", "-").replace("(", "").replace(")", "")]
                ))

        raw_set_cookie = headers.get("set-cookie", "")
        for cookie_val, provider in CDN_COOKIE_CHECKS:
            if cookie_val in raw_set_cookie:
                findings.append(make_finding(
                    entity=provider,
                    type="CDN Service (Cookie)",
                    source="CloudRecon",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"CDN: {provider} detected via set-cookie {cookie_val}",
                    tags=["cdn", provider.lower().replace(" ", "-")]
                ))

        for sig, provider in CLOUD_SERVER_HEADERS.items():
            if sig.lower() in server.lower() or sig.lower() in via.lower():
                findings.append(make_finding(
                    entity=provider,
                    type="Cloud Infrastructure (Header)",
                    source="CloudRecon",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Server header: {server}, Via: {via}, Signature: {sig}",
                    tags=["cloud", provider.lower().replace(" ", "-")]
                ))
                break

        x_robots = headers.get("x-robots-tag", "")
        if "noindex" in x_robots.lower():
            findings.append(make_finding(
                entity="Cloudflare / Noindex",
                type="Cloud Technology (Header)",
                source="CloudRecon",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=f"x-robots-tag: {x_robots}",
                tags=["cloud", "cloudflare", "seo"]
            ))

        x_frame = headers.get("x-frame-options", "")
        if x_frame:
            findings.append(make_finding(
                entity=f"X-Frame-Options: {x_frame}",
                type="Security Header",
                source="CloudRecon",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                raw_data=f"x-frame-options: {x_frame}",
                tags=["security", "header"]
            ))

        if via:
            findings.append(make_finding(
                entity=f"Via: {via[:200]}",
                type="Cloud Infrastructure (Via Header)",
                source="CloudRecon",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=f"Via: {via}",
                tags=["cloud", "header"]
            ))

        if x_powered:
            if any(cloud in x_powered.lower() for cloud in ["aws", "azure", "google", "cloud", "heroku"]):
                findings.append(make_finding(
                    entity=f"X-Powered-By: {x_powered[:100]}",
                    type="Cloud Technology (Header)",
                    source="CloudRecon",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    raw_data=x_powered,
                    tags=["cloud", "tech"]
                ))

        html = resp.text[:100000].lower() if hasattr(resp, 'text') else ""
        for pattern, provider in CLOUD_INDICATORS_HTML:
            if re.search(pattern, html):
                findings.append(make_finding(
                    entity=provider,
                    type="Cloud Service (HTML Indicator)",
                    source="CloudRecon",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    status="Suspected",
                    raw_data=f"HTML pattern '{pattern}' found indicating {provider}",
                    tags=["cloud", provider.lower().replace(" ", "-")]
                ))

        tech_findings = await _check_tech_stack(html)
        findings.extend(tech_findings)

    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            type="Cloud Recon Error",
            source="CloudRecon",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))
    return findings


async def _check_ip_ranges(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        loop = asyncio.get_event_loop()
        try:
            import ipaddress
            ipaddress.ip_address(target)
            target_ip = target
        except ValueError:
            target_ip = await loop.run_in_executor(None, lambda: resolve_ip(target))

        cloud_ranges = [
            (("34.0.0.0", "34.255.255.255"), "Google Cloud", "GCP"),
            (("35.184.0.0", "35.255.255.255"), "Google Cloud", "GCP"),
            (("8.34.0.0", "8.35.255.255"), "Google Cloud", "GCP"),
            (("13.0.0.0", "13.255.255.255"), "AWS", "AWS"),
            (("15.0.0.0", "15.255.255.255"), "AWS", "AWS"),
            (("16.0.0.0", "16.255.255.255"), "AWS", "AWS"),
            (("18.0.0.0", "18.255.255.255"), "AWS", "AWS"),
            (("35.0.0.0", "35.183.255.255"), "AWS", "AWS"),
            (("44.192.0.0", "44.255.255.255"), "AWS", "AWS"),
            (("52.0.0.0", "52.255.255.255"), "AWS", "AWS"),
            (("54.0.0.0", "54.255.255.255"), "AWS", "AWS"),
            (("20.0.0.0", "20.255.255.255"), "Azure", "Azure"),
            (("40.64.0.0", "40.127.255.255"), "Azure", "Azure"),
            (("52.128.0.0", "52.255.255.255"), "Azure", "Azure"),
            (("65.52.0.0", "65.55.255.255"), "Azure", "Azure"),
            (("104.208.0.0", "104.215.255.255"), "Azure", "Azure"),
            (("137.116.0.0", "137.135.255.255"), "Azure", "Azure"),
            (("104.131.0.0", "104.131.255.255"), "DigitalOcean", "DO"),
            (("159.65.0.0", "159.65.255.255"), "DigitalOcean", "DO"),
            (("167.99.0.0", "167.99.255.255"), "DigitalOcean", "DO"),
            (("138.197.0.0", "138.197.255.255"), "DigitalOcean", "DO"),
            (("165.227.0.0", "165.227.255.255"), "DigitalOcean", "DO"),
            (("157.230.0.0", "157.230.255.255"), "DigitalOcean", "DO"),
            (("139.162.0.0", "139.162.255.255"), "Linode", "Linode"),
            (("172.104.0.0", "172.104.255.255"), "Linode", "Linode"),
            (("45.33.0.0", "45.33.255.255"), "Linode", "Linode"),
            (("45.56.0.0", "45.56.255.255"), "Linode", "Linode"),
            (("45.79.0.0", "45.79.255.255"), "Linode", "Linode"),
            (("45.33.0.0", "45.33.255.255"), "Linode", "Linode"),
            (("96.126.0.0", "96.126.255.255"), "Linode", "Linode"),
            (("45.32.0.0", "45.32.255.255"), "Vultr", "Vultr"),
            (("149.28.0.0", "149.28.255.255"), "Vultr", "Vultr"),
            (("108.61.0.0", "108.61.255.255"), "Vultr", "Vultr"),
            (("207.148.0.0", "207.148.255.255"), "Vultr", "Vultr"),
            (("209.222.0.0", "209.222.255.255"), "Vultr", "Vultr"),
            (("49.12.0.0", "49.12.255.255"), "Hetzner", "Hetzner"),
            (("78.46.0.0", "78.46.255.255"), "Hetzner", "Hetzner"),
            (("88.198.0.0", "88.198.255.255"), "Hetzner", "Hetzner"),
            (("95.216.0.0", "95.216.255.255"), "Hetzner", "Hetzner"),
            (("65.21.0.0", "65.21.255.255"), "Hetzner", "Hetzner"),
            (("116.202.0.0", "116.202.255.255"), "Hetzner", "Hetzner"),
            (("144.76.0.0", "144.76.255.255"), "Hetzner", "Hetzner"),
            (("129.146.0.0", "129.146.255.255"), "Oracle Cloud", "OCI"),
            (("140.91.0.0", "140.91.255.255"), "Oracle Cloud", "OCI"),
            (("150.136.0.0", "150.136.255.255"), "Oracle Cloud", "OCI"),
            (("193.122.0.0", "193.122.255.255"), "Oracle Cloud", "OCI"),
            (("192.29.0.0", "192.29.255.255"), "Oracle Cloud", "OCI"),
            (("203.0.113.0", "203.0.113.255"), "Oracle Cloud", "OCI"),
            (("47.0.0.0", "47.255.255.255"), "Alibaba Cloud", "Alibaba"),
            (("8.128.0.0", "8.191.255.255"), "Alibaba Cloud", "Alibaba"),
            (("106.14.0.0", "106.14.255.255"), "Alibaba Cloud", "Alibaba"),
            (("9.0.0.0", "9.255.255.255"), "Tencent Cloud", "Tencent"),
            (("49.0.0.0", "49.255.255.255"), "Tencent Cloud", "Tencent"),
            (("51.0.0.0", "51.255.255.255"), "OVHcloud", "OVH"),
            (("141.0.0.0", "141.255.255.255"), "OVHcloud", "OVH"),
            (("51.15.0.0", "51.15.255.255"), "Scaleway", "Scaleway"),
            (("212.47.0.0", "212.47.255.255"), "Scaleway", "Scaleway"),
            (("185.19.28.0", "185.19.31.255"), "Exoscale", "Exoscale"),
            (("217.160.0.0", "217.160.255.255"), "IONOS", "IONOS"),
            (("195.201.0.0", "195.201.255.255"), "Contabo", "Contabo"),
            (("95.216.0.0", "95.216.255.255"), "UpCloud", "UpCloud"),
            (("104.18.0.0", "104.18.255.255"), "Cloudflare", "Cloudflare"),
            (("172.64.0.0", "172.64.255.255"), "Cloudflare", "Cloudflare"),
            (("141.101.0.0", "141.101.255.255"), "Cloudflare", "Cloudflare"),
        ]

        def ip_to_int(ip_str):
            parts = ip_str.split(".")
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

        try:
            ip_int = ip_to_int(target_ip)
            for (start_str, end_str), provider, short in cloud_ranges:
                start_int = ip_to_int(start_str)
                end_int = ip_to_int(end_str)
                if start_int <= ip_int <= end_int:
                    findings.append(make_finding(
                        entity=f"{provider} (IP Range Match)",
                        type="Cloud Provider IP",
                        source="CloudRecon",
                        confidence="High",
                        color="orange",
                        threat_level="Informational",
                        status="Verified",
                        resolution=target_ip,
                        raw_data=f"IP {target_ip} falls in {provider} range {start_str}-{end_str}",
                        tags=["cloud", short.lower()]
                    ))
                    break
        except Exception:
            pass

    except Exception:
        pass
    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    if target.startswith("http"):
        from urllib.parse import urlparse
        target = urlparse(target).netloc

    cname_findings = await _check_paas_cname(target, client)
    findings.extend(cname_findings)

    ns_findings = await _check_ns_record(target, client)
    findings.extend(ns_findings)

    mx_findings = await _check_mx_cloud(target, client)
    findings.extend(mx_findings)

    header_findings = await _analyze_headers(target, client)
    findings.extend(header_findings)

    ip_findings = await _check_ip_ranges(target, client)
    findings.extend(ip_findings)

    paas_count = sum(1 for f in findings if f.type == "PaaS Platform")
    cdn_count = sum(1 for f in findings if f.type == "CDN Service")
    cloud_count = sum(1 for f in findings if "Cloud" in f.type and f.type not in ("CDN Service",))
    tech_count = sum(1 for f in findings if f.type in ("CMS Detection", "JS Framework", "CSS Framework", "Analytics Service"))

    cloud_score = 0

    if paas_count > 0:
        cloud_score += min(paas_count * 10, 30)
    if cdn_count > 0:
        cloud_score += min(cdn_count * 10, 25)
    if cloud_count > 0:
        cloud_score += min(cloud_count * 5, 20)
    if tech_count > 0:
        cloud_score += min(tech_count * 5, 15)

    ns_count = sum(1 for f in findings if f.type == "DNS Nameserver Provider")
    if ns_count > 0:
        cloud_score += 5

    mx_count = sum(1 for f in findings if f.type == "Email Cloud Provider (MX)")
    if mx_count > 0:
        cloud_score += 5

    cloud_score = min(cloud_score, 100)

    if paas_count > 0 or cdn_count > 0 or cloud_count > 0 or tech_count > 0:
        findings.append(make_finding(
            entity=f"Cloud Recon Complete: {cloud_count} cloud, {cdn_count} CDN, {paas_count} PaaS, {tech_count} tech",
            type="Cloud Recon Summary",
            source="CloudRecon",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            resolution=f"{len(findings)} total findings",
            raw_data=f"Cloud: {cloud_count}, CDN: {cdn_count}, PaaS: {paas_count}, Tech: {tech_count}",
            tags=["cloud", "recon", "summary"]
        ))

        findings.append(make_finding(
            entity=f"Cloud Adoption Score: {cloud_score}/100",
            type="Cloud Infrastructure Score",
            source="CloudRecon",
            confidence="Medium",
            color="green" if cloud_score >= 60 else ("yellow" if cloud_score >= 30 else "slate"),
            threat_level="Informational",
            status="Calculated",
            resolution=f"Score: {cloud_score}/100",
            raw_data=f"Cloud adoption score: {cloud_score}. PaaS: {paas_count}, CDN: {cdn_count}, Cloud infra: {cloud_count}, Tech: {tech_count}, NS: {ns_count}, MX: {mx_count}",
            tags=["cloud", "score", "summary"]
        ))

    async def analyze_cloud_providers():
        providers = {}
        for f in findings:
            if f.type in ("PaaS Platform", "Cloud Provider IP", "DNS Nameserver Provider", "Email Cloud Provider (MX)", "CDN Service"):
                prov = f.entity.split("(")[0].split(":")[0].strip()
                providers[prov] = providers.get(prov, 0) + 1
        if providers:
            for prov, count in sorted(providers.items(), key=lambda x: -x[1])[:5]:
                findings.append(make_finding(entity=f"{prov}: {count}", type="Cloud Provider Breakdown", source="CloudRecon", confidence="Medium", color="purple", tags=["providers"]))
            findings.append(make_finding(entity=f"Unique providers: {len(providers)}", type="Provider Diversity", source="CloudRecon", confidence="Medium", color="slate", tags=["providers"]))

    async def analyze_service_tiers():
        findings.append(make_finding(entity=f"PaaS services: {paas_count}", type="Service Tier: PaaS", source="CloudRecon", confidence="Medium", color="slate", tags=["tiers"]))
        findings.append(make_finding(entity=f"CDN services: {cdn_count}", type="Service Tier: CDN", source="CloudRecon", confidence="Medium", color="slate", tags=["tiers"]))
        findings.append(make_finding(entity=f"DNS providers: {ns_count}", type="Service Tier: DNS", source="CloudRecon", confidence="Medium", color="slate", tags=["tiers"]))
        findings.append(make_finding(entity=f"Email cloud providers: {mx_count}", type="Service Tier: Email", source="CloudRecon", confidence="Medium", color="slate", tags=["tiers"]))

    async def analyze_exposure_risk():
        findings.append(make_finding(entity=f"Cloud recon score interpretation: {cloud_score}/100", type="Exposure Interpretation", source="CloudRecon", confidence="Medium", color="slate", tags=["exposure"]))
        if cloud_score > 50:
            findings.append(make_finding(entity="High cloud adoption - review provider security", type="Exposure Warning", source="CloudRecon", confidence="Medium", color="orange", tags=["exposure"]))
        else:
            findings.append(make_finding(entity="Moderate cloud adoption - standard security applies", type="Exposure Note", source="CloudRecon", confidence="Medium", color="emerald", tags=["exposure"]))
        findings.append(make_finding(entity=f"Total cloud-related findings: {sum(1 for f in findings if 'cloud' in (f.raw_data or '').lower() or any('cloud' in t.lower() for t in f.tags))}", type="Finding Volume", source="CloudRecon", confidence="Medium", color="slate", tags=["exposure"]))

    async def analyze_cdn_insight():
        findings.append(make_finding(entity=f"CDN services found: {cdn_count}", type="CDN Insight", source="CloudRecon", confidence="Medium", color="slate", tags=["cdn"]))
        findings.append(make_finding(entity=f"PaaS platforms found: {paas_count}", type="PaaS Insight", source="CloudRecon", confidence="Medium", color="slate", tags=["cdn"]))

    async def analyze_tech_stack():
        findings.append(make_finding(entity=f"Technologies detected: {tech_count}", type="Tech Stack", source="CloudRecon", confidence="Medium", color="slate", tags=["tech"]))
        findings.append(make_finding(entity=f"Cloud infra services: {cloud_count}", type="Cloud Infrastructure", source="CloudRecon", confidence="Medium", color="slate", tags=["tech"]))
        findings.append(make_finding(entity=f"Target: {target}", type="Scan Target", source="CloudRecon", confidence="High", color="slate", tags=["tech"]))

    async def analyze_cloud_verdict():
        findings.append(make_finding(entity=f"Cloud score range: {cloud_score}% adoption", type="Adoption Level", source="CloudRecon", confidence="Medium", color="purple", tags=["verdict"]))
        if cloud_score > 70:
            findings.append(make_finding(entity="Heavy cloud dependency - review multi-cloud security", type="Cloud Verdict", source="CloudRecon", confidence="Medium", color="orange", tags=["verdict"]))
        elif cloud_score > 30:
            findings.append(make_finding(entity="Moderate cloud usage - review provider configurations", type="Cloud Verdict", source="CloudRecon", confidence="Medium", color="yellow", tags=["verdict"]))
        else:
            findings.append(make_finding(entity="Minimal cloud footprint - low cloud attack surface", type="Cloud Verdict", source="CloudRecon", confidence="Medium", color="emerald", tags=["verdict"]))

    await asyncio.gather(
        analyze_cloud_providers(),
        analyze_service_tiers(),
        analyze_exposure_risk(),
        analyze_cdn_insight(),
        analyze_tech_stack(),
        analyze_cloud_verdict(),
    )

    return findings
