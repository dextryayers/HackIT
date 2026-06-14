import httpx
import socket
import asyncio
import json
import re
from models import IntelligenceFinding
from urllib.parse import urlparse

CLOUD_SERVICES = {
    "AWS S3": {
        "domains": ["s3.amazonaws.com", "s3-website", "s3.us-east-1",
                    "s3-eu-west", "s3.ap-southeast", "s3.dualstack",
                    "s3.us-west", "amazonaws.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist",
                         "404 Not Found", "NoSuchBucketPolicy"],
    },
    "AWS CloudFront": {
        "domains": ["cloudfront.net"],
        "fingerprints": ["error: the request could not be satisfied",
                         "badrequest", "x-cache: error from cloudfront",
                         "cloudfront", "the request could not be satisfied"],
    },
    "Azure App Service": {
        "domains": ["azurewebsites.net", "cloudapp.net", "azureedge.net",
                    "trafficmanager.net", "blob.core.windows.net", "azurefd.net",
                    "azure-api.net"],
        "fingerprints": ["there is no app hosted here",
                         "the web app you are trying to access does not exist",
                         "this web app has been removed",
                         "404 site not found", "app service - 404"],
    },
    "GitHub Pages": {
        "domains": ["github.io"],
        "fingerprints": ["there isn't a github pages site here",
                         "github pages site not found",
                         "404 not found"],
    },
    "Heroku": {
        "domains": ["herokuapp.com", "herokudns.com"],
        "fingerprints": ["no such app", "heroku | no such app",
                         "there is nothing here yet"],
    },
    "GitLab": {
        "domains": ["gitlab.io"],
        "fingerprints": ["the page you're looking for could not be found",
                         "page not found", "gitlab 404"],
    },
    "Netlify": {
        "domains": ["netlify.app", "netlify.com"],
        "fingerprints": ["not found - netlify", "page not found",
                         "netlify site not found"],
    },
    "Pantheon": {
        "domains": ["pantheonsite.io", "pantheon.io"],
        "fingerprints": ["no site found", "this site is no longer available",
                         "pantheon 404"],
    },
    "Shopify": {
        "domains": ["myshopify.com", "shopify.com"],
        "fingerprints": ["sorry, this shop is currently unavailable",
                         "shopify", "this store is unavailable"],
    },
    "Squarespace": {
        "domains": ["squarespace.com", "sqsp.com"],
        "fingerprints": ["no site found", "this site is no longer available",
                         "domain not found", "squarespace - no such site"],
    },
    "Tumblr": {
        "domains": ["tumblr.com"],
        "fingerprints": ["there's nothing here", "page not found",
                         "whatever you were looking for doesn't exist"],
    },
    "WordPress": {
        "domains": ["wordpress.com", "wpengine.com"],
        "fingerprints": ["domain not found", "wordpress.com",
                         "doesn't exist", "compare to"],
    },
    "Zendesk": {
        "domains": ["zendesk.com"],
        "fingerprints": ["help center closed",
                         "no longer available", "zendesk - page not found"],
    },
    "Freshdesk": {
        "domains": ["freshdesk.com"],
        "fingerprints": ["this support portal is no longer available",
                         "freshdesk - 404"],
    },
    "Readme.io": {
        "domains": ["readme.io", "readme.com"],
        "fingerprints": ["project doesn't exist", "page not found",
                         "readme 404"],
    },
    "Surge.sh": {
        "domains": ["surge.sh"],
        "fingerprints": ["project not found", "surge - page not found",
                         "there is no such project"],
    },
    "Fly.io": {
        "domains": ["fly.dev", "fly.io"],
        "fingerprints": ["app not found", "404 not found"],
    },
    "Fastly": {
        "domains": ["fastly.net", "fastly.com"],
        "fingerprints": ["fastly error: unknown domain",
                         "fastly - domain not found",
                         "domain unknown"],
    },
    "Bitbucket": {
        "domains": ["bitbucket.io"],
        "fingerprints": ["repository not found",
                         "this repository has been deleted"],
    },
    "Unbounce": {
        "domains": ["unbouncepages.com", "unbounce.com"],
        "fingerprints": ["unbounce - page not found",
                         "the page you requested does not exist"],
    },
    "Wix": {
        "domains": ["wixstudio.com", "editorx.io", "wixsite.com"],
        "fingerprints": ["sorry, this site is not published",
                         "wix - 404", "this site was created"],
    },
    "Strikingly": {
        "domains": ["strikingly.com", "strikinglydns.com"],
        "fingerprints": ["site not found", "strikingly 404"],
    },
    "Cargo": {
        "domains": ["cargocollective.com"],
        "fingerprints": ["page not found", "site not found"],
    },
    "Tilda": {
        "domains": ["tilda.ws"],
        "fingerprints": ["page not found", "site not found"],
    },
    "Helpjuice": {
        "domains": ["helpjuice.com"],
        "fingerprints": ["kb not found", "knowledge base not found"],
    },
    "Teamwork": {
        "domains": ["teamwork.com"],
        "fingerprints": ["project not found"],
    },
    "Intercom": {
        "domains": ["custom.intercom.help"],
        "fingerprints": ["page not found", "help center not found"],
    },
}

CNAME_CACHE: dict[str, set[str]] = {}


async def resolve_cname(hostname: str) -> list[str]:
    cnames = []
    try:
        loop = asyncio.get_event_loop()
        _, _, cname_list = await loop.run_in_executor(
            None, socket.gethostbyname_ex, hostname
        )
        return cname_list
    except (socket.gaierror, socket.herror, OSError):
        pass
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.getaddrinfo, hostname, 443)
        return []
    except Exception:
        return []


async def get_subdomains_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    subdomains = set()
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith("." + domain) or n == domain:
                        if n not in subdomains:
                            subdomains.add(n)
    except Exception:
        pass
    return subdomains


def check_service_cname(cname: str) -> str | None:
    cname_lower = cname.lower()
    for service_name, info in CLOUD_SERVICES.items():
        for cdomain in info["domains"]:
            if cdomain in cname_lower:
                return service_name
    return None


async def verify_takeover(hostname: str, service_name: str,
                          client: httpx.AsyncClient) -> tuple[bool, str]:
    service_info = CLOUD_SERVICES.get(service_name)
    if not service_info:
        return False, ""

    fingerprints = service_info["fingerprints"]
    test_url = f"https://{hostname}"

    try:
        resp = await client.get(test_url, timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        body = resp.text.lower()[:5000]
        for fp in fingerprints:
            if fp.lower() in body:
                return True, f"Matched fingerprint: {fp}"
        resp_code_text = resp.text.lower()[:2000]
        for fp in fingerprints:
            if fp.lower() in resp_code_text:
                return True, f"Matched fingerprint: {fp}"
    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
        pass

    try:
        resp = await client.get(
            f"http://{hostname}", timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        body = resp.text.lower()[:5000]
        for fp in fingerprints:
            if fp.lower() in body:
                return True, f"Matched fingerprint over HTTP: {fp}"
    except Exception:
        pass

    return False, ""


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        subdomains = await get_subdomains_crtsh(domain, client)
        if domain not in subdomains:
            subdomains.add(domain)

        if not subdomains:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="Subdomain Takeover",
                source="SubdomainTakeover",
                confidence="Low",
                color="slate",
                status="No subdomains discovered",
                resolution="CRT.sh returned no certificate results",
            ))
            return findings

        findings.append(IntelligenceFinding(
            entity=f"{len(subdomains)} subdomains discovered via CRT.sh",
            type="Subdomain Discovery",
            source="SubdomainTakeover",
            confidence="High",
            color="purple",
            status=f"{len(subdomains)} subdomains",
            resolution=domain,
        ))

        takeover_count = 0
        for subdomain in sorted(subdomains)[:30]:
            try:
                cnames = await resolve_cname(subdomain)
                if not cnames:
                    continue

                service_name = None
                for cname in cnames:
                    detected = check_service_cname(cname)
                    if detected:
                        service_name = detected
                        break

                if not service_name:
                    continue

                is_vulnerable, evidence = await verify_takeover(
                    subdomain, service_name, client)

                status_text = "Vulnerable" if is_vulnerable else "Not Vulnerable (claimed)"
                color = "red" if is_vulnerable else "slate"
                threat = "High Risk" if is_vulnerable else "Informational"

                findings.append(IntelligenceFinding(
                    entity=subdomain,
                    type=f"Takeover Check: {service_name}",
                    source="SubdomainTakeover",
                    confidence="High" if is_vulnerable else "Medium",
                    color=color,
                    threat_level=threat,
                    status=status_text,
                    resolution=f"CNAME: {', '.join(cnames)}",
                    raw_data=f"Service: {service_name}, "
                             f"CNAME: {', '.join(cnames)}, "
                             f"Evidence: {evidence}" if evidence else
                             f"Service: {service_name}, "
                             f"CNAME: {', '.join(cnames)}",
                    tags=["takeover"] if is_vulnerable else [],
                ))
                if is_vulnerable:
                    takeover_count += 1

            except Exception:
                continue

        findings.append(IntelligenceFinding(
            entity=f"Takeover scan complete: {takeover_count} vulnerable subdomains",
            type="Takeover Scan Summary",
            source="SubdomainTakeover",
            confidence="High",
            color="red" if takeover_count > 0 else "emerald",
            threat_level="High Risk" if takeover_count > 0 else "Informational",
            status=f"{takeover_count} vulnerable",
            resolution=domain,
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Subdomain takeover error: {str(e)[:150]}",
            type="Subdomain Takeover Error",
            source="SubdomainTakeover",
            confidence="Low",
            color="red",
            status="Error",
        ))

    return findings
