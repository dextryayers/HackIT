import asyncio
import dns.resolver

from osint_common import normalize_target, make_finding


CLOUD_PATTERNS = {
    "amazonaws.com": "AWS",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudapp.net": "Azure",
    "googlehosted.com": "Google Cloud",
    "ghs.googlehosted.com": "Google Hosted",
    "firebaseapp.com": "Firebase",
    "web.app": "Firebase Hosting",
    "herokuapp.com": "Heroku",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pages.dev": "Cloudflare Pages",
    "fastly.net": "Fastly",
    "akamai": "Akamai",
    "github.io": "GitHub Pages",
    "gitlab.io": "GitLab Pages",
}


async def crawl(target: str, client=None):
    findings = []
    domain = normalize_target(target)
    names = [domain, f"www.{domain}", f"api.{domain}", f"cdn.{domain}", f"static.{domain}", f"assets.{domain}"]
    loop = asyncio.get_event_loop()

    for name in names:
        for rtype in ["CNAME", "A", "AAAA", "NS"]:
            try:
                answers = await loop.run_in_executor(None, lambda n=name, rt=rtype: dns.resolver.resolve(n, rt))
                for answer in answers:
                    value = str(answer).rstrip(".")
                    lower = value.lower()
                    for pattern, provider in CLOUD_PATTERNS.items():
                        if pattern in lower:
                            findings.append(make_finding(
                                f"{name} -> {value}", "Cloud Asset", "Cloud Fingerprint Deep",
                                "High", "orange", threat_level="Informational",
                                raw_data=f"{rtype}: {value}", tags=["cloud", provider],
                            ))
            except Exception:
                pass
    return findings

