import asyncio
import dns.resolver

from osint_common import normalize_target, make_finding


async def _resolve(name, rtype):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: dns.resolver.resolve(name, rtype))


async def crawl(target: str, client=None):
    findings = []
    domain = normalize_target(target)

    checks = [
        (domain, "MX", "MX Record"),
        (domain, "TXT", "TXT Record"),
        (f"_dmarc.{domain}", "TXT", "DMARC Record"),
    ]
    for name, rtype, ftype in checks:
        try:
            answers = await _resolve(name, rtype)
            for item in answers:
                value = str(item)
                color = "emerald" if any(x in value.lower() for x in ["v=spf1", "v=dmarc1", "reject", "quarantine"]) else "slate"
                findings.append(make_finding(value, ftype, "Email Security Deep", "High", color, resolution=name, raw_data=value))
        except Exception:
            if ftype == "DMARC Record":
                findings.append(make_finding(
                    f"Missing DMARC for {domain}", "Email Security Gap", "Email Security Deep",
                    "High", "red", threat_level="Elevated Risk", status="Missing",
                    tags=["email-security", "dmarc"],
                ))

    selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]
    for selector in selectors:
        try:
            answers = await _resolve(f"{selector}._domainkey.{domain}", "TXT")
            for item in answers:
                findings.append(make_finding(
                    f"{selector}._domainkey.{domain}", "DKIM Record", "Email Security Deep",
                    "High", "emerald", resolution=str(item), raw_data=str(item),
                ))
        except Exception:
            pass

    return findings

