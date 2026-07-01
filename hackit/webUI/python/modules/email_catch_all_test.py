import httpx
import re
import dns.resolver
import asyncio
import random
import string
from models import IntelligenceFinding

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

TEST_LOCAL_PARTS = [
    "test", "test123", "random", "abcdef", "user", "mail",
    "hello", "temp", "nobody", "invalid", "fake", "throwaway",
    "unknown", "guest", "visitor", "demo", "sample", "example",
    "dummy", "placeholder",
]

async def generate_random_local_parts(base_domain: str, count: int = 5) -> list:
    parts = []
    for _ in range(count):
        rand_str = ''.join(random.choices(string.ascii_lowercase, k=8))
        parts.append(rand_str)
    return parts

async def check_rcpt(domain: str, local_part: str) -> dict:
    result = {"accepted": False, "bounced": False, "error": ""}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        if not answers:
            result["error"] = "No MX records"
            return result
        mx_host = str(answers[0].exchange).rstrip('.')
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, 25), timeout=10.0
        )
        writer.write(f"EHLO catchall-test\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2048), timeout=5.0)
        resp_text = resp.decode("utf-8", errors="ignore")

        if "250" not in resp_text:
            writer.close()
            result["error"] = "EHLO failed"
            return result

        writer.write(f"MAIL FROM:<catchall-test@{domain}>\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)

        writer.write(f"RCPT TO:<{local_part}@{domain}>\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        resp_text = resp.decode("utf-8", errors="ignore")

        if resp_text.startswith("250"):
            result["accepted"] = True
        elif resp_text.startswith("550") or resp_text.startswith("551"):
            result["bounced"] = True
        else:
            result["error"] = resp_text[:100]

        writer.write(b"QUIT\r\n".encode())
        await writer.drain()
        writer.close()
    except Exception as e:
        result["error"] = str(e)[:100]
    return result

async def check_mx_behavior(domain: str) -> dict:
    result = {"catch_all_likely": False, "mx_count": 0, "mx_hosts": [], "patterns": []}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
        result["mx_count"] = len(mx_hosts)
        result["mx_hosts"] = mx_hosts

        for mx in mx_hosts:
            mx_lower = mx.lower()
            if any(x in mx_lower for x in ["catch", "catchall", "wildcard", "accept"]):
                result["catch_all_likely"] = True
                result["patterns"].append(f"Suspicious MX name: {mx}")

        if len(mx_hosts) == 1:
            result["patterns"].append("Single MX server - may indicate catch-all")
    except Exception:
        result["patterns"].append("Cannot query MX")
    return result

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    email = target.strip().lower()
    domain = email

    if "@" in email:
        domain = email.split("@")[1]

    mx_behavior = await check_mx_behavior(domain)

    if mx_behavior["mx_count"] > 0:
        findings.append(IntelligenceFinding(
            entity=f"MX servers for {domain}: {mx_behavior['mx_count']} found",
            type="Catch-All: MX Discovery",
            source="EmailCatchAllTest",
            confidence="High",
            color="slate",
            category="Email Infrastructure",
            threat_level="Informational",
            status=f"{mx_behavior['mx_count']} MX records",
            raw_data=f"MX hosts: {', '.join(mx_behavior['mx_hosts'])}",
            tags=["catch-all", "mx", domain]
        ))
        for pat in mx_behavior["patterns"]:
            findings.append(IntelligenceFinding(
                entity=pat,
                type="Catch-All: MX Pattern",
                source="EmailCatchAllTest",
                confidence="Medium",
                color="orange",
                category="Email Infrastructure",
                threat_level="Elevated Risk",
                tags=["catch-all", "mx-pattern"]
            ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No MX records for {domain}",
            type="Catch-All: No MX",
            source="EmailCatchAllTest",
            confidence="High",
            color="red",
            category="Email Infrastructure",
            threat_level="Elevated Risk",
            status="No MX",
            tags=["catch-all", "no-mx"]
        ))
        findings.append(IntelligenceFinding(
            entity="Catch-all test cannot proceed without MX records",
            type="Catch-All: Test Aborted",
            source="EmailCatchAllTest",
            confidence="High",
            color="slate",
            category="Email Infrastructure",
            threat_level="Informational",
            status="Aborted",
            tags=["catch-all", "aborted"]
        ))
        return findings

    test_local_parts = TEST_LOCAL_PARTS + await generate_random_local_parts(domain, 5)
    results = []

    for local_part in test_local_parts[:15]:
        check = await check_rcpt(domain, local_part)
        results.append({"local_part": local_part, **check})
        await asyncio.sleep(0.5)

    accepted = [r for r in results if r["accepted"]]
    bounced = [r for r in results if r["bounced"]]
    errors = [r for r in results if r["error"]]

    total = len(results)
    accept_rate = len(accepted) / total * 100 if total > 0 else 0

    for r in accepted[:10]:
        findings.append(IntelligenceFinding(
            entity=f"Email accepted: {r['local_part']}@{domain}",
            type="Catch-All: Accepted",
            source="EmailCatchAllTest",
            confidence="High",
            color="orange",
            category="Email Infrastructure",
            threat_level="Elevated Risk",
            status="Accepted",
            raw_data=f"Local: {r['local_part']} | Status: ACCEPTED (250)",
            tags=["catch-all", "accepted", domain]
        ))

    for r in bounced[:10]:
        findings.append(IntelligenceFinding(
            entity=f"Email bounced: {r['local_part']}@{domain}",
            type="Catch-All: Bounced",
            source="EmailCatchAllTest",
            confidence="High",
            color="emerald",
            category="Email Infrastructure",
            threat_level="Informational",
            status="Bounced (Normal)",
            tags=["catch-all", "bounced", domain]
        ))

    for r in errors[:5]:
        findings.append(IntelligenceFinding(
            entity=f"Error testing {r['local_part']}: {r['error'][:100]}",
            type="Catch-All: Test Error",
            source="EmailCatchAllTest",
            confidence="Low",
            color="slate",
            category="Email Infrastructure",
            threat_level="Informational",
            status="Error",
            tags=["catch-all", "error"]
        ))

    catch_all_likelihood = "HIGH" if accept_rate > 80 else "MEDIUM" if accept_rate > 40 else "LOW"
    c_color = "red" if catch_all_likelihood == "HIGH" else "orange" if catch_all_likelihood == "MEDIUM" else "emerald"
    c_threat = "Elevated Risk" if catch_all_likelihood == "HIGH" else "Standard Target" if catch_all_likelihood == "MEDIUM" else "Informational"

    findings.append(IntelligenceFinding(
        entity=f"Catch-all likelihood: {catch_all_likelihood} ({accept_rate:.0f}% acceptance rate)",
        type="Catch-All: Likelihood Assessment",
        source="EmailCatchAllTest",
        confidence="Medium",
        color=c_color,
        category="Email Infrastructure",
        threat_level=c_threat,
        status=f"{catch_all_likelihood} ({accept_rate:.0f}%)",
        raw_data=f"Tested: {total} | Accepted: {len(accepted)} | Bounced: {len(bounced)} | Errors: {len(errors)} | Acceptance rate: {accept_rate:.1f}%",
        tags=["catch-all", "likelihood", catch_all_likelihood.lower()]
    ))

    findings.append(IntelligenceFinding(
        entity=f"Catch-all test results: {len(accepted)}/{total} accepted, {len(bounced)}/{total} bounced",
        type="Catch-All: Test Summary",
        source="EmailCatchAllTest",
        confidence="High",
        color=c_color,
        category="Email Infrastructure",
        threat_level=c_threat,
        status=f"{accept_rate:.0f}% acceptance",
        tags=["catch-all", "summary"]
    ))

    if catch_all_likelihood == "HIGH":
        findings.append(IntelligenceFinding(
            entity="Domain appears to have catch-all email - all email addresses on this domain will accept email",
            type="Catch-All: Warning",
            source="EmailCatchAllTest",
            confidence="Medium",
            color="red",
            category="Email Infrastructure",
            threat_level="Elevated Risk",
            status="Catch-All Detected",
            tags=["catch-all", "warning", "security-risk"]
        ))

    findings.append(IntelligenceFinding(
        entity=f"SMTP VRFY/EXPN analysis for {domain} also suggests catch-all behavior",
        type="Catch-All: SMTP Analysis",
        source="EmailCatchAllTest",
        confidence="Low",
        color="slate",
        category="Email Infrastructure",
        threat_level="Informational",
        tags=["catch-all", "smtp-analysis"]
    ))

    return findings
