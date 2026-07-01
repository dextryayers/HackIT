import httpx
import re
import json
from datetime import datetime
from urllib.parse import urlparse
from models import IntelligenceFinding

CA_ORGANIZATIONS = [
    "Let's Encrypt", "DigiCert", "Comodo", "GlobalSign", "Sectigo", "GoDaddy",
    "Symantec", "GeoTrust", "VeriSign", "Thawte", "RapidSSL", "AlphaSSL",
    "Certum", "Entrust", "Network Solutions", "IdenTrust", "Amazon",
    "Google Trust Services", "Microsoft", "Cloudflare", "BuyPass",
    "SSL.com", "ZeroSSL", "cPanel"
]

KNOWN_CA_OWNERS = {
    "Let's Encrypt": "ISRG (Internet Security Research Group)",
    "DigiCert Inc": "DigiCert",
    "DigiCert Inc ": "DigiCert",
    "Sectigo Limited": "Sectigo",
    "COMODO CA Limited": "Sectigo/Comodo",
    "GlobalSign nv-sa": "GlobalSign",
    "GoDaddy.com": "GoDaddy",
    "Google Trust Services": "Google",
    "Amazon": "Amazon Web Services",
    "Cloudflare, Inc.": "Cloudflare",
    "Microsoft Corporation": "Microsoft",
}

RISKY_CA_PATTERNS = ["self-signed", "self signed", "untrusted", "unknown"]

async def _fetch_ct_certificates(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=25.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            cert_timeline = []
            issuer_counts = {}
            algo_counts = {}
            san_sets = {}
            seen_serials = set()
            for cert in certs[:300]:
                serial = cert.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)
                issuer = str(cert.get("issuer_name", ""))
                nb = str(cert.get("not_before", ""))[:10]
                na = str(cert.get("not_after", ""))[:10]
                name_value = str(cert.get("name_value", ""))
                sans = name_value.split("\n") if name_value else []
                cert_timeline.append({"issuer": issuer, "not_before": nb, "not_after": na, "sans": sans})
                for ca_key, ca_label in KNOWN_CA_OWNERS.items():
                    if ca_key.lower() in issuer.lower():
                        issuer_counts[ca_label] = issuer_counts.get(ca_label, 0) + 1
                        break
                else:
                    issuer_counts[issuer[:60]] = issuer_counts.get(issuer[:60], 0) + 1
                for san in sans:
                    san_clean = san.strip().lower()
                    if san_clean and "*" not in san_clean and san_clean.endswith("." + domain):
                        if san_clean not in san_sets:
                            san_sets[san_clean] = {"first": nb, "last": na, "count": 0}
                        if nb and (nb < san_sets[san_clean]["first"] or not san_sets[san_clean]["first"]):
                            san_sets[san_clean]["first"] = nb
                        if na and (na > san_sets[san_clean]["last"] or not san_sets[san_clean]["last"]):
                            san_sets[san_clean]["last"] = na
                        san_sets[san_clean]["count"] += 1

            cert_timeline_sorted = sorted(cert_timeline, key=lambda x: x["not_before"])
            for i, entry in enumerate(cert_timeline_sorted[:20]):
                findings.append(IntelligenceFinding(
                    entity=f"Cert {i+1}: Issued {entry['not_before']}, Expires {entry['not_after']}",
                    type="SSL Certificate History - Timeline Entry",
                    source="crt.sh",
                    confidence="High",
                    color="emerald" if entry['not_after'] >= datetime.now().strftime("%Y-%m-%d") else "orange",
                    status="Active" if entry['not_after'] >= datetime.now().strftime("%Y-%m-%d") else "Expired",
                    resolution=f"Issuer: {entry['issuer'][:80]}",
                    raw_data=f"Not Before: {entry['not_before']}, Not After: {entry['not_after']}, Issuer: {entry['issuer']}",
                    tags=["ssl-history", "certificate", "timeline"]
                ))

            if cert_timeline_sorted:
                first_date = cert_timeline_sorted[0]["not_before"]
                last_date = cert_timeline_sorted[-1]["not_before"]
                total = len(cert_timeline_sorted)
                years_span = 0
                try:
                    if first_date and last_date:
                        fd = datetime.strptime(first_date[:10], "%Y-%m-%d") if first_date[:10].count("-") == 2 else datetime.now()
                        ld = datetime.strptime(last_date[:10], "%Y-%m-%d") if last_date[:10].count("-") == 2 else datetime.now()
                        years_span = (ld - fd).days / 365.25
                except Exception:
                    pass
                findings.append(IntelligenceFinding(
                    entity=f"{total} certificates issued over {years_span:.1f} years ({first_date} to {last_date})",
                    type="SSL Certificate History - Timeline Span",
                    source="crt.sh",
                    confidence="High",
                    color="blue",
                    status="Summary",
                    raw_data=f"First cert: {first_date}, Latest: {last_date}, Total: {total}, Span: {years_span:.1f}y",
                    tags=["ssl-history", "timeline", "summary"]
                ))

            issuance_dates = sorted(set(e["not_before"] for e in cert_timeline if e["not_before"]))
            if len(issuance_dates) > 1:
                gaps = []
                for i in range(1, len(issuance_dates)):
                    try:
                        prev = datetime.strptime(issuance_dates[i-1][:10], "%Y-%m-%d")
                        curr = datetime.strptime(issuance_dates[i][:10], "%Y-%m-%d")
                        gaps.append((curr - prev).days)
                    except Exception:
                        pass
                if gaps:
                    avg_gap = sum(gaps) / len(gaps)
                    freq_label = "frequent reissuance" if avg_gap < 30 else "normal" if avg_gap < 90 else "infrequent"
                    findings.append(IntelligenceFinding(
                        entity=f"Cert issuance frequency: avg {avg_gap:.0f} days between certs ({freq_label})",
                        type="SSL Certificate History - Issuance Frequency",
                        source="crt.sh",
                        confidence="High",
                        color="orange" if avg_gap < 30 else "emerald",
                        threat_level="Standard Target" if avg_gap < 30 else "Informational",
                        status=f"Avg gap: {avg_gap:.0f}d",
                        raw_data=f"Gaps between certs: {gaps}, Avg: {avg_gap:.0f}d",
                        tags=["ssl-history", "frequency", "issuance"]
                    ))

            for ca_name, count in sorted(issuer_counts.items(), key=lambda x: -x[1])[:10]:
                findings.append(IntelligenceFinding(
                    entity=f"{ca_name} ({count} certs)",
                    type="SSL Certificate History - Certificate Authority",
                    source="crt.sh",
                    confidence="High",
                    color="slate",
                    status=f"{count} certs",
                    raw_data=f"CA: {ca_name}, Certificate count: {count}",
                    tags=["ssl-history", "ca", "issuer"]
                ))

            if len(issuer_counts) > 3:
                findings.append(IntelligenceFinding(
                    entity=f"Multiple CA changes detected: {len(issuer_counts)} different issuers",
                    type="SSL Certificate History - CA Rotation",
                    source="crt.sh",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status="CA Changes",
                    raw_data=f"Unique CAs: {', '.join(sorted(issuer_counts.keys())[:8])}",
                    tags=["ssl-history", "ca-rotation", "changes"]
                ))

            for san, sdata in sorted(san_sets.items(), key=lambda x: x[1]["first"])[:40]:
                findings.append(IntelligenceFinding(
                    entity=san,
                    type="SSL Certificate History - Subdomain via SAN",
                    source="crt.sh",
                    confidence="High",
                    color="cyan",
                    status="Historical",
                    resolution=f"First: {sdata['first']}",
                    raw_data=f"SAN: {san}, First: {sdata['first']}, Last: {sdata['last']}, Certs: {sdata['count']}",
                    tags=["ssl-history", "san", "subdomain-discovery"]
                ))

            if san_sets:
                findings.append(IntelligenceFinding(
                    entity=f"{len(san_sets)} unique subdomains discovered from historical SANs",
                    type="SSL Certificate History - SAN Discovery Summary",
                    source="crt.sh",
                    confidence="High",
                    color="purple",
                    status="Summary",
                    raw_data=f"Total unique SANs ending in .{domain}: {len(san_sets)}",
                    tags=["ssl-history", "san", "summary"]
                ))

    except Exception:
        pass
    return findings

async def _analyze_cert_algorithm_history(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            algo_history = []
            seen_serials = set()
            for cert in certs[:200]:
                serial = cert.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)
                issuer = str(cert.get("issuer_name", ""))
                nb = str(cert.get("not_before", ""))[:10]
                ca_org = "Unknown"
                for org in CA_ORGANIZATIONS:
                    if org.lower() in issuer.lower():
                        ca_org = org
                        break
                algo_history.append({"date": nb, "ca": ca_org, "issuer": issuer[:80]})
            algo_history_sorted = sorted(algo_history, key=lambda x: x["date"])
            ca_progression = list(dict.fromkeys(e["ca"] for e in algo_history_sorted if e["ca"] != "Unknown"))
            if len(ca_progression) > 1:
                ca_chain = " -> ".join(ca_progression[:10])
                findings.append(IntelligenceFinding(
                    entity=f"CA progression: {ca_chain}",
                    type="SSL Certificate History - CA Change Timeline",
                    source="crt.sh",
                    confidence="High",
                    color="blue",
                    status="CA History",
                    raw_data=f"CA progression over time: {ca_chain}",
                    tags=["ssl-history", "ca-progression", "timeline"]
                ))
            if ca_progression:
                findings.append(IntelligenceFinding(
                    entity=f"Current/latest CA: {ca_progression[-1]}",
                    type="SSL Certificate History - Current Certificate Authority",
                    source="crt.sh",
                    confidence="High",
                    color="emerald",
                    status="Current CA",
                    tags=["ssl-history", "current-ca"]
                ))
    except Exception:
        pass
    return findings

async def _check_expired_certs(domain: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20.0,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if resp.status_code == 200:
            certs = resp.json() if isinstance(resp.text, str) and resp.text.startswith("[") else []
            now = datetime.now()
            expired_count = 0
            active_count = 0
            expired_sans = set()
            seen_serials = set()
            for cert in certs[:300]:
                serial = cert.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)
                na = str(cert.get("not_after", ""))[:10]
                name_value = str(cert.get("name_value", ""))
                try:
                    exp_date = datetime.strptime(na, "%Y-%m-%d") if na.count("-") == 2 else None
                except Exception:
                    exp_date = None
                if exp_date and exp_date < now:
                    expired_count += 1
                    for san in name_value.split("\n"):
                        san = san.strip().lower()
                        if san and "*" not in san and san.endswith("." + domain):
                            expired_sans.add(san)
                else:
                    active_count += 1
            if expired_count > 0:
                findings.append(IntelligenceFinding(
                    entity=f"{expired_count} expired certificates found ({active_count} active)",
                    type="SSL Certificate History - Expired Certificates",
                    source="crt.sh",
                    confidence="High",
                    color="orange",
                    threat_level="Standard Target",
                    status=f"{expired_count} Expired",
                    raw_data=f"Expired: {expired_count}, Active: {active_count}",
                    tags=["ssl-history", "expired", "certificates"]
                ))
            if expired_sans:
                for san in list(expired_sans)[:15]:
                    findings.append(IntelligenceFinding(
                        entity=san,
                        type="SSL Certificate History - Subdomain from Expired Cert",
                        source="crt.sh",
                        confidence="High",
                        color="orange",
                        status="From Expired Cert",
                        raw_data=f"Discovered from expired certificate SAN: {san}",
                        tags=["ssl-history", "expired-san", "subdomain"]
                    ))
                findings.append(IntelligenceFinding(
                    entity=f"{len(expired_sans)} subdomains discovered from expired certificates",
                    type="SSL Certificate History - Expired Cert Discovery",
                    source="crt.sh",
                    confidence="High",
                    color="purple",
                    status="Discovery Summary",
                    raw_data=f"Subdomains from expired certs: {len(expired_sans)}",
                    tags=["ssl-history", "expired-discovery", "summary"]
                ))
    except Exception:
        pass
    return findings

async def crawl(target: str, client: httpx.AsyncClient) -> list[IntelligenceFinding]:
    findings = []
    raw_target = target.strip().lower()
    if "://" in raw_target:
        domain = urlparse(raw_target).netloc
    else:
        domain = raw_target

    ct_findings = await _fetch_ct_certificates(domain, client)
    findings.extend(ct_findings)

    algo_findings = await _analyze_cert_algorithm_history(domain, client)
    findings.extend(algo_findings)

    expired_findings = await _check_expired_certs(domain, client)
    findings.extend(expired_findings)

    if findings:
        findings.append(IntelligenceFinding(
            entity=f"SSL Certificate History analysis complete: {len(findings)} total findings",
            type="SSL Certificate History - Summary",
            source="Passive SSL History",
            confidence="High",
            color="purple",
            status="Complete",
            tags=["ssl-history", "summary", "complete"]
        ))

    return findings
