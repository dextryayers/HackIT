import httpx
import re
import json
import datetime as dt
from collections import defaultdict
from datetime import datetime, timezone
from module_base import BaseScanner

CA_PATTERNS = {
    "Let's Encrypt": ["let's encrypt", "letsencrypt"],
    "DigiCert": ["digicert"],
    "Comodo": ["comodo", "sectigo"],
    "Cloudflare": ["cloudflare", "cloudflare-ssl"],
    "Google Trust": ["google trust", "gts"],
    "Amazon": ["amazon"],
    "Microsoft": ["microsoft"],
    "GlobalSign": ["globalsign"],
    "GoDaddy": ["godaddy"],
    "RapidSSL": ["rapidssl"],
    "GeoTrust": ["geotrust"],
    "Entrust": ["entrust"],
    "Thawte": ["thawte"],
    "Certum": ["certum"],
    "Verizon": ["verizon"],
    "Network Solutions": ["network solutions"],
    "IdenTrust": ["identrust"],
    "Buypass": ["buypass"],
    "SSLMate": ["sslmate"],
    "ZeroSSL": ["zerossl"],
    "Self-Signed": ["self-signed", "self signed"],
}

CERT_LOG_SOURCES = [
    "Google Argon", "Cloudflare Nimbus", "DigiCert Yeti",
    "Sectigo Mammoth", "Let's Encrypt Oak"
]

class CrtshScanner(BaseScanner):
    name = "crtsh"

    async def fetch_json(self, url: str) -> list:
        resp = await self.safe_request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        if resp and resp.status_code == 200 and resp.text.startswith("["):
            return resp.json()
        return []

    async def fetch_html(self, url: str) -> str:
        resp = await self.safe_request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        return resp.text if resp and resp.status_code == 200 else ""

    @staticmethod
    def classify_issuer(issuer_name: str) -> str:
        issuer_lower = issuer_name.lower()
        for ca_name, patterns in CA_PATTERNS.items():
            for pattern in patterns:
                if pattern in issuer_lower:
                    return ca_name
        return "Unknown/Other"

    @staticmethod
    def parse_html_fallback(html: str, domain: str) -> list:
        findings = []
        try:
            cert_blocks = re.findall(
                r'<tr[^>]*>\s*<td[^>]*>(\d+)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>',
                html, re.DOTALL
            )
            for cert_id, entry_type, name_value, not_before, not_after, cn, issuer in cert_blocks:
                clean_name = re.sub(r'<[^>]+>', '', name_value).strip().lower()
                clean_cn = re.sub(r'<[^>]+>', '', cn).strip().lower()
                clean_issuer = re.sub(r'<[^>]+>', '', issuer).strip()
                for name in [clean_name, clean_cn]:
                    if domain in name and name:
                        findings.append({
                            "id": cert_id, "name_value": name, "common_name": clean_cn,
                            "issuer_name": clean_issuer,
                            "not_before": re.sub(r'<[^>]+>', '', not_before).strip()[:10],
                            "not_after": re.sub(r'<[^>]+>', '', not_after).strip()[:10],
                        })
        except:
            pass
        return findings

    async def scan(self) -> list:
        results = []
        domain = self.target
        json_data = await self.fetch_json(f"https://crt.sh/?q=%25.{domain}&output=json")
        json_active = await self.fetch_json(f"https://crt.sh/?q=%25.{domain}&excluded=expired&output=json")
        if not json_data:
            html_data = await self.fetch_html(f"https://crt.sh/?q=%25.{domain}")
            if html_data:
                json_data = self.parse_html_fallback(html_data, domain)
        if not json_data:
            return results

        name_to_entries = defaultdict(list)
        seen_names = set()
        wildcard_names = set()
        issuer_counter = defaultdict(int)
        cert_year_map = defaultdict(int)

        for item in json_data:
            try:
                name_value = item.get("name_value", "") or ""
                common_name = item.get("common_name", "") or ""
                issuer_name = item.get("issuer_name", "") or ""
                not_before = item.get("not_before", "") or ""
                not_after = item.get("not_after", "") or ""
                id_val = item.get("id", 0)
                issuer_classified = self.classify_issuer(issuer_name)
                issuer_counter[issuer_classified] += 1

                for raw_name in [name_value, common_name]:
                    if not raw_name:
                        continue
                    for sub in raw_name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith("." + domain) or sub == domain:
                            is_wildcard = "*" in sub
                            entry = {"issuer": issuer_name, "issuer_classified": issuer_classified,
                                     "id": id_val, "not_before": not_before[:10], "not_after": not_after[:10]}
                            if is_wildcard:
                                wildcard_names.add(sub)
                            else:
                                if sub not in seen_names:
                                    seen_names.add(sub)
                            name_to_entries[sub].append(entry)
                            if not_before[:4].isdigit():
                                cert_year_map[not_before[:4]] += 1
            except:
                continue

        for sub, entries in name_to_entries.items():
            try:
                ids = [str(e["id"]) for e in entries[:5]]
                issuers_raw = list(set(e["issuer"] for e in entries if e["issuer"] != "Unknown"))
                issuers_classified = list(set(e["issuer_classified"] for e in entries))
                dates_before = sorted(set(e["not_before"] for e in entries if e["not_before"]))
                dates_after = sorted(set(e["not_after"] for e in entries if e["not_after"]))
                earliest = min(dates_before) if dates_before else ""
                latest = max(dates_after) if dates_after else ""
                cert_count = len(entries)
                is_wildcard_entry = "*" in sub
                name_type = "Wildcard Certificate" if is_wildcard_entry else "Subdomain (Certificate Transparency)"
                age_tag = "unknown-age"
                if earliest:
                    try:
                        age_days = (datetime.now() - datetime.strptime(earliest, "%Y-%m-%d")).days
                        age_tag = "new-cert" if age_days < 90 else ("moderate-age" if age_days < 365 else "old-cert")
                    except:
                        pass
                raw_parts = [f"Issuers: {', '.join(issuers_raw[:3])}"] if issuers_raw else []
                if issuers_classified:
                    raw_parts.append(f"CA: {', '.join(issuers_classified[:3])}")
                if earliest:
                    raw_parts.append(f"First seen: {earliest}")
                if latest:
                    raw_parts.append(f"Last seen: {latest}")
                raw_parts.append(f"Cert count: {cert_count} | IDs: {', '.join(ids)}")

                f = self.finding(
                    entity=sub, ftype=name_type, source="crt.sh", confidence="High",
                    color="emerald", category="Domain & DNS Enumeration",
                    threat_level="Standard Target", status="Logged in CT",
                    raw_data=" | ".join(raw_parts),
                    tags=["certificate-transparency", "crtsh", "ssl-tls", age_tag, "wildcard" if is_wildcard_entry else "explicit"]
                )
                if f: results.append(f)

                for issuer_class in issuers_classified:
                    if issuer_class and issuer_class != "Unknown/Other":
                        f2 = self.finding(
                            entity=f"{sub} issued by {issuer_class}", ftype="Certificate Issuer Detail",
                            source="crt.sh", confidence="Medium", color="purple",
                            threat_level="Informational",
                            raw_data=f"Subdomain {sub} uses certificate from {issuer_class}",
                            tags=["issuer", "ca", issuer_class.lower().replace(" ", "-")]
                        )
                        if f2: results.append(f2)
            except:
                continue

        if issuer_counter:
            for ca_name, count in sorted(issuer_counter.items(), key=lambda x: -x[1])[:8]:
                if ca_name == "Unknown/Other":
                    continue
                f = self.finding(
                    entity=f"{ca_name}: {count} certificates for {domain}",
                    ftype="Certificate Authority (CA) Breakdown", source="crt.sh",
                    confidence="High", color="purple", threat_level="Informational",
                    raw_data=f"CA {ca_name} issued {count} certificates covering {domain}",
                    tags=["ca", "issuer-stats", ca_name.lower().replace(" ", "-")]
                )
                if f: results.append(f)

        self_signed_count = issuer_counter.get("Self-Signed", 0)
        if self_signed_count > 0:
            f = self.finding(
                entity=f"{self_signed_count} self-signed certificate(s) found for {domain}",
                ftype="Self-Signed Certificate Alert", source="crt.sh",
                confidence="High", color="red", threat_level="Elevated Risk",
                raw_data=f"Self-signed certificates may indicate internal/testing infrastructure: {self_signed_count} found",
                tags=["self-signed", "security-risk"]
            )
            if f: results.append(f)

        le_count = issuer_counter.get("Let's Encrypt", 0)
        total_known = sum(v for k, v in issuer_counter.items() if k != "Unknown/Other")
        if total_known > 0 and le_count / total_known > 0.5:
            f = self.finding(
                entity=f"Let's Encrypt dominates ({le_count}/{total_known} certs)",
                ftype="CA Dominance Analysis", source="crt.sh",
                confidence="Medium", color="yellow", threat_level="Informational",
                raw_data=f"Let's Encrypt issued {le_count} of {total_known} classified certificates ({le_count*100//total_known}%)",
                tags=["ca-dominance", "lets-encrypt"]
            )
            if f: results.append(f)

        for year in sorted(cert_year_map.keys()):
            f = self.finding(
                entity=f"{year}: {cert_year_map[year]} certificates first seen",
                ftype="Certificate Temporal Distribution", source="crt.sh",
                confidence="Medium", color="blue", threat_level="Informational",
                raw_data=f"In {year}, {cert_year_map[year]} certificates were first observed for {domain}",
                tags=["temporal", f"year-{year}"]
            )
            if f: results.append(f)

        if wildcard_names:
            f = self.finding(
                entity=f"{len(wildcard_names)} wildcard cert patterns: {', '.join(sorted(wildcard_names)[:8])}",
                ftype="Wildcard Certificate Summary", source="crt.sh",
                confidence="High", color="orange", threat_level="Standard Target",
                raw_data="Wildcard certificates expand the attack surface significantly",
                tags=["wildcard", "summary"]
            )
            if f: results.append(f)

        f = self.finding(
            entity=f"Data from crt.sh covering {len(CERT_LOG_SOURCES)} CT log sources",
            ftype="CT Log Coverage", source="crt.sh",
            confidence="Medium", color="slate", threat_level="Informational",
            raw_data=f"CT logs: {', '.join(CERT_LOG_SOURCES)}",
            tags=["ct-logs", "coverage"]
        )
        if f: results.append(f)

        all_dates = [e["not_after"] for entries in name_to_entries.values() for e in entries if e["not_after"]]
        if all_dates:
            try:
                most_recent = max(all_dates)
                f = self.finding(
                    entity=f"Most recent certificate expires: {most_recent}",
                    ftype="Certificate Expiry Timeline", source="crt.sh",
                    confidence="High", color="blue", threat_level="Informational",
                    raw_data=f"Latest certificate expiry date for {domain}: {most_recent}",
                    tags=["timeline", "expiry"]
                )
                if f: results.append(f)
            except:
                pass

        san_counts = []
        for item in json_data[:50]:
            try:
                nv = item.get("name_value", "")
                if nv:
                    san_counts.append(len(nv.split("\n")))
            except:
                pass
        if san_counts:
            avg_san = sum(san_counts) // len(san_counts)
            f = self.finding(
                entity=f"SAN count: avg={avg_san}, max={max(san_counts)} per cert",
                ftype="SAN Count Analysis", source="crt.sh",
                confidence="Medium", color="blue", threat_level="Informational",
                raw_data=f"Average {avg_san} SANs per certificate, maximum {max(san_counts)}",
                tags=["san-analysis"]
            )
            if f: results.append(f)

        expired_count = 0
        recent_expired = []
        now = datetime.now(timezone.utc)
        for item in json_data:
            try:
                na = item.get("not_after", "")
                if na and len(na) >= 10 and datetime.strptime(na[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc) < now:
                    expired_count += 1
                    if len(recent_expired) < 5:
                        recent_expired.append(item.get("name_value", "?")[:60])
            except:
                pass
        if expired_count > 0:
            f = self.finding(
                entity=f"{expired_count} expired certificates found",
                ftype="Expired Certificate Detection", source="crt.sh",
                confidence="High", color="red", threat_level="Elevated Risk",
                raw_data=f"Expired certs: {expired_count}. Examples: {', '.join(recent_expired)}",
                tags=["expired", "risk"]
            )
            if f: results.append(f)

        years_sorted = sorted(cert_year_map.items())
        if len(years_sorted) >= 2:
            growth_rates = []
            for i in range(1, len(years_sorted)):
                prev_y, prev_c = years_sorted[i-1]
                curr_y, curr_c = years_sorted[i]
                if prev_c > 0:
                    growth_rates.append(f"{curr_y}: {((curr_c - prev_c) / prev_c) * 100:+.0f}%")
            if growth_rates:
                f = self.finding(
                    entity=f"Certificate issuance growth: {'; '.join(growth_rates)}",
                    ftype="Certificate Issuance Velocity", source="crt.sh",
                    confidence="Low", color="blue", threat_level="Informational",
                    raw_data="Year-over-year certificate issuance trends",
                    tags=["velocity", "growth"]
                )
                if f: results.append(f)

        new_subs, moderate_subs, old_subs = [], [], []
        for sub, entries in name_to_entries.items():
            if "*" in sub:
                continue
            dates = [e["not_before"] for e in entries if e["not_before"]]
            if dates:
                try:
                    age_days = (datetime.now() - datetime.strptime(min(dates), "%Y-%m-%d")).days
                    if age_days < 90:
                        new_subs.append(sub)
                    elif age_days < 365:
                        moderate_subs.append(sub)
                    else:
                        old_subs.append(sub)
                except:
                    pass

        if new_subs:
            f = self.finding(
                entity=f"{len(new_subs)} subdomains with new certs (<90 days): {', '.join(new_subs[:6])}",
                ftype="Subdomain Age Classification (New)", source="crt.sh",
                confidence="Medium", color="yellow", threat_level="Informational",
                raw_data="Recently obtained certificates may indicate new infrastructure",
                tags=["age-classification", "new-infra"]
            )
            if f: results.append(f)
        if moderate_subs:
            f = self.finding(
                entity=f"{len(moderate_subs)} subdomains with moderate-age certs (90-365 days)",
                ftype="Subdomain Age Classification (Moderate)", source="crt.sh",
                confidence="Medium", color="blue", threat_level="Informational",
                raw_data="Established infrastructure",
                tags=["age-classification", "moderate-infra"]
            )
            if f: results.append(f)
        if old_subs:
            f = self.finding(
                entity=f"{len(old_subs)} subdomains with old certs (>365 days): {', '.join(old_subs[:6])}",
                ftype="Subdomain Age Classification (Old)", source="crt.sh",
                confidence="Medium", color="purple", threat_level="Informational",
                raw_data="Long-standing certificates may indicate stable/legacy infrastructure",
                tags=["age-classification", "old-infra"]
            )
            if f: results.append(f)

        for identity in ["admin", "api", "dev", "test", "stage", "prod", "vpn", "mail", "cdn", "secure"]:
            ident_data = await self.fetch_json(f"https://crt.sh/?q={identity}.{domain}&output=json")
            if ident_data:
                f = self.finding(
                    entity=f"{identity}.{domain}: {len(ident_data)} cert entries",
                    ftype=f"Identity Query: {identity}", source="crt.sh",
                    confidence="Medium", color="blue", threat_level="Informational",
                    raw_data=f"Direct identity query for {identity}.{domain} returned {len(ident_data)} results",
                    tags=["identity-query", identity]
                )
                if f: results.append(f)

        all_ids = [item.get("id", 0) for item in json_data if item.get("id", 0) > 0]
        if all_ids:
            f = self.finding(
                entity=f"Cert ID range: {min(all_ids)} to {max(all_ids)}",
                ftype="Certificate ID Range Analysis", source="crt.sh",
                confidence="Low", color="slate", threat_level="Informational",
                raw_data=f"Certificate IDs span from {min(all_ids)} to {max(all_ids)}, indicating CT log coverage breadth",
                tags=["id-range"]
            )
            if f: results.append(f)

        total_unique = len([s for s in name_to_entries if "*" not in s])
        if total_unique > 5:
            f = self.finding(
                entity=f"Total: {total_unique} unique explicit subdomains + {len(wildcard_names)} wildcard patterns",
                ftype="Certificate Transparency Summary", source="crt.sh",
                confidence="High", color="blue", threat_level="Informational",
                raw_data=f"{total_unique} subdomains and {len(wildcard_names)} wildcard patterns discovered via crt.sh CT logs",
                tags=["summary", "total"]
            )
            if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = CrtshScanner(target, client)
    return await scanner.scan()
