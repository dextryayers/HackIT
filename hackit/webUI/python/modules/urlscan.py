import httpx
import json
import asyncio
from models import IntelligenceFinding

URLSCAN_API = "https://urlscan.io/api/v1"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    try:
        ip_resp = await client.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=10.0)
        resolved_ip = ""
        if ip_resp.status_code == 200:
            ip_data = ip_resp.json()
            answers = ip_data.get("Answer", [])
            if answers:
                resolved_ip = answers[0].get("data", "")

        if resolved_ip:
            findings.append(IntelligenceFinding(
                entity=resolved_ip,
                type="Resolved IP",
                source="urlscan.io",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Resolved",
                resolution=resolved_ip,
                raw_data=f"DNS A record for {domain}: {resolved_ip}",
                tags=["dns", "resolution"]
            ))
    except Exception:
        resolved_ip = ""

    try:
        search_urls = [
            f"{URLSCAN_API}/search/?q=domain:{domain}&size=100",
            f"{URLSCAN_API}/search/?q=ip:{resolved_ip}&size=50",
        ] if resolved_ip else [f"{URLSCAN_API}/search/?q=domain:{domain}&size=100"]

        for search_url in search_urls:
            try:
                resp = await client.get(search_url, timeout=20.0, headers={"User-Agent": USER_AGENT})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                results = data.get("results", [])
                total = data.get("total", len(results))

                for r in results[:25]:
                    page = r.get("page", {}) or {}
                    task = r.get("task", {}) or {}
                    scan_result = r.get("result", "")
                    screenshot_url = r.get("screenshot", "")
                    url = page.get("url", "")
                    ip = page.get("ip", "")
                    country = page.get("country", "")
                    server = page.get("server", "")
                    asn_name = page.get("asnname", "")
                    asn = page.get("asn", "")
                    domain_from_scan = page.get("domain", "")

                    verdicts = r.get("verdicts", {}) or {}
                    overall = verdicts.get("overall", {}) or {}
                    malicious_score = overall.get("maliciousScore", 0)
                    benign_score = overall.get("benignScore", 0)
                    has_malicious = overall.get("hasMalicious", False)
                    has_phishing = verdicts.get("phishing", {}).get("hasPhishing", False)
                    has_malware = verdicts.get("malware", {}).get("hasMalware", False)
                    has_spam = verdicts.get("spam", {}).get("hasSpam", False)

                    classification = "Benign"
                    threat_level = "Informational"
                    scan_color = "emerald"
                    if has_malicious or malicious_score > 50:
                        classification = "Malicious"
                        threat_level = "High Risk"
                        scan_color = "red"
                    elif has_phishing:
                        classification = "Phishing"
                        threat_level = "Critical"
                        scan_color = "red"
                    elif has_malware:
                        classification = "Malware"
                        threat_level = "Critical"
                        scan_color = "red"
                    elif has_spam:
                        classification = "Spam"
                        threat_level = "Elevated Risk"
                        scan_color = "orange"
                    elif malicious_score > 20:
                        classification = "Suspicious"
                        threat_level = "Elevated Risk"
                        scan_color = "orange"

                    if ip:
                        tags_list = ["urlscan"]
                        if has_malicious:
                            tags_list.append("malicious")
                        if has_phishing:
                            tags_list.append("phishing")
                        if has_malware:
                            tags_list.append("malware")
                        if asn:
                            tags_list.append(f"asn-{asn.replace(' ', '-')}")

                        raw_parts = []
                        if server:
                            raw_parts.append(f"Server: {server}")
                        if country:
                            raw_parts.append(f"Country: {country}")
                        if asn_name:
                            raw_parts.append(f"ASN: {asn_name}")
                        if classification:
                            raw_parts.append(f"Classification: {classification}")
                        if scan_result:
                            raw_parts.append(f"Result: {scan_result[:80]}")

                        findings.append(IntelligenceFinding(
                            entity=url[:200] if url else ip,
                            type=f"urlscan.io {classification}",
                            source="urlscan.io",
                            confidence="High" if ip else "Medium",
                            color=scan_color,
                            threat_level=threat_level,
                            status=classification,
                            resolution=ip,
                            raw_data=" | ".join(raw_parts) if raw_parts else json.dumps(page, default=str)[:500],
                            tags=tags_list
                        ))

                    if screenshot_url:
                        findings.append(IntelligenceFinding(
                            entity=screenshot_url[:200],
                            type="urlscan.io Screenshot",
                            source="urlscan.io",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            resolution=ip,
                            raw_data=f"Screenshot: {screenshot_url}",
                            tags=["screenshot"]
                        ))

                    if scan_result:
                        findings.append(IntelligenceFinding(
                            entity=scan_result[:200],
                            type="urlscan.io Result Link",
                            source="urlscan.io",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            resolution=ip,
                            raw_data=f"Result URL: {scan_result}",
                            tags=["result"]
                        ))

                    if country:
                        findings.append(IntelligenceFinding(
                            entity=f"{ip or domain} ({country})",
                            type="Host Country",
                            source="urlscan.io",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            resolution=ip,
                            raw_data=f"Country: {country}",
                            tags=["geo", "country"]
                        ))

                    if asn_name or asn:
                        entity = f"{asn_name} ({asn})" if asn_name and asn else (asn_name or asn)
                        findings.append(IntelligenceFinding(
                            entity=entity[:200],
                            type="ASN / Organization",
                            source="urlscan.io",
                            confidence="Medium",
                            color="purple",
                            threat_level="Informational",
                            resolution=ip,
                            raw_data=f"ASN: {asn} | Org: {asn_name}",
                            tags=["network", "asn"]
                        ))

                    if server:
                        findings.append(IntelligenceFinding(
                            entity=server[:200],
                            type="Server / Technology",
                            source="urlscan.io",
                            confidence="High",
                            color="orange",
                            threat_level="Informational",
                            resolution=ip,
                            raw_data=f"Server: {server}",
                            tags=["technology"]
                        ))

                    stats = r.get("stats", {}) or {}
                    console_msgs = stats.get("consoleMsgs", 0)
                    if console_msgs > 0:
                        findings.append(IntelligenceFinding(
                            entity=f"{console_msgs} console messages",
                            type="Page Console Activity",
                            source="urlscan.io",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Console messages: {console_msgs}",
                            tags=["page-stats"]
                        ))

                    domain_stats = stats.get("domainStats", [])
                    if domain_stats:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(domain_stats)} unique domains loaded",
                            type="Page Domain Stats",
                            source="urlscan.io",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            tags=["page-stats"]
                        ))

                    server_stats = stats.get("serverStats", [])
                    if server_stats:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(server_stats)} servers contacted",
                            type="Page Server Stats",
                            source="urlscan.io",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            tags=["page-stats"]
                        ))

                    ip_stats = stats.get("ipStats", [])
                    if ip_stats:
                        findings.append(IntelligenceFinding(
                            entity=f"{len(ip_stats)} unique IPs contacted",
                            type="Page IP Stats",
                            source="urlscan.io",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            tags=["page-stats"]
                        ))

                    malicious_count = sum(1 for r in results if (r.get("verdicts") or {}).get("overall", {}).get("hasMalicious", False))
                    phishing_count = sum(1 for r in results if (r.get("verdicts") or {}).get("phishing", {}).get("hasPhishing", False))
                    malware_count = sum(1 for r in results if (r.get("verdicts") or {}).get("malware", {}).get("hasMalware", False))
            except Exception:
                continue

        malicious_count = sum(1 for r in results if (r.get("verdicts") or {}).get("overall", {}).get("hasMalicious", False))
        phishing_count = sum(1 for r in results if (r.get("verdicts") or {}).get("phishing", {}).get("hasPhishing", False))
        malware_count = sum(1 for r in results if (r.get("verdicts") or {}).get("malware", {}).get("hasMalware", False))

        if results:
            summary_parts = []
            if malicious_count:
                summary_parts.append(f"{malicious_count} malicious")
            if phishing_count:
                summary_parts.append(f"{phishing_count} phishing")
            if malware_count:
                summary_parts.append(f"{malware_count} malware")
            if not summary_parts:
                summary_parts.append("all benign")

            findings.append(IntelligenceFinding(
                entity=f"{len(results)} urlscan results for {domain} ({', '.join(summary_parts)})",
                type="urlscan.io Summary",
                source="urlscan.io",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Complete",
                raw_data=f"Total: {total} | Displayed: {len(results)} | Malicious: {malicious_count} | Phishing: {phishing_count} | Malware: {malware_count}",
                tags=["summary", "urlscan"]
            ))
    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"urlscan.io API error: {str(e)[:100]}",
            type="urlscan.io Error",
            source="urlscan.io",
            confidence="Low",
            color="red",
            threat_level="Informational",
            status="Error",
            tags=["error"]
        ))

    try:
        uuid_resp = await client.get(
            f"{URLSCAN_API}/search/?q=domain:{domain}&size=1",
            timeout=10.0,
            headers={"User-Agent": USER_AGENT}
        )
        if uuid_resp.status_code == 200:
            uuid_data = uuid_resp.json()
            uuid_results = uuid_data.get("results", [])
            if uuid_results:
                scan_uuid = uuid_results[0].get("_id", "")
                if scan_uuid:
                    detail_resp = await client.get(
                        f"{URLSCAN_API}/result/{scan_uuid}/",
                        timeout=15.0,
                        headers={"User-Agent": USER_AGENT}
                    )
                    if detail_resp.status_code == 200:
                        detail = detail_resp.json()
                        lists_data = detail.get("data", {}).get("lists", {}) or {}
                        hashes_list = lists_data.get("hashes", [])
                        urls_list = lists_data.get("urls", [])
                        ip_list = lists_data.get("ips", [])
                        domains_list = lists_data.get("domains", [])
                        countries_list = lists_data.get("countries", [])

                        if countries_list:
                            unique_countries = set(c.get("name", "") for c in countries_list if isinstance(c, dict))
                            for country_name in list(unique_countries)[:5]:
                                if country_name:
                                    findings.append(IntelligenceFinding(
                                        entity=f"Request routed through: {country_name}",
                                        type="Request Path Country",
                                        source="urlscan.io",
                                        confidence="Medium",
                                        color="slate",
                                        threat_level="Informational",
                                        tags=["request-path", "geo"]
                                    ))

                        if ip_list:
                            response_ips = []
                            for ip_entry in ip_list[:15]:
                                if isinstance(ip_entry, dict):
                                    response_ips.append(ip_entry.get("ip", ""))
                                elif isinstance(ip_entry, str):
                                    response_ips.append(ip_entry)
                            if response_ips:
                                findings.append(IntelligenceFinding(
                                    entity=f"Connected IPs: {', '.join(response_ips[:8])}",
                                    type="Connected Hosts / IPs",
                                    source="urlscan.io",
                                    confidence="Medium",
                                    color="blue",
                                    threat_level="Informational",
                                    raw_data=f"IPs: {response_ips}",
                                    tags=["connected-hosts"]
                                ))

                        if hashes_list:
                            findings.append(IntelligenceFinding(
                                entity=f"{len(hashes_list)} resource hashes captured",
                                type="Page Resource Hashes",
                                source="urlscan.io",
                                confidence="Low",
                                color="slate",
                                threat_level="Informational",
                                tags=["hashes", "resources"]
                            ))

                        if urls_list:
                            external_urls = [u for u in urls_list[:20] if isinstance(u, str) and domain not in u]
                            if external_urls:
                                for ext_url in external_urls[:8]:
                                    findings.append(IntelligenceFinding(
                                        entity=ext_url[:200],
                                        type="External Resource URL",
                                        source="urlscan.io",
                                        confidence="Medium",
                                        color="slate",
                                        threat_level="Informational",
                                        tags=["external-resource"]
                                    ))

                        verdicts_detail = detail.get("verdicts", {}) or {}
                        urlscan_score = verdicts_detail.get("urlscan", {}).get("score", 0)
                        if urlscan_score:
                            findings.append(IntelligenceFinding(
                                entity=f"urlscan threat score: {urlscan_score}/100",
                                type="Threat Score",
                                source="urlscan.io",
                                confidence="Medium",
                                color="red" if urlscan_score > 50 else ("orange" if urlscan_score > 20 else "slate"),
                                threat_level="Critical" if urlscan_score > 70 else ("High Risk" if urlscan_score > 50 else ("Elevated Risk" if urlscan_score > 20 else "Informational")),
                                raw_data=f"Score: {urlscan_score}",
                                tags=["threat-score"]
                            ))

                        page_data = detail.get("page", {}) or {}
                        page_domain = page_data.get("domain", "")
                        page_ip = page_data.get("ip", "")
                        page_asn = page_data.get("asn", "")
                        page_asnname = page_data.get("asnname", "")
                        page_country = page_data.get("country", "")
                        page_city = page_data.get("city", "")
                        page_server = page_data.get("server", "")

                        if page_city and page_country:
                            findings.append(IntelligenceFinding(
                                entity=f"{page_city}, {page_country}",
                                type="Server Location",
                                source="urlscan.io",
                                confidence="High",
                                color="slate",
                                threat_level="Informational",
                                resolution=page_ip,
                                raw_data=f"City: {page_city} | Country: {page_country}",
                                tags=["geo", "location"]
                            ))

                        if page_server:
                            findings.append(IntelligenceFinding(
                                entity=page_server[:200],
                                type="Server (Detailed)",
                                source="urlscan.io",
                                confidence="High",
                                color="orange",
                                threat_level="Informational",
                                tags=["technology", "server"]
                            ))

    except Exception:
        pass

    try:
        uuid = await _submit_urlscan(domain, client)
        if uuid:
            result_data = await _poll_urlscan_result(uuid, client)
            if result_data:
                await _analyze_dom_element(result_data, findings, domain)
                await _analyze_redirects(result_data, findings, domain)
                await _analyze_cookies_from_lists(result_data, findings)
                await _analyze_tech_from_scan(result_data, findings)
    except Exception:
        pass

    try:
        sub_resp = await client.get(
            f"{URLSCAN_API}/search/?q=domain:{domain}&size=100",
            timeout=15.0,
            headers={"User-Agent": USER_AGENT}
        )
        if sub_resp.status_code == 200:
            sub_data = sub_resp.json()
            subdomains_found = set()
            for r in sub_data.get("results", []):
                page = r.get("page", {}) or {}
                pg_domain = page.get("domain", "")
                if pg_domain and pg_domain != domain and pg_domain.endswith(domain):
                    subdomains_found.add(pg_domain)
            if subdomains_found:
                for sd in sorted(subdomains_found)[:15]:
                    findings.append(IntelligenceFinding(
                        entity=sd,
                        type="urlscan.io Subdomain",
                        source="urlscan.io",
                        confidence="Medium",
                        color="emerald",
                        threat_level="Informational",
                        tags=["subdomain"]
                    ))
                if len(subdomains_found) > 15:
                    findings.append(IntelligenceFinding(
                        entity=f"... and {len(subdomains_found) - 15} more subdomains",
                        type="urlscan.io Subdomains Summary",
                        source="urlscan.io",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["subdomain", "summary"]
                    ))
    except Exception:
        pass

    return findings


async def _submit_urlscan(domain: str, client: httpx.AsyncClient) -> str | None:
    try:
        payload = {
            "url": f"https://{domain}",
            "public": "on",
            "useragent": USER_AGENT,
        }
        resp = await client.post(
            "https://urlscan.io/api/v1/scan/",
            json=payload,
            timeout=15.0,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("uuid", "")
    except Exception:
        pass
    return None


async def _poll_urlscan_result(uuid: str, client: httpx.AsyncClient) -> dict | None:
    for attempt in range(5):
        try:
            resp = await client.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                timeout=10.0,
                headers={"User-Agent": USER_AGENT},
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        if attempt < 4:
            await asyncio.sleep(3)
    return None


async def _analyze_dom_element(data: dict, findings: list, domain: str):
    try:
        dom_data = data.get("data", {}).get("dom", {}) if data else {}
        if not dom_data:
            return

        cookies = dom_data.get("cookies", [])
        if cookies:
            for c in cookies[:10]:
                c_name = c.get("name", "")
                c_domain = c.get("domain", "")
                c_secure = c.get("secure", False)
                c_http_only = c.get("httponly", False)
                c_same_site = c.get("sameSite", "")
                missing_attrs = []
                if not c_secure:
                    missing_attrs.append("Secure")
                if not c_http_only:
                    missing_attrs.append("HttpOnly")
                if missing_attrs:
                    findings.append(IntelligenceFinding(
                        entity=f"Cookie: {c_name} (missing: {', '.join(missing_attrs)})",
                        type="Insecure Cookie",
                        source="urlscan.io",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["cookie", "security"],
                    ))

                if c_domain and c_domain.startswith("."):
                    findings.append(IntelligenceFinding(
                        entity=f"Wildcard cookie domain: {c_name} -> {c_domain}",
                        type="Wildcard Cookie Domain",
                        source="urlscan.io",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["cookie", "security"],
                    ))

        localStorage = dom_data.get("localStorage", [])
        if localStorage:
            for ls in localStorage[:5]:
                ls_key = ls.get("name", "")
                ls_val = ls.get("value", "")
                if any(k in (ls_key + ls_val).lower() for k in ("token", "secret", "key", "password", "credential")):
                    findings.append(IntelligenceFinding(
                        entity=f"Sensitive localStorage: {ls_key}",
                        type="Sensitive Client Storage",
                        source="urlscan.io",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        tags=["security", "client-storage"],
                    ))

        sessionStorage = dom_data.get("sessionStorage", [])
        if sessionStorage:
            for ss in sessionStorage[:5]:
                ss_key = ss.get("name", "")
                ss_val = ss.get("value", "")
                if any(k in (ss_key + ss_val).lower() for k in ("token", "secret", "key", "password", "credential")):
                    findings.append(IntelligenceFinding(
                        entity=f"Sensitive sessionStorage: {ss_key}",
                        type="Sensitive Client Storage",
                        source="urlscan.io",
                        confidence="Medium",
                        color="red",
                        threat_level="High Risk",
                        tags=["security", "client-storage"],
                    ))
    except Exception:
        pass


async def _analyze_redirects(data: dict, findings: list, domain: str):
    try:
        redirect_chain = data.get("data", {}).get("requests", []) if data else []
        chain = []
        for req in redirect_chain[:30]:
            req_data = req.get("request", {})
            resp_data = req.get("response", {})
            req_url = (req_data or {}).get("url", "")
            resp_status = (resp_data or {}).get("status", 0)
            if resp_status in (301, 302, 303, 307, 308):
                chain.append(f"{resp_status} -> {req_url[:120]}")
        if len(chain) > 1:
            findings.append(IntelligenceFinding(
                entity=" -> ".join(chain[:5]),
                type="Redirect Chain",
                source="urlscan.io",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                tags=["redirect", "chain"],
            ))
        if len(chain) > 3:
            findings.append(IntelligenceFinding(
                entity=f"Long redirect chain: {len(chain)} hops",
                type="Excessive Redirects",
                source="urlscan.io",
                confidence="Medium",
                color="red",
                threat_level="Elevated Risk",
                tags=["redirect", "security"],
            ))
    except Exception:
        pass


async def _analyze_cookies_from_lists(data: dict, findings: list):
    try:
        lists_data = data.get("data", {}).get("lists", {}) if data else {}
        cookies_list = lists_data.get("cookies", [])
        if cookies_list:
            for c in cookies_list[:15]:
                c_name = c.get("name", "")
                c_val = c.get("value", "")
                if any(s in (c_val or "").lower() for s in ("session", "token", "auth", "sid", "jwt")):
                    findings.append(IntelligenceFinding(
                        entity=f"Auth-related cookie value: {c_name}",
                        type="Authentication Cookie",
                        source="urlscan.io",
                        confidence="Medium",
                        color="orange",
                        threat_level="Elevated Risk",
                        tags=["cookie", "authentication"],
                    ))
    except Exception:
        pass


async def _analyze_tech_from_scan(data: dict, findings: list):
    try:
        meta = data.get("meta", {}) if data else {}
        processors = meta.get("processors", {}) if meta else {}
        tech_data = processors.get("technology", {}).get("data", [])
        if tech_data:
            for tech in tech_data[:15]:
                t_name = tech.get("name", "")
                t_version = tech.get("version", "")
                t_confidence = tech.get("confidence", 0)
                if t_name:
                    entity = f"{t_name} {t_version}" if t_version else t_name
                    color_tech = "blue" if t_confidence > 80 else "slate"
                    findings.append(IntelligenceFinding(
                        entity=entity,
                        type="Detected Technology",
                        source="urlscan.io",
                        confidence="Medium",
                        color=color_tech,
                        threat_level="Informational",
                        tags=["technology", "detected"],
                    ))
    except Exception:
        pass
