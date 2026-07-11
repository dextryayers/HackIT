import asyncio
import dns.resolver
import dns.query
import dns.zone
import dns.name
import dns.dnssec
import re
import struct
import base64
from collections import defaultdict
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash

DNSSEC_ALGORITHMS = {
    1: "RSAMD5", 2: "DH", 3: "DSA", 4: "ECC",
    5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256", 10: "RSASHA512", 12: "ECC-GOST",
    13: "ECDSAP256R256", 14: "ECDSAP384R384", 15: "ED25519",
    16: "ED448", 252: "INDIRECT", 253: "PRIVATEDNS",
    254: "PRIVATEOID",
}

DIGEST_TYPES = {
    1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94",
    4: "SHA-384",
}

async def check_zone_transfer(domain):
    findings = []
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_server = str(ns.target)
            findings.append(make_finding(
                entity=f"Testing zone transfer on {ns_server}",
                ftype="Zone Transfer Attempt",
                source="DNS Deep Forensics",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data=f"Attempting zone transfer from {ns_server}",
                tags=["zone-transfer", ns_server]
            ))
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=10))
                if zone:
                    records = list(zone.nodes.keys())[:20]
                    findings.append(make_finding(
                        entity=domain,
                        ftype="DNS Zone Transfer",
                        source="DNS Deep Forensics",
                        confidence="Certain",
                        color="red",
                        threat_level="Critical",
                        status="VULNERABLE",
                        raw_data=f"Zone transfer successful from {ns_server}! Records: {len(zone.nodes)} total. Sample: {records}",
                        tags=["zone-transfer", "vulnerable", "critical"]
                    ))
                else:
                    findings.append(make_finding(
                        entity=f"Zone transfer denied by {ns_server}",
                        ftype="Zone Transfer Attempt",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="green",
                        threat_level="Informational",
                        status="Secure",
                        raw_data=f"Zone transfer refused by {ns_server}",
                        tags=["zone-transfer", "secure"]
                    ))
            except:
                findings.append(make_finding(
                    entity=f"Zone transfer DENIED by {ns_server}",
                    ftype="Zone Transfer Attempt",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color="green",
                    threat_level="Informational",
                    status="Secure",
                    raw_data=f"Zone transfer to {ns_server} failed as expected (secure)",
                    tags=["zone-transfer", "secure"]
                ))
    except:
        pass
    return findings

async def check_dnssec_analysis(domain):
    findings = []
    try:
        dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY')
        dnskey_records = list(dnskey_answers)
        if dnskey_records:
            findings.append(make_finding(
                entity=f"{len(dnskey_records)} DNSKEY records found for {domain}",
                type="DNSSEC DNSKEY Records",
                source="DNS Deep Forensics",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="DNSSEC Present",
                raw_data=f"Found {len(dnskey_records)} DNSKEY records",
                tags=["dnssec", "dnskey"]
            ))
            for i, key in enumerate(dnskey_records[:5]):
                try:
                    algo = DNSSEC_ALGORITHMS.get(key.algorithm, f"Unknown({key.algorithm})")
                    flags = key.flags
                    proto = key.protocol
                    key_tag = dns.dnssec.key_id(key) if hasattr(dns.dnssec, 'key_id') else 0
                    key_text = base64.b64encode(key.key).decode()[:60]
                    zsk = "ZSK" if flags == 256 else "KSK" if flags == 257 else "Unknown"
                    findings.append(make_finding(
                        entity=f"DNSKEY #{i+1}: {zsk}, algo={algo}, flags={flags}, tag={key_tag}",
                        ftype="DNSSEC DNSKEY Detail",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"DNSKEY: algorithm={algo}, flags={flags}, protocol={proto}, key={key_text}...",
                        tags=["dnssec", "dnskey", zsk.lower()]
                    ))
                except:
                    pass

        ds_answers = dns.resolver.resolve(domain, 'DS')
        ds_records = list(ds_answers)
        if ds_records:
            findings.append(make_finding(
                entity=f"{len(ds_records)} DS records found for {domain}",
                type="DNSSEC DS Records",
                source="DNS Deep Forensics",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="DS Present",
                raw_data=f"Found {len(ds_records)} Delegation Signer records",
                tags=["dnssec", "ds"]
            ))
            for ds in ds_records[:5]:
                try:
                    digest_type = DIGEST_TYPES.get(ds.digest_type, f"Unknown({ds.digest_type})")
                    algo_str = DNSSEC_ALGORITHMS.get(ds.algorithm, f"Unknown({ds.algorithm})")
                    findings.append(make_finding(
                        entity=f"DS: key_tag={ds.key_tag}, algo={algo_str}, digest={ds.digest[:20]}...",
                        ftype="DNSSEC DS Detail",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"DS record: key_tag={ds.key_tag}, algorithm={ds.algorithm}, digest_ftype={digest_type}, digest={ds.digest.hex()}",
                        tags=["dnssec", "ds"]
                    ))
                except:
                    pass

        rrsig_answers = dns.resolver.resolve(domain, 'RRSIG')
        rrsig_records = list(rrsig_answers)
        if rrsig_records:
            findings.append(make_finding(
                entity=f"{len(rrsig_records)} RRSIG records found for {domain}",
                type="DNSSEC RRSIG Records",
                source="DNS Deep Forensics",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="RRSIG Present",
                raw_data=f"Found {len(rrsig_records)} RRSIG signatures",
                tags=["dnssec", "rrsig"]
            ))
            for sig in rrsig_records[:5]:
                try:
                    algo_str = DNSSEC_ALGORITHMS.get(sig.algorithm, f"Unknown({sig.algorithm})")
                    findings.append(make_finding(
                        entity=f"RRSIG: {sig.type_covered} by {sig.signer}, algo={algo_str}, expires={sig.expiration}",
                        ftype="DNSSEC RRSIG Detail",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        raw_data=f"RRSIG: type_covered={sig.type_covered}, algorithm={sig.algorithm}, labels={sig.labels}, original_ttl={sig.original_ttl}, expiration={sig.expiration}, inception={sig.inception}, key_tag={sig.key_tag}, signer={sig.signer}",
                        tags=["dnssec", "rrsig"]
                    ))
                except:
                    pass

        if not dnskey_records and not ds_records and not rrsig_records:
            findings.append(make_finding(
                entity=f"No DNSSEC records found for {domain}",
                ftype="DNSSEC Status",
                source="DNS Deep Forensics",
                confidence="High",
                color="orange",
                threat_level="Elevated Risk",
                status="DNSSEC Missing",
                raw_data=f"No DNSKEY, DS, or RRSIG records for {domain}",
                tags=["dnssec", "missing"]
            ))
    except:
        findings.append(make_finding(
            entity=f"DNSSEC not configured for {domain}",
            ftype="DNSSEC Status",
            source="DNS Deep Forensics",
            confidence="Medium",
            color="orange",
            threat_level="Elevated Risk",
            status="No DNSSEC",
            raw_data=f"DNSSEC resolution failed for {domain}",
            tags=["dnssec", "missing"]
        ))
    return findings

async def check_cname_chain(domain):
    findings = []
    visited = set()
    chain = []
    current = domain
    max_depth = 8
    while current and current not in visited and len(chain) < max_depth:
        visited.add(current)
        try:
            cname_answers = dns.resolver.resolve(current, 'CNAME')
            cname_target = str(cname_answers[0].target).rstrip('.')
            chain.append((current, "CNAME", cname_target))
            findings.append(make_finding(
                entity=f"{current} -> CNAME -> {cname_target}",
                ftype="CNAME Chain Link",
                source="DNS Deep Forensics",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status=f"Hop {len(chain)}",
                raw_data=f"CNAME: {current} -> {cname_target}",
                tags=["cname", "chain", f"hop-{len(chain)}"]
            ))
            current = cname_target
        except:
            try:
                a_answers = dns.resolver.resolve(current, 'A')
                ip = str(a_answers[0])
                chain.append((current, "A", ip))
                findings.append(make_finding(
                    entity=f"{current} -> A -> {ip} (FINAL)",
                    type="CNAME Chain Final Resolution",
                    source="DNS Deep Forensics",
                    confidence="Certain",
                    color="emerald",
                    threat_level="Informational",
                    status="Final",
                    resolution=ip,
                    raw_data=f"Final A record: {current} = {ip} (chain length: {len(chain)})",
                    tags=["cname", "chain", "final", "a-record"]
                ))
                break
            except:
                try:
                    aaaa_answers = dns.resolver.resolve(current, 'AAAA')
                    ip = str(aaaa_answers[0])
                    chain.append((current, "AAAA", ip))
                    findings.append(make_finding(
                        entity=f"{current} -> AAAA -> {ip} (FINAL)",
                        type="CNAME Chain Final Resolution (IPv6)",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        status="Final (IPv6)",
                        resolution=ip,
                        raw_data=f"Final AAAA record: {current} = {ip}",
                        tags=["cname", "chain", "final", "aaaa"]
                    ))
                    break
                except:
                    break
    if len(chain) > 1:
        findings.append(make_finding(
            entity=f"CNAME chain for {domain}: {len(chain)} hops",
            type="CNAME Chain Summary",
            source="DNS Deep Forensics",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"CNAME chain length: {len(chain)}. Path: {' -> '.join(c[0] for c in chain)} -> {chain[-1][2]}",
            tags=["cname", "chain-summary"]
        ))
    return findings

async def check_ns_delegation(domain):
    findings = []
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        ns_hosts = [str(r).rstrip('.') for r in ns_answers]
        findings.append(make_finding(
            entity=f"{len(ns_hosts)} nameservers: {', '.join(ns_hosts)}",
            type="NS Delegation Records",
            source="DNS Deep Forensics",
            confidence="High",
            color="slate",
            threat_level="Informational",
            raw_data=f"Nameservers: {', '.join(ns_hosts)}",
            tags=["ns", "delegation"]
        ))

        for ns in ns_hosts:
            # Check glue records
            try:
                glue_a = dns.resolver.resolve(ns, 'A')
                for ip in glue_a:
                    findings.append(make_finding(
                        entity=f"Glue: {ns} -> {str(ip)}",
                        type="NS Glue Record (A)",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        resolution=str(ip),
                        raw_data=f"Glue A record: {ns} = {str(ip)}",
                        tags=["ns", "glue", "a-record"]
                    ))
            except:
                findings.append(make_finding(
                    entity=f"Missing glue A record for {ns}!",
                    ftype="Missing NS Glue Record",
                    source="DNS Deep Forensics",
                    confidence="Medium",
                    color="orange",
                    threat_level="Elevated Risk",
                    raw_data=f"No A record found for nameserver {ns} - may cause resolution delays",
                    tags=["ns", "missing-glue", "risk"]
                ))

            try:
                glue_aaaa = dns.resolver.resolve(ns, 'AAAA')
                for ip in glue_aaaa:
                    findings.append(make_finding(
                        entity=f"Glue (IPv6): {ns} -> {str(ip)}",
                        type="NS Glue Record (AAAA)",
                        source="DNS Deep Forensics",
                        confidence="Medium",
                        color="purple",
                        threat_level="Informational",
                        resolution=str(ip),
                        raw_data=f"Glue AAAA record: {ns} = {str(ip)}",
                        tags=["ns", "glue", "aaaa"]
                    ))
            except:
                pass
    except:
        pass
    return findings

async def check_soa_analysis(domain):
    findings = []
    try:
        soa_answers = dns.resolver.resolve(domain, 'SOA')
        for soa in soa_answers:
            mname = str(soa.mname).rstrip('.')
            rname = str(soa.rname).rstrip('.')
            serial = soa.serial
            refresh = soa.refresh
            retry = soa.retry
            expire = soa.expire
            minimum = soa.minimum

            findings.append(make_finding(
                entity=f"SOA: mname={mname}, rname={rname}",
                ftype="SOA Record (Authority)",
                source="DNS Deep Forensics",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"Primary NS: {mname}, Admin: {rname}",
                tags=["soa", "authority"]
            ))

            findings.append(make_finding(
                entity=f"Serial: {serial}",
                ftype="SOA Serial Number",
                source="DNS Deep Forensics",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"SOA Serial: {serial} (check if matches zone updates)",
                tags=["soa", "serial"]
            ))

            findings.append(make_finding(
                entity=f"Refresh: {refresh}s ({refresh//60}min), Retry: {retry}s ({retry//60}min)",
                type="SOA Timing: Refresh/Retry",
                source="DNS Deep Forensics",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"SOA Refresh={refresh}, Retry={retry}",
                tags=["soa", "timing"]
            ))

            findings.append(make_finding(
                entity=f"Expire: {expire}s ({expire//3600}h), MinTTL: {minimum}s ({minimum//60}min)",
                type="SOA Timing: Expire/Minimum",
                source="DNS Deep Forensics",
                confidence="High",
                color="indigo",
                threat_level="Informational",
                raw_data=f"SOA Expire={expire}, Minimum TTL={minimum}",
                tags=["soa", "timing"]
            ))

            # Security recommendations
            if minimum < 60:
                findings.append(make_finding(
                    entity=f"Low minimum TTL ({minimum}s) may indicate dynamic DNS",
                    type="SOA Security Suggestion",
                    source="DNS Deep Forensics",
                    confidence="Medium",
                    color="yellow",
                    threat_level="Informational",
                    raw_data=f"Minimum TTL of {minimum}s is very low",
                    tags=["soa", "ttl", "suggestion"]
                ))
            if expire < 604800:
                findings.append(make_finding(
                    entity=f"Low expire time ({expire}s) - secondary NS may drop zone quickly",
                    type="SOA Security Suggestion",
                    source="DNS Deep Forensics",
                    confidence="Medium",
                    color="yellow",
                    threat_level="Informational",
                    raw_data=f"Expire time of {expire}s is below recommended 7 days (604800s)",
                    tags=["soa", "expire", "suggestion"]
                ))

            # Interpret serial as date format (YYYYMMDDNN)
            serial_str = str(serial)
            if len(serial_str) >= 8 and serial_str[:4].isdigit():
                year = serial_str[:4]
                month = serial_str[4:6]
                day = serial_str[6:8]
                findings.append(make_finding(
                    entity=f"Serial {serial} possibly date-based: {year}-{month}-{day}",
                    ftype="SOA Serial Date Interpretation",
                    source="DNS Deep Forensics",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    raw_data=f"Serial number format suggests YYYYMMDD: {year}-{month}-{day}",
                    tags=["soa", "serial", "date"]
                ))
    except:
        pass
    return findings

async def check_dmarc_dkim_spf_deep(domain):
    findings = []
    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for r in txt_answers:
            txt = str(r)
            if txt.startswith("v=spf1"):
                redirects = re.findall(r'redirect=(\S+)', txt)
                includes = re.findall(r'include:(\S+)', txt)
                has_all = "+all" in txt or "?all" in txt
                has_hard_fail = "-all" in txt
                soft_fail = "~all" in txt

                spf_status = "STRICT" if has_hard_fail else "SOFT" if soft_fail else "WEAK" if has_all else "NEUTRAL"
                spf_color = "green" if has_hard_fail else "yellow" if soft_fail else "red" if has_all else "orange"

                findings.append(make_finding(
                    entity=f"SPF: {txt[:200]}",
                    ftype=f"SPF Record ({spf_status})",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color=spf_color,
                    threat_level="Elevated Risk" if has_all else "Informational",
                    raw_data=f"SPF: {txt}",
                    tags=["spf", "email-security", spf_status.lower()]
                ))

                if includes:
                    for inc in includes[:3]:
                        findings.append(make_finding(
                            entity=f"SPF includes: {inc}",
                            ftype="SPF Include Mechanism",
                            source="DNS Deep Forensics",
                            confidence="Medium",
                            color="blue",
                            threat_level="Informational",
                            raw_data=f"SPF include: {inc}",
                            tags=["spf", "include"]
                        ))

                if has_all:
                    findings.append(make_finding(
                        entity=f"DANGEROUS SPF '+all' on {domain}! Any server can send email as this domain",
                        ftype="SPF Critical Weakness",
                        source="DNS Deep Forensics",
                        confidence="Certain",
                        color="red",
                        threat_level="High",
                        status="VULNERABLE",
                        raw_data=f"SPF record contains '+all': {txt[:200]}",
                        tags=["spf", "critical", "spoofing"]
                    ))
    except:
        pass

    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in dmarc_answers:
            dmarc = str(r)
            policy = re.search(r'p=(\w+)', dmarc)
            sp_policy = re.search(r'sp=(\w+)', dmarc)
            pct = re.search(r'pct=(\d+)', dmarc)
            rua = re.search(r'rua=([^\s;]+)', dmarc)
            ruf = re.search(r'ruf=([^\s;]+)', dmarc)
            pct_val = pct.group(1) if pct else "100"
            policy_val = policy.group(1) if policy else "none"
            sp_val = sp_policy.group(1) if sp_policy else "none"

            dmarc_color = "green" if policy_val == "reject" else "yellow" if policy_val == "quarantine" else "red"
            dmarc_level = "Informational" if policy_val == "reject" else "Elevated Risk" if policy_val == "none" else "Standard Target"

            findings.append(make_finding(
                entity=f"DMARC: p={policy_val}, sp={sp_val}, pct={pct_val}",
                ftype=f"DMARC Policy ({policy_val.upper()})",
                source="DNS Deep Forensics",
                confidence="High",
                color=dmarc_color,
                threat_level=dmarc_level,
                raw_data=dmarc[:500],
                tags=["dmarc", "email-security", f"policy-{policy_val}"]
            ))

            if rua:
                findings.append(make_finding(
                    entity=f"DMARC reports sent to: {rua.group(1)}",
                    type="DMARC Reporting",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"DMARC RUA: {rua.group(1)}",
                    tags=["dmarc", "reporting"]
                ))
            if ruf:
                findings.append(make_finding(
                    entity=f"DMARC forensic reports to: {ruf.group(1)}",
                    type="DMARC Forensic Reporting",
                    source="DNS Deep Forensics",
                    confidence="Medium",
                    color="blue",
                    threat_level="Informational",
                    raw_data=f"DMARC RUF: {ruf.group(1)}",
                    tags=["dmarc", "forensic"]
                ))

            if policy_val == "none":
                findings.append(make_finding(
                    entity=f"DMARC policy is 'none' on {domain} - no email protection!",
                    ftype="DMARC Weakness",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="No Protection",
                    raw_data=f"DMARC policy 'none' means no action is taken on failing emails: {dmarc[:300]}",
                    tags=["dmarc", "weakness", "no-protection"]
                ))
    except:
        pass

    dkim_selectors = ['default', 'google', 'mail', 'k1', 'dkim', 'mx', 'selector1', 'selector2', 's1', 's2', 'protonmail', 'zoho', 'mailgun', 'sendgrid', 'mandrill', 'sparkpost', 'postmark', 'amazonses', 'smtp', 'email', 'secure', '2016', '2017', '2018', '2019', '2020', '2021', '2022', '2023', '2024', '2025', '2026']
    for selector in dkim_selectors:
        try:
            dkim_answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            for r in dkim_answers:
                dkim_text = str(r)
                dkim_type = "DKIM"
                dkim_color = "emerald"
                if "v=DKIM1" in dkim_text or "v=DKIM1" in dkim_text.upper():
                    dkim_type = "DKIM v1"
                findings.append(make_finding(
                    entity=f"DKIM ({selector}): {dkim_text[:200]}",
                    type=dkim_type,
                    source="DNS Deep Forensics",
                    confidence="High",
                    color=dkim_color,
                    threat_level="Informational",
                    status="DKIM Found",
                    raw_data=f"DKIM selector '{selector}': {dkim_text[:1000]}",
                    tags=["dkim", "email-security", f"selector-{selector}"]
                ))
        except:
            pass

    return findings

async def check_nsec_walking(domain):
    findings = []
    try:
        nsec_answers = dns.resolver.resolve(domain, 'NSEC')
        for nsec in nsec_answers:
            next_domain = str(nsec.next).rstrip('.')
            type_bitmaps = str(nsec.rdtypes) if hasattr(nsec, 'rdtypes') else "?"
            findings.append(make_finding(
                entity=f"NSEC: {domain} -> {next_domain} ({type_bitmaps})",
                type="NSEC Record (Zone Walking Possible)",
                source="DNS Deep Forensics",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                raw_data=f"NSEC record reveals next domain: {next_domain}. This enables zone enumeration via NSEC walking!",
                tags=["nsec", "zone-walking", "enumeration-risk"]
            ))
    except:
        try:
            nsec3_answers = dns.resolver.resolve(domain, 'NSEC3')
            for nsec3 in nsec3_answers:
                try:
                    salt = nsec3.salt.hex() if nsec3.salt else "none"
                    iterations = nsec3.iterations
                    next_hashed = nsec3.next.hex() if hasattr(nsec3, 'next') else "?"
                    findings.append(make_finding(
                        entity=f"NSEC3: salt={salt}, iterations={iterations}",
                        ftype="NSEC3 Record (NSEC3 Present)",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        raw_data=f"NSEC3 parameters: salt={salt}, iterations={iterations}, algorithm={nsec3.algorithm}",
                        tags=["nsec3", "dnssec"]
                    ))
                    findings.append(make_finding(
                        entity=f"NSEC3 mitigated zone walking (salt={salt}, iter={iterations})",
                        type="NSEC3 Mitigation Status",
                        source="DNS Deep Forensics",
                        confidence="Medium",
                        color="green",
                        threat_level="Informational",
                        raw_data=f"NSEC3 with salt and {iterations} iterations provides some protection against zone walking",
                        tags=["nsec3", "mitigation"]
                    ))
                except:
                    pass
        except:
            pass
    return findings

async def check_mx_security(domain):
    findings = []
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for mx in mx_answers:
            mx_host = str(mx.exchange).rstrip('.')
            mx_pref = mx.preference
            findings.append(make_finding(
                entity=f"MX {mx_pref}: {mx_host}",
                ftype="MX Record",
                source="DNS Deep Forensics",
                confidence="High",
                color="slate",
                threat_level="Informational",
                raw_data=f"MX preference {mx_pref} -> {mx_host}",
                tags=["mx", "email"]
            ))
            try:
                mx_a = dns.resolver.resolve(mx_host, 'A')
                for ip in mx_a:
                    findings.append(make_finding(
                        entity=f"MX {mx_host} -> {str(ip)}",
                        type="MX Server IP Resolution",
                        source="DNS Deep Forensics",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        resolution=str(ip),
                        raw_data=f"MX host {mx_host} resolves to {str(ip)}",
                        tags=["mx", "ip", "email"]
                    ))
                    try:
                        ptr = dns.resolver.resolve(dns.reversename.from_address(str(ip)), 'PTR')
                        for p in ptr:
                            findings.append(make_finding(
                                entity=f"PTR: {ip} -> {str(p)}",
                                type="MX Server PTR Record",
                                source="DNS Deep Forensics",
                                confidence="Medium",
                                color="blue",
                                threat_level="Informational",
                                raw_data=f"Reverse DNS: {ip} = {str(p)}",
                                tags=["mx", "ptr", "email"]
                            ))
                    except:
                        findings.append(make_finding(
                            entity=f"No PTR record for MX IP {ip}",
                            ftype="Missing MX PTR Record",
                            source="DNS Deep Forensics",
                            confidence="Medium",
                            color="yellow",
                            threat_level="Informational",
                            raw_data=f"MX server IP {ip} has no reverse DNS - may affect deliverability",
                            tags=["mx", "missing-ptr", "email"]
                        ))
            except:
                pass
    except:
        pass
    return findings

async def crawl(target, client):
    findings = []

    # Collect all forensics data
    tasks = [
        check_ns_delegation(target),
        check_soa_analysis(target),
        check_dnssec_analysis(target),
        check_cname_chain(target),
        check_mx_security(target),
        check_dmarc_dkim_spf_deep(target),
        check_nsec_walking(target),
    ]

    zone_transfer_results = await check_zone_transfer(target)
    findings.extend(zone_transfer_results)

    all_results = await asyncio.gather(*tasks)
    for result_list in all_results:
        findings.extend(result_list)

    # DNS Record Analysis (basic)
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'SPF', 'SOA', 'SRV', 'NS', 'CNAME', 'CAA']
    async def check_record(rtype):
        recs = []
        try:
            answers = await asyncio.get_event_loop().run_in_executor(None, lambda: dns.resolver.resolve(target, rtype))
            for rdata in answers:
                val = str(rdata)
                recs.append(make_finding(
                    entity=val[:300],
                    ftype=f"DNS {rtype} Record",
                    source="DNS Deep Forensics",
                    confidence="High",
                    color="blue",
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"Found {rtype} record for {target}: {val[:2000]}",
                    tags=["dns", rtype.lower()]
                ))
            return recs
        except:
            return []

    tasks = [check_record(rtype) for rtype in record_types]
    results = await asyncio.gather(*tasks)
    for rlist in results:
        findings.extend(rlist)

    return findings
