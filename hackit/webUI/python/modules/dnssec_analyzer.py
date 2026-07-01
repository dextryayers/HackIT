import asyncio
import dns.resolver
import dns.name
from models import IntelligenceFinding

ALGORITHM_MAP = {
    5: "RSASHA1", 7: "RSASHA1-NSEC3", 8: "RSASHA256", 10: "RSASHA512",
    13: "ECDSA-P256", 14: "ECDSA-P384", 15: "Ed25519", 16: "Ed448",
    3: "DSA", 6: "DSA-NSEC3", 12: "ECC-GOST", 17: "EC-GOST",
}

DNSSEC_RECORDS = ['DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY']

async def resolve_rtype(domain: str, rtype: str):
    loop = asyncio.get_event_loop()
    try:
        answers = await loop.run_in_executor(None, lambda: dns.resolver.resolve(domain, rtype))
        return list(answers)
    except:
        return []

async def crawl(target: str, client=None):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    dnskey_records = await resolve_rtype(domain, 'DNSKEY')
    ds_records = await resolve_rtype(domain, 'DS')
    rrsig_records = await resolve_rtype(domain, 'RRSIG')
    nsec_records = await resolve_rtype(domain, 'NSEC')
    nsec3_records = await resolve_rtype(domain, 'NSEC3')
    nsec3param = await resolve_rtype(domain, 'NSEC3PARAM')
    cds_records = await resolve_rtype(domain, 'CDS')
    cdnskey_records = await resolve_rtype(domain, 'CDNSKEY')

    algorithms_used = set()
    key_sizes = []
    sig_count = 0

    for key in dnskey_records:
        algo = getattr(key, 'algorithm', 0)
        algo_name = ALGORITHM_MAP.get(algo, f"Unknown-{algo}")
        algorithms_used.add(algo_name)
        key_tag = getattr(key, 'key_tag', 0)
        flags = getattr(key, 'flags', 0)
        zone_key = bool(flags & 256)
        secure_entry = bool(flags & 512)
        key_len = len(getattr(key, 'key', b'')) * 8 if hasattr(key, 'key') else 0
        key_sizes.append(key_len)
        findings.append(IntelligenceFinding(
            entity=f"DNSKEY: algorithm={algo_name}, flags={flags}, key_tag={key_tag}, key_size={key_len}bits",
            type="DNSSEC DNSKEY Record",
            source="DNSSEC Analyzer",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Active",
            raw_data=f"Algorithm: {algo_name} ({algo}) | Flags: {flags} | Key Tag: {key_tag} | Size: {key_len}bits | ZSK: {zone_key} | SEP: {secure_entry}",
            tags=["dnssec", "dnskey", algo_name.lower()]
        ))

    if dnskey_records:
        if algorithms_used:
            findings.append(IntelligenceFinding(
                entity=f"Algorithms used: {', '.join(sorted(algorithms_used))}",
                type="DNSSEC Algorithm Analysis",
                source="DNSSEC Analyzer",
                confidence="High",
                color="blue",
                threat_level="Informational",
                status="Analyzed",
                raw_data=f"Algorithms: {', '.join(sorted(algorithms_used))} | Key Count: {len(dnskey_records)}",
                tags=["dnssec", "algorithm"]
            ))
        modern = {'ECDSA-P256', 'ECDSA-P384', 'Ed25519', 'Ed448'}
        if algorithms_used & modern:
            findings.append(IntelligenceFinding(
                entity=f"Modern algorithms detected: {', '.join(sorted(algorithms_used & modern))}",
                type="DNSSEC Modern Algorithm",
                source="DNSSEC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Modern",
                tags=["dnssec", "modern", "strong-crypto"]
            ))
        weak = {'RSASHA1', 'RSASHA1-NSEC3', 'DSA'}
        if algorithms_used & weak:
            findings.append(IntelligenceFinding(
                entity=f"Weak algorithm detected: {', '.join(sorted(algorithms_used & weak))}",
                type="DNSSEC Weak Algorithm",
                source="DNSSEC Analyzer",
                confidence="High",
                color="red",
                threat_level="Elevated Risk",
                status="Weak Algorithm",
                tags=["dnssec", "weak", "deprecated"]
            ))
        if key_sizes:
            small_keys = [s for s in key_sizes if s < 1024]
            if small_keys:
                findings.append(IntelligenceFinding(
                    entity=f"Small DNSKEY sizes: {', '.join(map(str, small_keys))} bits",
                    type="DNSSEC Key Size Warning",
                    source="DNSSEC Analyzer",
                    confidence="High",
                    color="red",
                    threat_level="Elevated Risk",
                    status="Small Key",
                    raw_data=f"Keys below 1024 bits: {small_keys}",
                    tags=["dnssec", "key-size", "weak"]
                ))

    for ds in ds_records:
        key_tag_ds = getattr(ds, 'key_tag', 0)
        algo_ds = getattr(ds, 'algorithm', 0)
        algo_ds_name = ALGORITHM_MAP.get(algo_ds, f"Unknown-{algo_ds}")
        digest_type = getattr(ds, 'digest_type', 0)
        digest_bytes = getattr(ds, 'digest', b'')
        digest_hex = digest_bytes.hex() if digest_bytes else ''
        findings.append(IntelligenceFinding(
            entity=f"DS: key_tag={key_tag_ds}, algo={algo_ds_name}, digest_type={digest_type}, digest={digest_hex[:32]}",
            type="DNSSEC DS Record",
            source="DNSSEC Analyzer",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="Active",
            raw_data=f"Key Tag: {key_tag_ds} | Algorithm: {algo_ds_name} | Digest Type: {digest_type} | Digest: {digest_hex}",
            tags=["dnssec", "ds"]
        ))

    if ds_records and dnskey_records:
        ds_tags = {getattr(ds, 'key_tag', 0) for ds in ds_records}
        dnskey_tags = {getattr(k, 'key_tag', 0) for k in dnskey_records if getattr(k, 'flags', 0) & 512}
        matching = ds_tags & dnskey_tags
        if matching:
            findings.append(IntelligenceFinding(
                entity=f"DS/DNSKEY chain valid: {len(matching)} KSK(s) matched",
                type="DNSSEC Chain Validation",
                source="DNSSEC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Chain Valid",
                raw_data=f"Matched KSK tags: {matching}",
                tags=["dnssec", "chain", "valid"]
            ))
        else:
            findings.append(IntelligenceFinding(
                entity=f"DS/DNSKEY chain mismatch! DS tags: {ds_tags}, SEP tags: {dnskey_tags}",
                type="DNSSEC Chain Mismatch",
                source="DNSSEC Analyzer",
                confidence="High",
                color="red",
                threat_level="High Risk",
                status="Chain Broken",
                tags=["dnssec", "chain", "broken"]
            ))

    for sig in rrsig_records:
        sig_count += 1
        type_covered = getattr(sig, 'type_covered', 0)
        algo_sig = getattr(sig, 'algorithm', 0)
        algo_sig_name = ALGORITHM_MAP.get(algo_sig, f"Unknown-{algo_sig}")
        labels = getattr(sig, 'labels', 0)
        orig_ttl = getattr(sig, 'original_ttl', 0)
        sig_exp = getattr(sig, 'expiration', 0)
        sig_inc = getattr(sig, 'inception', 0)
        key_tag_sig = getattr(sig, 'key_tag', 0)
        covered_name = dns.rdatatype.to_text(type_covered) if type_covered else '?'
        if sig_count <= 5:
            findings.append(IntelligenceFinding(
                entity=f"RRSIG: covers {covered_name}, algo={algo_sig_name}, key_tag={key_tag_sig}, labels={labels}",
                type="DNSSEC RRSIG Record",
                source="DNSSEC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Active",
                raw_data=f"Type Covered: {covered_name} | Algorithm: {algo_sig_name} | Key Tag: {key_tag_sig} | Labels: {labels} | Original TTL: {orig_ttl}",
                tags=["dnssec", "rrsig"]
            ))

    if rrsig_records:
        findings.append(IntelligenceFinding(
            entity=f"Total RRSIGs: {sig_count} covering zone records",
            type="DNSSEC Signature Count",
            source="DNSSEC Analyzer",
            confidence="High",
            color="blue",
            threat_level="Informational",
            status=f"{sig_count} Signatures",
            tags=["dnssec", "rrsig", "count"]
        ))

    if nsec_records:
        for nsec in nsec_records[:3]:
            next_domain = getattr(nsec, 'next', '')
            type_bitmaps = getattr(nsec, 'bitmap', [])
            findings.append(IntelligenceFinding(
                entity=f"NSEC: {domain} -> {next_domain}, types: {len(type_bitmaps)}",
                type="DNSSEC NSEC Record",
                source="DNSSEC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Active",
                tags=["dnssec", "nsec"]
            ))
        findings.append(IntelligenceFinding(
            entity=f"NSEC (denial of existence) enabled - zone walking possible",
            type="DNSSEC NSEC Warning",
            source="DNSSEC Analyzer",
            confidence="High",
            color="orange",
            threat_level="Standard Target",
            status="NSEC Enabled",
            tags=["dnssec", "nsec", "zone-walk"]
        ))

    if nsec3_records:
        for nsec3 in nsec3_records[:3]:
            salt = getattr(nsec3, 'salt', b'')
            iterations = getattr(nsec3, 'iterations', 0)
            algo_nsec3 = getattr(nsec3, 'algorithm', 0)
            findings.append(IntelligenceFinding(
                entity=f"NSEC3: algo={algo_nsec3}, iterations={iterations}, salt_len={len(salt)}",
                type="DNSSEC NSEC3 Record",
                source="DNSSEC Analyzer",
                confidence="High",
                color="emerald",
                threat_level="Informational",
                status="Active",
                tags=["dnssec", "nsec3"]
            ))
        if nsec3param:
            for p in nsec3param:
                findings.append(IntelligenceFinding(
                    entity=f"NSEC3PARAM: algo={getattr(p, 'algorithm', 0)}, iterations={getattr(p, 'iterations', 0)}, salt={getattr(p, 'salt', b'').hex()[:16]}",
                    type="DNSSEC NSEC3PARAM",
                    source="DNSSEC Analyzer",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Active",
                    tags=["dnssec", "nsec3param"]
                ))

    if cds_records:
        for cds in cds_records:
            findings.append(IntelligenceFinding(
                entity=f"CDS: key_tag={getattr(cds, 'key_tag', 0)}, algo={getattr(cds, 'algorithm', 0)}, digest_type={getattr(cds, 'digest_type', 0)}",
                type="DNSSEC CDS Record",
                source="DNSSEC Analyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Active",
                tags=["dnssec", "cds"]
            ))

    if cdnskey_records:
        for ck in cdnskey_records:
            findings.append(IntelligenceFinding(
                entity=f"CDNSKEY: algo={getattr(ck, 'algorithm', 0)}, flags={getattr(ck, 'flags', 0)}, key_tag={getattr(ck, 'key_tag', 0)}",
                type="DNSSEC CDNSKEY Record",
                source="DNSSEC Analyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                status="Active",
                tags=["dnssec", "cdnskey"]
            ))

    has_dnskey = len(dnskey_records) > 0
    has_ds = len(ds_records) > 0
    has_rrsig = len(rrsig_records) > 0

    if has_dnskey and has_ds and has_rrsig:
        findings.append(IntelligenceFinding(
            entity=f"Full DNSSEC chain: {len(dnskey_records)} DNSKEY, {len(ds_records)} DS, {sig_count} RRSIG",
            type="DNSSEC Status: Complete",
            source="DNSSEC Analyzer",
            confidence="High",
            color="emerald",
            threat_level="Informational",
            status="DNSSEC Secured",
            raw_data=f"DNSKEY: {len(dnskey_records)} | DS: {len(ds_records)} | RRSIG: {sig_count} | NSEC: {len(nsec_records)} | NSEC3: {len(nsec3_records)}",
            tags=["dnssec", "complete"]
        ))
    elif has_dnskey and has_rrsig and not has_ds:
        findings.append(IntelligenceFinding(
            entity=f"DNSSEC partially enabled: DNSKEY+RRSIG present but NO DS in parent zone",
            type="DNSSEC Status: Partial (Missing DS)",
            source="DNSSEC Analyzer",
            confidence="High",
            color="orange",
            threat_level="Elevated Risk",
            status="Missing DS",
            tags=["dnssec", "partial", "missing-ds"]
        ))
    else:
        findings.append(IntelligenceFinding(
            entity=f"No DNSSEC records found for {domain}",
            type="DNSSEC Status: Not Enabled",
            source="DNSSEC Analyzer",
            confidence="High",
            color="red",
            threat_level="Elevated Risk",
            status="No DNSSEC",
            raw_data="Domain is vulnerable to DNS spoofing and cache poisoning attacks",
            tags=["dnssec", "missing", "vulnerable"]
        ))

    if not nsec_records and not nsec3_records:
        findings.append(IntelligenceFinding(
            entity=f"No NSEC/NSEC3 records - cannot verify denial of existence",
            type="DNSSEC Denial of Existence",
            source="DNSSEC Analyzer",
            confidence="Medium",
            color="orange",
            threat_level="Standard Target",
            status="Not Verified",
            tags=["dnssec", "denial-of-existence"]
        ))

    return findings
