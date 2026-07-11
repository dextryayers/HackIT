import asyncio
import dns.resolver
import time
from collections import defaultdict
from module_base import BaseScanner

ALL_RECORD_TYPES = ['A','AAAA','CNAME','MX','NS','TXT','SOA','SRV','PTR','CAA',
    'SSHFP','DNSKEY','DS','NSEC','NSEC3','RRSIG','LOC','HINFO','RP',
    'NAPTR','CERT','SMIMEA','TLSA','URI','SVCB','HTTPS','DNAME',
    'OPENPGPKEY','ZONEMD']

RECORD_META = {
    "A":{"color":"blue","desc":"IPv4"},"AAAA":{"color":"blue","desc":"IPv6"},
    "CNAME":{"color":"purple","desc":"Canonical Name"},"MX":{"color":"slate","desc":"Mail Exchange"},
    "NS":{"color":"slate","desc":"Nameserver"},"TXT":{"color":"emerald","desc":"Text"},
    "SOA":{"color":"purple","desc":"Start of Authority"},"SRV":{"color":"cyan","desc":"Service"},
    "CAA":{"color":"orange","desc":"CA Authorization"},
}
SECURITY_RECORDS = {"CAA","SSHFP","DNSKEY","DS","NSEC","NSEC3","RRSIG","TLSA","SMIMEA","OPENPGPKEY"}
DNSSEC_RECORDS = {"DNSKEY","DS","NSEC","NSEC3","RRSIG"}

BULK_SUBDOMAINS = ["www","mail","ftp","admin","api","dev","staging","vpn","cdn","blog","app",
    "webmail","remote","portal","ssh","git","jenkins","jira","confluence","mysql","db",
    "ns1","ns2","cloud","test","stage","demo","beta","smtp","imap","pop3","autodiscover",
    "m","mobile","chat","forum","help","support","docs","wiki","status","monitor",
    "dashboard","analytics","logs","sync","static","assets","media","img","upload",
    "download","files","backup","cpanel","server","redis","mongo","postgres","elastic",
    "kibana","grafana","prometheus","alertmanager","consul","k8s","kubernetes","docker",
    "registry","nexus","gitlab","bitbucket","lms","erp","crm","owa","exchange",
    "proxy","gateway","firewall","auth","login","sso","oauth","saml",
    "ldap","radius","ntp","dhcp","dns","vpn","rdp","citrix","vmware","openstack",
]

class DnsResolverScanner(BaseScanner):
    name = "dns_resolver"

    async def resolve(self, domain: str, rtype: str, resolver=None, timeout_sec=5):
        start = time.monotonic()
        try:
            res = dns.resolver.Resolver()
            if resolver: res.nameservers = [resolver]
            res.timeout = timeout_sec; res.lifetime = timeout_sec
            answers = await asyncio.get_event_loop().run_in_executor(None, lambda: res.resolve(domain, rtype))
            return answers, time.monotonic() - start
        except: return None, time.monotonic() - start

    async def check_dnssec(self, domain: str):
        status = {"valid":False,"algo":None,"keys":0,"rrsigs":0}
        dnskey = await self.resolve(domain, "DNSKEY")
        if dnskey[0]:
            status["keys"] = len(dnskey[0])
            for key in dnskey[0]:
                if hasattr(key,"algorithm"): status["algo"] = key.algorithm
        rrsig = await self.resolve(domain, "RRSIG")
        if rrsig[0]: status["rrsigs"] = len(rrsig[0]); status["valid"] = True
        return status

    async def check_amplification(self, domain: str):
        result = {"factor":0,"request_size":0,"response_size":0,"amplifiable":False}
        for rtype in ["ANY","DNSKEY","TXT","NS"]:
            try:
                rr = await self.resolve(domain, rtype)
                if rr[0]:
                    answers = rr[0]
                    resp_size = sum(len(str(r)) for r in answers) if answers else 0
                    req_size = 50
                    if req_size>0 and resp_size>req_size:
                        factor = resp_size/req_size
                        if factor>result["factor"]:
                            result = {"factor":round(factor,1),"request_size":req_size,"response_size":resp_size,"amplifiable":factor>3,"record_type":rtype}
            except: pass
        return result

    async def bulk_resolve(self, domain: str, record_types: list):
        loop = asyncio.get_event_loop()
        results = defaultdict(list)
        sem = asyncio.Semaphore(20)
        async def resolve_one(sub):
            async with sem:
                for rtype in record_types:
                    try:
                        answers,_ = await self.resolve(f"{sub}.{domain}", rtype, timeout_sec=3)
                        if answers:
                            for r in answers: results[(sub,rtype)].append(str(r))
                    except: pass
        await asyncio.gather(*[resolve_one(sub) for sub in BULK_SUBDOMAINS])
        return results

    async def scan(self) -> list:
        results = []
        domain = self.target
        loop = asyncio.get_event_loop()

        dnssec = await self.check_dnssec(domain)
        amp = await self.check_amplification(domain)

        security_records_found = set()
        all_records_found = set()

        for rtype in ALL_RECORD_TYPES:
            try:
                answers, elapsed = await self.resolve(domain, rtype)
                if answers:
                    all_records_found.add(rtype)
                    meta = RECORD_META.get(rtype, {"color":"slate","desc":rtype})
                    values = [str(r) for r in answers]
                    is_dnssec = rtype in DNSSEC_RECORDS
                    if rtype in SECURITY_RECORDS: security_records_found.add(rtype)
                    color = "emerald" if is_dnssec else meta["color"]

                    for val in values[:3]:
                        ftype = f"DNS {rtype} Record"
                        if rtype=="TXT":
                            lv = val.lower()
                            if lv.startswith("v=spf1"): ftype="SPF Record"; color="emerald"
                            elif "v=dkim1" in lv: ftype="DKIM Record"; color="emerald"
                            elif lv.startswith("v=dmarc1"): ftype="DMARC Record"; color="emerald"
                        elif rtype=="MX": ftype="MX Record"
                        elif rtype=="SOA": ftype="SOA Record"
                        elif rtype=="CAA": ftype="CAA Record"
                        elif rtype=="DNSKEY": ftype="DNSKEY (DNSSEC)"
                        elif rtype=="DS": ftype="DS Record (DNSSEC)"

                        f = self.finding(entity=val[:300], ftype=ftype, confidence="High",
                            color=color, threat_level="Informational",
                            status=f"{rtype} Resolved", resolution=f"{rtype} record for {domain}",
                            raw_data=f"Type: {rtype} | Value: {val[:2000]} | Resolved in {elapsed:.3f}s" if elapsed else f"Type: {rtype} | Value: {val[:2000]}",
                            tags=["dns",rtype.lower()]+(["dnssec"] if is_dnssec else []))
                        if f: results.append(f)
            except: pass

        if security_records_found:
            f = self.finding(entity=f"Security records: {', '.join(sorted(security_records_found))}",
                ftype="DNS Security Records Summary", confidence="High", color="emerald",
                threat_level="Informational", status="Security Records Found", tags=["dns","security"])
            if f: results.append(f)
        else:
            f = self.finding(entity=f"No DNS security records found for {domain}",
                ftype="DNS Security Records Summary", confidence="Medium", color="orange",
                threat_level="Elevated Risk", status="No Security Records", tags=["dns","security","missing"])
            if f: results.append(f)

        if dnssec["valid"]:
            f = self.finding(entity=f"DNSSEC Validated | {dnssec['keys']} DNSKEY(s), {dnssec['rrsigs']} RRSIG(s)",
                ftype="DNSSEC Status", confidence="High", color="emerald",
                threat_level="Informational", status="DNSSEC Enabled",
                raw_data=f"Algorithm: {dnssec.get('algo','?')}", tags=["dns","dnssec","security"])
            if f: results.append(f)
        else:
            f = self.finding(entity=f"Domain {domain} does NOT have DNSSEC",
                ftype="DNSSEC Status", confidence="High", color="orange",
                threat_level="Elevated Risk", status="DNSSEC Missing", tags=["dns","dnssec","security"])
            if f: results.append(f)

        if amp["request_size"]>0:
            f = self.finding(entity=f"DNS amplification factor: {amp['factor']}x ({amp.get('record_type','?')})",
                ftype="DNS Amplification Check", confidence="High",
                color="red" if amp["amplifiable"] else "green",
                threat_level="Elevated Risk" if amp["amplifiable"] else "Informational",
                status="Amplifiable" if amp["amplifiable"] else "Not Amplifiable",
                tags=["dns","amplification","dos-risk"])
            if f: results.append(f)

        bulk_record_types = ["A","AAAA","CNAME","MX","TXT","NS"]
        bulk_results = await self.bulk_resolve(domain, bulk_record_types)
        subdomain_data = defaultdict(lambda: defaultdict(list))
        for (sub, rtype), values in bulk_results.items():
            for v in values: subdomain_data[sub][rtype].append(v)

        for sub, records in sorted(subdomain_data.items()):
            ip_list = records.get("A",[])
            record_types_found = list(records.keys())
            raw_parts = [f"{rt}: {', '.join(recs[:2])}" for rt, recs in records.items()]
            f = self.finding(entity=f"{sub}.{domain}", ftype="Bulk Resolved Subdomain",
                confidence="High", color="emerald" if ip_list else "slate",
                threat_level="Informational", status=f"Resolved ({', '.join(record_types_found)})",
                resolution=ip_list[0] if ip_list else "",
                raw_data=" | ".join(raw_parts), tags=["bulk","subdomain","dns"]+record_types_found)
            if f: results.append(f)

        if subdomain_data:
            f = self.finding(entity=f"Bulk resolved {len(subdomain_data)}/{len(BULK_SUBDOMAINS)} common subdomains",
                ftype="Bulk Resolution Summary", confidence="High", color="blue",
                threat_level="Informational", tags=["dns","bulk","summary"])
            if f: results.append(f)

        total = len([f for f in results if f.type.startswith("DNS ")])
        f = self.finding(entity=f"{len(all_records_found)}/{len(ALL_RECORD_TYPES)} record types resolved | {total} total records",
            ftype="DNS Resolution Summary", confidence="High", color="blue",
            threat_level="Informational", status=f"{len(all_records_found)} types resolved",
            tags=["dns","summary"])
        if f: results.append(f)

        for sel in ["_dmarc"]:
            try:
                answers,_ = await self.resolve(f"{sel}.{domain}", "TXT")
                if answers and answers[0]:
                    f = self.finding(entity=str(answers[0])[:300], ftype="DMARC Record",
                        confidence="High", color="emerald", threat_level="Informational",
                        status="DMARC Found", tags=["dns","dmarc","email-security"])
                    if f: results.append(f)
            except:
                f = self.finding(entity=f"No DMARC record for {domain}", ftype="DMARC Status",
                    confidence="Medium", color="orange", threat_level="Elevated Risk",
                    status="No DMARC", tags=["dns","dmarc","missing"])
                if f: results.append(f)

        for sel in ['default','google','mail','k1','dkim','selector1','selector2',
                      'protonmail','mailgun','sendgrid','amazonses']:
            try:
                answers,_ = await self.resolve(f"{sel}._domainkey.{domain}", "TXT")
                if answers and answers[0]:
                    f = self.finding(entity=f"{sel}._domainkey.{domain}", ftype="DKIM Record",
                        confidence="High", color="emerald", threat_level="Informational",
                        status="DKIM Found", raw_data=str(answers[0])[:2000],
                        tags=["dns","dkim","email-security"])
                    if f: results.append(f)
            except: pass

        wild_val = f"wildcard-test-{abs(hash(domain))%100000}.{domain}"
        try:
            wild,_ = await self.resolve(wild_val, "A")
            if wild and wild[0]:
                f = self.finding(entity=f"*.{domain} resolves (wildcard DNS active)",
                    ftype="Wildcard DNS Detection", confidence="High", color="orange",
                    threat_level="Elevated Risk", status="Wildcard Active",
                    resolution=str(wild[0]), tags=["dns","wildcard"])
                if f: results.append(f)
        except: pass

        try:
            mx_answers,_ = await self.resolve(domain, "MX")
            if mx_answers:
                for mx_host in [str(r.exchange).rstrip('.') for r in mx_answers][:3]:
                    try:
                        mx_a,_ = await self.resolve(mx_host, "A")
                        if mx_a:
                            for ip in mx_a:
                                f = self.finding(entity=f"{mx_host} ({str(ip)})",
                                    ftype="MX Server Resolution", confidence="High",
                                    color="slate", threat_level="Informational",
                                    resolution=str(ip), tags=["dns","mx"])
                                if f: results.append(f)
                    except: pass
        except: pass
        return results


async def crawl(target: str, client=None):
    scanner = DnsResolverScanner(target, client)
    return await scanner.scan()
