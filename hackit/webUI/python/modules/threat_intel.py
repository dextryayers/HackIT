import httpx
import asyncio
import re
from collections import defaultdict
from module_base import BaseScanner

THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://threatfox.abuse.ch/export/json/ip/",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "https://raw.githubusercontent.com/scriptzteam/Threat-Intelligence/master/ips.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://www.dshield.org/block.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://malc0de.com/bl/IP_Blacklist.txt",
    "https://www.binarydefense.com/banlist.txt",
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/piwik/referrer-spam-blacklist/master/spammers.txt",
]
ADDITIONAL_FEEDS = [
    ("URLhaus","https://urlhaus.abuse.ch/downloads/text/"),
    ("Spamhaus DROP","https://www.spamhaus.org/drop/drop.txt"),
    ("OpenPhish Feed","https://openphish.com/feed.txt"),
    ("AlienVault Reputation","https://reputation.alienvault.com/reputation.data"),
    ("Greensnow","https://blocklist.greensnow.co/greensnow.txt"),
    ("Tor Exit Nodes","https://check.torproject.org/torbulkexitlist"),
]

class ThreatIntelScanner(BaseScanner):
    name = "threat_intel"

    async def fetch_feed(self, url: str) -> dict:
        result = {"name": url.split("/")[-1], "iocs": [], "source_url": url}
        try:
            resp = await self.safe_request(url, timeout=20, headers={"User-Agent":"Mozilla/5.0"})
            if resp and resp.status_code==200:
                for line in resp.text.splitlines()[:500]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        for ioc_type, pat in [("ipv4",r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
                                               ("domain",r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'),
                                               ("url",r'https?://[^\s<>"]+')]:
                            for m in re.findall(pat, line):
                                result["iocs"].append({"type":ioc_type,"value":m})
        except: pass
        return result

    async def fetch_additional(self, name: str, url: str) -> dict:
        try:
            resp = await self.safe_request(url, timeout=20, headers={"User-Agent":"Mozilla/5.0"})
            if resp and resp.status_code==200:
                lines = resp.text.splitlines()
                ips = sum(1 for l in lines[:300] if l.strip() and not l.startswith("#") and re.match(r'\d+\.\d+\.\d+\.\d+', l.strip()))
                return {"name":name,"url":url,"ips":ips,"total_lines":len(lines)}
        except: pass
        return {"name":name,"ips":0,"total_lines":0}

    async def scan(self) -> list:
        results = []
        query = self.target

        feed_tasks = [self.fetch_feed(url) for url in THREAT_FEEDS]
        feed_results = await asyncio.gather(*feed_tasks)

        all_iocs = defaultdict(list)
        for fr in feed_results:
            for ioc in fr.get("iocs",[]):
                all_iocs[ioc["type"]].append(ioc["value"])

        for ioc_type, values in all_iocs.items():
            if values:
                f = self.finding(entity=f"{len(set(values))} unique {ioc_type} IOCs collected",
                    ftype=f"IOC Collection: {ioc_type.upper()}", confidence="Medium",
                    color="slate", threat_level="Informational", status="Collected",
                    resolution=query, tags=["ioc",ioc_type,"collection"])
                if f: results.append(f)

        score = 0
        feeds_with_data = sum(1 for fr in feed_results if fr.get("iocs"))
        total_iocs = sum(len(fr.get("iocs",[])) for fr in feed_results)
        score += min(feeds_with_data*5, 30) + min(total_iocs//10, 30)
        score = min(score, 100)
        severity = "Critical" if score>=70 else ("High Risk" if score>=50 else ("Elevated Risk" if score>=30 else ("Low Risk" if score>=10 else "Informational")))

        f = self.finding(entity=f"Threat Score: {score}/100 ({severity}) - {feeds_with_data}/{len(THREAT_FEEDS)} feeds reporting",
            ftype="Threat Score Assessment", confidence="Medium",
            color="red" if score>=50 else "orange", threat_level=severity,
            status=f"Score: {score}", resolution=query,
            tags=["threat-score",severity.lower().replace(" ","-")])
        if f: results.append(f)

        add_tasks = [self.fetch_additional(name, url) for name, url in ADDITIONAL_FEEDS]
        add_results = await asyncio.gather(*add_tasks)
        for src in add_results:
            if src.get("ips",0) > 0:
                f = self.finding(entity=f"Additional feed: {src['name']} - {src['ips']} IPs ({src['total_lines']} lines)",
                    ftype="Additional Threat Feed", confidence="Medium", color="orange",
                    threat_level="Informational", status="Fetched", resolution=query,
                    tags=["threat-feed","additional",src['name'].lower().replace(" ","-")])
                if f: results.append(f)

        target_matches = []
        for fr in feed_results:
            for ioc in fr.get("iocs",[]):
                if query.lower() in ioc["value"].lower():
                    target_matches.append({"feed":fr["name"],"ioc":ioc["value"],"type":ioc["type"]})
        for match in target_matches[:10]:
            f = self.finding(entity=f"Target matches IOC in {match['feed']}: {match['ioc']} ({match['type']})",
                ftype="Target IOC Match", confidence="High", color="red",
                threat_level="High Risk", status="Match Found", resolution=query,
                tags=["ioc-match",match['type']])
            if f: results.append(f)

        if not results:
            f = self.finding(entity="No threat intelligence data collected",
                ftype="Threat Intel Complete", confidence="Low", color="emerald",
                threat_level="Informational", status="Clean", resolution=query,
                tags=["threat-intel","clean"])
            if f: results.append(f)

        f = self.finding(entity=f"Queried {len(THREAT_FEEDS)+len(ADDITIONAL_FEEDS)} threat feeds",
            ftype="Threat Feed Coverage Summary", confidence="Medium", color="slate",
            threat_level="Informational", status="Complete", resolution=query,
            tags=["coverage","summary"])
        if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = ThreatIntelScanner(target, client)
    return await scanner.scan()
