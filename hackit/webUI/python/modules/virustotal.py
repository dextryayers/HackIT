import httpx
import json
import socket
from module_base import BaseScanner
from settings_store import get_api_key

VT_API = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"User-Agent":"Mozilla/5.0","Accept":"application/json","x-apikey":""}

class VirusTotalScanner(BaseScanner):
    name = "virustotal"

    async def vt_get(self, path: str) -> dict:
        headers = dict(VT_HEADERS)
        headers["x-apikey"] = get_api_key("virustotal")
        try:
            resp = await self.safe_request(f"{VT_API}/{path}", headers=headers, timeout=15)
            return resp.json() if resp and resp.status_code==200 else {}
        except: return {}

    async def scan(self) -> list:
        results = []
        t = self.target

        is_ip = False
        try:
            socket.inet_aton(t); is_ip = True
        except: pass

        is_hash = None
        if len(t)==32: is_hash="MD5"
        elif len(t)==40: is_hash="SHA1"
        elif len(t)==64: is_hash="SHA256"

        data = {}
        endpoint_type = "unknown"
        if is_hash:
            data = await self.vt_get(f"files/{t}"); endpoint_type = "File"
        elif is_ip:
            data = await self.vt_get(f"ip_addresses/{t}"); endpoint_type = "IP"
        else:
            data = await self.vt_get(f"domains/{t}"); endpoint_type = "Domain"

        if not data:
            f = self.finding(entity="No VirusTotal data available", ftype="VirusTotal Check Complete",
                confidence="Low", color="emerald", threat_level="Informational",
                status="Not Found", resolution=t, tags=["virustotal","empty"])
            if f: results.append(f)
            return results

        attrs = data.get("data",{}).get("attributes",{})
        last_analysis = attrs.get("last_analysis_stats",{})
        malicious = last_analysis.get("malicious",0)
        suspicious = last_analysis.get("suspicious",0)
        total = malicious + suspicious + last_analysis.get("harmless",0) + last_analysis.get("undetected",0)

        if total > 0:
            f = self.finding(entity=f"VT Detection: {malicious}/{total} malicious ({suspicious} suspicious)",
                ftype=f"VirusTotal {endpoint_type} Report", confidence="High",
                color="red" if malicious>0 else "emerald",
                threat_level="High Risk" if malicious>0 else ("Elevated Risk" if suspicious>0 else "Informational"),
                status="Malicious" if malicious>0 else ("Suspicious" if suspicious>0 else "Clean"),
                resolution=t, raw_data=json.dumps(last_analysis), tags=["virustotal",endpoint_type.lower(),"detection"])
            if f: results.append(f)

        for engine, cat in list(attrs.get("categories",{}).items())[:5]:
            f = self.finding(entity=f"{engine}: {cat}", ftype="VirusTotal Category",
                confidence="Medium", color="slate", status="Categorized", resolution=t,
                tags=["virustotal","category"])
            if f: results.append(f)

        reputation = attrs.get("reputation",0)
        if reputation:
            f = self.finding(entity=f"VT Reputation: {reputation}", ftype="VirusTotal Reputation",
                confidence="Medium", color="slate", status="Scored", resolution=t,
                tags=["virustotal","reputation"])
            if f: results.append(f)

        for engine, result in attrs.get("last_analysis_results",{}).items():
            if result.get("category")=="malicious":
                f = self.finding(entity=f"{engine}: {result.get('result','malicious')}",
                    ftype="VirusTotal Engine Detection", confidence="High", color="red",
                    threat_level="High Risk", status="Detected", resolution=t,
                    tags=["virustotal","engine",engine.lower()])
                if f: results.append(f)

        tags_list = attrs.get("tags",[])
        if tags_list:
            f = self.finding(entity=f"Tags: {', '.join(tags_list[:5])}", ftype="VirusTotal Tags",
                confidence="Low", color="slate", status="Tagged", resolution=t,
                tags=["virustotal","tags"]+[t.lower() for t in tags_list[:3]])
            if f: results.append(f)
        return results


async def crawl(target: str, client: httpx.AsyncClient):
    scanner = VirusTotalScanner(target, client)
    return await scanner.scan()
