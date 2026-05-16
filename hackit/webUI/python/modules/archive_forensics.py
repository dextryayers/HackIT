import httpx
import asyncio
from models import IntelligenceFinding

async def crawl(target, client):
    findings = []
    
    # Combined logic from sfp_archiveorg and common crawl concepts
    # Wayback Machine CDX API is extremely powerful for finding historical files
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&collapse=urlkey&fl=original,mimetype,timestamp&limit=100"
    
    try:
        resp = await client.get(wayback_url, timeout=15.0)
        if resp.status_code == 200:
            data = resp.json()
            # First element is the header [original, mimetype, timestamp]
            if len(data) > 1:
                for entry in data[1:]:
                    original_url = entry[0]
                    mimetype = entry[1]
                    timestamp = entry[2]
                    
                    # Look for sensitive extensions in history
                    sensitive_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar.gz', '.sql', '.bak', '.env', '.conf']
                    is_sensitive = any(original_url.lower().endswith(ext) for ext in sensitive_exts)
                    
                    if is_sensitive:
                        findings.append(IntelligenceFinding(
                            entity=original_url,
                            type="Historical Sensitive File",
                            source="Wayback Machine Forensics",
                            confidence="Certain",
                            color="orange",
                            category="Historical Intel",
                            threat_level="Medium",
                            status="Historical Discovery",
                            raw_data=f"Found historical URL for sensitive file type ({mimetype}) from {timestamp}: {original_url}"
                        ))
                    else:
                        # Just log some common historical URLs
                        if len(findings) < 20: # Limit general noise
                            findings.append(IntelligenceFinding(
                                entity=original_url,
                                type="Historical URL",
                                source="Wayback Machine Forensics",
                                confidence="Medium",
                                color="grey",
                                category="Historical Intel",
                                threat_level="Informational",
                                status="Found in Archive",
                                raw_data=f"Historical URL found from {timestamp}: {original_url}"
                            ))
                            
    except Exception as e:
        pass
        
    return findings
