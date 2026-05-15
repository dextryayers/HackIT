import httpx
import re
from models import IntelligenceFinding
from bs4 import BeautifulSoup
from urllib.parse import urljoin

async def crawl(target, client):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target
    
    # Regex patterns for secrets
    patterns = {
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
        "Generic Secret": r"(?i)(key|secret|token|auth|password|passwd|creds)\s*[:=]\s*['\"]([a-zA-Z0-9-_]{16,})['\"]"
    }
    
    try:
        # 1. Fetch main page to find JS files
        resp = await client.get(base_url, timeout=10.0)
        soup = BeautifulSoup(resp.text, 'html.parser')
        js_files = [urljoin(base_url, script['src']) for script in soup.find_all('script', src=True)]
        
        # 2. Analyze each JS file
        for js_url in js_files:
            try:
                js_resp = await client.get(js_url, timeout=7.0)
                content = js_resp.text
                
                for secret_type, pattern in patterns.items():
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        finding_text = match.group(0)
                        if isinstance(finding_text, tuple): finding_text = finding_text[1] # For Generic Secret
                        
                        findings.append(IntelligenceFinding(
                            entity=f"{js_url} ({secret_type})",
                            type="Hardcoded Secret",
                            source="JSSecrets",
                            confidence="High",
                            color="red",
                            category="Credential Leak",
                            threat_level="High Risk",
                            raw_data=f"Found match: {finding_text}"
                        ))
            except: continue
            
    except Exception as e:
        pass
        
    return findings
