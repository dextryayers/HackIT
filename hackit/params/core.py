import asyncio
import aiohttp
import re
from typing import List, Dict, Any
from hackit.logger import get_logger

logger = get_logger(__name__)

class ParamFuzzer:
    DEFAULT_PAYLOADS = [
        "hackit", "<h1>hackit</h1>", "\"'<script>hackit</script>", 
        "{{7*7}}", "${7*7}", "../../../etc/passwd",
        "' OR '1'='1", "\"", "'", "<", ">"
    ]

    def __init__(self, url: str, threads: int = 10, timeout: int = 10):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.results = []

    async def fuzz(self, params: List[str], payloads: List[str] = None, method: str = "GET") -> List[Dict]:
        target_payloads = payloads if payloads else self.DEFAULT_PAYLOADS
        
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            
            for param in params:
                for payload in target_payloads:
                    tasks.append(self.check_param(session, param, payload, method))
            
            await asyncio.gather(*tasks)
            
        return self.results

    async def check_param(self, session, param, payload, method):
        try:
            # Prepare Request
            req_kwargs = {"timeout": self.timeout}
            if method == "GET":
                req_kwargs["params"] = {param: payload}
                func = session.get
            else:
                req_kwargs["data"] = {param: payload}
                func = session.post
            
            async with func(self.url, **req_kwargs) as resp:
                text = await resp.text()
                
                # Check Reflection
                if payload in text:
                    context = self.analyze_context(text, payload)
                    self.results.append({
                        "param": param,
                        "payload": payload,
                        "method": method,
                        "reflected": True,
                        "context": context,
                        "status": resp.status,
                        "length": len(text)
                    })
                
                # Check Errors (SQLi mostly)
                if "syntax error" in text.lower() or "mysql" in text.lower():
                     self.results.append({
                        "param": param,
                        "payload": payload,
                        "method": method,
                        "reflected": False,
                        "error": "Possible SQL Error",
                        "status": resp.status
                    })

        except Exception as e:
            pass

    def analyze_context(self, html: str, payload: str) -> str:
        """Analyze where the payload is reflected"""
        # Simple regex to find surrounding context
        try:
            # Escape payload for regex
            escaped_payload = re.escape(payload)
            
            # Check inside tags
            if re.search(f">{escaped_payload}<", html):
                return "HTML Text"
            
            # Check inside attributes
            if re.search(f"=['\"][^'\"]*{escaped_payload}", html):
                return "Attribute Value"
            
            # Check inside script
            if re.search(f"<script[^>]*>[^<]*{escaped_payload}", html, re.DOTALL):
                return "JavaScript"
            
            return "Unknown"
        except:
            return "Analysis Failed"
