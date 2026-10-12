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

    SQL_ERROR_MARKERS = (
        "you have an error in your sql syntax",
        "pg::syntaxerror",
        "unclosed quotation mark",
        "ora-01756",
        "sqlite3::sqlexception",
        "near \"syntax error\"",
    )

    def classify_sink(self, param, payload, text, status, location):
        """Classify where a reflected token lands: reflected, redirect_sink, file_sink."""
        lowered = (text or "").lower()
        token = payload.lower()
        if location and token in location.lower():
            return "redirect_sink"
        if token in lowered:
            if "include" in lowered or ".php" in lowered or "/etc/" in lowered:
                return "file_sink"
            return "reflected"
        return "none"

    async def check_param(self, session, param, payload, method):
        try:
            # Prepare Request
            req_kwargs = {"timeout": aiohttp.ClientTimeout(total=self.timeout)}
            if method == "GET":
                req_kwargs["params"] = {param: payload}
                func = session.get
            else:
                req_kwargs["data"] = {param: payload}
                func = session.post

            async with func(self.url, allow_redirects=False, **req_kwargs) as resp:
                text = await resp.text()
                location = resp.headers.get("Location", "")

                # Check Reflection with sink classification
                if payload in text or (location and payload in location):
                    context = self.analyze_context(text, payload)
                    sink = self.classify_sink(param, payload, text, resp.status, location)
                    self.results.append({
                        "param": param,
                        "payload": payload,
                        "method": method,
                        "reflected": True,
                        "context": context,
                        "sink_hint": sink,
                        "status": resp.status,
                        "length": len(text)
                    })

                # Check Errors (SQLi mostly, DB-specific markers only)
                lowered = text.lower()
                if any(marker in lowered for marker in self.SQL_ERROR_MARKERS):
                     self.results.append({
                        "param": param,
                        "payload": payload,
                        "method": method,
                        "reflected": False,
                        "sink_hint": "sqli_candidate",
                        "error": "Possible SQL Error",
                        "status": resp.status
                    })

        except asyncio.TimeoutError:
            self.results.append({
                "param": param,
                "payload": payload,
                "method": method,
                "reflected": False,
                "sink_hint": "none",
                "error": "request timeout",
            })
        except Exception as e:
            self.results.append({
                "param": param,
                "payload": payload,
                "method": method,
                "reflected": False,
                "sink_hint": "none",
                "error": "request failed: " + type(e).__name__[:40],
            })

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
        except Exception:
            return "Analysis Failed"
