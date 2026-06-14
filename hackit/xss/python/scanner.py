import json
import ssl
import urllib.request
import urllib.parse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

from .payloads import PAYLOADS


class Result:
    def __init__(self, url: str, parameter: str, payload: str,
                 details: str, confidence: str, severity: str,
                 impact: str, method: str = "GET"):
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.method = method
        self.type = "Reflected XSS"
        self.details = details
        self.confidence = confidence
        self.severity = severity
        self.impact = impact

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "method": self.method,
            "type": self.type,
            "details": self.details,
            "confidence": self.confidence,
            "severity": self.severity,
            "impact": self.impact,
        }


class Scanner:
    def __init__(self, timeout: int = 10, threads: int = 10):
        self.timeout = timeout
        self.threads = threads
        self.payloads = PAYLOADS
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    def detect_context(self, body: str, pay: str) -> tuple:
        body_lower = body.lower()
        pay_lower = pay.lower()

        if "href=\"javascript:" in body_lower or "src=javascript:" in body_lower:
            return ("CRITICAL: URI Handler Context (javascript:)", "High", "Critical", "Direct Code Execution")
        if f"<script>{pay_lower}" in body_lower or f"{pay_lower}</script>" in body_lower:
            return ("CRITICAL: Executable Script Context", "High", "High", "Full Account Takeover (Session Theft)")
        event_keywords = ["onerror=", "onload=", "onclick=", "onfocus=", "onmouseover=", "ontoggle=", "onstart="]
        for kw in event_keywords:
            if kw + pay_lower in body_lower:
                return ("HIGH: Event Handler Context (executable)", "High", "High", "Sensitive Data Access / Redirection")
        if "<script" in body_lower and pay_lower in body_lower and "</script>" in body_lower:
            return ("HIGH: Inside Script Block", "High", "Medium", "Phishing / Content Injection")
        if f"=\"{pay_lower}" in body_lower or f"='{pay_lower}" in body_lower:
            return ("HIGH: Attribute Breakout Context", "High", "Medium", "Phishing / Forced Redirection")
        if "{{" in pay or "${" in pay or "<%=" in pay:
            return ("MEDIUM: Template Injection Detected", "Medium", "Medium", "Server-Side Template Injection")
        if "base64" in pay_lower or "data:" in pay_lower:
            return ("MEDIUM: Data URI Injection", "Medium", "Medium", "Content Injection via Data URI")

        return ("LOW: Payload Reflected in Response", "Low", "Low", "Content Spoofing")

    def is_false_positive(self, body: str, pay: str) -> bool:
        html_map = {"<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;", "&": "&amp;"}
        for char, encoded in html_map.items():
            if char in pay and encoded in body and char not in body:
                return True
        return False

    def test_payload(self, url: str, param: str, pay: str) -> Optional[Result]:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [pay]
            new_query = urllib.parse.urlencode(params, doseq=True)
            attack_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            req = urllib.request.Request(
                attack_url,
                headers={"User-Agent": "HackIt-XSS/2.0", "Accept": "text/html,*/*"}
            )
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx)
            body = resp.read().decode('utf-8', errors='ignore')

            if pay not in body:
                return None
            if self.is_false_positive(body, pay):
                return None

            details, confidence, severity, impact = self.detect_context(body, pay)

            if "cookie" in pay.lower() or "fetch" in pay.lower():
                severity = "Critical"
                impact = "Data Exfiltration (Sensitive Information)"

            return Result(attack_url, param, pay, details, confidence, severity, impact)

        except Exception:
            return None

    def scan(self, target_url: str) -> List[Dict[str, Any]]:
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return [{"error": "No query parameters in URL"}]

        results = []
        lock = threading.Lock()
        total = sum(len(self.payloads) for _ in params)
        done = 0

        def worker(param: str, pay: str):
            nonlocal done
            r = self.test_payload(target_url, param, pay)
            if r:
                with lock:
                    results.append(r.to_dict())
            with lock:
                done += 1

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in params:
                for pay in self.payloads:
                    futures.append(executor.submit(worker, param, pay))
            for f in as_completed(futures):
                pass

        return results if results else [{"vulnerable": False, "note": "No XSS detected"}]
