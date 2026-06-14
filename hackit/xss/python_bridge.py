import os, sys, json
from typing import Dict, Any, List

class PythonEngine:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.scanner = None

    @property
    def available(self) -> bool:
        try:
            import ssl, urllib.request
            return True
        except ImportError:
            return False

    def ensure_compiled(self) -> bool:
        return True

    def run(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        try:
            sys.path.insert(0, self.base_dir)
            from python.scanner import Scanner
            timeout = kwargs.get('timeout', 10)
            threads = kwargs.get('threads', 10)
            scanner = Scanner(timeout=timeout, threads=threads)
            return scanner.scan(url)
        except Exception as e:
            return [{"error": f"Python XSS engine error: {e}"}]
