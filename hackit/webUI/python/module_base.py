import asyncio, hashlib, json, os, time
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
from models import IntelligenceFinding

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cache")

class DedupStore:
    def __init__(self, namespace="global"):
        self._memory: set = set()
        self._namespace = namespace
        os.makedirs(CACHE_DIR, exist_ok=True)
        self._file = os.path.join(CACHE_DIR, f"dedup_{namespace}.json")
        self._load()

    def _load(self):
        try:
            with open(self._file) as f: self._memory = set(json.load(f))
        except: self._memory = set()

    def _save(self):
        try:
            with open(self._file, 'w') as f: json.dump(list(self._memory), f)
        except: pass

    def check(self, key: str) -> bool: return key in self._memory

    def add(self, key: str): self._memory.add(key); self._save()

    def flush(self): self._memory.clear(); self._save()

store = DedupStore()

class BaseScanner:
    name = ""
    timeout = 15
    max_retries = 2

    def __init__(self, target: str, client=None, settings: Optional[Dict] = None):
        self.target = self.normalize(target)
        self.client = client
        self.settings = settings or {}
        self.timeout = int(self.settings.get("timeout", self.timeout))

    @staticmethod
    def normalize(target: str) -> str:
        target = target.strip()
        if target.startswith(("http://", "https://")):
            return urlparse(target).netloc.lower().strip(".")
        return target.split("/")[0].lower().strip(".")

    def finding(self, entity, ftype, source=None, confidence="Medium", color="slate",
                threat_level="Informational", status="Found", resolution=None,
                raw_data=None, tags=None) -> IntelligenceFinding:
        key = f"{entity}|{ftype}"
        if store.check(key): return None
        store.add(key)
        return IntelligenceFinding(
            entity=str(entity)[:500], type=ftype,
            source=source or f"Python:{self.name or type(self).__name__}",
            confidence=confidence, color=color,
            threat_level=threat_level, status=status,
            resolution=resolution,
            raw_data=str(raw_data)[:4000] if raw_data else None,
            tags=tags or [],
        )

    async def safe_request(self, url: str, method="GET", **kwargs) -> Optional[Any]:
        if not self.client: return None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await asyncio.wait_for(
                    getattr(self.client, method.lower())(url, **kwargs),
                    timeout=self.timeout
                )
                return resp
            except Exception as e:
                if attempt == self.max_retries: return None
                await asyncio.sleep(0.5 * (attempt + 1))

    async def crawl(self, client, target: str) -> List[IntelligenceFinding]:
        return []
