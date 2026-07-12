import json
import os
import threading

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "settings.json")

_lock = threading.Lock()
_cache = None

DEFAULT_API_KEYS = {
    "shodan": "",
    "virustotal": "",
    "abuseipdb": "",
    "binaryedge": "",
    "email_rep": "",
    "greynoise": "",
    "leakcheck": "",
    "hunter": "",
    "haveibeenpwned": "",
    "securitytrails": "",
    "ipinfo": "",
    "dehashed": "",
    "whoisxmlapi": "",
    "censys": "",
    "intelx": "",
}

DEFAULT_SETTINGS = {
    "api_keys": DEFAULT_API_KEYS,
    "scan_defaults": {
        "depth": "deep",
        "sniper_ratio": "max",
        "timeout": 15,
        "max_findings": 5000,
        "verify_findings": True,
        "correlation_engine": True,
    }
}

def _ensure_file():
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)

def load_settings() -> dict:
    global _cache
    with _lock:
        _ensure_file()
        try:
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
            merged = DEFAULT_SETTINGS.copy()
            merged.update(data)
            if "api_keys" not in merged:
                merged["api_keys"] = DEFAULT_API_KEYS.copy()
            else:
                for k, v in DEFAULT_API_KEYS.items():
                    merged["api_keys"].setdefault(k, v)
            _cache = merged
            return merged
        except:
            _cache = DEFAULT_SETTINGS.copy()
            return _cache

def save_settings(data: dict):
    global _cache
    with _lock:
        _ensure_file()
        merged = load_settings()
        merged.update(data)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(merged, f, indent=2)
        _cache = merged

def get_api_key(service: str) -> str:
    settings = load_settings()
    return settings.get("api_keys", {}).get(service, "")

def get_setting(key: str, default=None):
    return load_settings().get(key, default)
