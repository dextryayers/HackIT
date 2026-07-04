import json
import os
import getpass
import socket
import time
import shutil
import base64
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional, List, Tuple

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".hackit")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
CONFIG_VERSION = 2

MAX_BACKUPS = 3
BACKUP_DIR = os.path.join(CONFIG_DIR, "backups")

VALID_THEMES = [
    "kali", "cyberpunk", "minimalist", "retro", "gacor", "powerline",
    "modern", "pill", "nexus", "zinc", "vault", "storm", "drift", "pulse", "slash"
]
VALID_ACCENTS = ["cyan", "magenta", "green", "blue", "red", "yellow", "white"]
VALID_BORDERS = ["double", "single", "rounded", "block", "ascii", "none"]
VALID_PROMPTS = ["arrow", "hash", "dollar", "lambda", "skull", "none"]
VALID_OUTPUTS = ["json", "csv", "xml", "markdown", "table"]
VALID_SCAN_PROFILES = ["quick", "full", "stealth", "custom"]
VALID_MASKING_LEVELS = ["none", "basic", "medium", "advanced", "expert", "paranoid"]

MASKING_PROFILES = {
    "none": {
        "stealth_mode": False,
        "randomize_ua": False,
        "randomize_fingerprint": False,
        "proxy_rotation": False,
        "dns_leak_protection": False,
        "timing_jitter": False,
        "header_randomization": False,
        "request_padding": False,
        "tor_enabled": False,
        "mac_spoofing": False,
        "tls_fingerprint": False,
        "ip_rotation": False,
        "dns_over_https": False,
        "request_delay_min": 0.0,
        "request_delay_max": 0.0,
        "proxy_chain_depth": 0,
        "ip_rotation_freq": 0,
        "tor_stream_isolation": False,
        "cache_busting": False,
        "referer_spoofing": False,
        "session_isolation": False,
        "adaptive_delays": False,
        "http2_disable": False,
        "packet_fragmentation": False,
        "decoy_traffic": False,
    },
    "basic": {
        "stealth_mode": True,
        "randomize_ua": True,
        "randomize_fingerprint": False,
        "proxy_rotation": False,
        "dns_leak_protection": False,
        "timing_jitter": True,
        "header_randomization": False,
        "request_padding": False,
        "tor_enabled": False,
        "mac_spoofing": False,
        "tls_fingerprint": False,
        "ip_rotation": False,
        "dns_over_https": False,
        "request_delay_min": 0.3,
        "request_delay_max": 0.8,
        "proxy_chain_depth": 0,
        "ip_rotation_freq": 0,
        "tor_stream_isolation": False,
        "cache_busting": False,
        "referer_spoofing": True,
        "session_isolation": False,
        "adaptive_delays": False,
        "http2_disable": False,
        "packet_fragmentation": False,
        "decoy_traffic": False,
    },
    "medium": {
        "stealth_mode": True,
        "randomize_ua": True,
        "randomize_fingerprint": True,
        "proxy_rotation": True,
        "dns_leak_protection": True,
        "timing_jitter": True,
        "header_randomization": True,
        "request_padding": False,
        "tor_enabled": False,
        "mac_spoofing": False,
        "tls_fingerprint": False,
        "ip_rotation": False,
        "dns_over_https": False,
        "request_delay_min": 0.8,
        "request_delay_max": 2.0,
        "proxy_chain_depth": 1,
        "ip_rotation_freq": 15,
        "tor_stream_isolation": False,
        "cache_busting": True,
        "referer_spoofing": True,
        "session_isolation": True,
        "adaptive_delays": True,
        "http2_disable": False,
        "packet_fragmentation": False,
        "decoy_traffic": False,
    },
    "advanced": {
        "stealth_mode": True,
        "randomize_ua": True,
        "randomize_fingerprint": True,
        "proxy_rotation": True,
        "dns_leak_protection": True,
        "timing_jitter": True,
        "header_randomization": True,
        "request_padding": True,
        "tor_enabled": True,
        "mac_spoofing": False,
        "tls_fingerprint": True,
        "ip_rotation": True,
        "dns_over_https": True,
        "request_delay_min": 1.5,
        "request_delay_max": 4.0,
        "proxy_chain_depth": 2,
        "ip_rotation_freq": 8,
        "tor_stream_isolation": True,
        "cache_busting": True,
        "referer_spoofing": True,
        "session_isolation": True,
        "adaptive_delays": True,
        "http2_disable": True,
        "packet_fragmentation": False,
        "decoy_traffic": False,
    },
    "expert": {
        "stealth_mode": True,
        "randomize_ua": True,
        "randomize_fingerprint": True,
        "proxy_rotation": True,
        "dns_leak_protection": True,
        "timing_jitter": True,
        "header_randomization": True,
        "request_padding": True,
        "tor_enabled": True,
        "mac_spoofing": True,
        "tls_fingerprint": True,
        "ip_rotation": True,
        "dns_over_https": True,
        "request_delay_min": 2.5,
        "request_delay_max": 6.0,
        "proxy_chain_depth": 3,
        "ip_rotation_freq": 4,
        "tor_stream_isolation": True,
        "cache_busting": True,
        "referer_spoofing": True,
        "session_isolation": True,
        "adaptive_delays": True,
        "http2_disable": True,
        "packet_fragmentation": True,
        "decoy_traffic": False,
    },
    "paranoid": {
        "stealth_mode": True,
        "randomize_ua": True,
        "randomize_fingerprint": True,
        "proxy_rotation": True,
        "dns_leak_protection": True,
        "timing_jitter": True,
        "header_randomization": True,
        "request_padding": True,
        "tor_enabled": True,
        "mac_spoofing": True,
        "tls_fingerprint": True,
        "ip_rotation": True,
        "dns_over_https": True,
        "request_delay_min": 4.0,
        "request_delay_max": 10.0,
        "proxy_chain_depth": 3,
        "ip_rotation_freq": 1,
        "tor_stream_isolation": True,
        "cache_busting": True,
        "referer_spoofing": True,
        "session_isolation": True,
        "adaptive_delays": True,
        "http2_disable": True,
        "packet_fragmentation": True,
        "decoy_traffic": True,
    },
}

_ENCRYPT_KEY = None

def _get_encrypt_key() -> str:
    global _ENCRYPT_KEY
    if _ENCRYPT_KEY is None:
        mid = os.path.join(CONFIG_DIR, ".key")
        try:
            if os.path.exists(mid):
                with open(mid, "r") as f:
                    _ENCRYPT_KEY = f.read().strip()
            else:
                os.makedirs(CONFIG_DIR, exist_ok=True)
                _ENCRYPT_KEY = base64.b64encode(os.urandom(32)).decode()
                with open(mid, "w") as f:
                    f.write(_ENCRYPT_KEY)
                os.chmod(mid, 0o600)
        except Exception:
            _ENCRYPT_KEY = "hackit-default-fallback-key"
    return _ENCRYPT_KEY

def _obfuscate(text: str) -> str:
    if not text:
        return ""
    key = _get_encrypt_key()
    encoded = text.encode()
    key_bytes = key.encode()
    result = bytearray(len(encoded))
    for i in range(len(encoded)):
        result[i] = encoded[i] ^ key_bytes[i % len(key_bytes)]
    return base64.b64encode(bytes(result)).decode()

def _deobfuscate(encoded: str) -> str:
    if not encoded:
        return ""
    key = _get_encrypt_key()
    try:
        raw = base64.b64decode(encoded.encode())
        key_bytes = key.encode()
        result = bytearray(len(raw))
        for i in range(len(raw)):
            result[i] = raw[i] ^ key_bytes[i % len(key_bytes)]
        return result.decode()
    except Exception:
        return ""

DEFAULT_CONFIG: Dict[str, Any] = {
    "_version": CONFIG_VERSION,
    "_created": datetime.now().isoformat(),
    "_updated": datetime.now().isoformat(),
    "theme": "vault",
    "user": getpass.getuser(),
    "hostname": socket.gethostname(),
    "accent": "cyan",
    "border": "double",
    "prompt": "arrow",
    "ai_provider": "",
    "ai_keys": {},
    "ai_models": {},
    "timeout": 30,
    "max_threads": 50,
    "stealth_mode": False,
    "proxy": "",
    "verify_ssl": True,
    "output_format": "json",
    "auto_save_reports": True,
    "reports_dir": os.path.join(os.path.expanduser("~"), ".hackit_reports"),
    "session_id": "",
    "last_target": "",
    "history_size": 5000,
    "scan_profile": "full",
    "auto_update_check": True,
    "ai_timeout": 60,
    "ai_max_tokens": 8192,
    "ai_temperature": 0.7,
    "notifications_enabled": True,
    "masking_level": "none",
    "randomize_ua": False,
    "randomize_fingerprint": False,
    "proxy_rotation": False,
    "dns_leak_protection": False,
    "timing_jitter": False,
    "header_randomization": False,
    "request_padding": False,
    "tor_enabled": False,
    "mac_spoofing": False,
    "tls_fingerprint": False,
    "ip_rotation": False,
    "dns_over_https": False,
    "request_delay_min": 0.0,
    "request_delay_max": 0.0,
    "proxy_chain_depth": 0,
    "ip_rotation_freq": 0,
    "tor_stream_isolation": False,
    "cache_busting": False,
    "referer_spoofing": False,
    "session_isolation": False,
    "adaptive_delays": False,
    "http2_disable": False,
    "packet_fragmentation": False,
    "decoy_traffic": False,
}

SCHEMA: Dict[str, Dict[str, Any]] = {
    "_version":      {"type": int, "required": True},
    "_created":      {"type": str, "required": True},
    "_updated":      {"type": str, "required": True},
    "theme":         {"type": str, "validator": lambda v: v in VALID_THEMES, "label": "Terminal theme"},
    "accent":        {"type": str, "validator": lambda v: v in VALID_ACCENTS, "label": "Accent color"},
    "border":        {"type": str, "validator": lambda v: v in VALID_BORDERS, "label": "Border style"},
    "prompt":        {"type": str, "validator": lambda v: v in VALID_PROMPTS, "label": "Prompt style"},
    "user":          {"type": str, "label": "Display username"},
    "hostname":      {"type": str, "label": "Display hostname"},
    "timeout":       {"type": (int, float), "min": 1, "max": 300, "label": "Request timeout"},
    "max_threads":   {"type": int, "min": 1, "max": 1000, "label": "Max threads"},
    "stealth_mode":  {"type": bool, "label": "Stealth mode"},
    "verify_ssl":    {"type": bool, "label": "Verify SSL"},
    "output_format": {"type": str, "validator": lambda v: v in VALID_OUTPUTS, "label": "Output format"},
    "auto_save_reports": {"type": bool, "label": "Auto-save reports"},
    "history_size":  {"type": int, "min": 100, "max": 50000, "label": "History size"},
    "scan_profile":  {"type": str, "validator": lambda v: v in VALID_SCAN_PROFILES, "label": "Scan profile"},
    "auto_update_check": {"type": bool, "label": "Auto update check"},
    "ai_timeout":    {"type": (int, float), "min": 5, "max": 300, "label": "AI timeout"},
    "ai_max_tokens": {"type": int, "min": 128, "max": 131072, "label": "AI max tokens"},
    "ai_temperature":{"type": (int, float), "min": 0.0, "max": 2.0, "label": "AI temperature"},
    "notifications_enabled": {"type": bool, "label": "Notifications"},
    "proxy":         {"type": str, "label": "Proxy URL"},
    "reports_dir":   {"type": str, "label": "Reports directory"},
    "session_id":    {"type": str, "label": "Session ID"},
    "last_target":   {"type": str, "label": "Last target"},
    "ai_provider":   {"type": str, "label": "AI provider"},
    "ai_keys":       {"type": dict, "label": "AI API keys"},
    "ai_models":     {"type": dict, "label": "AI models"},
    "masking_level":        {"type": str, "validator": lambda v: v in VALID_MASKING_LEVELS, "label": "Masking level"},
    "randomize_ua":         {"type": bool, "label": "Randomize User-Agent"},
    "randomize_fingerprint":{"type": bool, "label": "Randomize browser fingerprint"},
    "proxy_rotation":       {"type": bool, "label": "Rotate proxies"},
    "dns_leak_protection":  {"type": bool, "label": "DNS leak protection"},
    "timing_jitter":        {"type": bool, "label": "Timing jitter"},
    "header_randomization": {"type": bool, "label": "Randomize HTTP headers"},
    "request_padding":      {"type": bool, "label": "Request padding"},
    "tor_enabled":          {"type": bool, "label": "Tor routing"},
    "mac_spoofing":         {"type": bool, "label": "MAC spoofing"},
    "tls_fingerprint":      {"type": bool, "label": "TLS fingerprint rand"},
    "ip_rotation":          {"type": bool, "label": "IP rotation"},
    "dns_over_https":       {"type": bool, "label": "DNS over HTTPS"},
    "request_delay_min":    {"type": (int, float), "min": 0.0, "max": 30.0, "label": "Min request delay"},
    "request_delay_max":    {"type": (int, float), "min": 0.0, "max": 30.0, "label": "Max request delay"},
    "proxy_chain_depth":    {"type": int, "min": 0, "max": 5, "label": "Proxy chain depth"},
    "ip_rotation_freq":     {"type": int, "min": 0, "max": 100, "label": "IP rotation freq"},
    "tor_stream_isolation": {"type": bool, "label": "Tor stream isolation"},
    "cache_busting":        {"type": bool, "label": "Cache busting"},
    "referer_spoofing":     {"type": bool, "label": "Referer spoofing"},
    "session_isolation":    {"type": bool, "label": "Session isolation"},
    "adaptive_delays":      {"type": bool, "label": "Adaptive delays"},
    "http2_disable":        {"type": bool, "label": "Disable HTTP/2"},
    "packet_fragmentation": {"type": bool, "label": "Packet fragmentation"},
    "decoy_traffic":        {"type": bool, "label": "Decoy traffic"},
}

ENV_MAP = {
    "HACKIT_THEME":        ("theme", str),
    "HACKIT_PROXY":        ("proxy", str),
    "HACKIT_TIMEOUT":      ("timeout", float),
    "HACKIT_THREADS":      ("max_threads", int),
    "HACKIT_OUTPUT":       ("output_format", str),
    "HACKIT_STEALTH":      ("stealth_mode", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_VERIFY":       ("verify_ssl", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_SCAN_PROFILE": ("scan_profile", str),
    "HACKIT_AI_PROVIDER":  ("ai_provider", str),
    "HACKIT_AI_KEY":       ("_env_ai_key", str),
    "HACKIT_MASKING":      ("masking_level", str),
    "HACKIT_RANDOM_UA":    ("randomize_ua", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_PROXY_ROTATE": ("proxy_rotation", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_TOR":          ("tor_enabled", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_DNS_LEAK":     ("dns_leak_protection", lambda v: v.lower() in ("true","1","yes")),
    "HACKIT_JITTER":       ("timing_jitter", lambda v: v.lower() in ("true","1","yes")),
}


def _validate_value(key: str, value: Any) -> Tuple[bool, Any, str]:
    schema = SCHEMA.get(key)
    if schema is None:
        return True, value, ""

    expected_type = schema.get("type")
    if expected_type is not None:
        if isinstance(expected_type, tuple):
            if not isinstance(value, expected_type):
                try:
                    for t in expected_type:
                        try:
                            value = t(value)
                            break
                        except (ValueError, TypeError):
                            continue
                    else:
                        return False, value, f"expected {'/'.join(t.__name__ for t in expected_type)}"
                except Exception:
                    return False, value, f"expected {'/'.join(t.__name__ for t in expected_type)}"
        elif expected_type is not None:
            if not isinstance(value, expected_type):
                try:
                    if expected_type in (int, float):
                        value = expected_type(value)
                    elif expected_type == bool and isinstance(value, str):
                        value = value.lower() in ("true", "1", "yes")
                    elif expected_type == str:
                        value = str(value)
                    else:
                        return False, value, f"expected {expected_type.__name__}"
                except (ValueError, TypeError):
                    return False, value, f"expected {expected_type.__name__}"

    mn = schema.get("min")
    mx = schema.get("max")
    if mn is not None and isinstance(value, (int, float)) and value < mn:
        return False, value, f"minimum {mn}"
    if mx is not None and isinstance(value, (int, float)) and value > mx:
        return False, value, f"maximum {mx}"

    validator = schema.get("validator")
    if validator is not None:
        if not validator(value):
            label = schema.get("label", key)
            return False, value, f"invalid {label}"

    return True, value, ""


def _validate_config(cfg: Dict[str, Any], strict: bool = False) -> Dict[str, Any]:
    for key in list(cfg.keys()):
        if key == "_version":
            continue
        if key not in SCHEMA and not strict:
            continue
        if key in SCHEMA:
            ok, val, err = _validate_value(key, cfg[key])
            if not ok:
                cfg[key] = DEFAULT_CONFIG.get(key)
    for key in SCHEMA:
        if key.startswith("_"):
            continue
        if key not in cfg:
            cfg[key] = DEFAULT_CONFIG.get(key)
    return cfg


def _rotate_backups():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    base = CONFIG_PATH
    if not os.path.exists(base):
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak_path = os.path.join(BACKUP_DIR, f"config_{ts}.json.bak")

    try:
        shutil.copy2(base, bak_path)
    except Exception:
        pass

    backups = sorted(
        [os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".bak")],
        key=os.path.getmtime
    )
    while len(backups) > MAX_BACKUPS:
        try:
            os.remove(backups.pop(0))
        except Exception:
            pass


def _env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    for env_key, (cfg_key, cast) in ENV_MAP.items():
        val = os.environ.get(env_key)
        if val is None:
            continue
        if env_key == "HACKIT_AI_KEY":
            prov = cfg.get("ai_provider", "")
            if prov:
                if "ai_keys" not in cfg:
                    cfg["ai_keys"] = {}
                cfg["ai_keys"][prov] = val
            continue
        try:
            if callable(cast):
                cfg[cfg_key] = cast(val)
            else:
                cfg[cfg_key] = cast(val)
        except (ValueError, TypeError):
            continue

    hackit_prov = os.environ.get("HACKIT_AI_PROVIDER")
    hackit_key = os.environ.get("HACKIT_AI_KEY")
    if hackit_prov and hackit_key:
        if "ai_keys" not in cfg:
            cfg["ai_keys"] = {}
        cfg["ai_keys"][hackit_prov] = hackit_key

    return cfg


def _migrate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    version = cfg.get("_version", 1)

    if version < 2:
        if "ai_keys" in cfg and isinstance(cfg["ai_keys"], dict):
            for prov, key in cfg["ai_keys"].items():
                if key and not key.startswith("__enc__"):
                    cfg["ai_keys"][prov] = "__enc__" + _obfuscate(key)
        cfg["_version"] = 2

    cfg["_version"] = CONFIG_VERSION
    return cfg


def load_config() -> Dict[str, Any]:
    os.makedirs(CONFIG_DIR, exist_ok=True)

    if not os.path.exists(CONFIG_PATH):
        cfg = DEFAULT_CONFIG.copy()
        cfg["_created"] = datetime.now().isoformat()
        cfg["_updated"] = datetime.now().isoformat()
        save_config(cfg)
        return cfg

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        backups = sorted(
            [os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if f.endswith(".bak")],
            key=os.path.getmtime, reverse=True
        )
        for bak in backups:
            try:
                with open(bak, "r", encoding="utf-8") as f:
                    data = json.load(f)
                print(f"  [!] Config corrupted, restored from: {bak}")
                break
            except Exception:
                continue
        else:
            print(f"  [!] Config corrupted, using defaults")
            cfg = DEFAULT_CONFIG.copy()
            cfg["_created"] = datetime.now().isoformat()
            cfg["_updated"] = datetime.now().isoformat()
            return cfg

    merged = DEFAULT_CONFIG.copy()
    for k, v in data.items():
        merged[k] = v

    merged = _migrate_config(merged)
    merged = _validate_config(merged)
    merged = _env_overrides(merged)
    merged = apply_masking_level(merged)

    return merged


def save_config(config: Dict[str, Any]) -> bool:
    config["_updated"] = datetime.now().isoformat()
    config["_version"] = CONFIG_VERSION
    config = _validate_config(config)

    export = {}
    for k, v in config.items():
        if k == "ai_keys" and isinstance(v, dict):
            export[k] = {}
            for prov, key in v.items():
                if key and not key.startswith("__enc__"):
                    export[k][prov] = "__enc__" + _obfuscate(key)
                else:
                    export[k][prov] = key
        else:
            export[k] = v

    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        _rotate_backups()
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(export, f, indent=4, ensure_ascii=False)
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        os.rename(tmp_path, CONFIG_PATH)
        return True
    except Exception as e:
        print(f"  [!] Config save error: {e}")
        return False


def get_theme() -> str:
    return load_config().get("theme", "vault")


def set_theme(theme_name: str) -> bool:
    cfg = load_config()
    ok, val, err = _validate_value("theme", theme_name)
    if not ok:
        return False
    cfg["theme"] = theme_name
    return save_config(cfg)


def get_user_info() -> Tuple[str, str]:
    cfg = load_config()
    user = cfg.get("user") or getpass.getuser()
    host = cfg.get("hostname") or socket.gethostname()
    return user, host


def get_value(key: str, default: Any = None) -> Any:
    cfg = load_config()
    if key == "ai_keys":
        raw = cfg.get(key, {})
        decrypted = {}
        for prov, val in raw.items():
            if isinstance(val, str) and val.startswith("__enc__"):
                decrypted[prov] = _deobfuscate(val[7:])
            else:
                decrypted[prov] = val
        return decrypted
    return cfg.get(key, default)


def set_value(key: str, value: Any) -> bool:
    cfg = load_config()
    ok, val, err = _validate_value(key, value)
    if not ok:
        print(f"  [!] Invalid value for {key}: {err}")
        return False
    cfg[key] = value
    return save_config(cfg)


def get_proxy() -> Optional[str]:
    proxy = os.environ.get("HACKIT_PROXY") or load_config().get("proxy", "")
    return proxy if proxy else None


def get_timeout() -> float:
    return float(load_config().get("timeout", 30))


def get_max_threads() -> int:
    return int(load_config().get("max_threads", 50))


def new_session_id() -> str:
    sid = f"HK-{int(time.time())}-{os.getpid()}"
    set_value("session_id", sid)
    return sid


def get_ai_key(provider: str) -> Optional[str]:
    keys = get_value("ai_keys", {})
    return keys.get(provider)


def set_ai_key(provider: str, key: str) -> bool:
    cfg = load_config()
    if "ai_keys" not in cfg:
        cfg["ai_keys"] = {}
    cfg["ai_keys"][provider] = key
    cfg["ai_provider"] = provider
    return save_config(cfg)


def config_diff(old: Dict[str, Any], new: Dict[str, Any]) -> List[Tuple[str, Any, Any]]:
    changes = []
    all_keys = set(old.keys()) | set(new.keys())
    for key in sorted(all_keys):
        if key.startswith("_"):
            continue
        ov = old.get(key)
        nv = new.get(key)
        if ov != nv:
            changes.append((key, ov, nv))
    return changes


def export_config(filepath: Optional[str] = None) -> Optional[str]:
    cfg = load_config()
    cfg.pop("_version", None)
    cfg.pop("_created", None)
    cfg.pop("_updated", None)
    if filepath is None:
        filepath = os.path.join(os.path.expanduser("~"), f"hackit_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    try:
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4, ensure_ascii=False)
        return filepath
    except Exception:
        return None


def import_config(filepath: str) -> bool:
    if not os.path.exists(filepath):
        return False
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = load_config()
        for k, v in data.items():
            if k in SCHEMA or k == "ai_keys":
                cfg[k] = v
        return save_config(cfg)
    except Exception:
        return False


def get_schema_info(key: str) -> Optional[Dict[str, Any]]:
    return SCHEMA.get(key)


def list_keys() -> List[str]:
    return [k for k in sorted(SCHEMA.keys()) if not k.startswith("_")]


def apply_masking_level(cfg: Dict[str, Any], level: Optional[str] = None) -> Dict[str, Any]:
    if level is None:
        level = cfg.get("masking_level", "none")
    if level not in MASKING_PROFILES:
        return cfg
    cfg["masking_level"] = level
    profile = MASKING_PROFILES[level]
    for key, value in profile.items():
        cfg[key] = value
    return cfg

_BOOL_MASKING_KEYS = [
    "stealth_mode", "randomize_ua", "randomize_fingerprint",
    "proxy_rotation", "dns_leak_protection", "timing_jitter",
    "header_randomization", "request_padding", "tor_enabled",
    "mac_spoofing", "tls_fingerprint", "ip_rotation",
    "dns_over_https", "tor_stream_isolation", "cache_busting",
    "referer_spoofing", "session_isolation", "adaptive_delays",
    "http2_disable", "packet_fragmentation", "decoy_traffic",
]

_NUM_MASKING_KEYS = ["request_delay_min", "request_delay_max", "proxy_chain_depth", "ip_rotation_freq"]

MASKING_CATEGORIES = {
    "Network":   ["proxy_rotation", "proxy_chain_depth", "ip_rotation", "ip_rotation_freq", "tor_enabled", "tor_stream_isolation"],
    "Headers":   ["randomize_ua", "randomize_fingerprint", "header_randomization", "referer_spoofing", "cache_busting"],
    "Privacy":   ["dns_leak_protection", "dns_over_https", "tls_fingerprint", "http2_disable", "session_isolation"],
    "Evasion":   ["timing_jitter", "adaptive_delays", "request_padding", "packet_fragmentation", "decoy_traffic", "mac_spoofing", "stealth_mode"],
}

def get_masking_info(cfg: Dict[str, Any]) -> Dict[str, Any]:
    level = cfg.get("masking_level", "none")
    profile = MASKING_PROFILES.get(level, MASKING_PROFILES["none"])

    bool_profile_active = [k for k in _BOOL_MASKING_KEYS if profile.get(k)]
    bool_active = [k for k in _BOOL_MASKING_KEYS if cfg.get(k)]

    active_cats = {}
    for cat, keys in MASKING_CATEGORIES.items():
        match = [k for k in keys if k in bool_active]
        if match:
            active_cats[cat] = match

    level_icons = {"none": "○", "basic": "◶", "medium": "◑", "advanced": "◐", "expert": "●", "paranoid": "★"}

    dmin = cfg.get("request_delay_min", profile.get("request_delay_min", 0))
    dmax = cfg.get("request_delay_max", profile.get("request_delay_max", 0))
    pdepth = cfg.get("proxy_chain_depth", profile.get("proxy_chain_depth", 0))
    ipfreq = cfg.get("ip_rotation_freq", profile.get("ip_rotation_freq", 0))

    return {
        "level": level,
        "icon": level_icons.get(level, "○"),
        "enabled_features": bool_active,
        "feature_count": len(bool_active),
        "total_features": len(_BOOL_MASKING_KEYS),
        "categories": active_cats,
        "numeric": {},
        "delay_range": (dmin, dmax),
        "proxy_depth": pdepth,
        "ip_rotate_freq": ipfreq,
    }

def reset_to_defaults() -> bool:
    cfg = DEFAULT_CONFIG.copy()
    cfg["_created"] = datetime.now().isoformat()
    cfg["_updated"] = datetime.now().isoformat()
    return save_config(cfg)
