import json
import os
import getpass
import socket
import time
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".hackit_config.json")
CONFIG_BACKUP_PATH = CONFIG_PATH + ".bak"

VALID_THEMES = [
    "kali", "cyberpunk", "minimalist", "retro", "gacor", "powerline",
    "modern", "pill", "nexus", "zinc", "vault", "storm", "drift", "pulse", "slash"
]
VALID_ACCENTS = ["cyan", "magenta", "green", "blue", "red", "yellow", "white"]
VALID_BORDERS = ["double", "single", "rounded", "block", "ascii", "none"]
VALID_PROMPTS = ["arrow", "hash", "dollar", "lambda", "skull", "none"]

DEFAULT_CONFIG: Dict[str, Any] = {
    "theme": "kali",
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
}

VALIDATORS = {
    "theme": lambda v: v in VALID_THEMES,
    "accent": lambda v: v in VALID_ACCENTS,
    "border": lambda v: v in VALID_BORDERS,
    "prompt": lambda v: v in VALID_PROMPTS,
    "timeout": lambda v: isinstance(v, (int, float)) and 1 <= v <= 300,
    "max_threads": lambda v: isinstance(v, int) and 1 <= v <= 1000,
    "stealth_mode": lambda v: isinstance(v, bool),
    "verify_ssl": lambda v: isinstance(v, bool),
    "output_format": lambda v: v in ("json", "csv", "xml", "markdown", "table"),
    "auto_save_reports": lambda v: isinstance(v, bool),
    "history_size": lambda v: isinstance(v, int) and 100 <= v <= 50000,
}


def _validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    for key, validator in VALIDATORS.items():
        if key in cfg and not validator(cfg[key]):
            cfg[key] = DEFAULT_CONFIG.get(key)
    return cfg


def _env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    mapping = {
        "HACKIT_THEME": "theme",
        "HACKIT_PROXY": "proxy",
        "HACKIT_TIMEOUT": "timeout",
        "HACKIT_THREADS": "max_threads",
        "HACKIT_OUTPUT": "output_format",
    }
    for env_key, cfg_key in mapping.items():
        val = os.environ.get(env_key)
        if val is not None:
            if cfg_key in ("timeout",):
                try:
                    val = float(val)
                except ValueError:
                    continue
            elif cfg_key in ("max_threads",):
                try:
                    val = int(val)
                except ValueError:
                    continue
            cfg[cfg_key] = val
    return cfg


def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        for k, v in data.items():
            merged[k] = v
        merged = _validate_config(merged)
        merged = _env_overrides(merged)
        return merged
    except (json.JSONDecodeError, IOError):
        if os.path.exists(CONFIG_BACKUP_PATH):
            try:
                with open(CONFIG_BACKUP_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                merged = DEFAULT_CONFIG.copy()
                merged.update(data)
                return _validate_config(merged)
            except Exception:
                pass
        return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any]) -> bool:
    config = _validate_config(config)
    try:
        parent = os.path.dirname(CONFIG_PATH)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(CONFIG_PATH):
            try:
                import shutil
                shutil.copy2(CONFIG_PATH, CONFIG_BACKUP_PATH)
            except Exception:
                pass
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        os.rename(tmp_path, CONFIG_PATH)
        return True
    except Exception as e:
        print(f"  [!] Config save error: {e}")
        return False


def get_theme() -> str:
    return load_config().get("theme", "kali")


def set_theme(theme_name: str) -> bool:
    if theme_name not in VALID_THEMES:
        return False
    config = load_config()
    config["theme"] = theme_name
    return save_config(config)


def get_user_info():
    config = load_config()
    user = config.get("user") or getpass.getuser()
    host = config.get("hostname") or socket.gethostname()
    return user, host


def get_value(key: str, default: Any = None) -> Any:
    return load_config().get(key, default)


def set_value(key: str, value: Any) -> bool:
    config = load_config()
    config[key] = value
    return save_config(config)


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
