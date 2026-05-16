import json
import os
import getpass
import socket

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".hackit_config.json")

DEFAULT_CONFIG = {
    "theme": "kali",
    "user": getpass.getuser(),
    "hostname": socket.gethostname(),
    "aggressive_default": True,
    "stealth_default": True,
    "ai_keys": {
        "gemini": "",
        "groq": "",
        "openai": "",
        "claude": "",
        "deepseek": "",
        "openrouter": "",
        "ollama": "llama3"
    },
    "ai_provider": "gemini"
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
            # Deep merge with defaults to ensure all keys exist
            merged = DEFAULT_CONFIG.copy()
            for k, v in data.items():
                if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
                    merged[k].update(v)
                else:
                    merged[k] = v
            return merged
    except Exception:
        return DEFAULT_CONFIG

def save_config(config):
    try:
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        
        # Write to a temporary file first for atomic-like safety
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
        
        # Replace the real config file
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        os.rename(tmp_path, CONFIG_PATH)
        return True
    except Exception as e:
        print(f"  [!] Config save error: {str(e)}")
        return False

def get_theme():
    config = load_config()
    return config.get("theme", "kali")

def set_theme(theme_name):
    config = load_config()
    config["theme"] = theme_name
    save_config(config)

def get_user_info():
    config = load_config()
    user = config.get("user") or getpass.getuser()
    host = config.get("hostname") or socket.gethostname()
    return user, host
