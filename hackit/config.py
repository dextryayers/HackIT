import json
import os
import getpass
import socket

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".hackit_config.json")

DEFAULT_CONFIG = {
    "theme": "kali",
    "user": getpass.getuser(),
    "hostname": socket.gethostname(),
    "accent": "cyan",
    "border": "double",
    "prompt": "arrow"
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            for k, v in data.items():
                if k in merged:
                    merged[k] = v
            return merged
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(config):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        tmp_path = CONFIG_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(config, f, indent=4)
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
