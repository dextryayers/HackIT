"""Unified AI provider registry for HackIt Agent.

This module is the single source of truth for:
  * provider identifiers and labels
  * API-key resolution (config file -> environment variables)
  * default / fallback model chains
  * live connectivity checks and remote model discovery
  * Ollama (local) detection and model selection

Everything is deliberately dependency-light (requests only) so that the
agent still works when optional AI packages are missing.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------

PROVIDERS: List[str] = [
    "gemini",
    "groq",
    "openai",
    "claude",
    "deepseek",
    "openrouter",
    "mistral",
    "togetherai",
    "ollama",
]

PROVIDER_LABELS: Dict[str, str] = {
    "gemini": "Gemini (Google)",
    "groq": "Groq",
    "openai": "OpenAI",
    "claude": "Claude (Anthropic)",
    "deepseek": "DeepSeek",
    "openrouter": "OpenRouter",
    "mistral": "Mistral AI",
    "togetherai": "Together AI",
    "ollama": "Ollama (Local)",
}

# Environment variable names checked, in order, for each provider.
ENV_KEYS: Dict[str, List[str]] = {
    "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY", "HACKIT_GEMINI_API_KEY"],
    "groq": ["GROQ_API_KEY", "HACKIT_GROQ_API_KEY"],
    "openai": ["OPENAI_API_KEY", "HACKIT_OPENAI_API_KEY"],
    "claude": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "HACKIT_CLAUDE_API_KEY"],
    "deepseek": ["DEEPSEEK_API_KEY", "HACKIT_DEEPSEEK_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY", "HACKIT_OPENROUTER_API_KEY"],
    "mistral": ["MISTRAL_API_KEY", "HACKIT_MISTRAL_API_KEY"],
    "togetherai": ["TOGETHER_API_KEY", "TOGETHERAI_API_KEY", "HACKIT_TOGETHER_API_KEY"],
    "ollama": [],  # local, no key required
}

# Preferred model used when the user has not selected one.
DEFAULT_MODELS: Dict[str, str] = {
    "gemini": "gemini-3.5-flash",
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
    "claude": "claude-sonnet-4-20250514",
    "deepseek": "deepseek-chat",
    "openrouter": "google/gemini-2.5-flash:free",
    "mistral": "mistral-small-latest",
    "togetherai": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "ollama": "llama3",
}

# Every engine tries the configured model first and then walks this chain.
# Keeping a chain makes the agent resilient to provider-side model retirements.
MODEL_FALLBACKS: Dict[str, List[str]] = {
    "gemini": [
        "gemini-3.5-flash",
        "gemini-3.1-flash-lite",
        "gemini-3-flash",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-1.5-flash",
    ],
    "groq": [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "llama-4-scout-17b-16e-instruct",
        "llama-4-maverick-17b-128e-instruct",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
    ],
    "openai": ["gpt-4o-mini", "gpt-4.1-mini", "gpt-4o", "gpt-4.1", "o3-mini", "o1-mini"],
    "claude": [
        "claude-sonnet-4-20250514",
        "claude-3-7-sonnet-20250219",
        "claude-3-5-sonnet-latest",
        "claude-3-5-haiku-latest",
        "claude-3-5-haiku-20241022",
        "claude-3-haiku-20240307",
    ],
    "deepseek": ["deepseek-chat", "deepseek-reasoner", "deepseek-coder"],
    "openrouter": [
        "google/gemini-2.5-flash:free",
        "google/gemini-3-flash-preview:free",
        "deepseek/deepseek-chat-v3-0324:free",
        "deepseek/deepseek-r1:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-coder:free",
        "nvidia/nemotron-3-ultra-550b-a55b:free",
        "mistralai/mistral-small-3.1-24b-instruct:free",
    ],
    "mistral": ["mistral-small-latest", "open-mistral-nemo", "mistral-large-latest", "codestral-latest"],
    "togetherai": [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "meta-llama/Llama-4-Maverick-17B-128E-Instruct",
        "deepseek-ai/DeepSeek-V3",
        "Qwen/Qwen2.5-72B-Instruct-Turbo",
    ],
    "ollama": ["llama3", "llama3.2", "qwen2.5", "mistral", "deepseek-r1", "gemma3"],
}

# Curated model catalogue shown by `agent models` / setup UI.
CURATED_MODELS: Dict[str, List[Tuple[str, str, str]]] = {
    "gemini": [
        ("gemini-3.5-flash", "free", "1M context, newest reasoning"),
        ("gemini-3.1-flash-lite", "free", "high-throughput"),
        ("gemini-3-flash", "free", "balanced"),
        ("gemini-2.5-flash", "free", "multimodal, 1M context"),
        ("gemini-2.0-flash", "free", "high rate limits"),
    ],
    "groq": [
        ("llama-3.3-70b-versatile", "freeish", "fast 70B"),
        ("llama-3.1-8b-instant", "freeish", "lightning fast"),
        ("llama-4-scout-17b-16e-instruct", "freeish", "Llama 4 Scout"),
        ("llama-4-maverick-17b-128e-instruct", "freeish", "Llama 4 Maverick"),
        ("mixtral-8x7b-32768", "freeish", "Mistral MoE"),
        ("gemma2-9b-it", "freeish", "Gemma 2"),
    ],
    "openai": [
        ("gpt-4o-mini", "paid", "cheap and fast"),
        ("gpt-4.1-mini", "paid", "new mini"),
        ("gpt-4o", "paid", "flagship multimodal"),
        ("gpt-4.1", "paid", "GPT-4 generation"),
        ("o3-mini", "paid", "reasoning mini"),
    ],
    "claude": [
        ("claude-sonnet-4-20250514", "paid", "newest Sonnet"),
        ("claude-3-7-sonnet-20250219", "paid", "extended thinking"),
        ("claude-3-5-sonnet-latest", "paid", "balanced"),
        ("claude-3-5-haiku-latest", "paid", "fastest"),
    ],
    "deepseek": [
        ("deepseek-chat", "paid", "best value"),
        ("deepseek-reasoner", "paid", "deep reasoning"),
        ("deepseek-coder", "paid", "code specialist"),
    ],
    "openrouter": [
        ("google/gemini-2.5-flash:free", "free", "1M context"),
        ("google/gemini-3-flash-preview:free", "free", "newest Gemini"),
        ("deepseek/deepseek-chat-v3-0324:free", "free", "general chat"),
        ("deepseek/deepseek-r1:free", "free", "top reasoning"),
        ("meta-llama/llama-3.3-70b-instruct:free", "free", "all-purpose"),
        ("qwen/qwen3-coder:free", "free", "best free coder"),
        ("nvidia/nemotron-3-ultra-550b-a55b:free", "free", "Nemotron Ultra reasoning"),
        ("mistralai/mistral-small-3.1-24b-instruct:free", "free", "multimodal"),
    ],
    "mistral": [
        ("mistral-small-latest", "freeish", "fast"),
        ("open-mistral-nemo", "freeish", "open 12B"),
        ("mistral-large-latest", "freeish", "premium"),
        ("codestral-latest", "freeish", "code"),
    ],
    "togetherai": [
        ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "paid", "per-token"),
        ("meta-llama/Llama-4-Maverick-17B-128E-Instruct", "paid", "Llama 4"),
        ("deepseek-ai/DeepSeek-V3", "paid", "V3"),
        ("Qwen/Qwen2.5-72B-Instruct-Turbo", "paid", "Qwen 72B"),
    ],
    "ollama": [],
}

# Endpoints used for connectivity checks and model discovery.
_MODELS_ENDPOINTS: Dict[str, Tuple[str, str]] = {
    # provider: (url, auth-style)
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/models", "query"),
    "openai": ("https://api.openai.com/v1/models", "bearer"),
    "groq": ("https://api.groq.com/openai/v1/models", "bearer"),
    "deepseek": ("https://api.deepseek.com/models", "bearer"),
    "mistral": ("https://api.mistral.ai/v1/models", "bearer"),
    "togetherai": ("https://api.together.xyz/v1/models", "bearer"),
    "openrouter": ("https://openrouter.ai/api/v1/models", "optional"),
    "claude": ("https://api.anthropic.com/v1/models", "anthropic"),
}

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_provider(name: str) -> str:
    """Map user aliases to canonical provider ids."""
    value = (name or "").strip().lower()
    aliases = {
        "google": "gemini",
        "anthropic": "claude",
        "together": "togetherai",
        "together-ai": "togetherai",
        "open-router": "openrouter",
        "local": "ollama",
        "localhost": "ollama",
        "nemotron": "openrouter",
        "neotron": "openrouter",
        "nvidia": "openrouter",
    }
    return aliases.get(value, value)


def provider_label(provider: str) -> str:
    return PROVIDER_LABELS.get(provider, provider.upper())


def ollama_host() -> str:
    host = os.environ.get("OLLAMA_HOST") or os.environ.get("HACKIT_OLLAMA_HOST") or DEFAULT_OLLAMA_HOST
    host = host.strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    # OLLAMA_HOST may omit the port (e.g. "127.0.0.1"); add default port.
    parsed = host.split("://", 1)[-1]
    if ":" not in parsed:
        host += ":11434"
    return host


def resolve_api_key(provider: str, cfg: Optional[Dict[str, Any]] = None) -> str:
    """Return the API key from config first, then environment variables."""
    provider = normalize_provider(provider)
    if provider == "ollama":
        return "AUTO_DETECT"

    cfg = cfg or {}
    key = ((cfg.get("ai_keys") or {}).get(provider) or "").strip()
    if key and key != "AUTO_DETECT":
        return key

    # Decrypt obfuscated values if the caller passed raw config data.
    if key.startswith("__enc__"):
        try:
            from hackit.config import _deobfuscate

            decrypted = _deobfuscate(key[7:])
            if decrypted:
                return decrypted
        except Exception:
            pass

    for env_name in ENV_KEYS.get(provider, []):
        value = (os.environ.get(env_name) or "").strip()
        if value:
            return value

    # Generic fallbacks used by some tools.
    generic = os.environ.get("HACKIT_AI_KEY")
    if generic and (os.environ.get("HACKIT_AI_PROVIDER") or "").lower() == provider:
        return generic.strip()
    return ""


def configured_providers(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    """Providers that have a key (or local Ollama detection configured)."""
    cfg = cfg or {}
    keys = cfg.get("ai_keys") or {}
    result: List[str] = []
    for provider in PROVIDERS:
        if provider == "ollama":
            if keys.get("ollama") or os.environ.get("HACKIT_OLLAMA_HOST"):
                result.append(provider)
            continue
        if resolve_api_key(provider, cfg):
            result.append(provider)
    return result


def get_active_provider(cfg: Optional[Dict[str, Any]] = None) -> str:
    cfg = cfg or {}
    active = normalize_provider(cfg.get("ai_provider") or "")
    available = configured_providers(cfg)
    if active and active in available:
        return active
    if active and active not in available and resolve_api_key(active, cfg):
        return active
    return available[0] if available else ""


def effective_model(provider: str, cfg: Optional[Dict[str, Any]] = None) -> str:
    cfg = cfg or {}
    model = ((cfg.get("ai_models") or {}).get(provider) or "").strip()
    if model:
        return model
    return DEFAULT_MODELS.get(provider, "")


def model_chain(provider: str, selected: str = "") -> List[str]:
    """Selected model first, then the curated fallback chain, de-duplicated."""
    seen: set = set()
    chain: List[str] = []
    for model in [selected] + MODEL_FALLBACKS.get(provider, []) + [DEFAULT_MODELS.get(provider, "")]:
        if model and model not in seen:
            seen.add(model)
            chain.append(model)
    return chain


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------


@dataclass
class OllamaInfo:
    online: bool = False
    host: str = ""
    version: str = ""
    models: List[str] = field(default_factory=list)
    error: str = ""

    def pick(self, preferred: str = "") -> str:
        return pick_ollama_model(self.models, preferred)


def detect_ollama(timeout: float = 1.5) -> OllamaInfo:
    host = ollama_host()
    info = OllamaInfo(host=host)
    try:
        response = requests.get(f"{host}/api/tags", timeout=timeout)
        if response.status_code != 200:
            info.error = f"HTTP {response.status_code}"
            return info
        payload = response.json()
        info.models = [item.get("name", "") for item in payload.get("models", []) if item.get("name")]
        info.online = True
    except Exception as exc:  # noqa: BLE001 - connectivity check must never raise
        info.error = str(exc)
        return info

    try:
        version_response = requests.get(f"{host}/api/version", timeout=timeout)
        if version_response.status_code == 200:
            info.version = version_response.json().get("version", "")
    except Exception:
        pass
    return info


def pick_ollama_model(models: Iterable[str], preferred: str = "") -> str:
    available = [m for m in models if m]
    if not available:
        return preferred or DEFAULT_MODELS["ollama"]

    def matches(model: str, candidate: str) -> bool:
        return candidate == model or candidate.split(":")[0] == model.split(":")[0]

    if preferred and preferred not in ("AUTO_DETECT", "auto"):
        for model in available:
            if matches(model, preferred):
                return model

    priorities = ["nemotron", "qwen", "deepseek", "llama", "mistral", "gemma", "phi", "codestral"]
    for needle in priorities:
        for model in available:
            if needle in model.lower():
                return model
    return available[0]


# ---------------------------------------------------------------------------
# Connectivity / discovery
# ---------------------------------------------------------------------------


@dataclass
class ProviderStatus:
    provider: str
    label: str
    configured: bool
    reachable: Optional[bool]
    latency_ms: Optional[int] = None
    models: List[str] = field(default_factory=list)
    error: str = ""
    detail: str = ""

    @property
    def state(self) -> str:
        if self.provider == "ollama":
            if not self.configured:
                return "not-configured"
            return "ready" if self.reachable else "offline"
        if not self.configured:
            return "not-configured"
        if self.reachable is False:
            return "unreachable"
        if self.reachable is None:
            return "configured"
        return "ready"


def _extract_model_ids(provider: str, payload: Any) -> List[str]:
    try:
        if provider == "gemini":
            return [m.get("name", "").replace("models/", "", 1) for m in payload.get("models", []) if m.get("name")]
        if provider == "openrouter":
            return [m.get("id", "") for m in payload.get("data", []) if m.get("id")]
        # OpenAI-compatible and Anthropic both use {"data": [{"id": ...}]}
        data = payload.get("data", [])
        ids = []
        for item in data:
            if isinstance(item, dict):
                model_id = item.get("id") or item.get("name")
                if model_id:
                    ids.append(str(model_id).replace("models/", "", 1))
        return ids
    except Exception:
        return []


def list_remote_models(provider: str, key: Optional[str] = None, timeout: float = 5.0) -> List[str]:
    provider = normalize_provider(provider)
    if provider == "ollama":
        return detect_ollama(timeout=timeout).models
    endpoint = _MODELS_ENDPOINTS.get(provider)
    if not endpoint:
        return []
    url, auth_style = endpoint
    key = key if key is not None else resolve_api_key(provider)
    headers: Dict[str, str] = {}
    params: Dict[str, str] = {}
    if auth_style == "query":
        params["key"] = key
    elif auth_style == "bearer" and key:
        headers["Authorization"] = f"Bearer {key}"
    elif auth_style == "optional" and key:
        headers["Authorization"] = f"Bearer {key}"
    elif auth_style == "anthropic" and key:
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        if response.status_code != 200:
            return []
        return _extract_model_ids(provider, response.json())
    except Exception:
        return []


def check_provider(provider: str, key: Optional[str] = None, cfg: Optional[Dict[str, Any]] = None,
                   timeout: float = 4.0) -> ProviderStatus:
    provider = normalize_provider(provider)
    cfg = cfg or {}
    label = provider_label(provider)
    status = ProviderStatus(provider=provider, label=label, configured=False, reachable=None)

    if provider == "ollama":
        info = detect_ollama(timeout=timeout)
        status.configured = info.online or bool((cfg.get("ai_keys") or {}).get("ollama")) or bool(
            (cfg.get("ai_models") or {}).get("ollama")
        )
        status.reachable = info.online
        status.models = info.models
        status.error = info.error
        status.detail = f"models={len(info.models)}" + (f" v{info.version}" if info.version else "")
        return status

    key = key if key is not None else resolve_api_key(provider, cfg)
    status.configured = bool(key)
    if not key:
        return status

    endpoint = _MODELS_ENDPOINTS.get(provider)
    if not endpoint:
        return status

    url, auth_style = endpoint
    headers: Dict[str, str] = {}
    params: Dict[str, str] = {}
    if auth_style == "query":
        params["key"] = key
    elif auth_style == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    elif auth_style == "optional" and key:
        headers["Authorization"] = f"Bearer {key}"
    elif auth_style == "anthropic":
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"

    started = time.time()
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        status.latency_ms = int((time.time() - started) * 1000)
        status.reachable = response.status_code == 200
        if status.reachable:
            status.models = _extract_model_ids(provider, response.json())
            status.detail = f"models={len(status.models)}"
        else:
            try:
                body = response.json()
                message = body.get("error", {}).get("message") if isinstance(body.get("error"), dict) else body.get("error")
                status.error = str(message or f"HTTP {response.status_code}")[:240]
            except Exception:
                status.error = f"HTTP {response.status_code}"
    except Exception as exc:  # noqa: BLE001
        status.reachable = False
        status.error = str(exc)[:240]

    return status


def doctor(cfg: Optional[Dict[str, Any]] = None, timeout: float = 4.0) -> List[ProviderStatus]:
    """Probe every configured provider concurrently.

    Unconfigured providers are skipped (except a reachable local Ollama) so the
    command stays fast and does not generate needless network traffic.
    """
    from concurrent.futures import ThreadPoolExecutor

    cfg = cfg or {}
    keys = {provider: resolve_api_key(provider, cfg) for provider in PROVIDERS}

    def probe(provider: str) -> ProviderStatus:
        return check_provider(provider, key=keys.get(provider, ""), cfg=cfg, timeout=timeout)

    statuses: List[ProviderStatus] = []
    with ThreadPoolExecutor(max_workers=min(9, max(1, len(PROVIDERS)))) as executor:
        results = list(executor.map(probe, PROVIDERS))
    for status in results:
        if status.provider == "ollama":
            if status.configured or status.reachable:
                statuses.append(status)
            continue
        if status.configured:
            statuses.append(status)
    return statuses


def model_options(provider: str, key: Optional[str] = None, include_remote: bool = True) -> List[Tuple[str, str, str]]:
    """Return (model, tier, description) tuples for selection UIs."""
    provider = normalize_provider(provider)
    if provider == "ollama":
        info = detect_ollama()
        return [(model, "free", "Local Ollama model") for model in info.models]

    curated = list(CURATED_MODELS.get(provider, []))
    seen = {item[0].lower() for item in curated}
    if include_remote:
        for model in list_remote_models(provider, key=key):
            if model.lower() in seen:
                continue
            tier = "free" if provider == "openrouter" and model.endswith(":free") else "freeish"
            curated.append((model, tier, "From provider API"))
            seen.add(model.lower())
    return curated
