"""Live token-usage tracking for HackIt Agent.

No provider exposes usage through the NDJSON stream, so tokens are
estimated from character counts (the standard ~1 token ≈ 4 characters
for English text).  Counts are exact for what the agent saw: prompt,
reasoning and answer text streamed through :mod:`hackit.agent.brain`.
Session totals are kept in memory and appended to
``~/.hackit/token_usage.json`` so they survive terminal restarts.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

USAGE_DIR = os.path.join(os.path.expanduser("~"), ".hackit")
USAGE_PATH = os.path.join(USAGE_DIR, "token_usage.json")
MAX_HISTORY = 500


def estimate_tokens(text: str) -> int:
    """Approximate token count for a text fragment."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def _load_history() -> List[Dict[str, Any]]:
    try:
        if not os.path.exists(USAGE_PATH):
            return []
        with open(USAGE_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("history"), list):
            return data["history"]
    except Exception:
        pass
    return []


@dataclass
class UsageRecord:
    started: float = field(default_factory=time.time)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    turns: int = 0
    provider: str = ""
    model: str = ""

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens + self.reasoning_tokens

    def summary(self) -> Dict[str, Any]:
        return {
            "prompt": self.prompt_tokens,
            "completion": self.completion_tokens,
            "reasoning": self.reasoning_tokens,
            "total": self.total_tokens,
            "turns": self.turns,
            "provider": self.provider,
            "model": self.model,
            "session_seconds": int(time.time() - self.started),
        }


class TokenMeter:
    """Track one brain instance's token consumption in real time."""

    def __init__(self, provider: str = "", model: str = "") -> None:
        self.record = UsageRecord(provider=provider, model=model)

    def set_model(self, provider: str, model: str) -> None:
        self.record.provider = provider or self.record.provider
        self.record.model = model or self.record.model

    def add_prompt(self, text: str) -> int:
        tokens = estimate_tokens(text or "")
        self.record.prompt_tokens += tokens
        return tokens

    def add_stream(self, kind: str, text: str) -> int:
        tokens = estimate_tokens(text or "")
        if kind == "thinking":
            self.record.reasoning_tokens += tokens
        else:
            self.record.completion_tokens += tokens
        return tokens

    def finish_turn(self) -> Dict[str, Any]:
        self.record.turns += 1
        snapshot = self.record.summary()
        self.persist(snapshot)
        return snapshot

    def summary(self) -> Dict[str, Any]:
        return self.record.summary()

    def total(self) -> int:
        return self.record.total_tokens

    def format(self) -> str:
        s = self.summary()
        return (
            f"~{s['total']:,} tok "
            f"(prompt {s['prompt']:,} · completion {s['completion']:,} · "
            f"reasoning {s['reasoning']:,}) · {s['turns']} turn(s)"
        )

    def persist(self, snapshot: Optional[Dict[str, Any]] = None) -> None:
        if snapshot is None:
            snapshot = self.record.summary()
        record = dict(snapshot)
        record["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            os.makedirs(USAGE_DIR, exist_ok=True)
            history = _load_history()
            history.append(record)
            history = history[-MAX_HISTORY:]
            with open(USAGE_PATH, "w", encoding="utf-8") as handle:
                json.dump(
                    {"updated": record["ts"], "history": history},
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )
        except Exception:
            pass


def session_totals(history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Aggregate totals across persisted sessions."""
    history = history if history is not None else _load_history()
    total = sum(int(item.get("total", 0)) for item in history)
    turns = sum(int(item.get("turns", 0)) for item in history)
    prompt = sum(int(item.get("prompt", 0)) for item in history)
    completion = sum(int(item.get("completion", 0)) for item in history)
    return {
        "total": total,
        "prompt": prompt,
        "completion": completion,
        "turns": turns,
        "entries": len(history),
        "history": history,
    }


def format_total(totals: Dict[str, Any]) -> str:
    return (
        f"~{totals['total']:,} tokens · {totals['turns']} turn(s) · "
        f"{totals['entries']} session(s)"
    )
