"""Conversation memory for HackIt Agent.

The memory layer has two backends:

* ``langchain`` – uses ``ConversationBufferWindowMemory`` when the optional
  LangChain package is installed.  This gives the agent a real message window
  with the same semantics as a LangChain chain.
* ``builtin`` – a zero-dependency JSON window that keeps the agent fully
  functional on minimal installations.

Both backends persist to ``~/.hackit/agent_memory/<session>.json`` so memory
survives across terminal sessions.  Long-term facts (targets, CVEs, domains)
are kept separately from the rolling conversation window.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

MEMORY_DIR = os.path.join(os.path.expanduser("~"), ".hackit", "agent_memory")
MAX_WINDOW = 16
MAX_CONTEXT_CHARS = 6000

_LANGCHAIN_AVAILABLE = False
_LANGCHAIN_ERROR = ""
_LANGCHAIN_IMPL = ""
ConversationBufferWindowMemory = None  # type: ignore
_HumanMessage = None  # type: ignore
_AIMessage = None  # type: ignore

try:  # pragma: no cover - optional dependency
    # langchain-core is the stable baseline and is present in every 1.x
    # installation.  It also lets memory work when only the core package is
    # installed.
    from langchain_core.messages import AIMessage as _AIMessage  # type: ignore
    from langchain_core.messages import HumanMessage as _HumanMessage  # type: ignore

    _LANGCHAIN_AVAILABLE = True
    _LANGCHAIN_IMPL = "langchain_core"
    try:
        # LangChain <=0.3 exposes the official windowed memory class.  It was
        # removed in 1.x, so this import is intentionally best-effort.
        from langchain.memory import ConversationBufferWindowMemory  # type: ignore

        _LANGCHAIN_IMPL = "langchain.memory"
    except Exception:  # noqa: BLE001 - optional legacy API
        pass
except Exception as exc:  # noqa: BLE001 - optional
    _LANGCHAIN_ERROR = str(exc)


def langchain_available() -> bool:
    return _LANGCHAIN_AVAILABLE


def langchain_error() -> str:
    return _LANGCHAIN_ERROR


def langchain_impl() -> str:
    return _LANGCHAIN_IMPL


class _CoreWindowMemory:
    """Windowed history backed by LangChain Core message objects.

    LangChain 1.x removed ``langchain.memory``.  This adapter preserves the
    HumanMessage/AIMessage semantics and exposes the small
    ``save_context``/``load_memory_variables`` surface used by
    :class:`AgentMemory`, without depending on the legacy package.
    """

    def __init__(self, k: int):
        self.k = max(1, int(k))
        self._messages: List[Any] = []

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, Any]) -> None:
        input_text = str((inputs or {}).get("input", "") or "").strip()
        output_text = str((outputs or {}).get("output", "") or "").strip()
        if input_text:
            self._messages.append(_HumanMessage(content=input_text))
        if output_text:
            self._messages.append(_AIMessage(content=output_text))
        del self._messages[: max(0, len(self._messages) - self.k * 2)]

    def load_memory_variables(
        self, _inputs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        lines: List[str] = []
        for message in self._messages:
            role = getattr(message, "type", "")
            label = "User" if role == "human" else "Assistant" if role == "ai" else "Note"
            lines.append(f"{label}: {message.content}")
        return {"history": "\n".join(lines)}

    def clear(self) -> None:
        self._messages.clear()


def _make_langchain_memory(k: int):
    """Return the best available LangChain windowed-memory backend."""
    if ConversationBufferWindowMemory is not None:
        try:
            return ConversationBufferWindowMemory(
                k=k,
                memory_key="history",
                return_messages=False,
            )
        except Exception:  # noqa: BLE001 - fall through to the core adapter
            pass
    if _HumanMessage is not None and _AIMessage is not None:
        return _CoreWindowMemory(k=k)
    raise RuntimeError("no LangChain memory backend is available")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "default").strip("._")
    return cleaned[:80] or "default"


@dataclass
class MemoryEntry:
    role: str
    content: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role, "content": self.content, "timestamp": self.timestamp}


class AgentMemory:
    """Rolling conversation memory with optional LangChain backend."""

    def __init__(self, session: str = "default", window: int = MAX_WINDOW,
                 use_langchain: bool = True, memory_dir: Optional[str] = None):
        self.session = _slug(session)
        self.window = max(2, min(int(window or MAX_WINDOW), 64))
        self.memory_dir = memory_dir or MEMORY_DIR
        self.backend = "builtin"
        self._entries: List[MemoryEntry] = []
        self._facts: List[str] = []
        self._lc_memory = None
        self._path = os.path.join(self.memory_dir, f"{self.session}.json")
        self._load()

        if use_langchain and _LANGCHAIN_AVAILABLE:
            try:
                self._lc_memory = _make_langchain_memory(self.window)
                # Replay persisted messages into the LangChain window.
                pending_user = None
                for entry in self._entries:
                    if entry.role == "user":
                        pending_user = entry.content
                    elif entry.role == "assistant" and pending_user is not None:
                        self._lc_memory.save_context({"input": pending_user}, {"output": entry.content})
                        pending_user = None
                self.backend = "langchain"
            except Exception:  # noqa: BLE001 - degrade gracefully
                self._lc_memory = None
                self.backend = "builtin"

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            self._entries = [
                MemoryEntry(
                    role=str(item.get("role", "")),
                    content=str(item.get("content", "")),
                    timestamp=float(item.get("timestamp", time.time())),
                )
                for item in data.get("messages", [])
                if item.get("role") and item.get("content")
            ][-self.window * 2:]
            self._facts = [str(fact) for fact in data.get("facts", []) if fact][-64:]
        except (OSError, ValueError, TypeError):
            self._entries = []
            self._facts = []

    def save(self) -> bool:
        try:
            os.makedirs(self.memory_dir, exist_ok=True)
            payload = {
                "session": self.session,
                "backend": self.backend,
                "updated_at": time.time(),
                "facts": self._facts,
                "messages": [entry.to_dict() for entry in self._entries],
            }
            tmp_path = self._path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self._path)
            return True
        except OSError:
            return False

    # -- writing ---------------------------------------------------------

    def add_user(self, content: str) -> None:
        self._append("user", content)
        self.extract_facts(content)

    def add_assistant(self, content: str) -> None:
        self._append("assistant", content)

    def add_system(self, content: str) -> None:
        self._append("system", content)

    def _append(self, role: str, content: str) -> None:
        content = (content or "").strip()
        if not content:
            return
        self._entries.append(MemoryEntry(role=role, content=content))
        # Keep a bounded window (user+assistant pairs).
        del self._entries[: max(0, len(self._entries) - self.window * 2)]
        if self._lc_memory is not None and role in ("user", "assistant"):
            # LangChain needs an input/output pair; buffer incomplete turns
            # until the assistant reply arrives.
            if role == "user":
                self._pending_user = content
            elif getattr(self, "_pending_user", None):
                try:
                    self._lc_memory.save_context({"input": self._pending_user}, {"output": content})
                except Exception:
                    pass
                self._pending_user = None

    def remember(self, fact: str) -> None:
        fact = (fact or "").strip()
        if fact and fact not in self._facts:
            self._facts.append(fact)
            self._facts = self._facts[-64:]

    def extract_facts(self, text: str) -> None:
        """Extract durable facts (targets, CVEs, domains) from user input."""
        if not text:
            return
        patterns = [
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "target-ip"),
            (r"\bhttps?://[^\s)>\]]+", "target-url"),
            (r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", "target-domain"),
            (r"\bCVE-\d{4}-\d{4,7}\b", "cve"),
        ]
        for pattern, label in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                if label == "target-domain" and match.lower().endswith(
                    (".py", ".go", ".js", ".json", ".md", ".txt", ".html", ".css")
                ):
                    continue
                self.remember(f"{label}:{match}")

    # -- reading ---------------------------------------------------------

    def context(self, max_chars: int = MAX_CONTEXT_CHARS) -> str:
        """Return a compact, provider-agnostic memory block for the prompt."""
        parts: List[str] = []
        if self._facts:
            parts.append("Known facts:\n" + "\n".join(f"- {fact}" for fact in self._facts[-24:]))

        history = ""
        if self._lc_memory is not None:
            try:
                history = str(self._lc_memory.load_memory_variables({}).get("history", "") or "").strip()
            except Exception:
                history = ""
        if not history:
            recent = self._entries[-self.window:]
            lines = []
            for entry in recent:
                label = {"user": "User", "assistant": "Assistant", "system": "Note"}.get(entry.role, entry.role)
                lines.append(f"{label}: {entry.content}")
            history = "\n".join(lines)

        if history:
            parts.append("Recent conversation:\n" + history)
        block = "\n\n".join(parts).strip()
        if len(block) > max_chars:
            block = block[-max_chars:]
        return block

    def snapshot(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self._entries]

    def stats(self) -> Dict[str, Any]:
        approx_tokens = sum(max(1, len(entry.content) // 4) for entry in self._entries)
        return {
            "session": self.session,
            "backend": self.backend,
            "messages": len(self._entries),
            "facts": len(self._facts),
            "approx_tokens": approx_tokens,
            "path": self._path,
            "langchain_available": _LANGCHAIN_AVAILABLE,
            "langchain_impl": _LANGCHAIN_IMPL,
        }

    # -- lifecycle -------------------------------------------------------

    def clear(self, keep_facts: bool = False) -> None:
        self._entries = []
        if not keep_facts:
            self._facts = []
        if self._lc_memory is not None:
            try:
                self._lc_memory.clear()
            except Exception:
                pass
        try:
            os.remove(self._path)
        except OSError:
            pass

    def forget_facts(self) -> None:
        self._facts = []
        self.save()

    def export(self, path: str) -> str:
        payload = {
            "session": self.session,
            "backend": self.backend,
            "facts": self._facts,
            "messages": self.snapshot(),
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        return path

    def import_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        count = 0
        for item in payload.get("messages", []):
            role = item.get("role")
            content = item.get("content")
            if role in ("user", "assistant", "system") and content:
                self._append(role, str(content))
                count += 1
        for fact in payload.get("facts", []):
            self.remember(str(fact))
        self.save()
        return count


def memory_session_name(engine: str = "chat", target: str = "") -> str:
    """Build a stable session name for chat/autopilot memory."""
    if target:
        return f"{engine}_{_slug(target)}"
    return f"{engine}_default"
