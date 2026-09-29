"""Robust module loader for the OSINT module library.

Why this exists
---------------
Modules in ``modules/`` were written by different authors and use two
different import styles for the shared helpers:

    from module_common import safe_fetch      # 189 modules (top level)
    from ..module_common import safe_fetch    #  13 modules (package relative)

The orchestrator loads modules by file path, so the relative style raised
``ImportError: attempted relative import with no known parent package`` and
those 13 modules silently never ran.

This loader mounts the python directory as a real package (``webui_pkg``),
aliases the shared helpers inside it, and then loads every module under
``webui_pkg.modules.<name>``. That makes both import styles resolve to the
same objects, with no per module patching and no duplicated helper code.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import threading
import types
from typing import Any, Dict, List, Optional

PY_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(PY_DIR, "modules")

PKG = "webui_pkg"
MODS_PKG = f"{PKG}.modules"

# Shared helpers that may be imported with a package relative path.
_SHARED = (
    "module_common",
    "module_base",
    "models",
    "settings_store",
    "osint_common",
)

_lock = threading.Lock()
_cache: Dict[str, Any] = {}
_errors: Dict[str, str] = {}
_ensured = False


def ensure_importable() -> None:
    """Put the python directory on sys.path and build the synthetic package."""
    global _ensured
    with _lock:
        if _ensured:
            return
        if PY_DIR not in sys.path:
            sys.path.insert(0, PY_DIR)

        pkg = types.ModuleType(PKG)
        pkg.__path__ = [PY_DIR]  # type: ignore[attr-defined]
        pkg.__doc__ = "HackIT webUI backend package (synthetic, for relative imports)"
        sys.modules.setdefault(PKG, pkg)

        mods = types.ModuleType(MODS_PKG)
        mods.__path__ = [MODULES_DIR]  # type: ignore[attr-defined]
        mods.__doc__ = "HackIT OSINT module library"
        sys.modules.setdefault(MODS_PKG, mods)
        setattr(pkg, "modules", mods)

        for name in _SHARED:
            try:
                real = importlib.import_module(name)
            except Exception:  # pragma: no cover - helper missing
                continue
            sys.modules[f"{PKG}.{name}"] = real
            setattr(pkg, name, real)

        importlib.invalidate_caches()
        _ensured = True


def module_path(name: str) -> Optional[str]:
    path = os.path.join(MODULES_DIR, f"{name}.py")
    return path if os.path.isfile(path) else None


def load(name: str) -> Optional[Any]:
    """Load one module by name. Returns None and records the error on failure."""
    ensure_importable()
    with _lock:
        if name in _cache:
            return _cache[name]
        if name in _errors:
            return None

    path = module_path(name)
    if path is None:
        with _lock:
            _errors[name] = "file not found"
        return None

    qualname = f"{MODS_PKG}.{name}"
    try:
        spec = importlib.util.spec_from_file_location(qualname, path)
        if spec is None or spec.loader is None:
            raise ImportError("no loader for module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[qualname] = module
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(qualname, None)
        with _lock:
            _errors[name] = f"{type(exc).__name__}: {exc}"
        return None

    with _lock:
        _cache[name] = module
        _errors.pop(name, None)
    return module


def load_error(name: str) -> Optional[str]:
    with _lock:
        return _errors.get(name)


def available_modules() -> List[str]:
    if not os.path.isdir(MODULES_DIR):
        return []
    return sorted(
        f[:-3]
        for f in os.listdir(MODULES_DIR)
        if f.endswith(".py") and f not in ("__init__.py", "module_common.py")
    )


def preload(names: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
    """Load many modules once. Returns {name: error or None}."""
    ensure_importable()
    names = names if names is not None else available_modules()
    return {name: load_error(name) or "" for name in names if load(name) is None}


def clear_cache() -> None:
    with _lock:
        _cache.clear()
        _errors.clear()
