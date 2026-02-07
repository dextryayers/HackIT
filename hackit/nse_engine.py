"""
Minimal NSE-like scripting engine loader.
Scripts placed under `hackit/nse_scripts/` must implement a `run(host, port, info)` function
that returns a list of findings (dicts) or an empty list.
"""
from importlib import import_module
from pathlib import Path
from typing import List, Dict, Any

SCRIPTS_PACKAGE = 'hackit.nse_scripts'
SCRIPTS_PATH = Path(__file__).parent / 'nse_scripts'


def load_scripts() -> List[str]:
    """Return list of available script module names (without package prefix)."""
    scripts = []
    if not SCRIPTS_PATH.exists():
        return scripts
    for p in SCRIPTS_PATH.glob('*.py'):
        if p.name == '__init__.py':
            continue
        scripts.append(p.stem)
    return scripts


def run_scripts_for_port(script_names: List[str], host: str, port: int, info: Dict[str, Any]) -> List[Dict]:
    """Run selected scripts (by name) against host:port.
    `info` contains scan info (status, banner, service, etc.)
    Returns aggregated list of findings.
    """
    findings = []
    for name in script_names:
        try:
            mod = import_module(f"{SCRIPTS_PACKAGE}.{name}")
            if hasattr(mod, 'run'):
                try:
                    out = mod.run(host, port, info) or []
                    if isinstance(out, list):
                        findings.extend(out)
                except Exception:
                    # script-level errors should not crash the engine
                    findings.append({
                        'script': name,
                        'error': 'script execution error'
                    })
        except ModuleNotFoundError:
            findings.append({'script': name, 'error': 'not found'})
        except Exception:
            findings.append({'script': name, 'error': 'load error'})
    return findings
