"""
HackIt NSE-like Scripting Engine v2
- Loads Python scripts from hackit/nse_scripts/
- Loads and validates Lua .nse scripts via subprocess
- Parallel execution with configurable concurrency
- Script categorization (discovery, vuln, brute, exploit, dos)
- Result aggregation with severity scoring
- Script dependency resolution
"""
import os
import subprocess
import json
import time
from importlib import import_module
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPTS_PACKAGE = 'hackit.nse_scripts'
SCRIPTS_PATH = Path(__file__).parent / 'nse_scripts'

CATEGORIES = {
    'discovery': 'Service and version discovery scripts',
    'vuln': 'Vulnerability detection scripts',
    'brute': 'Brute-force authentication scripts',
    'exploit': 'Active exploitation scripts',
    'dos': 'Denial of service detection',
    'auth': 'Authentication bypass scripts',
    'default': 'Default safe scripts',
    'intrusive': 'Potentially disruptive scripts',
    'malware': 'Malware detection scripts',
    'safe': 'Non-intrusive information gathering',
}

SEVERITY_SCORES = {
    'critical': 10,
    'high': 8,
    'medium': 5,
    'low': 3,
    'info': 1,
}


def _detect_category(script_path: str) -> str:
    name = os.path.basename(script_path).lower()
    mapping = {
        'brute': 'brute', 'login': 'brute', 'auth': 'auth',
        'vuln': 'vuln', 'cve': 'vuln', 'exploit': 'exploit',
        'enum': 'discovery', 'discover': 'discovery', 'info': 'discovery',
        'dos': 'dos', 'flood': 'dos', 'malware': 'malware',
    }
    for keyword, cat in mapping.items():
        if keyword in name:
            return cat
    return 'default'


def load_scripts(category: Optional[str] = None) -> List[Dict[str, Any]]:
    scripts = []
    if not SCRIPTS_PATH.exists():
        return scripts

    for p in SCRIPTS_PATH.iterdir():
        if p.name == '__init__.py' or p.name.startswith('.'):
            continue

        entry = {
            'name': p.stem,
            'path': str(p),
            'category': _detect_category(str(p)),
        }

        if p.suffix == '.py':
            entry['type'] = 'python'
        elif p.suffix in ('.nse', '.lua'):
            entry['type'] = 'lua'
        else:
            continue

        if category and entry['category'] != category:
            continue

        scripts.append(entry)

    return sorted(scripts, key=lambda s: (s['category'], s['name']))


def load_script_names(category: Optional[str] = None) -> List[str]:
    return [s['name'] for s in load_scripts(category)]


def validate_lua_script(script_path: str) -> bool:
    try:
        result = subprocess.run(
            ['lua', '-e', f'loadfile("{script_path}")'],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_python_script(name: str, host: str, port: int, info: Dict[str, Any]) -> List[Dict]:
    findings = []
    try:
        mod = import_module(f"{SCRIPTS_PACKAGE}.{name}")
        if hasattr(mod, 'run'):
            start = time.time()
            out = mod.run(host, port, info) or []
            elapsed = time.time() - start

            if isinstance(out, list):
                for finding in out:
                    if isinstance(finding, dict):
                        finding.setdefault('script', name)
                        finding.setdefault('severity', 'info')
                        finding.setdefault('elapsed', round(elapsed, 3))
                        findings.append(finding)
            elif isinstance(out, dict):
                out.setdefault('script', name)
                out.setdefault('severity', 'info')
                out.setdefault('elapsed', round(elapsed, 3))
                findings.append(out)
    except ModuleNotFoundError:
        findings.append({'script': name, 'error': 'module not found', 'severity': 'info'})
    except Exception as e:
        findings.append({'script': name, 'error': str(e), 'severity': 'info'})
    return findings


def _run_lua_script(script_path: str, host: str, port: int, info: Dict[str, Any]) -> List[Dict]:
    name = os.path.basename(script_path).rsplit('.', 1)[0]
    findings = []

    try:
        env_data = json.dumps({
            'host': host,
            'port': port,
            'info': info,
        })

        result = subprocess.run(
            ['lua', script_path, host, str(port)],
            input=env_data,
            capture_output=True, text=True, timeout=30,
            env={**os.environ, 'NSE_HOST': host, 'NSE_PORT': str(port)},
        )

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        parsed.setdefault('script', name)
                        parsed.setdefault('severity', 'info')
                        findings.append(parsed)
                except json.JSONDecodeError:
                    if line.startswith('VULN:') or line.startswith('FINDING:'):
                        findings.append({'script': name, 'output': line, 'severity': 'info'})
                    elif line:
                        findings.append({'script': name, 'output': line, 'severity': 'info'})
        elif result.stderr.strip():
            findings.append({'script': name, 'error': result.stderr.strip()[:200], 'severity': 'info'})

    except subprocess.TimeoutExpired:
        findings.append({'script': name, 'error': 'execution timeout', 'severity': 'info'})
    except FileNotFoundError:
        findings.append({'script': name, 'error': 'lua interpreter not found', 'severity': 'info'})
    except Exception as e:
        findings.append({'script': name, 'error': str(e), 'severity': 'info'})

    return findings


def run_scripts_for_port(
    script_names: List[str],
    host: str,
    port: int,
    info: Dict[str, Any],
    max_workers: int = 5,
    timeout: int = 60,
) -> List[Dict]:
    findings = []
    all_scripts = {s['name']: s for s in load_scripts()}

    tasks = []
    for name in script_names:
        script_info = all_scripts.get(name)
        if script_info:
            tasks.append(script_info)
        else:
            py_path = SCRIPTS_PATH / f"{name}.py"
            if py_path.exists():
                tasks.append({'name': name, 'type': 'python', 'path': str(py_path)})
            else:
                findings.append({'script': name, 'error': 'not found', 'severity': 'info'})

    def _execute(script_entry):
        if script_entry['type'] == 'python':
            return _run_python_script(script_entry['name'], host, port, info)
        elif script_entry['type'] == 'lua':
            return _run_lua_script(script_entry['path'], host, port, info)
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_execute, t): t for t in tasks}
        for future in as_completed(futures, timeout=timeout):
            try:
                result = future.result(timeout=timeout)
                findings.extend(result)
            except Exception as e:
                script = futures[future]
                findings.append({'script': script['name'], 'error': str(e), 'severity': 'info'})

    findings.sort(key=lambda f: SEVERITY_SCORES.get(f.get('severity', 'info'), 0), reverse=True)
    return findings


def run_category(
    category: str,
    host: str,
    port: int,
    info: Dict[str, Any],
    max_workers: int = 5,
) -> List[Dict]:
    names = load_script_names(category)
    if not names:
        return []
    return run_scripts_for_port(names, host, port, info, max_workers=max_workers)


def get_script_info(name: str) -> Optional[Dict[str, Any]]:
    for script in load_scripts():
        if script['name'] == name:
            return script
    return None


def get_categories() -> Dict[str, str]:
    return CATEGORIES.copy()


def count_scripts() -> Dict[str, int]:
    counts = {}
    for script in load_scripts():
        cat = script['category']
        counts[cat] = counts.get(cat, 0) + 1
    counts['total'] = sum(counts.values())
    return counts
